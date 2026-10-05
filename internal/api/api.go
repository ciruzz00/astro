// Package api serves the astro REST API (v1).
package api

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

// Request limits.
const (
	MaxBody          = 1 << 20
	MaxSearch        = 100
	MaxEnrich        = 50
	requestsPerSec   = 5
	requestsBurst    = 20
	maxQueryParamLen = ioc.MaxLen
)

//go:embed openapi.json
var openAPISpec []byte

// Source describes an intelligence source for /providers.
type Source struct {
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Offline    bool     `json:"offline"`
	KeyEnv     string   `json:"key_env,omitempty"`
	Indicators []string `json:"indicators"`
}

// Verifier checks bearer tokens.
type Verifier interface {
	Verify(ctx context.Context, secret string) (*store.Token, error)
}

// Config holds the dependencies of the API.
type Config struct {
	Engine  *engine.Engine
	Sources []Source
	Tokens  Verifier
	Version string
	Logger  *slog.Logger
}

type server struct {
	Config
	mu       sync.Mutex
	limiters map[int64]*rate.Limiter
}

// NewHandler returns the API handler.
func NewHandler(cfg Config) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &server{Config: cfg, limiters: map[int64]*rate.Limiter{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/openapi.json", s.openapi)
	mux.Handle("GET /api/v1/providers", s.auth(s.providers))
	mux.Handle("GET /api/v1/search", s.auth(s.searchGet))
	mux.Handle("POST /api/v1/search", s.auth(s.searchPost))
	mux.Handle("POST /api/v1/extract", s.auth(s.extract))
	mux.Handle("POST /api/v1/enrich", s.auth(s.enrich))
	return s.recoverer(securityHeaders(s.logRequests(jsonMuxErrors(mux))))
}

// NewHTTPServer wraps h in a server with conservative timeouts.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Searches wait on slow, rate-limited providers.
		WriteTimeout:   3 * time.Minute,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
}

// --- handlers ---

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.Version})
}

func (s *server) openapi(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openAPISpec)
}

func (s *server) providers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Sources)
}

// SearchOptions are the options shared by search and enrich requests.
type SearchOptions struct {
	Only    []string `json:"only,omitempty"`
	Offline bool     `json:"offline,omitempty"`
	NoCache bool     `json:"no_cache,omitempty"`
}

func (s *server) searchGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	value := q.Get("q")
	if value == "" || len(value) > maxQueryParamLen {
		writeError(w, http.StatusBadRequest, "query parameter q is required")
		return
	}
	opts := SearchOptions{NoCache: q.Get("no_cache") == "true", Offline: q.Get("offline") == "true"}
	if only := q.Get("only"); only != "" {
		opts.Only = strings.Split(only, ",")
	}
	ind, err := ioc.Parse(value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid indicator: "+err.Error())
		return
	}
	eo, err := s.engineOptions(opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Engine.Search(r.Context(), ind, eo))
}

// SearchRequest is the body of POST /search.
type SearchRequest struct {
	Indicators []string `json:"indicators"`
	SearchOptions
}

func (s *server) searchPost(w http.ResponseWriter, r *http.Request) {
	var req SearchRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Indicators) == 0 || len(req.Indicators) > MaxSearch {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("indicators must contain 1 to %d items", MaxSearch))
		return
	}
	inds, err := parseAll(req.Indicators)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	eo, err := s.engineOptions(req.SearchOptions)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Engine.SearchMany(r.Context(), inds, eo))
}

// ExtractRequest is the body of POST /extract.
type ExtractRequest struct {
	Text string `json:"text"`
}

func (s *server) extract(w http.ResponseWriter, r *http.Request) {
	var req ExtractRequest
	if !decode(w, r, &req) {
		return
	}
	inds := ioc.Extract(req.Text)
	if inds == nil {
		inds = []ioc.Indicator{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"indicators": inds})
}

// EnrichRequest is the body of POST /enrich: free text (an alert, a log line)
// and/or explicit indicators.
type EnrichRequest struct {
	Text       string   `json:"text,omitempty"`
	Indicators []string `json:"indicators,omitempty"`
	SearchOptions
}

// EnrichResponse summarizes the verdicts for automation (SOAR playbooks).
type EnrichResponse struct {
	Verdict    provider.Verdict `json:"verdict"`
	Searched   int              `json:"searched"`
	Truncated  bool             `json:"truncated"`
	Malicious  []ioc.Indicator  `json:"malicious"`
	Suspicious []ioc.Indicator  `json:"suspicious"`
	Reports    []*engine.Report `json:"reports"`
}

func (s *server) enrich(w http.ResponseWriter, r *http.Request) {
	var req EnrichRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Indicators) > MaxSearch {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d indicators", MaxSearch))
		return
	}
	inds, err := parseAll(req.Indicators)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, i := range ioc.Extract(req.Text) {
		if !slices.Contains(inds, i) {
			inds = append(inds, i)
		}
	}
	if len(inds) == 0 {
		writeError(w, http.StatusBadRequest, "no indicators found in text or indicators")
		return
	}
	eo, err := s.engineOptions(req.SearchOptions)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := EnrichResponse{Malicious: []ioc.Indicator{}, Suspicious: []ioc.Indicator{}}
	if len(inds) > MaxEnrich {
		inds, resp.Truncated = inds[:MaxEnrich], true
	}
	resp.Searched = len(inds)
	resp.Reports = s.Engine.SearchMany(r.Context(), inds, eo)
	for _, rep := range resp.Reports {
		switch rep.Verdict {
		case provider.VerdictMalicious:
			resp.Malicious = append(resp.Malicious, rep.Indicator)
		case provider.VerdictSuspicious:
			resp.Suspicious = append(resp.Suspicious, rep.Indicator)
		}
		if rep.Verdict.Rank() > resp.Verdict.Rank() {
			resp.Verdict = rep.Verdict
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- helpers ---

// engineOptions validates source selection against the configured sources.
func (s *server) engineOptions(o SearchOptions) (engine.SearchOptions, error) {
	eo := engine.SearchOptions{NoCache: o.NoCache}
	if o.Offline {
		if len(o.Only) > 0 {
			return eo, errors.New("offline and only are mutually exclusive")
		}
		for _, src := range s.Sources {
			if src.Offline {
				eo.Only = append(eo.Only, src.Name)
			}
		}
		return eo, nil
	}
	for _, name := range o.Only {
		i := slices.IndexFunc(s.Sources, func(src Source) bool { return src.Name == name })
		switch {
		case i < 0:
			return eo, fmt.Errorf("unknown source %q", name)
		case !s.Sources[i].Enabled:
			return eo, fmt.Errorf("source %q is disabled on this server", name)
		}
	}
	eo.Only = o.Only
	return eo, nil
}

func parseAll(values []string) ([]ioc.Indicator, error) {
	out := make([]ioc.Indicator, 0, len(values))
	for k, v := range values {
		i, err := ioc.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("indicators[%d]: %v", k, err)
		}
		if !slices.Contains(out, i) {
			out = append(out, i)
		}
	}
	return out, nil
}

// decode reads a single JSON object, rejecting unknown fields and oversized bodies.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body larger than %d bytes", MaxBody))
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		}
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "body must contain a single JSON object")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- middleware ---

// auth requires a valid bearer token and applies a per-token rate limit.
func (s *server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || secret == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="astro"`)
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		tok, err := s.Tokens.Verify(r.Context(), strings.TrimSpace(secret))
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="astro", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid or revoked token")
			return
		}
		if !s.limiter(tok.ID).Allow() {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		if rec, ok := w.(*statusRecorder); ok {
			rec.token = tok.Name
		}
		next(w, r)
	})
}

func (s *server) limiter(id int64) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.limiters[id]
	if !ok {
		l = rate.NewLimiter(requestsPerSec, requestsBurst)
		s.limiters[id] = l
	}
	return l
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	token  string
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// logRequests logs method, path, status and token name. The query string is
// left out: it carries the searched indicator, which may be sensitive.
func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.Logger.Info("request", "method", r.Method, "path", r.URL.Path, "status", strconv.Itoa(rec.status),
			"token", rec.token, "duration", time.Since(start).Round(time.Millisecond))
	})
}

// jsonMuxErrors turns the mux's plain-text 404 and 405 replies into JSON errors.
func jsonMuxErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&muxErrorWriter{ResponseWriter: w}, r)
	})
}

type muxErrorWriter struct {
	http.ResponseWriter
	swallow bool
}

func (m *muxErrorWriter) WriteHeader(code int) {
	plain := strings.HasPrefix(m.Header().Get("Content-Type"), "text/plain")
	if plain && (code == http.StatusNotFound || code == http.StatusMethodNotAllowed) {
		m.swallow = true
		writeError(m.ResponseWriter, code, strings.ToLower(http.StatusText(code)))
		return
	}
	m.ResponseWriter.WriteHeader(code)
}

func (m *muxErrorWriter) Write(b []byte) (int, error) {
	if m.swallow {
		return len(b), nil
	}
	return m.ResponseWriter.Write(b)
}

func (s *server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Logger.Error("handler panicked", "path", r.URL.Path, "panic", v)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

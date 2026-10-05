// Package web serves the astro browser interface. Pages are rendered on the
// server with html/template; htmx (vendored) boosts navigation and forms, and
// every page also works without JavaScript.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/api"
	"github.com/ciruzz00/astro/internal/auth"
	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/datasets"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Config holds the dependencies of the web interface.
type Config struct {
	Engine  *engine.Engine
	Cases   *cases.Service
	Store   *store.Store
	Tokens  *auth.Manager
	Sources []api.Source
	Fetcher datasets.Fetcher
	Version string
	// Secure marks the session cookie Secure (set when serving over TLS).
	Secure bool
	Logger *slog.Logger
}

type server struct {
	Config
	pages    map[string]*template.Template
	sessions *sessions
	login    *rate.Limiter
	now      func() time.Time
}

// pageFiles maps page names to their template files; each is parsed with the layout.
var pageFiles = []string{"login", "home", "results", "extract", "cases", "case", "sources", "tokens", "error"}

// NewHandler returns the web interface handler.
func NewHandler(cfg Config) (http.Handler, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &server{
		Config:   cfg,
		pages:    map[string]*template.Template{},
		sessions: newSessions(),
		login:    rate.NewLimiter(rate.Every(2*time.Second), 5),
		now:      time.Now,
	}
	assets, err := assetURLs()
	if err != nil {
		return nil, err
	}
	fm := template.FuncMap{"asset": func(name string) string { return assets[name] }}
	for _, p := range pageFiles {
		t, err := template.New("layout.html").Funcs(funcs).Funcs(fm).ParseFS(templateFS,
			"templates/layout.html", "templates/components.html", "templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		s.pages[p] = t
	}

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.logout)

	authed := http.NewServeMux()
	authed.HandleFunc("GET /{$}", s.home)
	authed.HandleFunc("GET /search", s.searchGet)
	authed.HandleFunc("POST /search", s.searchPost)
	authed.HandleFunc("GET /extract", s.extractPage)
	authed.HandleFunc("POST /extract", s.extractPost)
	authed.HandleFunc("POST /add-to-case", s.addToCase)
	authed.HandleFunc("GET /cases", s.casesPage)
	authed.HandleFunc("POST /cases", s.createCase)
	authed.HandleFunc("GET /cases/{name}", s.casePage)
	authed.HandleFunc("POST /cases/{name}/indicators", s.caseAddIndicators)
	authed.HandleFunc("POST /cases/{name}/search", s.caseSearch)
	authed.HandleFunc("POST /cases/{name}/notes", s.caseNote)
	authed.HandleFunc("POST /cases/{name}/tags", s.caseTags)
	authed.HandleFunc("POST /cases/{name}/items/remove", s.caseRemoveItem)
	authed.HandleFunc("POST /cases/{name}/edit", s.caseEdit)
	authed.HandleFunc("POST /cases/{name}/status", s.caseStatus)
	authed.HandleFunc("POST /cases/{name}/delete", s.caseDelete)
	authed.HandleFunc("GET /cases/{name}/export", s.caseExport)
	authed.HandleFunc("GET /sources", s.sourcesPage)
	authed.HandleFunc("POST /sources/sync", s.syncDatasets)
	authed.HandleFunc("GET /tokens", s.tokensPage)
	authed.HandleFunc("POST /tokens", s.createToken)
	authed.HandleFunc("POST /tokens/revoke", s.revokeToken)
	mux.Handle("/", s.requireSession(authed))

	cop := http.NewCrossOriginProtection()
	return s.recoverer(securityHeaders(s.logRequests(cop.Handler(mux)))), nil
}

// assetURLs maps each static file to a URL carrying a hash of its content,
// so browsers can cache assets for long and still never use a stale one.
func assetURLs() (map[string]string, error) {
	out := map[string]string{}
	err := fs.WalkDir(staticFS, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := staticFS.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		name := strings.TrimPrefix(path, "static/")
		out[name] = "/static/" + name + "?h=" + hex.EncodeToString(sum[:6])
		return nil
	})
	return out, err
}

// --- request context ---

type ctxKey struct{}

type reqInfo struct {
	sessionID string
	tokenName string
}

func info(r *http.Request) reqInfo {
	v, _ := r.Context().Value(ctxKey{}).(reqInfo)
	return v
}

// requireSession redirects to the login page unless the request carries a
// live session whose token has not been revoked.
func (s *server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		var sess *session
		if err == nil {
			sess, _ = s.sessions.get(c.Value, s.now())
		}
		if sess != nil {
			active, err := s.Store.TokenActive(r.Context(), sess.tokenID)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if !active {
				s.sessions.delete(c.Value)
				sess = nil
			}
		}
		if sess == nil {
			redirect(w, r, "/login")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, reqInfo{sessionID: c.Value, tokenName: sess.tokenName})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- rendering ---

type pageData struct {
	Title   string
	Nav     string
	Flash   *flash
	Version string
	User    string
	Data    any
}

// render executes a page with the layout. Pages are rendered into a buffer
// first so a template error never sends a half-written page.
func (s *server) render(w http.ResponseWriter, r *http.Request, status int, page, title, nav string, data any) {
	t, ok := s.pages[page]
	if !ok {
		s.fail(w, r, fmt.Errorf("unknown page %q", page))
		return
	}
	in := info(r)
	pd := pageData{Title: title, Nav: nav, Version: s.Version, User: in.tokenName, Data: data}
	if in.sessionID != "" {
		pd.Flash = s.sessions.takeFlash(in.sessionID)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", pd); err != nil {
		s.Logger.Error("render failed", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// flashRedirect stores a message for the next page and redirects (PRG).
func (s *server) flashRedirect(w http.ResponseWriter, r *http.Request, to, kind, msg string) {
	if id := info(r).sessionID; id != "" {
		s.sessions.setFlash(id, flash{Kind: kind, Message: msg})
	}
	redirect(w, r, to)
}

// redirect sends a 303. For htmx requests it asks the browser to navigate
// instead, so the address bar always shows a URL that is safe to reload.
// Only local paths are accepted, so a redirect can never leave the site.
func redirect(w http.ResponseWriter, r *http.Request, to string) {
	if !isLocalPath(to) {
		to = "/"
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther) // #nosec G710 -- restricted to local paths by isLocalPath
}

// isLocalPath accepts "/path" but not "//host", "/\host" or absolute URLs.
func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "/\\") &&
		!strings.ContainsAny(p, "\r\n")
}

// fail renders a generic error page and logs the cause.
func (s *server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.Logger.Error("web request failed", "path", r.URL.Path, "err", err)
	s.render(w, r, http.StatusInternalServerError, "error", "Error", "", "Something went wrong. Details are in the server log.")
}

// --- middleware ---

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// logRequests logs requests without query strings (they may carry indicators).
func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			s.Logger.Info("web", "method", r.Method, "path", r.URL.Path, "status", rec.status,
				"duration", time.Since(start).Round(time.Millisecond))
		}
	})
}

func (s *server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Logger.Error("web handler panicked", "path", r.URL.Path, "panic", v)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

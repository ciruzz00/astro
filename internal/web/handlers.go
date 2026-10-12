package web

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/api"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/store"
)

// Upload and form limits. Text uploads (logs to extract indicators from)
// may be large; they are streamed and only their indicators are kept.
const (
	maxUpload     = 8 << 20
	maxForm       = maxUpload + 1<<20
	maxTextUpload = 256 << 20
	maxExtracted  = 10000 // indicators kept from one extraction
	extractChunk  = 1 << 20
)

// --- login ---

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "login", "Sign in", "", "")
}

func (s *server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if !s.login.Allow() {
		s.render(w, r, http.StatusTooManyRequests, "login", "Sign in", "", "Too many attempts: wait a few seconds.")
		return
	}
	tok, err := s.Tokens.Verify(r.Context(), strings.TrimSpace(r.PostFormValue("token")))
	if err != nil {
		s.render(w, r, http.StatusUnauthorized, "login", "Sign in", "", "Invalid or revoked token.")
		return
	}
	id, err := s.sessions.create(tok.ID, tok.Name, s.now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	http.SetCookie(w, sessionCookie(id, s.Secure, int(sessionTTL.Seconds())))
	redirect(w, r, "/")
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.sessions.delete(c.Value)
	}
	http.SetCookie(w, sessionCookie("", s.Secure, -1))
	redirect(w, r, "/login")
}

// --- shared form helpers ---

// parseForm parses urlencoded and multipart forms with a size cap.
func parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		return r.ParseMultipartForm(maxUpload) // #nosec G120 -- body capped by MaxBytesReader above
	}
	return r.ParseForm() // #nosec G120 -- body capped by MaxBytesReader above
}

// parseTextForm parses a form that may carry a large text file: the body
// limit and the read deadline are raised for this request only, and the
// file goes to a temporary file instead of memory.
func parseTextForm(w http.ResponseWriter, r *http.Request) error {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Minute))
		r.Body = http.MaxBytesReader(w, r.Body, maxTextUpload+1<<20)
		err := r.ParseMultipartForm(maxUpload) // #nosec G120 -- body capped by MaxBytesReader above
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return fmt.Errorf("file larger than %d MB", maxTextUpload>>20)
		}
		return err
	}
	return parseForm(w, r)
}

// formFile returns the uploaded "file", or nil when there is none.
func formFile(r *http.Request) (io.ReadCloser, error) {
	f, _, err := r.FormFile("file")
	if errors.Is(err, http.ErrMissingFile) || errors.Is(err, http.ErrNotMultipart) {
		return nil, nil
	}
	return f, err
}

// formText returns the "text" field plus the content of an uploaded "file"
// (up to maxUpload: for one indicator per line).
func formText(r *http.Request) (string, error) {
	text := r.FormValue("text")
	f, err := formFile(r)
	if f == nil || err != nil {
		return text, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxUpload+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxUpload {
		return "", fmt.Errorf("a list of indicators is limited to %d MB: use \"extract from text\" for logs", maxUpload>>20)
	}
	return text + "\n" + string(b), nil
}

// extractAll extracts every indicator of text: ioc.Extract stops at
// ioc.MaxExtract, so a text that reaches the cap is split in two (at a line
// break) until each part fits. emit returns false to stop.
func extractAll(text string, emit func([]ioc.Indicator) bool) bool {
	inds := ioc.Extract(text)
	if len(inds) < ioc.MaxExtract {
		return emit(inds)
	}
	half := len(text) / 2
	cut := strings.LastIndexByte(text[:half], '\n') + 1
	if cut == 0 {
		i := strings.IndexByte(text[half:], '\n')
		if i < 0 { // one huge line: keep what Extract returned
			return emit(inds)
		}
		cut = half + i + 1
	}
	if cut >= len(text) {
		return emit(inds)
	}
	return extractAll(text[:cut], emit) && extractAll(text[cut:], emit)
}

// extractForm extracts the indicators of the "text" field and of an
// uploaded "file", reading the file in chunks so large logs fit. It keeps
// the first maxExtracted distinct indicators and reports if there were more.
func extractForm(r *http.Request) ([]ioc.Indicator, bool, error) {
	seen := map[ioc.Indicator]bool{}
	var out []ioc.Indicator
	more := false
	add := func(text string) {
		extractAll(text, func(inds []ioc.Indicator) bool {
			for _, i := range inds {
				if seen[i] {
					continue
				}
				if len(out) >= maxExtracted {
					more = true
					return false
				}
				seen[i] = true
				out = append(out, i)
			}
			return true
		})
	}
	add(r.FormValue("text"))
	f, err := formFile(r)
	if f == nil || err != nil {
		return out, more, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, extractChunk)
	var carry []byte
	buf := make([]byte, extractChunk)
	for !more {
		n, err := io.ReadFull(br, buf)
		chunk := append(carry, buf[:n]...)
		carry = nil
		if err == nil { // cut at the last newline; the rest joins the next chunk
			if i := bytes.LastIndexByte(chunk, '\n'); i >= 0 && i < len(chunk)-1 {
				carry = append([]byte(nil), chunk[i+1:]...)
				chunk = chunk[:i+1]
			}
		}
		add(string(chunk))
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return out, more, err
		}
	}
	return out, more, nil
}

// formOptions reads the source selection fields.
func (s *server) formOptions(r *http.Request) (engine.SearchOptions, api.SearchOptions, error) {
	o := api.SearchOptions{
		Offline: r.FormValue("offline") == "on",
		NoCache: r.FormValue("no_cache") == "on",
		Only:    r.Form["only"],
	}
	eo, err := api.ResolveOptions(s.Sources(), o)
	return eo, o, err
}

// formIndicators reads indicators: one per line ("list" mode) or extracted
// from free text and uploaded files ("text" mode).
func formIndicators(r *http.Request) ([]ioc.Indicator, error) {
	var inds []ioc.Indicator
	if r.FormValue("mode") == "text" {
		var err error
		if inds, _, err = extractForm(r); err != nil {
			return nil, err
		}
	} else {
		text, err := formText(r)
		if err != nil {
			return nil, err
		}
		var lines []string
		for _, l := range strings.Split(text, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, l)
			}
		}
		lines = append(lines, r.Form["ioc"]...)
		if inds, err = api.ParseIndicators(lines); err != nil {
			return nil, err
		}
	}
	if len(inds) == 0 {
		return nil, errors.New("no indicators found")
	}
	if len(inds) > api.MaxSearch {
		return nil, fmt.Errorf("too many indicators: at most %d per search (use a case to work in batches)", api.MaxSearch)
	}
	return inds, nil
}

func (s *server) openCases(r *http.Request) []store.CaseSummary {
	list, err := s.Cases.List(r.Context(), false)
	if err != nil {
		s.Logger.Warn("list cases", "err", err)
	}
	return list
}

// --- home and search ---

type homeData struct {
	Cases          []store.CaseSummary
	Sources        []api.Source
	Form           api.SearchOptions
	Missing        []string
	Stale          []string
	OpenCases      int
	Malicious      int
	Suspicious     int
	Enabled        int
	Total          int
	DatasetsSynced int
	DatasetsTotal  int
}

// staleAfter is the age after which an offline dataset should be synced again.
const staleAfter = 30 * 24 * time.Hour

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	ds, err := s.Store.Datasets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := homeData{Cases: s.openCases(r), Sources: s.Sources()}
	d.OpenCases = len(d.Cases)
	for _, c := range d.Cases {
		d.Malicious += c.Malicious
		d.Suspicious += c.Suspicious
	}
	for _, src := range d.Sources {
		d.Total++
		if src.Enabled {
			d.Enabled++
		}
	}
	have := map[string]bool{}
	for _, x := range ds {
		have[x.Name] = true
		if s.now().Sub(x.SyncedAt) > staleAfter {
			d.Stale = append(d.Stale, x.Name)
		}
	}
	names := datasetNames()
	d.DatasetsTotal = len(names)
	for _, n := range names {
		if have[n] {
			d.DatasetsSynced++
		} else {
			d.Missing = append(d.Missing, n)
		}
	}
	s.render(w, r, http.StatusOK, "home", "Search", "search", d)
}

type resultsData struct {
	Query   string
	Mode    string
	Reports []*engine.Report
	Cases   []store.CaseSummary
	Sources []api.Source
	Form    api.SearchOptions
	SavedTo string
	Error   string
}

func (s *server) searchGet(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		redirect(w, r, "/")
		return
	}
	ind, err := ioc.Parse(q)
	d := resultsData{Query: q, Mode: "list", Cases: s.openCases(r), Sources: s.Sources()}
	if err != nil {
		d.Error = s.tr(r, "Invalid indicator: %s", s.tr(r, err.Error()))
		s.render(w, r, http.StatusBadRequest, "results", "Search", "search", d)
		return
	}
	d.Reports = s.Engine.SearchMany(r.Context(), []ioc.Indicator{ind}, engine.SearchOptions{})
	s.render(w, r, http.StatusOK, "results", "Results", "search", d)
}

func (s *server) searchPost(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.render(w, r, http.StatusBadRequest, "error", "Error", "search", s.tr(r, "Invalid form: %s", err.Error()))
		return
	}
	d := resultsData{Query: r.FormValue("text"), Mode: r.FormValue("mode"), Cases: s.openCases(r), Sources: s.Sources()}
	eo, form, err := s.formOptions(r)
	d.Form = form
	if err != nil {
		d.Error = s.tr(r, err.Error())
		s.render(w, r, http.StatusBadRequest, "results", "Search", "search", d)
		return
	}
	inds, err := formIndicators(r)
	if err != nil {
		d.Error = s.tr(r, err.Error())
		s.render(w, r, http.StatusBadRequest, "results", "Search", "search", d)
		return
	}
	d.Reports = s.Engine.SearchMany(r.Context(), inds, eo)
	if name := r.FormValue("case"); name != "" {
		if err := s.Cases.Record(r.Context(), name, d.Reports); err != nil {
			d.Error = s.tr(r, "Results not saved: %s", s.tr(r, caseMessage(name, err)))
		} else {
			d.SavedTo = name
		}
	}
	s.render(w, r, http.StatusOK, "results", "Search results", "search", d)
}

// --- extract ---

type extractData struct {
	Text       string
	Indicators []ioc.Indicator
	Cases      []store.CaseSummary
	Searched   bool
	Error      string
	Truncated  bool
	Limit      int
}

func (s *server) extractPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "extract", "Extract", "extract", extractData{Cases: s.openCases(r)})
}

func (s *server) extractPost(w http.ResponseWriter, r *http.Request) {
	d := extractData{Cases: s.openCases(r), Searched: true}
	if err := parseTextForm(w, r); err != nil {
		d.Error = s.tr(r, "Invalid form: %s", err.Error())
		s.render(w, r, http.StatusBadRequest, "extract", "Extract", "extract", d)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	inds, more, err := extractForm(r)
	if err != nil {
		d.Error = err.Error()
		s.render(w, r, http.StatusBadRequest, "extract", "Extract", "extract", d)
		return
	}
	d.Text = r.FormValue("text")
	d.Indicators, d.Truncated, d.Limit = inds, more, maxExtracted
	s.render(w, r, http.StatusOK, "extract", "Extract", "extract", d)
}

// addToCase adds the selected indicators (from extract or search results) to a case.
func (s *server) addToCase(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.flashRedirect(w, r, "/", "error", "Invalid form")
		return
	}
	name := r.FormValue("case")
	if name == "" {
		s.flashRedirect(w, r, "/cases", "error", "Choose a case (or create one first).")
		return
	}
	inds, err := api.ParseIndicators(r.Form["ioc"])
	if err != nil || len(inds) == 0 {
		s.flashRedirect(w, r, "/", "error", "Select at least one valid indicator.")
		return
	}
	added, err := s.Cases.Add(r.Context(), name, inds, r.FormValue("note"))
	if err != nil {
		s.flashRedirect(w, r, "/cases", "error", caseMessage(name, err))
		return
	}
	msg := s.tr(r, "%d new indicators added (%d selected).", added, len(inds))
	if r.FormValue("search") == "on" {
		eo, _, err := s.formOptions(r)
		if err == nil {
			reps, err := s.Cases.Search(r.Context(), name, eo, true)
			if err == nil {
				msg += " " + s.tr(r, "%d searched.", len(reps))
			}
		}
	}
	s.flashRedirect(w, r, caseURL(name), "ok", msg)
}

func caseURL(name string) string { return "/cases/" + url.PathEscape(name) }

package web

import (
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

// Upload and form limits.
const (
	maxUpload = 8 << 20
	maxForm   = maxUpload + 1<<20
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

// formText returns the "text" field plus the content of an uploaded "file".
func formText(r *http.Request) (string, error) {
	text := r.FormValue("text")
	f, _, err := r.FormFile("file")
	if errors.Is(err, http.ErrMissingFile) || errors.Is(err, http.ErrNotMultipart) {
		return text, nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxUpload+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxUpload {
		return "", fmt.Errorf("file larger than %d MB", maxUpload>>20)
	}
	return text + "\n" + string(b), nil
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
	text, err := formText(r)
	if err != nil {
		return nil, err
	}
	var inds []ioc.Indicator
	if r.FormValue("mode") == "text" {
		inds = ioc.Extract(text)
	} else {
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
}

func (s *server) extractPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "extract", "Extract", "extract", extractData{Cases: s.openCases(r)})
}

func (s *server) extractPost(w http.ResponseWriter, r *http.Request) {
	d := extractData{Cases: s.openCases(r), Searched: true}
	if err := parseForm(w, r); err != nil {
		d.Error = s.tr(r, "Invalid form: %s", err.Error())
		s.render(w, r, http.StatusBadRequest, "extract", "Extract", "extract", d)
		return
	}
	text, err := formText(r)
	if err != nil {
		d.Error = err.Error()
		s.render(w, r, http.StatusBadRequest, "extract", "Extract", "extract", d)
		return
	}
	d.Text = r.FormValue("text")
	d.Indicators = ioc.Extract(text)
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

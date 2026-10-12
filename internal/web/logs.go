package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ciruzz00/astro/internal/detect"
	"github.com/ciruzz00/astro/internal/evidence"
	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/render"
	"github.com/ciruzz00/astro/internal/store"
)

// Log analysis pages of a case: evidence (import and inventory), timeline
// and findings. Imports run in the background, one per case at a time, so
// large folders do not hit the server write timeout; the evidence page
// polls their status.

// timelinePage is the number of events per timeline page.
const timelinePage = 100

// importTimeout bounds a background import.
const importTimeout = 6 * time.Hour

type importJob struct {
	Path     string
	Started  time.Time
	Finished time.Time
	Running  bool
	Files    int
	Events   int
	Skipped  int
	NotLogs  int // files that are not a supported log format
	Dupes    int // files already in the case
	Findings int
	TimeZone string // zone read from the collection, if any
	Err      string
}

type importJobs struct {
	mu   sync.Mutex
	jobs map[string]*importJob
}

func (j *importJobs) get(name string) *importJob {
	j.mu.Lock()
	defer j.mu.Unlock()
	if job, ok := j.jobs[name]; ok {
		c := *job
		return &c
	}
	return nil
}

// start registers a job unless one is already running for the case.
func (j *importJobs) start(name, path string, now time.Time) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if job, ok := j.jobs[name]; ok && job.Running {
		return false
	}
	j.jobs[name] = &importJob{Path: path, Started: now, Running: true}
	return true
}

func (j *importJobs) finish(name string, fn func(job *importJob)) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if job, ok := j.jobs[name]; ok {
		fn(job)
		job.Running = false
	}
}

// caseRef is the header shared by the log pages of a case.
type caseRef struct {
	Name  string
	Title string
	TLP   string
	Tab   string
}

func (s *server) caseRef(w http.ResponseWriter, r *http.Request, tab string) (caseRef, bool) {
	name, ok := s.caseName(w, r)
	if !ok {
		return caseRef{}, false
	}
	c, err := s.Store.CaseByName(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		s.render(w, r, http.StatusNotFound, "error", "Not found", "cases", "No such case.")
		return caseRef{}, false
	}
	if err != nil {
		s.fail(w, r, err)
		return caseRef{}, false
	}
	return caseRef{Name: c.Name, Title: c.Title, TLP: c.TLP, Tab: tab}, true
}

// logSummary is the log analysis block of the case overview.
type logSummary struct {
	Evidence int
	Events   int
	Findings int
	BySev    [5]int // indexed by logs.Severity
}

func (s *server) logSummary(ctx context.Context, name string) (*logSummary, error) {
	ev, err := s.Store.CaseEvidence(ctx, name)
	if err != nil {
		return nil, err
	}
	fs, err := s.Store.Findings(ctx, name)
	if err != nil {
		return nil, err
	}
	sum := &logSummary{Evidence: len(ev), Findings: len(fs)}
	for _, e := range ev {
		sum.Events += e.Events
	}
	for _, f := range fs {
		if f.Severity >= logs.Info && f.Severity <= logs.Critical {
			sum.BySev[f.Severity]++
		}
	}
	return sum, nil
}

// --- evidence ---

type evidenceRow struct {
	store.Evidence
	Custody  []store.CustodyEntry
	Verified bool
}

type importForm struct {
	Path, TZ, Year, Host string
}

type evidenceData struct {
	Case     caseRef
	Evidence []evidenceRow
	Job      *importJob
	Form     importForm
}

func (s *server) evidencePage(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caseRef(w, r, "evidence")
	if !ok {
		return
	}
	list, err := s.Store.CaseEvidence(r.Context(), c.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := evidenceData{Case: c, Job: s.jobs.get(c.Name), Form: importForm{TZ: "UTC"}}
	for _, e := range list {
		row := evidenceRow{Evidence: e}
		if row.Custody, err = s.Store.Custody(r.Context(), e.ID); err != nil {
			s.fail(w, r, err)
			return
		}
		row.Verified = s.Store.VerifyCustody(r.Context(), e.ID) == nil
		d.Evidence = append(d.Evidence, row)
	}
	s.render(w, r, http.StatusOK, "evidence", "Evidence", "cases", d)
}

// importStatus returns the status banner for htmx polling; when the job is
// over it asks htmx to reload the page.
func (s *server) importStatus(w http.ResponseWriter, r *http.Request) {
	name, ok := s.caseName(w, r)
	if !ok {
		return
	}
	job := s.jobs.get(name)
	if job != nil && !job.Running && r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Refresh", "true")
	}
	t := s.pages[langOf(r)]["evidence"]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "import-status", evidenceData{Case: caseRef{Name: name}, Job: job}); err != nil {
		s.Logger.Error("render failed", "page", "import-status", "err", err)
	}
}

func (s *server) importLogs(w http.ResponseWriter, r *http.Request) {
	name, ok := s.caseName(w, r)
	if !ok {
		return
	}
	back := caseURL(name) + "/evidence"
	if _, err := s.Store.CaseID(r.Context(), name); err != nil {
		s.flashRedirect(w, r, "/cases", "error", caseMessage(name, err))
		return
	}
	if job := s.jobs.get(name); job != nil && job.Running {
		s.flashRedirect(w, r, back, "error", "An import is already running for this case.")
		return
	}
	// Uploads (files or a folder chosen in the browser) arrive as multipart
	// and are streamed to disk; a plain form names a path on the server.
	value := r.FormValue
	var uploaded string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		up, err := s.receiveUpload(w, r, name)
		if err != nil {
			s.flashRedirect(w, r, back, "error", s.tr(r, "Upload failed: %s", err.Error()))
			return
		}
		value = func(k string) string { return up.fields[k] }
		uploaded = up.dir
	} else if err := parseForm(w, r); err != nil {
		s.flashRedirect(w, r, back, "error", "Invalid form")
		return
	}
	fail := func(msg string) {
		if uploaded != "" {
			_ = os.RemoveAll(uploaded)
		}
		s.flashRedirect(w, r, back, "error", msg)
	}
	path := strings.TrimSpace(value("path"))
	opts := evidence.Options{Host: strings.TrimSpace(value("host"))}
	if uploaded != "" {
		path, opts.Note = uploaded, "copy uploaded through the web interface"
	}
	if path == "" || len(path) > 4096 || len(opts.Host) > 255 {
		fail("Choose files or a folder to upload, or give a path on the computer where astro runs.")
		return
	}
	if tz := strings.TrimSpace(value("tz")); tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			fail(s.tr(r, "Unknown time zone %s.", tz))
			return
		}
		opts.Location = loc
	}
	if y := strings.TrimSpace(value("year")); y != "" {
		year, err := strconv.Atoi(y)
		if err != nil || year < 1970 || year > 2200 {
			fail("The year must be between 1970 and 2200.")
			return
		}
		opts.Year = year
	}
	if _, err := os.Stat(path); err != nil { // #nosec G703 -- the analyst names a local file on purpose; it is only read
		fail(s.tr(r, "Cannot read %s on the server: when astro runs in Docker only its own folders are visible, so upload the files instead.", path))
		return
	}
	if !s.jobs.start(name, path, s.now()) {
		fail("An import is already running for this case.")
		return
	}
	// The import outlives the request: keep its values, drop its cancellation.
	go s.runImport(context.WithoutCancel(r.Context()), name, path, opts)
	redirect(w, r, back) // the status banner follows the import
}

// runImport imports and analyzes in the background.
func (s *server) runImport(parent context.Context, name, path string, opts evidence.Options) {
	ctx, cancel := context.WithTimeout(parent, importTimeout)
	defer cancel()
	var files, events, skipped, notLogs, dupes, findings int
	var failure, zone string
	defer func() {
		if v := recover(); v != nil {
			s.Logger.Error("import panicked", "case", name, "panic", v)
			failure = "internal error"
		}
		s.jobs.finish(name, func(j *importJob) {
			j.Finished, j.Files, j.Events, j.Skipped, j.Findings, j.Err = s.now(), files, events, skipped, findings, failure
			j.NotLogs, j.Dupes, j.TimeZone = notLogs, dupes, zone
		})
	}()
	im := evidence.New(s.Store, evidence.DefaultParsers()...)
	im.Actor = s.Actor
	res, err := im.Import(ctx, name, path, opts)
	if err != nil {
		failure = err.Error()
		return
	}
	files, skipped, events = res.Counts()
	zone = res.TimeZone
	for _, f := range res.Files {
		switch {
		case f.Duplicate:
			dupes++
		case f.Skipped == "not a recognized log format":
			notLogs++
		}
	}
	out, err := detect.Analyze(ctx, s.Store, name, s.now().UTC())
	if err != nil {
		failure = "analysis: " + err.Error()
		return
	}
	findings = len(out.Findings)
}

func (s *server) analyzeLogs(w http.ResponseWriter, r *http.Request) {
	name, ok := s.caseName(w, r)
	if !ok {
		return
	}
	back := caseURL(name) + "/findings"
	res, err := detect.Analyze(r.Context(), s.Store, name, s.now().UTC())
	if err != nil {
		s.flashRedirect(w, r, back, "error", caseMessage(name, err))
		return
	}
	s.flashRedirect(w, r, back, "ok", s.tr(r, "Analysis done: %d findings.", len(res.Findings)))
}

func (s *server) findingIndicators(w http.ResponseWriter, r *http.Request) {
	name, ok := s.caseName(w, r)
	if !ok {
		return
	}
	back := caseURL(name) + "/findings"
	fs, err := s.Store.Findings(r.Context(), name)
	if err != nil {
		s.flashRedirect(w, r, back, "error", caseMessage(name, err))
		return
	}
	n, err := s.Cases.Add(r.Context(), name, detect.Indicators(fs), "from log analysis")
	if err != nil {
		s.flashRedirect(w, r, back, "error", caseMessage(name, err))
		return
	}
	s.flashRedirect(w, r, back, "ok", s.tr(r, "%d new indicators added to the case.", n))
}

// --- timeline ---

// timelineQuery is the filter of the timeline as typed in the form.
type timelineQuery struct {
	Severity, Host, User, IP, Source, Kind, EventID, Text, From, To string
	Offset                                                          int
}

func parseTimelineQuery(q url.Values) (timelineQuery, store.EventFilter, error) {
	tq := timelineQuery{Severity: q.Get("severity"), Host: q.Get("host"), User: q.Get("user"), IP: q.Get("ip"), Source: q.Get("source"),
		Kind: q.Get("kind"), EventID: q.Get("event_id"), Text: q.Get("q"), From: q.Get("from"), To: q.Get("to")}
	f := store.EventFilter{Host: tq.Host, User: tq.User, IP: tq.IP, Source: tq.Source, Kind: tq.Kind, Text: tq.Text}
	for _, v := range []string{tq.Host, tq.User, tq.IP, tq.Source, tq.Kind, tq.Text} {
		if len(v) > 512 {
			return tq, f, errors.New("filter values are limited to 512 characters")
		}
	}
	var err error
	if tq.Severity != "" {
		if f.MinSeverity, err = logs.ParseSeverity(tq.Severity); err != nil {
			return tq, f, err
		}
	}
	if tq.EventID != "" {
		if f.EventID, err = strconv.Atoi(tq.EventID); err != nil || f.EventID < 0 {
			return tq, f, errors.New("the event ID must be a number")
		}
	}
	if f.From, err = parseUTC(tq.From); err != nil {
		return tq, f, err
	}
	if f.To, err = parseUTC(tq.To); err != nil {
		return tq, f, err
	}
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o > 0 {
		tq.Offset = o
	}
	f.Offset, f.Limit = tq.Offset, timelinePage
	return tq, f, nil
}

// parseUTC reads a time from a form: the browser sends "2026-10-11T21:00"
// (datetime-local) and users type dates or RFC 3339.
func parseUTC(v string) (time.Time, error) {
	if v = strings.TrimSpace(v); v == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02", time.RFC3339Nano} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unreadable time %q", v)
}

type timelineData struct {
	Case      caseRef
	Query     timelineQuery
	Events    []logs.Event
	Total     int
	First     int
	Last      int
	PrevURL   string
	NextURL   string
	CSVURL    string
	Error     string
	Filtered  bool
	HasEvents bool
}

func (s *server) timelinePage(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caseRef(w, r, "timeline")
	if !ok {
		return
	}
	q := r.URL.Query()
	tq, f, err := parseTimelineQuery(q)
	d := timelineData{Case: c, Query: tq}
	if err != nil {
		d.Error = err.Error()
		s.render(w, r, http.StatusBadRequest, "timeline", "Timeline", "cases", d)
		return
	}
	evs, total, err := s.Store.Events(r.Context(), c.Name, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Events, d.Total = evs, total
	d.Filtered = tq != (timelineQuery{Offset: tq.Offset})
	d.HasEvents = total > 0 || d.Filtered
	if len(evs) > 0 {
		d.First, d.Last = tq.Offset+1, tq.Offset+len(evs)
	}
	base := caseURL(c.Name) + "/timeline"
	page := func(offset int) string {
		v := url.Values{}
		for k := range q {
			if k != "offset" && q.Get(k) != "" {
				v.Set(k, q.Get(k))
			}
		}
		if offset > 0 {
			v.Set("offset", strconv.Itoa(offset))
		}
		if len(v) == 0 {
			return base
		}
		return base + "?" + v.Encode()
	}
	if tq.Offset > 0 {
		d.PrevURL = page(max(tq.Offset-timelinePage, 0))
	}
	if tq.Offset+len(evs) < total {
		d.NextURL = page(tq.Offset + timelinePage)
	}
	csv := page(0)
	d.CSVURL = strings.Replace(csv, base, base+".csv", 1)
	s.render(w, r, http.StatusOK, "timeline", "Timeline", "cases", d)
}

func (s *server) timelineCSV(w http.ResponseWriter, r *http.Request) {
	name, ok := s.caseName(w, r)
	if !ok {
		return
	}
	_, f, err := parseTimelineQuery(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var all []logs.Event
	for off := 0; ; off += store.MaxEventPage {
		f.Offset, f.Limit = off, store.MaxEventPage
		evs, _, err := s.Store.Events(r.Context(), name, f)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				http.NotFound(w, r)
				return
			}
			s.fail(w, r, err)
			return
		}
		all = append(all, evs...)
		if len(evs) < store.MaxEventPage {
			break
		}
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-timeline.csv"`, name))
	if err := render.TimelineCSV(w, all); err != nil {
		s.Logger.Warn("timeline export failed", "case", name, "err", err)
	}
}

// --- findings ---

type findingView struct {
	logs.Finding
	Events []logs.Event
}

type findingsData struct {
	Case     caseRef
	Findings []findingView
	BySev    [5]int
	Imported bool
}

func (s *server) findingsPage(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caseRef(w, r, "findings")
	if !ok {
		return
	}
	fs, err := s.Store.Findings(r.Context(), c.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev, err := s.Store.CaseEvidence(r.Context(), c.Name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := findingsData{Case: c, Imported: len(ev) > 0}
	for _, f := range fs {
		v := findingView{Finding: f}
		if v.Events, err = s.Store.EventsByID(r.Context(), c.Name, f.EventIDs[:min(len(f.EventIDs), 5)]); err != nil {
			s.fail(w, r, err)
			return
		}
		if f.Severity >= logs.Info && f.Severity <= logs.Critical {
			d.BySev[f.Severity]++
		}
		d.Findings = append(d.Findings, v)
	}
	s.render(w, r, http.StatusOK, "findings", "Findings", "cases", d)
}

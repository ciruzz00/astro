package web

import (
	"bytes"
	"errors"
	"net/http"
	"strings"

	"github.com/ciruzz00/astro/internal/api"
	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/report"
	"github.com/ciruzz00/astro/internal/store"
)

var tlpLevels = []string{cases.TLPClear, cases.TLPGreen, cases.TLPAmber, cases.TLPAmberStrict, cases.TLPRed}

func caseMessage(name string, err error) string {
	if errors.Is(err, cases.ErrNotFound) {
		return "No such case."
	}
	return err.Error()
}

// caseName validates the {name} path value; invalid names get a 404 page.
func (s *server) caseName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if cases.ValidateName(name) != nil {
		s.render(w, r, http.StatusNotFound, "error", "Not found", "cases", "No such case.")
		return "", false
	}
	return name, true
}

// --- list and create ---

type casesData struct {
	Cases []store.CaseSummary
	All   bool
	TLPs  []string
}

func (s *server) casesPage(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "1"
	list, err := s.Cases.List(r.Context(), all)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "cases", "Cases", "cases", casesData{Cases: list, All: all, TLPs: tlpLevels})
}

func (s *server) createCase(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.flashRedirect(w, r, "/cases", "error", "Invalid form")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if err := s.Cases.Create(r.Context(), name, strings.TrimSpace(r.FormValue("title")), r.FormValue("tlp"), splitTags(r.FormValue("tags"))); err != nil {
		s.flashRedirect(w, r, "/cases", "error", err.Error())
		return
	}
	s.flashRedirect(w, r, caseURL(name), "ok", "Case created.")
}

func splitTags(s string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		out = append(out, strings.TrimSpace(t))
	}
	return out
}

// --- case page ---

type caseData struct {
	View       *cases.View
	Malicious  int
	Suspicious int
	Clean      int
	Pending    int
	Sources    []api.Source
	Form       api.SearchOptions
	TLPs       []string
	Formats    []string
}

func (s *server) casePage(w http.ResponseWriter, r *http.Request) {
	name, ok := s.caseName(w, r)
	if !ok {
		return
	}
	v, err := s.Cases.Load(r.Context(), name)
	if errors.Is(err, cases.ErrNotFound) {
		s.render(w, r, http.StatusNotFound, "error", "Not found", "cases", "No such case.")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := caseData{View: v, Sources: s.Sources(), TLPs: tlpLevels, Formats: report.Formats}
	d.Malicious, d.Suspicious, d.Clean, d.Pending = v.Counts()
	title := v.Case.Title
	if title == "" {
		title = v.Case.Name
	}
	s.render(w, r, http.StatusOK, "case", title, "cases", d)
}

// caseAction parses the form of a case action and runs fn, then redirects
// back to the case with a flash message.
func (s *server) caseAction(w http.ResponseWriter, r *http.Request, anchor string, fn func(name string) (string, error)) {
	name, ok := s.caseName(w, r)
	if !ok {
		return
	}
	if err := parseForm(w, r); err != nil {
		s.flashRedirect(w, r, caseURL(name), "error", s.tr(r, "Invalid form: %s", err.Error()))
		return
	}
	msg, err := fn(name)
	if err != nil {
		s.flashRedirect(w, r, caseURL(name)+anchor, "error", caseMessage(name, err))
		return
	}
	s.flashRedirect(w, r, caseURL(name)+anchor, "ok", msg)
}

func (s *server) caseAddIndicators(w http.ResponseWriter, r *http.Request) {
	s.caseAction(w, r, "#indicators", func(name string) (string, error) {
		inds, err := formIndicators(r)
		if err != nil {
			return "", err
		}
		added, err := s.Cases.Add(r.Context(), name, inds, strings.TrimSpace(r.FormValue("note")))
		if err != nil {
			return "", err
		}
		msg := s.tr(r, "%d new indicators added (%d given).", added, len(inds))
		if r.FormValue("search") == "on" {
			eo, _, err := s.formOptions(r)
			if err != nil {
				return "", err
			}
			reps, err := s.Cases.Search(r.Context(), name, eo, true)
			if err != nil {
				return "", err
			}
			msg += " " + s.tr(r, "%d searched.", len(reps))
		}
		return msg, nil
	})
}

func (s *server) caseSearch(w http.ResponseWriter, r *http.Request) {
	s.caseAction(w, r, "#indicators", func(name string) (string, error) {
		eo, _, err := s.formOptions(r)
		if err != nil {
			return "", err
		}
		reps, err := s.Cases.Search(r.Context(), name, eo, r.FormValue("scope") != "all")
		if err != nil {
			return "", err
		}
		if len(reps) == 0 {
			return "Nothing new to search: use \"Search all again\" to refresh every result.", nil
		}
		return s.tr(r, "%d indicators searched.", len(reps)), nil
	})
}

func (s *server) caseNote(w http.ResponseWriter, r *http.Request) {
	s.caseAction(w, r, "#notes", func(name string) (string, error) {
		return "Note added.", s.Cases.Note(r.Context(), name, r.FormValue("body"))
	})
}

func (s *server) caseTags(w http.ResponseWriter, r *http.Request) {
	s.caseAction(w, r, "", func(name string) (string, error) {
		if t := r.FormValue("remove"); t != "" {
			return "Tag removed.", s.Cases.Tag(r.Context(), name, nil, []string{t})
		}
		tags := splitTags(r.FormValue("add"))
		if len(tags) == 0 {
			return "", errors.New("enter at least one tag")
		}
		return "Tags added.", s.Cases.Tag(r.Context(), name, tags, nil)
	})
}

func (s *server) caseRemoveItem(w http.ResponseWriter, r *http.Request) {
	s.caseAction(w, r, "#indicators", func(name string) (string, error) {
		i, err := ioc.Parse(r.FormValue("ioc"))
		if err != nil {
			return "", err
		}
		if err := s.Cases.Remove(r.Context(), name, i); err != nil {
			return "", err
		}
		return s.tr(r, "%s removed.", ioc.Defang(i)), nil
	})
}

func (s *server) caseEdit(w http.ResponseWriter, r *http.Request) {
	s.caseAction(w, r, "", func(name string) (string, error) {
		title := strings.TrimSpace(r.FormValue("title"))
		desc := strings.TrimSpace(r.FormValue("description"))
		tlp := r.FormValue("tlp")
		return "Case updated.", s.Cases.Update(r.Context(), name, &title, &desc, &tlp, nil)
	})
}

func (s *server) caseStatus(w http.ResponseWriter, r *http.Request) {
	s.caseAction(w, r, "", func(name string) (string, error) {
		status := r.FormValue("status")
		msg := "Case reopened."
		if status == "closed" {
			msg = "Case closed."
		}
		return msg, s.Cases.Update(r.Context(), name, nil, nil, nil, &status)
	})
}

func (s *server) caseDelete(w http.ResponseWriter, r *http.Request) {
	name, ok := s.caseName(w, r)
	if !ok {
		return
	}
	if err := parseForm(w, r); err != nil || r.FormValue("confirm") != name {
		s.flashRedirect(w, r, caseURL(name)+"#danger", "error", "Type the case name exactly to confirm the deletion.")
		return
	}
	if err := s.Cases.Delete(r.Context(), name); err != nil {
		s.flashRedirect(w, r, "/cases", "error", caseMessage(name, err))
		return
	}
	s.flashRedirect(w, r, "/cases", "ok", s.tr(r, "Case %s deleted.", name))
}

func (s *server) caseExport(w http.ResponseWriter, r *http.Request) {
	name, ok := s.caseName(w, r)
	if !ok {
		return
	}
	v, err := s.Cases.Load(r.Context(), name)
	if err != nil {
		s.render(w, r, http.StatusNotFound, "error", "Not found", "cases", caseMessage(name, err))
		return
	}
	format := r.URL.Query().Get("format")
	var buf bytes.Buffer
	opts := report.Options{Version: s.Version, AttackVersion: s.attackVersion(r)}
	if err := report.Write(&buf, format, v, opts); err != nil {
		s.render(w, r, http.StatusBadRequest, "error", "Export", "cases", err.Error())
		return
	}
	w.Header().Set("Content-Type", report.ContentType(format))
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+report.Extension(format)+`"`)
	_, _ = w.Write(buf.Bytes())
}

func (s *server) attackVersion(r *http.Request) string {
	ds, err := s.Store.Datasets(r.Context())
	if err != nil {
		return ""
	}
	for _, d := range ds {
		if d.Name == "attack-enterprise" {
			return d.Version
		}
	}
	return ""
}

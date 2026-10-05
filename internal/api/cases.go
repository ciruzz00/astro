package api

import (
	"bytes"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/report"
)

func (s *server) routeCases(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/cases", s.auth(s.listCases))
	mux.Handle("POST /api/v1/cases", s.auth(s.createCase))
	mux.Handle("GET /api/v1/cases/{name}", s.auth(s.getCase))
	mux.Handle("POST /api/v1/cases/{name}/indicators", s.auth(s.addCaseIndicators))
	mux.Handle("GET /api/v1/cases/{name}/export", s.auth(s.exportCase))
}

// caseName validates the {name} path value.
func caseName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if err := cases.ValidateName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	return name, true
}

func writeCaseError(w http.ResponseWriter, err error) {
	if errors.Is(err, cases.ErrNotFound) {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}
	writeError(w, http.StatusInternalServerError, "internal error")
}

func (s *server) listCases(w http.ResponseWriter, r *http.Request) {
	list, err := s.Cases.List(r.Context(), r.URL.Query().Get("all") == "true")
	if err != nil {
		writeCaseError(w, err)
		return
	}
	if list == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// CreateCaseRequest is the body of POST /cases.
type CreateCaseRequest struct {
	Name  string   `json:"name"`
	Title string   `json:"title,omitempty"`
	TLP   string   `json:"tlp,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

func (s *server) createCase(w http.ResponseWriter, r *http.Request) {
	var req CreateCaseRequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.Cases.Create(r.Context(), req.Name, req.Title, req.TLP, req.Tags); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "already exists") {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	v, err := s.Cases.Load(r.Context(), req.Name)
	if err != nil {
		writeCaseError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *server) getCase(w http.ResponseWriter, r *http.Request) {
	name, ok := caseName(w, r)
	if !ok {
		return
	}
	v, err := s.Cases.Load(r.Context(), name)
	if err != nil {
		writeCaseError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// AddIndicatorsRequest is the body of POST /cases/{name}/indicators.
type AddIndicatorsRequest struct {
	Indicators []string `json:"indicators,omitempty"`
	Text       string   `json:"text,omitempty"`
	Note       string   `json:"note,omitempty"`
	Search     bool     `json:"search,omitempty"`
	SearchOptions
}

// AddIndicatorsResponse reports what was added (and searched).
type AddIndicatorsResponse struct {
	Added    int `json:"added"`
	Given    int `json:"given"`
	Searched int `json:"searched"`
}

func (s *server) addCaseIndicators(w http.ResponseWriter, r *http.Request) {
	name, ok := caseName(w, r)
	if !ok {
		return
	}
	var req AddIndicatorsRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Indicators) > MaxSearch {
		writeError(w, http.StatusBadRequest, "too many indicators")
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
	if len(inds) == 0 || len(inds) > MaxSearch {
		writeError(w, http.StatusBadRequest, "provide 1 to 100 indicators in indicators or text")
		return
	}
	eo, err := s.engineOptions(req.SearchOptions)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := AddIndicatorsResponse{Given: len(inds)}
	if resp.Added, err = s.Cases.Add(r.Context(), name, inds, req.Note); err != nil {
		if errors.Is(err, cases.ErrNotFound) {
			writeCaseError(w, err)
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	if req.Search {
		reports, err := s.Cases.Search(r.Context(), name, eo, true)
		if err != nil {
			writeCaseError(w, err)
			return
		}
		resp.Searched = len(reports)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) exportCase(w http.ResponseWriter, r *http.Request) {
	name, ok := caseName(w, r)
	if !ok {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	v, err := s.Cases.Load(r.Context(), name)
	if err != nil {
		writeCaseError(w, err)
		return
	}
	var buf bytes.Buffer
	if err := report.Write(&buf, format, v, report.Options{Version: s.Version, AttackVersion: s.AttackVersion}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", report.ContentType(format))
	// name is validated (letters, digits, . _ -): safe in the header.
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+report.Extension(format)+`"`)
	_, _ = w.Write(buf.Bytes())
}

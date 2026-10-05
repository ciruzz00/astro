package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/api"
	"github.com/ciruzz00/astro/internal/datasets"
	"github.com/ciruzz00/astro/internal/store"
)

func datasetNames() []string {
	names := make([]string, len(datasets.Sources))
	for k, s := range datasets.Sources {
		names[k] = s.Name
	}
	return names
}

// --- sources and datasets ---

type datasetRow struct {
	Name        string
	Description string
	Synced      *store.Dataset
}

type sourcesData struct {
	Sources  []api.Source
	Datasets []datasetRow
}

func (s *server) sourcesPage(w http.ResponseWriter, r *http.Request) {
	ds, err := s.Store.Datasets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	byName := map[string]store.Dataset{}
	for _, d := range ds {
		byName[d.Name] = d
	}
	d := sourcesData{Sources: s.Sources}
	for _, src := range datasets.Sources {
		row := datasetRow{Name: src.Name, Description: src.Description}
		if x, ok := byName[src.Name]; ok {
			row.Synced = &x
		}
		d.Datasets = append(d.Datasets, row)
	}
	s.render(w, r, http.StatusOK, "sources", "Sources", "sources", d)
}

func (s *server) syncDatasets(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.flashRedirect(w, r, "/sources", "error", "Invalid form")
		return
	}
	srcs, err := datasets.Select(r.Form["dataset"])
	if err != nil {
		s.flashRedirect(w, r, "/sources", "error", err.Error())
		return
	}
	var ok, failed []string
	for _, src := range srcs {
		start := time.Now()
		n, err := src.Sync(r.Context(), s.Fetcher, s.Store)
		if err != nil {
			s.Logger.Warn("dataset sync failed", "dataset", src.Name, "err", err)
			failed = append(failed, src.Name)
			continue
		}
		ok = append(ok, fmt.Sprintf("%s (%d records, %s)", src.Name, n, time.Since(start).Round(100*time.Millisecond)))
	}
	if len(failed) > 0 {
		s.flashRedirect(w, r, "/sources", "error", "Sync failed for "+strings.Join(failed, ", ")+". See the server log.")
		return
	}
	s.flashRedirect(w, r, "/sources", "ok", "Synced: "+strings.Join(ok, "; ")+".")
}

// --- tokens ---

type tokensData struct {
	Tokens    []store.Token
	NewName   string
	NewSecret string
	Current   string
}

func (s *server) tokensPage(w http.ResponseWriter, r *http.Request) {
	s.renderTokens(w, r, http.StatusOK, tokensData{})
}

func (s *server) renderTokens(w http.ResponseWriter, r *http.Request, status int, d tokensData) {
	list, err := s.Store.Tokens(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Tokens, d.Current = list, info(r).tokenName
	s.render(w, r, status, "tokens", "API tokens", "tokens", d)
}

func (s *server) createToken(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.flashRedirect(w, r, "/tokens", "error", "Invalid form")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	secret, _, err := s.Tokens.Create(r.Context(), name)
	if err != nil {
		s.flashRedirect(w, r, "/tokens", "error", err.Error())
		return
	}
	// Rendered directly (not redirected): the secret must never be stored.
	s.renderTokens(w, r, http.StatusCreated, tokensData{NewName: name, NewSecret: secret})
}

func (s *server) revokeToken(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(w, r); err != nil {
		s.flashRedirect(w, r, "/tokens", "error", "Invalid form")
		return
	}
	name := r.FormValue("name")
	err := s.Store.RevokeToken(r.Context(), name, time.Now())
	if errors.Is(err, store.ErrNotFound) {
		s.flashRedirect(w, r, "/tokens", "error", "No active token named "+name+".")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.flashRedirect(w, r, "/tokens", "ok", "Token "+name+" revoked.")
}

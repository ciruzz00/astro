package tui

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/ciruzz00/astro/internal/api"
	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/datasets"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/report"
	"github.com/ciruzz00/astro/internal/store"
)

// Messages produced by the asynchronous commands.
type (
	searchDoneMsg struct{ reports []*engine.Report }
	casesMsg      struct {
		list []store.CaseSummary
		err  error
	}
	caseMsg struct {
		view *cases.View
		err  error
	}
	sourcesMsg struct {
		datasets []store.Dataset
		err      error
	}
	// doneMsg reports the end of an action; reload asks to refresh case data.
	doneMsg struct {
		text   string
		err    error
		reload bool
	}
)

// parseInput turns the search box into indicators: every indicator found in
// the text, or the whole text as one name (e.g. "Lazarus Group").
func parseInput(s string) ([]ioc.Indicator, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("type an indicator, several of them, or a threat name")
	}
	if found := ioc.Extract(s); len(found) > 0 {
		if len(found) > api.MaxSearch {
			return nil, fmt.Errorf("at most %d indicators per search", api.MaxSearch)
		}
		return found, nil
	}
	i, err := ioc.Parse(s)
	if err != nil {
		return nil, err
	}
	return []ioc.Indicator{i}, nil
}

func (m *Model) searchOptions() engine.SearchOptions {
	opts := engine.SearchOptions{}
	if m.offline {
		for _, src := range m.cfg.Sources() {
			if src.Offline {
				opts.Only = append(opts.Only, src.Name)
			}
		}
	}
	return opts
}

func (m *Model) searchCmd(inds []ioc.Indicator) tea.Cmd {
	opts := m.searchOptions()
	return func() tea.Msg {
		return searchDoneMsg{reports: m.cfg.Engine.SearchMany(m.cfg.Ctx, inds, opts)}
	}
}

func (m *Model) loadCasesCmd() tea.Cmd {
	all := m.includeClosed
	return func() tea.Msg {
		list, err := m.cfg.Cases.List(m.cfg.Ctx, all)
		return casesMsg{list: list, err: err}
	}
}

func (m *Model) loadCaseCmd(name string) tea.Cmd {
	return func() tea.Msg {
		v, err := m.cfg.Cases.Load(m.cfg.Ctx, name)
		return caseMsg{view: v, err: err}
	}
}

func (m *Model) loadSourcesCmd() tea.Cmd {
	return func() tea.Msg {
		ds, err := m.cfg.Store.Datasets(m.cfg.Ctx)
		return sourcesMsg{datasets: ds, err: err}
	}
}

// action runs fn in the background and reports its message.
func (m *Model) action(reload bool, fn func() (string, error)) tea.Cmd {
	return func() tea.Msg {
		text, err := fn()
		return doneMsg{text: text, err: err, reload: reload}
	}
}

func (m *Model) createCaseCmd(name string) tea.Cmd {
	return m.action(true, func() (string, error) {
		if err := m.cfg.Cases.Create(m.cfg.Ctx, strings.TrimSpace(name), "", "", nil); err != nil {
			return "", err
		}
		return "case " + name + " created", nil
	})
}

func (m *Model) saveResultsCmd(name string) tea.Cmd {
	reports := m.reports
	return m.action(true, func() (string, error) {
		if err := m.cfg.Cases.Record(m.cfg.Ctx, strings.TrimSpace(name), reports); err != nil {
			return "", caseError(err)
		}
		return fmt.Sprintf("%d results saved to case %s", len(reports), name), nil
	})
}

func (m *Model) caseSearchCmd(name string, all bool) tea.Cmd {
	opts := m.searchOptions()
	return m.action(true, func() (string, error) {
		reps, err := m.cfg.Cases.Search(m.cfg.Ctx, name, opts, !all)
		if err != nil {
			return "", caseError(err)
		}
		if len(reps) == 0 {
			return "nothing new to search (S searches everything again)", nil
		}
		return fmt.Sprintf("%d indicators searched", len(reps)), nil
	})
}

func (m *Model) addIndicatorsCmd(name, text string) tea.Cmd {
	return m.action(true, func() (string, error) {
		inds, err := parseInput(text)
		if err != nil {
			return "", err
		}
		n, err := m.cfg.Cases.Add(m.cfg.Ctx, name, inds, "")
		if err != nil {
			return "", caseError(err)
		}
		return fmt.Sprintf("%d new indicators added (s to search them)", n), nil
	})
}

func (m *Model) noteCmd(name, body string) tea.Cmd {
	return m.action(true, func() (string, error) {
		if err := m.cfg.Cases.Note(m.cfg.Ctx, name, body); err != nil {
			return "", caseError(err)
		}
		return "note added", nil
	})
}

func (m *Model) statusCmd(name, status string) tea.Cmd {
	return m.action(true, func() (string, error) {
		if err := m.cfg.Cases.Update(m.cfg.Ctx, name, nil, nil, nil, &status); err != nil {
			return "", caseError(err)
		}
		return "case " + status, nil
	})
}

// exportCmd writes the case to ./<name><ext> with owner-only permissions,
// never overwriting an existing file.
func (m *Model) exportCmd(name, format string) tea.Cmd {
	format = strings.ToLower(strings.TrimSpace(format))
	return m.action(false, func() (string, error) {
		v, err := m.cfg.Cases.Load(m.cfg.Ctx, name)
		if err != nil {
			return "", caseError(err)
		}
		path := name + report.Extension(format)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- name is a validated case name
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("%s already exists in the current directory", path)
		}
		if err != nil {
			return "", err
		}
		opts := report.Options{Version: m.cfg.Version}
		if m.cfg.AttackVersion != nil {
			opts.AttackVersion = m.cfg.AttackVersion()
		}
		if err := report.Write(f, format, v, opts); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		return "exported to " + path + " (TLP:" + v.Case.TLP + ")", nil
	})
}

func (m *Model) syncCmd() tea.Cmd {
	return m.action(false, func() (string, error) {
		var done []string
		for _, src := range datasets.Sources {
			start := time.Now()
			n, err := src.Sync(m.cfg.Ctx, m.cfg.Fetcher, m.cfg.Store)
			if err != nil {
				return "", fmt.Errorf("sync %s: %w", src.Name, err)
			}
			done = append(done, fmt.Sprintf("%s %d (%s)", src.Name, n, time.Since(start).Round(100*time.Millisecond)))
		}
		return "synced: " + strings.Join(done, ", "), nil
	})
}

func caseError(err error) error {
	if errors.Is(err, cases.ErrNotFound) {
		return errors.New("no such case")
	}
	return err
}

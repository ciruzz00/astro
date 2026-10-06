package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/ciruzz00/astro/internal/api"
	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

// fakeProvider flags 198.51.100.7 and returns terminal escape sequences in
// its summary, which must never reach the screen.
type fakeProvider struct{ name string }

func (f fakeProvider) Name() string           { return f.name }
func (f fakeProvider) Supports(ioc.Type) bool { return true }
func (f fakeProvider) Lookup(_ context.Context, i ioc.Indicator) (*provider.Result, error) {
	v := provider.VerdictClean
	if i.Value == "198.51.100.7" {
		v = provider.VerdictMalicious
	}
	return &provider.Result{Found: true, Verdict: v, Summary: "seen\x1b[2J\x1b]0;pwned\x07 by " + f.name,
		Fields: []provider.Field{{Name: "Owner", Value: "Example Hosting"}}}, nil
}

func newModel(t *testing.T) Model {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := engine.New([]provider.Provider{fakeProvider{"online"}, fakeProvider{"local"}})
	m := New(Config{
		Engine: eng, Cases: cases.New(st, eng), Store: st, Version: "test",
		Sources: func() []api.Source {
			return []api.Source{{Name: "online", Enabled: true}, {Name: "local", Enabled: true, Offline: true}}
		},
	})
	// A blinking cursor schedules a timer on every key: turn it off so the
	// commands run by send return immediately.
	m.blink = false
	value := m.input.Placeholder
	m.input = m.newInput()
	m.input.Placeholder = value
	m.input.Focus()
	return send(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
}

// send delivers msg and then runs the resulting commands synchronously,
// feeding astro's own messages back into the model.
func send(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	next, cmd := m.Update(msg)
	m = next.(Model)
	return run(t, m, cmd, 0)
}

func run(t *testing.T, m Model, cmd tea.Cmd, depth int) Model {
	t.Helper()
	if cmd == nil || depth > 8 {
		return m
	}
	switch msg := cmd().(type) {
	case tea.BatchMsg:
		for _, c := range msg {
			m = run(t, m, c, depth+1)
		}
	case searchDoneMsg, casesMsg, caseMsg, sourcesMsg, doneMsg:
		next, c := m.Update(msg)
		m = run(t, next.(Model), c, depth+1)
	}
	return m
}

func typeText(t *testing.T, m Model, s string) Model {
	t.Helper()
	for _, r := range s {
		m = send(t, m, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	return m
}

func key(t *testing.T, m Model, k string) Model {
	t.Helper()
	switch k {
	case "enter":
		return send(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	case "esc":
		return send(t, m, tea.KeyPressMsg{Code: tea.KeyEscape})
	case "ctrl+o", "ctrl+s":
		return send(t, m, tea.KeyPressMsg{Code: rune(k[len(k)-1]), Mod: tea.ModCtrl})
	}
	return send(t, m, tea.KeyPressMsg{Code: rune(k[0]), Text: k})
}

func screen(m Model) string { return m.View().Content }

func TestSearchShowsSanitizedResults(t *testing.T) {
	m := newModel(t)
	m = typeText(t, m, "beacon to 198.51.100[.]7 and example.com")
	m = key(t, m, "enter")
	if len(m.reports) != 2 || m.reports[0].Verdict != provider.VerdictMalicious {
		t.Fatalf("reports = %+v", m.reports)
	}
	out := screen(m)
	for _, bad := range []string{"\x1b[2J", "\x1b]0;", "\x07"} {
		if strings.Contains(out, bad) {
			t.Errorf("screen contains control sequence %q", bad)
		}
	}
	for _, want := range []string{"198.51.100.7", "malicious", "Owner", "seen", "2 indicators searched"} {
		if !strings.Contains(out, want) {
			t.Errorf("screen missing %q", want)
		}
	}
	// Moving the selection shows the other report.
	m = key(t, m, "j")
	if m.sel != 1 || !strings.Contains(m.detail.View(), "example.com") {
		t.Errorf("selection did not move: sel=%d", m.sel)
	}
}

func TestOfflineModeUsesOnlyLocalSources(t *testing.T) {
	m := newModel(t)
	m = key(t, m, "ctrl+o")
	if !m.offline || !strings.Contains(screen(m), "OFFLINE") {
		t.Fatal("offline mode not shown")
	}
	m = typeText(t, m, "8.8.8.8")
	m = key(t, m, "enter")
	if r := m.reports[0].Results; len(r) != 1 || r[0].Provider != "local" {
		t.Errorf("offline search queried %+v", r)
	}
}

func TestInvalidInputShowsError(t *testing.T) {
	m := newModel(t)
	m = key(t, m, "enter")
	if !m.statusErr || len(m.reports) != 0 {
		t.Errorf("empty search must show an error, status=%q", m.status)
	}
}

func TestCaseWorkflow(t *testing.T) {
	t.Chdir(t.TempDir())
	m := newModel(t)
	m = key(t, m, "esc") // leave the search box
	m = key(t, m, "2")
	if m.tab != tabCases || !strings.Contains(screen(m), "No cases yet") {
		t.Fatal("cases tab not shown")
	}

	m = key(t, m, "n")
	m = typeText(t, m, "inc-1")
	m = key(t, m, "enter")
	if len(m.caseList) != 1 || m.caseList[0].Name != "inc-1" {
		t.Fatalf("case not created: %v (%s)", m.caseList, m.status)
	}

	m = key(t, m, "enter")
	if m.open == nil {
		t.Fatal("case not opened")
	}
	steps := []struct {
		key, text, want string
	}{
		{"i", "198.51.100.7 example.com", "2 new indicators added"},
		{"s", "", "2 indicators searched"},
		{"m", "Initial access via phishing", "note added"},
		{"e", "md", "exported to inc-1.md"},
		{"c", "", "case closed"},
	}
	for _, s := range steps {
		m = key(t, m, s.key)
		if s.text != "" {
			if s.key == "e" {
				m.prompt.input.SetValue("")
			}
			m = typeText(t, m, s.text)
			m = key(t, m, "enter")
		}
		if !strings.Contains(m.status, s.want) {
			t.Fatalf("after %q: status %q, want %q", s.key, m.status, s.want)
		}
	}
	if m.open.Case.Status != "closed" || len(m.open.Case.Notes) != 1 || len(m.open.Items) != 2 {
		t.Errorf("case = %+v", m.open.Case)
	}
	info, err := os.Stat("inc-1.md")
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("export file: %v %v", info, err)
	}
	// A second export never overwrites the first.
	m = key(t, m, "e")
	m.prompt.input.SetValue("md")
	m = key(t, m, "enter")
	if !m.statusErr || !strings.Contains(m.status, "already exists") {
		t.Errorf("overwrite must be refused: %q", m.status)
	}

	m = key(t, m, "esc")
	if m.open != nil {
		t.Error("esc must go back to the case list")
	}
}

func TestSaveSearchResultsToCase(t *testing.T) {
	m := newModel(t)
	if err := m.cfg.Cases.Create(context.Background(), "inc-2", "", "", nil); err != nil {
		t.Fatal(err)
	}
	m = typeText(t, m, "198.51.100.7")
	m = key(t, m, "enter")
	m = key(t, m, "ctrl+s")
	if m.prompt == nil {
		t.Fatal("save prompt not shown")
	}
	m = typeText(t, m, "inc-2")
	m = key(t, m, "enter")
	if !strings.Contains(m.status, "1 results saved to case inc-2") {
		t.Fatalf("status = %q", m.status)
	}
	v, err := m.cfg.Cases.Load(context.Background(), "inc-2")
	if err != nil || len(v.Items) != 1 || v.Items[0].Verdict != provider.VerdictMalicious {
		t.Errorf("case items = %+v, %v", v, err)
	}
}

func TestPromptCanBeCancelled(t *testing.T) {
	m := newModel(t)
	m = key(t, m, "esc")
	m = key(t, m, "2")
	m = key(t, m, "n")
	m = key(t, m, "esc")
	if m.prompt != nil || m.status != "cancelled" {
		t.Errorf("prompt not cancelled: %q", m.status)
	}
}

func TestTabsRenderAtSmallSizes(t *testing.T) {
	m := newModel(t)
	m = key(t, m, "esc")
	for _, size := range []tea.WindowSizeMsg{{Width: 40, Height: 12}, {Width: 200, Height: 60}} {
		m = send(t, m, size)
		for _, k := range []string{"1", "2", "3", "?"} {
			m = key(t, m, k)
			if v := m.View(); !v.AltScreen || v.Content == "" {
				t.Errorf("tab %s at %dx%d: empty view", k, size.Width, size.Height)
			}
		}
	}
	if !strings.Contains(screen(m), "offline mode") {
		t.Error("help tab missing")
	}
}

func TestParseInput(t *testing.T) {
	tests := map[string]int{
		"8.8.8.8":                             1,
		"Lazarus Group":                       1,
		"hxxp://evil[.]example[.]com 1.1.1.1": 2,
		"T1059.001":                           1,
	}
	for in, want := range tests {
		got, err := parseInput(in)
		if err != nil || len(got) != want {
			t.Errorf("parseInput(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := parseInput("   "); err == nil {
		t.Error("empty input must fail")
	}
}

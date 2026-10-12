package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ciruzz00/astro/internal/logs"
)

// authLog writes an invented auth.log: failed logins, one with escape
// sequences in the user name, then a successful one from the same address.
func authLog(t *testing.T, failures int) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	for i := range failures {
		fmt.Fprintf(&b, "Oct 11 22:%02d:%02d web01 sshd[1]: Failed password for root from 203.0.113.9 port %d ssh2\n",
			i/60, i%60, 40000+i)
	}
	b.WriteString("Oct 11 22:30:00 web01 sshd[1]: Failed password for invalid user ev\x1b]0;pwned\x07il from 198.51.100.7 port 4100 ssh2\n")
	b.WriteString("Oct 11 22:31:00 web01 sshd[1]: Accepted password for root from 203.0.113.9 port 4101 ssh2\n")
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	return dir
}

// openCase creates a case and opens it in the Cases tab.
func openCase(t *testing.T, name string) Model {
	t.Helper()
	m := newModel(t)
	if err := m.cfg.Cases.Create(context.Background(), name, "", "", nil); err != nil {
		t.Fatal(err)
	}
	m = key(t, m, "esc")
	m = key(t, m, "2")
	m = key(t, m, "enter")
	if m.open == nil || m.open.Case.Name != name {
		t.Fatalf("case %s not opened: %s", name, m.status)
	}
	return m
}

func importLogs(t *testing.T, m Model, path string) Model {
	t.Helper()
	m = key(t, m, "l")
	m = typeText(t, m, path)
	return key(t, m, "enter")
}

func press(t *testing.T, m Model, code rune) Model {
	t.Helper()
	return send(t, m, tea.KeyPressMsg{Code: code})
}

func TestImportLogsAndBrowseTimeline(t *testing.T) {
	m := openCase(t, "inc-1")
	if !strings.Contains(screen(m), "no logs yet: l imports") {
		t.Error("an empty case must say how to import logs")
	}
	m = importLogs(t, m, filepath.Join(t.TempDir(), "missing"))
	if !m.statusErr {
		t.Errorf("a missing path must fail: %q", m.status)
	}
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "notes.txt"), []byte("not a log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m = importLogs(t, m, empty)
	if !m.statusErr || !strings.Contains(m.status, "no supported log") {
		t.Errorf("a folder without logs: %q", m.status)
	}

	dir := authLog(t, 520) // more than one page of the timeline
	m = importLogs(t, m, dir)
	if m.statusErr || !strings.Contains(m.status, "1 files imported, 522 events") || !strings.Contains(m.status, "critical") {
		t.Fatalf("import: %q", m.status)
	}
	if !strings.Contains(screen(m), "t Timeline 522") {
		t.Errorf("tabs do not count the events:\n%s", screen(m))
	}
	m = importLogs(t, m, dir)
	if !m.statusErr || !strings.Contains(m.status, "already in the case") {
		t.Errorf("a second import: %q", m.status)
	}

	m = key(t, m, "t")
	if m.mode != modeTimeline || m.tl.total != 522 || len(m.tl.events) != timelinePage {
		t.Fatalf("timeline: mode %d, %d of %d loaded", m.mode, len(m.tl.events), m.tl.total)
	}
	out := screen(m)
	for _, want := range []string{"event 1 of 522", "2026-10-11 22:00:00~", "auth.log", "Evidence", "SHA-256", "line 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("timeline screen lacks %q", want)
		}
	}

	// The last event lives on the second page: G loads it.
	m = key(t, m, "G")
	if m.tl.offset != timelinePage || m.tl.pos() != 521 || !strings.Contains(screen(m), "event 522 of 522") {
		t.Fatalf("G: offset %d pos %d", m.tl.offset, m.tl.pos())
	}
	if !strings.Contains(m.detail.View(), "CRITICAL") || !strings.Contains(m.detail.View(), "203.0.113.9") {
		t.Errorf("detail of the last event:\n%s", m.detail.View())
	}
	m = key(t, m, "k") // the one before: the escaped user name
	if strings.ContainsAny(screen(m), "\x07") || strings.Contains(screen(m), "\x1b]0;") {
		t.Error("control sequences from the log reach the screen")
	}
	// Going back past the start of the page loads the previous one.
	for range 21 {
		m = key(t, m, "k")
	}
	if m.tl.offset != 0 || m.tl.pos() != 499 {
		t.Errorf("up across pages: offset %d pos %d", m.tl.offset, m.tl.pos())
	}
	m = press(t, m, tea.KeyPgUp)
	if m.tl.pos() >= 499 {
		t.Errorf("pgup did not move: %d", m.tl.pos())
	}

	// Severity filter: only the critical login is left.
	for range 4 {
		m = key(t, m, "+")
	}
	if m.tl.minSev != logs.Critical || m.tl.total != 1 || !strings.Contains(screen(m), "filter: critical") {
		t.Fatalf("severity filter: %v, %d events", m.tl.minSev, m.tl.total)
	}
	m = key(t, m, "+") // already at the top
	if m.tl.minSev != logs.Critical {
		t.Error("severity went past critical")
	}
	for range 4 {
		m = key(t, m, "-")
	}

	// Text filter, then cleared with an empty value.
	m = key(t, m, "/")
	m = typeText(t, m, "invalid user")
	m = key(t, m, "enter")
	if m.tl.total != 1 || m.busy || !strings.Contains(screen(m), `filter: "invalid user"`) {
		t.Errorf("text filter: %d events, busy %v", m.tl.total, m.busy)
	}
	m = key(t, m, "/")
	m.prompt.input.SetValue("")
	m = key(t, m, "enter")
	if m.tl.total != 522 || m.tl.grep != "" {
		t.Errorf("cleared filter: %d events", m.tl.total)
	}

	m = key(t, m, "esc")
	if m.mode != modeIndicators || m.open == nil {
		t.Error("esc must go back to the indicators of the case")
	}
}

func TestFindingsView(t *testing.T) {
	m := openCase(t, "inc-2")
	m = key(t, m, "f")
	if !strings.Contains(screen(m), "No logs in this case") {
		t.Error("findings of a case without logs")
	}
	m = importLogs(t, m, authLog(t, 12))
	if m.mode != modeFindings || len(m.logs.findings) < 2 {
		t.Fatalf("findings: %+v (%s)", m.logs.findings, m.status)
	}
	if m.logs.findings[0].Severity != logs.Critical {
		t.Errorf("most severe first: %v", m.logs.findings[0].Severity)
	}
	out := screen(m)
	for _, want := range []string{"CRITICAL Successful login after a brute force", "T1078", "attack.mitre.org/techniques/T1078/", "203.0.113.9"} {
		if !strings.Contains(out, want) {
			t.Errorf("findings screen lacks %q:\n%s", want, out)
		}
	}
	m = key(t, m, "j")
	if m.findSel != 1 || !strings.Contains(m.detail.View(), "First 10 of") {
		t.Errorf("second finding:\n%s", m.detail.View())
	}
	for range 4 {
		m = key(t, m, "+")
	}
	if n := len(m.shownFindings()); n != 1 || m.findSel != 0 {
		t.Errorf("critical findings = %d", n)
	}
	m = key(t, m, "i")
	if m.statusErr || !strings.Contains(m.status, "new indicators added from the findings") || len(m.open.Items) == 0 {
		t.Errorf("add indicators: %q, %d items", m.status, len(m.open.Items))
	}
	m = key(t, m, "r")
	if !strings.Contains(m.status, "analysis: ") {
		t.Errorf("analyze again: %q", m.status)
	}
	m = key(t, m, "t")
	if m.mode != modeTimeline || m.tl.total != 14 {
		t.Errorf("t from the findings: mode %d, %d events", m.mode, m.tl.total)
	}
}

func TestLogViewsKeepTheLayout(t *testing.T) {
	m := openCase(t, "inc-3")
	m = importLogs(t, m, authLog(t, 30))
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 100, Height: 30}, {Width: 200, Height: 60}} {
		m = send(t, m, size)
		for _, k := range []string{"t", "f"} {
			m = key(t, m, k)
			out := screen(m)
			if lines := strings.Count(out, "\n") + 1; lines > size.Height {
				t.Errorf("%s at %dx%d: %d lines", k, size.Width, size.Height, lines)
			}
			for _, l := range strings.Split(out, "\n") {
				if w := lipgloss.Width(l); w > size.Width {
					t.Errorf("%s at %dx%d: line of %d columns: %q", k, size.Width, size.Height, w, l)
					break
				}
			}
		}
	}
}

package render

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/store"
)

var t0 = time.Date(2026, 10, 11, 21, 0, 0, 0, time.UTC)

func sample() []logs.Event {
	return []logs.Event{
		{Time: t0, Severity: logs.Critical, Host: "web01", Source: "auth.log", User: "root", SrcIP: "203.0.113.9",
			Message: "SSH login accepted\nfor root \x1b[31mred", Ref: logs.EvidenceRef{Path: "/e/var/log/auth.log", Record: "line 3"}},
		{Time: t0.Add(time.Second), Severity: logs.Low, YearGuessed: true, Source: ".bash_history", Message: "=cmd|' /C calc'!A0",
			CommandLine: "@SUM(1+1)", Ref: logs.EvidenceRef{Path: `C:\e\.bash_history`, Record: "line 1"}},
		{Time: t0.Add(2 * time.Second), TimeUnknown: true, Message: "id"},
	}
}

func TestTimeline(t *testing.T) {
	var b bytes.Buffer
	if err := Timeline(&b, sample(), Style{}, 0); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %q", lines)
	}
	if !strings.HasPrefix(lines[0], "2026-10-11 21:00:00  CRITICAL web01") || !strings.Contains(lines[0], "root 203.0.113.9") ||
		!strings.Contains(lines[0], "SSH login accepted for root [31mred") || strings.ContainsRune(lines[0], 0x1b) {
		t.Errorf("line 0 = %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "2026-10-11 21:00:01~ LOW") || !strings.HasPrefix(lines[2], "2026-10-11 21:00:02? INFO") {
		t.Errorf("time flags = %q / %q", lines[1], lines[2])
	}
	b.Reset()
	long := sample()[:1]
	long[0].Message = strings.Repeat("x", 300)
	if err := Timeline(&b, long, Style{}, 120); err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(strings.TrimRight(b.String(), "\n"))); n != 120 {
		t.Errorf("line of %d runes on a 120-column terminal", n)
	}
	b.Reset()
	if err := Timeline(&b, sample()[:1], Style{Color: true}, 0); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "\x1b[1;31m2026-10-11") {
		t.Errorf("critical row not red: %q", b.String())
	}
}

func TestTimelineCSVIsSafe(t *testing.T) {
	var b bytes.Buffer
	if err := TimelineCSV(&b, sample()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil || len(rows) != 4 {
		t.Fatalf("rows = %d, %v", len(rows), err)
	}
	if rows[2][13] != "'=cmd|' /C calc'!A0" || rows[2][12] != "'@SUM(1+1)" || rows[2][17] != "true" {
		t.Errorf("formula not neutralized: %q", rows[2])
	}
	if rows[1][0] != "2026-10-11T21:00:00Z" || rows[1][1] != "critical" || rows[1][16] != "line 3" {
		t.Errorf("row = %q", rows[1])
	}
}

func TestFindingsAndEvidence(t *testing.T) {
	fs := []logs.Finding{{RuleID: "x", Title: "Brute force", Severity: logs.High, Technique: "T1110", First: t0, Last: t0.Add(time.Minute),
		Host: "web01", SrcIP: "203.0.113.9", Summary: "12 failed logins", Count: 12, EventIDs: []int64{1}}}
	var b bytes.Buffer
	cited := func(*logs.Finding) []logs.Event { return sample()[:1] }
	if err := Findings(&b, fs, Style{}, cited); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"HIGH     Brute force  T1110", "2026-10-11 21:00:00 → 2026-10-11 21:01:00", "12 event(s)", "host web01, from 203.0.113.9",
		"12 failed logins", "auth.log line 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("findings output lacks %q:\n%s", want, out)
		}
	}
	b.Reset()
	first, last := t0, t0.Add(time.Hour)
	ev := []store.Evidence{{ID: 1, Name: "auth.log", Path: "/e/auth.log", Kind: logs.KindSyslog, Size: 10, Events: 2, ParseErrors: 1,
		SHA256: "abc", SHA1: "def", MD5: "123", FirstEvent: &first, LastEvent: &last, Compressed: true}}
	if err := Evidence(&b, ev, Style{}); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); !strings.Contains(out, "#1 auth.log  syslog") || !strings.Contains(out, "1 unparsable") || !strings.Contains(out, "sha256 abc") {
		t.Errorf("evidence = %s", out)
	}
	b.Reset()
	_ = Custody(&b, []store.CustodyEntry{{At: t0, Action: "imported", Actor: "analyst", Detail: "size 10"}}, errors.New("entry 2"), Style{})
	if !strings.Contains(b.String(), "does NOT verify") {
		t.Errorf("custody = %s", b.String())
	}
}

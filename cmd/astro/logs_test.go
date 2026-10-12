package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// astro runs the command line with a private data directory.
func astro(t *testing.T, dataDir string, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"--data-dir", dataDir, "--no-color"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestLogsCommands(t *testing.T) {
	for _, k := range []string{"ASTRO_VIRUSTOTAL_KEY", "ASTRO_ABUSECH_KEY", "ASTRO_ABUSEIPDB_KEY", "ASTRO_OTX_KEY", "ASTRO_SHODAN_KEY", "ASTRO_GREYNOISE_KEY", "ASTRO_NVD_KEY", "ASTRO_ANALYST"} {
		t.Setenv(k, "")
	}
	data, logsDir := t.TempDir(), t.TempDir()
	var b strings.Builder
	for i := range 12 {
		fmt.Fprintf(&b, "Oct 11 21:00:%02d web01 sshd[1]: Failed password for root from 203.0.113.9 port 4%d ssh2\n", i, i)
	}
	b.WriteString("Oct 11 21:01:00 web01 sshd[1]: Accepted password for root from 203.0.113.9 port 4100 ssh2\n")
	auth := filepath.Join(logsDir, "auth.log")
	if err := os.WriteFile(auth, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(auth, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logsDir, "notes.txt"), []byte("not a log\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := astro(t, data, "logs", "import", "nope", logsDir); err == nil || !strings.Contains(err.Error(), "astro case new nope") {
		t.Errorf("import into a missing case: %v", err)
	}
	if _, err := astro(t, data, "case", "new", "inc-1"); err != nil {
		t.Fatal(err)
	}
	out, err := astro(t, data, "logs", "import", "inc-1", logsDir, "--actor", "j.doe", "--add-indicators")
	if err != nil {
		t.Fatalf("import: %v\n%s", err, out)
	}
	for _, want := range []string{"1 files imported, 13 events", "1 other files skipped", "CRITICAL Successful login after a brute force",
		"HIGH     Brute force of logins", "new indicators added to the case"} {
		if !strings.Contains(out, want) {
			t.Errorf("import output lacks %q:\n%s", want, out)
		}
	}

	out, err = astro(t, data, "logs", "timeline", "inc-1", "--severity", "critical")
	if err != nil || !strings.Contains(out, "2026-10-11 21:01:00~ CRITICAL web01") || strings.Count(out, "\n") != 1 {
		t.Errorf("timeline: %v\n%s", err, out)
	}
	out, err = astro(t, data, "logs", "timeline", "inc-1", "--limit", "5", "--offset", "10")
	if err != nil || !strings.Contains(out, "showing 11-13 of 13 events") {
		t.Errorf("paged timeline: %v\n%s", err, out)
	}
	out, _ = astro(t, data, "logs", "timeline", "inc-1", "--from", "2026-10-11 21:00:10", "--csv")
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 4 || !strings.HasPrefix(lines[0], "time_utc,severity") {
		t.Errorf("csv export from 21:00:10 = %d lines:\n%s", len(lines), out)
	}
	if _, err := astro(t, data, "logs", "timeline", "inc-1", "--from", "yesterday"); err == nil {
		t.Error("bad --from accepted")
	}

	out, err = astro(t, data, "logs", "findings", "inc-1", "--json")
	var fs []struct {
		RuleID   string  `json:"rule_id"`
		EventIDs []int64 `json:"event_ids"`
	}
	if err != nil || json.Unmarshal([]byte(out), &fs) != nil || len(fs) < 2 || fs[0].RuleID != "auth-success-after-brute-force" || len(fs[0].EventIDs) == 0 {
		t.Errorf("findings json: %v\n%s", err, out)
	}
	out, _ = astro(t, data, "logs", "findings", "inc-1", "--events", "--severity", "high")
	if !strings.Contains(out, "auth.log line 13") || strings.Contains(out, "MEDIUM") {
		t.Errorf("findings with events:\n%s", out)
	}

	out, err = astro(t, data, "logs", "evidence", "inc-1", "--custody")
	if err != nil || !strings.Contains(out, "chain of custody verified") || !strings.Contains(out, "j.doe") || !strings.Contains(out, "imported") {
		t.Errorf("evidence: %v\n%s", err, out)
	}
	out, _ = astro(t, data, "logs", "import", "inc-1", auth)
	if !strings.Contains(out, "already in the case") {
		t.Errorf("re-import:\n%s", out)
	}
	out, err = astro(t, data, "case", "show", "inc-1")
	if err != nil || !strings.Contains(out, "203[.]0[.]113[.]9") {
		t.Errorf("indicator not added to the case: %v\n%s", err, out)
	}
	if _, err := astro(t, data, "logs", "import", "inc-1", auth, "--tz", "Mars/Olympus"); err == nil {
		t.Error("unknown zone accepted")
	}
}

func TestActorAndTimeFlag(t *testing.T) {
	t.Setenv("ASTRO_ANALYST", "")
	if actor("") != "analyst" || actor(" j.doe ") != "j.doe" {
		t.Error("actor default/flag")
	}
	t.Setenv("ASTRO_ANALYST", "team-ir")
	if actor("") != "team-ir" {
		t.Error("actor from environment")
	}
	for in, want := range map[string]string{"2026-10-11": "2026-10-11T00:00:00Z", "2026-10-11 21:30:05": "2026-10-11T21:30:05Z",
		"2026-10-11T23:30:05+02:00": "2026-10-11T21:30:05Z"} {
		got, err := timeFlag("from", in)
		if err != nil || got.Format(time.RFC3339) != want {
			t.Errorf("timeFlag(%q) = %v, %v", in, got, err)
		}
	}
}

func TestLogsImportReadsCollectionZone(t *testing.T) {
	data, col := t.TempDir(), t.TempDir()
	for path, content := range map[string]string{
		"[root]/etc/timezone":     "Europe/Rome\n",
		"[root]/var/log/auth.log": "Oct 11 23:00:00 web01 sshd[1]: Accepted password for alice from 203.0.113.9 port 4100 ssh2\n",
	} {
		p := filepath.Join(col, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := astro(t, data, "case", "new", "inc-tz"); err != nil {
		t.Fatal(err)
	}
	out, err := astro(t, data, "logs", "import", "inc-tz", col, "--year", "2026")
	if err != nil || !strings.Contains(out, "read in Europe/Rome") {
		t.Fatalf("import: %v\n%s", err, out)
	}
	// 23:00 in Rome (UTC+2 in October) is 21:00 UTC.
	out, _ = astro(t, data, "logs", "timeline", "inc-tz")
	if !strings.Contains(out, "2026-10-11 21:00:00") {
		t.Errorf("timeline not in UTC:\n%s", out)
	}
}

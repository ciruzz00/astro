package evidence

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/store"
)

// lineParser is a stand-in syslog parser: one event per line, the host is
// the fourth word, lines starting with "!" are malformed.
type lineParser struct{}

func (lineParser) Kind() logs.Kind { return logs.KindSyslog }

func (lineParser) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if strings.HasPrefix(line, "!") {
			st.Errors++
			continue
		}
		f := strings.Fields(line)
		host := ""
		if len(f) > 3 {
			host = f[3]
		}
		t := time.Date(2026, 10, 11, 21, 0, n, 0, time.UTC)
		if err := emit(&logs.Event{Time: t, Host: host, Kind: "line", Message: line, Ref: logs.EvidenceRef{Record: "line"}}); err != nil {
			return st, err
		}
		st.Events++
	}
	return st, sc.Err()
}

const authLog = "Oct 11 21:00:01 web01 sshd[1]: Failed password for root from 203.0.113.9\n" +
	"! garbage line\n" +
	"Oct 11 21:00:05 web01 sshd[1]: Accepted password for root from 203.0.113.9\n"

func setup(t *testing.T) (*store.Store, *Importer, string) {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.CreateCase(ctx, store.Case{Name: "inc-1", TLP: "AMBER"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return s, New(s, lineParser{}), t.TempDir()
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func gz(t *testing.T, s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestImportDirectory(t *testing.T) {
	s, im, dir := setup(t)
	ctx := context.Background()
	rotated := gz(t, strings.ReplaceAll(authLog, "web01", "web02"))
	write(t, filepath.Join(dir, "var/log/auth.log"), []byte(authLog))
	write(t, filepath.Join(dir, "var/log/auth.log.2.gz"), rotated)
	write(t, filepath.Join(dir, "notes.txt"), []byte("not a log\n"))
	write(t, filepath.Join(dir, "home/root/.bash_history"), []byte("id\nwhoami\n"))
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(dir, "var/log/auth.log"), filepath.Join(dir, "link.log")); err != nil {
			t.Fatal(err)
		}
	}

	res, err := im.Import(ctx, "inc-1", dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]FileResult{}
	for _, f := range res.Files {
		byName[filepath.Base(f.Path)] = f
	}
	plain := byName["auth.log"]
	if !plain.Imported() || plain.Kind != logs.KindSyslog || plain.Events != 2 || plain.Errors != 1 || plain.SHA256 != sha([]byte(authLog)) || plain.Warning != "" {
		t.Errorf("auth.log = %+v", plain)
	}
	if r := byName["auth.log.2.gz"]; !r.Imported() || r.Events != 2 || r.SHA256 != sha(rotated) {
		t.Errorf("auth.log.2.gz = %+v", r)
	}
	if r := byName["notes.txt"]; r.Imported() || r.Skipped != "not a recognized log format" {
		t.Errorf("notes.txt = %+v", r)
	}
	if r := byName[".bash_history"]; !r.Imported() || r.Kind != logs.KindBashHistory || !strings.Contains(r.Warning, "no parser") {
		t.Errorf(".bash_history = %+v", r)
	}
	if runtime.GOOS != "windows" {
		if r := byName["link.log"]; r.Imported() || r.Skipped != "symbolic link not followed" {
			t.Errorf("link.log = %+v", r)
		}
	}
	if imported, _, events := res.Counts(); imported != 3 || events != 4 {
		t.Errorf("Counts = %d imported, %d events", imported, events)
	}

	ev, err := s.CaseEvidence(ctx, "inc-1")
	if err != nil || len(ev) != 3 {
		t.Fatalf("CaseEvidence = %d, %v", len(ev), err)
	}
	for _, e := range ev {
		if e.Name == "auth.log.2.gz" && (!e.Compressed || e.Host != "web02" || e.Events != 2 || e.FirstEvent == nil) {
			t.Errorf("rotated evidence = %+v", e)
		}
		if len(e.SHA1) != 40 || len(e.MD5) != 32 {
			t.Errorf("hashes of %s = %s %s", e.Name, e.SHA1, e.MD5)
		}
		if err := s.VerifyCustody(ctx, e.ID); err != nil {
			t.Errorf("custody of %s: %v", e.Name, err)
		}
		chain, _ := s.Custody(ctx, e.ID)
		want := 2
		if e.Kind == logs.KindBashHistory {
			want = 1 // inventoried only
		}
		if len(chain) != want || chain[0].Action != store.CustodyImported || !strings.Contains(chain[0].Detail, e.SHA256) {
			t.Errorf("custody of %s = %+v", e.Name, chain)
		}
	}

	events, total, err := s.Events(ctx, "inc-1", store.EventFilter{Host: "web02"})
	if err != nil || total != 2 || events[0].Source != "auth.log.2" || events[0].Seq != 1 || events[1].Seq != 2 ||
		events[0].Ref.SHA256 != sha(rotated) || !strings.HasSuffix(events[0].Ref.Path, "auth.log.2.gz") {
		t.Errorf("events = %+v, %d, %v", events, total, err)
	}

	// Importing again finds only duplicates.
	again, err := im.Import(ctx, "inc-1", dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if imported, _, _ := again.Counts(); imported != 0 || !againHas(again, "auth.log") {
		t.Errorf("re-import = %+v", again.Files)
	}
}

func againHas(r *Result, name string) bool {
	for _, f := range r.Files {
		if filepath.Base(f.Path) == name && f.Duplicate {
			return true
		}
	}
	return false
}

func TestImportSingleFileAndOptions(t *testing.T) {
	s, im, dir := setup(t)
	ctx := context.Background()
	unknown := filepath.Join(dir, "sample.bin")
	write(t, unknown, []byte{0x4d, 0x5a, 0x90, 0x00})
	res, err := im.Import(ctx, "inc-1", unknown, Options{})
	if err != nil || len(res.Files) != 1 || !res.Files[0].Imported() || res.Files[0].Kind != logs.KindUnknown {
		t.Fatalf("explicit unknown file = %+v, %v", res, err)
	}

	log := filepath.Join(dir, "secure")
	write(t, log, []byte(authLog))
	im.MaxEvents = 1
	res, err = im.Import(ctx, "inc-1", log, Options{Host: "forced"})
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Files[0]; r.Events != 1 || !r.Truncated {
		t.Errorf("limited import = %+v", r)
	}
	events, _, _ := s.Events(ctx, "inc-1", store.EventFilter{})
	if len(events) != 1 || events[0].Host != "forced" {
		t.Errorf("events = %+v", events)
	}
	ev, _ := s.CaseEvidence(ctx, "inc-1")
	if last := ev[len(ev)-1]; !last.Truncated || last.Host != "forced" {
		t.Errorf("evidence = %+v", last)
	}

	im.MaxFileSize = 2
	big := filepath.Join(dir, "big.log")
	write(t, big, []byte(authLog))
	if res, _ := im.Import(ctx, "inc-1", big, Options{}); res.Files[0].Imported() || !strings.Contains(res.Files[0].Skipped, "limit") {
		t.Errorf("oversized file = %+v", res.Files[0])
	}
}

func TestImportErrors(t *testing.T) {
	_, im, dir := setup(t)
	ctx := context.Background()
	if _, err := im.Import(ctx, "nope", dir, Options{}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown case: %v", err)
	}
	if _, err := im.Import(ctx, "inc-1", filepath.Join(dir, "missing"), Options{}); err == nil {
		t.Error("missing path accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	target := filepath.Join(dir, "auth.log")
	write(t, target, []byte(authLog))
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := im.Import(ctx, "inc-1", link, Options{}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("symlink root: %v", err)
	}
	// A file that claims to be gzip but is not is detected on its raw bytes.
	write(t, filepath.Join(dir, "sub", "fake.gz"), []byte{0x1f, 0x8b, 'n', 'o', 'p', 'e'})
	res, err := im.Import(ctx, "inc-1", filepath.Join(dir, "sub"), Options{})
	if err != nil || len(res.Files) != 1 || res.Files[0].Imported() {
		t.Errorf("fake gzip = %+v, %v", res, err)
	}
}

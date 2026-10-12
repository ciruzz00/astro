package bodyfile

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// An invented host: a dropper written to /tmp, made executable and run, a
// directory and pseudo filesystem entries that must stay quiet.
const sample = "0|/|2|drwxr-xr-x|0|0|4096|1775600000|1775400000|1775400000|1775400000\n" +
	"0|/tmp/.x/run|1201|-rwxr-xr-x|1000|1000|250|1775500300|1775500000|1775500200|1775500000\n" +
	"d41d8cd98f00b204e9800998ecf8427e|/home/alice/a|b.txt|1202|r/rrw-r--r--|1000|1000|10|1775500000|1775500000|1775500000|0\n" +
	"0|/proc/1/status|3|-r--r--r--|0|0|0|1775600000|1775600000|1775600000|0\n" +
	"0|/dev/shm/k|4|-rwx------|0|0|99|1775500000|1775500000|1775500000|1775500000\n" +
	"not|a|bodyfile|line\n" +
	"0|/bad|5|-rw-r--r--|0|0|x|1|2|3|4\n"

func parse(t *testing.T, in string, opts logs.Options) ([]*logs.Event, logs.Stats) {
	t.Helper()
	var evs []*logs.Event
	st, err := New().Parse(context.Background(), strings.NewReader(in), opts, func(e *logs.Event) error {
		evs = append(evs, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return evs, st
}

func TestDetect(t *testing.T) {
	if k := logs.Detect("bodyfile.txt", []byte(sample)); k != logs.KindBodyfile {
		t.Errorf("Detect = %s", k)
	}
	if k := logs.Detect("notes.txt", []byte("a|b|c\n")); k == logs.KindBodyfile {
		t.Error("plain text detected as bodyfile")
	}
}

func TestParse(t *testing.T) {
	evs, st := parse(t, sample, logs.Options{Source: "bodyfile.txt", Host: "web01"})
	if st.Errors != 2 {
		t.Errorf("errors = %d, want 2", st.Errors)
	}
	byPath := map[string][]*logs.Event{}
	for _, e := range evs {
		byPath[e.Fields["path"]] = append(byPath[e.Fields["path"]], e)
		if e.Host != "web01" || e.Source != "bodyfile.txt" || !strings.HasPrefix(e.Ref.Record, "line ") {
			t.Errorf("event metadata = %+v", e)
		}
	}
	if _, ok := byPath["/proc/1/status"]; ok {
		t.Error("pseudo filesystem entries must be skipped")
	}
	// The root directory: created and modified at the same time, read later
	// (a directory read is not an event).
	if root := byPath["/"]; len(root) != 1 || root[0].Kind != KindCreated || root[0].Fields["macb"] != "m.cb" {
		t.Errorf("/ = %+v", root)
	}
	run := byPath["/tmp/.x/run"]
	if len(run) != 3 {
		t.Fatalf("/tmp/.x/run: %d events", len(run))
	}
	for i, want := range []struct{ kind, macb string }{{KindCreated, "m..b"}, {KindChanged, "..c."}, {KindAccessed, ".a.."}} {
		if run[i].Kind != want.kind || run[i].Fields["macb"] != want.macb {
			t.Errorf("event %d = %s %s, want %s %s", i, run[i].Kind, run[i].Fields["macb"], want.kind, want.macb)
		}
	}
	if !run[0].Time.Equal(time.Unix(1775500000, 0).UTC()) || run[0].Fields["mode"] != "-rwxr-xr-x" || run[0].Fields["uid"] != "1000" {
		t.Errorf("first event = %+v", run[0])
	}
	if !strings.Contains(run[0].Message, "/tmp/.x/run") {
		t.Errorf("message = %q", run[0].Message)
	}
	// A "|" in the name, the fls mode format and an MD5.
	odd := byPath["/home/alice/a|b.txt"]
	if len(odd) != 1 || odd[0].Fields["mode"] != "rrw-r--r--" || odd[0].Fields["md5"] != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("odd name = %+v", odd)
	}
	if len(byPath["/dev/shm/k"]) != 1 {
		t.Error("/dev/shm is a real place for files and must be kept")
	}
}

func TestPackageDatesBeforeInstallAreSkipped(t *testing.T) {
	in := "0|/|2|drwxr-xr-x|0|0|4096|1775600000|1775400000|1775400000|1775400000\n" +
		// A package file: content from 2021, installed with the system.
		"0|/usr/bin/tool|9|-rwxr-xr-x|0|0|10|1775500000|1620000000|1775400000|1775400000\n"
	evs, _ := parse(t, in, logs.Options{})
	for _, e := range evs {
		if e.Time.Unix() < 1775400000-86400 {
			t.Errorf("package date kept: %+v", e)
		}
	}
	if len(evs) != 3 || evs[1].Fields["mtime"] != "2021-05-03T00:00:00Z" {
		t.Errorf("events = %d, second %+v", len(evs), evs[1])
	}
}

func TestLimit(t *testing.T) {
	evs, st := parse(t, sample, logs.Options{MaxEvents: 2})
	if len(evs) != 2 || !st.Truncated {
		t.Errorf("limit: %d events, truncated %v", len(evs), st.Truncated)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sample)
	f.Add("0|" + strings.Repeat("|", 30) + "\n")
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = New().Parse(context.Background(), strings.NewReader(in), logs.Options{}, func(*logs.Event) error { return nil })
	})
}

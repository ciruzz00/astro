package docker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/logs/access"
)

const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParse(t *testing.T) {
	big := strings.Repeat("a", 20000)
	in := `{"log":"Starting web app...\n","stream":"stdout","time":"2026-10-11T21:00:00.123456789Z"}` + "\n" +
		`{"log":"203.0.113.9 - - [11/Oct/2026:21:00:01 +0000] \"GET /login HTTP/1.1\" 200 1500 \"-\" \"curl/8.5.0\"\n","stream":"stdout","time":"2026-10-11T21:00:01.500000000Z"}` + "\n" +
		`{"log":"` + big[:16384] + `","stream":"stderr","time":"2026-10-11T21:00:02Z"}` + "\n" +
		`{"log":"` + big[16384:] + `\n","stream":"stderr","time":"2026-10-11T21:00:02.1Z"}` + "\n" +
		"{broken json\n" +
		`{"log":"x\n","stream":"stdout","time":"yesterday"}` + "\n"
	var evs []*logs.Event
	st, err := New().Parse(context.Background(), strings.NewReader(in),
		logs.Options{Source: id + "-json.log", Path: "/var/lib/docker/containers/" + id + "/" + id + "-json.log"},
		func(e *logs.Event) error { evs = append(evs, e); return nil })
	if err != nil || st.Errors != 2 || len(evs) != 3 {
		t.Fatalf("stats = %+v, events = %d, err = %v", st, len(evs), err)
	}
	if e := evs[0]; e.Kind != KindOutput || e.Message != "Starting web app..." || e.Fields["container_id"] != id[:12] || e.Source != "docker "+id[:12] ||
		e.Fields["stream"] != "stdout" || !e.Time.Equal(time.Date(2026, 10, 11, 21, 0, 0, 123456789, time.UTC)) {
		t.Errorf("output = %+v", e)
	}
	if e := evs[1]; e.Kind != access.KindRequest || e.SrcIP != "203.0.113.9" || e.Fields["user_agent"] != "curl/8.5.0" ||
		e.Fields["path"] != "/login" || e.Fields["logged_at"] != "2026-10-11T21:00:01Z" || e.Ref.Record != "line 2" {
		t.Errorf("request = %+v", e)
	}
	if e := evs[2]; len(e.Raw) != len(big) || e.Ref.Record != "line 3" || e.Fields["stream"] != "stderr" {
		t.Errorf("joined partial: %d bytes, %s", len(e.Raw), e.Ref.Record)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`{"log":"hello\n","stream":"stdout","time":"2026-10-11T21:00:00Z"}` + "\n")
	f.Add(`{"log":"part","stream":"stdout","time":"2026-10-11T21:00:00Z"}` + "\n")
	f.Fuzz(func(t *testing.T, in string) {
		_, err := New().Parse(context.Background(), strings.NewReader(in), logs.Options{}, func(e *logs.Event) error {
			if e.Time.IsZero() || e.Kind == "" {
				t.Fatalf("bad event %+v", e)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

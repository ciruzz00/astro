package access

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ciruzz00/astro/internal/logs"
)

const sample = `203.0.113.9 - - [11/Oct/2026:23:00:00 +0200] "POST /api/v1/login HTTP/1.1" 200 512 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"
198.51.100.7 - admin [11/Oct/2026:21:00:05 +0000] "GET /search?q=\"x\" HTTP/1.1" 404 - "-" "python-requests/2.31.0"
192.0.2.1 - - [11/Oct/2026:21:00:06 +0000] "\x16\x03\x01\x02\x00\x01" 400 157
not an access log line
2001:db8::5 - - [11/Oct/2026:21:00:07 +0000] "GET /health HTTP/1.1" 200 2 "-" "kube-probe/1.30" rt=0.001
`

func TestParse(t *testing.T) {
	var evs []*logs.Event
	st, err := New().Parse(context.Background(), strings.NewReader(sample), logs.Options{Source: "access.log"}, func(e *logs.Event) error {
		evs = append(evs, e)
		return nil
	})
	if err != nil || st.Errors != 1 || len(evs) != 4 {
		t.Fatalf("stats = %+v, events = %d, err = %v", st, len(evs), err)
	}
	e := evs[0]
	if e.Kind != KindRequest || e.SrcIP != "203.0.113.9" || e.Fields["method"] != "POST" || e.Fields["path"] != "/api/v1/login" ||
		e.Fields["status"] != "200" || e.Fields["user_agent"] != "Mozilla/5.0 (X11; Linux x86_64)" || e.Fields["referer"] != "https://example.com/" ||
		!e.Time.Equal(time.Date(2026, 10, 11, 21, 0, 0, 0, time.UTC)) || e.Ref.Record != "line 1" {
		t.Errorf("combined = %+v", e)
	}
	if e := evs[1]; e.User != "admin" || e.Fields["path"] != `/search?q="x"` || e.Fields["size"] != "" || e.Fields["status"] != "404" {
		t.Errorf("escaped = %+v", e)
	}
	if e := evs[2]; e.Fields["method"] != "" || e.Fields["path"] != `\x16\x03\x01\x02\x00\x01` || e.Fields["user_agent"] != "" {
		t.Errorf("TLS on plain HTTP = %+v", e)
	}
	if e := evs[3]; e.SrcIP != "2001:db8::5" || e.Fields["user_agent"] != "kube-probe/1.30" {
		t.Errorf("IPv6 with extra fields = %+v", e)
	}
	if evs[0].Message != "203.0.113.9 POST /api/v1/login → 200 (Mozilla/5.0 (X11; Linux x86_64))" {
		t.Errorf("message = %q", evs[0].Message)
	}
}

func FuzzParseLine(f *testing.F) {
	for _, l := range strings.Split(sample, "\n") {
		f.Add(l)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, ok := ParseLine(s)
		if ok && (r.Time.IsZero() || r.Time.Location() != time.UTC) {
			t.Fatalf("bad request %+v", r)
		}
		if ok && utf8.ValidString(s) && !utf8.ValidString(r.UserAgent) {
			t.Fatal("user agent broke UTF-8")
		}
	})
}

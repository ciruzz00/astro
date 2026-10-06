package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

const newDomain = `{"ldhName":"example.org","events":[{"eventAction":"registration","eventDate":"2026-09-30T10:00:00Z"}]}`

func newTestProvider(t *testing.T) *Provider {
	t.Helper()
	files := map[string]string{"/domain/example.com": "testdata/domain.json", "/ip/192.0.2.1": "testdata/ip.json"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/domain/example.org" {
			_, _ = w.Write([]byte(newDomain))
			return
		}
		f, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	p := New(httpx.NewClient(5*time.Second), srv.URL)
	p.limiter = rate.NewLimiter(rate.Inf, 1)
	p.now = func() time.Time { return time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC) }
	return p
}

func TestDomain(t *testing.T) {
	p := newTestProvider(t)
	r, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.URL, Value: "https://www.example.com/login"})
	if err != nil || !r.Found {
		t.Fatalf("Lookup = %+v, %v", r, err)
	}
	d := r.Details.(*Details)
	if d.Object != "example.com" || d.Registered != "1995-08-14" || d.Expires != "2027-08-13" ||
		d.Registrar != "Example Registrar, Inc." || d.Abuse != "abuse@registrar.example" ||
		len(d.Nameservers) != 2 || d.Nameservers[0] != "a.iana-servers.net" || len(d.Status) != 2 {
		t.Errorf("details = %+v", d)
	}
	if r.Verdict != provider.VerdictInfo || d.AgeDays < 11000 {
		t.Errorf("old domain: verdict %v, age %d", r.Verdict, d.AgeDays)
	}

	r, err = p.Lookup(context.Background(), ioc.Indicator{Type: ioc.Email, Value: "billing@mail.example.org"})
	if err != nil || r.Verdict != provider.VerdictSuspicious || r.Details.(*Details).AgeDays != 6 {
		t.Errorf("newly registered = %+v, %v", r, err)
	}

	r, err = p.Lookup(context.Background(), ioc.Indicator{Type: ioc.Domain, Value: "example.net"})
	if err != nil || r.Found {
		t.Errorf("unknown domain = %+v, %v", r, err)
	}
}

func TestIP(t *testing.T) {
	p := newTestProvider(t)
	r, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.URL, Value: "http://192.0.2.1:8080/x"})
	if err != nil || !r.Found {
		t.Fatalf("Lookup = %+v, %v", r, err)
	}
	d := r.Details.(*Details)
	if d.Object != "192.0.2.1" || d.Network != "TEST-NET-1" || d.Range != "192.0.2.0 - 192.0.2.255" ||
		d.Registrant != "Example Networks" || d.Abuse != "abuse@example.net" {
		t.Errorf("details = %+v", d)
	}
}

func TestTarget(t *testing.T) {
	tests := []struct {
		in   ioc.Indicator
		path string
	}{
		{ioc.Indicator{Type: ioc.Domain, Value: "a.b.example.co.uk"}, "/domain/example.co.uk"},
		{ioc.Indicator{Type: ioc.Domain, Value: "someone.github.io"}, "/domain/github.io"},
		{ioc.Indicator{Type: ioc.IPv6, Value: "2001:db8::1"}, "/ip/2001:db8::1"},
		{ioc.Indicator{Type: ioc.URL, Value: "https://[2001:db8::1]/x"}, "/ip/2001:db8::1"},
	}
	for _, tt := range tests {
		if path, _, ok := target(tt.in); !ok || path != tt.path {
			t.Errorf("target(%s) = %q, %v, want %q", tt.in.Value, path, ok, tt.path)
		}
	}
}

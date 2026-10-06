package dns

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
)

// zone answers DoH JSON queries: name|type → answers ("type data").
var zone = map[string][]string{
	"www.example.com|1":          {`5 "example.com."`, `1 "192.0.2.10"`},
	"www.example.com|28":         {`28 "2001:db8::10"`},
	"www.example.com|5":          {`5 "example.com."`},
	"www.example.com|16":         {`16 "\"v=spf1 \" \"-all\""`},
	"example.org|15":             {`15 "20 mx2.example.org."`, `15 "10 mx1.example.org."`},
	"example.net|15":             {`15 "0 ."`},
	"10.2.0.192.in-addr.arpa|12": {`12 "host10.example.net."`},
}

func newTestProvider(t *testing.T) (*Provider, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/dns-json" {
			http.Error(w, "bad accept", http.StatusBadRequest)
			return
		}
		key := r.URL.Query().Get("name") + "|" + r.URL.Query().Get("type")
		mu.Lock()
		asked = append(asked, key)
		mu.Unlock()
		switch {
		case strings.HasPrefix(key, "nx.example.com|"):
			_, _ = w.Write([]byte(`{"Status":3}`))
			return
		case strings.HasPrefix(key, "servfail.example.com|"):
			_, _ = w.Write([]byte(`{"Status":2}`))
			return
		}
		var rrs []string
		for _, a := range zone[key] {
			typ, data, _ := strings.Cut(a, " ")
			rrs = append(rrs, fmt.Sprintf(`{"type":%s,"data":%s}`, typ, data))
		}
		fmt.Fprintf(w, `{"Status":0,"Answer":[%s]}`, strings.Join(rrs, ","))
	}))
	t.Cleanup(srv.Close)
	p := New(httpx.NewClient(5*time.Second), srv.URL)
	p.limiter = rate.NewLimiter(rate.Inf, 1)
	return p, &asked
}

func TestHost(t *testing.T) {
	p, _ := newTestProvider(t)
	r, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.URL, Value: "https://www.example.com/x"})
	if err != nil || !r.Found {
		t.Fatalf("Lookup = %+v, %v", r, err)
	}
	rec := r.Details.(Details).Records
	if len(rec["A"]) != 1 || rec["A"][0] != "192.0.2.10" || rec["AAAA"][0] != "2001:db8::10" ||
		rec["CNAME"][0] != "example.com" || rec["TXT"][0] != "v=spf1 -all" {
		t.Errorf("records = %v", rec)
	}
	if !strings.Contains(r.Summary, "2 addresses") {
		t.Errorf("summary = %q", r.Summary)
	}

	r, err = p.Lookup(context.Background(), ioc.Indicator{Type: ioc.Domain, Value: "nx.example.com"})
	if err != nil || r.Found || !r.Details.(Details).NXDomain {
		t.Errorf("NXDOMAIN = %+v, %v", r, err)
	}
	if _, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.Domain, Value: "servfail.example.com"}); err == nil {
		t.Error("SERVFAIL must be an error")
	}
}

func TestEmailOnlyAsksMX(t *testing.T) {
	p, asked := newTestProvider(t)
	r, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.Email, Value: "user@example.org"})
	if err != nil || !r.Found || !strings.Contains(r.Summary, "mx1.example.org") {
		t.Fatalf("Lookup = %+v, %v", r, err)
	}
	if len(*asked) != 1 || (*asked)[0] != "example.org|15" {
		t.Errorf("queries = %v", *asked)
	}
	if mx := r.Details.(Details).Records["MX"]; mx[0] != "10 mx1.example.org" {
		t.Errorf("MX not sorted by preference: %v", mx)
	}
	r, _ = p.Lookup(context.Background(), ioc.Indicator{Type: ioc.Email, Value: "user@example.net"})
	if mx := r.Details.(Details).Records["MX"]; len(mx) != 1 || !strings.Contains(mx[0], "null MX") {
		t.Errorf("null MX = %v", mx)
	}
}

func TestReverse(t *testing.T) {
	p, _ := newTestProvider(t)
	r, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.IPv4, Value: "192.0.2.10"})
	if err != nil || !r.Found || r.Summary != "reverse DNS: host10.example.net" {
		t.Fatalf("Lookup = %+v, %v", r, err)
	}
	r, err = p.Lookup(context.Background(), ioc.Indicator{Type: ioc.IPv4, Value: "198.51.100.1"})
	if err != nil || r.Found {
		t.Errorf("no PTR = %+v, %v", r, err)
	}

	got, err := reverseName("2001:db8::1")
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if err != nil || got != want {
		t.Errorf("reverseName(v6) = %q, %v", got, err)
	}
}

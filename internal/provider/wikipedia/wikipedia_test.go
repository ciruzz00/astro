package wikipedia

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
)

const (
	searchCVE = `{"pages":[
		{"key":"Log4j","title":"Log4j","description":"Java logging library","excerpt":"Apache <span class=\"searchmatch\">Log4j</span> is a logging framework"},
		{"key":"Log4Shell","title":"Log4Shell","description":"Software vulnerability","excerpt":"Log4Shell (<span class=\"searchmatch\">CVE</span>-<span class=\"searchmatch\">2021</span>-<span class=\"searchmatch\">44228</span>) is a zero-day"}]}`
	searchGroup = `{"pages":[
		{"key":"Lazarus_Group","title":"Lazarus Group","description":"Hacker group","excerpt":"<span class=\"searchmatch\">Lazarus</span> <span class=\"searchmatch\">Group</span> is a cybercrime group"},
		{"key":"Lazarus","title":"Lazarus","description":"Biblical figure","excerpt":"<span class=\"searchmatch\">Lazarus</span> of Bethany"},
		{"key":"Unrelated","title":"Unrelated","excerpt":"no match &amp; nothing"}]}`
	summaryLog4Shell = `{"type":"standard","extract":"Log4Shell is a zero-day vulnerability in Log4j."}`
)

func newTestProvider(t *testing.T) *Provider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/w/rest.php/v1/search/page":
			switch r.URL.Query().Get("q") {
			case "CVE-2021-44228":
				_, _ = w.Write([]byte(searchCVE))
			case "Lazarus Group":
				_, _ = w.Write([]byte(searchGroup))
			default:
				_, _ = w.Write([]byte(`{"pages":[{"key":"X","title":"X","excerpt":"nothing"}]}`))
			}
		case "/api/rest_v1/page/summary/Log4Shell":
			_, _ = w.Write([]byte(summaryLog4Shell))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	p := New(httpx.NewClient(5*time.Second), srv.URL)
	p.limiter = rate.NewLimiter(rate.Inf, 1)
	return p
}

func TestCVE(t *testing.T) {
	p := newTestProvider(t)
	r, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.CVE, Value: "CVE-2021-44228"})
	if err != nil || !r.Found {
		t.Fatalf("Lookup = %+v, %v", r, err)
	}
	d := r.Details.(Details)
	if d.Title != "Log4Shell" || d.Extract != "Log4Shell is a zero-day vulnerability in Log4j." || !strings.HasSuffix(d.URL, "/wiki/Log4Shell") {
		t.Errorf("details = %+v", d)
	}
}

func TestKeyword(t *testing.T) {
	p := newTestProvider(t)
	r, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.Keyword, Value: "Lazarus Group"})
	if err != nil || !r.Found {
		t.Fatalf("Lookup = %+v, %v", r, err)
	}
	d := r.Details.(Details)
	// The summary endpoint has no page for it: the search excerpt is used.
	if d.Title != "Lazarus Group" || d.Extract != "Lazarus Group is a cybercrime group" ||
		len(d.Others) != 1 || d.Others[0] != "Lazarus" || r.Summary != "Lazarus Group: Hacker group" {
		t.Errorf("details = %+v, summary %q", d, r.Summary)
	}

	r, err = p.Lookup(context.Background(), ioc.Indicator{Type: ioc.Keyword, Value: "zzzz"})
	if err != nil || r.Found {
		t.Errorf("no match = %+v, %v", r, err)
	}
}

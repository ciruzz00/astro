package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
)

func TestLookup(t *testing.T) {
	fixture, err := os.ReadFile("testdata/CVE-2021-44228.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "k" {
			t.Errorf("apiKey header = %q", r.Header.Get("apiKey"))
		}
		if r.URL.Query().Get("cveId") == "CVE-2021-44228" {
			_, _ = w.Write(fixture)
			return
		}
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()

	p := New(httpx.NewClient(5*time.Second), srv.URL, config.Secret("k"))
	r, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.CVE, Value: "CVE-2021-44228"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Found || r.Summary != "CVSS 3.1 10.0 CRITICAL" {
		t.Errorf("result = %+v", r)
	}
	d := r.Details.(Details)
	if len(d.CWEs) == 0 || !strings.HasPrefix(d.Description, "Apache Log4j2") {
		t.Errorf("details = %+v", d)
	}

	r, err = p.Lookup(context.Background(), ioc.Indicator{Type: ioc.CVE, Value: "CVE-1999-0001"})
	if err != nil || r.Found {
		t.Errorf("unknown CVE: %+v, %v", r, err)
	}
}

func TestBestMetricPrefersNewestPrimary(t *testing.T) {
	v31 := []metric{
		{Type: "Secondary", CVSSData: cvssData{Version: "3.1", BaseScore: 7}},
		{Type: "Primary", CVSSData: cvssData{Version: "3.1", BaseScore: 9}},
	}
	v2 := []metric{{Type: "Primary", CVSSData: cvssData{Version: "2.0", BaseScore: 5}}}
	m, ok := bestMetric(nil, v31, nil, v2)
	if !ok || m.CVSSData.BaseScore != 9 {
		t.Errorf("bestMetric = %+v", m)
	}
}

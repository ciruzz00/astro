package epss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
)

func TestLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("cve") {
		case "CVE-2021-44228":
			_, _ = w.Write([]byte(`{"status":"OK","data":[{"cve":"CVE-2021-44228","epss":"0.999990000","percentile":"1.000000000","date":"2026-10-05"}]}`))
		case "CVE-2000-0002":
			_, _ = w.Write([]byte(`{"status":"OK","data":[{"cve":"CVE-2000-0002","epss":"oops","percentile":"1"}]}`))
		default:
			_, _ = w.Write([]byte(`{"status":"OK","data":[]}`))
		}
	}))
	defer srv.Close()
	p := New(httpx.NewClient(5*time.Second), srv.URL)
	ctx := context.Background()

	r, err := p.Lookup(ctx, ioc.Indicator{Type: ioc.CVE, Value: "CVE-2021-44228"})
	if err != nil || !r.Found || r.Details.(Details).EPSS != 0.99999 {
		t.Fatalf("Lookup = %+v, %v", r, err)
	}
	r, err = p.Lookup(ctx, ioc.Indicator{Type: ioc.CVE, Value: "CVE-2000-0001"})
	if err != nil || r.Found {
		t.Errorf("unknown CVE = %+v, %v", r, err)
	}
	if _, err := p.Lookup(ctx, ioc.Indicator{Type: ioc.CVE, Value: "CVE-2000-0002"}); err == nil {
		t.Error("malformed score must fail")
	}
}

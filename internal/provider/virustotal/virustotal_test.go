package virustotal

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

const eicarMD5 = "44d88612fea8a8f36de82e1278abb02f"

func server(t *testing.T) *httptest.Server {
	t.Helper()
	urlID := base64.RawURLEncoding.EncodeToString([]byte("https://example.com/login"))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/files/" + eicarMD5:
			_, _ = w.Write([]byte(`{"data":{"attributes":{
				"last_analysis_stats":{"malicious":66,"suspicious":0,"undetected":2,"harmless":0},
				"reputation":3797,"md5":"44d88612fea8a8f36de82e1278abb02f",
				"sha256":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
				"meaningful_name":"eicar.com","type_description":"Text","size":68,
				"popular_threat_classification":{"suggested_threat_label":"virus.eicar/test",
					"popular_threat_category":[{"value":"virus","count":15}]}}}}`))
		case "/domains/example.com":
			_, _ = w.Write([]byte(`{"data":{"attributes":{
				"last_analysis_stats":{"malicious":2,"suspicious":0,"undetected":29,"harmless":60},
				"reputation":700,"registrar":"Example Registrar","categories":{"a":"Search Engines","b":"search engines"}}}}`))
		case "/ip_addresses/198.51.100.7":
			_, _ = w.Write([]byte(`{"data":{"attributes":{
				"last_analysis_stats":{"malicious":2,"suspicious":0,"undetected":80,"harmless":9},
				"reputation":-5,"as_owner":"Example Hosting","asn":64500,"country":"NL"}}}`))
		case "/urls/" + urlID:
			_, _ = w.Write([]byte(`{"data":{"attributes":{
				"last_analysis_stats":{"malicious":9,"suspicious":1,"undetected":20,"harmless":60},
				"title":"Sign in","last_final_url":"https://example.com/phish"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"NotFoundError"}}`))
		}
	}))
}

func TestLookup(t *testing.T) {
	srv := server(t)
	defer srv.Close()
	p := New(httpx.NewClient(5*time.Second), srv.URL, config.Secret("k"))
	p.limiter = rate.NewLimiter(rate.Inf, 1) // the real 4/min limit would slow the test
	ctx := context.Background()

	tests := []struct {
		ind     ioc.Indicator
		verdict provider.Verdict
		summary string
	}{
		{ioc.Indicator{Type: ioc.MD5, Value: eicarMD5}, provider.VerdictMalicious, "66/68 engines flag it as malicious (virus.eicar/test)"},
		{ioc.Indicator{Type: ioc.Domain, Value: "example.com"}, provider.VerdictClean, "2/91 engines flag it as malicious, ignored: community reputation 700"},
		{ioc.Indicator{Type: ioc.IPv4, Value: "198.51.100.7"}, provider.VerdictSuspicious, "2/91 engines flag it as malicious"},
		{ioc.Indicator{Type: ioc.URL, Value: "https://example.com/login"}, provider.VerdictMalicious, "9/90 engines flag it as malicious"},
	}
	for _, tt := range tests {
		r, err := p.Lookup(ctx, tt.ind)
		if err != nil {
			t.Fatalf("%v: %v", tt.ind, err)
		}
		if !r.Found || r.Verdict != tt.verdict || r.Summary != tt.summary {
			t.Errorf("%v: got %q %q, want %q %q", tt.ind, r.Verdict, r.Summary, tt.verdict, tt.summary)
		}
	}

	r, err := p.Lookup(ctx, ioc.Indicator{Type: ioc.SHA256, Value: strings.Repeat("0", 64)})
	if err != nil || r.Found {
		t.Errorf("unknown hash = %+v, %v", r, err)
	}
}

func TestBadKey(t *testing.T) {
	srv := server(t)
	defer srv.Close()
	p := New(httpx.NewClient(5*time.Second), srv.URL, config.Secret("wrong"))
	_, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.MD5, Value: eicarMD5})
	if err == nil || !strings.Contains(err.Error(), "check the API key") {
		t.Errorf("err = %v", err)
	}
}

func TestEndpoints(t *testing.T) {
	api, gui := endpoints(ioc.Indicator{Type: ioc.URL, Value: "http://www.google.com/"})
	if api != "/urls/aHR0cDovL3d3dy5nb29nbGUuY29tLw" || gui != "/url/aHR0cDovL3d3dy5nb29nbGUuY29tLw" {
		t.Errorf("endpoints = %q %q", api, gui)
	}
}

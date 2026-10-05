package abusech

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

const sampleSHA256 = "32aded55547f7ddfa2bbe0298985f27848009d77f5ad117221f44d86266e353d"

// server emulates the three abuse.ch APIs under /mb/, /tf/ and /uh/.
func server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Auth-Key") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		switch r.URL.Path {
		case "/mb/":
			if form.Get("query") == "get_info" && form.Get("hash") == sampleSHA256 {
				_, _ = w.Write([]byte(`{"query_status":"ok","data":[{"sha256_hash":"` + sampleSHA256 + `",
					"md5_hash":"52fa00a270274ce339ab0f0d828396ec","file_name":"payment.js","file_type":"js",
					"file_size":5891,"signature":"AsyncRAT","first_seen":"2026-10-05 20:48:28","last_seen":null,"tags":["js"]}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"query_status":"hash_not_found"}`))
		case "/tf/":
			var q map[string]string
			_ = json.Unmarshal(body, &q)
			if q["query"] == "search_ioc" && q["search_term"] == "198.51.100.7" {
				_, _ = w.Write([]byte(`{"query_status":"ok","data":[
					{"id":"1","ioc":"198.51.100.7:443","ioc_type":"ip:port","threat_type":"botnet_cc","malware_printable":"Havoc","confidence_level":100},
					{"id":"2","ioc":"198.51.100.70:80","ioc_type":"ip:port","threat_type":"botnet_cc","malware_printable":"Other","confidence_level":50}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"query_status":"no_result","data":"Your search did not yield any results"}`))
		case "/uh/url/":
			if form.Get("url") == "http://198.51.100.9:8080/bin.sh" {
				_, _ = w.Write([]byte(`{"query_status":"ok","id":"3","url":"http://198.51.100.9:8080/bin.sh","url_status":"online",
					"host":"198.51.100.9","threat":"malware_download","urlhaus_reference":"https://urlhaus.abuse.ch/url/3/",
					"payloads":[{"filename":"bin.sh","response_sha256":"abc","signature":"Mirai"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"query_status":"no_results"}`))
		case "/uh/host/":
			if form.Get("host") == "example.org" {
				_, _ = w.Write([]byte(`{"query_status":"ok","host":"example.org","url_count":"1",
					"urls":[{"url":"https://example.org/AA/","url_status":"offline"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"query_status":"no_results"}`))
		default:
			_, _ = w.Write([]byte(`{"query_status":"no_results"}`))
		}
	}))
}

func TestProviders(t *testing.T) {
	srv := server(t)
	defer srv.Close()
	c := httpx.NewClient(5 * time.Second)
	key := config.Secret("k")
	mb := NewMalwareBazaar(c, srv.URL+"/mb/", key)
	tf := NewThreatFox(c, srv.URL+"/tf/", key)
	uh := NewURLhaus(c, srv.URL+"/uh/", key)
	ctx := context.Background()

	tests := []struct {
		p       provider.Provider
		ind     ioc.Indicator
		found   bool
		verdict provider.Verdict
		summary string
	}{
		{mb, ioc.Indicator{Type: ioc.SHA256, Value: sampleSHA256}, true, provider.VerdictMalicious, "known malware sample: AsyncRAT"},
		{mb, ioc.Indicator{Type: ioc.MD5, Value: strings.Repeat("0", 32)}, false, "", "sample not in MalwareBazaar"},
		{tf, ioc.Indicator{Type: ioc.IPv4, Value: "198.51.100.7"}, true, provider.VerdictMalicious, "Havoc botnet cc (confidence 100%)"},
		{tf, ioc.Indicator{Type: ioc.Domain, Value: "example.com"}, false, "", "no ThreatFox IOC matches"},
		{uh, ioc.Indicator{Type: ioc.URL, Value: "http://198.51.100.9:8080/bin.sh"}, true, provider.VerdictMalicious, "malware download URL, currently online"},
		{uh, ioc.Indicator{Type: ioc.Domain, Value: "example.org"}, true, provider.VerdictSuspicious, "1 malware URLs reported on this host, 0 online"},
		{uh, ioc.Indicator{Type: ioc.IPv4, Value: "203.0.113.1"}, false, "", "not listed in URLhaus"},
	}
	for _, tt := range tests {
		r, err := tt.p.Lookup(ctx, tt.ind)
		if err != nil {
			t.Fatalf("%s %v: %v", tt.p.Name(), tt.ind, err)
		}
		if r.Found != tt.found || r.Verdict != tt.verdict || r.Summary != tt.summary {
			t.Errorf("%s %v: got %v %q %q", tt.p.Name(), tt.ind, r.Found, r.Verdict, r.Summary)
		}
	}
}

func TestThreatFoxIgnoresPartialIPMatches(t *testing.T) {
	all := []IOC{{IOC: "198.51.100.70:80"}, {IOC: "198.51.100.7:443"}, {IOC: "[2001:db8::1]:8443"}, {IOC: "198.51.100.7:abc"}}
	got := filterMatches(ioc.Indicator{Type: ioc.IPv4, Value: "198.51.100.7"}, all)
	if len(got) != 1 || got[0].IOC != "198.51.100.7:443" {
		t.Errorf("IPv4 matches = %+v", got)
	}
	got = filterMatches(ioc.Indicator{Type: ioc.IPv6, Value: "2001:db8::1"}, all)
	if len(got) != 1 {
		t.Errorf("IPv6 matches = %+v", got)
	}
}

func TestBadKey(t *testing.T) {
	srv := server(t)
	defer srv.Close()
	p := NewMalwareBazaar(httpx.NewClient(5*time.Second), srv.URL+"/mb/", config.Secret("wrong"))
	if _, err := p.Lookup(context.Background(), ioc.Indicator{Type: ioc.SHA256, Value: sampleSHA256}); err == nil {
		t.Error("expected an authentication error")
	}
}

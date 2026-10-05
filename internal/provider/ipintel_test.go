package provider_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/provider/abuseipdb"
	"github.com/ciruzz00/astro/internal/provider/greynoise"
	"github.com/ciruzz00/astro/internal/provider/otx"
	"github.com/ciruzz00/astro/internal/provider/shodan"
)

// Tests for the IP/domain reputation providers, against fake APIs.

const (
	badIP   = "198.51.100.7"
	cleanIP = "192.0.2.10"
	newIP   = "203.0.113.99"
)

func fakeAPI(t *testing.T, header, key string, routes map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header != "" && r.Header.Get(header) != key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		route := r.URL.Path
		if q := r.URL.Query().Get("ipAddress"); q != "" {
			route += "?" + q
		}
		body, ok := routes[route]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
}

type lookupCase struct {
	ind     ioc.Indicator
	found   bool
	verdict provider.Verdict
	summary string
}

func runCases(t *testing.T, p provider.Provider, cases []lookupCase) {
	t.Helper()
	for _, c := range cases {
		r, err := p.Lookup(context.Background(), c.ind)
		if err != nil {
			t.Fatalf("%s %v: %v", p.Name(), c.ind, err)
		}
		if r.Found != c.found || r.Verdict != c.verdict || !strings.HasPrefix(r.Summary, c.summary) {
			t.Errorf("%s %v: got %v %q %q, want %v %q %q", p.Name(), c.ind, r.Found, r.Verdict, r.Summary, c.found, c.verdict, c.summary)
		}
	}
}

func ip(v string) ioc.Indicator { return ioc.Indicator{Type: ioc.IPv4, Value: v} }

func TestAbuseIPDB(t *testing.T) {
	srv := fakeAPI(t, "Key", "k", map[string]string{
		"/check?" + badIP:   `{"data":{"ipAddress":"198.51.100.7","isPublic":true,"abuseConfidenceScore":100,"totalReports":42,"numDistinctUsers":7,"isp":"Example Hosting","isTor":true}}`,
		"/check?" + cleanIP: `{"data":{"ipAddress":"192.0.2.10","isPublic":true,"abuseConfidenceScore":0,"totalReports":0}}`,
		"/check?10.0.0.1":   `{"data":{"ipAddress":"10.0.0.1","isPublic":false}}`,
	})
	defer srv.Close()
	runCases(t, abuseipdb.New(httpx.NewClient(5*time.Second), srv.URL, config.Secret("k")), []lookupCase{
		{ip(badIP), true, provider.VerdictMalicious, "abuse confidence 100%, 42 reports from 7 users"},
		{ip(cleanIP), true, provider.VerdictClean, "no abuse reports"},
		{ip("10.0.0.1"), true, provider.VerdictInfo, "private or reserved address"},
	})
}

func TestOTX(t *testing.T) {
	srv := fakeAPI(t, "X-OTX-API-KEY", "k", map[string]string{
		"/indicators/IPv4/" + badIP + "/general": `{"pulse_info":{"count":2,"pulses":[
			{"name":"Havoc C2","malware_families":[{"display_name":"Havoc"}],"attack_ids":[{"id":"T1071"}]},
			{"name":"Scanners","adversary":"APT-Example"}]}}`,
		"/indicators/IPv4/" + cleanIP + "/general":     `{"pulse_info":{"count":0,"pulses":[]},"validation":[{"source":"whitelist","message":"Known good"}]}`,
		"/indicators/IPv4/" + newIP + "/general":       `{"pulse_info":{"count":0,"pulses":[]}}`,
		"/indicators/hostname/a.b.example.com/general": `{"pulse_info":{"count":1,"pulses":[{"name":"Phishing"}]}}`,
	})
	defer srv.Close()
	runCases(t, otx.New(httpx.NewClient(5*time.Second), srv.URL, config.Secret("k")), []lookupCase{
		{ip(badIP), true, provider.VerdictSuspicious, "referenced in 2 community pulses"},
		{ip(cleanIP), true, provider.VerdictClean, "whitelisted"},
		{ip(newIP), false, "", "no OTX pulses"},
		{ioc.Indicator{Type: ioc.Domain, Value: "a.b.example.com"}, true, provider.VerdictSuspicious, "referenced in 1"},
	})
}

func TestGreyNoise(t *testing.T) {
	srv := fakeAPI(t, "", "", map[string]string{
		"/" + badIP:   `{"ip":"198.51.100.7","noise":true,"riot":false,"classification":"malicious","name":"unknown"}`,
		"/" + cleanIP: `{"ip":"192.0.2.10","noise":false,"riot":true,"classification":"benign","name":"Example DNS"}`,
	})
	defer srv.Close()
	runCases(t, greynoise.New(httpx.NewClient(5*time.Second), srv.URL, ""), []lookupCase{
		{ip(badIP), true, provider.VerdictMalicious, "mass scanner"},
		{ip(cleanIP), true, provider.VerdictClean, "known benign business service"},
		{ip(newIP), false, "", "not observed"},
	})
}

func TestShodanWithAndWithoutKey(t *testing.T) {
	srv := fakeAPI(t, "", "", map[string]string{
		"/shodan/host/" + badIP: `{"ports":[443,22],"vulns":["CVE-2024-0001"],"org":"Example Hosting",
			"data":[{"port":22,"transport":"tcp","product":"OpenSSH","version":"9.6"}]}`,
		"/" + cleanIP: `{"ip":"192.0.2.10","ports":[53],"hostnames":["dns.example"],"vulns":[],"tags":[],"cpes":[]}`,
	})
	defer srv.Close()
	c := httpx.NewClient(5 * time.Second)

	keyed := shodan.New(c, srv.URL, srv.URL, config.Secret("k"))
	runCases(t, keyed, []lookupCase{
		{ip(badIP), true, provider.VerdictInfo, "2 open ports, 1 known vulnerabilities (Shodan)"},
	})
	keyless := shodan.New(c, srv.URL, srv.URL, "")
	runCases(t, keyless, []lookupCase{
		{ip(cleanIP), true, provider.VerdictInfo, "1 open ports, 0 known vulnerabilities (InternetDB)"},
		{ip(newIP), false, "", "no exposed services"},
	})
}

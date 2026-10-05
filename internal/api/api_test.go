package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

const goodToken = "astro_good"

type fakeVerifier struct{}

func (fakeVerifier) Verify(_ context.Context, secret string) (*store.Token, error) {
	if secret == goodToken {
		return &store.Token{ID: 1, Name: "test"}, nil
	}
	return nil, io.EOF
}

// fakeProvider flags 198.51.100.7 as malicious and everything else clean.
type fakeProvider struct {
	name  string
	local bool
}

func (f fakeProvider) Name() string { return f.name }

func (f fakeProvider) Supports(t ioc.Type) bool { return true }

func (f fakeProvider) Lookup(_ context.Context, i ioc.Indicator) (*provider.Result, error) {
	v := provider.VerdictClean
	if i.Value == "198.51.100.7" {
		v = provider.VerdictMalicious
	}
	return &provider.Result{Found: true, Verdict: v, Summary: f.name}, nil
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	providers := []provider.Provider{fakeProvider{name: "online"}, fakeProvider{name: "local", local: true}}
	h := NewHandler(Config{
		Engine: engine.New(providers),
		Sources: []Source{
			{Name: "online", Enabled: true},
			{Name: "local", Enabled: true, Offline: true},
			{Name: "paid", Enabled: false, KeyEnv: "ASTRO_PAID_KEY"},
		},
		Tokens:  fakeVerifier{},
		Version: "test",
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, srv *httptest.Server, method, path, token, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestAuth(t *testing.T) {
	srv := newTestServer(t)
	for _, tok := range []string{"", "astro_bad"} {
		resp, body := do(t, srv, "GET", "/api/v1/search?q=8.8.8.8", tok, "")
		if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" || !strings.Contains(body, `"error"`) {
			t.Errorf("token %q: %d %s", tok, resp.StatusCode, body)
		}
	}
	for _, path := range []string{"/api/v1/health", "/api/v1/openapi.json"} {
		if resp, _ := do(t, srv, "GET", path, "", ""); resp.StatusCode != 200 {
			t.Errorf("%s must be public, got %d", path, resp.StatusCode)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv := newTestServer(t)
	resp, _ := do(t, srv, "GET", "/api/v1/health", "", "")
	for h, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           "no-store",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	} {
		if got := resp.Header.Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("CORS must not be enabled")
	}
	resp, body := do(t, srv, "GET", "/nope", "", "")
	if resp.StatusCode != 404 || resp.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(body, `{"error"`) {
		t.Errorf("404 must be JSON with security headers: %d %v %s", resp.StatusCode, resp.Header, body)
	}
}

func TestSearch(t *testing.T) {
	srv := newTestServer(t)

	resp, body := do(t, srv, "GET", "/api/v1/search?q=198.51.100%5B.%5D7", goodToken, "")
	var rep engine.Report
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &rep) != nil {
		t.Fatalf("GET search: %d %s", resp.StatusCode, body)
	}
	if rep.Indicator.Value != "198.51.100.7" || rep.Verdict != provider.VerdictMalicious || len(rep.Results) != 2 {
		t.Errorf("report = %+v", rep)
	}

	resp, body = do(t, srv, "POST", "/api/v1/search", goodToken, `{"indicators":["8.8.8.8","8.8.8.8","example.com"],"only":["local"]}`)
	var reps []engine.Report
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &reps) != nil {
		t.Fatalf("POST search: %d %s", resp.StatusCode, body)
	}
	if len(reps) != 2 || len(reps[0].Results) != 1 || reps[0].Results[0].Provider != "local" {
		t.Errorf("duplicates must be merged and only respected: %s", body)
	}

	resp, body = do(t, srv, "GET", "/api/v1/search?q=8.8.8.8&offline=true", goodToken, "")
	if resp.StatusCode != 200 || strings.Contains(body, `"provider":"online"`) {
		t.Errorf("offline must use only offline sources: %s", body)
	}
}

func TestBadRequests(t *testing.T) {
	srv := newTestServer(t)
	many := `{"indicators":[` + strings.Repeat(`"8.8.8.8",`, MaxSearch) + `"1.1.1.1"]}`
	tests := []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/api/v1/search", "", 400},
		{"GET", "/api/v1/search?q=x", "", 400},
		{"GET", "/api/v1/search?q=8.8.8.8&only=paid", "", 400},
		{"GET", "/api/v1/search?q=8.8.8.8&only=nope", "", 400},
		{"POST", "/api/v1/search", `{"indicators":[]}`, 400},
		{"POST", "/api/v1/search", many, 400},
		{"POST", "/api/v1/search", `{"indicators":["8.8.8.8"],"evil":1}`, 400},
		{"POST", "/api/v1/search", `{"indicators":["8.8.8.8"]}{}`, 400},
		{"POST", "/api/v1/search", `{"indicators":["8.8.8.8"],"offline":true,"only":["local"]}`, 400},
		{"POST", "/api/v1/extract", `{"text":"` + strings.Repeat("a", MaxBody) + `"}`, 413},
		{"POST", "/api/v1/enrich", `{"text":"nothing to see here"}`, 400},
		{"DELETE", "/api/v1/search", "", 405},
		{"GET", "/api/v2/anything", "", 404},
	}
	for _, tt := range tests {
		resp, body := do(t, srv, tt.method, tt.path, goodToken, tt.body)
		if resp.StatusCode != tt.status {
			t.Errorf("%s %s: status %d, want %d (%s)", tt.method, tt.path, resp.StatusCode, tt.status, body)
		}
	}

	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/extract", strings.NewReader(`{"text":"x"}`))
	req.Header.Set("Authorization", "Bearer "+goodToken)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 415 {
		t.Errorf("wrong content type: status %d", resp.StatusCode)
	}
}

func TestExtractAndEnrich(t *testing.T) {
	srv := newTestServer(t)

	_, body := do(t, srv, "POST", "/api/v1/extract", goodToken, `{"text":"beacon to hxxp://evil[.]example[.]com from 198.51.100.7"}`)
	if !strings.Contains(body, `"value":"http://evil.example.com"`) || !strings.Contains(body, `"value":"198.51.100.7"`) {
		t.Errorf("extract = %s", body)
	}

	alert := `{"text":"{\"alert\":\"C2 traffic\",\"dst\":\"198.51.100.7\",\"src\":\"192.0.2.10\"}","indicators":["example.com"]}`
	resp, body := do(t, srv, "POST", "/api/v1/enrich", goodToken, alert)
	var er EnrichResponse
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &er) != nil {
		t.Fatalf("enrich: %d %s", resp.StatusCode, body)
	}
	if er.Verdict != provider.VerdictMalicious || er.Searched != 3 || len(er.Malicious) != 1 || er.Malicious[0].Value != "198.51.100.7" {
		t.Errorf("enrich = %+v", er)
	}
}

func TestRateLimit(t *testing.T) {
	srv := newTestServer(t)
	limited := false
	for range requestsBurst + 5 {
		if resp, _ := do(t, srv, "GET", "/api/v1/providers", goodToken, ""); resp.StatusCode == 429 {
			limited = resp.Header.Get("Retry-After") != ""
			break
		}
	}
	if !limited {
		t.Error("expected 429 with Retry-After after the burst")
	}
}

// TestOpenAPIMatchesRoutes keeps the spec in sync with the handlers.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	var spec struct {
		OpenAPI string                    `json:"openapi"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	want := map[string][]string{
		"/api/v1/health":       {"get"},
		"/api/v1/openapi.json": {"get"},
		"/api/v1/providers":    {"get"},
		"/api/v1/search":       {"get", "post"},
		"/api/v1/extract":      {"post"},
		"/api/v1/enrich":       {"post"},
	}
	if len(spec.Paths) != len(want) {
		t.Errorf("spec has %d paths, handlers %d", len(spec.Paths), len(want))
	}
	for path, methods := range want {
		for _, m := range methods {
			if _, ok := spec.Paths[path][m]; !ok {
				t.Errorf("spec is missing %s %s", strings.ToUpper(m), path)
			}
		}
	}
}

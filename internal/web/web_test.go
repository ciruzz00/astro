package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ciruzz00/astro/internal/api"
	"github.com/ciruzz00/astro/internal/auth"
	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/datasets"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

// fakeProvider flags 198.51.100.7 and returns an XSS payload in its summary.
type fakeProvider struct{}

func (fakeProvider) Name() string           { return "fake" }
func (fakeProvider) Supports(ioc.Type) bool { return true }
func (fakeProvider) Lookup(_ context.Context, i ioc.Indicator) (*provider.Result, error) {
	v := provider.VerdictClean
	if i.Value == "198.51.100.7" {
		v = provider.VerdictMalicious
	}
	return &provider.Result{Found: true, Verdict: v, Summary: `<script>alert("xss")</script>`,
		Reference: "javascript:alert(1)", Fields: []provider.Field{{Name: "Owner", Value: "<b>evil</b>"}}}, nil
}

type env struct {
	srv    *httptest.Server
	client *http.Client
	secret string
	store  *store.Store
}

func setup(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := engine.New([]provider.Provider{fakeProvider{}})
	tokens := auth.NewManager(st)
	secret, _, err := tokens.Create(context.Background(), "web")
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{
		Engine: eng, Cases: cases.New(st, eng), Store: st, Tokens: tokens,
		Sources: []api.Source{{Name: "fake", Enabled: true, Indicators: []string{"hash"}}, {Name: "paid", KeyEnv: "ASTRO_PAID_KEY"}},
		Fetcher: func(context.Context, string, int64) ([]byte, error) { return nil, io.ErrUnexpectedEOF },
		Version: "test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &env{srv: srv, client: &http.Client{Jar: jar}, secret: secret, store: st}
}

func (e *env) do(t *testing.T, method, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (e *env) login(t *testing.T) {
	t.Helper()
	resp, body := e.do(t, "POST", "/login", url.Values{"token": {e.secret}})
	if resp.StatusCode != 200 || !strings.Contains(body, "Sign out") {
		t.Fatalf("login failed: %d %s", resp.StatusCode, body)
	}
}

func TestLoginRequiredAndCookie(t *testing.T) {
	e := setup(t)
	resp, body := e.do(t, "GET", "/cases", nil)
	if resp.Request.URL.Path != "/login" || !strings.Contains(body, "Sign in") {
		t.Fatalf("unauthenticated request must land on /login, got %s", resp.Request.URL)
	}
	if resp, body := e.do(t, "POST", "/login", url.Values{"token": {"astro_wrong"}}); resp.StatusCode != 401 || !strings.Contains(body, "Invalid") {
		t.Errorf("bad token: %d", resp.StatusCode)
	}

	req, _ := http.NewRequest("POST", e.srv.URL+"/login", strings.NewReader(url.Values{"token": {e.secret}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	c := r.Cookies()
	if len(c) != 1 || !c[0].HttpOnly || c[0].SameSite != http.SameSiteStrictMode || c[0].Path != "/" || len(c[0].Value) < 40 {
		t.Errorf("session cookie = %+v", c)
	}
	if strings.Contains(c[0].Value, e.secret) {
		t.Error("the cookie must not contain the token")
	}
}

func TestPagesRenderWithSecurityHeaders(t *testing.T) {
	e := setup(t)
	e.login(t)
	for _, p := range []string{"/", "/extract", "/cases", "/cases?all=1", "/sources", "/tokens", "/search?q=8.8.8.8"} {
		resp, body := e.do(t, "GET", p, nil)
		if resp.StatusCode != 200 || !strings.Contains(body, "</html>") {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") || resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("GET %s: weak headers %v", p, resp.Header)
		}
		if strings.Contains(body, "<script>") && !strings.Contains(body, `<script src="/static/`) {
			t.Errorf("GET %s: inline script found", p)
		}
	}
	if resp, _ := e.do(t, "GET", "/static/htmx.min.js", nil); resp.StatusCode != 200 {
		t.Errorf("static htmx: %d", resp.StatusCode)
	}
}

func TestSearchEscapesProviderData(t *testing.T) {
	e := setup(t)
	e.login(t)
	resp, body := e.do(t, "POST", "/search", url.Values{"text": {"198.51.100[.]7\nexample.com"}, "mode": {"list"}})
	if resp.StatusCode != 200 {
		t.Fatalf("search: %d", resp.StatusCode)
	}
	for _, bad := range []string{`<script>alert("xss")`, "<b>evil</b>", `href="javascript:`} {
		if strings.Contains(body, bad) {
			t.Errorf("unescaped provider data %q in page", bad)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "v-malicious") || !strings.Contains(body, "198[.]51[.]100[.]7") {
		t.Error("results missing escaped summary, verdict or defanged copy value")
	}

	resp, body = e.do(t, "POST", "/search", url.Values{"text": {"x"}, "mode": {"list"}})
	if resp.StatusCode != 400 || !strings.Contains(body, "flash-error") {
		t.Errorf("invalid input must show an error, got %d", resp.StatusCode)
	}
	resp, _ = e.do(t, "POST", "/search", url.Values{"text": {"8.8.8.8"}, "only": {"paid"}})
	if resp.StatusCode != 400 {
		t.Errorf("disabled source must be refused, got %d", resp.StatusCode)
	}
}

func TestExtract(t *testing.T) {
	e := setup(t)
	e.login(t)
	_, body := e.do(t, "POST", "/extract", url.Values{"text": {"beacon hxxps://evil[.]example[.]com from 198.51.100.7, CVE-2021-44228"}})
	if !strings.Contains(body, "3 indicators found") || !strings.Contains(body, `value="https://evil.example.com"`) {
		t.Errorf("extract page:\n%s", body)
	}
}

func TestCaseWorkflow(t *testing.T) {
	e := setup(t)
	e.login(t)
	steps := []struct {
		path   string
		form   url.Values
		expect string
	}{
		{"/cases", url.Values{"name": {"inc-1"}, "title": {"Phishing <wave>"}, "tlp": {"RED"}, "tags": {"soc, phishing"}}, "Case created."},
		{"/cases/inc-1/indicators", url.Values{"text": {"mail from 198.51.100.7 to example.com"}, "mode": {"text"}, "note": {"from mail"}, "search": {"on"}}, "2 new indicators added (2 given). 2 searched."},
		{"/cases/inc-1/notes", url.Values{"body": {"User clicked the link"}}, "Note added."},
		{"/cases/inc-1/tags", url.Values{"add": {"urgent"}}, "Tags added."},
		{"/cases/inc-1/tags", url.Values{"remove": {"soc"}}, "Tag removed."},
		{"/cases/inc-1/search", url.Values{"scope": {"all"}}, "2 indicators searched."},
		{"/cases/inc-1/items/remove", url.Values{"ioc": {"example.com"}}, "example[.]com removed."},
		{"/cases/inc-1/edit", url.Values{"title": {"Phishing wave"}, "description": {"Q4 campaign"}, "tlp": {"amber"}}, "Case updated."},
		{"/cases/inc-1/status", url.Values{"status": {"closed"}}, "Case closed."},
		{"/add-to-case", url.Values{"case": {"inc-1"}, "ioc": {"203.0.113.9"}}, "1 new indicators added (1 selected)."},
	}
	for _, s := range steps {
		resp, body := e.do(t, "POST", s.path, s.form)
		if resp.StatusCode != 200 || !strings.Contains(body, s.expect) {
			t.Fatalf("POST %s: %d, want flash %q\n%s", s.path, resp.StatusCode, s.expect, body)
		}
	}

	_, body := e.do(t, "GET", "/cases/inc-1", nil)
	for _, want := range []string{"Phishing wave", "TLP:AMBER", "closed", "User clicked the link", "urgent", "phishing", "Q4 campaign", "v-malicious"} {
		if !strings.Contains(body, want) {
			t.Errorf("case page missing %q", want)
		}
	}

	resp, body := e.do(t, "GET", "/cases/inc-1/export?format=md", nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment") || !strings.Contains(body, "# Phishing wave") {
		t.Errorf("export: %d %v", resp.StatusCode, resp.Header)
	}

	if _, body := e.do(t, "POST", "/cases/inc-1/delete", url.Values{"confirm": {"wrong"}}); !strings.Contains(body, "Type the case name") {
		t.Error("delete without confirmation must be refused")
	}
	if _, body := e.do(t, "POST", "/cases/inc-1/delete", url.Values{"confirm": {"inc-1"}}); !strings.Contains(body, "Case inc-1 deleted.") {
		t.Error("delete with confirmation failed")
	}
	if resp, _ := e.do(t, "GET", "/cases/inc-1", nil); resp.StatusCode != 404 {
		t.Errorf("deleted case: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, "GET", "/cases/..%2Fx", nil); resp.StatusCode != 404 {
		t.Errorf("bad case name: %d", resp.StatusCode)
	}
}

func TestCrossOriginPostsAreBlocked(t *testing.T) {
	e := setup(t)
	e.login(t)
	req, _ := http.NewRequest("POST", e.srv.URL+"/cases", strings.NewReader("name=evil"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://evil.example.com")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin POST: %d, want 403", resp.StatusCode)
	}
	if list, _ := e.store.CaseSummaries(context.Background(), true); len(list) != 0 {
		t.Error("cross-origin POST must not create a case")
	}
}

func TestTokensAndRevocationLogsOut(t *testing.T) {
	e := setup(t)
	e.login(t)
	resp, body := e.do(t, "POST", "/tokens", url.Values{"name": {"soar"}})
	if resp.StatusCode != 201 || !strings.Contains(body, `class="secret-value">astro_`) {
		t.Fatalf("create token: %d", resp.StatusCode)
	}
	// The secret is shown once: a reload does not show it again.
	if _, body := e.do(t, "GET", "/tokens", nil); strings.Contains(body, "secret-value") {
		t.Error("secret shown again")
	}
	_, body = e.do(t, "POST", "/tokens/revoke", url.Values{"name": {"web"}})
	if !strings.Contains(body, "Sign in") {
		t.Error("revoking the session's own token must sign it out")
	}
}

func TestSyncFailureIsReported(t *testing.T) {
	e := setup(t)
	e.login(t)
	_, body := e.do(t, "POST", "/sources/sync", url.Values{"dataset": {"kev"}})
	if !strings.Contains(body, "Sync failed for kev") {
		t.Errorf("sync failure not reported")
	}
	if len(datasetNames()) != len(datasets.Sources) {
		t.Error("datasetNames out of sync")
	}
}

func TestHTMXRedirect(t *testing.T) {
	e := setup(t)
	e.login(t)
	req, _ := http.NewRequest("POST", e.srv.URL+"/cases", strings.NewReader("name=hx-case"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 || resp.Header.Get("HX-Redirect") != "/cases/hx-case" {
		t.Errorf("htmx redirect: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestIsLocalPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/":                true,
		"/cases/x#notes":   true,
		"//evil.com":       false,
		"/\\evil.com":      false,
		"https://evil.com": false,
		"cases":            false,
		"/x\r\nSet-Cookie: a=b": false,
	} {
		if got := isLocalPath(p); got != want {
			t.Errorf("isLocalPath(%q) = %v, want %v", p, got, want)
		}
	}
}

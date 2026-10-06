package hostinfo

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/net/idna"

	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

func hasHint(d Details, prefix string) bool {
	for _, h := range d.Hints {
		if strings.HasPrefix(h, prefix) {
			return true
		}
	}
	return false
}

func TestAnalyze(t *testing.T) {
	d := Analyze("www.example.com")
	if d.RegistrableDomain != "example.com" || d.PublicSuffix != "com" || !d.ICANN || d.SubdomainLevels != 1 || len(d.Hints) != 0 {
		t.Errorf("www.example.com = %+v", d)
	}

	d = Analyze("a.b.c.d.example.co.uk")
	if d.RegistrableDomain != "example.co.uk" || d.PublicSuffix != "co.uk" || d.SubdomainLevels != 4 || !hasHint(d, "deeply nested") {
		t.Errorf("nested = %+v", d)
	}

	d = Analyze("someone.github.io")
	if d.ICANN || d.RegistrableDomain != "someone.github.io" || !hasHint(d, "private public suffix") {
		t.Errorf("private suffix = %+v", d)
	}

	d = Analyze("x7k2qp9zr4mw8vbn1tj.example.com")
	if !hasHint(d, "long, high-entropy") {
		t.Errorf("DGA-like label not flagged: %+v", d)
	}
	if d := Analyze("internationalization.example.com"); hasHint(d, "long, high-entropy") {
		t.Errorf("dictionary word flagged as DGA: entropy %.2f", d.Entropy)
	}
}

func TestHomograph(t *testing.T) {
	// "apple" with a Cyrillic "а" (U+0430) as first letter.
	host, err := idna.ToASCII("аpple.com")
	if err != nil {
		t.Fatal(err)
	}
	r, err := New().Lookup(context.Background(), ioc.Indicator{Type: ioc.Domain, Value: host})
	if err != nil {
		t.Fatal(err)
	}
	d := r.Details.(Details)
	if d.Unicode != "аpple.com" || !hasHint(d, "mixed scripts") || r.Verdict != provider.VerdictSuspicious {
		t.Errorf("homograph = %+v (verdict %v)", d, r.Verdict)
	}

	// A fully non-Latin name is internationalized, not a homograph.
	host, _ = idna.ToASCII("пример.com")
	r, _ = New().Lookup(context.Background(), ioc.Indicator{Type: ioc.Domain, Value: host})
	if r.Verdict != provider.VerdictInfo || hasHint(r.Details.(Details), "mixed scripts") {
		t.Errorf("single-script IDN = %+v", r)
	}
}

func TestHostOf(t *testing.T) {
	tests := []struct {
		in   ioc.Indicator
		want string
	}{
		{ioc.Indicator{Type: ioc.Domain, Value: "example.com"}, "example.com"},
		{ioc.Indicator{Type: ioc.Email, Value: "user@mail.example.org"}, "mail.example.org"},
		{ioc.Indicator{Type: ioc.URL, Value: "https://login.example.net:8443/a?b=c"}, "login.example.net"},
		{ioc.Indicator{Type: ioc.URL, Value: "http://192.0.2.10/payload.bin"}, ""},
		{ioc.Indicator{Type: ioc.IPv4, Value: "192.0.2.10"}, ""},
	}
	for _, tt := range tests {
		if got := HostOf(tt.in); got != tt.want {
			t.Errorf("HostOf(%s) = %q, want %q", tt.in.Value, got, tt.want)
		}
	}

	r, err := New().Lookup(context.Background(), ioc.Indicator{Type: ioc.URL, Value: "http://192.0.2.10/x"})
	if err != nil || r.Found {
		t.Errorf("URL with an IP = %+v, %v", r, err)
	}
}

func TestRegisteredDomain(t *testing.T) {
	tests := map[string]string{
		"www.example.com":          "example.com",
		"a.b.example.co.uk":        "example.co.uk",
		"someone.github.io":        "github.io",
		"github.io":                "github.io",
		"bucket.s3.amazonaws.com":  "amazonaws.com",
		"host.example.invalidtld0": "example.invalidtld0",
	}
	for host, want := range tests {
		if got := RegisteredDomain(host); got != want {
			t.Errorf("RegisteredDomain(%s) = %q, want %q", host, got, want)
		}
	}
}

package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

func TestSanitize(t *testing.T) {
	in := "ok\x1b[2J\x07 line\nnext\ttab\u202edanger\u0085"
	want := "ok[2J line\nnext\ttabdanger"
	if got := Sanitize(in); got != want {
		t.Errorf("Sanitize = %q, want %q", got, want)
	}
}

func TestTextNeverPrintsProviderEscapes(t *testing.T) {
	rep := &engine.Report{
		Indicator: ioc.Indicator{Type: ioc.Domain, Value: "evil.com"},
		Verdict:   provider.VerdictMalicious,
		Results: []*provider.Result{
			{Provider: "x", Found: true, Verdict: provider.VerdictMalicious, Summary: "bad\x1b]0;pwned\x07",
				Fields: []provider.Field{{Name: "Note", Value: "multi\nline"}}},
			{Provider: "y", Error: "boom"},
			{Provider: "z"},
		},
	}
	var buf bytes.Buffer
	if err := Text(&buf, rep, Style{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Errorf("output contains control characters: %q", out)
	}
	for _, want := range []string{"evil[.]com", "MALICIOUS", "error: boom", "no data", "multi\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// Package render formats search reports for terminals and machines.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

// Sanitize strips control characters (ANSI escapes included) from untrusted
// provider data before it reaches a terminal. Newlines and tabs are kept.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Bidi_Control, r) {
			return -1
		}
		return r
	}, s)
}

// Style controls terminal colors.
type Style struct{ Color bool }

func (s Style) paint(code, text string) string {
	if !s.Color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s Style) bold(t string) string { return s.paint("1", t) }
func (s Style) dim(t string) string  { return s.paint("2", t) }

func (s Style) verdict(v provider.Verdict) string {
	switch v {
	case provider.VerdictMalicious:
		return s.paint("1;31", "MALICIOUS")
	case provider.VerdictSuspicious:
		return s.paint("1;33", "SUSPICIOUS")
	case provider.VerdictClean:
		return s.paint("1;32", "CLEAN")
	}
	return s.dim("no verdict")
}

// Text writes a human readable report.
func Text(w io.Writer, rep *engine.Report, st Style) error {
	ew := &errWriter{w: w}
	ew.printf("%s  %s  %s\n", st.bold(Sanitize(ioc.Defang(rep.Indicator))), st.dim("["+string(rep.Indicator.Type)+"]"), st.verdict(rep.Verdict))
	if len(rep.Results) == 0 {
		ew.printf("  %s\n", st.dim("no provider supports this indicator type yet"))
	}
	for _, r := range rep.Results {
		ew.printf("\n  %s", st.bold(r.Provider))
		switch {
		case r.Error != "":
			ew.printf("  %s\n", st.paint("33", "error: "+Sanitize(r.Error)))
			continue
		case !r.Found:
			ew.printf("  %s\n", st.dim(Sanitize(orDefault(r.Summary, "no data"))))
			continue
		}
		if r.Verdict.Rank() > 0 {
			ew.printf("  %s", st.verdict(r.Verdict))
		}
		if r.Cached {
			ew.printf("  %s", st.dim("(cached "+r.FetchedAt.Local().Format("2006-01-02 15:04")+")"))
		}
		ew.printf("\n")
		if r.Summary != "" {
			ew.printf("    %s\n", Sanitize(r.Summary))
		}
		width := 0
		for _, f := range r.Fields {
			width = max(width, len([]rune(f.Name)))
		}
		for _, f := range r.Fields {
			name := Sanitize(f.Name)
			pad := strings.Repeat(" ", width-len([]rune(name)))
			ew.printf("    %s%s  %s\n", st.dim(name), pad, indent(Sanitize(f.Value), width+6))
		}
		if r.Reference != "" {
			ew.printf("    %s\n", st.dim(Sanitize(r.Reference)))
		}
	}
	ew.printf("\n")
	return ew.err
}

// JSON writes reports as indented JSON.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// indent aligns continuation lines of multi-line values under the first one.
func indent(s string, n int) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n"+strings.Repeat(" ", n))
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, args...)
	}
}

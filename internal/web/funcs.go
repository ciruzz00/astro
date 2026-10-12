package web

import (
	"fmt"
	"html/template"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/render"
)

var reTechnique = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

var funcs = template.FuncMap{
	"defang": ioc.Defang,
	"clean":  render.Sanitize,
	"upper":  strings.ToUpper,
	"join":   strings.Join,
	"contains": func(list []string, v string) bool {
		return slices.Contains(list, v)
	},
	"verdictClass": func(v provider.Verdict) string {
		switch v {
		case provider.VerdictMalicious:
			return "v-malicious"
		case provider.VerdictSuspicious:
			return "v-suspicious"
		case provider.VerdictClean:
			return "v-clean"
		case provider.VerdictInfo:
			return "v-info"
		}
		return "v-none"
	},
	"verdictLabel": func(v provider.Verdict) string {
		if v == "" {
			return "no verdict"
		}
		return string(v)
	},
	"tlpClass": func(tlp string) string {
		return "tlp-" + strings.ToLower(strings.ReplaceAll(tlp, "+", "-"))
	},
	"date": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			if v.IsZero() {
				return ""
			}
			return v.Local().Format("2006-01-02 15:04")
		case *time.Time:
			if v == nil {
				return ""
			}
			return v.Local().Format("2006-01-02 15:04")
		}
		return ""
	},
	"flagged": func(rep *engine.Report) []string {
		if rep == nil {
			return nil
		}
		var out []string
		for _, r := range rep.Results {
			if r.Verdict.Rank() >= 2 {
				out = append(out, r.Provider)
			}
		}
		return out
	},
	"searchable": func(t ioc.Type) bool { return t != ioc.Keyword },
	// Log analysis.
	"sevClass": func(sev logs.Severity) string { return "sev-" + sev.String() },
	"sevName":  func(sev logs.Severity) string { return sev.String() },
	"sevOrder": func() []logs.Severity {
		return []logs.Severity{logs.Critical, logs.High, logs.Medium, logs.Low, logs.Info}
	},
	"utc": func(v any) string {
		var t time.Time
		switch x := v.(type) {
		case time.Time:
			t = x
		case *time.Time:
			if x != nil {
				t = *x
			}
		}
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04:05")
	},
	"evtime":   func(e logs.Event) string { return strings.TrimSpace(render.EventTime(&e)) },
	"baseName": func(p string) string { return p[strings.LastIndexAny(p, `/\`)+1:] },
	// techURL links an ATT&CK technique (T1110.003) to its page.
	"techURL": func(id string) string {
		if !reTechnique.MatchString(id) {
			return ""
		}
		return "https://attack.mitre.org/techniques/" + strings.Replace(id, ".", "/", 1) + "/"
	},
	"size": func(n int64) string {
		switch {
		case n >= 1<<30:
			return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
		case n >= 1<<20:
			return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
		case n >= 1<<10:
			return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
		}
		return fmt.Sprintf("%d B", n)
	},
	"tab": func(name, active string) map[string]string { return map[string]string{"Name": name, "Active": active} },
	// shown lists the results with data or an error, most severe first.
	"shown": func(rs []*provider.Result) []*provider.Result {
		var out []*provider.Result
		for _, r := range rs {
			if r.Found || r.Error != "" {
				out = append(out, r)
			}
		}
		slices.SortStableFunc(out, func(a, b *provider.Result) int { return b.Verdict.Rank() - a.Verdict.Rank() })
		return out
	},
	// noData lists the sources that know nothing about the indicator.
	"noData": func(rs []*provider.Result) []string {
		var out []string
		for _, r := range rs {
			if !r.Found && r.Error == "" {
				out = append(out, r.Provider)
			}
		}
		return out
	},
}

package web

import (
	"html/template"
	"slices"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/render"
)

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
}

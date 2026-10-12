package detect

import (
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/logs"
)

// Indicators collects the indicators worth adding to the case from the
// findings of medium severity or more: their source addresses and the
// addresses, URLs, domains and hashes quoted in their summaries (commands,
// requests). Nothing is searched here: enrichment stays on request, and
// internal addresses never reach online sources anyway.
func Indicators(fs []logs.Finding) []ioc.Indicator {
	seen := map[ioc.Indicator]bool{}
	var out []ioc.Indicator
	add := func(i ioc.Indicator) {
		switch {
		case seen[i], i.Type == ioc.Keyword, i.Type.IsAttack(), i.Type == ioc.Email, i.Type == ioc.MAC:
			return
		}
		seen[i] = true
		out = append(out, i)
	}
	for _, f := range fs {
		if f.Severity < logs.Medium {
			continue
		}
		if f.SrcIP != "" {
			if i, err := ioc.Parse(f.SrcIP); err == nil {
				add(i)
			}
		}
		for _, i := range ioc.Extract(f.Summary) {
			add(i)
		}
	}
	return out
}

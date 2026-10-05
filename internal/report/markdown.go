package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/render"
)

// Markdown writes a human-readable case report. Indicators are defanged and
// all provider data is escaped, so the report is safe to paste and render.
func Markdown(w io.Writer, v *cases.View, o Options) error {
	b := &strings.Builder{}
	c := v.Case
	title := c.Title
	if title == "" {
		title = c.Name
	}
	fmt.Fprintf(b, "# %s\n\n", md(title))
	fmt.Fprintf(b, "**TLP:%s**\n\n", c.TLP)
	fmt.Fprintf(b, "| | |\n|---|---|\n")
	fmt.Fprintf(b, "| Case | `%s` |\n", c.Name)
	fmt.Fprintf(b, "| Status | %s |\n", c.Status)
	if len(c.Tags) > 0 {
		fmt.Fprintf(b, "| Tags | %s |\n", md(strings.Join(c.Tags, ", ")))
	}
	fmt.Fprintf(b, "| Created | %s |\n", c.CreatedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(b, "| Updated | %s |\n", c.UpdatedAt.Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(b, "| Generated | %s by astro %s |\n\n", o.Now.Format("2006-01-02 15:04 UTC"), md(o.Version))
	if c.Description != "" {
		fmt.Fprintf(b, "%s\n\n", md(ioc.DefangText(c.Description)))
	}

	mal, sus, clean, pending := v.Counts()
	fmt.Fprintf(b, "## Summary\n\n%d indicators: **%d malicious**, %d suspicious, %d clean, %d not searched.\n\n",
		len(v.Items), mal, sus, clean, pending)

	if len(v.Items) > 0 {
		fmt.Fprintf(b, "## Indicators\n\n| Indicator | Type | Verdict | Flagged by | Note |\n|---|---|---|---|---|\n")
		for _, it := range v.Items {
			fmt.Fprintf(b, "| `%s` | %s | %s | %s | %s |\n",
				code(ioc.Defang(it.Indicator)), it.Indicator.Type, verdictLabel(it), md(strings.Join(flaggedBy(it), ", ")), md(ioc.DefangText(it.Note)))
		}
		b.WriteString("\n## Details\n")
		for _, it := range v.Items {
			if it.Report == nil {
				continue
			}
			fmt.Fprintf(b, "\n### `%s`\n\n", code(ioc.Defang(it.Indicator)))
			fmt.Fprintf(b, "Searched %s.\n\n", it.SearchedAt.Format("2006-01-02 15:04 UTC"))
			for _, r := range it.Report.Results {
				switch {
				case r.Error != "":
					fmt.Fprintf(b, "- **%s**: error: %s\n", md(r.Provider), md(r.Error))
				case !r.Found:
					fmt.Fprintf(b, "- **%s**: %s\n", md(r.Provider), md(orDefault(r.Summary, "no data")))
				default:
					verdict := ""
					if r.Verdict.Rank() > 0 {
						verdict = " (" + strings.ToUpper(string(r.Verdict)) + ")"
					}
					fmt.Fprintf(b, "- **%s**%s: %s\n", md(r.Provider), verdict, md(r.Summary))
				}
			}
		}
	}

	if len(c.Notes) > 0 {
		b.WriteString("\n## Notes\n")
		for _, n := range c.Notes {
			// Notes are the analyst's own Markdown: keep the formatting but
			// strip control characters and raw HTML.
			fmt.Fprintf(b, "\n**%s**\n\n%s\n", n.CreatedAt.Format("2006-01-02 15:04 UTC"), noHTML(render.Sanitize(ioc.DefangText(n.Body))))
		}
	}
	fmt.Fprintf(b, "\n---\n*TLP:%s. Indicators are defanged.*\n", c.TLP)
	_, err := io.WriteString(w, b.String())
	return err
}

func verdictLabel(it cases.Item) string {
	switch {
	case it.SearchedAt == nil:
		return "not searched"
	case it.Verdict == "":
		return "no verdict"
	case it.Verdict.Rank() >= 2:
		return "**" + strings.ToUpper(string(it.Verdict)) + "**"
	}
	return string(it.Verdict)
}

// flaggedBy lists the providers that rated the indicator suspicious or worse.
func flaggedBy(it cases.Item) []string {
	if it.Report == nil {
		return nil
	}
	var out []string
	for _, r := range it.Report.Results {
		if r.Verdict.Rank() >= 2 {
			out = append(out, r.Provider)
		}
	}
	return out
}

var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"<", "&lt;", ">", "&gt;", "|", `\|`, "#", `\#`, "\r", "", "\n", " ",
)

// md escapes untrusted text for a single Markdown line or table cell.
func md(s string) string { return mdEscaper.Replace(render.Sanitize(s)) }

// code makes s safe inside an inline code span.
func code(s string) string { return strings.ReplaceAll(render.Sanitize(s), "`", "'") }

var htmlEscaper = strings.NewReplacer("<", "&lt;", ">", "&gt;")

func noHTML(s string) string { return htmlEscaper.Replace(s) }

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

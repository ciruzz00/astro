package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/render"
)

func (m Model) View() tea.View {
	parts := []string{m.header()}
	switch m.tab {
	case tabSearch:
		parts = append(parts, m.searchView())
	case tabCases:
		if m.open != nil {
			parts = append(parts, m.caseView())
		} else {
			parts = append(parts, m.caseListView())
		}
	case tabSources:
		parts = append(parts, m.sourcesView())
	case tabHelp:
		parts = append(parts, helpView())
	}
	body := lipgloss.JoinVertical(lipgloss.Left, parts...)
	// Pad so the footer always sits on the last lines.
	if pad := m.height - footerH - lipgloss.Height(body); pad > 0 {
		body += strings.Repeat("\n", pad)
	}
	v := tea.NewView(lipgloss.JoinVertical(lipgloss.Left, body, m.footer()))
	v.AltScreen = true
	v.WindowTitle = "astro"
	return v
}

func (m Model) header() string {
	var tabs []string
	for i, name := range tabNames {
		if tab(i) == m.tab {
			tabs = append(tabs, sTabOn.Render(name))
		} else {
			tabs = append(tabs, sTab.Render(name))
		}
	}
	left := sBrand.Render("astro") + " " + strings.Join(tabs, "")
	right := sMuted.Render("online")
	if m.offline {
		right = lipgloss.NewStyle().Bold(true).Foreground(cYellow).Render("OFFLINE")
	}
	right += sMuted.Render("  " + m.cfg.Version)
	gap := max(1, m.width-lipgloss.Width(left)-lipgloss.Width(right))
	return left + strings.Repeat(" ", gap) + right + "\n"
}

func (m Model) footer() string {
	text := truncate(m.status, m.width-4) // plain text: truncate before styling
	status := ""
	switch {
	case m.busy:
		status = m.spin.View() + " " + text
	case m.statusErr:
		status = sError.Render("✗ " + text)
	case text != "":
		status = sOK.Render("✓ ") + text
	}
	if m.prompt != nil {
		box := sPrompt.Width(max(20, m.width-2)).Render(sBold.Render(m.prompt.label) + "\n" + m.prompt.input.View())
		return box
	}
	return lipgloss.JoinVertical(lipgloss.Left, "", status, m.keyHelp())
}

func (m Model) keyHelp() string {
	var keys [][2]string
	switch {
	case m.tab == tabSearch && m.input.Focused():
		keys = [][2]string{{"enter", "search"}, {"esc", "results"}, {"ctrl+o", "offline"}, {"ctrl+c", "quit"}}
	case m.tab == tabSearch:
		keys = [][2]string{{"↑↓", "select"}, {"pgup/pgdn", "scroll"}, {"/", "new search"}, {"ctrl+s", "save to case"}, {"ctrl+o", "offline"}, {"1-3 ?", "tabs"}, {"q", "quit"}}
	case m.tab == tabCases && m.open != nil:
		keys = [][2]string{{"↑↓", "select"}, {"s/S", "search new/all"}, {"i", "add IOCs"}, {"m", "note"}, {"e", "export"}, {"c", "close/reopen"}, {"esc", "back"}}
	case m.tab == tabCases:
		keys = [][2]string{{"↑↓", "select"}, {"enter", "open"}, {"n", "new case"}, {"a", "show closed"}, {"r", "refresh"}, {"q", "quit"}}
	case m.tab == tabSources:
		keys = [][2]string{{"u", "sync datasets"}, {"1-3 ?", "tabs"}, {"q", "quit"}}
	default:
		keys = [][2]string{{"1-3", "tabs"}, {"q", "quit"}}
	}
	var out []string
	used := 0
	for _, k := range keys {
		w := len([]rune(k[0])) + 1 + len(k[1]) + 2
		if used+w > m.width {
			break
		}
		used += w
		out = append(out, sKey.Render(k[0])+" "+sMuted.Render(k[1]))
	}
	return strings.Join(out, "  ")
}

// --- search ---

func (m Model) searchView() string {
	inStyle := sPane
	if m.input.Focused() {
		inStyle = sPaneOn
	}
	input := inStyle.Width(max(20, m.width-2)).Render(m.input.View())
	if len(m.reports) == 0 {
		hint := sMuted.Render("Type indicators and press enter. Defanged input and whole log lines are accepted.\n" +
			"ctrl+o switches to offline mode (local datasets only) for sensitive indicators.")
		return lipgloss.JoinVertical(lipgloss.Left, input, "", hint)
	}
	h := m.paneHeight()
	left := m.leftWidth()
	var rows []string
	for i, rep := range m.reports {
		rows = append(rows, listRow(rep.Verdict, rep.Indicator.Value, left-4, i == m.sel, m.focusResults))
	}
	list := paneStyle(m.focusResults).Width(left).Height(h - 2).Render(window(rows, m.sel, h-4))
	detail := sPane.Width(m.width - left - 2).Height(h - 2).Render(m.detail.View())
	return lipgloss.JoinVertical(lipgloss.Left, input, lipgloss.JoinHorizontal(lipgloss.Top, list, detail))
}

// --- cases ---

func (m Model) caseListView() string {
	title := sBold.Render("Cases")
	if m.includeClosed {
		title += sMuted.Render("  (including closed)")
	}
	if len(m.caseList) == 0 {
		return title + "\n\n" + sMuted.Render("No cases yet. Press n to create one.")
	}
	rows := []string{sMuted.Render(fmt.Sprintf("%-24s %-14s %-7s %5s %6s %6s  %s", "NAME", "TLP", "STATUS", "IOCS", "MAL", "SUSP", "TITLE"))}
	for i, c := range m.caseList {
		line := fmt.Sprintf("%-24s %-14s %-7s %5d %6d %6d  %s", truncate(c.Name, 24), "TLP:"+c.TLP, c.Status,
			c.Indicators, c.Malicious, c.Suspicious, render.Sanitize(c.Title))
		line = truncate(line, m.width-2)
		if i == m.caseSel {
			line = sSelected.Render(line)
		}
		rows = append(rows, line)
	}
	return title + "\n\n" + window(rows, m.caseSel+1, m.bodyHeight()-3)
}

func (m Model) caseView() string {
	c := m.open.Case
	mal, sus, clean, pending := m.open.Counts()
	title := c.Title
	if title == "" {
		title = c.Name
	}
	head := tlpStyle(c.TLP).Render(" TLP:"+c.TLP+" ") + " " + sBold.Render(render.Sanitize(title)) + "  " + sMuted.Render(c.Name+" · "+c.Status)
	stats := fmt.Sprintf("%d indicators  %s  %s  %s  %s",
		len(m.open.Items),
		verdictStyle("malicious").Render(fmt.Sprintf("%d malicious", mal)),
		verdictStyle("suspicious").Render(fmt.Sprintf("%d suspicious", sus)),
		verdictStyle("clean").Render(fmt.Sprintf("%d clean", clean)),
		sMuted.Render(fmt.Sprintf("%d not searched", pending)))
	if len(c.Tags) > 0 {
		stats += sMuted.Render("  tags: " + render.Sanitize(strings.Join(c.Tags, ", ")))
	}

	h := m.paneHeight()
	left := m.leftWidth()
	var rows []string
	for i, it := range m.open.Items {
		v := it.Verdict
		if it.SearchedAt == nil {
			v = "not searched"
		}
		rows = append(rows, listRow(v, ioc.Defang(it.Indicator), left-4, i == m.itemSel, true))
	}
	if len(rows) == 0 {
		rows = []string{sMuted.Render("No indicators: press i to add some.")}
	}
	list := sPaneOn.Width(left).Height(h - 2).Render(window(rows, m.itemSel, h-4))
	detail := sPane.Width(m.width - left - 2).Height(h - 2).Render(m.detail.View())
	return lipgloss.JoinVertical(lipgloss.Left, head, stats, "", lipgloss.JoinHorizontal(lipgloss.Top, list, detail))
}

// --- sources ---

func (m Model) sourcesView() string {
	b := &strings.Builder{}
	b.WriteString(sBold.Render("Intelligence sources") + "\n\n")
	for _, s := range m.cfg.Sources() {
		state := sOK.Render("enabled ")
		if !s.Enabled {
			state = sMuted.Render("disabled")
		}
		where := "online "
		if s.Offline {
			where = "offline"
		}
		extra := ""
		if !s.Enabled && s.KeyEnv != "" {
			extra = sMuted.Render("  set " + s.KeyEnv + " or: astro keys set")
		}
		fmt.Fprintf(b, "  %-15s %s  %s  %s%s\n", s.Name, state, sMuted.Render(where), sMuted.Render(strings.Join(s.Indicators, ", ")), extra)
	}
	b.WriteString("\n" + sBold.Render("Offline datasets") + "\n\n")
	if len(m.datasets) == 0 {
		b.WriteString(sMuted.Render("  Not synced yet: press u.") + "\n")
	}
	for _, d := range m.datasets {
		fmt.Fprintf(b, "  %-18s %7d records  %-10s %s\n", d.Name, d.Records, d.Version, sMuted.Render("synced "+d.SyncedAt.Local().Format("2006-01-02 15:04")))
	}
	return b.String()
}

func helpView() string {
	rows := [][2]string{
		{"1 Search", "type one or more indicators (hashes, IPs, domains, URLs, CVEs, ATT&CK IDs, MAC addresses, names) or paste log lines, then enter"},
		{"", "↑↓ selects a result, pgup/pgdn scrolls its details, / starts a new search, ctrl+s saves every result into a case"},
		{"2 Cases", "enter opens a case; n creates one; a shows closed cases"},
		{"", "in a case: s searches new indicators, S searches all again, i adds indicators, m adds a note,"},
		{"", "e exports (pdf, md, json, stix, navigator) to the current directory, c closes or reopens, esc goes back"},
		{"3 Sources", "enabled sources and offline datasets; u downloads or updates the datasets"},
		{"ctrl+o", "offline mode: only local datasets are queried, nothing leaves this machine"},
		{"q / ctrl+c", "quit"},
	}
	b := &strings.Builder{}
	b.WriteString(sBold.Render("Keys") + "\n\n")
	for _, r := range rows {
		fmt.Fprintf(b, "  %s %s\n", sKey.Render(fmt.Sprintf("%-11s", r[0])), r[1])
	}
	b.WriteString("\n" + sMuted.Render("API keys, access tokens and the REST API are managed with the CLI (astro keys, astro token) or the web interface (astro serve)."))
	return b.String()
}

// --- helpers ---

// listRow renders "verdict  indicator", colored by verdict, highlighted when selected.
func listRow(v provider.Verdict, value string, width int, selected, focused bool) string {
	label := verdictLabel(v)
	if v == "not searched" {
		label = "-"
	}
	text := truncate(fmt.Sprintf("%-11s %s", label, render.Sanitize(value)), width)
	switch {
	case selected && focused:
		return sSelected.Render(text + strings.Repeat(" ", max(0, width-lipgloss.Width(text))))
	case selected:
		return sBold.Render(text)
	}
	cut := min(11, len(text))
	return verdictStyle(v).Render(text[:cut]) + text[cut:]
}

func paneStyle(focused bool) lipgloss.Style {
	if focused {
		return sPaneOn
	}
	return sPane
}

// window returns the rows around sel that fit in height.
func window(rows []string, sel, height int) string {
	if height < 1 || len(rows) <= height {
		return strings.Join(rows, "\n")
	}
	start := max(0, sel-height/2)
	end := min(len(rows), start+height)
	start = max(0, end-height)
	return strings.Join(rows[start:end], "\n")
}

// truncate shortens plain text to n display cells.
func truncate(s string, n int) string {
	if n <= 1 || lipgloss.Width(s) <= n {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r)) > n-1 {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ciruzz00/astro/internal/detect"
	"github.com/ciruzz00/astro/internal/evidence"
	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/render"
	"github.com/ciruzz00/astro/internal/store"
)

// caseMode is the view of an open case.
type caseMode int

const (
	modeIndicators caseMode = iota
	modeTimeline
	modeFindings
)

const (
	// timelinePage is how many events are kept in memory at a time.
	timelinePage = 500
	// citedPerFinding bounds the events shown under a finding.
	citedPerFinding = 10
	// maxRaw bounds the original record shown in the event detail.
	maxRaw = 4000
)

// timeline is the loaded page of the case timeline and its filter.
type timeline struct {
	events             []logs.Event
	total, offset, sel int
	minSev             logs.Severity
	grep               string
}

// pos is the position of the selected event in the whole timeline.
func (t *timeline) pos() int { return t.offset + t.sel }

// caseLogs holds the evidence and findings of the open case.
type caseLogs struct {
	evidence []store.Evidence
	findings []logs.Finding
	cited    map[int64][]logs.Event
}

func (l *caseLogs) events() int {
	n := 0
	for _, e := range l.evidence {
		n += e.Events
	}
	return n
}

// Messages of the log views; name drops answers about a case that is no
// longer open.
type (
	logsMsg struct {
		name string
		logs caseLogs
		err  error
	}
	timelineMsg struct {
		name               string
		events             []logs.Event
		total, offset, sel int
		err                error
		minSev             logs.Severity
		grep               string
	}
)

func (m *Model) loadLogsCmd(name string) tea.Cmd {
	return func() tea.Msg {
		ctx := m.cfg.Ctx
		ev, err := m.cfg.Store.CaseEvidence(ctx, name)
		if err != nil {
			return logsMsg{name: name, err: err}
		}
		fs, err := m.cfg.Store.Findings(ctx, name)
		if err != nil {
			return logsMsg{name: name, err: err}
		}
		cited := make(map[int64][]logs.Event, len(fs))
		for _, f := range fs {
			ids := f.EventIDs[:min(len(f.EventIDs), citedPerFinding)]
			evs, err := m.cfg.Store.EventsByID(ctx, name, ids)
			if err != nil {
				return logsMsg{name: name, err: err}
			}
			cited[f.ID] = evs
		}
		return logsMsg{name: name, logs: caseLogs{evidence: ev, findings: fs, cited: cited}}
	}
}

// loadTimelineCmd loads the page starting at offset with the current
// filter and selects its sel-th event.
func (m *Model) loadTimelineCmd(name string, offset, sel int) tea.Cmd {
	minSev, grep := m.tl.minSev, m.tl.grep
	return func() tea.Msg {
		evs, total, err := m.cfg.Store.Events(m.cfg.Ctx, name, store.EventFilter{
			MinSeverity: minSev, Text: grep, Limit: timelinePage, Offset: offset,
		})
		return timelineMsg{name: name, events: evs, total: total, offset: offset, sel: sel, err: err, minSev: minSev, grep: grep}
	}
}

// importCmd imports a file or folder of this machine into the case and
// analyzes the case again.
func (m *Model) importCmd(name, path string) tea.Cmd {
	path = expandHome(path)
	return m.action(true, func() (string, error) {
		ctx := m.cfg.Ctx
		im := evidence.New(m.cfg.Store, evidence.DefaultParsers()...)
		if m.cfg.Actor != "" {
			im.Actor = m.cfg.Actor
		}
		res, err := im.Import(ctx, name, path, evidence.Options{})
		if err != nil {
			return "", err
		}
		files, _, events := res.Counts()
		if files == 0 {
			for _, f := range res.Files {
				if f.Duplicate {
					return "", fmt.Errorf("nothing new in %s: its logs are already in the case", path)
				}
			}
			return "", fmt.Errorf("no supported log in %s (in a UAC collection import the whole folder: the logs are under var/log)", path)
		}
		an, err := detect.Analyze(ctx, m.cfg.Store, name, time.Now().UTC())
		if err != nil {
			return "", fmt.Errorf("analysis: %w", err)
		}
		text := fmt.Sprintf("%d files imported, %d events; %s", files, events, findingCounts(an.Findings))
		if res.TimeZone != "" {
			text += "; times read in " + res.TimeZone + " (from the collection)"
		}
		if res.Truncated {
			text += fmt.Sprintf(" (stopped at %d files)", im.MaxFiles)
		}
		return text, nil
	})
}

func (m *Model) analyzeCmd(name string) tea.Cmd {
	return m.action(true, func() (string, error) {
		an, err := detect.Analyze(m.cfg.Ctx, m.cfg.Store, name, time.Now().UTC())
		if err != nil {
			return "", err
		}
		return "analysis: " + findingCounts(an.Findings), nil
	})
}

// addFindingIndicatorsCmd adds the indicators cited by the findings to the
// case; they are searched later, from the Indicators view.
func (m *Model) addFindingIndicatorsCmd(name string) tea.Cmd {
	fs := m.logs.findings
	return m.action(true, func() (string, error) {
		inds := detect.Indicators(fs)
		if len(inds) == 0 {
			return "the findings cite no indicator to search", nil
		}
		n, err := m.cfg.Cases.Add(m.cfg.Ctx, name, inds, "from log analysis")
		if err != nil {
			return "", caseError(err)
		}
		return fmt.Sprintf("%d new indicators added from the findings (s on the Indicators view searches them)", n), nil
	})
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

func findingCounts(fs []logs.Finding) string {
	if len(fs) == 0 {
		return "no findings"
	}
	counts := map[logs.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	var parts []string
	for sev := logs.Critical; sev >= logs.Info; sev-- {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	return fmt.Sprintf("%d findings (%s)", len(fs), strings.Join(parts, ", "))
}

// --- keys ---

// logKeys handles the keys of the Timeline and Findings views.
func (m Model) logKeys(key string) (tea.Model, tea.Cmd) {
	name := m.open.Case.Name
	switch key {
	case "space":
		m.detail.PageDown()
		return m, nil
	case "b":
		m.detail.PageUp()
		return m, nil
	case "r":
		if !m.busy {
			m.busy = true
			m.setStatus("analyzing…", false)
			return m, tea.Batch(m.analyzeCmd(name), m.spin.Tick)
		}
		return m, nil
	}
	if m.mode == modeFindings {
		return m.findingKeys(key)
	}
	rows := max(1, m.paneHeight()-4)
	switch key {
	case "up", "k":
		return m.timelineGo(m.tl.pos() - 1)
	case "down", "j":
		return m.timelineGo(m.tl.pos() + 1)
	case "pgup":
		return m.timelineGo(m.tl.pos() - rows)
	case "pgdown":
		return m.timelineGo(m.tl.pos() + rows)
	case "home", "g":
		return m.timelineGo(0)
	case "end", "G":
		return m.timelineGo(m.tl.total - 1)
	case "+", "=", "-":
		sev := m.tl.minSev + 1
		if key == "-" {
			sev = m.tl.minSev - 1
		}
		if sev < logs.Info || sev > logs.Critical {
			return m, nil
		}
		m.tl.minSev = sev
		return m, m.loadTimelineCmd(name, 0, 0)
	case "/":
		m.ask("show events whose message or command line contains (empty shows all)", m.tl.grep, func(v string) tea.Cmd {
			return func() tea.Msg { return grepMsg(v) }
		})
		m.prompt.allowEmpty = true
	}
	return m, nil
}

// grepMsg sets the text filter of the timeline.
type grepMsg string

// timelineGo selects the event at pos of the whole timeline, loading its
// page when it is not in memory.
func (m Model) timelineGo(pos int) (tea.Model, tea.Cmd) {
	pos = clamp(pos, m.tl.total)
	if pos >= m.tl.offset && pos < m.tl.offset+len(m.tl.events) {
		m.tl.sel = pos - m.tl.offset
		m.refreshDetail()
		return m, nil
	}
	if m.tl.total == 0 {
		return m, nil
	}
	off := pos / timelinePage * timelinePage
	return m, m.loadTimelineCmd(m.open.Case.Name, off, pos-off)
}

func (m Model) findingKeys(key string) (tea.Model, tea.Cmd) {
	n := len(m.shownFindings())
	switch key {
	case "up", "k":
		m.findSel = clamp(m.findSel-1, n)
	case "down", "j":
		m.findSel = clamp(m.findSel+1, n)
	case "home", "g":
		m.findSel = 0
	case "end", "G":
		m.findSel = clamp(n-1, n)
	case "+", "=", "-":
		sev := m.findMin + 1
		if key == "-" {
			sev = m.findMin - 1
		}
		if sev < logs.Info || sev > logs.Critical {
			return m, nil
		}
		m.findMin, m.findSel = sev, 0
	case "i":
		if !m.busy && len(m.logs.findings) > 0 {
			m.busy = true
			return m, tea.Batch(m.addFindingIndicatorsCmd(m.open.Case.Name), m.spin.Tick)
		}
		return m, nil
	default:
		return m, nil
	}
	m.refreshDetail()
	return m, nil
}

// shownFindings are the findings at or above the severity filter.
func (m *Model) shownFindings() []logs.Finding {
	var out []logs.Finding
	for _, f := range m.logs.findings {
		if f.Severity >= m.findMin {
			out = append(out, f)
		}
	}
	return out
}

// --- views ---

// caseTabs is the line that switches between the views of a case.
func (m Model) caseTabs() string {
	tabs := []struct {
		mode  caseMode
		label string
	}{
		{modeIndicators, fmt.Sprintf("Indicators %d", len(m.open.Items))},
		{modeTimeline, fmt.Sprintf("t Timeline %d", m.logs.events())},
		{modeFindings, fmt.Sprintf("f Findings %d", len(m.logs.findings))},
	}
	var parts []string
	for _, t := range tabs {
		if t.mode == m.mode {
			parts = append(parts, sTabOn.Render(t.label))
		} else {
			parts = append(parts, sTab.Render(t.label))
		}
	}
	left := strings.Join(parts, "")
	right := ""
	switch {
	case len(m.logs.evidence) == 0:
		right = "no logs yet: l imports a file or folder"
	case m.mode == modeTimeline:
		if m.tl.total > 0 {
			right = fmt.Sprintf("event %d of %d", m.tl.pos()+1, m.tl.total)
		}
		if f := m.tl.filter(); f != "" {
			right = strings.TrimSpace(right + "  filter: " + f)
		}
	case m.mode == modeFindings && m.findMin > logs.Info:
		right = fmt.Sprintf("%d of %d  filter: %s", len(m.shownFindings()), len(m.logs.findings), sevFilter(m.findMin))
	}
	right = truncate(render.Sanitize(right), max(0, m.width-lipgloss.Width(left)-2))
	if right == "" {
		return left
	}
	gap := max(1, m.width-lipgloss.Width(left)-lipgloss.Width(right))
	return left + strings.Repeat(" ", gap) + sMuted.Render(right)
}

func (t *timeline) filter() string {
	var f []string
	if t.minSev > logs.Info {
		f = append(f, sevFilter(t.minSev))
	}
	if t.grep != "" {
		f = append(f, strconv.Quote(t.grep))
	}
	return strings.Join(f, " ")
}

func sevFilter(s logs.Severity) string {
	if s == logs.Critical {
		return "critical"
	}
	return s.String() + "+"
}

// timelineRows renders the visible part of the loaded page.
func (m Model) timelineRows(width, height int) string {
	if len(m.tl.events) == 0 {
		switch {
		case len(m.logs.evidence) == 0:
			return sMuted.Render("No logs in this case: press l to import a file or a folder.")
		case m.tl.filter() != "":
			return sMuted.Render("No events match the filter: - lowers the severity, / changes the text.")
		}
		return sMuted.Render("No events.")
	}
	start, end := span(len(m.tl.events), m.tl.sel, height)
	rows := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		rows = append(rows, eventRow(&m.tl.events[i], width, i == m.tl.sel))
	}
	return strings.Join(rows, "\n")
}

func (m Model) findingRows(width, height int) string {
	fs := m.shownFindings()
	if len(fs) == 0 {
		switch {
		case len(m.logs.evidence) == 0:
			return sMuted.Render("No logs in this case: press l to import a file or a folder.")
		case len(m.logs.findings) > 0:
			return sMuted.Render("No findings at this severity: - lowers it.")
		}
		return sMuted.Render("No findings: the rules matched nothing.")
	}
	start, end := span(len(fs), m.findSel, height)
	rows := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		f := &fs[i]
		who := strings.Join(nonEmpty(f.Host, f.User, f.SrcIP), " ")
		rows = append(rows, sevRow(f.Severity, "", render.SeverityLabel(f.Severity)+" ", flat(f.Title)+"  "+flat(who), width, i == m.findSel))
	}
	return strings.Join(rows, "\n")
}

// eventRow renders "time severity source message"; critical and high
// events are colored entirely, like in the command line.
func eventRow(e *logs.Event, width int, selected bool) string {
	when := render.EventTime(e) + " "
	if width < 50 {
		when = "" // narrow pane: keep the message readable
	}
	src := flat(e.Source)
	if n := len([]rune(src)); n < 12 {
		src += strings.Repeat(" ", 12-n)
	} else {
		src = truncate(src, 12)
	}
	return sevRow(e.Severity, when, render.SeverityLabel(e.Severity)+" ", src+" "+flat(e.Message), width, selected)
}

// sevRow joins a muted prefix, a severity label and plain text, cut to width.
func sevRow(sev logs.Severity, prefix, label, rest string, width int, selected bool) string {
	head := prefix + label
	rest = truncate(rest, max(2, width-lipgloss.Width(head)))
	switch {
	case selected:
		text := head + rest
		return sSelected.Render(text + strings.Repeat(" ", max(0, width-lipgloss.Width(text))))
	case sev >= logs.High:
		return sevStyle(sev).Render(head + rest)
	}
	return sMuted.Render(prefix) + sevStyle(sev).Render(label) + rest
}

var reTechnique = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// findingText is the detail of a finding and of the first events it cites.
func findingText(f *logs.Finding, cited []logs.Event, width int) string {
	b := &strings.Builder{}
	b.WriteString(sevStyle(f.Severity).Render(strings.ToUpper(f.Severity.String())) + "  " + sBold.Render(flat(f.Title)) + "\n\n")
	if f.Summary != "" {
		b.WriteString(wrap(flat(f.Summary), width, "") + "\n\n")
	}
	tech := f.Technique
	if reTechnique.MatchString(tech) {
		tech += "  https://attack.mitre.org/techniques/" + strings.Replace(tech, ".", "/", 1) + "/"
	}
	for _, kv := range [][2]string{
		{"ATT&CK", tech}, {"Rule", f.RuleID},
		{"First", f.First.UTC().Format(render.TimeLayout) + " UTC"}, {"Last", f.Last.UTC().Format(render.TimeLayout) + " UTC"},
		{"Host", f.Host}, {"User", f.User}, {"Source IP", f.SrcIP}, {"Events", strconv.Itoa(f.Count)},
	} {
		if kv[1] != "" {
			b.WriteString(field(kv[0], kv[1], width) + "\n")
		}
	}
	if len(cited) > 0 {
		head := "Events"
		if f.Count > len(cited) {
			head = fmt.Sprintf("First %d of %d events", len(cited), f.Count)
		}
		b.WriteString("\n" + sBold.Render(head) + "\n")
		for i := range cited {
			e := &cited[i]
			b.WriteString(eventRow(e, width, false) + "\n")
			if e.CommandLine != "" {
				b.WriteString(wrap(sMuted.Render("$ ")+flat(e.CommandLine), width, "  ") + "\n")
			}
		}
	}
	return b.String()
}

// eventText is the full detail of an event: fields, command line and the
// reference to the evidence it comes from.
func eventText(e *logs.Event, width int) string {
	b := &strings.Builder{}
	b.WriteString(sevStyle(e.Severity).Render(strings.ToUpper(e.Severity.String())) + "  " +
		sBold.Render(strings.TrimSpace(render.EventTime(e))+" UTC") + "\n")
	switch {
	case e.TimeUnknown:
		b.WriteString(sMuted.Render("no timestamp: shown after the last known time") + "\n")
	case e.YearGuessed:
		b.WriteString(sMuted.Render("year guessed from the file date") + "\n")
	}
	if msg := flat(e.Message); msg != "" {
		b.WriteString("\n" + wrap(msg, width, "") + "\n")
	}
	b.WriteString("\n")
	id := ""
	if e.EventID != 0 {
		id = strconv.Itoa(e.EventID)
	}
	for _, kv := range [][2]string{
		{"Host", e.Host}, {"Source", e.Source}, {"Kind", e.Kind}, {"Event ID", id}, {"Channel", e.Channel},
		{"Provider", e.Provider}, {"User", e.User}, {"Source IP", e.SrcIP}, {"Destination IP", e.DstIP},
		{"Process", e.Process}, {"Parent", e.Parent},
	} {
		if kv[1] != "" {
			b.WriteString(field(kv[0], kv[1], width) + "\n")
		}
	}
	if e.CommandLine != "" {
		b.WriteString("\n" + sBold.Render("Command line") + "\n" + wrap(flat(e.CommandLine), width, "  ") + "\n")
	}
	if len(e.Fields) > 0 {
		keys := make([]string, 0, len(e.Fields))
		for k := range e.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("\n" + sBold.Render("Fields") + "\n")
		for _, k := range keys {
			b.WriteString(field(k, e.Fields[k], width) + "\n")
		}
	}
	b.WriteString("\n" + sBold.Render("Evidence") + "\n")
	for _, kv := range [][2]string{{"File", e.Ref.Path}, {"SHA-256", e.Ref.SHA256}, {"Record", e.Ref.Record}} {
		if kv[1] != "" {
			b.WriteString(field(kv[0], kv[1], width) + "\n")
		}
	}
	if e.Raw != "" {
		raw := flat(e.Raw)
		if r := []rune(raw); len(r) > maxRaw {
			raw = string(r[:maxRaw]) + "…"
		}
		b.WriteString("\n" + sBold.Render("Original record") + "\n" + sMuted.Render(wrap(raw, width, "  ")) + "\n")
	}
	return b.String()
}

func field(name, value string, width int) string {
	return wrap(sMuted.Render(flat(name)+": ")+flat(value), width, "  ")
}

// flat sanitizes untrusted text for one line of the terminal.
func flat(s string) string {
	return strings.Join(strings.Fields(render.Sanitize(s)), " ")
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

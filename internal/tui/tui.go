// Package tui is astro's terminal interface, built with Bubble Tea.
package tui

import (
	"context"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ciruzz00/astro/internal/api"
	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/datasets"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/render"
	"github.com/ciruzz00/astro/internal/report"
	"github.com/ciruzz00/astro/internal/store"
)

// Config holds the dependencies of the terminal interface.
type Config struct {
	Ctx           context.Context
	Engine        *engine.Engine
	Cases         *cases.Service
	Store         *store.Store
	Sources       func() []api.Source
	Fetcher       datasets.Fetcher
	Version       string
	AttackVersion func() string
}

type tab int

const (
	tabSearch tab = iota
	tabCases
	tabSources
	tabHelp
)

var tabNames = []string{"1 Search", "2 Cases", "3 Sources", "? Help"}

// prompt is a one-line question shown over the current screen.
type prompt struct {
	label  string
	input  textinput.Model
	submit func(string) tea.Cmd
}

// Model is the Bubble Tea model of the interface.
type Model struct {
	cfg           Config
	width, height int
	tab           tab
	status        string
	statusErr     bool
	busy          bool
	spin          spinner.Model
	prompt        *prompt
	// blink makes the text cursors blink; tests turn it off.
	blink bool

	// search
	input        textinput.Model
	offline      bool
	reports      []*engine.Report
	sel          int
	focusResults bool
	detail       viewport.Model

	// cases
	caseList      []store.CaseSummary
	caseSel       int
	includeClosed bool
	open          *cases.View
	itemSel       int

	// sources
	datasets []store.Dataset
}

// New returns the initial model.
func New(cfg Config) Model {
	if cfg.Ctx == nil {
		cfg.Ctx = context.Background()
	}
	m := Model{cfg: cfg, spin: spinner.New(), detail: viewport.New(), width: 100, height: 30, blink: true}
	m.input = m.newInput()
	m.input.Placeholder = "hash, IP, domain, URL, CVE, T1059, MAC, threat name… (several at once, defanged ok)"
	m.input.CharLimit = ioc.MaxLen * 4
	m.input.Focus()
	m.resize()
	return m
}

// Run starts the interface and blocks until the user quits.
func Run(cfg Config) error {
	_, err := tea.NewProgram(New(cfg), tea.WithContext(cfg.Ctx)).Run()
	return err
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, m.loadCasesCmd(), m.loadSourcesCmd())
}

// --- update ---

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
		m.refreshDetail()
		return m, nil

	case spinner.TickMsg:
		if !m.busy {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case searchDoneMsg:
		m.busy = false
		m.reports, m.sel, m.focusResults = msg.reports, 0, true
		m.input.Blur()
		m.setStatus(fmt.Sprintf("%d indicators searched", len(msg.reports)), false)
		m.refreshDetail()
		return m, nil

	case casesMsg:
		if msg.err != nil {
			m.setStatus(msg.err.Error(), true)
			return m, nil
		}
		m.caseList = msg.list
		m.caseSel = clamp(m.caseSel, len(m.caseList))
		return m, nil

	case caseMsg:
		if msg.err != nil {
			m.open = nil
			m.setStatus(caseError(msg.err).Error(), true)
			return m, nil
		}
		m.open = msg.view
		m.itemSel = clamp(m.itemSel, len(m.open.Items))
		m.refreshDetail()
		return m, nil

	case sourcesMsg:
		if msg.err == nil {
			m.datasets = msg.datasets
		}
		return m, nil

	case doneMsg:
		m.busy = false
		if msg.err != nil {
			m.setStatus(msg.err.Error(), true)
		} else {
			m.setStatus(msg.text, false)
		}
		cmds := []tea.Cmd{m.loadSourcesCmd()}
		if msg.reload {
			cmds = append(cmds, m.loadCasesCmd())
			if m.open != nil {
				cmds = append(cmds, m.loadCaseCmd(m.open.Case.Name))
			}
		}
		return m, tea.Batch(cmds...)

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}

	if m.prompt != nil {
		var cmd tea.Cmd
		m.prompt.input, cmd = m.prompt.input.Update(msg)
		return m, cmd
	}
	if m.tab == tabSearch && m.input.Focused() {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		return m, tea.Quit
	}
	if m.prompt != nil {
		return m.handlePromptKey(msg)
	}
	if key == "ctrl+o" {
		m.offline = !m.offline
		if m.offline {
			m.setStatus("offline mode: only local datasets are queried", false)
		} else {
			m.setStatus("online mode: every enabled source is queried", false)
		}
		return m, nil
	}

	// Typing in the search box: only enter, esc and tab are special.
	if m.tab == tabSearch && m.input.Focused() {
		switch key {
		case "enter":
			inds, err := parseInput(m.input.Value())
			if err != nil {
				m.setStatus(err.Error(), true)
				return m, nil
			}
			m.busy = true
			m.setStatus(fmt.Sprintf("searching %d indicators…", len(inds)), false)
			return m, tea.Batch(m.searchCmd(inds), m.spin.Tick)
		case "esc", "tab":
			if len(m.reports) > 0 {
				m.input.Blur()
				m.focusResults = true
			} else if key == "esc" {
				m.input.Blur()
			}
			return m, nil
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}

	switch key {
	case "q":
		return m, tea.Quit
	case "1":
		m.tab = tabSearch
		return m, nil
	case "2":
		m.tab = tabCases
		return m, m.loadCasesCmd()
	case "3":
		m.tab = tabSources
		return m, m.loadSourcesCmd()
	case "?":
		m.tab = tabHelp
		return m, nil
	}

	switch m.tab {
	case tabSearch:
		return m.searchKeys(key)
	case tabCases:
		if m.open != nil {
			return m.caseKeys(key)
		}
		return m.caseListKeys(key)
	case tabSources:
		if key == "u" && !m.busy {
			m.busy = true
			m.setStatus("syncing offline datasets…", false)
			return m, tea.Batch(m.syncCmd(), m.spin.Tick)
		}
	}
	return m, nil
}

func (m Model) searchKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "/", "tab", "i":
		m.focusResults = false
		return m, m.input.Focus()
	case "up", "k":
		m.sel = clamp(m.sel-1, len(m.reports))
		m.refreshDetail()
	case "down", "j":
		m.sel = clamp(m.sel+1, len(m.reports))
		m.refreshDetail()
	case "pgdown", "space", "f":
		m.detail.PageDown()
	case "pgup", "b":
		m.detail.PageUp()
	case "ctrl+s":
		if len(m.reports) > 0 {
			m.ask("save all results to case (name)", "", m.saveResultsCmd)
		}
	}
	return m, nil
}

func (m Model) caseListKeys(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.caseSel = clamp(m.caseSel-1, len(m.caseList))
	case "down", "j":
		m.caseSel = clamp(m.caseSel+1, len(m.caseList))
	case "enter":
		if len(m.caseList) > 0 {
			m.itemSel = 0
			return m, m.loadCaseCmd(m.caseList[m.caseSel].Name)
		}
	case "n":
		m.ask("new case name (letters, digits, . _ -)", "", m.createCaseCmd)
	case "a":
		m.includeClosed = !m.includeClosed
		return m, m.loadCasesCmd()
	case "r":
		return m, m.loadCasesCmd()
	}
	return m, nil
}

func (m Model) caseKeys(key string) (tea.Model, tea.Cmd) {
	name := m.open.Case.Name
	switch key {
	case "esc", "backspace", "left", "h":
		m.open = nil
		return m, m.loadCasesCmd()
	case "up", "k":
		m.itemSel = clamp(m.itemSel-1, len(m.open.Items))
		m.refreshDetail()
	case "down", "j":
		m.itemSel = clamp(m.itemSel+1, len(m.open.Items))
		m.refreshDetail()
	case "pgdown", "space", "f":
		m.detail.PageDown()
	case "pgup", "b":
		m.detail.PageUp()
	case "s", "S":
		if !m.busy {
			m.busy = true
			m.setStatus("searching…", false)
			return m, tea.Batch(m.caseSearchCmd(name, key == "S"), m.spin.Tick)
		}
	case "i":
		m.ask("add indicators (several at once, or paste text)", "", func(v string) tea.Cmd { return m.addIndicatorsCmd(name, v) })
	case "m":
		m.ask("add note", "", func(v string) tea.Cmd { return m.noteCmd(name, v) })
	case "e":
		m.ask("export format: "+strings.Join(report.Formats, ", "), "pdf", func(v string) tea.Cmd { return m.exportCmd(name, v) })
	case "c":
		status := "closed"
		if m.open.Case.Status == "closed" {
			status = "open"
		}
		return m, m.statusCmd(name, status)
	}
	return m, nil
}

func (m Model) handlePromptKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.prompt = nil
		m.setStatus("cancelled", false)
		return m, nil
	case "enter":
		value := strings.TrimSpace(m.prompt.input.Value())
		submit := m.prompt.submit
		m.prompt = nil
		if value == "" {
			return m, nil
		}
		m.busy = true
		return m, tea.Batch(submit(value), m.spin.Tick)
	}
	var cmd tea.Cmd
	m.prompt.input, cmd = m.prompt.input.Update(msg)
	return m, cmd
}

// ask opens a prompt; submit runs with the entered value.
func (m *Model) ask(label, value string, submit func(string) tea.Cmd) {
	in := m.newInput()
	in.CharLimit = cases.MaxText
	in.SetWidth(max(20, m.width-8))
	in.SetValue(value)
	in.Focus()
	m.prompt = &prompt{label: label, input: in, submit: submit}
}

func (m *Model) newInput() textinput.Model {
	in := textinput.New()
	in.Prompt = "› "
	st := in.Styles()
	st.Cursor.Blink = m.blink
	in.SetStyles(st)
	return in
}

func (m *Model) setStatus(s string, isErr bool) {
	m.status, m.statusErr = render.Sanitize(s), isErr
}

func clamp(i, n int) int {
	if n == 0 || i < 0 {
		return 0
	}
	if i >= n {
		return n - 1
	}
	return i
}

// --- layout ---

const (
	headerH = 2
	footerH = 3
	inputH  = 3
)

func (m *Model) resize() {
	m.input.SetWidth(max(20, m.width-6))
	left := m.leftWidth()
	m.detail.SetWidth(max(20, m.width-left-4))
	m.detail.SetHeight(max(3, m.paneHeight()-2))
}

// caseHeadH is the number of lines above the panes of an open case.
const caseHeadH = 3

// paneHeight is the outer height of the list and detail panes.
func (m *Model) paneHeight() int {
	h := m.bodyHeight()
	if m.tab == tabCases && m.open != nil {
		h -= caseHeadH
	}
	return max(5, h)
}

func (m *Model) bodyHeight() int {
	h := m.height - headerH - footerH
	if m.tab == tabSearch {
		h -= inputH
	}
	return max(5, h)
}

func (m *Model) leftWidth() int { return max(24, m.width*2/5) }

// refreshDetail renders the selected report into the scrollable pane.
func (m *Model) refreshDetail() {
	m.resize()
	var rep *engine.Report
	notes := ""
	switch {
	case m.tab == tabCases && m.open != nil:
		if len(m.open.Items) > 0 {
			rep = m.open.Items[m.itemSel].Report
		}
		notes = caseNotes(m.open)
	case len(m.reports) > 0:
		rep = m.reports[m.sel]
	}
	content := reportText(rep, m.detail.Width())
	if notes != "" {
		content += "\n" + notes
	}
	m.detail.SetContent(content)
	m.detail.GotoTop()
}

func reportText(rep *engine.Report, width int) string {
	if rep == nil {
		return sMuted.Render("Not searched yet.")
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "%s  %s  %s\n", sBold.Render(render.Sanitize(rep.Indicator.Value)),
		sMuted.Render(string(rep.Indicator.Type)), verdictStyle(rep.Verdict).Render(strings.ToUpper(verdictLabel(rep.Verdict))))
	fmt.Fprintf(b, "%s\n", sMuted.Render("defanged: "+render.Sanitize(ioc.Defang(rep.Indicator))))
	if len(rep.Results) == 0 {
		b.WriteString(sMuted.Render("\nNo enabled source supports this indicator type.\n"))
	}
	for _, r := range rep.Results {
		b.WriteString("\n")
		head := sBold.Render(r.Provider)
		switch {
		case r.Error != "":
			head += "  " + sError.Render("error: "+render.Sanitize(r.Error))
		case !r.Found:
			head += "  " + sMuted.Render(render.Sanitize(orDefault(r.Summary, "no data")))
		default:
			if r.Verdict.Rank() > 0 {
				head += "  " + verdictStyle(r.Verdict).Render(strings.ToUpper(string(r.Verdict)))
			}
			if r.Cached {
				head += "  " + sMuted.Render("cached")
			}
		}
		b.WriteString(head + "\n")
		if r.Error != "" || !r.Found {
			continue
		}
		if r.Summary != "" {
			b.WriteString(wrap(render.Sanitize(r.Summary), width-2, "  ") + "\n")
		}
		for _, f := range r.Fields {
			line := sMuted.Render(render.Sanitize(f.Name)+": ") + render.Sanitize(strings.ReplaceAll(f.Value, "\n", " "))
			b.WriteString(wrap(line, width-2, "  ") + "\n")
		}
		if r.Reference != "" {
			b.WriteString("  " + sMuted.Render(render.Sanitize(r.Reference)) + "\n")
		}
	}
	return b.String()
}

func caseNotes(v *cases.View) string {
	if len(v.Case.Notes) == 0 {
		return ""
	}
	b := &strings.Builder{}
	b.WriteString(sBold.Render("Notes") + "\n")
	for _, n := range v.Case.Notes {
		fmt.Fprintf(b, "%s\n%s\n", sMuted.Render(n.CreatedAt.Local().Format("2006-01-02 15:04")), render.Sanitize(n.Body))
	}
	return b.String()
}

// wrap breaks text to width, indenting every line.
func wrap(s string, width int, indent string) string {
	w := lipgloss.NewStyle().Width(max(10, width-len(indent))).Render(s)
	lines := strings.Split(w, "\n")
	for i := range lines {
		lines[i] = indent + strings.TrimRight(lines[i], " ")
	}
	return strings.Join(lines, "\n")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

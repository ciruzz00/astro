// Package detect runs detection rules over the timeline of a case and turns
// what they match into findings: each one with a severity, a MITRE ATT&CK
// technique and references to the events that prove it. The events cited
// by a finding take its severity, so the timeline shows them in color.
package detect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// Rule identifies what a finding is about.
type Rule struct {
	ID        string
	Title     string
	Severity  logs.Severity
	Technique string
}

// maxExamples bounds the distinct examples quoted in a finding summary.
const maxExamples = 3

// builder accumulates the events of one finding.
type builder struct {
	f        logs.Finding
	examples []string
	detail   func(b *builder) string
}

// Engine feeds events, in time order, to every rule.
type Engine struct {
	findings map[string]*builder
	order    []string
	raise    map[int64]logs.Severity
	stateful []stateful
}

// stateful rules see every event and report at the end (correlations).
type stateful interface {
	observe(e *logs.Event, en *Engine)
}

// New returns an engine with the built-in rules.
func New() *Engine {
	return &Engine{findings: map[string]*builder{}, raise: map[int64]logs.Severity{}, stateful: newCorrelations()}
}

// Observe runs the rules on one event. Events must come in time order.
func (en *Engine) Observe(e *logs.Event) {
	if e.CommandLine != "" {
		for _, r := range commandRules {
			if r.re.MatchString(e.CommandLine) {
				en.hit(r.Rule, groupKey(e), e, e.CommandLine)
			}
		}
	}
	for _, r := range eventRules {
		if r.match(e) {
			key := groupKey(e)
			if r.group != nil {
				key = r.group(e)
			}
			example := e.Message
			if r.example != nil {
				example = r.example(e)
			}
			en.hit(r.Rule, key, e, example)
		}
	}
	for _, s := range en.stateful {
		s.observe(e, en)
	}
}

// groupKey merges the matches of a rule on the same host and account.
func groupKey(e *logs.Event) string {
	return strings.ToLower(e.Host) + "|" + strings.ToLower(e.User)
}

// hit records that rule r matched e; matches with the same key make one finding.
func (en *Engine) hit(r Rule, key string, e *logs.Event, example string) *builder {
	id := r.ID + "\x00" + key
	b := en.findings[id]
	if b == nil {
		b = &builder{f: logs.Finding{RuleID: r.ID, Title: r.Title, Severity: r.Severity, Technique: r.Technique,
			First: e.Time, Host: e.Host, User: e.User, SrcIP: e.SrcIP}}
		en.findings[id] = b
		en.order = append(en.order, id)
	}
	b.f.Count++
	if e.Time.Before(b.f.First) {
		b.f.First = e.Time
	}
	if e.Time.After(b.f.Last) {
		b.f.Last = e.Time
	}
	if b.f.SrcIP == "" {
		b.f.SrcIP = e.SrcIP
	}
	if e.ID != 0 && len(b.f.EventIDs) < logs.MaxFindingEvents {
		b.f.EventIDs = append(b.f.EventIDs, e.ID)
	}
	if e.ID != 0 && en.raise[e.ID] < r.Severity {
		en.raise[e.ID] = r.Severity
	}
	example = strings.TrimSpace(strings.ReplaceAll(example, "\n", " "))
	if example != "" && len(b.examples) < maxExamples && !contains(b.examples, example) {
		b.examples = append(b.examples, logs.Truncate(example, 300))
	}
	return b
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Result is the outcome of a detection run.
type Result struct {
	Findings []logs.Finding
	// Raise maps event ids to the severity their findings give them.
	Raise map[int64]logs.Severity
}

// Finish returns the findings, most severe first.
func (en *Engine) Finish() Result {
	out := make([]logs.Finding, 0, len(en.order))
	for _, id := range en.order {
		b := en.findings[id]
		if b.f.Last.IsZero() {
			b.f.Last = b.f.First
		}
		switch {
		case b.detail != nil:
			b.f.Summary = b.detail(b)
		default:
			b.f.Summary = strings.Join(b.examples, " · ")
			if extra := b.f.Count - len(b.examples); extra > 0 && b.f.Count > 1 {
				b.f.Summary += fmt.Sprintf(" (%d matching events)", b.f.Count)
			}
		}
		out = append(out, b.f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].First.Before(out[j].First)
	})
	return Result{Findings: out, Raise: en.raise}
}

// window is a sliding window of event times.
type window struct {
	span  time.Duration
	times []time.Time
}

// add records n occurrences at t and returns how many fall in the window.
func (w *window) add(t time.Time, n int) int {
	for range min(max(n, 1), 1000) { // n comes from the log ("message repeated N times")
		w.times = append(w.times, t)
	}
	return w.count(t)
}

// count returns how many occurrences fall in the window ending at t.
func (w *window) count(t time.Time) int {
	cut := 0
	for cut < len(w.times) && t.Sub(w.times[cut]) > w.span {
		cut++
	}
	w.times = w.times[cut:]
	return len(w.times)
}

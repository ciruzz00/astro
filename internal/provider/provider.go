// Package provider defines the interface every intelligence source implements.
package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/ioc"
)

// Verdict is a provider's assessment of an indicator.
type Verdict string

const (
	VerdictNone       Verdict = ""
	VerdictInfo       Verdict = "info"
	VerdictClean      Verdict = "clean"
	VerdictSuspicious Verdict = "suspicious"
	VerdictMalicious  Verdict = "malicious"
)

// Rank orders verdicts by severity; informational results rank lowest.
func (v Verdict) Rank() int {
	switch v {
	case VerdictClean:
		return 1
	case VerdictSuspicious:
		return 2
	case VerdictMalicious:
		return 3
	}
	return 0
}

// Field is a labelled value shown to the user, in display order.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Result is what a provider knows about an indicator.
type Result struct {
	Provider  string    `json:"provider"`
	Found     bool      `json:"found"`
	Verdict   Verdict   `json:"verdict,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	Fields    []Field   `json:"fields,omitempty"`
	Reference string    `json:"reference,omitempty"`
	Details   any       `json:"details,omitempty"`
	Error     string    `json:"error,omitempty"`
	Cached    bool      `json:"cached,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
}

// Add appends a field, skipping empty values.
func (r *Result) Add(name, value string) {
	if strings.TrimSpace(value) != "" {
		r.Fields = append(r.Fields, Field{Name: name, Value: value})
	}
}

// Addf appends a formatted field.
func (r *Result) Addf(name, format string, args ...any) {
	r.Add(name, fmt.Sprintf(format, args...))
}

// Provider is an intelligence source.
type Provider interface {
	// Name is a short, stable identifier (e.g. "virustotal").
	Name() string
	// Supports reports whether the provider can look up this indicator type.
	Supports(t ioc.Type) bool
	// Lookup queries the source. "No data" is a Result with Found=false,
	// not an error; errors are for failures (network, quota, bad data).
	Lookup(ctx context.Context, i ioc.Indicator) (*Result, error)
}

// Cacheable is implemented by providers whose results should be cached.
type Cacheable interface {
	CacheTTL() time.Duration
}

// NotFound returns an empty result for provider name.
func NotFound(name, summary string) *Result {
	return &Result{Provider: name, Summary: summary}
}

// List joins up to max items, noting how many were left out.
func List(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(items[:max], ", "), len(items)-max)
}

// Truncate shortens s to at most n runes.
func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n])) + "..."
}

// Package logs defines the event model shared by the log parsers, the
// detection rules and the timeline, and recognizes log file formats.
package logs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Severity ranks events and findings.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// ParseSeverity accepts a severity name in any case.
func ParseSeverity(s string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(strings.TrimSpace(s), n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", s)
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	*s = v
	return err
}

// EvidenceRef points from an event back to the evidence it was read from.
type EvidenceRef struct {
	EvidenceID int64  `json:"evidence_id,omitempty"`
	Path       string `json:"path,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	// Record locates the event in the file: "line 12", "record 345".
	Record string `json:"record,omitempty"`
}

// Event is one normalized entry of a log. Every value comes from untrusted
// files: sanitize it for terminals and escape it for HTML and reports.
type Event struct {
	ID   int64     `json:"id,omitempty"`
	Time time.Time `json:"time"`
	// YearGuessed marks syslog timestamps whose year was inferred.
	YearGuessed bool `json:"year_guessed,omitempty"`
	// TimeUnknown marks entries without a timestamp (plain shell history),
	// placed after the last event with a known time.
	TimeUnknown bool `json:"time_unknown,omitempty"`
	// Seq orders events of the same evidence that share a timestamp.
	Seq         int64             `json:"seq,omitempty"`
	Host        string            `json:"host,omitempty"`
	Source      string            `json:"source"`
	Kind        string            `json:"kind"`
	EventID     int               `json:"event_id,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	Provider    string            `json:"provider,omitempty"`
	User        string            `json:"user,omitempty"`
	SrcIP       string            `json:"src_ip,omitempty"`
	DstIP       string            `json:"dst_ip,omitempty"`
	Process     string            `json:"process,omitempty"`
	Parent      string            `json:"parent,omitempty"`
	CommandLine string            `json:"command_line,omitempty"`
	Message     string            `json:"message"`
	Fields      map[string]string `json:"fields,omitempty"`
	Raw         string            `json:"raw,omitempty"`
	Severity    Severity          `json:"severity"`
	Ref         EvidenceRef       `json:"ref"`
}

// MaxRaw bounds the raw text kept for each event.
const MaxRaw = 8 << 10

// Truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}

// Options tune a parser run.
type Options struct {
	// Year forces the year of timestamps that lack one (syslog); 0 infers it
	// from ModTime.
	Year int
	// Location is the time zone of timestamps without an offset; nil is UTC.
	Location *time.Location
	// Host overrides the host name of every event.
	Host string
	// Source names the file in events (its base name).
	Source string
	// Path is the full path of the evidence (e.g. to tell whose shell
	// history it is).
	Path string
	// ModTime is the file modification time, used to infer syslog years.
	ModTime time.Time
	// MaxEvents stops the parser after this many events; 0 means no limit.
	MaxEvents int
}

// Loc returns the configured location, UTC by default.
func (o Options) Loc() *time.Location {
	if o.Location == nil {
		return time.UTC
	}
	return o.Location
}

// Stats summarize a parser run.
type Stats struct {
	Events int
	// Errors counts lines or records that could not be parsed and were skipped.
	Errors int
	// Truncated reports that MaxEvents stopped the parser.
	Truncated bool
}

// ErrLimit is returned by an emit callback to stop a parser early.
var ErrLimit = errors.New("event limit reached")

// Parser reads one log format. Parse must stream: it calls emit for each
// event in file order and never keeps the whole file in memory (r may be a
// decompressed .gz stream). A malformed line or record is counted in
// Stats.Errors and skipped, not returned as an error. An error from emit
// stops the parser and is returned as is.
type Parser interface {
	Kind() Kind
	Parse(ctx context.Context, r io.Reader, opts Options, emit func(*Event) error) (Stats, error)
}

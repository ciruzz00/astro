package render

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/store"
)

// TimeLayout is how log times are shown: always UTC.
const TimeLayout = "2006-01-02 15:04:05"

// Severity paints text with the severity palette used everywhere in astro:
// critical red, high orange, medium yellow, low blue, info gray.
func (s Style) Severity(sev logs.Severity, text string) string {
	switch sev {
	case logs.Critical:
		return s.paint("1;31", text)
	case logs.High:
		return s.paint("38;5;208", text)
	case logs.Medium:
		return s.paint("33", text)
	case logs.Low:
		return s.paint("34", text)
	}
	return s.paint("90", text)
}

// SeverityLabel is the fixed-width upper-case label of a severity.
func SeverityLabel(sev logs.Severity) string {
	return fmt.Sprintf("%-8s", strings.ToUpper(sev.String()))
}

// oneLine sanitizes untrusted text for a single terminal line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(Sanitize(s)), " ")
}

// cut shortens s to n runes.
func cut(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func pad(s string, n int) string {
	s = cut(s, n)
	if k := utf8.RuneCountInString(s); k < n {
		s += strings.Repeat(" ", n-k)
	}
	return s
}

// EventTime formats an event time: "~" marks a guessed year, "?" an
// unknown time (shown as the last known one).
func EventTime(e *logs.Event) string {
	t := e.Time.UTC().Format(TimeLayout)
	switch {
	case e.TimeUnknown:
		return t + "?"
	case e.YearGuessed:
		return t + "~"
	}
	return t + " "
}

// Timeline writes one line per event. width bounds the line length (0
// means no limit); critical and high events are colored entirely.
func Timeline(w io.Writer, evs []logs.Event, st Style, width int) error {
	ew := &errWriter{w: w}
	for i := range evs {
		e := &evs[i]
		who := e.User
		if e.SrcIP != "" {
			if who != "" {
				who += " "
			}
			who += e.SrcIP
		}
		t, label := EventTime(e), SeverityLabel(e.Severity)
		rest := pad(oneLine(e.Host), 14) + " " + pad(oneLine(e.Source), 16) + " " + pad(oneLine(who), 26) + " "
		msg := oneLine(e.Message)
		if width > 0 {
			used := utf8.RuneCountInString(t) + 1 + utf8.RuneCountInString(label) + 1 + utf8.RuneCountInString(rest)
			msg = cut(msg, max(width-used, 20))
		}
		if e.Severity >= logs.High {
			ew.printf("%s\n", st.Severity(e.Severity, t+" "+label+" "+rest+msg))
			continue
		}
		ew.printf("%s %s %s%s\n", st.dim(t), st.Severity(e.Severity, label), rest, msg)
	}
	return ew.err
}

// csvSafe neutralizes values that spreadsheets would run as formulas.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// TimelineCSV writes events as CSV, one row per event.
func TimelineCSV(w io.Writer, evs []logs.Event) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"time_utc", "severity", "host", "source", "kind", "event_id", "provider", "user", "src_ip", "dst_ip",
		"process", "parent", "command_line", "message", "evidence_path", "evidence_sha256", "record", "year_guessed", "time_unknown"}); err != nil {
		return err
	}
	for i := range evs {
		e := &evs[i]
		id := ""
		if e.EventID != 0 {
			id = strconv.Itoa(e.EventID)
		}
		row := []string{e.Time.UTC().Format(time.RFC3339Nano), e.Severity.String(), e.Host, e.Source, e.Kind, id, e.Provider, e.User,
			e.SrcIP, e.DstIP, e.Process, e.Parent, e.CommandLine, e.Message, e.Ref.Path, e.Ref.SHA256, e.Ref.Record,
			strconv.FormatBool(e.YearGuessed), strconv.FormatBool(e.TimeUnknown)}
		for j := range row {
			row[j] = csvSafe(row[j])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// Findings writes the findings of a case, most severe first; cited, when
// set, returns the events to show under each finding.
func Findings(w io.Writer, fs []logs.Finding, st Style, cited func(f *logs.Finding) []logs.Event) error {
	ew := &errWriter{w: w}
	if len(fs) == 0 {
		ew.printf("%s\n", st.dim("no findings"))
		return ew.err
	}
	for i := range fs {
		f := &fs[i]
		tech := ""
		if f.Technique != "" {
			tech = "  " + st.dim(f.Technique)
		}
		ew.printf("%s %s%s\n", st.Severity(f.Severity, SeverityLabel(f.Severity)), st.bold(oneLine(f.Title)), tech)
		when := f.First.UTC().Format(TimeLayout)
		if last := f.Last.UTC().Format(TimeLayout); last != when {
			when += " → " + last
		}
		var who []string
		for _, kv := range [][2]string{{"host", f.Host}, {"user", f.User}, {"from", f.SrcIP}} {
			if kv[1] != "" {
				who = append(who, kv[0]+" "+oneLine(kv[1]))
			}
		}
		ew.printf("         %s  %s  %s\n", st.dim(when), st.dim(fmt.Sprintf("%d event(s)", f.Count)), strings.Join(who, ", "))
		ew.printf("         %s\n", oneLine(f.Summary))
		if cited != nil {
			for _, e := range cited(f) {
				ew.printf("           %s %s  %s\n", st.dim(EventTime(&e)), st.dim(oneLine(baseName(e.Ref.Path))+" "+e.Ref.Record), cut(oneLine(e.Message), 120))
			}
		}
	}
	return ew.err
}

// baseName is the file name of a path written on any system.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Evidence writes the inventory of a case.
func Evidence(w io.Writer, list []store.Evidence, st Style) error {
	ew := &errWriter{w: w}
	if len(list) == 0 {
		ew.printf("%s\n", st.dim("no evidence imported"))
		return ew.err
	}
	for _, e := range list {
		span := "no timed events"
		if e.FirstEvent != nil {
			span = e.FirstEvent.UTC().Format(TimeLayout) + " → " + e.LastEvent.UTC().Format(TimeLayout)
		}
		flags := ""
		if e.Compressed {
			flags += " gzip"
		}
		if e.Truncated {
			flags += " " + st.Severity(logs.Medium, "truncated at the event limit")
		}
		if e.ParseErrors > 0 {
			flags += " " + st.Severity(logs.Medium, fmt.Sprintf("%d unparsable", e.ParseErrors))
		}
		ew.printf("%s %s  %s\n", st.bold(fmt.Sprintf("#%d", e.ID)), st.bold(oneLine(e.Name)), st.dim(string(e.Kind)))
		ew.printf("    %s\n", oneLine(e.Path))
		ew.printf("    %d bytes, %d events, %s%s\n", e.Size, e.Events, span, flags)
		if e.Host != "" {
			ew.printf("    host %s\n", oneLine(e.Host))
		}
		ew.printf("    %s\n    %s %s\n", st.dim("sha256 "+e.SHA256), st.dim("sha1 "+e.SHA1), st.dim("md5 "+e.MD5))
	}
	return ew.err
}

// Custody writes a chain of custody and whether it verifies.
func Custody(w io.Writer, entries []store.CustodyEntry, verifyErr error, st Style) error {
	ew := &errWriter{w: w}
	for _, c := range entries {
		ew.printf("    %s  %-9s %s  %s\n", st.dim(c.At.UTC().Format(TimeLayout)), c.Action, oneLine(c.Actor), oneLine(c.Detail))
	}
	if verifyErr != nil {
		ew.printf("    %s\n", st.Severity(logs.Critical, "chain of custody does NOT verify: "+verifyErr.Error()))
	} else {
		ew.printf("    %s\n", st.paint("32", "chain of custody verified"))
	}
	return ew.err
}

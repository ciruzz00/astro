// Package syslog parses text syslog files (auth.log, secure, syslog,
// messages) in RFC 3164, RFC 5424 and ISO 8601 (rsyslog) formats, and
// recognizes the authentication and account management messages that
// matter in an investigation.
package syslog

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// Parser reads syslog text files.
type Parser struct {
	// now is the reference time when a file has no modification time.
	now func() time.Time
}

// New returns a syslog parser.
func New() *Parser { return &Parser{now: time.Now} }

// Kind implements logs.Parser.
func (*Parser) Kind() logs.Kind { return logs.KindSyslog }

var (
	re3164 = regexp.MustCompile(`^([A-Z][a-z]{2}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) (\S+) (.*)$`)
	reISO  = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:?\d\d)) (\S+) (.*)$`)
	re5424 = regexp.MustCompile(`^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$`)
	// The optional "]" after the name is a GDM quirk ("gdm-password]: ...").
	reTag = regexp.MustCompile(`^([^\s\[\]:]{1,64})\]?(?:\[(\d{1,10})\])?: ?(.*)$`)

	months = map[string]time.Month{"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
		"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
)

// header is the part common to every syslog line.
type header struct {
	time    time.Time
	guessed bool
	host    string
	prog    string
	pid     string
	msg     string
	fields  map[string]string
}

// Parse implements logs.Parser.
func (p *Parser) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	ref := opts.ModTime
	if ref.IsZero() {
		ref = p.now()
	}
	var last time.Time
	pendingNUL, pendingLine := 0, 0
	long, err := logs.ScanLines(ctx, r, logs.MaxLine, func(n int, line string) error {
		line, nul := logs.StripNUL(line)
		if nul > 0 && pendingNUL == 0 {
			pendingLine = n
		}
		pendingNUL += nul
		if strings.TrimSpace(line) == "" {
			return nil
		}
		h, ok := parseHeader(line, opts, ref)
		if !ok {
			st.Errors++
			return nil
		}
		if pendingNUL > 0 {
			// Report the gap at the time the log resumes.
			gap := logs.NULPaddingEvent(opts.Source, pendingLine, pendingNUL, h.time)
			gap.Host, gap.Raw = h.host, fmt.Sprintf("[%d NUL bytes]", pendingNUL)
			pendingNUL = 0
			if err := emit(gap); err != nil {
				return err
			}
			st.Events++
		}
		last = h.time
		e := &logs.Event{Time: h.time, YearGuessed: h.guessed, Host: h.host, Source: opts.Source,
			Provider: h.prog, Process: h.prog, Raw: line, Ref: logs.EvidenceRef{Record: "line " + strconv.Itoa(n)}}
		e.Fields = h.fields
		if h.pid != "" {
			setField(e, "pid", h.pid)
		}
		classify(e, h.prog, h.msg)
		if err := emit(e); err != nil {
			return err
		}
		st.Events++
		return nil
	})
	if err == nil && pendingNUL > 0 { // NUL bytes up to the end of the file
		gap := logs.NULPaddingEvent(opts.Source, pendingLine, pendingNUL, last)
		if last.IsZero() {
			gap.Time = ref.UTC()
		}
		gap.Raw = fmt.Sprintf("[%d NUL bytes]", pendingNUL)
		if err = emit(gap); err == nil {
			st.Events++
		}
	}
	st.Errors += long
	return st, err
}

func parseHeader(line string, opts logs.Options, ref time.Time) (header, bool) {
	if m := re3164.FindStringSubmatch(line); m != nil {
		t, guessed, ok := time3164(m, opts, ref)
		if !ok {
			return header{}, false
		}
		h := header{time: t, guessed: guessed, host: m[6]}
		h.prog, h.pid, h.msg = splitTag(m[7])
		return h, true
	}
	if m := reISO.FindStringSubmatch(line); m != nil {
		t, ok := parseISO(m[1])
		if !ok {
			return header{}, false
		}
		h := header{time: t, host: m[2]}
		h.prog, h.pid, h.msg = splitTag(m[3])
		return h, true
	}
	if m := re5424.FindStringSubmatch(line); m != nil {
		t, ok := parseISO(m[2])
		if !ok {
			return header{}, false
		}
		h := header{time: t, host: nilValue(m[3]), prog: nilValue(m[4]), pid: nilValue(m[5]), fields: map[string]string{}}
		if pri, err := strconv.Atoi(m[1]); err == nil && pri <= 191 {
			h.fields["facility"], h.fields["priority"] = strconv.Itoa(pri/8), strconv.Itoa(pri%8)
		}
		if id := nilValue(m[6]); id != "" {
			h.fields["msgid"] = id
		}
		sd, msg, ok := splitStructuredData(m[7])
		if !ok {
			return header{}, false
		}
		if sd != "" {
			h.fields["structured_data"] = sd
		}
		h.msg = strings.TrimPrefix(msg, "\uFEFF") // RFC 5424 BOM before UTF-8 messages
		return h, true
	}
	return header{}, false
}

// time3164 builds an RFC 3164 timestamp, which has neither year nor zone.
// Without a forced year it takes the year of the file modification time,
// minus one for dates after it (a December line in a file last written in
// January belongs to the previous year).
func time3164(m []string, opts logs.Options, ref time.Time) (time.Time, bool, bool) {
	mon, ok := months[m[1]]
	day, _ := strconv.Atoi(m[2])
	hh, _ := strconv.Atoi(m[3])
	mm, _ := strconv.Atoi(m[4])
	ss, _ := strconv.Atoi(m[5])
	if !ok || day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60 {
		return time.Time{}, false, false
	}
	loc := opts.Loc()
	year, guessed := opts.Year, opts.Year == 0
	if guessed {
		year = ref.In(loc).Year()
	}
	t := time.Date(year, mon, day, hh, mm, ss, 0, loc)
	if t.Day() != day { // Feb 30 and the like
		return time.Time{}, false, false
	}
	if guessed && t.After(ref.Add(48*time.Hour)) {
		t = time.Date(year-1, mon, day, hh, mm, ss, 0, loc)
	}
	return t.UTC(), guessed, true
}

func parseISO(s string) (time.Time, bool) {
	// Accept "+0200" as well as "+02:00".
	if n := len(s); n > 5 && (s[n-5] == '+' || s[n-5] == '-') && s[n-3] != ':' {
		s = s[:n-2] + ":" + s[n-2:]
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func splitTag(rest string) (prog, pid, msg string) {
	if m := reTag.FindStringSubmatch(rest); m != nil {
		return m[1], m[2], m[3]
	}
	return "", "", rest
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// splitStructuredData separates RFC 5424 structured data ("-" or
// "[id k="v"]...", where \] escapes a bracket) from the message.
func splitStructuredData(s string) (sd, msg string, ok bool) {
	if strings.HasPrefix(s, "-") {
		return "", strings.TrimPrefix(strings.TrimPrefix(s, "-"), " "), true
	}
	i := 0
	for i < len(s) && s[i] == '[' {
		j := i + 1
		for ; j < len(s); j++ {
			if s[j] == '\\' {
				j++
				continue
			}
			if s[j] == ']' {
				break
			}
		}
		if j >= len(s) {
			return "", "", false
		}
		i = j + 1
	}
	if i == 0 {
		return "", "", false
	}
	return s[:i], strings.TrimPrefix(s[i:], " "), true
}

func setField(e *logs.Event, k, v string) {
	if v == "" {
		return
	}
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	e.Fields[k] = v
}

// setIP stores a remote address: IPs go to SrcIP, host names to a field.
func setIP(e *logs.Event, v string) {
	if a, err := netip.ParseAddr(v); err == nil {
		e.SrcIP = a.Unmap().String()
		return
	}
	setField(e, "rhost", v)
}

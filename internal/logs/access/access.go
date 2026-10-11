// Package access parses web server access logs in the Common and Combined
// Log Formats (nginx, Apache, gunicorn, most reverse proxies), as files or
// as lines found inside other logs (container output).
package access

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

// KindRequest is the kind of an HTTP request event.
const KindRequest = "http-request"

// Line matches "client ident user [time] "request" status size" with the
// optional "referer" "user-agent" of the Combined format and anything after.
var reLine = regexp.MustCompile(`^(\S+) (\S+) (\S+) \[([^\]]{1,64})\] "((?:[^"\\]|\\.)*)" (\d{3}|-) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?(.*)$`)

// Match reports whether s looks like an access log line.
func Match(s string) bool { return reLine.MatchString(s) }

// Request is a parsed access log line.
type Request struct {
	Time      time.Time
	Client    string
	User      string
	Method    string
	Path      string
	Proto     string
	Status    int
	Size      string
	Referer   string
	UserAgent string
}

// ParseLine parses one access log line.
func ParseLine(s string) (Request, bool) {
	m := reLine.FindStringSubmatch(s)
	if m == nil {
		return Request{}, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[4])
	if err != nil {
		return Request{}, false
	}
	r := Request{Time: t.UTC(), Client: m[1], User: dash(m[3]), Size: dash(m[7]),
		Referer: dash(unescape(m[8])), UserAgent: dash(unescape(m[9]))}
	r.Status, _ = strconv.Atoi(m[6])
	req := unescape(m[5])
	parts := strings.SplitN(req, " ", 3)
	switch len(parts) {
	case 3:
		r.Method, r.Path, r.Proto = parts[0], parts[1], parts[2]
	case 2:
		r.Method, r.Path = parts[0], parts[1]
	default:
		r.Path = req // garbage or a TLS handshake sent to a plain HTTP port
	}
	return r, true
}

// Fill sets the HTTP fields of an event from a request.
func (r Request) Fill(e *logs.Event) {
	e.Kind = KindRequest
	if a, err := netip.ParseAddr(r.Client); err == nil {
		e.SrcIP = a.Unmap().String()
	} else {
		setField(e, "client", r.Client)
	}
	e.User = r.User
	setField(e, "method", r.Method)
	setField(e, "path", r.Path)
	setField(e, "protocol", r.Proto)
	if r.Status > 0 {
		setField(e, "status", strconv.Itoa(r.Status))
	}
	setField(e, "size", r.Size)
	setField(e, "referer", r.Referer)
	setField(e, "user_agent", r.UserAgent)
	e.Message = fmt.Sprintf("%s %s %s → %d", r.Client, orDash(r.Method), r.Path, r.Status)
	if r.UserAgent != "" {
		e.Message += " (" + r.UserAgent + ")"
	}
}

// Parser reads access log files.
type Parser struct{}

// New returns an access log parser.
func New() *Parser { return &Parser{} }

// Kind implements logs.Parser.
func (*Parser) Kind() logs.Kind { return logs.KindAccess }

// Parse implements logs.Parser.
func (*Parser) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	long, err := logs.ScanLines(ctx, r, logs.MaxLine, func(n int, line string) error {
		line, _ = logs.StripNUL(line)
		if strings.TrimSpace(line) == "" {
			return nil
		}
		req, ok := ParseLine(line)
		if !ok {
			st.Errors++
			return nil
		}
		e := &logs.Event{Time: req.Time, Source: opts.Source, Raw: line, Ref: logs.EvidenceRef{Record: "line " + strconv.Itoa(n)}}
		req.Fill(e)
		if err := emit(e); err != nil {
			return err
		}
		st.Events++
		return nil
	})
	st.Errors += long
	return st, err
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

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// unescape decodes the \" and \\ escapes nginx and Apache write in quoted
// fields; \xHH sequences stay as they are (they are evidence).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(s)
}

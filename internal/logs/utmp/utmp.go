// Package utmp parses the Linux login records: wtmp (logins, logouts,
// boots), btmp (failed logins) and utmp (sessions open at the time).
package utmp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// Record types (ut_type).
const (
	runLevel     = 1
	bootTime     = 2
	newTime      = 3
	oldTime      = 4
	initProcess  = 5
	loginProcess = 6
	userProcess  = 7
	deadProcess  = 8
	accounting   = 9
)

// Event kinds set by this parser.
const (
	KindLogin       = "login"
	KindLogout      = "logout"
	KindLoginFailed = "login-failed"
	KindBoot        = "boot"
	KindShutdown    = "shutdown"
	KindRunLevel    = "runlevel"
	KindClock       = "clock-change"
	KindProcess     = "init-process"
)

// Parser reads one of the utmp family files.
type Parser struct{ kind logs.Kind }

// New returns a parser for kind (logs.KindWtmp, KindBtmp or KindUtmp).
func New(kind logs.Kind) *Parser { return &Parser{kind: kind} }

// Kind implements logs.Parser.
func (p *Parser) Kind() logs.Kind { return p.kind }

// Parse implements logs.Parser.
func (p *Parser) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	rec := make([]byte, logs.UtmpSize)
	for n := 1; ; n++ {
		if n%4096 == 0 && ctx.Err() != nil {
			return st, ctx.Err()
		}
		_, err := io.ReadFull(r, rec)
		if errors.Is(err, io.EOF) {
			return st, nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			st.Errors++ // truncated last record
			return st, nil
		}
		if err != nil {
			return st, err
		}
		e, ok := p.decode(rec, n, opts)
		if !ok {
			st.Errors++
			continue
		}
		if e == nil { // empty slot
			continue
		}
		if err := emit(e); err != nil {
			return st, err
		}
		st.Events++
	}
}

func (p *Parser) decode(rec []byte, n int, opts logs.Options) (*logs.Event, bool) {
	le := binary.LittleEndian
	typ := le.Uint16(rec[0:2])
	if typ == 0 {
		return nil, true // EMPTY: unused utmp slot
	}
	if typ > accounting {
		return nil, false
	}
	line, id, user, host := cstr(rec[8:40]), cstr(rec[40:44]), cstr(rec[44:76]), cstr(rec[76:332])
	pid := le.Uint32(rec[4:8])
	sec, usec := le.Uint32(rec[340:344]), le.Uint32(rec[344:348])
	if usec >= 1_000_000 {
		return nil, false
	}
	e := &logs.Event{
		Time:   time.Unix(int64(sec), int64(usec)*1000).UTC(),
		Source: opts.Source, User: user,
		Raw: fmt.Sprintf("type=%d pid=%d line=%q id=%q user=%q host=%q session=%d exit=%d/%d",
			typ, pid, line, id, user, host, le.Uint32(rec[336:340]), le.Uint16(rec[332:334]), le.Uint16(rec[334:336])),
		Ref:    logs.EvidenceRef{Record: "record " + strconv.Itoa(n)},
		Fields: map[string]string{},
	}
	set := func(k, v string) {
		if v != "" {
			e.Fields[k] = v
		}
	}
	set("tty", line)
	set("pid", strconv.FormatUint(uint64(pid), 10))
	set("id", id)
	set("remote_host", host)
	if ip := addr(rec[348:364]); ip.IsValid() {
		e.SrcIP = ip.String()
	} else if a, err := netip.ParseAddr(host); err == nil {
		e.SrcIP = a.Unmap().String()
	}
	from := ""
	if host != "" {
		from = " from " + host
	}

	if p.kind == logs.KindBtmp {
		e.Kind, e.Severity = KindLoginFailed, logs.Low
		e.Message = fmt.Sprintf("failed login for %s on %s%s", orUnknown(user), orUnknown(line), from)
		return e, true
	}
	switch typ {
	case userProcess:
		e.Kind = KindLogin
		e.Message = fmt.Sprintf("login of %s on %s%s", orUnknown(user), orUnknown(line), from)
	case deadProcess:
		e.Kind = KindLogout
		e.Message = fmt.Sprintf("logout on %s", orUnknown(line))
		if user != "" {
			e.Message = fmt.Sprintf("logout of %s on %s", user, orUnknown(line))
		}
	case bootTime:
		e.Kind, e.Message = KindBoot, "system boot (kernel "+orUnknown(host)+")"
	case runLevel:
		e.Kind, e.Message = KindRunLevel, "run level change"
		if user == "shutdown" {
			e.Kind, e.Message = KindShutdown, "system shutdown"
		}
		set("runlevel", runLevelName(pid))
	case newTime, oldTime:
		e.Kind, e.Severity = KindClock, logs.Low
		e.Message = "system clock changed"
	default: // init, login process, accounting
		e.Kind = KindProcess
		e.Message = fmt.Sprintf("process record (type %d) on %s", typ, orUnknown(line))
	}
	return e, true
}

// cstr reads a NUL padded field.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(bytes.ToValidUTF8(b, []byte("\uFFFD")))
}

// addr decodes ut_addr_v6: an IPv4 address in the first word, or IPv6.
func addr(b []byte) netip.Addr {
	if bytes.Equal(b, make([]byte, 16)) {
		return netip.Addr{}
	}
	if bytes.Equal(b[4:], make([]byte, 12)) {
		return netip.AddrFrom4([4]byte(b[:4]))
	}
	return netip.AddrFrom16([16]byte(b)).Unmap()
}

// runLevelName decodes ut_pid of a RUN_LVL record ('3' + 256*previous).
func runLevelName(pid uint32) string {
	if c := byte(pid & 0xff); c >= '0' && c <= 'z' {
		return string(c)
	}
	return ""
}

func orUnknown(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

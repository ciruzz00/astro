// Package history parses shell history files: bash (with or without the
// "#epoch" lines written when HISTTIMEFORMAT is set) and zsh (plain or
// EXTENDED_HISTORY ": epoch:duration;command" lines).
package history

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// KindCommand is the kind of every event of this parser.
const KindCommand = "shell-command"

// MaxCommand bounds a multi-line command.
const MaxCommand = 64 << 10

var (
	reBashTime = regexp.MustCompile(`^#(\d{9,11})$`)
	reZshExt   = regexp.MustCompile(`^: (\d{9,11}):(\d+);`)
)

// Parser reads bash or zsh history.
type Parser struct{ kind logs.Kind }

// New returns a parser for logs.KindBashHistory or logs.KindZshHistory.
func New(kind logs.Kind) *Parser { return &Parser{kind: kind} }

// Kind implements logs.Parser.
func (p *Parser) Kind() logs.Kind { return p.kind }

// entry is a command being assembled from one or more lines.
type entry struct {
	line     int
	cmd      []string
	time     time.Time
	duration string
	open     bool // zsh: the last line ended with a backslash
	size     int
}

// add appends a line, dropping what exceeds MaxCommand.
func (e *entry) add(line string) {
	if e.size+len(line) > MaxCommand {
		n := max(0, MaxCommand-e.size)
		for n > 0 && line[n]&0xC0 == 0x80 { // do not split a UTF-8 sequence
			n--
		}
		line = line[:n]
	}
	if line == "" && e.size >= MaxCommand {
		return
	}
	e.size += len(line) + 1
	e.cmd = append(e.cmd, line)
}

// Parse implements logs.Parser. Commands without a timestamp get the time
// of the last timestamped command before them, or the file modification
// time, and are flagged TimeUnknown.
func (p *Parser) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	shell := "bash"
	if p.kind == logs.KindZshHistory {
		shell = "zsh"
	}
	user := userFromPath(opts.Path)
	last := opts.ModTime.UTC()
	timed := false // bash: the file has "#epoch" lines
	var cur *entry

	flush := func() error {
		if cur == nil {
			return nil
		}
		e := cur
		cur = nil
		cmd := strings.Join(e.cmd, "\n")
		if strings.TrimSpace(cmd) == "" {
			return nil
		}
		ev := &logs.Event{Source: opts.Source, Kind: KindCommand, User: user, Process: shell,
			CommandLine: cmd, Message: cmd,
			Raw: cmd, Ref: logs.EvidenceRef{Record: "line " + strconv.Itoa(e.line)}}
		if e.time.IsZero() {
			ev.Time, ev.TimeUnknown = last, true
		} else {
			ev.Time, last = e.time, e.time
		}
		if e.duration != "" {
			ev.Fields = map[string]string{"duration_s": e.duration}
		}
		st.Events++
		return emit(ev)
	}

	long, err := logs.ScanRawLines(ctx, r, logs.MaxLine, func(n int, raw []byte) error {
		if shell == "zsh" {
			raw = unmetafy(raw)
		}
		line, nul := logs.StripNUL(strings.ToValidUTF8(string(raw), "\uFFFD"))
		if nul > 0 {
			gap := logs.NULPaddingEvent(opts.Source, n, nul, last)
			gap.User, gap.Raw, gap.TimeUnknown = user, fmt.Sprintf("[%d NUL bytes]", nul), true
			if err := emit(gap); err != nil {
				return err
			}
			st.Events++
		}
		if shell == "bash" {
			return p.bashLine(n, line, &cur, &timed, flush)
		}
		return p.zshLine(n, line, &cur, flush)
	})
	if err == nil {
		err = flush()
	}
	st.Errors += long
	return st, err
}

func (p *Parser) bashLine(n int, line string, cur **entry, timed *bool, flush func() error) error {
	if m := reBashTime.FindStringSubmatch(line); m != nil {
		if err := flush(); err != nil {
			return err
		}
		sec, _ := strconv.ParseInt(m[1], 10, 64)
		*timed = true
		*cur = &entry{line: n + 1, time: time.Unix(sec, 0).UTC()}
		return nil
	}
	// With timestamps, every line up to the next "#epoch" is one command.
	if *timed && *cur != nil {
		(*cur).add(line)
		return nil
	}
	if err := flush(); err != nil {
		return err
	}
	*cur = &entry{line: n}
	(*cur).add(line)
	return flush()
}

func (p *Parser) zshLine(n int, line string, cur **entry, flush func() error) error {
	if c := *cur; c != nil && c.open {
		c.open = strings.HasSuffix(line, `\`)
		c.add(strings.TrimSuffix(line, `\`))
		if !c.open {
			return flush()
		}
		return nil
	}
	if err := flush(); err != nil {
		return err
	}
	e := &entry{line: n}
	if m := reZshExt.FindStringSubmatch(line); m != nil {
		sec, _ := strconv.ParseInt(m[1], 10, 64)
		e.time, e.duration = time.Unix(sec, 0).UTC(), m[2]
		line = line[len(m[0]):]
	}
	e.open = strings.HasSuffix(line, `\`)
	e.add(strings.TrimSuffix(line, `\`))
	*cur = e
	if !e.open {
		return flush()
	}
	return nil
}

// unmetafy decodes zsh's history encoding: a 0x83 byte means the next
// byte was XORed with 0x20.
func unmetafy(b []byte) []byte {
	if bytes.IndexByte(b, 0x83) < 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == 0x83 && i+1 < len(b) {
			i++
			out = append(out, b[i]^0x20)
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// userFromPath guesses whose history it is: /home/alice/.bash_history,
// /root/.zsh_history, C:\triage\home\bob\.bash_history.
func userFromPath(path string) string {
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) < 2 {
		return ""
	}
	dir := parts[len(parts)-2]
	if dir == "root" {
		return "root"
	}
	if len(parts) >= 3 {
		switch strings.ToLower(parts[len(parts)-3]) {
		case "home", "users":
			return dir
		}
	}
	return ""
}

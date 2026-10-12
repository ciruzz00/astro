// Package config reads configuration files that make commands run later,
// as found in triage collections: APT/dpkg hooks (apt.conf.d), crontabs and
// systemd units. Each configured command becomes an event dated with the
// file modification time, so the command rules can judge it.
package config

import (
	"context"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/ciruzz00/astro/internal/logs"
)

// Kinds of the events.
const (
	KindAptHook     = "apt-hook"
	KindCronEntry   = "cron-entry"
	KindSystemdExec = "systemd-exec"
)

var (
	// An APT hook: DPkg::Post-Invoke, APT::Update::Pre-Invoke...
	reHookStart = regexp.MustCompile(`((?:DPkg|APT|Dpkg|apt)::[A-Za-z:-]*(?:Invoke|Install-Pkgs)[A-Za-z-]*)\s*\{`)
	reQuoted    = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
	reCronTime  = regexp.MustCompile(`^(@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|(\S+\s+){4}\S+)\s+`)
	reEnvLine   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)
	reExecKey   = regexp.MustCompile(`^(Exec(Start|StartPre|StartPost|Stop|StopPost|Reload|Condition))\s*=\s*(.*)$`)
)

// Parser reads persistence configuration files.
type Parser struct{}

// New returns a parser for logs.KindConfig.
func New() *Parser { return &Parser{} }

// Kind implements logs.Parser.
func (*Parser) Kind() logs.Kind { return logs.KindConfig }

// maxConfig bounds the bytes read from one configuration file.
const maxConfig = 1 << 20

// Parse implements logs.Parser.
func (*Parser) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	typ := logs.ConfigFile(opts.Path)
	if typ == "" {
		typ = logs.ConfigFile(opts.Source)
	}
	data, err := io.ReadAll(io.LimitReader(r, maxConfig))
	if err != nil {
		return st, err
	}
	if err := ctx.Err(); err != nil {
		return st, err
	}
	text := strings.ToValidUTF8(string(data), "�")
	var entries []entry
	switch typ {
	case logs.ConfigApt:
		entries = aptHooks(text)
	case logs.ConfigCron, logs.ConfigUserCron:
		entries, st.Errors = cronEntries(text, typ == logs.ConfigCron)
	case logs.ConfigSystemd:
		entries = unitExecs(text)
	}
	unit := path.Base(strings.ReplaceAll(opts.Path, `\`, "/"))
	for _, en := range entries {
		if opts.MaxEvents > 0 && st.Events >= opts.MaxEvents {
			st.Truncated = true
			break
		}
		e := &logs.Event{
			Time: opts.ModTime.UTC(), TimeUnknown: opts.ModTime.IsZero(), Host: opts.Host, Source: opts.Source,
			Kind: en.kind, User: en.user, CommandLine: en.command,
			Fields: map[string]string{en.keyName: en.key, "file": unit},
			Raw:    logs.Truncate(en.raw, 4096), Ref: logs.EvidenceRef{Record: "line " + strconv.Itoa(en.line)},
		}
		e.Message = fmt.Sprintf("%s %s in %s: %s", en.label, en.key, unit, logs.Truncate(en.command, 300))
		if err := emit(e); err != nil {
			return st, err
		}
		st.Events++
	}
	return st, nil
}

type entry struct {
	kind, label, keyName, key, user, command, raw string
	line                                          int
}

func lineAt(text string, offset int) int { return strings.Count(text[:offset], "\n") + 1 }

// aptHooks returns the commands of every hook block. Comments are dropped
// first; a block ends at the first "};".
func aptHooks(text string) []entry {
	clean := stripComments(text)
	var out []entry
	for _, loc := range reHookStart.FindAllStringSubmatchIndex(clean, -1) {
		name := clean[loc[2]:loc[3]]
		body := clean[loc[1]:]
		if end := strings.Index(body, "};"); end >= 0 {
			body = body[:end]
		}
		for _, q := range reQuoted.FindAllStringSubmatchIndex(body, -1) {
			cmd := strings.ReplaceAll(body[q[2]:q[3]], `\"`, `"`)
			out = append(out, entry{kind: KindAptHook, label: "APT hook", keyName: "hook", key: name, command: cmd,
				raw: body[q[0]:q[1]], line: lineAt(clean, loc[1]+q[0])})
		}
	}
	return out
}

// stripComments blanks // and # comments outside quotes and /* */ blocks,
// keeping line numbers.
func stripComments(s string) string {
	b := []byte(s)
	inQuote, block := false, false
	for i := 0; i < len(b); i++ {
		switch {
		case block:
			if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
				b[i], b[i+1] = ' ', ' '
				block = false
				i++
			} else if b[i] != '\n' {
				b[i] = ' '
			}
		case inQuote:
			if b[i] == '\\' {
				i++
			} else if b[i] == '"' {
				inQuote = false
			}
		case b[i] == '"':
			inQuote = true
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			b[i], b[i+1] = ' ', ' '
			block = true
			i++
		case b[i] == '#' || (b[i] == '/' && i+1 < len(b) && b[i+1] == '/'):
			for i < len(b) && b[i] != '\n' {
				b[i] = ' '
				i++
			}
		}
	}
	return string(b)
}

// cronEntries reads crontab lines: schedule, optional user, command.
func cronEntries(text string, withUser bool) ([]entry, int) {
	var out []entry
	bad := 0
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || reEnvLine.MatchString(line) {
			continue
		}
		m := reCronTime.FindString(line)
		if m == "" {
			bad++
			continue
		}
		sched, rest := strings.TrimSpace(m), strings.TrimSpace(line[len(m):])
		user := ""
		if withUser {
			f := strings.Fields(rest)
			if len(f) < 2 {
				bad++
				continue
			}
			user, rest = f[0], strings.TrimSpace(rest[len(f[0]):])
		}
		out = append(out, entry{kind: KindCronEntry, label: "cron job", keyName: "schedule", key: sched, user: user,
			command: rest, raw: raw, line: i + 1})
	}
	return out, bad
}

// unitExecs reads the Exec* lines of a systemd unit.
func unitExecs(text string) []entry {
	var out []entry
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		m := reExecKey.FindStringSubmatch(line)
		if m == nil || strings.TrimSpace(m[3]) == "" {
			continue
		}
		// Prefixes change how systemd runs the command: -, @, :, +, !.
		cmd := strings.TrimLeft(strings.TrimSpace(m[3]), "-@:+!")
		out = append(out, entry{kind: KindSystemdExec, label: "systemd", keyName: "directive", key: m[1], command: cmd, raw: raw, line: i + 1})
	}
	return out
}

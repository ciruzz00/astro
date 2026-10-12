// Package live reads listings taken on a running system during triage
// (UAC live_response and similar): the process list of "ps -ef" and the
// TCP sockets of "ss -tanp". They are snapshots: every event carries the
// time of the collection (the file modification time), not the time the
// process started or the connection opened.
package live

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// Kinds of the events.
const (
	KindProcess = "process"
	KindSocket  = "socket"
)

// Processes reads "ps -ef" listings.
type Processes struct{}

// NewProcesses returns a parser for logs.KindProcessList.
func NewProcesses() *Processes { return &Processes{} }

// Kind implements logs.Parser.
func (*Processes) Kind() logs.Kind { return logs.KindProcessList }

// snapshotTime is the time of every event of a listing.
func snapshotTime(opts logs.Options) (time.Time, bool) {
	if opts.ModTime.IsZero() {
		return time.Time{}, true
	}
	return opts.ModTime.UTC(), false
}

// fieldsAt splits the first n whitespace separated fields and returns the
// rest of the line as is (a command line keeps its spaces).
func fieldsAt(line string, n int) ([]string, string, bool) {
	out := make([]string, 0, n)
	rest := line
	for len(out) < n {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			return nil, "", false
		}
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			end = len(rest)
		}
		out = append(out, rest[:end])
		rest = rest[end:]
	}
	return out, strings.TrimSpace(rest), true
}

// Parse implements logs.Parser.
func (*Processes) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	at, unknown := snapshotTime(opts)
	long, err := logs.ScanLines(ctx, r, logs.MaxLine, func(n int, line string) error {
		if n == 1 || strings.TrimSpace(line) == "" {
			return nil // header
		}
		f, cmd, ok := fieldsAt(line, 7)
		if !ok || cmd == "" {
			st.Errors++
			return nil
		}
		pid, err1 := strconv.Atoi(f[1])
		ppid, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil {
			st.Errors++
			return nil
		}
		// Kernel threads have no command line to judge.
		if pid == 2 || ppid == 2 {
			return nil
		}
		if opts.MaxEvents > 0 && st.Events >= opts.MaxEvents {
			st.Truncated = true
			return logs.ErrLimit
		}
		e := &logs.Event{
			Time: at, TimeUnknown: unknown, Host: opts.Host, Source: opts.Source, Kind: KindProcess,
			User: f[0], Process: program(cmd), CommandLine: cmd,
			Message: fmt.Sprintf("running at collection: pid %d (parent %d) %s: %s", pid, ppid, f[0], logs.Truncate(cmd, 300)),
			Fields:  map[string]string{"pid": f[1], "ppid": f[2], "tty": f[5], "start": f[4], "cpu_time": f[6]},
			Raw:     logs.Truncate(line, 4096), Ref: logs.EvidenceRef{Record: "line " + strconv.Itoa(n)},
		}
		if err := emit(e); err != nil {
			return err
		}
		st.Events++
		return nil
	})
	st.Errors += long
	if err == logs.ErrLimit {
		err = nil
	}
	return st, err
}

// program is the executable of a command line, without its folder.
func program(cmd string) string {
	first := cmd
	if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		first = cmd[:i]
	}
	return path.Base(strings.TrimSuffix(first, ":"))
}

// Sockets reads "ss -tanp" listings.
type Sockets struct{}

// NewSockets returns a parser for logs.KindSockets.
func NewSockets() *Sockets { return &Sockets{} }

// Kind implements logs.Parser.
func (*Sockets) Kind() logs.Kind { return logs.KindSockets }

// reUsers reads the process column: users:(("sshd",pid=811,fd=3),...).
var reUsers = regexp.MustCompile(`\("([^"]*)",pid=(\d+)`)

// Parse implements logs.Parser.
func (*Sockets) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	at, unknown := snapshotTime(opts)
	long, err := logs.ScanLines(ctx, r, logs.MaxLine, func(n int, line string) error {
		if n == 1 || strings.TrimSpace(line) == "" {
			return nil
		}
		f, rest, ok := fieldsAt(line, 5)
		if !ok {
			st.Errors++
			return nil
		}
		localIP, localPort, ok1 := splitAddr(f[3])
		peerIP, peerPort, ok2 := splitAddr(f[4])
		if !ok1 || !ok2 {
			st.Errors++
			return nil
		}
		if opts.MaxEvents > 0 && st.Events >= opts.MaxEvents {
			st.Truncated = true
			return logs.ErrLimit
		}
		var names, pids []string
		for _, m := range reUsers.FindAllStringSubmatch(rest, 32) {
			names = append(names, m[1])
			pids = append(pids, m[2])
		}
		owners := make([]string, len(names))
		for i := range names {
			owners[i] = names[i] + "(" + pids[i] + ")"
		}
		e := &logs.Event{
			Time: at, TimeUnknown: unknown, Host: opts.Host, Source: opts.Source, Kind: KindSocket,
			Fields: map[string]string{"state": f[0], "local": f[3], "peer": f[4], "local_port": localPort, "peer_port": peerPort,
				"processes": strings.Join(names, ","), "pids": strings.Join(pids, ",")},
			Raw: logs.Truncate(line, 4096), Ref: logs.EvidenceRef{Record: "line " + strconv.Itoa(n)},
		}
		if len(names) > 0 {
			e.Process = names[0]
		}
		if a, err := netip.ParseAddr(peerIP); err == nil && !a.IsUnspecified() {
			e.DstIP = a.Unmap().String()
		}
		if a, err := netip.ParseAddr(localIP); err == nil && !a.IsUnspecified() {
			e.Fields["local_ip"] = a.Unmap().String()
		}
		e.Message = fmt.Sprintf("socket at collection: %s %s → %s", f[0], f[3], f[4])
		if len(owners) > 0 {
			e.Message += " " + logs.Truncate(strings.Join(owners, " "), 300)
		}
		if err := emit(e); err != nil {
			return err
		}
		st.Events++
		return nil
	})
	st.Errors += long
	if err == logs.ErrLimit {
		err = nil
	}
	return st, err
}

// splitAddr splits "10.0.0.1:22", "[::1]:22", "127.0.0.53%lo:53" and "*:*".
func splitAddr(s string) (ip, port string, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	ip, port = strings.Trim(s[:i], "[]"), s[i+1:]
	if j := strings.IndexByte(ip, '%'); j >= 0 {
		ip = ip[:j]
	}
	if port != "*" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return "", "", false
		}
	}
	return ip, port, true
}

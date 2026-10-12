// Package bodyfile reads filesystem timelines in the bodyfile format of The
// Sleuth Kit (written by fls, mac-robber and UAC):
//
//	MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
//
// Every distinct time of a file becomes an event marked with the MACB
// letters it stands for: m (content modified), a (accessed), c (metadata
// changed: permissions, owner, rename) and b (born, created).
package bodyfile

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// Kinds of the events, after the most telling letter of their time.
const (
	KindCreated  = "file-created"
	KindModified = "file-modified"
	KindChanged  = "file-changed" // metadata only: permissions, owner, links
	KindAccessed = "file-accessed"
)

// Parser reads bodyfiles.
type Parser struct{}

// New returns a bodyfile parser.
func New() *Parser { return &Parser{} }

// Kind implements logs.Parser.
func (*Parser) Kind() logs.Kind { return logs.KindBodyfile }

// Entry is one line of a bodyfile.
type Entry struct {
	MD5, Name, Inode, Mode string
	UID, GID               string
	Size                   int64
	// Times in seconds since the epoch, in MACB order; 0 means unknown.
	Atime, Mtime, Ctime, Crtime int64
}

// ParseLine splits a bodyfile line. The name may contain "|": the fields
// around it have a fixed count.
func ParseLine(line string) (Entry, bool) {
	f := strings.Split(line, "|")
	if len(f) < 11 {
		return Entry{}, false
	}
	n := len(f)
	e := Entry{MD5: f[0], Name: strings.Join(f[1:n-9], "|"), Inode: f[n-9], Mode: f[n-8], UID: f[n-7], GID: f[n-6]}
	var nums [5]int64
	for i, s := range f[n-5:] {
		v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil || v < 0 {
			return Entry{}, false
		}
		nums[i] = v
	}
	e.Size, e.Atime, e.Mtime, e.Ctime, e.Crtime = nums[0], nums[1], nums[2], nums[3], nums[4]
	if e.Name == "" || len(e.Mode) > 24 {
		return Entry{}, false
	}
	return e, true
}

// Mode letters: fls writes "r/rrwxr-xr-x", stat-based tools "-rwxr-xr-x".
func (e Entry) perms() string {
	m := e.Mode
	if i := strings.LastIndexByte(m, '/'); i >= 0 && i < len(m)-1 {
		m = m[i+1:]
	}
	return m
}

// IsDir reports a directory.
func (e Entry) IsDir() bool { p := e.perms(); return p != "" && p[0] == 'd' }

// IsLink reports a symbolic link.
func (e Entry) IsLink() bool { p := e.perms(); return p != "" && p[0] == 'l' }

// pseudo reports kernel filesystems whose times say nothing about activity.
func pseudo(name string) bool {
	for _, p := range []string{"/proc/", "/sys/", "/dev/"} {
		if strings.HasPrefix(name, p) && !strings.HasPrefix(name, "/dev/shm/") {
			return true
		}
	}
	return name == "/proc" || name == "/sys"
}

// maxTime rejects times past 2200 (corrupt entries).
const maxTime = 7258118400

// Parse implements logs.Parser.
func (p *Parser) Parse(ctx context.Context, r io.Reader, opts logs.Options, emit func(*logs.Event) error) (logs.Stats, error) {
	var st logs.Stats
	long, err := logs.ScanLines(ctx, r, logs.MaxLine, func(n int, line string) error {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			return nil
		}
		e, ok := ParseLine(line)
		if !ok {
			st.Errors++
			return nil
		}
		if pseudo(e.Name) {
			return nil
		}
		for _, ev := range events(e, n, opts) {
			if opts.MaxEvents > 0 && st.Events >= opts.MaxEvents {
				st.Truncated = true
				return logs.ErrLimit
			}
			if err := emit(ev); err != nil {
				return err
			}
			st.Events++
		}
		return nil
	})
	st.Errors += long
	if err == logs.ErrLimit {
		err = nil
	}
	return st, err
}

// events groups the times of an entry: one event per distinct time.
func events(e Entry, n int, opts logs.Options) []*logs.Event {
	letters := map[int64][]byte{}
	for i, t := range []int64{e.Mtime, e.Atime, e.Ctime, e.Crtime} {
		if t <= 0 || t > maxTime {
			continue
		}
		if letters[t] == nil {
			letters[t] = []byte("....")
		}
		letters[t][i] = "macb"[i]
	}
	times := make([]int64, 0, len(letters))
	for t := range letters {
		times = append(times, t)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

	var out []*logs.Event
	for _, t := range times {
		macb := string(letters[t])
		kind := KindAccessed
		switch {
		case macb[3] == 'b':
			kind = KindCreated
		case macb[0] == 'm':
			kind = KindModified
		case macb[2] == 'c':
			kind = KindChanged
		}
		// Directory listings and link lookups touch atimes all the time.
		if kind == KindAccessed && (e.IsDir() || e.IsLink()) {
			continue
		}
		ev := &logs.Event{
			Time: time.Unix(t, 0).UTC(), Host: opts.Host, Source: opts.Source, Kind: kind,
			Message: fmt.Sprintf("%s %s (%s, %d bytes, uid %s)", macb, e.Name, e.perms(), e.Size, e.UID),
			Fields: map[string]string{"path": e.Name, "macb": macb, "mode": e.perms(), "uid": e.UID, "gid": e.GID,
				"size": strconv.FormatInt(e.Size, 10), "inode": e.Inode},
			Raw: logs.Truncate(fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|%d|%d|%d", e.MD5, e.Name, e.Inode, e.Mode, e.UID, e.GID,
				e.Size, e.Atime, e.Mtime, e.Ctime, e.Crtime), 4096),
			Ref: logs.EvidenceRef{Record: "line " + strconv.Itoa(n)},
		}
		if e.MD5 != "" && e.MD5 != "0" {
			ev.Fields["md5"] = e.MD5
		}
		out = append(out, ev)
	}
	return out
}

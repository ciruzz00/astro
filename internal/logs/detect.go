package logs

import (
	"bytes"
	"encoding/binary"
	"path"
	"regexp"
	"strings"
)

// Kind is a log file format.
type Kind string

const (
	KindUnknown     Kind = "unknown"
	KindEVTX        Kind = "evtx"
	KindWtmp        Kind = "wtmp" // successful logins and logouts
	KindBtmp        Kind = "btmp" // failed logins
	KindUtmp        Kind = "utmp" // current sessions
	KindSyslog      Kind = "syslog"
	KindBashHistory Kind = "bash-history"
	KindZshHistory  Kind = "zsh-history"
	KindAccess      Kind = "access-log"   // web server access log (Common/Combined)
	KindDocker      Kind = "docker-json"  // Docker json-file container log
	KindBodyfile    Kind = "bodyfile"     // filesystem timeline (The Sleuth Kit bodyfile, UAC)
	KindProcessList Kind = "process-list" // "ps -ef" taken on the live system
	KindSockets     Kind = "socket-list"  // "ss -tanp" taken on the live system
)

// Kinds lists the known formats.
var Kinds = []Kind{KindEVTX, KindWtmp, KindBtmp, KindUtmp, KindSyslog, KindBashHistory, KindZshHistory, KindAccess, KindDocker, KindBodyfile, KindProcessList, KindSockets}

// HeadSize is how many leading bytes Detect needs.
const HeadSize = 4096

// UtmpSize is the size of a Linux utmp/wtmp/btmp record (glibc, 64-bit).
const UtmpSize = 384

var (
	magicEVTX = []byte("ElfFile\x00")
	magicGzip = []byte{0x1f, 0x8b}

	// Syslog lines: RFC 3164 ("Oct 11 21:00:00 host prog[1]: msg"), RFC 5424
	// ("<34>1 2026-10-11T21:00:00Z host ...") and the ISO 8601 format of
	// modern rsyslog and journald exports.
	reSyslog = regexp.MustCompile(`^(?:<\d{1,3}>1 \d{4}-\d\d-\d\dT|[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ |\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d) \S+ )`)
	reZsh    = regexp.MustCompile(`(?m)^: \d{9,11}:\d+;`)
	reAccess = regexp.MustCompile(`^\S+ \S+ \S+ \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "`)
	reDocker = regexp.MustCompile(`^\{"log":".*","stream":"\w+","time":"\d{4}-`)
	// MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
	rePsEf     = regexp.MustCompile(`^\s*UID\s+PID\s+PPID\s+C\s+STIME\s+TTY\s+TIME\s+CMD\s*$`)
	reSSTCP    = regexp.MustCompile(`^State\s+Recv-Q\s+Send-Q\s+Local Address:Port\s+Peer Address:Port`)
	reBodyfile = regexp.MustCompile(`^(?:0|[0-9a-fA-F]{32})\|.+\|[0-9-]+\|[^|]{1,24}\|\d+\|\d+\|\d+\|\d+\|\d+\|\d+\|\d+\s*$`)
)

// IsGzip reports whether head starts a gzip stream (rotated logs: auth.log.2.gz).
func IsGzip(head []byte) bool { return bytes.HasPrefix(head, magicGzip) }

// Detect recognizes a log format from the file name and its first bytes
// (already decompressed for .gz files). Content wins over the name; the
// name only separates formats that share a structure (wtmp, btmp, utmp)
// and confirms text formats that are hard to sniff.
func Detect(name string, head []byte) Kind {
	base := strings.ToLower(path.Base(strings.ReplaceAll(name, `\`, "/")))
	base = strings.TrimSuffix(base, ".gz")

	if bytes.HasPrefix(head, magicEVTX) {
		return KindEVTX
	}
	if looksLikeUtmp(head) {
		switch {
		case strings.HasPrefix(base, "btmp"):
			return KindBtmp
		case strings.HasPrefix(base, "utmp"):
			return KindUtmp
		default:
			return KindWtmp
		}
	}
	// Runs of NUL bytes appear in text logs truncated while being written
	// (log wiping) or after a crash: judge the text around them.
	head = bytes.ReplaceAll(head, []byte{0}, nil)
	if !isText(head) {
		return KindUnknown
	}
	if strings.HasSuffix(base, "history") {
		if reZsh.Match(head) || strings.Contains(base, "zsh") {
			return KindZshHistory
		}
		return KindBashHistory
	}
	first := firstLine(head)
	switch {
	case reSyslog.Match(first):
		return KindSyslog
	case reDocker.Match(first):
		return KindDocker
	case reAccess.Match(first):
		return KindAccess
	case reBodyfile.Match(first):
		return KindBodyfile
	case rePsEf.Match(first) && oneListing(base, "ps_-", "ps_-ef.txt"):
		return KindProcessList
	case reSSTCP.Match(first) && oneListing(base, "ss_-", "ss_-tanp.txt"):
		return KindSockets
	}
	return KindUnknown
}

// oneListing keeps one of the listings UAC saves with different options
// (ps -ef and ps -deaf, ss -tanp and ss -tlnp...), which would repeat the
// same processes and sockets: a file named with the UAC prefix is read
// only if it is the chosen one.
func oneListing(base, uacPrefix, chosen string) bool {
	return !strings.HasPrefix(base, uacPrefix) || base == chosen
}

// looksLikeUtmp checks the first record: a known ut_type, a plausible
// process id and printable, NUL padded line and user fields.
func looksLikeUtmp(head []byte) bool {
	if len(head) < UtmpSize {
		return false
	}
	typ := binary.LittleEndian.Uint16(head[0:2])
	if typ < 1 || typ > 9 || head[2] != 0 || head[3] != 0 {
		return false
	}
	if binary.LittleEndian.Uint32(head[4:8])&(1<<31) != 0 { // negative pid_t
		return false
	}
	return printableField(head[8:40]) && printableField(head[44:76])
}

// printableField accepts a NUL padded ASCII field.
func printableField(b []byte) bool {
	end := bytes.IndexByte(b, 0)
	if end < 0 {
		end = len(b)
	}
	for _, c := range b[:end] {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// isText rejects binary data: many control characters.
func isText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	ctrl := 0
	for _, c := range b {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
			ctrl++
		}
	}
	return ctrl*20 < len(b)
}

func firstLine(b []byte) []byte {
	b = bytes.TrimLeft(b, "\r\n")
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[:i]
	}
	return b
}

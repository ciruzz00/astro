package detect

import (
	"net/netip"
	"path"
	"regexp"
	"strings"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/logs/live"
)

// Rules on the process and socket listings of a live triage.
var (
	reKernelThreadName = regexp.MustCompile(`^\[[^\]]{1,64}\]$`)
	reSocatListener    = regexp.MustCompile(`(?i)\bsocat\b.*\btcp[46]?-listen:.*\b(exec|system|file:/dev/pts|pty)\b`)
	// Programs that should not hold a network connection of their own.
	shellish = map[string]bool{"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "csh": true, "tcsh": true,
		"python": true, "python2": true, "python3": true, "perl": true, "ruby": true, "php": true, "lua": true, "node": true,
		"nc": true, "ncat": true, "netcat": true, "socat": true, "script": true, "telnet": true, "awk": true}
	// Ports of common services: a connection elsewhere stands out.
	commonPorts = map[string]bool{"21": true, "22": true, "25": true, "53": true, "80": true, "110": true, "123": true, "143": true,
		"443": true, "465": true, "587": true, "853": true, "993": true, "995": true, "3478": true, "5222": true, "5228": true,
		"8080": true, "8443": true, "9418": true}
)

func init() {
	eventRules = append(eventRules,
		eventRule{Rule: Rule{"live-hidden-process", "Process running from a hidden or temporary folder", logs.High, "T1564.001"},
			match: func(e *logs.Event) bool { return e.Kind == live.KindProcess && hiddenProgram(e.CommandLine) },
			group: func(e *logs.Event) string { return strings.ToLower(e.Host) + "|" + firstWord(e.CommandLine) }},
		eventRule{Rule: Rule{"live-fake-kernel-thread", "Process disguised as a kernel thread", logs.High, "T1036.004"},
			match: func(e *logs.Event) bool {
				return e.Kind == live.KindProcess && reKernelThreadName.MatchString(strings.TrimSpace(e.CommandLine))
			}},
		eventRule{Rule: Rule{"live-socat-listener", "Shell, terminal or program exposed on the network with socat", logs.Medium, "T1059.004"},
			match: func(e *logs.Event) bool {
				return e.Kind == live.KindProcess && reSocatListener.MatchString(e.CommandLine)
			}},
		eventRule{Rule: Rule{"live-shell-connection", "Shell or interpreter connected to an external address (reverse shell)", logs.High, "T1059.004"},
			match: func(e *logs.Event) bool { return established(e) && external(e.DstIP) && ownedByShell(e) },
			group: func(e *logs.Event) string { return strings.ToLower(e.Host) + "|" + e.DstIP }},
		eventRule{Rule: Rule{"live-unusual-port", "Connection to an external address on an unusual port", logs.Medium, "T1571"},
			match: func(e *logs.Event) bool {
				return established(e) && external(e.DstIP) && !commonPorts[field(e, "peer_port")] && !ownedByShell(e)
			},
			group: func(e *logs.Event) string { return strings.ToLower(e.Host) + "|" + e.DstIP }},
		eventRule{Rule: Rule{"live-shell-listener", "Shell, interpreter or relay listening on the network", logs.High, "T1059.004"},
			match: func(e *logs.Event) bool {
				return e.Kind == live.KindSocket && field(e, "state") == "LISTEN" && ownedByShell(e) && !loopbackListener(e)
			},
			group: func(e *logs.Event) string { return strings.ToLower(e.Host) + "|" + field(e, "local") }},
	)
}

func established(e *logs.Event) bool {
	return e.Kind == live.KindSocket && field(e, "state") == "ESTAB"
}

// external reports a public address: not private, loopback or link-local.
func external(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() || cgnat.Contains(a))
}

func ownedByShell(e *logs.Event) bool {
	for _, p := range strings.Split(field(e, "processes"), ",") {
		if shellish[p] {
			return true
		}
	}
	return false
}

func loopbackListener(e *logs.Event) bool {
	a, err := netip.ParseAddr(field(e, "local_ip"))
	return err == nil && a.IsLoopback()
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// hiddenProgram reports a program started from a temporary folder or from
// a hidden folder (also through a relative path: ./x/../.cache/run).
func hiddenProgram(cmd string) bool {
	prog := firstWord(cmd)
	if !strings.Contains(prog, "/") {
		return false
	}
	if reTempPlace.MatchString(path.Clean(prog)) {
		return true
	}
	for _, c := range strings.Split(prog, "/") {
		if strings.HasPrefix(c, ".") && c != "." && c != ".." && !usualHidden[c] {
			return true
		}
	}
	return false
}

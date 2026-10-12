package syslog

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ciruzz00/astro/internal/logs"
)

// Event kinds set by this parser. Detection rules match on them.
const (
	KindGeneric         = "syslog"
	KindSSHFailed       = "ssh-failed"
	KindSSHAccepted     = "ssh-accepted"
	KindSSHInvalidUser  = "ssh-invalid-user"
	KindSSHDisconnect   = "ssh-disconnect"
	KindAuthFailure     = "auth-failure"
	KindSessionOpened   = "session-opened"
	KindSessionClosed   = "session-closed"
	KindSudo            = "sudo"
	KindSudoFailed      = "sudo-failed"
	KindSudoDenied      = "sudo-denied"
	KindPkexec          = "pkexec"
	KindPkexecDenied    = "pkexec-denied"
	KindSSHListening    = "ssh-listening"
	KindLogindRemoved   = "logind-session-removed"
	KindSu              = "su"
	KindSuFailed        = "su-failed"
	KindUserCreated     = "user-created"
	KindUserDeleted     = "user-deleted"
	KindGroupCreated    = "group-created"
	KindGroupMember     = "group-member-added"
	KindPasswordChanged = "password-changed"
	KindCron            = "cron-command"
	KindLogindSession   = "logind-session"
	KindServiceStarted  = "service-started"
	KindRootLogin       = "root-login"     // login(1): ROOT LOGIN on a terminal
	KindTerminalLogin   = "terminal-login" // login(1): LOGIN ON tty BY user
)

// baseline is the severity of a kind before the detection rules look at
// the context (failures are worth a glance, account changes more).
var baseline = map[string]logs.Severity{
	KindSSHFailed: logs.Low, KindSSHInvalidUser: logs.Low, KindAuthFailure: logs.Low,
	KindSudoFailed: logs.Low, KindSuFailed: logs.Low, KindSudoDenied: logs.Medium, KindPkexecDenied: logs.Medium,
	KindUserCreated: logs.Medium, KindUserDeleted: logs.Medium, KindGroupMember: logs.Medium,
	KindPasswordChanged: logs.Low, KindGroupCreated: logs.Low,
}

var (
	reRepeated    = regexp.MustCompile(`^message repeated (\d+) times: \[ ?(.*?) ?\]$`)
	reSSHFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)`)
	reSSHAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	reSSHInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)(?: port (\d+))?`)
	reSSHDisc     = regexp.MustCompile(`^(?:Disconnected from|Connection closed by|Received disconnect from) (?:(?:authenticating |invalid )?user (\S+) )?(\S+) port (\d+)`)
	rePamSession  = regexp.MustCompile(`^pam_unix\(([^:)]+):session\): session (opened|closed) for user ([^\s(]+)(?:\(uid=\d+\))?(?: by ([^\s(]*)(?:\(uid=\d+\))?)?`)
	rePamAuthFail = regexp.MustCompile(`^pam_unix\(([^:)]+):auth\): authentication failure;(.*)$`)
	rePamPasswd   = regexp.MustCompile(`^pam_unix\(([^:)]+):chauthtok\): password changed for (\S+)`)
	reSudo        = regexp.MustCompile(`^\s*(\S+) : (.*)$`)
	reSu          = regexp.MustCompile(`^(FAILED SU )?\(to (\S+)\) (\S+) on (\S+)`)
	reNewUser     = regexp.MustCompile(`^new user: name=([^,]+), UID=(\d+), GID=(\d+), home=([^,]+), shell=([^,\s]+)`)
	reNewGroup    = regexp.MustCompile(`^new group: name=([^,]+), GID=(\d+)`)
	reAddGroup    = regexp.MustCompile(`^(?:add|adding user) '?([^' ]+)'? to (?:shadow )?group '?([^' ]+)'?`)
	reDelUser     = regexp.MustCompile(`^delete user '([^']+)'`)
	reCron        = regexp.MustCompile(`^\((\S+)\) CMD \((.*)\)$`)
	rePkexec      = regexp.MustCompile(`^(\S+): (Executing command|Error executing command as another user: [^\[]*?) ?\[USER=([^\]]*)\] \[TTY=([^\]]*)\] \[CWD=([^\]]*)\] \[COMMAND=(.*)\]$`)
	rePasswdBy    = regexp.MustCompile(`^password for '([^']+)' changed by '([^']+)'`)
	reListening   = regexp.MustCompile(`^Server listening on (\S+) port (\d+)`)
	reLogindGone  = regexp.MustCompile(`^Removed session (\S+?)\.?$`)
	reLogind      = regexp.MustCompile(`^New session (\S+) of user (\S+?)\.?$`)
	reStarted     = regexp.MustCompile(`^Started (.+?)\.?$`)
	reRootLogin   = regexp.MustCompile(`^ROOT LOGIN\s+(?:ON|on) '?([^'\s]+)'?(?:\s+(?:FROM|from) '?([^'\s]*)'?)?`)
	reTermLogin   = regexp.MustCompile(`^LOGIN ON '?([^'\s]+)'? BY '?([^'\s]+)'?(?: FROM '?([^'\s]*)'?)?`)
)

// classify fills the kind, user, addresses and a readable message.
func classify(e *logs.Event, prog, msg string) {
	if m := reRepeated.FindStringSubmatch(msg); m != nil {
		setField(e, "repeated", m[1])
		msg = m[2]
	}
	e.Kind, e.Message = KindGeneric, msg
	defer func() { e.Severity = baseline[e.Kind] }()

	switch {
	case strings.HasPrefix(msg, "pam_unix("):
		classifyPAM(e, msg)
		return
	case prog == "sshd" || prog == "sshd-session":
		classifySSH(e, msg)
	case prog == "sudo":
		classifySudo(e, msg)
	case prog == "pkexec":
		if m := rePkexec.FindStringSubmatch(msg); m != nil {
			e.Kind, e.User, e.CommandLine = KindPkexec, m[1], m[6]
			setField(e, "target_user", m[3])
			setField(e, "tty", m[4])
			setField(e, "cwd", m[5])
			e.Message = fmt.Sprintf("pkexec by %s as %s: %s", m[1], m[3], m[6])
			if m[2] != "Executing command" {
				e.Kind = KindPkexecDenied
				setField(e, "note", strings.TrimSpace(strings.TrimPrefix(m[2], "Error executing command as another user:")))
				e.Message = fmt.Sprintf("pkexec denied for %s as %s: %s", m[1], m[3], m[6])
			}
		}
	case prog == "passwd" || prog == "chpasswd":
		if m := rePasswdBy.FindStringSubmatch(msg); m != nil {
			e.Kind, e.User = KindPasswordChanged, m[1]
			setField(e, "by", m[2])
			e.Message = fmt.Sprintf("password of %s changed by %s", m[1], m[2])
		}
	case prog == "su":
		if m := reSu.FindStringSubmatch(msg); m != nil {
			e.Kind, e.User = KindSu, m[3]
			setField(e, "target_user", m[2])
			setField(e, "tty", m[4])
			e.Message = fmt.Sprintf("su to %s by %s on %s", m[2], m[3], m[4])
			if m[1] != "" {
				e.Kind, e.Message = KindSuFailed, "Failed "+e.Message
			}
		}
	case prog == "useradd" || prog == "groupadd" || prog == "usermod" || prog == "gpasswd" || prog == "userdel" || prog == "adduser":
		classifyAccounts(e, msg)
	case strings.EqualFold(prog, "cron"):
		if m := reCron.FindStringSubmatch(msg); m != nil {
			e.Kind, e.User, e.CommandLine = KindCron, m[1], m[2]
			e.Message = fmt.Sprintf("cron job of %s: %s", m[1], m[2])
		}
	case prog == "login":
		if m := reRootLogin.FindStringSubmatch(msg); m != nil {
			e.Kind, e.User = KindRootLogin, "root"
			setField(e, "tty", m[1])
			e.Message = "root login on " + m[1]
			if m[2] != "" {
				e.Message += " from " + m[2]
				setIP(e, m[2])
			}
		} else if m := reTermLogin.FindStringSubmatch(msg); m != nil {
			e.Kind, e.User = KindTerminalLogin, m[2]
			setField(e, "tty", m[1])
			e.Message = fmt.Sprintf("login of %s on %s", m[2], m[1])
			if m[3] != "" {
				e.Message += " from " + m[3]
				setIP(e, m[3])
			}
		}
	case prog == "systemd-logind":
		if m := reLogind.FindStringSubmatch(msg); m != nil {
			e.Kind, e.User = KindLogindSession, m[2]
			setField(e, "session", m[1])
		} else if m := reLogindGone.FindStringSubmatch(msg); m != nil {
			e.Kind = KindLogindRemoved
			setField(e, "session", m[1])
		}
	case prog == "systemd":
		if m := reStarted.FindStringSubmatch(msg); m != nil {
			e.Kind = KindServiceStarted
			setField(e, "unit", m[1])
		}
	}
}

func classifySSH(e *logs.Event, msg string) {
	if m := reSSHFailed.FindStringSubmatch(msg); m != nil {
		e.Kind, e.User = KindSSHFailed, m[3]
		setIP(e, m[4])
		setField(e, "method", m[1])
		setField(e, "port", m[5])
		invalid := ""
		if m[2] != "" {
			setField(e, "invalid_user", "true")
			invalid = "invalid user "
		}
		e.Message = fmt.Sprintf("SSH login failed for %s%s from %s (%s)", invalid, m[3], m[4], m[1])
		return
	}
	if m := reSSHAccepted.FindStringSubmatch(msg); m != nil {
		e.Kind, e.User = KindSSHAccepted, m[2]
		setIP(e, m[3])
		setField(e, "method", m[1])
		setField(e, "port", m[4])
		e.Message = fmt.Sprintf("SSH login accepted for %s from %s (%s)", m[2], m[3], m[1])
		return
	}
	if m := reSSHInvalid.FindStringSubmatch(msg); m != nil {
		e.Kind, e.User = KindSSHInvalidUser, m[1]
		setIP(e, m[2])
		setField(e, "port", m[3])
		e.Message = fmt.Sprintf("SSH attempt for unknown user %s from %s", m[1], m[2])
		return
	}
	if m := reSSHDisc.FindStringSubmatch(msg); m != nil {
		e.Kind, e.User = KindSSHDisconnect, m[1]
		setIP(e, m[2])
		setField(e, "port", m[3])
		return
	}
	if m := reListening.FindStringSubmatch(msg); m != nil {
		e.Kind = KindSSHListening
		setField(e, "address", m[1])
		setField(e, "port", m[2])
		e.Message = fmt.Sprintf("SSH server listening on %s port %s", m[1], m[2])
	}
}

func classifyPAM(e *logs.Event, msg string) {
	if m := rePamSession.FindStringSubmatch(msg); m != nil {
		e.Kind, e.User = KindSessionOpened, m[3]
		verb := "opened"
		if m[2] == "closed" {
			e.Kind, verb = KindSessionClosed, "closed"
		}
		setField(e, "service", m[1])
		setField(e, "by", m[4])
		e.Message = fmt.Sprintf("%s session %s for %s", m[1], verb, m[3])
		if m[4] != "" {
			e.Message += " by " + m[4]
		}
		return
	}
	if m := rePamAuthFail.FindStringSubmatch(msg); m != nil {
		e.Kind = KindAuthFailure
		setField(e, "service", m[1])
		kv := keyValues(m[2])
		e.User = kv["user"]
		if kv["rhost"] != "" {
			setIP(e, kv["rhost"])
		}
		setField(e, "tty", kv["tty"])
		setField(e, "ruser", kv["ruser"])
		e.Message = fmt.Sprintf("%s authentication failure", m[1])
		if e.User != "" {
			e.Message += " for " + e.User
		}
		if kv["rhost"] != "" {
			e.Message += " from " + kv["rhost"]
		}
		return
	}
	if m := rePamPasswd.FindStringSubmatch(msg); m != nil {
		e.Kind, e.User = KindPasswordChanged, m[2]
		setField(e, "service", m[1])
		e.Message = "password changed for " + m[2]
	}
}

// classifySudo reads "user : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/sh".
func classifySudo(e *logs.Event, msg string) {
	m := reSudo.FindStringSubmatch(msg)
	if m == nil {
		return
	}
	e.User = m[1]
	body := m[2]
	cmd := ""
	if i := strings.Index(body, "COMMAND="); i >= 0 {
		cmd, body = body[i+len("COMMAND="):], body[:i]
	}
	var note string
	for _, part := range strings.Split(body, " ; ") {
		part = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(part), ";"))
		k, v, ok := strings.Cut(part, "=")
		switch {
		case ok && k == "TTY":
			setField(e, "tty", v)
		case ok && k == "PWD":
			setField(e, "pwd", v)
		case ok && k == "USER":
			setField(e, "target_user", v)
		case !ok && part != "":
			note = part
		}
	}
	e.Kind, e.CommandLine = KindSudo, cmd
	target := orDefault(e.Fields["target_user"], "root")
	e.Message = fmt.Sprintf("sudo by %s as %s: %s", e.User, target, cmd)
	switch {
	case strings.Contains(note, "incorrect password"):
		e.Kind, e.Message = KindSudoFailed, fmt.Sprintf("sudo failed for %s (%s): %s", e.User, note, cmd)
	case strings.Contains(note, "NOT in sudoers") || strings.Contains(note, "not allowed"):
		e.Kind, e.Message = KindSudoDenied, fmt.Sprintf("sudo denied for %s (%s): %s", e.User, note, cmd)
	}
	setField(e, "note", note)
}

func classifyAccounts(e *logs.Event, msg string) {
	switch m := reNewUser.FindStringSubmatch(msg); {
	case m != nil:
		e.Kind, e.User = KindUserCreated, m[1]
		setField(e, "uid", m[2])
		setField(e, "gid", m[3])
		setField(e, "home", m[4])
		setField(e, "shell", m[5])
		e.Message = fmt.Sprintf("user %s created (uid %s, shell %s)", m[1], m[2], m[5])
		return
	}
	if m := reNewGroup.FindStringSubmatch(msg); m != nil {
		e.Kind = KindGroupCreated
		setField(e, "group", m[1])
		setField(e, "gid", m[2])
		e.Message = fmt.Sprintf("group %s created (gid %s)", m[1], m[2])
		return
	}
	if m := reAddGroup.FindStringSubmatch(msg); m != nil {
		e.Kind, e.User = KindGroupMember, m[1]
		setField(e, "group", m[2])
		e.Message = fmt.Sprintf("%s added to group %s", m[1], m[2])
		return
	}
	if m := reDelUser.FindStringSubmatch(msg); m != nil {
		e.Kind, e.User = KindUserDeleted, m[1]
		e.Message = "user " + m[1] + " deleted"
	}
}

// keyValues reads "logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root".
func keyValues(s string) map[string]string {
	out := map[string]string{}
	for _, f := range strings.Fields(s) {
		if k, v, ok := strings.Cut(f, "="); ok && v != "" {
			out[k] = v
		}
	}
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

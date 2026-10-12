package detect

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/logs/config"
	"github.com/ciruzz00/astro/internal/logs/live"
)

func liveEvents(t *testing.T, p logs.Parser, in string) []logs.Event {
	t.Helper()
	var evs []logs.Event
	_, err := p.Parse(context.Background(), strings.NewReader(in), logs.Options{ModTime: t0, Host: "web01"},
		func(e *logs.Event) error { evs = append(evs, *e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestLiveRules(t *testing.T) {
	ps := `UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 08:41 ?        00:00:02 /sbin/init splash
root        1207       1  0 08:42 ?        00:00:00 /usr/bin/socat TCP-LISTEN:2323,fork,reuseaddr EXEC:/opt/legacy/telnetd -n
alice       4100       1  0 09:03 ?        00:00:01 ./tools/../lib/.cache/agent
alice       4101    4100  0 09:04 pts/0    00:00:00 python3 -c import pty; pty.spawn("/bin/bash")
alice       4102       1  0 09:04 ?        00:00:00 /dev/shm/x
root        4103       1  0 09:05 ?        00:00:00 [kworker/9:9]
alice       4104       1  0 09:06 ?        00:00:00 /home/alice/.local/bin/sync-tool --watch
`
	ss := `State  Recv-Q Send-Q   Local Address:Port    Peer Address:PortProcess
LISTEN 0      5              0.0.0.0:5555         0.0.0.0:*    users:(("socat",pid=4200,fd=11))
LISTEN 0      5            127.0.0.1:8888         0.0.0.0:*    users:(("python3",pid=4300,fd=3))
ESTAB  0      0          192.0.2.10:51022   203.0.113.9:4444  users:(("bash",pid=4101,fd=3),("agent",pid=4100,fd=3))
ESTAB  0      0          192.0.2.10:50000  198.51.100.7:6667  users:(("ircbot",pid=4400,fd=5))
ESTAB  0      0          192.0.2.10:50001  198.51.100.8:443   users:(("firefox",pid=4500,fd=50))
ESTAB  0      0          192.0.2.10:50002     10.0.0.5:6667   users:(("ircbot",pid=4400,fd=6))
`
	evs := append(liveEvents(t, live.NewProcesses(), ps), liveEvents(t, live.NewSockets(), ss)...)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
	got, _ := run(evs)
	want := map[string]int{
		"live-hidden-process": 2, "live-fake-kernel-thread": 1, "live-socat-listener": 1,
		"live-shell-connection": 1, "live-unusual-port": 1, "live-shell-listener": 1, "cmd-reverse-shell": 0,
	}
	for id, n := range want {
		total := 0
		for _, f := range got[id] {
			total += f.Count
		}
		if total != n {
			t.Errorf("%s matched %d events, want %d (%+v)", id, total, n, got[id])
		}
	}
	if c := got["live-shell-connection"]; len(c) == 1 && !strings.Contains(c[0].Summary, "203.0.113.9:4444") {
		t.Errorf("shell connection summary = %q", c[0].Summary)
	}
	if ind := Indicators(got["live-shell-connection"]); len(ind) == 0 || ind[0].Value != "203.0.113.9" {
		t.Errorf("indicators = %v", ind)
	}
}

func TestConfigRules(t *testing.T) {
	ev := func(kind, cmd string, f map[string]string) logs.Event {
		return logs.Event{Time: t0, Host: "web01", Kind: kind, CommandLine: cmd, Fields: f, Message: cmd}
	}
	evs := []logs.Event{
		ev(config.KindAptHook, "touch /var/lib/apt/periodic/refresh-stamp 2>/dev/null || true", map[string]string{"hook": "APT::Update::Post-Invoke-Success"}),
		ev(config.KindAptHook, "if [ -d /var/lib/example-notifier ]; then touch /var/lib/example-notifier/run-stamp; fi; /usr/lib/example-notifier/refresh 2>/dev/null || true", map[string]string{"hook": "DPkg::Post-Invoke"}),
		ev(config.KindAptHook, "bash -c 'nohup /usr/local/bin/agent > /dev/null 2>&1 &'", map[string]string{"hook": "DPkg::Post-Invoke"}),
		ev(config.KindCronEntry, "/home/alice/.x/run", map[string]string{"schedule": "@reboot"}),
		ev(config.KindCronEntry, "cd / && run-parts --report /etc/cron.hourly", map[string]string{"schedule": "17 * * * *"}),
		ev(config.KindSystemdExec, "/usr/bin/socat TCP-LISTEN:2323,fork EXEC:/opt/legacy/telnetd", map[string]string{"directive": "ExecStart"}),
	}
	got, _ := run(evs)
	for id, n := range map[string]int{"config-apt-hook": 1, "config-hidden-program": 1, "live-socat-listener": 1} {
		if c := len(got[id]); c != n {
			t.Errorf("%s: %d findings, want %d (%+v)", id, c, n, got[id])
		}
	}
	if h := got["config-apt-hook"]; len(h) == 1 && !strings.Contains(h[0].Summary, "DPkg::Post-Invoke: bash -c") {
		t.Errorf("hook summary = %q", h[0].Summary)
	}
}

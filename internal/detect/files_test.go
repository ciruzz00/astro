package detect

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/logs/bodyfile"
)

// bodyEvents parses an invented bodyfile and returns its events in time order.
func bodyEvents(t *testing.T, lines []string) []logs.Event {
	t.Helper()
	var evs []logs.Event
	_, err := bodyfile.New().Parse(context.Background(), strings.NewReader(strings.Join(lines, "\n")), logs.Options{Host: "web01"},
		func(e *logs.Event) error { evs = append(evs, *e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
	return evs
}

func TestFileRules(t *testing.T) {
	const install, day = 1775000000, 86400
	at := func(d int) int { return install + d }
	// line writes a file whose four times are the same.
	line := func(p, mode string, t int) string {
		return fmt.Sprintf("0|%s|1|%s|0|0|100|%d|%d|%d|%d", p, mode, t, t, t, t)
	}
	read := func(p string, t int) string { // read at t, created at install
		return fmt.Sprintf("0|%s|1|-rw-r--r--|1000|1000|100|%d|%d|%d|%d", p, t, install, install, install)
	}
	lines := []string{
		line("/", "drwxr-xr-x", install),
		line("/etc/cron.d/popularity-contest", "-rw-r--r--", at(600)), // set up with the system
		line("/home/alice/proj/tools/.cache/agent", "-rwxrwxr-x", at(day)),
		line("/home/alice/proj/.git/hooks/pre-commit.sample", "-rwxrwxr-x", at(day)),
		line("/home/alice/.local/bin/tool", "-rwxr-xr-x", at(day)),
		line("/tmp/notes.txt", "-rw-r--r--", at(day)),
		line("/tmp/.X11-unix/x.py", "-rw-rw-r--", at(day)),
		line("/tmp/.X11-unix/X0", "srwxrwxrwx", at(day)),
		line("/var/tmp/stage.sh", "-rw-r--r--", at(day)),
		line("/dev/shm/k", "-rwx------", at(day)),
		line("/etc/apt/apt.conf.d/99hook", "-rw-r--r--", at(day+100)),
		line("/root/.ssh/authorized_keys", "-rw-------", at(day+200)),
		// A package upgrade: new file, content dated before the system.
		fmt.Sprintf("0|/usr/lib/systemd/system/avahi.service|1|-rw-r--r--|0|0|10|%d|%d|%d|%d", at(day), install-day, at(day), at(day)),
		line("/etc/systemd/system/snap.tool.daemon.service", "-rw-r--r--", at(day)),
		line("/etc/systemd/system/backdoor.service", "-rw-r--r--", at(day+300)),
		fmt.Sprintf("0|/usr/bin/lss|1|-rwsr-xr-x|0|0|10|%d|%d|%d|%d", at(day+400), at(day+390), at(day+460), at(day+400)),
		fmt.Sprintf("0|/usr/bin/vim|1|-rwxr-xr-x|0|0|10|%d|%d|%d|%d", at(day), install-day, at(day), at(day)),
		read("/usr/bin/zip", at(2*day)),
		read("/usr/bin/curl", at(2*day+120)),
	}
	for i := range 150 { // a folder archived in two seconds
		lines = append(lines, read(fmt.Sprintf("/home/alice/Documents/f%d.txt", i), at(2*day+10+i/100)))
	}
	for i := range 50 { // music played over an hour
		lines = append(lines, read(fmt.Sprintf("/home/alice/Music/s%d.mp3", i), at(3*day+i*60)))
	}
	got, res := run(bodyEvents(t, lines))
	raised := 0
	for _, id := range got["fs-bulk-read"][0].EventIDs {
		if res.Raise[id] > logs.Info {
			raised++
		}
	}
	if raised != 1 {
		t.Errorf("bulk read raised %d events, want only the first", raised)
	}

	if x := got["fs-socket-dir-file"]; len(x) != 1 || !strings.Contains(x[0].Summary, "x.py") {
		t.Errorf("socket folder = %+v", x)
	}
	if h := got["fs-exec-hidden"]; len(h) != 3 {
		t.Errorf("hidden executables = %+v", h)
	} else if !strings.Contains(h[0].Summary+h[1].Summary, "/home/alice/proj/tools/.cache/agent") {
		t.Errorf("hidden summary = %q / %q", h[0].Summary, h[1].Summary)
	}
	if c := got["fs-cron"]; len(c) != 0 {
		t.Errorf("cron file of the installation flagged: %+v", c)
	}
	if a := got["fs-apt-config"]; len(a) != 1 || !strings.Contains(a[0].Summary, "99hook") {
		t.Errorf("apt hook = %+v", a)
	}
	if u := got["fs-systemd-unit"]; len(u) != 1 || !strings.Contains(u[0].Summary, "backdoor.service") {
		t.Errorf("systemd units = %+v", u)
	}
	if b := got["fs-system-binary"]; len(b) != 1 || b[0].Count != 3 || !strings.Contains(b[0].Summary, "/usr/bin/lss") {
		t.Errorf("system binaries = %+v", b)
	}
	if k := got["fs-ssh-keys"]; len(k) != 1 {
		t.Errorf("ssh keys = %+v", k)
	}
	s := got["fs-archive-then-transfer"]
	if len(s) != 1 || s[0].Count != 2 || !strings.Contains(s[0].Summary, "zip") || !strings.Contains(s[0].Summary, "curl") {
		t.Errorf("staging = %+v", s)
	}
	b := got["fs-bulk-read"]
	if len(b) != 1 || b[0].Count != 150 || !strings.Contains(b[0].Summary, "/home/alice/Documents") {
		t.Errorf("bulk read = %+v", b)
	}
}

func TestHiddenOrTemp(t *testing.T) {
	for p, want := range map[string]bool{
		"/tmp/x":                                true,
		"/var/tmp/a/b":                          true,
		"/usr/bin/.sshd":                        true,
		"/home/bob/p/vendor/.cache/u":           true,
		"/home/bob/.cache/ms-playwright/run":    false,
		"/home/bob/p/node_modules/.bin/tsc":     false,
		"/root/.local/bin/x":                    false,
		"/usr/bin/curl":                         false,
		"/app/home/.cache/uv/archive/x/bin/run": false,
		"/app/.venv/.lock":                      false,
		"/.dockerenv":                           false,
		"/opt/tool/.fossa.yml":                  false,
		"/opt/tool/.hidden":                     true,
	} {
		if got := hiddenOrTemp(p); got != want {
			t.Errorf("hiddenOrTemp(%s) = %v", p, got)
		}
	}
	for m, want := range map[string]bool{"-rwxr-xr-x": true, "-rw-r--r--": false, "-rwSr--r--": false, "-rwsr-xr-x": true, "drwxr-xr-x": false, "-rw": false} {
		if executable(m) != want {
			t.Errorf("executable(%s) != %v", m, want)
		}
	}
}

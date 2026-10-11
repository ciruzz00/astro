package utmp

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ciruzz00/astro/internal/logs"
)

type rec struct {
	typ              uint16
	pid              uint32
	line, user, host string
	ip               []byte
	sec, usec        uint32
}

func (r rec) bytes() []byte {
	b := make([]byte, logs.UtmpSize)
	le := binary.LittleEndian
	le.PutUint16(b[0:], r.typ)
	le.PutUint32(b[4:], r.pid)
	copy(b[8:40], r.line)
	copy(b[40:44], "ts/0")
	copy(b[44:76], r.user)
	copy(b[76:332], r.host)
	le.PutUint32(b[340:], r.sec)
	le.PutUint32(b[344:], r.usec)
	copy(b[348:364], r.ip)
	return b
}

const t0 = 1760216400 // 2025-10-11 21:00:00 UTC

func parse(t *testing.T, kind logs.Kind, data []byte) ([]*logs.Event, logs.Stats) {
	t.Helper()
	var out []*logs.Event
	st, err := New(kind).Parse(context.Background(), bytes.NewReader(data), logs.Options{Source: string(kind)}, func(e *logs.Event) error {
		out = append(out, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out, st
}

func TestWtmp(t *testing.T) {
	var data []byte
	for _, r := range []rec{
		{typ: bootTime, user: "reboot", line: "~", host: "6.8.0-45-generic", sec: t0},
		{typ: runLevel, pid: '5', user: "runlevel", line: "~", host: "6.8.0-45-generic", sec: t0 + 5},
		{typ: userProcess, pid: 1234, line: "pts/0", user: "root", host: "203.0.113.9", ip: []byte{203, 0, 113, 9}, sec: t0 + 60, usec: 250000},
		{typ: userProcess, pid: 1300, line: "pts/1", user: "deploy", host: "2001:db8::7", ip: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}, sec: t0 + 70},
		{typ: deadProcess, pid: 1234, line: "pts/0", sec: t0 + 120},
		{typ: 0},  // empty slot
		{typ: 42}, // corrupt
		{typ: runLevel, pid: '0', user: "shutdown", line: "~~", sec: t0 + 200},
	} {
		data = append(data, r.bytes()...)
	}
	data = append(data, 1, 2, 3) // truncated tail
	evs, st := parse(t, logs.KindWtmp, data)
	if st.Errors != 2 || st.Events != 6 || len(evs) != 6 {
		t.Fatalf("stats = %+v", st)
	}
	kinds := []string{KindBoot, KindRunLevel, KindLogin, KindLogin, KindLogout, KindShutdown}
	for i, k := range kinds {
		if evs[i].Kind != k || evs[i].Time.Location() != time.UTC {
			t.Errorf("event %d kind = %s, want %s", i, evs[i].Kind, k)
		}
	}
	login := evs[2]
	if login.User != "root" || login.SrcIP != "203.0.113.9" || login.Fields["tty"] != "pts/0" ||
		!login.Time.Equal(time.Unix(t0+60, 250000000)) || login.Ref.Record != "record 3" ||
		login.Message != "login of root on pts/0 from 203.0.113.9" {
		t.Errorf("login = %+v", login)
	}
	if evs[3].SrcIP != "2001:db8::7" {
		t.Errorf("IPv6 = %s", evs[3].SrcIP)
	}
	if evs[1].Fields["runlevel"] != "5" || evs[0].Message != "system boot (kernel 6.8.0-45-generic)" {
		t.Errorf("boot/runlevel = %+v %+v", evs[0], evs[1])
	}
	if evs[4].Ref.Record != "record 5" {
		t.Errorf("record numbering = %s", evs[4].Ref.Record)
	}
}

func TestBtmp(t *testing.T) {
	data := rec{typ: loginProcess, line: "ssh:notty", user: "admin", host: "198.51.100.7", sec: t0}.bytes()
	evs, _ := parse(t, logs.KindBtmp, data)
	if len(evs) != 1 || evs[0].Kind != KindLoginFailed || evs[0].Severity != logs.Low || evs[0].SrcIP != "198.51.100.7" || evs[0].User != "admin" {
		t.Errorf("btmp = %+v", evs)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(rec{typ: userProcess, line: "pts/0", user: "root", host: "x", sec: t0}.bytes())
	f.Add(append(rec{typ: bootTime}.bytes(), 0xff))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, err := New(logs.KindWtmp).Parse(context.Background(), bytes.NewReader(data), logs.Options{}, func(e *logs.Event) error {
			if e.Kind == "" || !utf8.ValidString(e.Raw) || !utf8.ValidString(e.User) {
				t.Fatalf("bad event %+v", e)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

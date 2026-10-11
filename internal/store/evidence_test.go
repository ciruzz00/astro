package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

var t0 = time.Date(2026, 10, 11, 21, 0, 0, 0, time.UTC)

func newEvidenceCase(t *testing.T) (*Store, int64, int64) {
	t.Helper()
	s := openTest(t)
	ctx := context.Background()
	if err := s.CreateCase(ctx, Case{Name: "inc-1", TLP: "AMBER"}, t0); err != nil {
		t.Fatal(err)
	}
	ev := Evidence{Path: "/evidence/auth.log", Name: "auth.log", Kind: logs.KindSyslog, Size: 123, ModTime: t0,
		SHA256: strings.Repeat("a", 64), SHA1: strings.Repeat("b", 40), MD5: strings.Repeat("c", 32)}
	id, err := s.AddEvidence(ctx, "inc-1", ev, "analyst", "size 123", t0)
	if err != nil {
		t.Fatal(err)
	}
	caseID, err := s.CaseID(ctx, "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	return s, caseID, id
}

func TestEvidenceAndCustody(t *testing.T) {
	s, _, id := newEvidenceCase(t)
	ctx := context.Background()

	dup := Evidence{Path: "/elsewhere/auth.log", Name: "auth.log", Kind: logs.KindSyslog, SHA256: strings.Repeat("a", 64)}
	if _, err := s.AddEvidence(ctx, "inc-1", dup, "analyst", "", t0); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate content: err = %v, want ErrExists", err)
	}
	if _, err := s.AddEvidence(ctx, "nope", dup, "analyst", "", t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown case: err = %v", err)
	}

	if err := s.AppendCustody(ctx, id, CustodyParsed, "analyst", "12 events", t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyCustody(ctx, id); err != nil {
		t.Fatalf("VerifyCustody: %v", err)
	}
	chain, err := s.Custody(ctx, id)
	if err != nil || len(chain) != 2 || chain[0].Action != CustodyImported || chain[1].PrevHash != chain[0].Hash {
		t.Fatalf("custody = %+v, %v", chain, err)
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE custody_log SET detail = 'forged'`); err == nil {
		t.Error("custody entries can be updated")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM custody_log`); err == nil {
		t.Error("custody entries can be deleted")
	}

	// Bypass the triggers to simulate tampering with the database file.
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER custody_log_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE custody_log SET detail = 'forged' WHERE action = 'parsed'`); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyCustody(ctx, id); !errors.Is(err, ErrCustodyBroken) {
		t.Errorf("tampered chain verified: %v", err)
	}
}

func TestEventsTimeline(t *testing.T) {
	s, caseID, id := newEvidenceCase(t)
	ctx := context.Background()
	evs := []*logs.Event{
		{Time: t0.Add(2 * time.Minute), Seq: 3, Host: "web01", Source: "auth.log", Kind: "ssh-login", User: "root",
			SrcIP: "203.0.113.9", Message: "Accepted password for root", Severity: logs.High, Ref: logs.EvidenceRef{Record: "line 3"},
			Fields: map[string]string{"method": "password"}},
		{Time: t0, Seq: 1, Host: "web01", Source: "auth.log", Kind: "ssh-failed", User: "admin", SrcIP: "203.0.113.9",
			Message: "Failed password for admin", Severity: logs.Medium, YearGuessed: true},
		{Time: t0, Seq: 2, Host: "WEB01", Source: "auth.log", Kind: "sudo", User: "root", Message: "sudo 100%_done",
			CommandLine: "/bin/cat /etc/shadow", Raw: strings.Repeat("x", logs.MaxRaw+10)},
	}
	if err := s.InsertEvents(ctx, caseID, id, evs); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishEvidence(ctx, id, "web01", 1, false); err != nil {
		t.Fatal(err)
	}
	list, err := s.CaseEvidence(ctx, "inc-1")
	if err != nil || len(list) != 1 {
		t.Fatalf("CaseEvidence = %+v, %v", list, err)
	}
	e := list[0]
	if e.Events != 3 || e.ParseErrors != 1 || e.Host != "web01" || !e.FirstEvent.Equal(t0) || !e.LastEvent.Equal(t0.Add(2*time.Minute)) {
		t.Errorf("evidence = %+v", e)
	}

	all, total, err := s.Events(ctx, "inc-1", EventFilter{})
	if err != nil || total != 3 || len(all) != 3 {
		t.Fatalf("Events = %d/%d, %v", len(all), total, err)
	}
	if all[0].Kind != "ssh-failed" || all[1].Kind != "sudo" || all[2].Kind != "ssh-login" {
		t.Errorf("order = %s, %s, %s", all[0].Kind, all[1].Kind, all[2].Kind)
	}
	if !all[0].YearGuessed || all[2].Fields["method"] != "password" || all[2].Ref.Path != "/evidence/auth.log" ||
		all[2].Ref.SHA256 != strings.Repeat("a", 64) || all[2].Ref.Record != "line 3" || !all[2].Time.Equal(t0.Add(2*time.Minute)) {
		t.Errorf("event fields = %+v", all[2])
	}
	if len(all[1].Raw) > logs.MaxRaw+len("…") {
		t.Errorf("raw not truncated: %d bytes", len(all[1].Raw))
	}

	tests := []struct {
		name string
		f    EventFilter
		want int
	}{
		{"severity", EventFilter{MinSeverity: logs.Medium}, 2},
		{"high", EventFilter{MinSeverity: logs.High}, 1},
		{"host ignores case", EventFilter{Host: "web01"}, 3},
		{"user", EventFilter{User: "ROOT"}, 2},
		{"ip", EventFilter{IP: "203.0.113.9"}, 2},
		{"from", EventFilter{From: t0.Add(time.Minute)}, 1},
		{"to", EventFilter{To: t0}, 2},
		{"text in command", EventFilter{Text: "shadow"}, 1},
		{"like is escaped", EventFilter{Text: "100%_"}, 1},
		{"like wildcard literal", EventFilter{Text: "%"}, 1},
		{"kind", EventFilter{Kind: "sudo"}, 1},
		{"page", EventFilter{Limit: 1, Offset: 2}, 1},
	}
	for _, tt := range tests {
		got, total, err := s.Events(ctx, "inc-1", tt.f)
		if err != nil || len(got) != tt.want {
			t.Errorf("%s: %d events (total %d), %v; want %d", tt.name, len(got), total, err, tt.want)
		}
	}
	if _, _, err := s.Events(ctx, "nope", EventFilter{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown case: %v", err)
	}

	// Deleting the case removes evidence, custody and events.
	if err := s.DeleteCase(ctx, "inc-1"); err != nil {
		t.Fatalf("DeleteCase: %v", err)
	}
	for _, table := range []string{"evidence", "custody_log", "events"} {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil || n != 0 { // #nosec G202 -- constant table names
			t.Errorf("%s rows after case deletion = %d, %v", table, n, err)
		}
	}
}

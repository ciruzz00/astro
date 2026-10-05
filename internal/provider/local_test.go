package provider_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/provider/attack"
	"github.com/ciruzz00/astro/internal/provider/kev"
	"github.com/ciruzz00/astro/internal/provider/oui"
	"github.com/ciruzz00/astro/internal/store"
)

// Tests for the providers backed by offline datasets.

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func field(r *provider.Result, name string) string {
	for _, f := range r.Fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

func TestLocalProvidersNeedSync(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	cases := []struct {
		p   provider.Provider
		ind ioc.Indicator
	}{
		{attack.New(s), ioc.Indicator{Type: ioc.AttackTechnique, Value: "T1059"}},
		{kev.New(s), ioc.Indicator{Type: ioc.CVE, Value: "CVE-2021-44228"}},
		{oui.New(s), ioc.Indicator{Type: ioc.MAC, Value: "00:50:56:AA:BB:CC"}},
	}
	for _, c := range cases {
		if _, err := c.p.Lookup(ctx, c.ind); err == nil || !strings.Contains(err.Error(), "astro sync") {
			t.Errorf("%s: err = %v, want hint to run astro sync", c.p.Name(), err)
		}
	}
}

func TestAttackProvider(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	d := store.Dataset{Name: "attack-enterprise", Source: "test", SyncedAt: time.Now()}
	objs := []store.AttackObject{
		{ID: "TA0002", Kind: "tactic", Name: "Execution"},
		{ID: "T1059", Kind: "technique", Name: "Command and Scripting Interpreter", Tactics: []string{"Execution"}},
		{ID: "T1059.001", Kind: "technique", Name: "PowerShell", Tactics: []string{"Execution"}, URL: "https://attack.mitre.org/techniques/T1059/001"},
		{ID: "G0032", Kind: "group", Name: "Lazarus Group", Aliases: []string{"ZINC"}},
		{ID: "M1042", Kind: "mitigation", Name: "Disable or Remove Feature or Program"},
	}
	rels := []store.AttackRelation{
		{SourceID: "T1059.001", Rel: "subtechnique-of", TargetID: "T1059"},
		{SourceID: "G0032", Rel: "uses", TargetID: "T1059.001"},
		{SourceID: "M1042", Rel: "mitigates", TargetID: "T1059.001"},
	}
	if err := s.ReplaceAttack(ctx, d, "enterprise-attack", objs, rels); err != nil {
		t.Fatal(err)
	}
	p := attack.New(s)

	r, err := p.Lookup(ctx, ioc.Indicator{Type: ioc.AttackTechnique, Value: "T1059.001"})
	if err != nil || !r.Found {
		t.Fatalf("Lookup = %+v, %v", r, err)
	}
	checks := map[string]string{
		"Parent technique": "T1059 Command and Scripting Interpreter",
		"Used by groups":   "G0032 Lazarus Group",
		"Mitigations":      "M1042 Disable or Remove Feature or Program",
		"Tactics":          "Execution",
	}
	for k, want := range checks {
		if got := field(r, k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	r, err = p.Lookup(ctx, ioc.Indicator{Type: ioc.Keyword, Value: "zinc"})
	if err != nil || !strings.HasPrefix(r.Summary, "G0032") || field(r, "Uses techniques") != "T1059.001 PowerShell" {
		t.Errorf("keyword lookup = %+v, %v", r, err)
	}

	r, err = p.Lookup(ctx, ioc.Indicator{Type: ioc.AttackTactic, Value: "TA0002"})
	if err != nil || field(r, "Techniques") != "T1059 Command and Scripting Interpreter, T1059.001 PowerShell" {
		t.Errorf("tactic lookup = %+v, %v", r, err)
	}

	r, err = p.Lookup(ctx, ioc.Indicator{Type: ioc.AttackGroup, Value: "G9999"})
	if err != nil || r.Found {
		t.Errorf("unknown ID = %+v, %v", r, err)
	}
}

func TestKEVProvider(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	d := store.Dataset{Name: "kev", Source: "test", SyncedAt: time.Now()}
	if err := s.ReplaceKEV(ctx, d, []store.KEV{{CVE: "CVE-2021-44228", DateAdded: "2021-12-10", Ransomware: "Known"}}); err != nil {
		t.Fatal(err)
	}
	p := kev.New(s)
	r, err := p.Lookup(ctx, ioc.Indicator{Type: ioc.CVE, Value: "CVE-2021-44228"})
	if err != nil || !r.Found || field(r, "Ransomware use") != "Known" {
		t.Errorf("Lookup = %+v, %v", r, err)
	}
	r, err = p.Lookup(ctx, ioc.Indicator{Type: ioc.CVE, Value: "CVE-2000-0001"})
	if err != nil || r.Found {
		t.Errorf("missing CVE = %+v, %v", r, err)
	}
}

func TestOUIProvider(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	d := store.Dataset{Name: "oui", Source: "test", SyncedAt: time.Now()}
	if err := s.ReplaceOUI(ctx, d, []store.OUI{{Prefix: "005056", Registry: "MA-L", Org: "VMware, Inc."}}); err != nil {
		t.Fatal(err)
	}
	p := oui.New(s)

	tests := []struct {
		mac, summary, hint string
		found              bool
	}{
		{"00:50:56:AA:BB:CC", "VMware, Inc.", "VMware virtual NIC", true},
		{"52:54:00:12:34:56", "locally administered", "QEMU/KVM virtual NIC", true},
		{"FF:FF:FF:FF:FF:FF", "broadcast address", "", true},
		{"00:11:22:33:44:55", "vendor not found", "", false},
	}
	for _, tt := range tests {
		r, err := p.Lookup(ctx, ioc.Indicator{Type: ioc.MAC, Value: tt.mac})
		if err != nil {
			t.Fatalf("%s: %v", tt.mac, err)
		}
		if r.Found != tt.found || !strings.HasPrefix(r.Summary, tt.summary) || field(r, "Hint") != tt.hint {
			t.Errorf("%s: %+v", tt.mac, r)
		}
	}
}

package datasets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ciruzz00/astro/internal/store"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseAttack(t *testing.T) {
	b, err := ParseAttack(readFixture(t, "attack.json"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != "18.0" {
		t.Errorf("Version = %q", b.Version)
	}
	byID := map[string]store.AttackObject{}
	for _, o := range b.Objects {
		byID[o.ID] = o
	}
	if _, ok := byID["T9999"]; ok {
		t.Error("revoked object must be dropped")
	}
	ps := byID["T1059.001"]
	if ps.Description != "Adversaries may abuse PowerShell commands." {
		t.Errorf("markdown links not cleaned: %q", ps.Description)
	}
	if !slices.Equal(ps.Tactics, []string{"Execution"}) {
		t.Errorf("Tactics = %v", ps.Tactics)
	}
	if d := byID["T1059"].Description; d != "Adversaries may abuse interpreters.\nRun cmd.exe." {
		t.Errorf("description not cleaned: %q", d)
	}
	if a := byID["G0032"].Aliases; !slices.Equal(a, []string{"HIDDEN COBRA", "ZINC"}) {
		t.Errorf("Aliases = %v (own name must be dropped)", a)
	}
	if s := byID["S0245"]; s.Kind != "software" || s.Subtype != "malware" || len(s.Aliases) != 0 {
		t.Errorf("software = %+v", s)
	}
	if len(b.Relations) != 4 {
		t.Errorf("Relations = %+v, want 4 (revoked and unsupported dropped)", b.Relations)
	}
}

func TestParseAttackRejectsGarbage(t *testing.T) {
	for _, in := range []string{`{`, `{"type":"indicator"}`} {
		if _, err := ParseAttack([]byte(in)); err == nil {
			t.Errorf("ParseAttack(%q) should fail", in)
		}
	}
}

func TestParseKEV(t *testing.T) {
	v, e, err := ParseKEV(readFixture(t, "kev.json"))
	if err != nil {
		t.Fatal(err)
	}
	if v != "2026.10.04" || len(e) != 1 || e[0].Ransomware != "Known" || len(e[0].CWEs) != 3 {
		t.Errorf("ParseKEV = %q %+v", v, e)
	}
	if _, _, err := ParseKEV([]byte(`{"vulnerabilities":[]}`)); err == nil {
		t.Error("empty feed must fail")
	}
}

func TestParseOUI(t *testing.T) {
	e, err := ParseOUI(readFixture(t, "oui.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if len(e) != 3 {
		t.Fatalf("entries = %+v, want 3 (bad prefix skipped)", e)
	}
	if e[0].Org != "VMware, Inc." || e[0].Address != "3401 Hillview Avenue PALO ALTO CA US 94304" {
		t.Errorf("entry = %+v", e[0])
	}
	if _, err := ParseOUI([]byte("a,b,c\n")); err == nil {
		t.Error("unexpected header must fail")
	}
}

func TestSyncAll(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	attack, kev, oui := readFixture(t, "attack.json"), readFixture(t, "kev.json"), readFixture(t, "oui.csv")
	fetch := func(_ context.Context, url string, _ int64) ([]byte, error) {
		switch {
		case strings.HasSuffix(url, "-attack.json"):
			return attack, nil
		case url == kevURL:
			return kev, nil
		case strings.HasSuffix(url, ".csv"):
			return oui, nil
		}
		return nil, errors.New("unexpected url " + url)
	}

	srcs, err := Select(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range srcs {
		if _, err := src.Sync(ctx, fetch, s); err != nil {
			t.Fatalf("sync %s: %v", src.Name, err)
		}
	}
	ds, err := s.Datasets(ctx)
	if err != nil || len(ds) != 5 {
		t.Fatalf("Datasets = %+v, %v", ds, err)
	}
	if o, err := s.OUILookup(ctx, "005056AABBCC"); err != nil || o.Org != "VMware, Inc." {
		t.Errorf("OUILookup = %+v, %v", o, err)
	}
}

func TestSelect(t *testing.T) {
	got, err := Select([]string{"attack"})
	if err != nil || len(got) != 3 {
		t.Fatalf("Select(attack) = %d, %v", len(got), err)
	}
	if _, err := Select([]string{"nope"}); err == nil {
		t.Error("unknown dataset must fail")
	}
}

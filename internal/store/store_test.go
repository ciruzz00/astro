package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenIsIdempotentAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astro.db")
	for range 2 {
		s, err := Open(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("db permissions = %v, want 0600", perm)
	}
}

func TestCache(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)

	if _, _, err := s.CacheGet(ctx, "p", "k", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty cache: err = %v", err)
	}
	if err := s.CachePut(ctx, "p", "k", []byte("v1"), now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.CachePut(ctx, "p", "k", []byte("v2"), now, time.Hour); err != nil {
		t.Fatal(err)
	}
	data, fetched, err := s.CacheGet(ctx, "p", "k", now.Add(time.Minute))
	if err != nil || string(data) != "v2" || !fetched.Equal(now) {
		t.Fatalf("CacheGet = %q, %v, %v", data, fetched, err)
	}
	if _, _, err := s.CacheGet(ctx, "p", "k", now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired entry returned, err = %v", err)
	}
	n, err := s.CachePurge(ctx, now.Add(2*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("CachePurge = %d, %v", n, err)
	}
}

func TestAttack(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	objs := []AttackObject{
		{ID: "T1059", Kind: "technique", Name: "Command and Scripting Interpreter", Tactics: []string{"Execution"}},
		{ID: "T1059.001", Kind: "technique", Name: "PowerShell", Platforms: []string{"Windows"}},
		{ID: "G0032", Kind: "group", Name: "Lazarus Group", Aliases: []string{"HIDDEN COBRA", "ZINC"}},
		{ID: "G9999", Kind: "group", Name: "Old_Group", Deprecated: true},
	}
	rels := []AttackRelation{
		{SourceID: "T1059.001", Rel: "subtechnique-of", TargetID: "T1059"},
		{SourceID: "G0032", Rel: "uses", TargetID: "T1059.001"},
	}
	d := Dataset{Name: "attack-enterprise", Source: "test", Records: len(objs), SyncedAt: time.Now()}
	if err := s.ReplaceAttack(ctx, d, "enterprise-attack", objs, rels); err != nil {
		t.Fatal(err)
	}
	// Replacing again must not duplicate rows.
	if err := s.ReplaceAttack(ctx, d, "enterprise-attack", objs, rels); err != nil {
		t.Fatal(err)
	}

	got, err := s.AttackByID(ctx, "T1059.001")
	if err != nil || len(got) != 1 || got[0].Name != "PowerShell" || got[0].Platforms[0] != "Windows" {
		t.Fatalf("AttackByID = %+v, %v", got, err)
	}

	found, err := s.AttackSearch(ctx, "zinc", 10)
	if err != nil || len(found) != 1 || found[0].ID != "G0032" {
		t.Fatalf("AttackSearch(alias) = %+v, %v", found, err)
	}
	if found, _ := s.AttackSearch(ctx, "_", 10); len(found) != 0 {
		t.Errorf("LIKE wildcards must be escaped, got %+v", found)
	}

	related, err := s.AttackRelated(ctx, "T1059.001")
	if err != nil || len(related) != 2 {
		t.Fatalf("AttackRelated = %+v, %v", related, err)
	}

	ok, err := s.HasDataset(ctx, "attack-enterprise")
	if err != nil || !ok {
		t.Fatalf("HasDataset = %v, %v", ok, err)
	}
}

func TestKEVAndOUI(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	d := Dataset{Name: "x", Source: "test", SyncedAt: time.Now()}

	if err := s.ReplaceKEV(ctx, d, []KEV{{CVE: "CVE-2021-44228", Vendor: "Apache", CWEs: []string{"CWE-20"}}}); err != nil {
		t.Fatal(err)
	}
	k, err := s.KEVByCVE(ctx, "CVE-2021-44228")
	if err != nil || k.Vendor != "Apache" || k.CWEs[0] != "CWE-20" {
		t.Fatalf("KEVByCVE = %+v, %v", k, err)
	}
	if _, err := s.KEVByCVE(ctx, "CVE-2000-0001"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing CVE: err = %v", err)
	}

	err = s.ReplaceOUI(ctx, d, []OUI{
		{Prefix: "8C1F64", Registry: "MA-L", Org: "IEEE Registration Authority"},
		{Prefix: "8C1F64AFA", Registry: "MA-S", Org: "DATA ELECTRONIC DEVICES, INC"},
	})
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.OUILookup(ctx, "8C1F64AFA123")
	if err != nil || o.Registry != "MA-S" {
		t.Fatalf("OUILookup most specific = %+v, %v", o, err)
	}
	o, err = s.OUILookup(ctx, "8C1F64000000")
	if err != nil || o.Registry != "MA-L" {
		t.Fatalf("OUILookup fallback = %+v, %v", o, err)
	}
}

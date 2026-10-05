package cases

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

type fake struct{}

func (fake) Name() string           { return "fake" }
func (fake) Supports(ioc.Type) bool { return true }
func (fake) Lookup(_ context.Context, i ioc.Indicator) (*provider.Result, error) {
	v := provider.VerdictClean
	if i.Value == "198.51.100.7" {
		v = provider.VerdictMalicious
	}
	return &provider.Result{Found: true, Verdict: v, Summary: "fake says " + string(v)}, nil
}

func newService(t *testing.T) *Service {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return New(s, engine.New([]provider.Provider{fake{}}))
}

func ind(v string) ioc.Indicator {
	i, err := ioc.Parse(v)
	if err != nil {
		panic(err)
	}
	return i
}

func TestNormalizeTLP(t *testing.T) {
	for in, want := range map[string]string{
		"amber": TLPAmber, "TLP:RED": TLPRed, " tlp:amber+strict ": TLPAmberStrict, "white": TLPClear, "Clear": TLPClear,
	} {
		if got, err := NormalizeTLP(in); err != nil || got != want {
			t.Errorf("NormalizeTLP(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := NormalizeTLP("purple"); err == nil {
		t.Error("unknown TLP must fail")
	}
}

func TestCaseLifecycle(t *testing.T) {
	s := newService(t)
	ctx := context.Background()

	if err := s.Create(ctx, "sherlock-1", "HTB Sherlock", "green", []string{"htb", "dfir"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, "sherlock-1", "", "", nil); err == nil {
		t.Error("duplicate name must fail")
	}
	for _, bad := range []string{"", "a b", "../x", "-x"} {
		if err := s.Create(ctx, bad, "", "", nil); err == nil {
			t.Errorf("Create(%q) must fail", bad)
		}
	}

	n, err := s.Add(ctx, "sherlock-1", []ioc.Indicator{ind("198.51.100.7"), ind("example.com"), ind("T1059.001")}, "from triage")
	if err != nil || n != 3 {
		t.Fatalf("Add = %d, %v", n, err)
	}
	if n, _ := s.Add(ctx, "sherlock-1", []ioc.Indicator{ind("198.51.100.7")}, ""); n != 0 {
		t.Errorf("re-adding must not duplicate, added %d", n)
	}
	if _, err := s.Add(ctx, "nope", []ioc.Indicator{ind("8.8.8.8")}, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown case: err = %v", err)
	}

	reps, err := s.Search(ctx, "sherlock-1", engine.SearchOptions{}, true)
	if err != nil || len(reps) != 3 {
		t.Fatalf("Search = %d, %v", len(reps), err)
	}
	if reps, _ := s.Search(ctx, "sherlock-1", engine.SearchOptions{}, true); len(reps) != 0 {
		t.Errorf("pendingOnly must skip searched items, got %d", len(reps))
	}

	if err := s.Note(ctx, "sherlock-1", "Initial access via **phishing**"); err != nil {
		t.Fatal(err)
	}
	if err := s.Note(ctx, "sherlock-1", "bad\x1b[2Jnote"); err == nil {
		t.Error("control characters in notes must be rejected")
	}
	if err := s.Tag(ctx, "sherlock-1", []string{"apt"}, []string{"dfir"}); err != nil {
		t.Fatal(err)
	}
	closed := "closed"
	if err := s.Update(ctx, "sherlock-1", nil, nil, nil, &closed); err != nil {
		t.Fatal(err)
	}

	v, err := s.Load(ctx, "sherlock-1")
	if err != nil {
		t.Fatal(err)
	}
	mal, sus, clean, pending := v.Counts()
	if mal != 1 || sus != 0 || clean != 2 || pending != 0 {
		t.Errorf("Counts = %d %d %d %d", mal, sus, clean, pending)
	}
	if v.Case.TLP != TLPGreen || v.Case.Status != "closed" || len(v.Case.Notes) != 1 {
		t.Errorf("case = %+v", v.Case)
	}
	if got := v.Case.Tags; len(got) != 2 || got[0] != "apt" || got[1] != "htb" {
		t.Errorf("tags = %v", got)
	}
	if v.Items[0].Report == nil || v.Items[0].Report.Results[0].Summary != "fake says malicious" || v.Items[0].Note != "from triage" {
		t.Errorf("item = %+v", v.Items[0])
	}

	if list, _ := s.List(ctx, false); len(list) != 0 {
		t.Errorf("closed cases must be hidden by default, got %d", len(list))
	}
	if list, _ := s.List(ctx, true); len(list) != 1 || list[0].Malicious != 1 || list[0].Indicators != 3 {
		t.Errorf("List(all) = %+v", list)
	}

	if err := s.Remove(ctx, "sherlock-1", ind("example.com")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "sherlock-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, "sherlock-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted case: err = %v", err)
	}
}

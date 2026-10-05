package engine

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

type fake struct {
	name    string
	types   []ioc.Type
	verdict provider.Verdict
	err     error
	delay   time.Duration
	panics  bool
	ttl     time.Duration
	calls   atomic.Int32
}

func (f *fake) Name() string { return f.name }

func (f *fake) Supports(t ioc.Type) bool {
	for _, x := range f.types {
		if x == t {
			return true
		}
	}
	return false
}

func (f *fake) CacheTTL() time.Duration { return f.ttl }

func (f *fake) Lookup(ctx context.Context, _ ioc.Indicator) (*provider.Result, error) {
	f.calls.Add(1)
	if f.panics {
		panic("boom")
	}
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	return &provider.Result{Found: true, Verdict: f.verdict, Summary: f.name}, nil
}

var ip = ioc.Indicator{Type: ioc.IPv4, Value: "1.2.3.4"}

func TestSearchAggregates(t *testing.T) {
	providers := []provider.Provider{
		&fake{name: "a", types: []ioc.Type{ioc.IPv4}, verdict: provider.VerdictClean},
		&fake{name: "b", types: []ioc.Type{ioc.IPv4}, verdict: provider.VerdictMalicious, delay: 20 * time.Millisecond},
		&fake{name: "c", types: []ioc.Type{ioc.MD5}, verdict: provider.VerdictMalicious},
		&fake{name: "d", types: []ioc.Type{ioc.IPv4}, err: errors.New("quota exceeded")},
		&fake{name: "e", types: []ioc.Type{ioc.IPv4}, panics: true},
		&fake{name: "f", types: []ioc.Type{ioc.IPv4}, delay: time.Second},
	}
	e := New(providers, WithTimeout(100*time.Millisecond))
	rep := e.Search(context.Background(), ip, SearchOptions{})

	if rep.Verdict != provider.VerdictMalicious {
		t.Errorf("Verdict = %q", rep.Verdict)
	}
	want := []struct{ name, err string }{
		{"a", ""}, {"b", ""}, {"d", "quota exceeded"}, {"e", "internal error in provider"}, {"f", "timed out"},
	}
	if len(rep.Results) != len(want) {
		t.Fatalf("got %d results, want %d", len(rep.Results), len(want))
	}
	for i, w := range want {
		r := rep.Results[i]
		if r.Provider != w.name || r.Error != w.err {
			t.Errorf("result %d = %s/%q, want %s/%q", i, r.Provider, r.Error, w.name, w.err)
		}
	}
}

func TestSearchUsesCache(t *testing.T) {
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	cached := &fake{name: "cached", types: []ioc.Type{ioc.IPv4}, verdict: provider.VerdictSuspicious, ttl: time.Hour}
	live := &fake{name: "live", types: []ioc.Type{ioc.IPv4}}
	e := New([]provider.Provider{cached, live}, WithCache(s))
	ctx := context.Background()

	e.Search(ctx, ip, SearchOptions{})
	rep := e.Search(ctx, ip, SearchOptions{})
	if cached.calls.Load() != 1 || live.calls.Load() != 2 {
		t.Errorf("calls cached=%d live=%d, want 1 and 2", cached.calls.Load(), live.calls.Load())
	}
	if !rep.Results[0].Cached || rep.Results[0].Verdict != provider.VerdictSuspicious {
		t.Errorf("cached result = %+v", rep.Results[0])
	}

	e.Search(ctx, ip, SearchOptions{NoCache: true})
	if cached.calls.Load() != 2 {
		t.Errorf("NoCache must bypass the cache, calls = %d", cached.calls.Load())
	}
}

func TestSearchMany(t *testing.T) {
	e := New([]provider.Provider{&fake{name: "a", types: []ioc.Type{ioc.IPv4, ioc.MD5}}})
	inds := []ioc.Indicator{ip, {Type: ioc.MD5, Value: "d41d8cd98f00b204e9800998ecf8427e"}}
	reps := e.SearchMany(context.Background(), inds, SearchOptions{})
	if len(reps) != 2 || reps[1].Indicator != inds[1] {
		t.Errorf("SearchMany = %+v", reps)
	}
}

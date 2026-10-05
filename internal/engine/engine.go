// Package engine fans a search out to every provider that supports the
// indicator, with timeouts and caching, and aggregates the results.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

// Cache stores provider results between searches.
type Cache interface {
	CacheGet(ctx context.Context, provider, key string, now time.Time) ([]byte, time.Time, error)
	CachePut(ctx context.Context, provider, key string, data []byte, now time.Time, ttl time.Duration) error
}

// Engine runs searches across providers.
type Engine struct {
	providers []provider.Provider
	cache     Cache
	timeout   time.Duration
	log       *slog.Logger
	now       func() time.Time
}

// Option configures an Engine.
type Option func(*Engine)

// WithCache enables result caching.
func WithCache(c Cache) Option { return func(e *Engine) { e.cache = c } }

// WithTimeout sets the per-provider timeout.
func WithTimeout(d time.Duration) Option { return func(e *Engine) { e.timeout = d } }

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option { return func(e *Engine) { e.log = l } }

// New returns an engine over the given providers, kept in that display order.
func New(providers []provider.Provider, opts ...Option) *Engine {
	e := &Engine{providers: providers, timeout: 30 * time.Second, log: slog.Default(), now: time.Now}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Providers returns the configured providers.
func (e *Engine) Providers() []provider.Provider { return e.providers }

// Report is the aggregated outcome of a search.
type Report struct {
	Indicator ioc.Indicator      `json:"indicator"`
	Verdict   provider.Verdict   `json:"verdict,omitempty"`
	Results   []*provider.Result `json:"results"`
	Started   time.Time          `json:"started"`
	Duration  time.Duration      `json:"duration_ns"`
}

// SearchOptions tunes a single search.
type SearchOptions struct {
	NoCache bool
	// Only restricts the search to these provider names; empty means all.
	Only []string
}

// Search queries every supporting provider concurrently.
func (e *Engine) Search(ctx context.Context, ind ioc.Indicator, opts SearchOptions) *Report {
	start := e.now()
	var selected []provider.Provider
	for _, p := range e.providers {
		if p.Supports(ind.Type) && (len(opts.Only) == 0 || slices.Contains(opts.Only, p.Name())) {
			selected = append(selected, p)
		}
	}

	results := make([]*provider.Result, len(selected))
	var wg sync.WaitGroup
	for idx, p := range selected {
		wg.Go(func() {
			results[idx] = e.lookup(ctx, p, ind, opts)
		})
	}
	wg.Wait()

	rep := &Report{Indicator: ind, Results: results, Started: start, Duration: e.now().Sub(start)}
	for _, r := range results {
		if r.Verdict.Rank() > rep.Verdict.Rank() {
			rep.Verdict = r.Verdict
		}
	}
	return rep
}

// SearchMany searches several indicators with bounded concurrency.
func (e *Engine) SearchMany(ctx context.Context, inds []ioc.Indicator, opts SearchOptions) []*Report {
	const parallel = 4
	out := make([]*Report, len(inds))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for idx, ind := range inds {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			out[idx] = e.Search(ctx, ind, opts)
		})
	}
	wg.Wait()
	return out
}

func (e *Engine) lookup(ctx context.Context, p provider.Provider, ind ioc.Indicator, opts SearchOptions) (res *provider.Result) {
	name := p.Name()
	defer func() {
		if v := recover(); v != nil {
			e.log.Error("provider panicked", "provider", name, "panic", v)
			res = &provider.Result{Provider: name, Error: "internal error in provider"}
		}
	}()

	ttl := time.Duration(0)
	if c, ok := p.(provider.Cacheable); ok && e.cache != nil {
		ttl = c.CacheTTL()
	}
	key := ind.String()
	if ttl > 0 && !opts.NoCache {
		if r, ok := e.fromCache(ctx, name, key); ok {
			return r
		}
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	r, err := p.Lookup(ctx, ind)
	if err != nil {
		e.log.Debug("provider lookup failed", "provider", name, "indicator", key, "err", err)
		return &provider.Result{Provider: name, Error: errorMessage(err), FetchedAt: e.now()}
	}
	r.Provider = name
	r.FetchedAt = e.now()

	if ttl > 0 {
		if data, err := json.Marshal(r); err == nil {
			if err := e.cache.CachePut(ctx, name, key, data, r.FetchedAt, ttl); err != nil {
				e.log.Warn("cache write failed", "provider", name, "err", err)
			}
		}
	}
	return r
}

func (e *Engine) fromCache(ctx context.Context, name, key string) (*provider.Result, bool) {
	data, fetched, err := e.cache.CacheGet(ctx, name, key, e.now())
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			e.log.Warn("cache read failed", "provider", name, "err", err)
		}
		return nil, false
	}
	var r provider.Result
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, false
	}
	r.Cached, r.FetchedAt = true, fetched
	return &r, true
}

func errorMessage(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	return fmt.Sprint(err)
}

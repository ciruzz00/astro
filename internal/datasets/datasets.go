// Package datasets downloads and imports the offline datasets
// (MITRE ATT&CK, CISA KEV, IEEE OUI) into the local store.
package datasets

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/store"
)

// Fetcher downloads url, reading at most limit bytes.
type Fetcher func(ctx context.Context, url string, limit int64) ([]byte, error)

// HTTPFetcher returns a Fetcher backed by an HTTP client.
func HTTPFetcher(c *http.Client) Fetcher {
	return func(ctx context.Context, url string, limit int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		return httpx.Do(c, req, limit)
	}
}

// Source is a dataset that can be synced.
type Source struct {
	Name        string
	Description string
	sync        func(ctx context.Context, f Fetcher, s *store.Store, now time.Time) (int, error)
}

const attackBase = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"

// Sources lists every available dataset in sync order.
var Sources = []Source{
	attackSource("enterprise"),
	attackSource("mobile"),
	attackSource("ics"),
	{
		Name:        "kev",
		Description: "CISA Known Exploited Vulnerabilities",
		sync:        syncKEV,
	},
	{
		Name:        "oui",
		Description: "IEEE MAC address registry (MA-L, MA-M, MA-S)",
		sync:        syncOUI,
	},
}

// Select returns the sources matching names. A name matches a source exactly
// or by the part before the dash ("attack" selects every ATT&CK domain).
// No names selects everything.
func Select(names []string) ([]Source, error) {
	if len(names) == 0 {
		return Sources, nil
	}
	var out []Source
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		matched := false
		for _, s := range Sources {
			if s.Name == n || strings.SplitN(s.Name, "-", 2)[0] == n {
				out = append(out, s)
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("unknown dataset %q", n)
		}
	}
	return out, nil
}

// Sync imports one source and returns the number of records stored.
func (src Source) Sync(ctx context.Context, f Fetcher, s *store.Store) (int, error) {
	return src.sync(ctx, f, s, time.Now().UTC())
}

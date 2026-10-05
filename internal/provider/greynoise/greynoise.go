// Package greynoise queries the GreyNoise Community API, which tells whether
// an IP is internet background noise (mass scanners) or a known business service.
package greynoise

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

const (
	name        = "greynoise"
	DefaultBase = "https://api.greynoise.io/v3/community"
)

// Provider queries GreyNoise. The key is optional but raises the daily limit.
type Provider struct {
	client  *http.Client
	base    string
	key     config.Secret
	limiter *rate.Limiter
}

// New returns a GreyNoise provider.
func New(c *http.Client, base string, key config.Secret) *Provider {
	return &Provider{client: c, base: base, key: key, limiter: rate.NewLimiter(rate.Every(time.Second), 3)}
}

func (p *Provider) Name() string { return name }

// Supports IPv4 only: the Community API does not index IPv6.
func (p *Provider) Supports(t ioc.Type) bool { return t == ioc.IPv4 }

func (p *Provider) CacheTTL() time.Duration { return 6 * time.Hour }

// Details is the GreyNoise Community response.
type Details struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	RIOT           bool   `json:"riot"`
	Classification string `json:"classification"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	if err := provider.Wait(ctx, p.limiter); err != nil {
		return nil, err
	}
	h := http.Header{}
	if p.key.IsSet() {
		h.Set("key", p.key.Reveal())
	}
	var d Details
	err := httpx.GetJSON(ctx, p.client, p.base+"/"+url.PathEscape(i.Value), h, &d)
	if errors.Is(err, httpx.ErrNotFound) {
		// GreyNoise answers 404 for IPs it has never observed.
		return provider.NotFound(name, "not observed scanning the internet"), nil
	}
	if err != nil {
		return nil, err
	}

	r := &provider.Result{Provider: name, Found: true, Reference: d.Link, Details: d}
	if r.Reference == "" {
		r.Reference = "https://viz.greynoise.io/ip/" + url.PathEscape(i.Value)
	}
	switch {
	case d.RIOT:
		r.Verdict = provider.VerdictClean
		r.Summary = "known benign business service (RIOT)"
	case d.Classification == "malicious":
		r.Verdict = provider.VerdictMalicious
		r.Summary = "mass scanner with malicious intent"
	case d.Classification == "benign":
		r.Verdict = provider.VerdictClean
		r.Summary = "benign scanner"
	case d.Noise:
		r.Verdict = provider.VerdictSuspicious
		r.Summary = "scanning the internet, intent unknown"
	default:
		r.Verdict = provider.VerdictInfo
		r.Summary = d.Message
	}
	r.Add("Name", d.Name)
	r.Add("Classification", d.Classification)
	r.Add("Last seen", d.LastSeen)
	return r, nil
}

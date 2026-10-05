// Package epss queries FIRST's Exploit Prediction Scoring System.
package epss

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

const (
	name        = "first-epss"
	DefaultBase = "https://api.first.org/data/v1/epss"
)

// Provider queries the public EPSS API (no key required).
type Provider struct {
	client  *http.Client
	base    string
	limiter *rate.Limiter
}

// New returns an EPSS provider.
func New(c *http.Client, base string) *Provider {
	return &Provider{client: c, base: base, limiter: rate.NewLimiter(rate.Every(time.Second), 5)}
}

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool { return t == ioc.CVE }

func (p *Provider) CacheTTL() time.Duration { return 24 * time.Hour }

// Details is the structured payload of an EPSS result.
type Details struct {
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	if err := p.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		} `json:"data"`
	}
	if err := httpx.GetJSON(ctx, p.client, p.base+"?cve="+url.QueryEscape(i.Value), nil, &resp); err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 {
		return provider.NotFound(name, "no EPSS score for this CVE"), nil
	}
	e := resp.Data[0]
	score, err := strconv.ParseFloat(e.EPSS, 64)
	if err != nil {
		return nil, fmt.Errorf("bad epss value %q", e.EPSS)
	}
	pct, err := strconv.ParseFloat(e.Percentile, 64)
	if err != nil {
		return nil, fmt.Errorf("bad percentile value %q", e.Percentile)
	}
	d := Details{EPSS: score, Percentile: pct, Date: e.Date}

	r := &provider.Result{
		Provider:  name,
		Found:     true,
		Verdict:   provider.VerdictInfo,
		Summary:   fmt.Sprintf("%.2f%% probability of exploitation in the next 30 days (higher than %.1f%% of CVEs)", score*100, pct*100),
		Reference: "https://www.first.org/epss/",
		Details:   d,
	}
	r.Addf("EPSS", "%.5f", score)
	r.Addf("Percentile", "%.5f", pct)
	r.Add("Score date", e.Date)
	return r, nil
}

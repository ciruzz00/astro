// Package abuseipdb queries the AbuseIPDB reputation API v2.
package abuseipdb

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

const (
	name        = "abuseipdb"
	DefaultBase = "https://api.abuseipdb.com/api/v2"
	maxAgeDays  = 90
)

// Confidence score thresholds.
const (
	maliciousAt  = 75
	suspiciousAt = 25
)

// Provider queries AbuseIPDB. The free tier allows 1,000 checks per day.
type Provider struct {
	client  *http.Client
	base    string
	key     config.Secret
	limiter *rate.Limiter
}

// New returns an AbuseIPDB provider.
func New(c *http.Client, base string, key config.Secret) *Provider {
	return &Provider{client: c, base: base, key: key, limiter: rate.NewLimiter(rate.Every(time.Second), 5)}
}

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool { return t.IsIP() }

func (p *Provider) CacheTTL() time.Duration { return 6 * time.Hour }

// Details is the AbuseIPDB check result.
type Details struct {
	IPAddress        string   `json:"ipAddress"`
	IsPublic         bool     `json:"isPublic"`
	IsWhitelisted    bool     `json:"isWhitelisted"`
	Score            int      `json:"abuseConfidenceScore"`
	CountryCode      string   `json:"countryCode"`
	UsageType        string   `json:"usageType"`
	ISP              string   `json:"isp"`
	Domain           string   `json:"domain"`
	Hostnames        []string `json:"hostnames"`
	IsTor            bool     `json:"isTor"`
	TotalReports     int      `json:"totalReports"`
	NumDistinctUsers int      `json:"numDistinctUsers"`
	LastReportedAt   string   `json:"lastReportedAt"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	if err := provider.Wait(ctx, p.limiter); err != nil {
		return nil, err
	}
	q := url.Values{"ipAddress": {i.Value}, "maxAgeInDays": {fmt.Sprint(maxAgeDays)}}
	var resp struct {
		Data Details `json:"data"`
	}
	if err := httpx.GetJSON(ctx, p.client, p.base+"/check?"+q.Encode(), http.Header{"Key": {p.key.Reveal()}}, &resp); err != nil {
		return nil, err
	}
	d := resp.Data
	r := &provider.Result{
		Provider:  name,
		Found:     true,
		Verdict:   verdict(d),
		Reference: "https://www.abuseipdb.com/check/" + url.PathEscape(i.Value),
		Details:   d,
	}
	switch {
	case !d.IsPublic:
		r.Summary = "private or reserved address"
	case d.TotalReports == 0:
		r.Summary = fmt.Sprintf("no abuse reports in the last %d days", maxAgeDays)
	default:
		r.Summary = fmt.Sprintf("abuse confidence %d%%, %d reports from %d users in the last %d days",
			d.Score, d.TotalReports, d.NumDistinctUsers, maxAgeDays)
	}
	r.Add("ISP", d.ISP)
	r.Add("Usage", d.UsageType)
	r.Add("Domain", d.Domain)
	r.Add("Country", d.CountryCode)
	r.Add("Hostnames", strings.Join(d.Hostnames, ", "))
	if d.IsTor {
		r.Add("Tor", "exit node")
	}
	if d.IsWhitelisted {
		r.Add("Whitelisted", "yes")
	}
	r.Add("Last reported", d.LastReportedAt)
	return r, nil
}

func verdict(d Details) provider.Verdict {
	switch {
	case !d.IsPublic:
		return provider.VerdictInfo
	case d.IsWhitelisted:
		return provider.VerdictClean
	case d.Score >= maliciousAt:
		return provider.VerdictMalicious
	case d.Score >= suspiciousAt:
		return provider.VerdictSuspicious
	}
	return provider.VerdictClean
}

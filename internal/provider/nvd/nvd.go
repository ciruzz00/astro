// Package nvd queries the NIST National Vulnerability Database (API 2.0).
package nvd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

const (
	name        = "nvd"
	DefaultBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

// Provider queries NVD. It works without a key, with a lower rate limit.
type Provider struct {
	client  *http.Client
	base    string
	key     config.Secret
	limiter *rate.Limiter
}

// New returns an NVD provider. NVD allows 5 requests per 30s without a key, 50 with one.
func New(c *http.Client, base string, key config.Secret) *Provider {
	lim := rate.NewLimiter(rate.Every(6*time.Second), 5)
	if key.IsSet() {
		lim = rate.NewLimiter(rate.Every(600*time.Millisecond), 50)
	}
	return &Provider{client: c, base: base, key: key, limiter: lim}
}

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool { return t == ioc.CVE }

func (p *Provider) CacheTTL() time.Duration { return 24 * time.Hour }

type cvssData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type metric struct {
	Source       string   `json:"source"`
	Type         string   `json:"type"`
	CVSSData     cvssData `json:"cvssData"`
	BaseSeverity string   `json:"baseSeverity"` // v2 keeps severity outside cvssData
}

type reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

type response struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			VulnStatus   string `json:"vulnStatus"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V40 []metric `json:"cvssMetricV40"`
				V31 []metric `json:"cvssMetricV31"`
				V30 []metric `json:"cvssMetricV30"`
				V2  []metric `json:"cvssMetricV2"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []struct {
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			References     []reference `json:"references"`
			CISAExploitAdd string      `json:"cisaExploitAdd"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Details is the structured payload of an NVD result.
type Details struct {
	ID           string   `json:"id"`
	Status       string   `json:"status"`
	Published    string   `json:"published"`
	LastModified string   `json:"last_modified"`
	Description  string   `json:"description"`
	CVSSVersion  string   `json:"cvss_version,omitempty"`
	CVSSScore    float64  `json:"cvss_score,omitempty"`
	CVSSSeverity string   `json:"cvss_severity,omitempty"`
	CVSSVector   string   `json:"cvss_vector,omitempty"`
	CWEs         []string `json:"cwes,omitempty"`
	References   []string `json:"references,omitempty"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	if err := p.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	h := http.Header{}
	if p.key.IsSet() {
		h.Set("apiKey", p.key.Reveal())
	}
	var resp response
	if err := httpx.GetJSON(ctx, p.client, p.base+"?cveId="+url.QueryEscape(i.Value), h, &resp); err != nil {
		return nil, err
	}
	if resp.TotalResults == 0 || len(resp.Vulnerabilities) == 0 {
		return provider.NotFound(name, "CVE not found in NVD"), nil
	}

	c := resp.Vulnerabilities[0].CVE
	d := Details{ID: c.ID, Status: c.VulnStatus, Published: day(c.Published), LastModified: day(c.LastModified)}
	for _, desc := range c.Descriptions {
		if desc.Lang == "en" {
			d.Description = desc.Value
			break
		}
	}
	if m, ok := bestMetric(c.Metrics.V40, c.Metrics.V31, c.Metrics.V30, c.Metrics.V2); ok {
		d.CVSSVersion, d.CVSSScore, d.CVSSVector = m.CVSSData.Version, m.CVSSData.BaseScore, m.CVSSData.VectorString
		d.CVSSSeverity = m.CVSSData.BaseSeverity
		if d.CVSSSeverity == "" {
			d.CVSSSeverity = m.BaseSeverity
		}
	}
	for _, w := range c.Weaknesses {
		for _, desc := range w.Description {
			if strings.HasPrefix(desc.Value, "CWE-") && !slices.Contains(d.CWEs, desc.Value) {
				d.CWEs = append(d.CWEs, desc.Value)
			}
		}
	}
	d.References = rankReferences(c.References)

	r := &provider.Result{
		Provider:  name,
		Found:     true,
		Verdict:   provider.VerdictInfo,
		Reference: "https://nvd.nist.gov/vuln/detail/" + c.ID,
		Details:   d,
	}
	if d.CVSSVersion != "" {
		r.Summary = fmt.Sprintf("CVSS %s %.1f %s", d.CVSSVersion, d.CVSSScore, d.CVSSSeverity)
		r.Add("CVSS", fmt.Sprintf("%.1f %s (%s)", d.CVSSScore, d.CVSSSeverity, d.CVSSVector))
	} else {
		r.Summary = "no CVSS score yet (" + d.Status + ")"
	}
	r.Add("Status", d.Status)
	r.Add("Published", d.Published)
	r.Add("Last modified", d.LastModified)
	r.Add("CWE", strings.Join(d.CWEs, ", "))
	if c.CISAExploitAdd != "" {
		r.Add("CISA KEV", "added "+c.CISAExploitAdd)
	}
	r.Add("Description", provider.Truncate(d.Description, 700))
	r.Add("References", provider.List(d.References, 5))
	return r, nil
}

// bestMetric returns the newest CVSS version available, preferring NVD's
// own (Primary) score over the CNA's.
func bestMetric(groups ...[]metric) (metric, bool) {
	for _, g := range groups {
		for _, m := range g {
			if m.Type == "Primary" {
				return m, true
			}
		}
		if len(g) > 0 {
			return g[0], true
		}
	}
	return metric{}, false
}

// rankReferences lists exploit, advisory and patch references first.
func rankReferences(refs []reference) []string {
	score := func(tags []string) int {
		switch {
		case slices.Contains(tags, "Exploit"):
			return 0
		case slices.Contains(tags, "Vendor Advisory"):
			return 1
		case slices.Contains(tags, "Patch"):
			return 2
		}
		return 3
	}
	sorted := slices.Clone(refs)
	slices.SortStableFunc(sorted, func(a, b reference) int {
		return score(a.Tags) - score(b.Tags)
	})
	out := make([]string, 0, len(sorted))
	for _, r := range sorted {
		out = append(out, r.URL)
	}
	return out
}

func day(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

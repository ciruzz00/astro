// Package otx queries AlienVault Open Threat Exchange (OTX) pulses.
package otx

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
	name        = "alienvault-otx"
	DefaultBase = "https://otx.alienvault.com/api/v1"
)

// Provider queries OTX indicator details.
type Provider struct {
	client  *http.Client
	base    string
	key     config.Secret
	limiter *rate.Limiter
}

// New returns an OTX provider.
func New(c *http.Client, base string, key config.Secret) *Provider {
	return &Provider{client: c, base: base, key: key, limiter: rate.NewLimiter(rate.Every(time.Second), 5)}
}

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool {
	return t.IsHash() || t.IsIP() || t == ioc.Domain || t == ioc.URL || t == ioc.CVE
}

func (p *Provider) CacheTTL() time.Duration { return 6 * time.Hour }

// Pulse is a community threat report referencing the indicator.
type Pulse struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Created         string   `json:"created"`
	Adversary       string   `json:"adversary"`
	TLP             string   `json:"TLP"`
	Tags            []string `json:"tags"`
	MalwareFamilies []struct {
		DisplayName string `json:"display_name"`
	} `json:"malware_families"`
	AttackIDs []struct {
		ID string `json:"id"`
	} `json:"attack_ids"`
}

// Details is the structured payload of an OTX result.
type Details struct {
	PulseCount int      `json:"pulse_count"`
	Pulses     []Pulse  `json:"pulses,omitempty"`
	Whitelist  []string `json:"whitelist,omitempty"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	section := indicatorType(i)
	if err := provider.Wait(ctx, p.limiter); err != nil {
		return nil, err
	}
	var resp struct {
		PulseInfo struct {
			Count  int     `json:"count"`
			Pulses []Pulse `json:"pulses"`
		} `json:"pulse_info"`
		Validation []struct {
			Source  string `json:"source"`
			Message string `json:"message"`
		} `json:"validation"`
		ASN         string `json:"asn"`
		CountryName string `json:"country_name"`
	}
	endpoint := fmt.Sprintf("%s/indicators/%s/%s/general", p.base, section, url.PathEscape(i.Value))
	if err := httpx.GetJSON(ctx, p.client, endpoint, http.Header{"X-OTX-API-KEY": {p.key.Reveal()}}, &resp); err != nil {
		return nil, err
	}

	d := Details{PulseCount: resp.PulseInfo.Count, Pulses: resp.PulseInfo.Pulses}
	for _, v := range resp.Validation {
		d.Whitelist = append(d.Whitelist, strings.TrimSpace(v.Source+": "+v.Message))
	}
	r := &provider.Result{
		Provider:  name,
		Reference: fmt.Sprintf("https://otx.alienvault.com/indicator/%s/%s", section, url.PathEscape(i.Value)),
		Details:   d,
	}
	switch {
	case len(d.Whitelist) > 0:
		r.Found, r.Verdict = true, provider.VerdictClean
		r.Summary = "whitelisted by OTX validation"
	case d.PulseCount > 0:
		r.Found, r.Verdict = true, provider.VerdictSuspicious
		r.Summary = fmt.Sprintf("referenced in %d community pulses", d.PulseCount)
	default:
		r.Summary = "no OTX pulses reference it"
		return r, nil
	}

	families, adversaries, techniques, names := set(), set(), set(), []string{}
	for _, pl := range d.Pulses {
		names = append(names, pl.Name)
		adversaries.add(pl.Adversary)
		for _, m := range pl.MalwareFamilies {
			families.add(m.DisplayName)
		}
		for _, a := range pl.AttackIDs {
			techniques.add(a.ID)
		}
	}
	r.Add("Malware families", provider.List(families.items, 10))
	r.Add("Adversaries", provider.List(adversaries.items, 10))
	r.Add("ATT&CK", provider.List(techniques.items, 15))
	r.Add("Pulses", provider.List(names, 5))
	r.Add("Whitelist", strings.Join(d.Whitelist, "; "))
	r.Add("ASN", resp.ASN)
	r.Add("Country", resp.CountryName)
	return r, nil
}

// indicatorType maps astro types to OTX indicator sections.
func indicatorType(i ioc.Indicator) string {
	switch {
	case i.Type.IsHash():
		return "file"
	case i.Type == ioc.IPv4:
		return "IPv4"
	case i.Type == ioc.IPv6:
		return "IPv6"
	case i.Type == ioc.URL:
		return "url"
	case i.Type == ioc.CVE:
		return "cve"
	case strings.Count(i.Value, ".") > 1:
		return "hostname"
	}
	return "domain"
}

type stringSet struct {
	seen  map[string]bool
	items []string
}

func set() *stringSet { return &stringSet{seen: map[string]bool{}} }

func (s *stringSet) add(v string) {
	v = strings.TrimSpace(v)
	if v != "" && !s.seen[v] {
		s.seen[v] = true
		s.items = append(s.items, v)
	}
}

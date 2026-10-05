// Package shodan reports the internet exposure of an IP: open ports, services
// and known vulnerabilities. It uses the Shodan host API when a key is set and
// the free, keyless InternetDB otherwise.
package shodan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

const (
	name               = "shodan"
	DefaultBase        = "https://api.shodan.io"
	DefaultInternetDB  = "https://internetdb.shodan.io"
	maxListedPorts     = 30
	maxListedVulns     = 15
	maxListedHostnames = 10
	maxListedServices  = 10
)

// Provider queries Shodan.
type Provider struct {
	client     *http.Client
	base       string
	internetDB string
	key        config.Secret
	limiter    *rate.Limiter
}

// New returns a Shodan provider; without a key it falls back to InternetDB.
func New(c *http.Client, base, internetDB string, key config.Secret) *Provider {
	return &Provider{client: c, base: base, internetDB: internetDB, key: key, limiter: rate.NewLimiter(rate.Every(time.Second), 1)}
}

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool { return t.IsIP() }

func (p *Provider) CacheTTL() time.Duration { return 24 * time.Hour }

// Details is the structured payload of a Shodan result.
type Details struct {
	Source     string   `json:"source"`
	Ports      []int    `json:"ports"`
	Hostnames  []string `json:"hostnames,omitempty"`
	Vulns      []string `json:"vulns,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	CPEs       []string `json:"cpes,omitempty"`
	Services   []string `json:"services,omitempty"`
	Org        string   `json:"org,omitempty"`
	ISP        string   `json:"isp,omitempty"`
	ASN        string   `json:"asn,omitempty"`
	OS         string   `json:"os,omitempty"`
	Country    string   `json:"country,omitempty"`
	City       string   `json:"city,omitempty"`
	LastUpdate string   `json:"last_update,omitempty"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	if err := provider.Wait(ctx, p.limiter); err != nil {
		return nil, err
	}
	var (
		d   Details
		err error
	)
	if p.key.IsSet() {
		d, err = p.host(ctx, i.Value)
	} else {
		d, err = p.internetDBLookup(ctx, i.Value)
	}
	if errors.Is(err, httpx.ErrNotFound) {
		return provider.NotFound(name, "no exposed services seen by Shodan"), nil
	}
	if err != nil {
		return nil, err
	}

	sort.Ints(d.Ports)
	ports := make([]string, len(d.Ports))
	for k, port := range d.Ports {
		ports[k] = fmt.Sprint(port)
	}
	r := &provider.Result{
		Provider:  name,
		Found:     true,
		Verdict:   provider.VerdictInfo,
		Summary:   fmt.Sprintf("%d open ports, %d known vulnerabilities (%s)", len(d.Ports), len(d.Vulns), d.Source),
		Reference: "https://www.shodan.io/host/" + url.PathEscape(i.Value),
		Details:   d,
	}
	r.Add("Ports", provider.List(ports, maxListedPorts))
	r.Add("Services", provider.List(d.Services, maxListedServices))
	r.Add("Vulns", provider.List(d.Vulns, maxListedVulns))
	r.Add("Hostnames", provider.List(d.Hostnames, maxListedHostnames))
	r.Add("Tags", strings.Join(d.Tags, ", "))
	r.Add("Org", d.Org)
	if d.ISP != d.Org {
		r.Add("ISP", d.ISP)
	}
	r.Add("ASN", d.ASN)
	r.Add("OS", d.OS)
	r.Add("Location", strings.Trim(d.City+", "+d.Country, ", "))
	r.Add("CPE", provider.List(d.CPEs, 5))
	r.Add("Last update", d.LastUpdate)
	return r, nil
}

func (p *Provider) host(ctx context.Context, ip string) (Details, error) {
	var resp struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		Vulns     []string `json:"vulns"`
		Tags      []string `json:"tags"`
		Org       string   `json:"org"`
		ISP       string   `json:"isp"`
		ASN       string   `json:"asn"`
		OS        string   `json:"os"`
		Country   string   `json:"country_name"`
		City      string   `json:"city"`
		Updated   string   `json:"last_update"`
		Data      []struct {
			Port      int    `json:"port"`
			Transport string `json:"transport"`
			Product   string `json:"product"`
			Version   string `json:"version"`
		} `json:"data"`
	}
	// Shodan only accepts the key as a query parameter; httpx strips query
	// strings from errors so it cannot leak into messages.
	endpoint := p.base + "/shodan/host/" + url.PathEscape(ip) + "?minify=false&key=" + url.QueryEscape(p.key.Reveal())
	if err := httpx.GetJSON(ctx, p.client, endpoint, nil, &resp); err != nil {
		return Details{}, err
	}
	d := Details{
		Source: "Shodan", Ports: resp.Ports, Hostnames: resp.Hostnames, Vulns: resp.Vulns, Tags: resp.Tags,
		Org: resp.Org, ISP: resp.ISP, ASN: resp.ASN, OS: resp.OS, Country: resp.Country, City: resp.City,
		LastUpdate: resp.Updated,
	}
	for _, s := range resp.Data {
		svc := fmt.Sprintf("%d/%s %s %s", s.Port, s.Transport, s.Product, s.Version)
		d.Services = append(d.Services, strings.TrimSpace(svc))
	}
	sort.Strings(d.Vulns)
	return d, nil
}

func (p *Provider) internetDBLookup(ctx context.Context, ip string) (Details, error) {
	var resp struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		Vulns     []string `json:"vulns"`
		Tags      []string `json:"tags"`
		CPEs      []string `json:"cpes"`
	}
	if err := httpx.GetJSON(ctx, p.client, p.internetDB+"/"+url.PathEscape(ip), nil, &resp); err != nil {
		return Details{}, err
	}
	sort.Strings(resp.Vulns)
	return Details{
		Source: "InternetDB", Ports: resp.Ports, Hostnames: resp.Hostnames,
		Vulns: resp.Vulns, Tags: resp.Tags, CPEs: resp.CPEs,
	}, nil
}

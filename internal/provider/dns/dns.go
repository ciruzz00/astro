// Package dns resolves host names and IP addresses with DNS-over-HTTPS.
//
// DNS-over-HTTPS goes through astro's hardened HTTP client, works the same on
// every platform and inside containers, and keeps lookups out of the local or
// corporate resolver logs. The authoritative name servers of the domain still
// see a query, coming from the DoH resolver.
package dns

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/provider/hostinfo"
)

const (
	name = "dns"
	// DefaultBase is Cloudflare's DNS-over-HTTPS JSON endpoint.
	DefaultBase = "https://cloudflare-dns.com/dns-query"
	maxTXT      = 8
)

// DNS response codes (RFC 1035 / 2136).
const (
	rcodeOK       = 0
	rcodeNXDomain = 3
)

// Record types queried for host names, in display order.
var hostTypes = []struct {
	name string
	code int
}{{"A", 1}, {"AAAA", 28}, {"CNAME", 5}, {"MX", 15}, {"NS", 2}, {"TXT", 16}}

const typePTR = 12

// Provider resolves names through a DNS-over-HTTPS JSON API.
type Provider struct {
	client  *http.Client
	base    string
	limiter *rate.Limiter
}

// New returns a DNS provider.
func New(c *http.Client, base string) *Provider {
	return &Provider{client: c, base: base, limiter: rate.NewLimiter(rate.Every(100*time.Millisecond), 20)}
}

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool {
	return t == ioc.Domain || t == ioc.URL || t == ioc.Email || t.IsIP()
}

func (p *Provider) CacheTTL() time.Duration { return time.Hour }

// Details lists the records found, by type.
type Details struct {
	Name     string              `json:"name"`
	NXDomain bool                `json:"nxdomain"`
	Records  map[string][]string `json:"records,omitempty"`
}

type answer struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	if i.Type.IsIP() {
		return p.reverse(ctx, i.Value)
	}
	host := hostinfo.HostOf(i)
	if host == "" {
		return provider.NotFound(name, "no host name to resolve"), nil
	}
	types := hostTypes
	if i.Type == ioc.Email {
		types = hostTypes[3:4] // MX: where mail for the address goes
	}

	d := Details{Name: host, Records: map[string][]string{}}
	for _, t := range types {
		a, err := p.query(ctx, host, t.code)
		if err != nil {
			return nil, err
		}
		if a.Status == rcodeNXDomain {
			d.NXDomain = true
			break
		}
		for _, rr := range a.Answer {
			if rr.Type == t.code {
				d.Records[t.name] = append(d.Records[t.name], clean(rr.Data))
			}
		}
	}
	sortMX(d.Records["MX"])

	r := &provider.Result{Provider: name, Verdict: provider.VerdictInfo, Details: d,
		Reference: "https://dns.google/query?name=" + url.QueryEscape(host)}
	if d.NXDomain {
		r.Summary = host + " does not exist (NXDOMAIN)"
		return r, nil
	}
	if len(d.Records) == 0 {
		r.Summary = "no records for " + host
		return r, nil
	}
	r.Found = true
	addrs := len(d.Records["A"]) + len(d.Records["AAAA"])
	switch {
	case i.Type == ioc.Email:
		r.Summary = fmt.Sprintf("mail for %s is handled by %s", host, provider.List(d.Records["MX"], 3))
	case addrs > 0:
		r.Summary = fmt.Sprintf("%s resolves to %d addresses", host, addrs)
	default:
		r.Summary = host + " has records but no address"
	}
	for _, t := range types {
		recs := d.Records[t.name]
		if t.name == "TXT" && len(recs) > maxTXT {
			recs = append(recs[:maxTXT], fmt.Sprintf("(+%d more)", len(d.Records["TXT"])-maxTXT))
		}
		if len(recs) > 0 {
			r.Add(t.name, strings.Join(recs, "\n"))
		}
	}
	return r, nil
}

func (p *Provider) reverse(ctx context.Context, ip string) (*provider.Result, error) {
	arpa, err := reverseName(ip)
	if err != nil {
		return nil, err
	}
	a, err := p.query(ctx, arpa, typePTR)
	if err != nil {
		return nil, err
	}
	d := Details{Name: arpa, NXDomain: a.Status == rcodeNXDomain, Records: map[string][]string{}}
	for _, rr := range a.Answer {
		if rr.Type == typePTR {
			d.Records["PTR"] = append(d.Records["PTR"], clean(rr.Data))
		}
	}
	r := &provider.Result{Provider: name, Verdict: provider.VerdictInfo, Details: d}
	if len(d.Records["PTR"]) == 0 {
		r.Summary = "no reverse DNS (PTR) name"
		return r, nil
	}
	r.Found = true
	r.Summary = "reverse DNS: " + strings.Join(d.Records["PTR"], ", ")
	r.Add("PTR", strings.Join(d.Records["PTR"], "\n"))
	return r, nil
}

func (p *Provider) query(ctx context.Context, qname string, qtype int) (*answer, error) {
	if err := provider.Wait(ctx, p.limiter); err != nil {
		return nil, err
	}
	q := url.Values{"name": {qname}, "type": {fmt.Sprint(qtype)}}
	var a answer
	if err := httpx.GetJSON(ctx, p.client, p.base+"?"+q.Encode(), http.Header{"Accept": {"application/dns-json"}}, &a); err != nil {
		return nil, err
	}
	if a.Status != rcodeOK && a.Status != rcodeNXDomain {
		return nil, fmt.Errorf("DNS error (rcode %d) for %s", a.Status, qname)
	}
	return &a, nil
}

// sortMX orders MX records by preference and spells out a null MX (RFC 7505).
func sortMX(mx []string) {
	pref := func(s string) int {
		f, _, _ := strings.Cut(s, " ")
		n, err := strconv.Atoi(f)
		if err != nil {
			return math.MaxInt
		}
		return n
	}
	sort.SliceStable(mx, func(a, b int) bool { return pref(mx[a]) < pref(mx[b]) })
	for k, v := range mx {
		if v == "0" {
			mx[k] = "none (null MX: the domain accepts no mail)"
		}
	}
}

// reverseName returns the in-addr.arpa or ip6.arpa name of an address.
func reverseName(ip string) (string, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", errors.New("invalid IP address")
	}
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0]), nil
	}
	b := a.As16()
	var sb strings.Builder
	for k := len(b) - 1; k >= 0; k-- {
		fmt.Fprintf(&sb, "%x.%x.", b[k]&0x0f, b[k]>>4)
	}
	sb.WriteString("ip6.arpa")
	return sb.String(), nil
}

// clean removes the trailing dot of names and the quotes of TXT data.
func clean(s string) string {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) >= 2 && s[0] == '"' {
		s = strings.ReplaceAll(strings.Trim(s, `"`), `" "`, "")
	}
	return s
}

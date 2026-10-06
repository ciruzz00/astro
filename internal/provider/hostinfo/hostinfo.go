// Package hostinfo analyzes host names offline: registrable domain, public
// suffix, subdomain depth, internationalized names and look-alike characters.
package hostinfo

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

const name = "hostinfo"

// Thresholds of the "algorithmically generated" hint on the longest label.
const (
	dgaMinLength  = 15
	dgaMinEntropy = 3.8
)

// Provider needs no network access.
type Provider struct{}

// New returns a host analysis provider.
func New() *Provider { return &Provider{} }

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool {
	return t == ioc.Domain || t == ioc.URL || t == ioc.Email
}

// Details is the structured payload of a host analysis.
type Details struct {
	Host              string   `json:"host"`
	Unicode           string   `json:"unicode,omitempty"`
	RegistrableDomain string   `json:"registrable_domain,omitempty"`
	PublicSuffix      string   `json:"public_suffix"`
	ICANN             bool     `json:"icann"`
	SubdomainLevels   int      `json:"subdomain_levels"`
	Length            int      `json:"length"`
	LongestLabel      string   `json:"longest_label"`
	Entropy           float64  `json:"entropy"`
	Hints             []string `json:"hints,omitempty"`
}

// HostOf returns the host name of a domain, URL or email indicator, or ""
// when there is none (e.g. a URL pointing to an IP address).
func HostOf(i ioc.Indicator) string {
	switch i.Type {
	case ioc.Domain:
		return i.Value
	case ioc.Email:
		if _, d, ok := strings.Cut(i.Value, "@"); ok {
			return d
		}
	case ioc.URL:
		u, err := url.Parse(i.Value)
		if err != nil {
			return ""
		}
		h := u.Hostname()
		if parsed, err := ioc.Parse(h); err == nil && parsed.Type == ioc.Domain {
			return h
		}
	}
	return ""
}

// RegisteredDomain returns the domain registered at an ICANN registry, the one
// RDAP and WHOIS know. Under a private suffix (github.io, s3.amazonaws.com) it
// is the owner of the suffix, not the customer's subdomain.
func RegisteredDomain(host string) string {
	if suffix, icann := publicsuffix.PublicSuffix(host); !icann {
		for c := suffix; strings.Contains(c, "."); {
			_, parent, _ := strings.Cut(c, ".")
			if ps, ok := publicsuffix.PublicSuffix(parent); ok && ps == parent {
				return c
			}
			c = parent
		}
	}
	if reg, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return reg
	}
	return host
}

func (p *Provider) Lookup(_ context.Context, i ioc.Indicator) (*provider.Result, error) {
	host := HostOf(i)
	if host == "" {
		return provider.NotFound(name, "no host name to analyze (IP address)"), nil
	}
	d := Analyze(host)
	r := &provider.Result{Provider: name, Found: true, Verdict: provider.VerdictInfo, Details: d}
	r.Summary = fmt.Sprintf("registrable domain %s", d.RegistrableDomain)
	if d.SubdomainLevels > 0 {
		r.Summary += fmt.Sprintf(", %d subdomain levels", d.SubdomainLevels)
	}
	for _, h := range d.Hints {
		if strings.HasPrefix(h, "mixed scripts") {
			r.Verdict = provider.VerdictSuspicious
			r.Summary = "possible homograph: " + h
		}
	}
	r.Add("Host", d.Host)
	r.Add("Unicode", d.Unicode)
	r.Add("Registrable domain", d.RegistrableDomain)
	suffix := d.PublicSuffix
	if !d.ICANN {
		suffix += " (private suffix, e.g. a hosting or dynamic DNS service)"
	}
	r.Add("Public suffix", suffix)
	r.Addf("Subdomain levels", "%d", d.SubdomainLevels)
	r.Addf("Length", "%d characters, longest label %d (entropy %.2f)", d.Length, len(d.LongestLabel), d.Entropy)
	r.Add("Hints", strings.Join(d.Hints, "; "))
	return r, nil
}

// Analyze inspects a lower-case host name.
func Analyze(host string) Details {
	d := Details{Host: host, Length: len(host)}
	if u, err := idna.ToUnicode(host); err == nil && u != host {
		d.Unicode = u
	}
	d.PublicSuffix, d.ICANN = publicsuffix.PublicSuffix(host)
	if reg, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		d.RegistrableDomain = reg
		d.SubdomainLevels = strings.Count(host, ".") - strings.Count(reg, ".")
	} else {
		d.RegistrableDomain = host
	}

	for _, l := range strings.Split(host, ".") {
		if len(l) > len(d.LongestLabel) {
			d.LongestLabel = l
		}
	}
	d.Entropy = entropy(d.LongestLabel)

	if d.Unicode != "" {
		d.Hints = append(d.Hints, "internationalized name (punycode)")
		for _, l := range strings.Split(d.Unicode, ".") {
			if scripts := scriptsOf(l); len(scripts) > 1 {
				d.Hints = append(d.Hints, fmt.Sprintf("mixed scripts in %q (%s): look-alike characters", l, strings.Join(scripts, " + ")))
			}
		}
	}
	if !d.ICANN {
		d.Hints = append(d.Hints, "private public suffix: subdomains are assigned to different owners")
	}
	if len(d.LongestLabel) >= dgaMinLength && d.Entropy >= dgaMinEntropy && !strings.HasPrefix(d.LongestLabel, "xn--") {
		d.Hints = append(d.Hints, "long, high-entropy label: possibly algorithmically generated (DGA)")
	}
	if d.SubdomainLevels >= 4 {
		d.Hints = append(d.Hints, "deeply nested subdomains")
	}
	return d
}

// scriptsOf lists the writing systems of the letters in s.
func scriptsOf(s string) []string {
	tables := []struct {
		name  string
		table *unicode.RangeTable
	}{
		{"Latin", unicode.Latin}, {"Cyrillic", unicode.Cyrillic}, {"Greek", unicode.Greek},
		{"Armenian", unicode.Armenian}, {"Arabic", unicode.Arabic}, {"Hebrew", unicode.Hebrew},
		{"Han", unicode.Han}, {"Hangul", unicode.Hangul}, {"Hiragana", unicode.Hiragana},
		{"Katakana", unicode.Katakana}, {"Thai", unicode.Thai},
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range s {
		if !unicode.IsLetter(r) {
			continue
		}
		for _, t := range tables {
			if unicode.Is(t.table, r) && !seen[t.name] {
				seen[t.name] = true
				out = append(out, t.name)
			}
		}
	}
	return out
}

// entropy is the Shannon entropy of s, in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

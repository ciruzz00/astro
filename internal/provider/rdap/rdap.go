// Package rdap looks up domain and IP registration data with RDAP, the
// structured successor of WHOIS, through the rdap.org bootstrap service.
package rdap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/provider/hostinfo"
)

const (
	name        = "rdap"
	DefaultBase = "https://rdap.org"
	// Domains younger than this are flagged: phishing and malware
	// infrastructure is often registered days before use.
	newlyRegistered = 30 * 24 * time.Hour
)

// Provider queries RDAP.
type Provider struct {
	client  *http.Client
	base    string
	limiter *rate.Limiter
	now     func() time.Time
}

// New returns an RDAP provider.
func New(c *http.Client, base string) *Provider {
	return &Provider{client: c, base: base, limiter: rate.NewLimiter(rate.Every(time.Second), 3), now: time.Now}
}

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool {
	return t == ioc.Domain || t == ioc.URL || t == ioc.Email || t.IsIP()
}

func (p *Provider) CacheTTL() time.Duration { return 24 * time.Hour }

type vcardEntity struct {
	Roles      []string `json:"roles"`
	VCardArray []any    `json:"vcardArray"`
	PublicIDs  []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []vcardEntity `json:"entities"`
}

type response struct {
	LDHName string   `json:"ldhName"`
	Handle  string   `json:"handle"`
	Name    string   `json:"name"`
	Country string   `json:"country"`
	Start   string   `json:"startAddress"`
	End     string   `json:"endAddress"`
	Type    string   `json:"type"`
	Status  []string `json:"status"`
	Events  []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities []vcardEntity `json:"entities"`
}

// Details is the structured payload of an RDAP result.
type Details struct {
	Object      string   `json:"object"`
	Registered  string   `json:"registered,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	Changed     string   `json:"changed,omitempty"`
	AgeDays     int      `json:"age_days,omitempty"`
	Registrar   string   `json:"registrar,omitempty"`
	Registrant  string   `json:"registrant,omitempty"`
	Status      []string `json:"status,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	Network     string   `json:"network,omitempty"`
	Range       string   `json:"range,omitempty"`
	Country     string   `json:"country,omitempty"`
	Abuse       string   `json:"abuse,omitempty"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	path, object, ok := target(i)
	if !ok {
		return provider.NotFound(name, "no domain or IP to look up"), nil
	}
	if err := provider.Wait(ctx, p.limiter); err != nil {
		return nil, err
	}
	var resp response
	err := httpx.GetJSON(ctx, p.client, p.base+path, http.Header{"Accept": {"application/rdap+json"}}, &resp)
	if errors.Is(err, httpx.ErrNotFound) {
		return provider.NotFound(name, "no registration data for "+object+" (not registered, or its registry has no RDAP service, as for many country-code TLDs)"), nil
	}
	if err != nil {
		return nil, err
	}

	d := Details{Object: object, Status: resp.Status}
	for _, e := range resp.Events {
		switch e.Action {
		case "registration":
			d.Registered = day(e.Date)
		case "expiration":
			d.Expires = day(e.Date)
		case "last changed":
			d.Changed = day(e.Date)
		}
	}
	for _, ns := range resp.Nameservers {
		d.Nameservers = append(d.Nameservers, strings.ToLower(ns.LDHName))
	}
	for _, e := range resp.Entities {
		switch {
		case has(e.Roles, "registrar"):
			d.Registrar = vcardName(e.VCardArray)
		case has(e.Roles, "registrant"):
			d.Registrant = vcardName(e.VCardArray)
		}
		if a := abuseEmail(e); a != "" && d.Abuse == "" {
			d.Abuse = a
		}
	}

	r := &provider.Result{Provider: name, Found: true, Verdict: provider.VerdictInfo, Details: &d,
		Reference: "https://client.rdap.org/?type=" + strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)[0] + "&object=" + url.QueryEscape(object)}

	if strings.HasPrefix(path, "/ip/") {
		d.Network, d.Country = resp.Name, resp.Country
		if resp.Start != "" {
			d.Range = resp.Start + " - " + resp.End
		}
		r.Summary = strings.TrimSpace(fmt.Sprintf("network %s %s", resp.Name, paren(d.Registrant)))
		r.Add("Network", strings.TrimSpace(resp.Name+" "+paren(resp.Handle)))
		r.Add("Range", d.Range)
		r.Add("Type", resp.Type)
		r.Add("Owner", d.Registrant)
		r.Add("Country", d.Country)
		r.Add("Abuse contact", d.Abuse)
		return r, nil
	}

	if t, err := time.Parse("2006-01-02", d.Registered); err == nil {
		age := p.now().Sub(t)
		d.AgeDays = int(age.Hours() / 24)
		if age < newlyRegistered {
			r.Verdict = provider.VerdictSuspicious
			r.Summary = fmt.Sprintf("newly registered: %d days ago (%s)", d.AgeDays, d.Registered)
		} else {
			r.Summary = fmt.Sprintf("registered %s (%s ago)", d.Registered, humanAge(d.AgeDays))
		}
	} else {
		r.Summary = "registered, date not published"
	}
	if d.Registrar != "" {
		r.Summary += " via " + d.Registrar
	}
	r.Add("Domain", object)
	r.Add("Registered", d.Registered)
	r.Add("Expires", d.Expires)
	r.Add("Last changed", d.Changed)
	r.Add("Registrar", d.Registrar)
	r.Add("Registrant", d.Registrant)
	r.Add("Status", provider.List(d.Status, 8))
	r.Add("Nameservers", provider.List(d.Nameservers, 6))
	r.Add("Abuse contact", d.Abuse)
	return r, nil
}

// target returns the RDAP path and object for an indicator. Domains are
// looked up by their registrable part: registries know example.com, not
// www.example.com.
func target(i ioc.Indicator) (path, object string, ok bool) {
	if i.Type.IsIP() {
		return "/ip/" + url.PathEscape(i.Value), i.Value, true
	}
	if i.Type == ioc.URL {
		if u, err := url.Parse(i.Value); err == nil {
			if ipi, err := ioc.Parse(u.Hostname()); err == nil && ipi.Type.IsIP() {
				return "/ip/" + url.PathEscape(ipi.Value), ipi.Value, true
			}
		}
	}
	host := hostinfo.HostOf(i)
	if host == "" {
		return "", "", false
	}
	reg := hostinfo.RegisteredDomain(host)
	return "/domain/" + url.PathEscape(reg), reg, true
}

// vcardName returns the "fn" property of a jCard (RFC 7095).
func vcardName(v []any) string {
	return vcardProp(v, "fn")
}

func vcardProp(v []any, prop string) string {
	if len(v) < 2 {
		return ""
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		fields, _ := p.([]any)
		if len(fields) >= 4 {
			if n, _ := fields[0].(string); n == prop {
				s, _ := fields[3].(string)
				return s
			}
		}
	}
	return ""
}

// abuseEmail finds the email of an entity with the abuse role, at any depth.
func abuseEmail(e vcardEntity) string {
	if has(e.Roles, "abuse") {
		if m := vcardProp(e.VCardArray, "email"); m != "" {
			return m
		}
	}
	for _, sub := range e.Entities {
		if m := abuseEmail(sub); m != "" {
			return m
		}
	}
	return ""
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func day(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

func humanAge(days int) string {
	switch {
	case days >= 730:
		return fmt.Sprintf("%d years", days/365)
	case days >= 60:
		return fmt.Sprintf("%d months", days/30)
	}
	return fmt.Sprintf("%d days", days)
}

func paren(s string) string {
	if s == "" {
		return ""
	}
	return "(" + s + ")"
}

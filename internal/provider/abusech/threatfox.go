package abusech

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

// ThreatFox looks up IOCs (C2 servers, payload URLs, hashes) linked to malware families.
type ThreatFox struct{ c client }

// NewThreatFox returns a ThreatFox provider.
func NewThreatFox(hc *http.Client, base string, key config.Secret) *ThreatFox {
	return &ThreatFox{c: newClient(hc, base, key)}
}

func (p *ThreatFox) Name() string { return "threatfox" }

func (p *ThreatFox) Supports(t ioc.Type) bool {
	return t.IsIP() || t == ioc.Domain || t == ioc.URL || t == ioc.MD5 || t == ioc.SHA1 || t == ioc.SHA256
}

func (p *ThreatFox) CacheTTL() time.Duration { return cacheTTL }

// IOC is a ThreatFox entry.
type IOC struct {
	ID          string   `json:"id"`
	IOC         string   `json:"ioc"`
	Type        string   `json:"ioc_type"`
	ThreatType  string   `json:"threat_type"`
	Malware     string   `json:"malware_printable"`
	Alias       string   `json:"malware_alias"`
	Malpedia    string   `json:"malware_malpedia"`
	Confidence  int      `json:"confidence_level"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	Reference   string   `json:"reference"`
	Tags        []string `json:"tags"`
	Compromised bool     `json:"is_compromised"`
}

// minConfidence separates suspicious from malicious entries.
const minConfidence = 75

func (p *ThreatFox) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	if err := provider.Wait(ctx, p.c.limiter); err != nil {
		return nil, err
	}
	// search_ioc matches substrings, so an IP also finds its "ip:port" entries.
	payload := map[string]any{"query": "search_ioc", "search_term": i.Value}
	var resp status
	if err := httpx.PostJSON(ctx, p.c.http, p.c.base, p.c.header(), payload, &resp); err != nil {
		return nil, err
	}
	switch resp.QueryStatus {
	case "ok":
	case "no_result", "no_results":
		return provider.NotFound(p.Name(), "no ThreatFox IOC matches"), nil
	default:
		return nil, fmt.Errorf("query status %q", resp.QueryStatus)
	}
	var all []IOC
	if err := json.Unmarshal(resp.Data, &all); err != nil {
		return nil, fmt.Errorf("unexpected data: %w", err)
	}
	matches := filterMatches(i, all)
	if len(matches) == 0 {
		return provider.NotFound(p.Name(), "no ThreatFox IOC matches"), nil
	}

	best := matches[0]
	for _, m := range matches[1:] {
		if m.Confidence > best.Confidence {
			best = m
		}
	}
	r := &provider.Result{
		Provider:  p.Name(),
		Found:     true,
		Verdict:   provider.VerdictSuspicious,
		Summary:   fmt.Sprintf("%s %s (confidence %d%%)", best.Malware, strings.ReplaceAll(best.ThreatType, "_", " "), best.Confidence),
		Reference: "https://threatfox.abuse.ch/ioc/" + best.ID + "/",
		Details:   matches,
	}
	if best.Confidence >= minConfidence {
		r.Verdict = provider.VerdictMalicious
	}
	var families, iocs []string
	seen := map[string]bool{}
	for _, m := range matches {
		if !seen[m.Malware] {
			seen[m.Malware] = true
			families = append(families, m.Malware)
		}
		iocs = append(iocs, m.IOC+" ["+m.Type+"]")
	}
	r.Add("Malware", strings.Join(families, ", "))
	r.Add("Alias", best.Alias)
	r.Add("Threat type", best.ThreatType)
	r.Add("Entries", provider.List(iocs, 8))
	r.Add("First seen", best.FirstSeen)
	r.Add("Last seen", best.LastSeen)
	r.Add("Tags", strings.Join(best.Tags, ", "))
	r.Add("Malpedia", best.Malpedia)
	r.Add("Report", best.Reference)
	return r, nil
}

// filterMatches keeps entries that really are the indicator: substring search
// would otherwise match 1.2.3.4 against 1.2.3.45.
func filterMatches(i ioc.Indicator, all []IOC) []IOC {
	var out []IOC
	for _, m := range all {
		v := strings.ToLower(m.IOC)
		ok := v == strings.ToLower(i.Value)
		if i.Type.IsIP() {
			host, port, found := strings.Cut(v, ":")
			if i.Type == ioc.IPv6 {
				// IPv6 entries look like "[2001:db8::1]:443".
				if h, p, f := strings.Cut(strings.TrimPrefix(v, "["), "]:"); f {
					host, port, found = h, p, true
				}
			}
			_, perr := strconv.Atoi(port)
			ok = ok || (found && perr == nil && host == i.Value)
		}
		if ok {
			out = append(out, m)
		}
	}
	return out
}

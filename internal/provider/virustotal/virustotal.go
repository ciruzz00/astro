// Package virustotal queries the VirusTotal API v3.
package virustotal

import (
	"context"
	"encoding/base64"
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
	name        = "virustotal"
	DefaultBase = "https://www.virustotal.com/api/v3"
	guiBase     = "https://www.virustotal.com/gui"
)

// Verdict thresholds on the number of engines flagging an object.
const (
	maliciousAt = 5
	// Objects with a community reputation above this are treated as benign
	// when only a few engines flag them (e.g. popular domains).
	trustedReputation = 50
)

// Provider queries VirusTotal. The free tier allows 4 requests per minute.
type Provider struct {
	client  *http.Client
	base    string
	key     config.Secret
	limiter *rate.Limiter
}

// New returns a VirusTotal provider.
func New(c *http.Client, base string, key config.Secret) *Provider {
	return &Provider{client: c, base: base, key: key, limiter: rate.NewLimiter(rate.Every(15*time.Second), 4)}
}

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool {
	return t.IsHash() || t.IsIP() || t == ioc.Domain || t == ioc.URL
}

func (p *Provider) CacheTTL() time.Duration { return 6 * time.Hour }

// Stats counts engine results of the last analysis.
type Stats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
	Harmless   int `json:"harmless"`
}

type attributes struct {
	Stats      Stats             `json:"last_analysis_stats"`
	Reputation int               `json:"reputation"`
	Tags       []string          `json:"tags"`
	LastDate   int64             `json:"last_analysis_date"`
	Categories map[string]string `json:"categories"`

	// files
	MD5             string   `json:"md5"`
	SHA1            string   `json:"sha1"`
	SHA256          string   `json:"sha256"`
	MeaningfulName  string   `json:"meaningful_name"`
	Names           []string `json:"names"`
	TypeDescription string   `json:"type_description"`
	Size            int64    `json:"size"`
	FirstSubmission int64    `json:"first_submission_date"`
	TimesSubmitted  int      `json:"times_submitted"`
	Classification  struct {
		Label      string `json:"suggested_threat_label"`
		Categories []struct {
			Value string `json:"value"`
		} `json:"popular_threat_category"`
		Names []struct {
			Value string `json:"value"`
		} `json:"popular_threat_name"`
	} `json:"popular_threat_classification"`

	// IPs
	ASOwner string `json:"as_owner"`
	ASN     int    `json:"asn"`
	Country string `json:"country"`
	Network string `json:"network"`

	// domains
	Registrar    string `json:"registrar"`
	CreationDate int64  `json:"creation_date"`

	// URLs
	Title        string `json:"title"`
	LastFinalURL string `json:"last_final_url"`
}

// Details is the structured payload of a VirusTotal result.
type Details struct {
	Stats          Stats    `json:"stats"`
	Reputation     int      `json:"reputation"`
	ThreatLabel    string   `json:"threat_label,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	MD5            string   `json:"md5,omitempty"`
	SHA1           string   `json:"sha1,omitempty"`
	SHA256         string   `json:"sha256,omitempty"`
	LastAnalysisAt string   `json:"last_analysis_at,omitempty"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	path, gui := endpoints(i)
	if err := provider.Wait(ctx, p.limiter); err != nil {
		return nil, err
	}
	var resp struct {
		Data struct {
			Attributes attributes `json:"attributes"`
		} `json:"data"`
	}
	err := httpx.GetJSON(ctx, p.client, p.base+path, http.Header{"x-apikey": {p.key.Reveal()}}, &resp)
	if errors.Is(err, httpx.ErrNotFound) {
		return provider.NotFound(name, "never seen by VirusTotal"), nil
	}
	if err != nil {
		return nil, err
	}

	a := resp.Data.Attributes
	d := Details{
		Stats: a.Stats, Reputation: a.Reputation, ThreatLabel: a.Classification.Label, Tags: a.Tags,
		MD5: a.MD5, SHA1: a.SHA1, SHA256: a.SHA256, LastAnalysisAt: provider.UnixDate(a.LastDate),
	}
	r := &provider.Result{
		Provider:  name,
		Found:     true,
		Verdict:   verdict(a.Stats, a.Reputation),
		Reference: guiBase + gui,
		Details:   d,
	}
	total := a.Stats.Malicious + a.Stats.Suspicious + a.Stats.Undetected + a.Stats.Harmless
	r.Summary = fmt.Sprintf("%d/%d engines flag it as malicious", a.Stats.Malicious, total)
	if d.ThreatLabel != "" {
		r.Summary += " (" + d.ThreatLabel + ")"
	}
	if r.Verdict == provider.VerdictClean && a.Stats.Malicious > 0 {
		r.Summary += fmt.Sprintf(", ignored: community reputation %d", a.Reputation)
	}

	r.Addf("Detections", "%d malicious, %d suspicious, %d harmless, %d undetected",
		a.Stats.Malicious, a.Stats.Suspicious, a.Stats.Harmless, a.Stats.Undetected)
	r.Addf("Reputation", "%d", a.Reputation)
	switch {
	case i.Type.IsHash():
		r.Add("Name", a.MeaningfulName)
		r.Add("Type", a.TypeDescription)
		if a.Size > 0 {
			r.Addf("Size", "%d bytes", a.Size)
		}
		var cats, names []string
		for _, c := range a.Classification.Categories {
			cats = append(cats, c.Value)
		}
		for _, n := range a.Classification.Names {
			names = append(names, n.Value)
		}
		r.Add("Threat category", strings.Join(cats, ", "))
		r.Add("Threat names", provider.List(names, 8))
		r.Add("First submitted", provider.UnixDate(a.FirstSubmission))
		r.Add("MD5", a.MD5)
		r.Add("SHA1", a.SHA1)
		r.Add("SHA256", a.SHA256)
		if len(a.Names) > 1 {
			r.Add("Other names", provider.List(a.Names, 5))
		}
	case i.Type.IsIP():
		r.Add("Owner", strings.TrimSpace(fmt.Sprintf("%s (AS%d)", a.ASOwner, a.ASN)))
		r.Add("Network", a.Network)
		r.Add("Country", a.Country)
	case i.Type == ioc.Domain:
		r.Add("Registrar", a.Registrar)
		r.Add("Created", provider.UnixDate(a.CreationDate))
		r.Add("Categories", categories(a.Categories))
	case i.Type == ioc.URL:
		r.Add("Title", a.Title)
		if a.LastFinalURL != "" && a.LastFinalURL != i.Value {
			r.Add("Redirects to", a.LastFinalURL)
		}
		r.Add("Categories", categories(a.Categories))
	}
	r.Add("Tags", provider.List(a.Tags, 10))
	r.Add("Last analysis", d.LastAnalysisAt)
	return r, nil
}

// endpoints returns the API path and the web UI path for an indicator.
func endpoints(i ioc.Indicator) (api, gui string) {
	v := url.PathEscape(i.Value)
	switch {
	case i.Type.IsHash():
		return "/files/" + v, "/file/" + v
	case i.Type.IsIP():
		return "/ip_addresses/" + v, "/ip-address/" + v
	case i.Type == ioc.Domain:
		return "/domains/" + v, "/domain/" + v
	}
	// URL identifiers are the unpadded base64url of the URL.
	id := base64.RawURLEncoding.EncodeToString([]byte(i.Value))
	return "/urls/" + id, "/url/" + id
}

func verdict(s Stats, reputation int) provider.Verdict {
	switch {
	case s.Malicious >= maliciousAt:
		return provider.VerdictMalicious
	case (s.Malicious > 0 || s.Suspicious > 1) && reputation <= trustedReputation:
		return provider.VerdictSuspicious
	case s.Malicious+s.Suspicious+s.Harmless+s.Undetected > 0:
		return provider.VerdictClean
	}
	return provider.VerdictNone
}

// categories de-duplicates vendor categories.
func categories(m map[string]string) string {
	seen := map[string]bool{}
	var out []string
	for _, c := range m {
		c = strings.ToLower(strings.TrimSpace(c))
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return provider.List(out, 6)
}

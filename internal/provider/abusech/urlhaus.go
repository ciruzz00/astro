package abusech

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/config"
	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

// URLhaus looks up malware distribution URLs, the hosts serving them and their payloads.
type URLhaus struct{ c client }

// NewURLhaus returns a URLhaus provider.
func NewURLhaus(hc *http.Client, base string, key config.Secret) *URLhaus {
	return &URLhaus{c: newClient(hc, base, key)}
}

func (p *URLhaus) Name() string { return "urlhaus" }

func (p *URLhaus) Supports(t ioc.Type) bool {
	return t == ioc.URL || t == ioc.Domain || t.IsIP() || t == ioc.MD5 || t == ioc.SHA256
}

func (p *URLhaus) CacheTTL() time.Duration { return cacheTTL }

// Entry is a URL listed in URLhaus.
type Entry struct {
	URL       string   `json:"url"`
	Status    string   `json:"url_status"`
	Threat    string   `json:"threat"`
	DateAdded string   `json:"date_added"`
	Tags      []string `json:"tags"`
	Reference string   `json:"urlhaus_reference"`
}

// Response holds the fields of the url, host and payload endpoints.
type Response struct {
	QueryStatus string           `json:"query_status"`
	Reference   string           `json:"urlhaus_reference"`
	Entry                        // url endpoint
	Host        string           `json:"host"`
	FirstSeen   string           `json:"firstseen"`
	URLCount    provider.FlexInt `json:"url_count"`
	Blacklists  struct {
		SpamhausDBL string `json:"spamhaus_dbl"`
		SURBL       string `json:"surbl"`
	} `json:"blacklists"`
	URLs      []Entry `json:"urls"` // host and payload endpoints
	Signature string  `json:"signature"`
	FileType  string  `json:"file_type"`
	Payloads  []struct {
		Filename  string `json:"filename"`
		FileType  string `json:"file_type"`
		SHA256    string `json:"response_sha256"`
		Signature string `json:"signature"`
	} `json:"payloads"`
}

func (p *URLhaus) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	endpoint, form := "url/", url.Values{"url": {i.Value}}
	switch {
	case i.Type == ioc.MD5:
		endpoint, form = "payload/", url.Values{"md5_hash": {i.Value}}
	case i.Type == ioc.SHA256:
		endpoint, form = "payload/", url.Values{"sha256_hash": {i.Value}}
	case i.Type != ioc.URL:
		endpoint, form = "host/", url.Values{"host": {i.Value}}
	}
	if err := provider.Wait(ctx, p.c.limiter); err != nil {
		return nil, err
	}
	var resp Response
	if err := httpx.PostForm(ctx, p.c.http, p.c.base+endpoint, p.c.header(), form, &resp); err != nil {
		return nil, err
	}
	switch resp.QueryStatus {
	case "ok":
	case "no_results", "no_result":
		return provider.NotFound(p.Name(), "not listed in URLhaus"), nil
	default:
		return nil, fmt.Errorf("query status %q", resp.QueryStatus)
	}

	r := &provider.Result{Provider: p.Name(), Found: true, Reference: resp.Reference, Details: resp}
	switch endpoint {
	case "url/":
		r.Verdict = statusVerdict(resp.Status == "online")
		r.Summary = fmt.Sprintf("%s URL, currently %s", strings.ReplaceAll(resp.Threat, "_", " "), resp.Status)
		r.Add("Added", resp.DateAdded)
		r.Add("Host", resp.Host)
		r.Add("Tags", strings.Join(resp.Tags, ", "))
		var payloads []string
		for _, pl := range resp.Payloads {
			payloads = append(payloads, strings.TrimSpace(pl.Filename+" "+pl.Signature+" "+pl.SHA256))
		}
		r.Add("Payloads", provider.List(payloads, 5))
	case "host/":
		online := 0
		var urls []string
		for _, u := range resp.URLs {
			if u.Status == "online" {
				online++
			}
			urls = append(urls, u.URL+" ["+u.Status+"]")
		}
		r.Verdict = statusVerdict(online > 0)
		r.Summary = fmt.Sprintf("%d malware URLs reported on this host, %d online", resp.URLCount, online)
		r.Add("First seen", resp.FirstSeen)
		r.Add("URLs", provider.List(urls, 8))
		r.Add("Spamhaus DBL", resp.Blacklists.SpamhausDBL)
		r.Add("SURBL", resp.Blacklists.SURBL)
	default:
		r.Verdict = provider.VerdictMalicious
		r.Summary = fmt.Sprintf("payload distributed by %d URLs", resp.URLCount)
		r.Add("Signature", resp.Signature)
		r.Add("File type", resp.FileType)
		var urls []string
		for _, u := range resp.URLs {
			urls = append(urls, u.URL+" ["+u.Status+"]")
		}
		r.Add("URLs", provider.List(urls, 8))
	}
	return r, nil
}

// statusVerdict: still-online distribution is malicious, historical listings suspicious.
func statusVerdict(online bool) provider.Verdict {
	if online {
		return provider.VerdictMalicious
	}
	return provider.VerdictSuspicious
}

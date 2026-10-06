// Package wikipedia finds the Wikipedia article about a threat name (group,
// malware, campaign) or a well-known vulnerability.
package wikipedia

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/ciruzz00/astro/internal/httpx"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

const (
	name = "wikipedia"
	// DefaultBase is the English Wikipedia.
	DefaultBase = "https://en.wikipedia.org"
	maxResults  = 5
)

// Provider queries the Wikipedia REST APIs. Wikimedia asks clients to send a
// descriptive User-Agent with a contact, which httpx does.
type Provider struct {
	client  *http.Client
	base    string
	limiter *rate.Limiter
}

// New returns a Wikipedia provider.
func New(c *http.Client, base string) *Provider {
	return &Provider{client: c, base: base, limiter: rate.NewLimiter(rate.Every(500*time.Millisecond), 4)}
}

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool { return t == ioc.Keyword || t == ioc.CVE }

func (p *Provider) CacheTTL() time.Duration { return 24 * time.Hour }

type page struct {
	Key         string `json:"key"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Excerpt     string `json:"excerpt"`
}

// Details is the structured payload of a Wikipedia result.
type Details struct {
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Extract     string   `json:"extract,omitempty"`
	URL         string   `json:"url"`
	Others      []string `json:"others,omitempty"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	if err := provider.Wait(ctx, p.limiter); err != nil {
		return nil, err
	}
	q := url.Values{"q": {i.Value}, "limit": {"5"}}
	var search struct {
		Pages []page `json:"pages"`
	}
	if err := httpx.GetJSON(ctx, p.client, p.base+"/w/rest.php/v1/search/page?"+q.Encode(), nil, &search); err != nil {
		return nil, err
	}
	best, others := pick(i, search.Pages)
	if best == nil {
		return provider.NotFound(name, "no matching Wikipedia article"), nil
	}

	d := Details{Title: best.Title, Description: best.Description, Others: others,
		URL: p.base + "/wiki/" + url.PathEscape(best.Key)}
	if err := provider.Wait(ctx, p.limiter); err != nil {
		return nil, err
	}
	var summary struct {
		Type    string `json:"type"`
		Extract string `json:"extract"`
	}
	err := httpx.GetJSON(ctx, p.client, p.base+"/api/rest_v1/page/summary/"+url.PathEscape(best.Key), nil, &summary)
	switch {
	case err == nil:
		d.Extract = summary.Extract
	case errors.Is(err, httpx.ErrNotFound):
		d.Extract = stripHTML(best.Excerpt)
	default:
		return nil, err
	}

	r := &provider.Result{Provider: name, Found: true, Verdict: provider.VerdictInfo, Reference: d.URL, Details: d}
	r.Summary = d.Title
	if d.Description != "" {
		r.Summary += ": " + d.Description
	}
	r.Add("Article", d.Title)
	r.Add("Summary", provider.Truncate(d.Extract, 700))
	r.Add("Other articles", provider.List(others, 4))
	return r, nil
}

// pick chooses the article to show. For CVEs only an article whose excerpt
// cites the exact identifier is accepted, so unrelated pages never appear;
// for names, the first article that matched the query text.
func pick(i ioc.Indicator, pages []page) (*page, []string) {
	var best *page
	var others []string
	for k := range pages {
		pg := &pages[k]
		ok := strings.Contains(pg.Excerpt, `class="searchmatch"`) || strings.EqualFold(pg.Title, i.Value)
		if i.Type == ioc.CVE {
			ok = strings.Contains(strings.ToUpper(stripHTML(pg.Excerpt)), i.Value) || strings.EqualFold(pg.Title, i.Value)
		}
		switch {
		case ok && best == nil:
			best = pg
		case ok && len(others) < maxResults:
			others = append(others, pg.Title)
		}
	}
	return best, others
}

var reTag = regexp.MustCompile(`<[^>]*>`)

func stripHTML(s string) string {
	return strings.TrimSpace(html.UnescapeString(reTag.ReplaceAllString(s, "")))
}

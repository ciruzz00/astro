// Package kev checks CVEs against the offline CISA Known Exploited Vulnerabilities catalog.
package kev

import (
	"context"
	"errors"
	"strings"

	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

const name = "cisa-kev"

// Provider queries the KEV table of the store.
type Provider struct {
	store *store.Store
}

// New returns a KEV provider.
func New(s *store.Store) *Provider { return &Provider{store: s} }

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool { return t == ioc.CVE }

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	k, err := p.store.KEVByCVE(ctx, i.Value)
	if errors.Is(err, store.ErrNotFound) {
		synced, err := p.store.HasDataset(ctx, "kev")
		if err != nil {
			return nil, err
		}
		if !synced {
			return nil, errors.New("KEV dataset not synced: run 'astro sync kev'")
		}
		return provider.NotFound(name, "not in the CISA KEV catalog (no known exploitation reported)"), nil
	}
	if err != nil {
		return nil, err
	}

	r := &provider.Result{
		Provider:  name,
		Found:     true,
		Verdict:   provider.VerdictInfo,
		Summary:   "KNOWN EXPLOITED in the wild (added to CISA KEV on " + k.DateAdded + ")",
		Reference: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + k.CVE,
		Details:   k,
	}
	r.Add("Name", k.Name)
	r.Add("Vendor / product", strings.TrimSpace(k.Vendor+" "+k.Product))
	r.Add("Ransomware use", k.Ransomware)
	r.Add("Date added", k.DateAdded)
	r.Add("Due date", k.DueDate)
	r.Add("CWE", strings.Join(k.CWEs, ", "))
	r.Add("Description", k.ShortDescription)
	r.Add("Required action", provider.Truncate(k.RequiredAction, 300))
	return r, nil
}

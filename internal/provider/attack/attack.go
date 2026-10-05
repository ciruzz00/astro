// Package attack looks up MITRE ATT&CK objects in the offline dataset.
package attack

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

const name = "mitre-attack"

// Provider queries the ATT&CK tables of the store.
type Provider struct {
	store *store.Store
}

// New returns an ATT&CK provider.
func New(s *store.Store) *Provider { return &Provider{store: s} }

func (p *Provider) Name() string { return name }

func (p *Provider) Supports(t ioc.Type) bool { return t.IsAttack() || t == ioc.Keyword }

// Details is the structured payload of an ATT&CK result.
type Details struct {
	Objects []store.AttackObject `json:"objects"`
	Related []store.Related      `json:"related,omitempty"`
	Matches []store.AttackObject `json:"matches,omitempty"`
}

func (p *Provider) Lookup(ctx context.Context, i ioc.Indicator) (*provider.Result, error) {
	synced, err := p.synced(ctx)
	if err != nil {
		return nil, err
	}
	if !synced {
		return nil, errors.New("ATT&CK dataset not synced: run 'astro sync attack'")
	}

	var objs, matches []store.AttackObject
	if i.Type == ioc.Keyword {
		matches, err = p.store.AttackSearch(ctx, i.Value, 40)
		if err != nil {
			return nil, err
		}
		// The same object can exist in several domains: keep one per ID.
		seen := map[string]bool{}
		matches = slices.DeleteFunc(matches, func(o store.AttackObject) bool {
			dup := seen[o.ID]
			seen[o.ID] = true
			return dup
		})
		if len(matches) == 0 {
			return provider.NotFound(name, "no ATT&CK object matches this name"), nil
		}
		objs, err = p.store.AttackByID(ctx, matches[0].ID)
	} else {
		objs, err = p.store.AttackByID(ctx, i.Value)
	}
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return provider.NotFound(name, "unknown ATT&CK ID"), nil
	}

	o := objs[0]
	related, err := p.store.AttackRelated(ctx, o.ID)
	if err != nil {
		return nil, err
	}
	if o.Kind == "tactic" {
		techs, err := p.store.AttackTechniquesByTactic(ctx, o.Name, o.Domain)
		if err != nil {
			return nil, err
		}
		for _, t := range techs {
			related = append(related, store.Related{Rel: "tactic-of", Incoming: true, ID: t.ID, Kind: t.Kind, Name: t.Name})
		}
	}

	r := &provider.Result{
		Provider:  name,
		Found:     true,
		Verdict:   provider.VerdictInfo,
		Summary:   fmt.Sprintf("%s %s (%s)", o.ID, o.Name, kindLabel(o)),
		Reference: o.URL,
		Details:   Details{Objects: objs, Related: related, Matches: matches},
	}
	if o.Deprecated {
		r.Summary += " [deprecated]"
	}
	var domains []string
	for _, d := range objs {
		domains = append(domains, strings.TrimSuffix(d.Domain, "-attack"))
	}
	r.Add("Domain", strings.Join(domains, ", "))
	r.Add("Tactics", strings.Join(o.Tactics, ", "))
	r.Add("Platforms", strings.Join(o.Platforms, ", "))
	r.Add("Aliases", strings.Join(o.Aliases, ", "))
	r.Add("Description", provider.Truncate(o.Description, 700))
	for _, g := range groupRelated(o, related) {
		r.Add(g.label, provider.List(g.items, 15))
	}
	if len(matches) > 1 {
		var other []string
		for _, m := range matches[1:] {
			other = append(other, m.ID+" "+m.Name)
		}
		r.Add("Other matches", provider.List(other, 10))
	}
	return r, nil
}

func (p *Provider) synced(ctx context.Context) (bool, error) {
	for _, d := range []string{"attack-enterprise", "attack-mobile", "attack-ics"} {
		ok, err := p.store.HasDataset(ctx, d)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

func kindLabel(o store.AttackObject) string {
	if o.Subtype != "" {
		return o.Kind + "/" + o.Subtype
	}
	if o.Kind == "technique" && strings.Contains(o.ID, ".") {
		return "sub-technique"
	}
	return o.Kind
}

type group struct {
	label string
	items []string
}

// groupRelated turns raw relations into labelled lists, in a fixed order.
func groupRelated(o store.AttackObject, related []store.Related) []group {
	order := []string{}
	byLabel := map[string][]string{}
	for _, rel := range related {
		label := relLabel(o, rel)
		if label == "" {
			continue
		}
		if _, ok := byLabel[label]; !ok {
			order = append(order, label)
		}
		byLabel[label] = append(byLabel[label], rel.ID+" "+rel.Name)
	}
	var out []group
	for _, l := range labelOrder {
		if items, ok := byLabel[l]; ok {
			out = append(out, group{l, items})
		}
	}
	for _, l := range order {
		if !slices.Contains(labelOrder, l) {
			out = append(out, group{l, byLabel[l]})
		}
	}
	return out
}

var labelOrder = []string{
	"Parent technique", "Sub-techniques", "Techniques", "Used by groups", "Used by software",
	"Used in campaigns", "Uses techniques", "Uses software", "Mitigations", "Mitigates",
	"Attributed to", "Campaigns",
}

func relLabel(o store.AttackObject, r store.Related) string {
	switch {
	case r.Rel == "subtechnique-of" && !r.Incoming:
		return "Parent technique"
	case r.Rel == "subtechnique-of" && r.Incoming:
		return "Sub-techniques"
	case r.Rel == "tactic-of":
		return "Techniques"
	case r.Rel == "uses" && r.Incoming:
		switch r.Kind {
		case "group":
			return "Used by groups"
		case "software":
			return "Used by software"
		case "campaign":
			return "Used in campaigns"
		}
	case r.Rel == "uses" && !r.Incoming:
		if r.Kind == "software" {
			return "Uses software"
		}
		return "Uses techniques"
	case r.Rel == "mitigates" && r.Incoming:
		return "Mitigations"
	case r.Rel == "mitigates" && !r.Incoming:
		return "Mitigates"
	case r.Rel == "attributed-to" && !r.Incoming:
		return "Attributed to"
	case r.Rel == "attributed-to" && r.Incoming:
		return "Campaigns"
	}
	return ""
}

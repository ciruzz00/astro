package datasets

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/store"
)

const maxAttackBundle = 256 << 20

func attackSource(domain string) Source {
	name := domain + "-attack"
	return Source{
		Name:        "attack-" + domain,
		Description: "MITRE ATT&CK " + domain + " (STIX 2.1)",
		sync: func(ctx context.Context, f Fetcher, s *store.Store, now time.Time) (int, error) {
			url := attackBase + name + "/" + name + ".json"
			body, err := f(ctx, url, maxAttackBundle)
			if err != nil {
				return 0, err
			}
			b, err := ParseAttack(body)
			if err != nil {
				return 0, err
			}
			d := store.Dataset{Name: "attack-" + domain, Source: url, Version: b.Version, Records: len(b.Objects), SyncedAt: now}
			return len(b.Objects), s.ReplaceAttack(ctx, d, name, b.Objects, b.Relations)
		},
	}
}

// AttackBundle is the result of parsing an ATT&CK STIX bundle.
type AttackBundle struct {
	Version   string
	Objects   []store.AttackObject
	Relations []store.AttackRelation
}

type stixObject struct {
	Type         string   `json:"type"`
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Revoked      bool     `json:"revoked"`
	Deprecated   bool     `json:"x_mitre_deprecated"`
	Version      string   `json:"x_mitre_version"`
	Platforms    []string `json:"x_mitre_platforms"`
	Aliases      []string `json:"aliases"`
	MitreAliases []string `json:"x_mitre_aliases"`
	Shortname    string   `json:"x_mitre_shortname"`
	RelType      string   `json:"relationship_type"`
	SourceRef    string   `json:"source_ref"`
	TargetRef    string   `json:"target_ref"`
	ExternalRefs []struct {
		SourceName string `json:"source_name"`
		URL        string `json:"url"`
		ExternalID string `json:"external_id"`
	} `json:"external_references"`
	KillChain []struct {
		PhaseName string `json:"phase_name"`
	} `json:"kill_chain_phases"`
}

var attackKinds = map[string]string{
	"attack-pattern":   "technique",
	"x-mitre-tactic":   "tactic",
	"intrusion-set":    "group",
	"malware":          "software",
	"tool":             "software",
	"course-of-action": "mitigation",
	"campaign":         "campaign",
}

var attackRels = map[string]bool{"uses": true, "mitigates": true, "subtechnique-of": true, "attributed-to": true}

// ParseAttack converts a MITRE ATT&CK STIX 2.1 bundle into store records.
// Revoked objects are dropped; deprecated ones are kept and flagged.
func ParseAttack(data []byte) (*AttackBundle, error) {
	var bundle struct {
		Type    string       `json:"type"`
		Objects []stixObject `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("decode STIX bundle: %w", err)
	}
	if bundle.Type != "bundle" {
		return nil, fmt.Errorf("not a STIX bundle (type %q)", bundle.Type)
	}

	out := &AttackBundle{}
	extIDs := make(map[string]string)  // STIX id -> ATT&CK id
	tactics := make(map[string]string) // shortname -> tactic name
	for _, o := range bundle.Objects {
		switch {
		case o.Type == "x-mitre-collection":
			out.Version = o.Version
		case o.Type == "x-mitre-tactic":
			tactics[o.Shortname] = o.Name
		}
	}

	for _, o := range bundle.Objects {
		kind, ok := attackKinds[o.Type]
		if !ok || o.Revoked {
			continue
		}
		id, url := mitreRef(o)
		if id == "" {
			continue
		}
		extIDs[o.ID] = id
		obj := store.AttackObject{
			ID:          id,
			Kind:        kind,
			Name:        o.Name,
			Description: cleanDescription(o.Description),
			URL:         url,
			Platforms:   o.Platforms,
			Aliases:     aliases(o),
			Deprecated:  o.Deprecated,
		}
		if kind == "software" {
			obj.Subtype = o.Type
		}
		for _, k := range o.KillChain {
			if name, ok := tactics[k.PhaseName]; ok {
				obj.Tactics = append(obj.Tactics, name)
			}
		}
		out.Objects = append(out.Objects, obj)
	}

	for _, o := range bundle.Objects {
		if o.Type != "relationship" || o.Revoked || o.Deprecated || !attackRels[o.RelType] {
			continue
		}
		src, okS := extIDs[o.SourceRef]
		dst, okT := extIDs[o.TargetRef]
		if okS && okT {
			out.Relations = append(out.Relations, store.AttackRelation{SourceID: src, Rel: o.RelType, TargetID: dst})
		}
	}
	return out, nil
}

func mitreRef(o stixObject) (id, url string) {
	for _, r := range o.ExternalRefs {
		if strings.HasPrefix(r.SourceName, "mitre-") && strings.HasSuffix(r.SourceName, "attack") && r.ExternalID != "" {
			return r.ExternalID, r.URL
		}
	}
	return "", ""
}

func aliases(o stixObject) []string {
	var out []string
	for _, a := range append(o.Aliases, o.MitreAliases...) {
		if a != o.Name && a != "" {
			out = append(out, a)
		}
	}
	return out
}

var (
	reCitation = regexp.MustCompile(`\s*\(Citation:[^)]*\)`)
	reMDLink   = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`)
	reHTMLTag  = regexp.MustCompile(`</?(code|b|i|em|strong|br)\s*/?>`)
	reBlank    = regexp.MustCompile(`\n\s*\n+`)
)

// cleanDescription removes citation markers, markdown links, inline HTML
// and blank lines from ATT&CK prose.
func cleanDescription(s string) string {
	s = reCitation.ReplaceAllString(s, "")
	s = reMDLink.ReplaceAllString(s, "$1")
	s = reHTMLTag.ReplaceAllString(s, "")
	s = reBlank.ReplaceAllString(s, "\n")
	return strings.TrimSpace(s)
}

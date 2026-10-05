package report

import (
	"crypto/sha1" // #nosec G505 -- SHA-1 is mandated by RFC 4122 for UUIDv5, not used for security
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
)

// TLP 2.0 marking definitions published by OASIS
// (cti-stix-common-objects, extension-definition-specifications/tlp-2.0).
const tlpExtension = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"

var tlpMarkings = map[string]string{
	cases.TLPClear:       "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
	cases.TLPGreen:       "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
	cases.TLPAmber:       "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
	cases.TLPAmberStrict: "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
	cases.TLPRed:         "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}

// stixNamespace seeds the deterministic (UUIDv5) object IDs, so exporting the
// same case twice yields the same IDs and consumers can de-duplicate.
var stixNamespace = [16]byte{0x7a, 0x1e, 0x2b, 0x5c, 0x41, 0x0d, 0x4e, 0x8a, 0x9c, 0x3f, 0x60, 0x11, 0x5d, 0x27, 0xa4, 0x93}

type stixObject map[string]any

// STIX writes the case as a STIX 2.1 bundle: a report referencing indicators,
// vulnerabilities and ATT&CK objects, all marked with the case TLP.
func STIX(w io.Writer, v *cases.View, o Options) error {
	ts := o.Now.Format("2006-01-02T15:04:05.000Z")
	created := v.Case.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z")
	marking := tlpMarkings[v.Case.TLP]
	if marking == "" {
		marking = tlpMarkings[cases.TLPAmber]
	}
	identity := "identity--" + uuid5("astro")

	common := func(typ, key string) stixObject {
		return stixObject{
			"type": typ, "spec_version": "2.1", "id": typ + "--" + uuid5(v.Case.Name+"|"+typ+"|"+key),
			"created": created, "modified": ts, "created_by_ref": identity,
			"object_marking_refs": []string{marking},
		}
	}

	objects := []stixObject{
		{"type": "identity", "spec_version": "2.1", "id": identity, "created": "2026-01-01T00:00:00.000Z",
			"modified": "2026-01-01T00:00:00.000Z", "name": "astro", "identity_class": "system"},
		{"type": "marking-definition", "spec_version": "2.1", "id": marking, "created": "2022-10-01T00:00:00.000Z",
			"name": "TLP:" + v.Case.TLP, "extensions": map[string]any{
				tlpExtension: map[string]any{"extension_type": "property-extension", "tlp_2_0": strings.ToLower(v.Case.TLP)},
			}},
	}
	var refs []string
	for _, it := range v.Items {
		obj := itemObject(it, common, ts)
		if obj == nil {
			continue
		}
		objects = append(objects, obj)
		refs = append(refs, obj["id"].(string))
	}

	name := v.Case.Title
	if name == "" {
		name = v.Case.Name
	}
	rep := common("report", "report")
	rep["name"] = name
	rep["published"] = ts
	rep["report_types"] = []string{"threat-report"}
	if v.Case.Description != "" {
		rep["description"] = v.Case.Description
	}
	if len(v.Case.Tags) > 0 {
		rep["labels"] = v.Case.Tags
	}
	if len(refs) == 0 {
		// A report must reference at least one object.
		refs = []string{identity}
	}
	rep["object_refs"] = refs
	objects = append(objects, rep)

	return writeJSON(w, map[string]any{
		"type": "bundle", "id": "bundle--" + uuid5(v.Case.Name+"|bundle|"+ts), "objects": objects,
	})
}

func itemObject(it cases.Item, common func(typ, key string) stixObject, ts string) stixObject {
	i := it.Indicator
	key := string(i.Type) + ":" + i.Value
	if pattern := stixPattern(i); pattern != "" {
		obj := common("indicator", key)
		obj["name"] = i.Value
		obj["pattern"] = pattern
		obj["pattern_type"] = "stix"
		obj["valid_from"] = ts
		switch it.Verdict {
		case provider.VerdictMalicious:
			obj["indicator_types"] = []string{"malicious-activity"}
		case provider.VerdictSuspicious:
			obj["indicator_types"] = []string{"anomalous-activity"}
		default:
			obj["indicator_types"] = []string{"unknown"}
		}
		if it.Note != "" {
			obj["description"] = it.Note
		}
		return obj
	}

	extRef := func(source string) []map[string]string {
		return []map[string]string{{"source_name": source, "external_id": i.Value}}
	}
	name := attackName(it)
	switch i.Type {
	case ioc.CVE:
		obj := common("vulnerability", key)
		obj["name"] = i.Value
		obj["external_references"] = extRef("cve")
		return obj
	case ioc.AttackTechnique:
		obj := common("attack-pattern", key)
		obj["name"] = name
		obj["external_references"] = extRef("mitre-attack")
		return obj
	case ioc.AttackGroup:
		obj := common("intrusion-set", key)
		obj["name"] = name
		obj["external_references"] = extRef("mitre-attack")
		return obj
	case ioc.AttackSoftware:
		obj := common("malware", key)
		obj["name"] = name
		obj["is_family"] = true
		obj["external_references"] = extRef("mitre-attack")
		return obj
	case ioc.AttackCampaign:
		obj := common("campaign", key)
		obj["name"] = name
		obj["external_references"] = extRef("mitre-attack")
		return obj
	}
	return nil
}

// stixPattern returns a STIX pattern for observable indicators, or "".
func stixPattern(i ioc.Indicator) string {
	q := func(s string) string { return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'" }
	switch i.Type {
	case ioc.MD5:
		return "[file:hashes.MD5 = " + q(i.Value) + "]"
	case ioc.SHA1:
		return "[file:hashes.'SHA-1' = " + q(i.Value) + "]"
	case ioc.SHA256:
		return "[file:hashes.'SHA-256' = " + q(i.Value) + "]"
	case ioc.SHA512:
		return "[file:hashes.'SHA-512' = " + q(i.Value) + "]"
	case ioc.IPv4:
		return "[ipv4-addr:value = " + q(i.Value) + "]"
	case ioc.IPv6:
		return "[ipv6-addr:value = " + q(i.Value) + "]"
	case ioc.Domain:
		return "[domain-name:value = " + q(i.Value) + "]"
	case ioc.URL:
		return "[url:value = " + q(i.Value) + "]"
	case ioc.Email:
		return "[email-addr:value = " + q(i.Value) + "]"
	case ioc.MAC:
		return "[mac-addr:value = " + q(strings.ToLower(i.Value)) + "]"
	}
	return ""
}

// attackName extracts the ATT&CK object name from the stored MITRE result
// ("T1059.001 PowerShell (sub-technique)"), falling back to the ID.
func attackName(it cases.Item) string {
	if it.Report != nil {
		for _, r := range it.Report.Results {
			if r.Provider == "mitre-attack" && r.Found {
				s := strings.TrimPrefix(r.Summary, it.Indicator.Value+" ")
				if k := strings.LastIndex(s, " ("); k > 0 {
					s = s[:k]
				}
				if s != "" {
					return s
				}
			}
		}
	}
	return it.Indicator.Value
}

// uuid5 returns an RFC 4122 version 5 UUID of name in stixNamespace.
func uuid5(name string) string {
	h := sha1.New() // #nosec G401 -- required by the UUIDv5 algorithm
	h.Write(stixNamespace[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	x := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", x[0:8], x[8:12], x[12:16], x[16:20], x[20:32])
}

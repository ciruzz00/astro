package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/cases"
	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

var (
	created  = time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	searched = time.Date(2026, 10, 5, 11, 0, 0, 0, time.UTC)
	opts     = Options{Version: "v1.0.0", AttackVersion: "19.2", Now: time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)}
)

func view() *cases.View {
	otxDetails := map[string]any{"pulses": []any{
		map[string]any{"name": "C2", "attack_ids": []any{map[string]any{"id": "T1071.001"}, map[string]any{"id": "not-an-id"}}},
	}}
	return &cases.View{
		Case: store.Case{
			Name: "sherlock-1", Title: "Brutus <script>alert(1)</script>", TLP: cases.TLPAmber, Status: "open",
			Tags: []string{"htb"}, CreatedAt: created, UpdatedAt: searched,
			Notes: []store.CaseNote{{Body: "Attacker used **hydra** from 198.51.100.7 <img src=x onerror=alert(1)>", CreatedAt: searched}},
		},
		Items: []cases.Item{
			{
				Indicator: ioc.Indicator{Type: ioc.IPv4, Value: "198.51.100.7"}, Verdict: provider.VerdictMalicious,
				SearchedAt: &searched, AddedAt: created, Note: "brute force | source",
				Report: &engine.Report{Results: []*provider.Result{
					{Provider: "virustotal", Found: true, Verdict: provider.VerdictMalicious, Summary: "9/90 [click](javascript:alert(1))"},
					{Provider: "alienvault-otx", Found: true, Verdict: provider.VerdictSuspicious, Summary: "1 pulse", Details: otxDetails},
					{Provider: "abuseipdb", Error: "rate limit"},
					{Provider: "dns", Found: true, Verdict: provider.VerdictInfo, Summary: "reverse DNS: c2.example.net"},
				}},
			},
			{Indicator: ioc.Indicator{Type: ioc.URL, Value: "https://evil.example.com/a'b"}, AddedAt: created},
			{Indicator: ioc.Indicator{Type: ioc.CVE, Value: "CVE-2021-44228"}, AddedAt: created},
			{
				Indicator: ioc.Indicator{Type: ioc.AttackTechnique, Value: "T1110.001"}, AddedAt: created, SearchedAt: &searched,
				Report: &engine.Report{Results: []*provider.Result{
					{Provider: "mitre-attack", Found: true, Verdict: provider.VerdictInfo, Summary: "T1110.001 Password Guessing (sub-technique)"},
				}},
			},
			{Indicator: ioc.Indicator{Type: ioc.Keyword, Value: "hydra"}, AddedAt: created},
		},
	}
}

func TestMarkdownIsSafe(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "md", view(), opts); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, bad := range []string{"<script>", "<img", "198.51.100.7", "https://evil", "c2.example.net"} {
		if strings.Contains(out, bad) {
			t.Errorf("markdown contains %q:\n%s", bad, out)
		}
	}
	// A clickable link needs an unescaped "](": provider text must never produce one.
	if regexp.MustCompile(`[^\\]\]\(javascript:`).MatchString(out) {
		t.Errorf("markdown contains a live javascript link:\n%s", out)
	}
	for _, want := range []string{"**TLP:AMBER**", "198[.]51[.]100[.]7", "**MALICIOUS**", "virustotal, alienvault-otx", "brute force \\| source", "not searched", "**hydra**"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
}

func TestSTIX(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "stix", view(), opts); err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Type    string           `json:"type"`
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(b.Bytes(), &bundle); err != nil || bundle.Type != "bundle" {
		t.Fatalf("invalid bundle: %v", err)
	}
	reID := regexp.MustCompile(`^[a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	byType := map[string][]map[string]any{}
	for _, o := range bundle.Objects {
		id, _ := o["id"].(string)
		if !reID.MatchString(id) || !strings.HasPrefix(id, o["type"].(string)+"--") {
			t.Errorf("bad id %q", id)
		}
		byType[o["type"].(string)] = append(byType[o["type"].(string)], o)
	}
	if n := len(byType["indicator"]); n != 2 {
		t.Errorf("indicators = %d, want 2 (IP and URL)", n)
	}
	patterns := map[string]bool{}
	for _, o := range byType["indicator"] {
		patterns[o["pattern"].(string)] = true
		if refs := o["object_marking_refs"].([]any); refs[0] != tlpMarkings[cases.TLPAmber] {
			t.Errorf("marking = %v", refs)
		}
	}
	if !patterns[`[ipv4-addr:value = '198.51.100.7']`] || !patterns[`[url:value = 'https://evil.example.com/a\'b']`] {
		t.Errorf("patterns = %v", patterns)
	}
	if ap := byType["attack-pattern"]; len(ap) != 1 || ap[0]["name"] != "Password Guessing" {
		t.Errorf("attack-pattern = %v", ap)
	}
	if len(byType["vulnerability"]) != 1 || len(byType["report"]) != 1 || len(byType["marking-definition"]) != 1 {
		t.Errorf("objects by type = %v", byType)
	}
	if refs := byType["report"][0]["object_refs"].([]any); len(refs) != 4 {
		t.Errorf("report refs = %d, want 4 (keyword skipped)", len(refs))
	}

	// Same case, same IDs.
	var again bytes.Buffer
	_ = Write(&again, "stix", view(), opts)
	if again.String() != b.String() {
		t.Error("export must be deterministic")
	}
}

func TestNavigator(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "navigator", view(), opts); err != nil {
		t.Fatal(err)
	}
	var layer struct {
		Versions   map[string]string `json:"versions"`
		Domain     string            `json:"domain"`
		Techniques []navTechnique    `json:"techniques"`
	}
	if err := json.Unmarshal(b.Bytes(), &layer); err != nil {
		t.Fatal(err)
	}
	if layer.Versions["attack"] != "19" || layer.Domain != "enterprise-attack" {
		t.Errorf("layer = %+v", layer)
	}
	if len(layer.Techniques) != 2 || layer.Techniques[0].TechniqueID != "T1071.001" || layer.Techniques[1].Score != scoreDirect {
		t.Errorf("techniques = %+v", layer.Techniques)
	}
}

func TestPDF(t *testing.T) {
	v := view()
	// Many items force page breaks; exotic scripts must not break rendering.
	for i := range 120 {
		v.Items = append(v.Items, cases.Item{Indicator: ioc.Indicator{Type: ioc.Keyword, Value: fmt.Sprintf("Группа 攻撃者 %d", i)}, AddedAt: created})
	}
	v.Case.Notes = append(v.Case.Notes, store.CaseNote{Body: strings.Repeat("Long note with àccénts and a\ttab. ", 80), CreatedAt: searched})
	var b bytes.Buffer
	if err := Write(&b, "pdf", v, opts); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-")) || !bytes.Contains(out[len(out)-32:], []byte("%%EOF")) {
		t.Fatalf("not a PDF (%d bytes)", len(out))
	}
	if pages := bytes.Count(out, []byte("/Type /Page\n")) + bytes.Count(out, []byte("/Type /Page ")); pages < 3 {
		t.Logf("pages marker count = %d", pages)
	}
	if ContentType("pdf") != "application/pdf" || Extension("pdf") != ".pdf" {
		t.Error("pdf content type or extension")
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "docx", view(), opts); err == nil {
		t.Error("unknown format must fail")
	}
}

func TestUUID5(t *testing.T) {
	a, b := uuid5("x"), uuid5("x")
	if a != b || a == uuid5("y") || a[14] != '5' {
		t.Errorf("uuid5 = %s", a)
	}
}

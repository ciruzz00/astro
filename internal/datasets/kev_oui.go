package datasets

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/store"
)

const (
	kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	maxKEV = 32 << 20
	maxOUI = 32 << 20
)

var ouiURLs = []string{
	"https://standards-oui.ieee.org/oui/oui.csv",
	"https://standards-oui.ieee.org/oui28/mam.csv",
	"https://standards-oui.ieee.org/oui36/oui36.csv",
}

func syncKEV(ctx context.Context, f Fetcher, s *store.Store, now time.Time) (int, error) {
	body, err := f(ctx, kevURL, maxKEV)
	if err != nil {
		return 0, err
	}
	version, entries, err := ParseKEV(body)
	if err != nil {
		return 0, err
	}
	d := store.Dataset{Name: "kev", Source: kevURL, Version: version, Records: len(entries), SyncedAt: now}
	return len(entries), s.ReplaceKEV(ctx, d, entries)
}

// ParseKEV decodes the CISA KEV JSON feed.
func ParseKEV(data []byte) (version string, entries []store.KEV, err error) {
	var feed struct {
		CatalogVersion  string `json:"catalogVersion"`
		Vulnerabilities []struct {
			CVE              string   `json:"cveID"`
			Vendor           string   `json:"vendorProject"`
			Product          string   `json:"product"`
			Name             string   `json:"vulnerabilityName"`
			DateAdded        string   `json:"dateAdded"`
			DueDate          string   `json:"dueDate"`
			ShortDescription string   `json:"shortDescription"`
			RequiredAction   string   `json:"requiredAction"`
			Ransomware       string   `json:"knownRansomwareCampaignUse"`
			Notes            string   `json:"notes"`
			CWEs             []string `json:"cwes"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &feed); err != nil {
		return "", nil, fmt.Errorf("decode KEV feed: %w", err)
	}
	if len(feed.Vulnerabilities) == 0 {
		return "", nil, errors.New("KEV feed is empty")
	}
	for _, v := range feed.Vulnerabilities {
		entries = append(entries, store.KEV{
			CVE: strings.ToUpper(strings.TrimSpace(v.CVE)), Vendor: v.Vendor, Product: v.Product, Name: v.Name,
			DateAdded: v.DateAdded, DueDate: v.DueDate, ShortDescription: v.ShortDescription,
			RequiredAction: v.RequiredAction, Ransomware: v.Ransomware, Notes: v.Notes, CWEs: v.CWEs,
		})
	}
	return feed.CatalogVersion, entries, nil
}

func syncOUI(ctx context.Context, f Fetcher, s *store.Store, now time.Time) (int, error) {
	var all []store.OUI
	for _, u := range ouiURLs {
		body, err := f(ctx, u, maxOUI)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", u, err)
		}
		entries, err := ParseOUI(body)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", u, err)
		}
		all = append(all, entries...)
	}
	d := store.Dataset{Name: "oui", Source: "https://standards-oui.ieee.org/", Records: len(all), SyncedAt: now}
	return len(all), s.ReplaceOUI(ctx, d, all)
}

// ParseOUI decodes an IEEE registry CSV (Registry, Assignment, Organization Name, Organization Address).
func ParseOUI(data []byte) ([]store.OUI, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if len(header) < 3 || !strings.EqualFold(strings.TrimPrefix(header[0], "\ufeff"), "Registry") {
		return nil, fmt.Errorf("unexpected header %q", header)
	}
	var out []store.OUI
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) < 3 {
			continue
		}
		prefix := strings.ToUpper(strings.TrimSpace(rec[1]))
		if l := len(prefix); l != 6 && l != 7 && l != 9 {
			continue
		}
		o := store.OUI{Registry: strings.TrimSpace(rec[0]), Prefix: prefix, Org: strings.TrimSpace(rec[2])}
		if len(rec) > 3 {
			o.Address = strings.Join(strings.Fields(rec[3]), " ")
		}
		out = append(out, o)
	}
	if len(out) == 0 {
		return nil, errors.New("no entries")
	}
	return out, nil
}

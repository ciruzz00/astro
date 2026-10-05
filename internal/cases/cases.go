// Package cases manages investigations: collections of indicators with their
// latest search results, notes, tags and a TLP marking.
package cases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/engine"
	"github.com/ciruzz00/astro/internal/ioc"
	"github.com/ciruzz00/astro/internal/provider"
	"github.com/ciruzz00/astro/internal/store"
)

// TLP 2.0 labels.
const (
	TLPClear       = "CLEAR"
	TLPGreen       = "GREEN"
	TLPAmber       = "AMBER"
	TLPAmberStrict = "AMBER+STRICT"
	TLPRed         = "RED"
)

// Limits on user-supplied case content.
const (
	MaxTitle = 200
	MaxText  = 64 << 10
	MaxTags  = 50
)

var (
	reName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	reTag  = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N}._:/-]{0,63}$`)

	// ErrNotFound is returned for unknown cases or indicators.
	ErrNotFound = store.ErrNotFound
)

// ValidateName checks a case name (it is used in commands and URLs).
func ValidateName(name string) error {
	if !reName.MatchString(name) {
		return errors.New("case name must be 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	return nil
}

// NormalizeTLP accepts TLP labels in any case, with or without the "TLP:"
// prefix, and the TLP 1.0 WHITE alias.
func NormalizeTLP(s string) (string, error) {
	v := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "TLP:")))
	switch v {
	case TLPClear, "WHITE":
		return TLPClear, nil
	case TLPGreen, TLPAmber, TLPAmberStrict, TLPRed:
		return v, nil
	}
	return "", fmt.Errorf("unknown TLP %q (use clear, green, amber, amber+strict or red)", s)
}

func validateTags(tags []string) error {
	if len(tags) > MaxTags {
		return fmt.Errorf("at most %d tags", MaxTags)
	}
	for _, t := range tags {
		if !reTag.MatchString(t) {
			return fmt.Errorf("invalid tag %q", t)
		}
	}
	return nil
}

func validateText(field, v string, limit int) error {
	if len(v) > limit {
		return fmt.Errorf("%s longer than %d bytes", field, limit)
	}
	if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\t' && r != '\r' }) {
		return fmt.Errorf("%s contains control characters", field)
	}
	return nil
}

// Service implements case operations over the store and the search engine.
type Service struct {
	store  *store.Store
	engine *engine.Engine
	now    func() time.Time
}

// New returns a case service.
func New(s *store.Store, e *engine.Engine) *Service {
	return &Service{store: s, engine: e, now: time.Now}
}

// Create opens a new case.
func (s *Service) Create(ctx context.Context, name, title, tlp string, tags []string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := validateText("title", title, MaxTitle); err != nil {
		return err
	}
	if tlp == "" {
		tlp = TLPAmber
	}
	norm, err := NormalizeTLP(tlp)
	if err != nil {
		return err
	}
	if err := validateTags(tags); err != nil {
		return err
	}
	err = s.store.CreateCase(ctx, store.Case{Name: name, Title: title, TLP: norm, Tags: tags}, s.now())
	if errors.Is(err, store.ErrExists) {
		return fmt.Errorf("a case named %q already exists", name)
	}
	return err
}

// Update changes title, description, TLP or status; nil means unchanged.
func (s *Service) Update(ctx context.Context, name string, title, description, tlp, status *string) error {
	if title != nil {
		if err := validateText("title", *title, MaxTitle); err != nil {
			return err
		}
	}
	if description != nil {
		if err := validateText("description", *description, MaxText); err != nil {
			return err
		}
	}
	if tlp != nil {
		norm, err := NormalizeTLP(*tlp)
		if err != nil {
			return err
		}
		tlp = &norm
	}
	if status != nil && *status != "open" && *status != "closed" {
		return fmt.Errorf("status must be open or closed")
	}
	return s.store.UpdateCase(ctx, name, title, description, tlp, status, s.now())
}

// Add puts indicators in a case and returns how many were new.
func (s *Service) Add(ctx context.Context, name string, inds []ioc.Indicator, note string) (int, error) {
	if err := validateText("note", note, MaxText); err != nil {
		return 0, err
	}
	items := make([]store.CaseItem, len(inds))
	for k, i := range inds {
		items[k] = store.CaseItem{Type: string(i.Type), Value: i.Value, Note: note}
	}
	return s.store.AddCaseItems(ctx, name, items, s.now())
}

// Remove deletes an indicator from a case.
func (s *Service) Remove(ctx context.Context, name string, i ioc.Indicator) error {
	return s.store.RemoveCaseItem(ctx, name, string(i.Type), i.Value, s.now())
}

// Note appends a Markdown note.
func (s *Service) Note(ctx context.Context, name, body string) error {
	body = strings.TrimSpace(body)
	if body == "" {
		return errors.New("empty note")
	}
	if err := validateText("note", body, MaxText); err != nil {
		return err
	}
	return s.store.AddCaseNote(ctx, name, body, s.now())
}

// Tag adds and removes tags.
func (s *Service) Tag(ctx context.Context, name string, add, remove []string) error {
	if err := validateTags(add); err != nil {
		return err
	}
	return s.store.SetCaseTags(ctx, name, add, remove, s.now())
}

// Delete removes a case permanently.
func (s *Service) Delete(ctx context.Context, name string) error {
	return s.store.DeleteCase(ctx, name)
}

// List returns case summaries.
func (s *Service) List(ctx context.Context, includeClosed bool) ([]store.CaseSummary, error) {
	return s.store.CaseSummaries(ctx, includeClosed)
}

// Record saves search reports into a case, adding missing indicators.
func (s *Service) Record(ctx context.Context, name string, reports []*engine.Report) error {
	for _, rep := range reports {
		data, err := json.Marshal(rep)
		if err != nil {
			return err
		}
		if err := s.store.SetCaseItemResult(ctx, name, string(rep.Indicator.Type), rep.Indicator.Value,
			string(rep.Verdict), data, s.now()); err != nil {
			return err
		}
	}
	return nil
}

// Search (re)searches the indicators of a case and records the results.
// With pendingOnly, only indicators never searched are queried.
func (s *Service) Search(ctx context.Context, name string, opts engine.SearchOptions, pendingOnly bool) ([]*engine.Report, error) {
	c, err := s.store.CaseByName(ctx, name)
	if err != nil {
		return nil, err
	}
	var inds []ioc.Indicator
	for _, it := range c.Items {
		if pendingOnly && it.SearchedAt != nil {
			continue
		}
		inds = append(inds, ioc.Indicator{Type: ioc.Type(it.Type), Value: it.Value})
	}
	if len(inds) == 0 {
		return nil, nil
	}
	reports := s.engine.SearchMany(ctx, inds, opts)
	return reports, s.Record(ctx, name, reports)
}

// View is a case ready for display and export.
type View struct {
	Case  store.Case `json:"case"`
	Items []Item     `json:"items"`
}

// Item is a case indicator with its decoded last report.
type Item struct {
	Indicator  ioc.Indicator    `json:"indicator"`
	Note       string           `json:"note,omitempty"`
	Verdict    provider.Verdict `json:"verdict,omitempty"`
	Report     *engine.Report   `json:"report,omitempty"`
	SearchedAt *time.Time       `json:"searched_at,omitempty"`
	AddedAt    time.Time        `json:"added_at"`
}

// Load returns a case with decoded reports.
func (s *Service) Load(ctx context.Context, name string) (*View, error) {
	c, err := s.store.CaseByName(ctx, name)
	if err != nil {
		return nil, err
	}
	v := &View{Case: *c, Items: make([]Item, 0, len(c.Items))}
	for _, it := range c.Items {
		item := Item{
			Indicator: ioc.Indicator{Type: ioc.Type(it.Type), Value: it.Value},
			Note:      it.Note, Verdict: provider.Verdict(it.Verdict),
			SearchedAt: it.SearchedAt, AddedAt: it.AddedAt,
		}
		if len(it.Report) > 0 {
			var rep engine.Report
			if err := json.Unmarshal(it.Report, &rep); err == nil {
				item.Report = &rep
			}
		}
		v.Items = append(v.Items, item)
	}
	v.Case.Items = nil
	return v, nil
}

// Counts returns how many items have each verdict.
func (v *View) Counts() (malicious, suspicious, clean, unsearched int) {
	for _, it := range v.Items {
		switch {
		case it.SearchedAt == nil:
			unsearched++
		case it.Verdict == provider.VerdictMalicious:
			malicious++
		case it.Verdict == provider.VerdictSuspicious:
			suspicious++
		case it.Verdict == provider.VerdictClean:
			clean++
		}
	}
	return
}

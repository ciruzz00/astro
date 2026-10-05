package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Dataset describes an offline dataset and when it was last synced.
type Dataset struct {
	Name     string    `json:"name"`
	Source   string    `json:"source"`
	Version  string    `json:"version,omitempty"`
	Records  int       `json:"records"`
	SyncedAt time.Time `json:"synced_at"`
}

// Datasets returns every synced dataset ordered by name.
func (s *Store) Datasets(ctx context.Context) ([]Dataset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, source, version, records, synced_at FROM datasets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Dataset
	for rows.Next() {
		var d Dataset
		var synced int64
		if err := rows.Scan(&d.Name, &d.Source, &d.Version, &d.Records, &synced); err != nil {
			return nil, err
		}
		d.SyncedAt = time.Unix(synced, 0).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// HasDataset reports whether a dataset has been synced at least once.
func (s *Store) HasDataset(ctx context.Context, name string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM datasets WHERE name = ?`, name).Scan(&n)
	return n > 0, err
}

func setDataset(ctx context.Context, tx *sql.Tx, d Dataset) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO datasets (name, source, version, records, synced_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (name) DO UPDATE SET source = excluded.source, version = excluded.version,
		 records = excluded.records, synced_at = excluded.synced_at`,
		d.Name, d.Source, d.Version, d.Records, d.SyncedAt.Unix(),
	)
	return err
}

// AttackObject is a MITRE ATT&CK object.
type AttackObject struct {
	ID          string   `json:"id"`
	Domain      string   `json:"domain"`
	Kind        string   `json:"kind"`
	Subtype     string   `json:"subtype,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	URL         string   `json:"url,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	Platforms   []string `json:"platforms,omitempty"`
	Tactics     []string `json:"tactics,omitempty"`
	Deprecated  bool     `json:"deprecated,omitempty"`
}

// AttackRelation links two ATT&CK objects, e.g. G0032 uses T1059.
type AttackRelation struct {
	SourceID string `json:"source_id"`
	Rel      string `json:"rel"`
	TargetID string `json:"target_id"`
	Domain   string `json:"domain"`
}

// Related is an object linked to the queried one.
type Related struct {
	Rel      string `json:"rel"`
	Incoming bool   `json:"incoming"`
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
}

// ReplaceAttack replaces every object and relation of an ATT&CK domain.
func (s *Store) ReplaceAttack(ctx context.Context, d Dataset, domain string, objs []AttackObject, rels []AttackRelation) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{`DELETE FROM attack_objects WHERE domain = ?`, `DELETE FROM attack_relations WHERE domain = ?`} {
			if _, err := tx.ExecContext(ctx, q, domain); err != nil {
				return err
			}
		}
		insObj, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO attack_objects
			(id, domain, kind, subtype, name, description, url, aliases, platforms, tactics, deprecated)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer insObj.Close()
		for _, o := range objs {
			if _, err := insObj.ExecContext(ctx, o.ID, domain, o.Kind, o.Subtype, o.Name, o.Description, o.URL,
				jsonList(o.Aliases), jsonList(o.Platforms), jsonList(o.Tactics), o.Deprecated); err != nil {
				return fmt.Errorf("insert %s: %w", o.ID, err)
			}
		}
		insRel, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO attack_relations (source_id, rel, target_id, domain) VALUES (?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer insRel.Close()
		for _, r := range rels {
			if _, err := insRel.ExecContext(ctx, r.SourceID, r.Rel, r.TargetID, domain); err != nil {
				return err
			}
		}
		return setDataset(ctx, tx, d)
	})
}

const attackCols = `id, domain, kind, subtype, name, description, url, aliases, platforms, tactics, deprecated`

// AttackByID returns the object with the given external ID, in every domain it exists.
func (s *Store) AttackByID(ctx context.Context, id string) ([]AttackObject, error) {
	return s.queryAttack(ctx, `SELECT `+attackCols+` FROM attack_objects WHERE id = ? ORDER BY domain`, id)
}

// AttackSearch finds non-deprecated objects whose name or aliases contain q.
func (s *Store) AttackSearch(ctx context.Context, q string, limit int) ([]AttackObject, error) {
	like := "%" + escapeLike(q) + "%"
	return s.queryAttack(ctx, `SELECT `+attackCols+` FROM attack_objects
		WHERE deprecated = 0 AND (name LIKE ? ESCAPE '\' OR aliases LIKE ? ESCAPE '\')
		ORDER BY (lower(name) = lower(?)) DESC, kind, id LIMIT ?`, like, like, q, limit)
}

// AttackTechniquesByTactic returns the non-deprecated techniques of a tactic in a domain.
func (s *Store) AttackTechniquesByTactic(ctx context.Context, tactic, domain string) ([]AttackObject, error) {
	b, _ := json.Marshal(tactic)
	return s.queryAttack(ctx, `SELECT `+attackCols+` FROM attack_objects
		WHERE kind = 'technique' AND deprecated = 0 AND domain = ? AND tactics LIKE ? ESCAPE '\'
		ORDER BY id`, domain, "%"+escapeLike(string(b))+"%")
}

// AttackRelated returns the objects linked to id in either direction.
func (s *Store) AttackRelated(ctx context.Context, id string) ([]Related, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT r.rel, 0, o.id, o.kind, o.name FROM attack_relations r
		JOIN attack_objects o ON o.id = r.target_id AND o.domain = r.domain
		WHERE r.source_id = ? AND o.deprecated = 0
		UNION
		SELECT DISTINCT r.rel, 1, o.id, o.kind, o.name FROM attack_relations r
		JOIN attack_objects o ON o.id = r.source_id AND o.domain = r.domain
		WHERE r.target_id = ? AND o.deprecated = 0
		ORDER BY 1, 2, 3`, id, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Related
	for rows.Next() {
		var r Related
		if err := rows.Scan(&r.Rel, &r.Incoming, &r.ID, &r.Kind, &r.Name); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) queryAttack(ctx context.Context, q string, args ...any) ([]AttackObject, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AttackObject
	for rows.Next() {
		var o AttackObject
		var aliases, platforms, tactics string
		if err := rows.Scan(&o.ID, &o.Domain, &o.Kind, &o.Subtype, &o.Name, &o.Description, &o.URL,
			&aliases, &platforms, &tactics, &o.Deprecated); err != nil {
			return nil, err
		}
		o.Aliases, o.Platforms, o.Tactics = parseList(aliases), parseList(platforms), parseList(tactics)
		out = append(out, o)
	}
	return out, rows.Err()
}

// KEV is a CISA Known Exploited Vulnerabilities entry.
type KEV struct {
	CVE              string   `json:"cve"`
	Vendor           string   `json:"vendor"`
	Product          string   `json:"product"`
	Name             string   `json:"name"`
	DateAdded        string   `json:"date_added"`
	DueDate          string   `json:"due_date"`
	ShortDescription string   `json:"short_description"`
	RequiredAction   string   `json:"required_action"`
	Ransomware       string   `json:"ransomware"`
	Notes            string   `json:"notes,omitempty"`
	CWEs             []string `json:"cwes,omitempty"`
}

// ReplaceKEV replaces the whole KEV catalog.
func (s *Store) ReplaceKEV(ctx context.Context, d Dataset, entries []KEV) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM kev`); err != nil {
			return err
		}
		ins, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO kev
			(cve_id, vendor, product, name, date_added, due_date, short_description, required_action, ransomware, notes, cwes)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, k := range entries {
			if _, err := ins.ExecContext(ctx, k.CVE, k.Vendor, k.Product, k.Name, k.DateAdded, k.DueDate,
				k.ShortDescription, k.RequiredAction, k.Ransomware, k.Notes, jsonList(k.CWEs)); err != nil {
				return err
			}
		}
		return setDataset(ctx, tx, d)
	})
}

// KEVByCVE returns the KEV entry for a CVE ID.
func (s *Store) KEVByCVE(ctx context.Context, cve string) (*KEV, error) {
	var k KEV
	var cwes string
	err := s.db.QueryRowContext(ctx, `SELECT cve_id, vendor, product, name, date_added, due_date,
		short_description, required_action, ransomware, notes, cwes FROM kev WHERE cve_id = ?`, cve).
		Scan(&k.CVE, &k.Vendor, &k.Product, &k.Name, &k.DateAdded, &k.DueDate,
			&k.ShortDescription, &k.RequiredAction, &k.Ransomware, &k.Notes, &cwes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k.CWEs = parseList(cwes)
	return &k, nil
}

// OUI is an IEEE MAC address block assignment.
type OUI struct {
	Prefix   string `json:"prefix"`
	Registry string `json:"registry"`
	Org      string `json:"org"`
	Address  string `json:"address,omitempty"`
}

// ReplaceOUI replaces the whole IEEE registry.
func (s *Store) ReplaceOUI(ctx context.Context, d Dataset, entries []OUI) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM oui`); err != nil {
			return err
		}
		ins, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO oui (prefix, registry, org, address) VALUES (?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, o := range entries {
			if _, err := ins.ExecContext(ctx, o.Prefix, o.Registry, o.Org, o.Address); err != nil {
				return err
			}
		}
		return setDataset(ctx, tx, d)
	})
}

// OUILookup finds the most specific block (MA-S, MA-M, then MA-L) for a MAC
// given as 12 upper-case hex digits.
func (s *Store) OUILookup(ctx context.Context, hex string) (*OUI, error) {
	if len(hex) != 12 {
		return nil, fmt.Errorf("invalid MAC %q", hex)
	}
	var o OUI
	err := s.db.QueryRowContext(ctx, `SELECT prefix, registry, org, address FROM oui
		WHERE prefix IN (?, ?, ?) ORDER BY length(prefix) DESC LIMIT 1`,
		hex[:9], hex[:7], hex[:6]).Scan(&o.Prefix, &o.Registry, &o.Org, &o.Address)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func jsonList(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func parseList(s string) []string {
	var v []string
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func escapeLike(s string) string { return likeEscaper.Replace(s) }

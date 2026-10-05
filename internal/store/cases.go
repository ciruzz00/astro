package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Case is an investigation.
type Case struct {
	ID          int64      `json:"-"`
	Name        string     `json:"name"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	TLP         string     `json:"tlp"`
	Status      string     `json:"status"`
	Tags        []string   `json:"tags"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Items       []CaseItem `json:"items,omitempty"`
	Notes       []CaseNote `json:"notes,omitempty"`
}

// CaseItem is an indicator collected in a case with its last search result.
type CaseItem struct {
	Type       string          `json:"type"`
	Value      string          `json:"value"`
	Note       string          `json:"note,omitempty"`
	Verdict    string          `json:"verdict,omitempty"`
	Report     json.RawMessage `json:"report,omitempty"`
	SearchedAt *time.Time      `json:"searched_at,omitempty"`
	AddedAt    time.Time       `json:"added_at"`
}

// CaseNote is a free-text (Markdown) note.
type CaseNote struct {
	ID        int64     `json:"id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// CaseSummary is a case without its items, with verdict counts.
type CaseSummary struct {
	Case
	Indicators int `json:"indicators"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
}

// CreateCase creates a case; ErrExists if the name is taken.
func (s *Store) CreateCase(ctx context.Context, c Case, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO cases (name, title, description, tlp, status, created_at, updated_at) VALUES (?, ?, ?, ?, 'open', ?, ?)`,
			c.Name, c.Title, c.Description, c.TLP, now.Unix(), now.Unix())
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrExists
			}
			return err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		return addTags(ctx, tx, id, c.Tags)
	})
}

// CaseSummaries lists cases, newest activity first.
func (s *Store) CaseSummaries(ctx context.Context, includeClosed bool) ([]CaseSummary, error) {
	q := `SELECT c.id, c.name, c.title, c.description, c.tlp, c.status, c.created_at, c.updated_at,
		COUNT(i.id), COALESCE(SUM(i.verdict = 'malicious'), 0), COALESCE(SUM(i.verdict = 'suspicious'), 0)
		FROM cases c LEFT JOIN case_items i ON i.case_id = c.id`
	if !includeClosed {
		q += ` WHERE c.status = 'open'`
	}
	q += ` GROUP BY c.id ORDER BY c.updated_at DESC, c.id DESC`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CaseSummary
	for rows.Next() {
		var cs CaseSummary
		var created, updated int64
		if err := rows.Scan(&cs.ID, &cs.Name, &cs.Title, &cs.Description, &cs.TLP, &cs.Status, &created, &updated,
			&cs.Indicators, &cs.Malicious, &cs.Suspicious); err != nil {
			return nil, err
		}
		cs.CreatedAt, cs.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
		out = append(out, cs)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for k := range out {
		if out[k].Tags, err = s.caseTags(ctx, out[k].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CaseByName loads a case with tags, items and notes.
func (s *Store) CaseByName(ctx context.Context, name string) (*Case, error) {
	var c Case
	var created, updated int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, title, description, tlp, status, created_at, updated_at FROM cases WHERE name = ?`, name).
		Scan(&c.ID, &c.Name, &c.Title, &c.Description, &c.TLP, &c.Status, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.CreatedAt, c.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	if c.Tags, err = s.caseTags(ctx, c.ID); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT type, value, note, verdict, report, searched_at, added_at FROM case_items WHERE case_id = ? ORDER BY id`, c.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var it CaseItem
		var searched sql.NullInt64
		var added int64
		var report []byte
		if err := rows.Scan(&it.Type, &it.Value, &it.Note, &it.Verdict, &report, &searched, &added); err != nil {
			return nil, err
		}
		it.Report = report
		it.AddedAt = time.Unix(added, 0).UTC()
		if searched.Valid {
			t := time.Unix(searched.Int64, 0).UTC()
			it.SearchedAt = &t
		}
		c.Items = append(c.Items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	nrows, err := s.db.QueryContext(ctx, `SELECT id, body, created_at FROM case_notes WHERE case_id = ? ORDER BY id`, c.ID)
	if err != nil {
		return nil, err
	}
	defer nrows.Close()
	for nrows.Next() {
		var n CaseNote
		var at int64
		if err := nrows.Scan(&n.ID, &n.Body, &at); err != nil {
			return nil, err
		}
		n.CreatedAt = time.Unix(at, 0).UTC()
		c.Notes = append(c.Notes, n)
	}
	return &c, nrows.Err()
}

// UpdateCase changes the editable fields of a case. Nil fields are left unchanged.
func (s *Store) UpdateCase(ctx context.Context, name string, title, description, tlp, status *string, now time.Time) error {
	return s.withCase(ctx, name, now, func(tx *sql.Tx, id int64) error {
		_, err := tx.ExecContext(ctx, `UPDATE cases SET
			title = COALESCE(?, title), description = COALESCE(?, description),
			tlp = COALESCE(?, tlp), status = COALESCE(?, status) WHERE id = ?`,
			title, description, tlp, status, id)
		return err
	})
}

// DeleteCase removes a case and everything in it.
func (s *Store) DeleteCase(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM cases WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AddCaseItems adds indicators and returns how many were new. For existing
// ones only a non-empty note is updated.
func (s *Store) AddCaseItems(ctx context.Context, name string, items []CaseItem, now time.Time) (int, error) {
	added := 0
	err := s.withCase(ctx, name, now, func(tx *sql.Tx, id int64) error {
		for _, it := range items {
			var exists bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM case_items WHERE case_id = ? AND type = ? AND value = ?)`,
				id, it.Type, it.Value).Scan(&exists); err != nil {
				return err
			}
			var err error
			switch {
			case !exists:
				_, err = tx.ExecContext(ctx, `INSERT INTO case_items (case_id, type, value, note, added_at) VALUES (?, ?, ?, ?, ?)`,
					id, it.Type, it.Value, it.Note, now.Unix())
				added++
			case it.Note != "":
				_, err = tx.ExecContext(ctx, `UPDATE case_items SET note = ? WHERE case_id = ? AND type = ? AND value = ?`,
					it.Note, id, it.Type, it.Value)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	return added, err
}

// SetCaseItemResult stores the latest search result of an indicator, adding it if needed.
func (s *Store) SetCaseItemResult(ctx context.Context, name, typ, value, verdict string, report []byte, now time.Time) error {
	return s.withCase(ctx, name, now, func(tx *sql.Tx, id int64) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO case_items (case_id, type, value, verdict, report, searched_at, added_at) VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT (case_id, type, value) DO UPDATE SET verdict = excluded.verdict, report = excluded.report, searched_at = excluded.searched_at`,
			id, typ, value, verdict, report, now.Unix(), now.Unix())
		return err
	})
}

// RemoveCaseItem deletes an indicator from a case.
func (s *Store) RemoveCaseItem(ctx context.Context, name, typ, value string, now time.Time) error {
	return s.withCase(ctx, name, now, func(tx *sql.Tx, id int64) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM case_items WHERE case_id = ? AND type = ? AND value = ?`, id, typ, value)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// AddCaseNote appends a note.
func (s *Store) AddCaseNote(ctx context.Context, name, body string, now time.Time) error {
	return s.withCase(ctx, name, now, func(tx *sql.Tx, id int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO case_notes (case_id, body, created_at) VALUES (?, ?, ?)`, id, body, now.Unix())
		return err
	})
}

// SetCaseTags adds and removes tags.
func (s *Store) SetCaseTags(ctx context.Context, name string, add, remove []string, now time.Time) error {
	return s.withCase(ctx, name, now, func(tx *sql.Tx, id int64) error {
		if err := addTags(ctx, tx, id, add); err != nil {
			return err
		}
		for _, t := range remove {
			if _, err := tx.ExecContext(ctx, `DELETE FROM case_tags WHERE case_id = ? AND tag = ?`, id, t); err != nil {
				return err
			}
		}
		return nil
	})
}

// withCase runs fn in a transaction on the case named name and bumps its updated_at.
func (s *Store) withCase(ctx context.Context, name string, now time.Time, fn func(tx *sql.Tx, id int64) error) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM cases WHERE name = ?`, name).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := fn(tx, id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE cases SET updated_at = ? WHERE id = ?`, now.Unix(), id)
		return err
	})
}

func addTags(ctx context.Context, tx *sql.Tx, id int64, tags []string) error {
	for _, t := range tags {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO case_tags (case_id, tag) VALUES (?, ?)`, id, t); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) caseTags(ctx context.Context, id int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT tag FROM case_tags WHERE case_id = ? ORDER BY tag`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tags := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

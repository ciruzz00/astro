package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// ReplaceFindings stores the findings of a detection run, replacing those
// of the previous run, and raises the severity of the events they cite.
func (s *Store) ReplaceFindings(ctx context.Context, caseName string, fs []logs.Finding, raise map[int64]logs.Severity, now time.Time) error {
	return s.withCase(ctx, caseName, now, func(tx *sql.Tx, caseID int64) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE case_id = ?`, caseID); err != nil {
			return err
		}
		ins, err := tx.PrepareContext(ctx, `INSERT INTO findings
			(case_id, rule_id, title, severity, technique, first_ns, last_ns, host, username, src_ip, summary, count, event_ids, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, f := range fs {
			ids := f.EventIDs
			if len(ids) > logs.MaxFindingEvents {
				ids = ids[:logs.MaxFindingEvents]
			}
			b, err := json.Marshal(ids)
			if err != nil {
				return err
			}
			if _, err := ins.ExecContext(ctx, caseID, f.RuleID, f.Title, int(f.Severity), f.Technique,
				f.First.UnixNano(), f.Last.UnixNano(), f.Host, f.User, f.SrcIP,
				logs.Truncate(f.Summary, logs.MaxRaw), f.Count, string(b), now.Unix()); err != nil {
				return err
			}
		}
		up, err := tx.PrepareContext(ctx, `UPDATE events SET severity = MAX(severity, ?) WHERE id = ? AND case_id = ?`)
		if err != nil {
			return err
		}
		defer up.Close()
		for id, sev := range raise {
			if _, err := up.ExecContext(ctx, int(sev), id, caseID); err != nil {
				return err
			}
		}
		return nil
	})
}

// Findings lists the findings of a case, most severe and earliest first.
func (s *Store) Findings(ctx context.Context, caseName string) ([]logs.Finding, error) {
	caseID, err := s.CaseID(ctx, caseName)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, rule_id, title, severity, technique, first_ns, last_ns,
		host, username, src_ip, summary, count, event_ids
		FROM findings WHERE case_id = ? ORDER BY severity DESC, first_ns, id`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []logs.Finding
	for rows.Next() {
		var f logs.Finding
		var sev int
		var first, last int64
		var ids string
		if err := rows.Scan(&f.ID, &f.RuleID, &f.Title, &sev, &f.Technique, &first, &last,
			&f.Host, &f.User, &f.SrcIP, &f.Summary, &f.Count, &ids); err != nil {
			return nil, err
		}
		f.Severity, f.First, f.Last = logs.Severity(sev), time.Unix(0, first).UTC(), time.Unix(0, last).UTC()
		if err := json.Unmarshal([]byte(ids), &f.EventIDs); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// EventsByID returns events of a case by id (the references of a finding).
func (s *Store) EventsByID(ctx context.Context, caseName string, ids []int64) ([]logs.Event, error) {
	caseID, err := s.CaseID(ctx, caseName)
	if err != nil {
		return nil, err
	}
	var out []logs.Event
	for _, id := range ids {
		evs, _, err := s.events(ctx, "ev.case_id = ? AND ev.id = ?", []any{caseID, id}, 1, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
	}
	return out, nil
}

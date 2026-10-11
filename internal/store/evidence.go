package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ciruzz00/astro/internal/logs"
)

// Evidence is a file imported into a case. Files are read where they are and
// never copied: the hashes prove which content the events came from.
type Evidence struct {
	ID          int64      `json:"id"`
	Path        string     `json:"path"`
	Name        string     `json:"name"`
	Kind        logs.Kind  `json:"kind"`
	Compressed  bool       `json:"compressed,omitempty"`
	Size        int64      `json:"size"`
	ModTime     time.Time  `json:"mod_time"`
	SHA256      string     `json:"sha256"`
	SHA1        string     `json:"sha1"`
	MD5         string     `json:"md5"`
	Host        string     `json:"host,omitempty"`
	Events      int        `json:"events"`
	ParseErrors int        `json:"parse_errors"`
	Truncated   bool       `json:"truncated,omitempty"`
	FirstEvent  *time.Time `json:"first_event,omitempty"`
	LastEvent   *time.Time `json:"last_event,omitempty"`
	ImportedAt  time.Time  `json:"imported_at"`
}

// CustodyEntry is one link of an evidence's chain of custody.
type CustodyEntry struct {
	ID         int64     `json:"id"`
	EvidenceID int64     `json:"evidence_id"`
	At         time.Time `json:"at"`
	Action     string    `json:"action"`
	Actor      string    `json:"actor"`
	Detail     string    `json:"detail,omitempty"`
	PrevHash   string    `json:"prev_hash"`
	Hash       string    `json:"hash"`
}

// Custody actions.
const (
	CustodyImported = "imported"
	CustodyParsed   = "parsed"
	CustodyVerified = "verified"
	CustodyChanged  = "changed"
	CustodyExported = "exported"
)

// ErrCustodyBroken is returned when the custody chain does not verify.
var ErrCustodyBroken = errors.New("chain of custody does not verify")

func custodyHash(evidenceID int64, at time.Time, action, actor, detail, prev string) string {
	h := sha256.New()
	// Length-prefixed fields: no separator can be forged inside a value.
	for _, f := range []string{strconv.FormatInt(evidenceID, 10), strconv.FormatInt(at.UnixNano(), 10), action, actor, detail, prev} {
		fmt.Fprintf(h, "%d:%s;", len(f), f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func appendCustody(ctx context.Context, tx *sql.Tx, evidenceID int64, action, actor, detail string, now time.Time) error {
	var prev string
	err := tx.QueryRowContext(ctx, `SELECT hash FROM custody_log WHERE evidence_id = ? ORDER BY id DESC LIMIT 1`, evidenceID).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO custody_log (evidence_id, at, action, actor, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		evidenceID, now.UnixNano(), action, actor, detail, prev, custodyHash(evidenceID, now, action, actor, detail, prev))
	return err
}

// CaseID returns the id of the named case.
func (s *Store) CaseID(ctx context.Context, name string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM cases WHERE name = ?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// AddEvidence records a file in a case together with the first custody
// entry. It returns ErrExists if the case already holds the same content.
func (s *Store) AddEvidence(ctx context.Context, caseName string, e Evidence, actor, detail string, now time.Time) (int64, error) {
	var id int64
	err := s.withCase(ctx, caseName, now, func(tx *sql.Tx, caseID int64) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO evidence
			(case_id, path, name, kind, compressed, size, mod_time, sha256, sha1, md5, host, imported_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			caseID, e.Path, e.Name, string(e.Kind), e.Compressed, e.Size, e.ModTime.UnixNano(),
			e.SHA256, e.SHA1, e.MD5, e.Host, now.UnixNano())
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrExists
			}
			return err
		}
		if id, err = res.LastInsertId(); err != nil {
			return err
		}
		return appendCustody(ctx, tx, id, CustodyImported, actor, detail, now)
	})
	return id, err
}

// AppendCustody adds an entry to an evidence's chain of custody.
func (s *Store) AppendCustody(ctx context.Context, evidenceID int64, action, actor, detail string, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		return appendCustody(ctx, tx, evidenceID, action, actor, detail, now)
	})
}

// Custody returns an evidence's chain of custody, oldest first.
func (s *Store) Custody(ctx context.Context, evidenceID int64) ([]CustodyEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, evidence_id, at, action, actor, detail, prev_hash, hash
		FROM custody_log WHERE evidence_id = ? ORDER BY id`, evidenceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustodyEntry
	for rows.Next() {
		var c CustodyEntry
		var at int64
		if err := rows.Scan(&c.ID, &c.EvidenceID, &at, &c.Action, &c.Actor, &c.Detail, &c.PrevHash, &c.Hash); err != nil {
			return nil, err
		}
		c.At = time.Unix(0, at).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// VerifyCustody recomputes the chain of custody of an evidence.
func (s *Store) VerifyCustody(ctx context.Context, evidenceID int64) error {
	entries, err := s.Custody(ctx, evidenceID)
	if err != nil {
		return err
	}
	prev := ""
	for _, c := range entries {
		if c.PrevHash != prev || c.Hash != custodyHash(c.EvidenceID, c.At, c.Action, c.Actor, c.Detail, c.PrevHash) {
			return fmt.Errorf("%w: entry %d (%s)", ErrCustodyBroken, c.ID, c.Action)
		}
		prev = c.Hash
	}
	if len(entries) == 0 {
		return fmt.Errorf("%w: no entries", ErrCustodyBroken)
	}
	return nil
}

// maxCommandLine bounds the command line stored for an event.
const maxCommandLine = 64 << 10

// InsertEvents stores a batch of parsed events in one transaction.
func (s *Store) InsertEvents(ctx context.Context, caseID, evidenceID int64, evs []*logs.Event) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		st, err := tx.PrepareContext(ctx, `INSERT INTO events
			(case_id, evidence_id, time_ns, seq, year_guessed, time_unknown, host, source, kind, event_id,
			 channel, provider, username, src_ip, dst_ip, process, parent, command_line, message, fields,
			 raw, severity, record)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, e := range evs {
			var fields any
			if len(e.Fields) > 0 {
				b, err := json.Marshal(e.Fields)
				if err != nil {
					return err
				}
				fields = string(b)
			}
			if _, err := st.ExecContext(ctx, caseID, evidenceID, e.Time.UnixNano(), e.Seq, e.YearGuessed, e.TimeUnknown,
				e.Host, e.Source, e.Kind, e.EventID, e.Channel, e.Provider, e.User, e.SrcIP, e.DstIP,
				e.Process, e.Parent, logs.Truncate(e.CommandLine, maxCommandLine), logs.Truncate(e.Message, logs.MaxRaw),
				fields, logs.Truncate(e.Raw, logs.MaxRaw),
				int(e.Severity), e.Ref.Record); err != nil {
				return err
			}
		}
		return nil
	})
}

// FinishEvidence stores the outcome of parsing: counts and time range are
// computed from the stored events.
func (s *Store) FinishEvidence(ctx context.Context, evidenceID int64, host string, parseErrors int, truncated bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE evidence SET
		host = CASE WHEN ? <> '' THEN ? ELSE host END,
		parse_errors = ?, truncated = ?,
		events = (SELECT COUNT(*) FROM events WHERE evidence_id = evidence.id),
		first_event = (SELECT MIN(time_ns) FROM events WHERE evidence_id = evidence.id AND time_unknown = 0),
		last_event = (SELECT MAX(time_ns) FROM events WHERE evidence_id = evidence.id AND time_unknown = 0)
		WHERE id = ?`, host, host, parseErrors, truncated, evidenceID)
	return err
}

// CaseEvidence lists the evidence of a case in import order.
func (s *Store) CaseEvidence(ctx context.Context, caseName string) ([]Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT e.id, e.path, e.name, e.kind, e.compressed, e.size, e.mod_time,
		e.sha256, e.sha1, e.md5, e.host, e.events, e.parse_errors, e.truncated, e.first_event, e.last_event, e.imported_at
		FROM evidence e JOIN cases c ON c.id = e.case_id WHERE c.name = ? ORDER BY e.id`, caseName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		var e Evidence
		var kind string
		var mod, imported int64
		var first, last sql.NullInt64
		if err := rows.Scan(&e.ID, &e.Path, &e.Name, &kind, &e.Compressed, &e.Size, &mod, &e.SHA256, &e.SHA1, &e.MD5,
			&e.Host, &e.Events, &e.ParseErrors, &e.Truncated, &first, &last, &imported); err != nil {
			return nil, err
		}
		e.Kind, e.ModTime, e.ImportedAt = logs.Kind(kind), time.Unix(0, mod).UTC(), time.Unix(0, imported).UTC()
		e.FirstEvent, e.LastEvent = nsTime(first), nsTime(last)
		out = append(out, e)
	}
	return out, rows.Err()
}

func nsTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(0, v.Int64).UTC()
	return &t
}

// EventFilter selects events of a case. Zero values match everything.
type EventFilter struct {
	From, To    time.Time
	MinSeverity logs.Severity
	Host        string
	User        string
	// IP matches the source or the destination address.
	IP         string
	Source     string
	Kind       string
	EventID    int
	EvidenceID int64
	// Text is a case-insensitive substring of the message or command line.
	Text   string
	Limit  int
	Offset int
}

// MaxEventPage bounds the events returned by one query.
const MaxEventPage = 5000

// Events returns a page of the case timeline in time order and the total
// number of matching events.
func (s *Store) Events(ctx context.Context, caseName string, f EventFilter) ([]logs.Event, int, error) {
	caseID, err := s.CaseID(ctx, caseName)
	if err != nil {
		return nil, 0, err
	}
	where := []string{"ev.case_id = ?"}
	args := []any{caseID}
	add := func(cond string, v ...any) { where = append(where, cond); args = append(args, v...) }
	if !f.From.IsZero() {
		add("ev.time_ns >= ?", f.From.UnixNano())
	}
	if !f.To.IsZero() {
		add("ev.time_ns <= ?", f.To.UnixNano())
	}
	if f.MinSeverity > logs.Info {
		add("ev.severity >= ?", int(f.MinSeverity))
	}
	if f.Host != "" {
		add("ev.host = ? COLLATE NOCASE", f.Host)
	}
	if f.User != "" {
		add("ev.username = ? COLLATE NOCASE", f.User)
	}
	if f.IP != "" {
		add("(ev.src_ip = ? OR ev.dst_ip = ?)", f.IP, f.IP)
	}
	if f.Source != "" {
		add("ev.source = ?", f.Source)
	}
	if f.Kind != "" {
		add("ev.kind = ?", f.Kind)
	}
	if f.EventID != 0 {
		add("ev.event_id = ?", f.EventID)
	}
	if f.EvidenceID != 0 {
		add("ev.evidence_id = ?", f.EvidenceID)
	}
	if f.Text != "" {
		like := "%" + escapeLike(f.Text) + "%"
		add(`(ev.message LIKE ? ESCAPE '\' OR ev.command_line LIKE ? ESCAPE '\')`, like, like)
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events ev WHERE `+cond, args...).Scan(&total); err != nil { // #nosec G202 -- cond only joins constant clauses; values are parameters
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > MaxEventPage {
		limit = MaxEventPage
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ev.id, ev.time_ns, ev.seq, ev.year_guessed, ev.time_unknown, ev.host,
		ev.source, ev.kind, ev.event_id, ev.channel, ev.provider, ev.username, ev.src_ip, ev.dst_ip, ev.process,
		ev.parent, ev.command_line, ev.message, ev.fields, ev.raw, ev.severity, ev.record,
		ev.evidence_id, e.path, e.sha256
		FROM events ev JOIN evidence e ON e.id = ev.evidence_id
		WHERE `+cond+` ORDER BY ev.time_ns, ev.evidence_id, ev.seq, ev.id LIMIT ? OFFSET ?`, // #nosec G202 -- see above
		append(args, limit, max(f.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []logs.Event
	for rows.Next() {
		var e logs.Event
		var ns int64
		var sev int
		var fields sql.NullString
		if err := rows.Scan(&e.ID, &ns, &e.Seq, &e.YearGuessed, &e.TimeUnknown, &e.Host, &e.Source, &e.Kind,
			&e.EventID, &e.Channel, &e.Provider, &e.User, &e.SrcIP, &e.DstIP, &e.Process, &e.Parent,
			&e.CommandLine, &e.Message, &fields, &e.Raw, &sev, &e.Ref.Record,
			&e.Ref.EvidenceID, &e.Ref.Path, &e.Ref.SHA256); err != nil {
			return nil, 0, err
		}
		e.Time, e.Severity = time.Unix(0, ns).UTC(), logs.Severity(sev)
		if fields.Valid {
			if err := json.Unmarshal([]byte(fields.String), &e.Fields); err != nil {
				return nil, 0, fmt.Errorf("event %d fields: %w", e.ID, err)
			}
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrExists is returned when a unique name is already taken.
var ErrExists = errors.New("already exists")

// Token is an API token's metadata; the secret itself is never stored.
type Token struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// CreateToken stores the hash of a new token.
func (s *Store) CreateToken(ctx context.Context, name string, hash []byte, prefix string, now time.Time) (*Token, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens (name, hash, prefix, created_at) VALUES (?, ?, ?, ?)`,
		name, hash, prefix, now.Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrExists
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &Token{ID: id, Name: name, Prefix: prefix, CreatedAt: time.Unix(now.Unix(), 0).UTC()}, nil
}

// TokenByHash returns the active (not revoked) token with this hash.
func (s *Store) TokenByHash(ctx context.Context, hash []byte) (*Token, []byte, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+tokenCols+`, hash FROM api_tokens WHERE hash = ? AND revoked_at IS NULL`, hash)
	var stored []byte
	t, err := scanToken(row, &stored)
	return t, stored, err
}

// TouchToken records a use of the token, at most once per minute.
func (s *Store) TouchToken(ctx context.Context, id int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_tokens SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)`,
		now.Unix(), id, now.Add(-time.Minute).Unix())
	return err
}

// Tokens lists every token, revoked ones included.
func (s *Store) Tokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+tokenCols+` FROM api_tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// ActiveTokens counts tokens that are not revoked.
func (s *Store) ActiveTokens(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL`).Scan(&n)
	return n, err
}

// RevokeToken revokes the active token with this name.
func (s *Store) RevokeToken(ctx context.Context, name string, now time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_tokens SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL`, now.Unix(), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const tokenCols = `id, name, prefix, created_at, last_used_at, revoked_at` // #nosec G101 -- column list, not a credential

type scanner interface{ Scan(dest ...any) error }

func scanToken(row scanner, extra ...any) (*Token, error) {
	var t Token
	var created int64
	var used, revoked sql.NullInt64
	dest := append([]any{&t.ID, &t.Name, &t.Prefix, &created, &used, &revoked}, extra...)
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt = time.Unix(created, 0).UTC()
	if used.Valid {
		u := time.Unix(used.Int64, 0).UTC()
		t.LastUsedAt = &u
	}
	if revoked.Valid {
		r := time.Unix(revoked.Int64, 0).UTC()
		t.RevokedAt = &r
	}
	return &t, nil
}

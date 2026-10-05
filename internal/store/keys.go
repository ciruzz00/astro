package store

import (
	"context"
	"time"
)

// ProviderKey is an API key stored in the database.
type ProviderKey struct {
	Name      string
	Value     string
	UpdatedAt time.Time
}

// ProviderKeys returns every stored provider key, by name.
func (s *Store) ProviderKeys(ctx context.Context) (map[string]ProviderKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, value, updated_at FROM provider_keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ProviderKey{}
	for rows.Next() {
		var k ProviderKey
		var at int64
		if err := rows.Scan(&k.Name, &k.Value, &at); err != nil {
			return nil, err
		}
		k.UpdatedAt = time.Unix(at, 0).UTC()
		out[k.Name] = k
	}
	return out, rows.Err()
}

// SetProviderKey stores or replaces a provider key.
func (s *Store) SetProviderKey(ctx context.Context, name, value string, now time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO provider_keys (name, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		name, value, now.Unix())
	return err
}

// DeleteProviderKey removes a stored provider key.
func (s *Store) DeleteProviderKey(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM provider_keys WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

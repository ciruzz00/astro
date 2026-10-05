package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// CacheGet returns the cached payload for provider/key if it has not expired.
func (s *Store) CacheGet(ctx context.Context, provider, key string, now time.Time) (data []byte, fetched time.Time, err error) {
	var fetchedUnix int64
	err = s.db.QueryRowContext(ctx,
		`SELECT data, fetched_at FROM cache WHERE provider = ? AND indicator = ? AND expires_at > ?`,
		provider, key, now.Unix(),
	).Scan(&data, &fetchedUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, ErrNotFound
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, time.Unix(fetchedUnix, 0), nil
}

// CachePut stores a payload for provider/key until now+ttl.
func (s *Store) CachePut(ctx context.Context, provider, key string, data []byte, now time.Time, ttl time.Duration) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cache (provider, indicator, data, fetched_at, expires_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (provider, indicator) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at, expires_at = excluded.expires_at`,
		provider, key, data, now.Unix(), now.Add(ttl).Unix(),
	)
	return err
}

// CachePurge deletes expired entries and returns how many were removed.
func (s *Store) CachePurge(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM cache WHERE expires_at <= ?`, now.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

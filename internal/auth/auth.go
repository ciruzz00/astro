// Package auth creates and verifies REST API bearer tokens.
// Tokens are 256-bit random values; only their SHA-256 is stored.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"regexp"
	"time"

	"github.com/ciruzz00/astro/internal/store"
)

// Prefix marks astro tokens, so they are recognizable in secret scanners.
const Prefix = "astro_"

// ErrInvalid is returned for unknown, malformed or revoked tokens.
var ErrInvalid = errors.New("invalid or revoked token")

var (
	reToken = regexp.MustCompile(`^astro_[A-Za-z0-9_-]{43}$`)
	reName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Store is the token persistence used by Manager.
type Store interface {
	CreateToken(ctx context.Context, name string, hash []byte, prefix string, now time.Time) (*store.Token, error)
	TokenByHash(ctx context.Context, hash []byte) (*store.Token, []byte, error)
	TouchToken(ctx context.Context, id int64, now time.Time) error
}

// Manager issues and verifies tokens.
type Manager struct {
	store Store
	now   func() time.Time
}

// NewManager returns a token manager over s.
func NewManager(s Store) *Manager { return &Manager{store: s, now: time.Now} }

// Create issues a new token. The returned secret is shown once and never stored.
func (m *Manager) Create(ctx context.Context, name string) (secret string, t *store.Token, err error) {
	if !reName.MatchString(name) {
		return "", nil, errors.New("token name must be 1-64 letters, digits, '.', '_' or '-'")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	secret = Prefix + base64.RawURLEncoding.EncodeToString(b)
	t, err = m.store.CreateToken(ctx, name, hash(secret), secret[:len(Prefix)+4], m.now())
	if errors.Is(err, store.ErrExists) {
		return "", nil, errors.New("a token named " + name + " already exists")
	}
	return secret, t, err
}

// Verify returns the token metadata if secret is a valid, active token.
func (m *Manager) Verify(ctx context.Context, secret string) (*store.Token, error) {
	if !reToken.MatchString(secret) {
		return nil, ErrInvalid
	}
	h := hash(secret)
	t, stored, err := m.store.TokenByHash(ctx, h)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(h, stored) != 1 {
		return nil, ErrInvalid
	}
	_ = m.store.TouchToken(ctx, t.ID, m.now())
	return t, nil
}

func hash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

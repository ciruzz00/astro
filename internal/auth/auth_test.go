package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ciruzz00/astro/internal/store"
)

func newManager(t *testing.T) (*Manager, *store.Store) {
	t.Helper()
	s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "astro.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return NewManager(s), s
}

func TestCreateVerifyRevoke(t *testing.T) {
	m, s := newManager(t)
	ctx := context.Background()

	secret, tok, err := m.Create(ctx, "sentinelone")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, Prefix) || len(secret) != len(Prefix)+43 || tok.Prefix != secret[:10] {
		t.Fatalf("unexpected token format (len %d)", len(secret))
	}
	got, err := m.Verify(ctx, secret)
	if err != nil || got.Name != "sentinelone" {
		t.Fatalf("Verify = %+v, %v", got, err)
	}

	list, err := s.Tokens(ctx)
	if err != nil || len(list) != 1 || list[0].LastUsedAt == nil {
		t.Fatalf("Tokens = %+v, %v (last use must be recorded)", list, err)
	}

	if _, _, err := m.Create(ctx, "sentinelone"); err == nil {
		t.Error("duplicate names must be rejected")
	}
	if err := s.RevokeToken(ctx, "sentinelone", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify(ctx, secret); !errors.Is(err, ErrInvalid) {
		t.Errorf("revoked token: err = %v", err)
	}
	if err := s.RevokeToken(ctx, "sentinelone", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("double revoke: err = %v", err)
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	m, _ := newManager(t)
	for _, s := range []string{"", "astro_short", "Bearer x", "astro_" + strings.Repeat("A", 43)} {
		if _, err := m.Verify(context.Background(), s); !errors.Is(err, ErrInvalid) {
			t.Errorf("Verify(%q) err = %v", s, err)
		}
	}
}

func TestCreateRejectsBadNames(t *testing.T) {
	m, _ := newManager(t)
	for _, n := range []string{"", "-x", "a b", strings.Repeat("a", 65), "x\n"} {
		if _, _, err := m.Create(context.Background(), n); err == nil {
			t.Errorf("Create(%q) should fail", n)
		}
	}
}

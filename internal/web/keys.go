package web

import (
	"context"
	"time"
)

// KeyStatus describes a provider API key without revealing it.
type KeyStatus struct {
	Name      string
	Label     string
	Env       string
	URL       string
	Origin    string // "env", "database", "file" or "" when not set
	UpdatedAt *time.Time
	Providers []string
}

// KeyTest is the outcome of testing a key against one provider.
type KeyTest struct {
	Provider string
	OK       bool
	Message  string
}

// KeyManager reads and changes provider API keys.
type KeyManager interface {
	KeyStatuses(ctx context.Context) ([]KeyStatus, error)
	SetKey(ctx context.Context, name, value string) error
	DeleteKey(ctx context.Context, name string) error
	TestKey(ctx context.Context, name string) ([]KeyTest, error)
}

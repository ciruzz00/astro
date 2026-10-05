// Package config loads astro settings from a TOML file and environment variables.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
)

// Secret is a string that never prints its value, to keep API keys out of
// logs, errors and JSON output by accident.
type Secret string

func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return "[redacted]"
}

// GoString keeps %#v from leaking the value.
func (s Secret) GoString() string { return s.String() }

// LogValue keeps log/slog from leaking the value.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.String()) }

// MarshalText keeps encoders from leaking the value.
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText reads the real value from config files.
func (s *Secret) UnmarshalText(b []byte) error { *s = Secret(b); return nil }

// Reveal returns the actual value. Only call it where the key is sent to its provider.
func (s Secret) Reveal() string { return string(s) }

// IsSet reports whether a value is configured.
func (s Secret) IsSet() bool { return s != "" }

// Keys holds the API keys of the external providers.
type Keys struct {
	VirusTotal Secret `toml:"virustotal"`
	AbuseCH    Secret `toml:"abusech"`
	AbuseIPDB  Secret `toml:"abuseipdb"`
	OTX        Secret `toml:"otx"`
	Shodan     Secret `toml:"shodan"`
	GreyNoise  Secret `toml:"greynoise"`
	NVD        Secret `toml:"nvd"`
}

// Config is the runtime configuration.
type Config struct {
	DataDir     string        `toml:"-"`
	HTTPTimeout time.Duration `toml:"http_timeout"`
	CacheTTL    time.Duration `toml:"cache_ttl"`
	Keys        Keys          `toml:"keys"`
}

// FileName is the name of the config file inside the data directory.
const FileName = "config.toml"

// envKeys maps environment variables to the key they set.
var envKeys = map[string]func(*Keys) *Secret{
	"ASTRO_VIRUSTOTAL_KEY": func(k *Keys) *Secret { return &k.VirusTotal },
	"ASTRO_ABUSECH_KEY":    func(k *Keys) *Secret { return &k.AbuseCH },
	"ASTRO_ABUSEIPDB_KEY":  func(k *Keys) *Secret { return &k.AbuseIPDB },
	"ASTRO_OTX_KEY":        func(k *Keys) *Secret { return &k.OTX },
	"ASTRO_SHODAN_KEY":     func(k *Keys) *Secret { return &k.Shodan },
	"ASTRO_GREYNOISE_KEY":  func(k *Keys) *Secret { return &k.GreyNoise },
	"ASTRO_NVD_KEY":        func(k *Keys) *Secret { return &k.NVD },
}

// DefaultDataDir returns $ASTRO_DATA_DIR or the per-user config directory.
func DefaultDataDir() (string, error) {
	if d := os.Getenv("ASTRO_DATA_DIR"); d != "" {
		return d, nil
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config dir: %w", err)
	}
	return filepath.Join(d, "astro"), nil
}

// Load reads <dataDir>/config.toml if present, then applies environment
// overrides. Environment variables win over the file.
func Load(dataDir string) (*Config, error) {
	cfg := &Config{
		DataDir:     dataDir,
		HTTPTimeout: 20 * time.Second,
		CacheTTL:    24 * time.Hour,
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	path := filepath.Join(dataDir, FileName)
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("stat config: %w", err)
	default:
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s is accessible by other users (mode %v): run chmod 600 on it", path, info.Mode().Perm())
		}
		if _, err := toml.DecodeFile(path, cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}

	for name, field := range envKeys {
		if v := os.Getenv(name); v != "" {
			*field(&cfg.Keys) = Secret(v)
		}
	}
	if cfg.HTTPTimeout <= 0 || cfg.HTTPTimeout > 5*time.Minute {
		return nil, fmt.Errorf("http_timeout must be between 0 and 5m, got %v", cfg.HTTPTimeout)
	}
	if cfg.CacheTTL < 0 {
		return nil, fmt.Errorf("cache_ttl must not be negative, got %v", cfg.CacheTTL)
	}
	return cfg, nil
}

// DBPath returns the path of the SQLite database.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "astro.db") }

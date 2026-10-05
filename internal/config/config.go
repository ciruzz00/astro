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
	// KeyOrigin records where each set key came from: OriginEnv or OriginFile.
	KeyOrigin map[string]string `toml:"-"`
}

// Key origins, in order of precedence.
const (
	OriginEnv      = "env"
	OriginDatabase = "database"
	OriginFile     = "file"
)

// KeyDef describes an API key astro can use.
type KeyDef struct {
	Name  string // config file key and identifier ("virustotal")
	Env   string // environment variable
	Label string // human-readable service name
	URL   string // where to get a key
	field func(*Keys) *Secret
}

// Field returns the key of this definition in k.
func (d KeyDef) Field(k *Keys) *Secret { return d.field(k) }

// KeyDefs lists every supported API key.
var KeyDefs = []KeyDef{
	{"virustotal", "ASTRO_VIRUSTOTAL_KEY", "VirusTotal", "https://www.virustotal.com/gui/my-apikey", func(k *Keys) *Secret { return &k.VirusTotal }},
	{"abusech", "ASTRO_ABUSECH_KEY", "abuse.ch (MalwareBazaar, ThreatFox, URLhaus)", "https://auth.abuse.ch/", func(k *Keys) *Secret { return &k.AbuseCH }},
	{"abuseipdb", "ASTRO_ABUSEIPDB_KEY", "AbuseIPDB", "https://www.abuseipdb.com/account/api", func(k *Keys) *Secret { return &k.AbuseIPDB }},
	{"otx", "ASTRO_OTX_KEY", "AlienVault OTX", "https://otx.alienvault.com/settings", func(k *Keys) *Secret { return &k.OTX }},
	{"shodan", "ASTRO_SHODAN_KEY", "Shodan", "https://account.shodan.io/", func(k *Keys) *Secret { return &k.Shodan }},
	{"greynoise", "ASTRO_GREYNOISE_KEY", "GreyNoise", "https://viz.greynoise.io/account/api-key", func(k *Keys) *Secret { return &k.GreyNoise }},
	{"nvd", "ASTRO_NVD_KEY", "NVD", "https://nvd.nist.gov/developers/request-an-api-key", func(k *Keys) *Secret { return &k.NVD }},
}

// KeyDefByName returns the definition of a key.
func KeyDefByName(name string) (KeyDef, bool) {
	for _, d := range KeyDefs {
		if d.Name == name {
			return d, true
		}
	}
	return KeyDef{}, false
}

// ValidateKeyValue rejects values that cannot be API keys.
func ValidateKeyValue(v string) error {
	if len(v) < 8 || len(v) > 512 {
		return errors.New("an API key must be 8 to 512 characters long")
	}
	for _, r := range v {
		if r <= ' ' || r > '~' {
			return errors.New("an API key may only contain printable ASCII characters, without spaces")
		}
	}
	return nil
}

// FileName is the name of the config file inside the data directory.
const FileName = "config.toml"

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
		KeyOrigin:   map[string]string{},
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

	for _, d := range KeyDefs {
		if d.Field(&cfg.Keys).IsSet() {
			cfg.KeyOrigin[d.Name] = OriginFile
		}
		if v := os.Getenv(d.Env); v != "" {
			*d.Field(&cfg.Keys) = Secret(v)
			cfg.KeyOrigin[d.Name] = OriginEnv
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

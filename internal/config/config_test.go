package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSecretNeverLeaks(t *testing.T) {
	s := Secret("super-secret-key")
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "key", s)
	js, _ := json.Marshal(struct{ K Secret }{s})
	outputs := []string{
		s.String(), fmt.Sprint(s), fmt.Sprintf("%v %s %#v", s, s, s), buf.String(), string(js),
	}
	for _, out := range outputs {
		if strings.Contains(out, "super-secret-key") {
			t.Errorf("secret leaked in %q", out)
		}
	}
	if s.Reveal() != "super-secret-key" {
		t.Error("Reveal() must return the value")
	}
}

// clearEnv unsets every key variable so a developer's real keys can never
// influence (or be printed by) these tests.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, d := range KeyDefs {
		t.Setenv(d.Env, "")
	}
}

func TestLoadFileAndEnv(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	conf := "http_timeout = \"5s\"\n[keys]\nvirustotal = \"from-file\"\nnvd = \"nvd-file\"\n"
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ASTRO_NVD_KEY", "nvd-env")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPTimeout != 5*time.Second {
		t.Errorf("HTTPTimeout = %v", cfg.HTTPTimeout)
	}
	// Never print key values in failures: they could be real secrets.
	if cfg.Keys.VirusTotal.Reveal() != "from-file" {
		t.Error("VirusTotal key was not read from the config file")
	}
	if cfg.Keys.NVD.Reveal() != "nvd-env" {
		t.Error("environment must override the config file")
	}
	if cfg.Keys.Shodan.IsSet() {
		t.Error("Shodan key should be unset")
	}
	if cfg.KeyOrigin["virustotal"] != OriginFile || cfg.KeyOrigin["nvd"] != OriginEnv || cfg.KeyOrigin["shodan"] != "" {
		t.Errorf("KeyOrigin = %v", cfg.KeyOrigin)
	}
}

func TestLoadRejectsWorldReadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error for a config readable by other users")
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPTimeout != 20*time.Second || cfg.CacheTTL != 24*time.Hour {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestValidateKeyValue(t *testing.T) {
	for v, ok := range map[string]bool{"abcdef12": true, "short": false, "has space 123": false, "tab\tkey1234": false, "àccentedkey": false} {
		if err := ValidateKeyValue(v); (err == nil) != ok {
			t.Errorf("ValidateKeyValue(%q) = %v", v, err)
		}
	}
	if _, ok := KeyDefByName("virustotal"); !ok {
		t.Error("virustotal key definition missing")
	}
}

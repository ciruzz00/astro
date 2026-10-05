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

func TestLoadFileAndEnv(t *testing.T) {
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
	if cfg.Keys.VirusTotal.Reveal() != "from-file" {
		t.Errorf("VirusTotal key = %q", cfg.Keys.VirusTotal.Reveal())
	}
	if cfg.Keys.NVD.Reveal() != "nvd-env" {
		t.Errorf("env must override file, got %q", cfg.Keys.NVD.Reveal())
	}
	if cfg.Keys.Shodan.IsSet() {
		t.Error("Shodan key should be unset")
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
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPTimeout != 20*time.Second || cfg.CacheTTL != 24*time.Hour {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

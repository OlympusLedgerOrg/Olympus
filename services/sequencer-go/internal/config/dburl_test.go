package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// fakeEnv implements envReader from an in-memory map.
type fakeEnv map[string]string

func (f fakeEnv) Getenv(k string) string { return f[k] }

func fakeReader(files map[string]string) fileReader {
	return func(path string) ([]byte, error) {
		v, ok := files[path]
		if !ok {
			return nil, fmt.Errorf("no such file: %s", path)
		}
		return []byte(v), nil
	}
}

func TestLoadDBConfig_URLMode(t *testing.T) {
	env := fakeEnv{
		"SEQUENCER_DB_URL": "postgresql://u:p@h:5432/db?sslmode=verify-full",
	}
	cfg, err := loadDBConfig(env, fakeReader(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.URL != "postgresql://u:p@h:5432/db?sslmode=verify-full" {
		t.Errorf("URL not preserved: %q", cfg.URL)
	}
	if cfg.Source != SourceEmbedded {
		t.Errorf("unexpected Source: %q", cfg.Source)
	}
}

func TestLoadDBConfig_ComponentMode_FileWins(t *testing.T) {
	env := fakeEnv{
		"SEQUENCER_DB_HOST":          "db",
		"SEQUENCER_DB_USER":          "olympus",
		"SEQUENCER_DB_NAME":          "olympus",
		"SEQUENCER_DB_SSLMODE":       "disable",
		"SEQUENCER_DB_PASSWORD_FILE": "/run/secrets/db_password",
	}
	cfg, err := loadDBConfig(env, fakeReader(map[string]string{
		"/run/secrets/db_password": "s3cret\n",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		t.Fatalf("URL did not parse: %v", err)
	}
	if u.Scheme != "postgresql" {
		t.Errorf("scheme: %q", u.Scheme)
	}
	if u.User.Username() != "olympus" {
		t.Errorf("user: %q", u.User.Username())
	}
	if pass, _ := u.User.Password(); pass != "s3cret" {
		// Trailing \n must have been stripped.
		t.Errorf("password not stripped of trailing newline: %q", pass)
	}
	if u.Host != "db:5432" {
		t.Errorf("host: %q", u.Host)
	}
	if u.Path != "/olympus" {
		t.Errorf("path: %q", u.Path)
	}
	if u.Query().Get("sslmode") != "disable" {
		t.Errorf("sslmode: %q", u.Query().Get("sslmode"))
	}
	if cfg.Source != SourceFile {
		t.Errorf("Source: %q", cfg.Source)
	}
}

func TestLoadDBConfig_ComponentMode_EnvFallback(t *testing.T) {
	env := fakeEnv{
		"SEQUENCER_DB_HOST":     "db",
		"SEQUENCER_DB_USER":     "olympus",
		"SEQUENCER_DB_NAME":     "olympus",
		"SEQUENCER_DB_SSLMODE":  "verify-full",
		"SEQUENCER_DB_PASSWORD": "s3cret",
	}
	cfg, err := loadDBConfig(env, fakeReader(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Source != SourceEnv {
		t.Errorf("Source: %q", cfg.Source)
	}
	u, _ := url.Parse(cfg.URL)
	if pass, _ := u.User.Password(); pass != "s3cret" {
		t.Errorf("password: %q", pass)
	}
}

// Passwords with reserved URL characters must survive a parse round-trip.
func TestLoadDBConfig_ComponentMode_PasswordEscaping(t *testing.T) {
	tricky := "p@ss:wo/rd?#&"
	env := fakeEnv{
		"SEQUENCER_DB_HOST":     "db",
		"SEQUENCER_DB_USER":     "olympus",
		"SEQUENCER_DB_NAME":     "olympus",
		"SEQUENCER_DB_SSLMODE":  "disable",
		"SEQUENCER_DB_PASSWORD": tricky,
	}
	cfg, err := loadDBConfig(env, fakeReader(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		t.Fatalf("URL did not parse: %v", err)
	}
	pass, ok := u.User.Password()
	if !ok || pass != tricky {
		t.Errorf("password round-trip failed: got %q want %q", pass, tricky)
	}
}

func TestLoadDBConfig_AmbiguousModesRejected(t *testing.T) {
	env := fakeEnv{
		"SEQUENCER_DB_URL":  "postgresql://u:p@h/db?sslmode=disable",
		"SEQUENCER_DB_HOST": "db",
	}
	_, err := loadDBConfig(env, fakeReader(nil))
	if err == nil {
		t.Fatalf("expected ambiguity error, got nil")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadDBConfig_BothPasswordSourcesRejected(t *testing.T) {
	env := fakeEnv{
		"SEQUENCER_DB_HOST":          "db",
		"SEQUENCER_DB_USER":          "u",
		"SEQUENCER_DB_NAME":          "d",
		"SEQUENCER_DB_SSLMODE":       "disable",
		"SEQUENCER_DB_PASSWORD":      "x",
		"SEQUENCER_DB_PASSWORD_FILE": "/tmp/p",
	}
	_, err := loadDBConfig(env, fakeReader(map[string]string{"/tmp/p": "y"}))
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected mutually-exclusive error, got %v", err)
	}
}

func TestLoadDBConfig_NoConfig(t *testing.T) {
	_, err := loadDBConfig(fakeEnv{}, fakeReader(nil))
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no DB configuration") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadDBConfig_MissingComponents(t *testing.T) {
	env := fakeEnv{
		"SEQUENCER_DB_HOST":          "db",
		"SEQUENCER_DB_PASSWORD_FILE": "/tmp/p",
	}
	_, err := loadDBConfig(env, fakeReader(map[string]string{"/tmp/p": "x"}))
	if err == nil || !strings.Contains(err.Error(), "missing required vars") {
		t.Fatalf("expected missing-vars error, got %v", err)
	}
}

func TestLoadDBConfig_PasswordFileMissing(t *testing.T) {
	env := fakeEnv{
		"SEQUENCER_DB_HOST":          "db",
		"SEQUENCER_DB_USER":          "u",
		"SEQUENCER_DB_NAME":          "d",
		"SEQUENCER_DB_SSLMODE":       "disable",
		"SEQUENCER_DB_PASSWORD_FILE": "/nope",
	}
	_, err := loadDBConfig(env, fakeReader(nil))
	if err == nil || !strings.Contains(err.Error(), "read SEQUENCER_DB_PASSWORD_FILE") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestLoadDBConfig_PasswordFileEmpty(t *testing.T) {
	env := fakeEnv{
		"SEQUENCER_DB_HOST":          "db",
		"SEQUENCER_DB_USER":          "u",
		"SEQUENCER_DB_NAME":          "d",
		"SEQUENCER_DB_SSLMODE":       "disable",
		"SEQUENCER_DB_PASSWORD_FILE": "/p",
	}
	_, err := loadDBConfig(env, fakeReader(map[string]string{"/p": "\n"}))
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("expected empty-file error, got %v", err)
	}
}

func TestLoadDBConfig_DefaultPort(t *testing.T) {
	env := fakeEnv{
		"SEQUENCER_DB_HOST":          "db",
		"SEQUENCER_DB_USER":          "u",
		"SEQUENCER_DB_NAME":          "d",
		"SEQUENCER_DB_SSLMODE":       "disable",
		"SEQUENCER_DB_PASSWORD_FILE": "/p",
	}
	cfg, err := loadDBConfig(env, fakeReader(map[string]string{"/p": "x"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	u, _ := url.Parse(cfg.URL)
	if u.Host != "db:5432" {
		t.Errorf("default port not applied: host=%q", u.Host)
	}
}

// Spot-check that errors.Is wrapping behaves on file-read failures so
// callers can distinguish them if needed.
func TestLoadDBConfig_FileReadErrorWrapped(t *testing.T) {
	sentinel := errors.New("disk on fire")
	reader := func(string) ([]byte, error) { return nil, sentinel }
	env := fakeEnv{
		"SEQUENCER_DB_HOST":          "db",
		"SEQUENCER_DB_USER":          "u",
		"SEQUENCER_DB_NAME":          "d",
		"SEQUENCER_DB_SSLMODE":       "disable",
		"SEQUENCER_DB_PASSWORD_FILE": "/p",
	}
	_, err := loadDBConfig(env, reader)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel, got %v", err)
	}
}

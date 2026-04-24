// Package config builds the sequencer's runtime configuration from the
// process environment.
//
// The DB connection string is sensitive: putting a full
// postgresql://user:pass@host/db URL in an env var leaks the password into
// /proc/<pid>/environ and into any tooling that reads the container's
// environment (e.g. `docker inspect`). The Python side already supports a
// file-backed password (see api/config.py::_load_db_password); this package
// brings the Go side to parity so both services can share the same
// `db_password` Docker secret without ever putting credentials in env vars.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// DBConfig is the resolved input that NewPostgresStorage needs.
type DBConfig struct {
	// URL is the fully assembled connection string. It is constructed
	// either from SEQUENCER_DB_URL (back-compat) or from the component
	// env vars + SEQUENCER_DB_PASSWORD_FILE. Callers must not echo it
	// in logs because it may contain the password.
	URL string

	// PasswordSource describes where the password came from, for
	// non-sensitive startup logging (e.g. "file:/run/secrets/db_password",
	// "env:SEQUENCER_DB_PASSWORD", "embedded:SEQUENCER_DB_URL").
	PasswordSource string
}

// envReader is the small slice of os we need; it lets tests inject a fake
// environment without touching real os.Setenv state.
type envReader interface {
	Getenv(string) string
}

type osEnv struct{}

func (osEnv) Getenv(k string) string { return os.Getenv(k) }

// fileReader is the small slice of os/io we need to read the password file.
type fileReader func(string) ([]byte, error)

// LoadDBConfig resolves the sequencer's database connection from the
// process environment.
//
// Two mutually-exclusive modes are supported:
//
//  1. SEQUENCER_DB_URL — full libpq connection string, including the
//     password. This is the historical mode and is preserved for non-Docker
//     deployments and for ad-hoc local testing. A startup warning is
//     emitted by callers because the password is then visible in the
//     process environment.
//
//  2. Component variables — SEQUENCER_DB_HOST, SEQUENCER_DB_PORT,
//     SEQUENCER_DB_USER, SEQUENCER_DB_NAME, SEQUENCER_DB_SSLMODE
//     plus exactly one of SEQUENCER_DB_PASSWORD_FILE (preferred) or
//     SEQUENCER_DB_PASSWORD. The file-backed form lets the service mount a
//     0600 Docker secret instead of leaking the password through env vars.
//
// Mixing the two modes (setting SEQUENCER_DB_URL together with any
// SEQUENCER_DB_HOST / SEQUENCER_DB_USER / SEQUENCER_DB_PASSWORD* variable)
// is rejected so that operators get a clear error rather than a confusing
// "which one wins?" surprise.
func LoadDBConfig() (*DBConfig, error) {
	return loadDBConfig(osEnv{}, os.ReadFile)
}

func loadDBConfig(env envReader, readFile fileReader) (*DBConfig, error) {
	urlVar := strings.TrimSpace(env.Getenv("SEQUENCER_DB_URL"))

	// Detect whether any component variable has been supplied. We treat
	// the presence of *any* of these as a signal that the operator
	// intends to use component mode.
	componentVars := []string{
		"SEQUENCER_DB_HOST",
		"SEQUENCER_DB_PORT",
		"SEQUENCER_DB_USER",
		"SEQUENCER_DB_NAME",
		"SEQUENCER_DB_SSLMODE",
		"SEQUENCER_DB_PASSWORD",
		"SEQUENCER_DB_PASSWORD_FILE",
	}
	componentSet := false
	for _, name := range componentVars {
		if strings.TrimSpace(env.Getenv(name)) != "" {
			componentSet = true
			break
		}
	}

	switch {
	case urlVar != "" && componentSet:
		return nil, fmt.Errorf(
			"ambiguous DB configuration: SEQUENCER_DB_URL is set together with one or " +
				"more component variables (SEQUENCER_DB_HOST/USER/PASSWORD/...). " +
				"Pick exactly one mode: either SEQUENCER_DB_URL alone, or the component " +
				"variables alone (with SEQUENCER_DB_PASSWORD_FILE for the password)")
	case urlVar != "":
		return &DBConfig{
			URL:            urlVar,
			PasswordSource: "embedded:SEQUENCER_DB_URL",
		}, nil
	case componentSet:
		return buildFromComponents(env, readFile)
	default:
		return nil, fmt.Errorf(
			"no DB configuration found: set SEQUENCER_DB_URL, or set the component " +
				"variables SEQUENCER_DB_HOST, SEQUENCER_DB_USER, SEQUENCER_DB_NAME, " +
				"SEQUENCER_DB_SSLMODE plus SEQUENCER_DB_PASSWORD_FILE (preferred) or " +
				"SEQUENCER_DB_PASSWORD")
	}
}

func buildFromComponents(env envReader, readFile fileReader) (*DBConfig, error) {
	host := strings.TrimSpace(env.Getenv("SEQUENCER_DB_HOST"))
	user := strings.TrimSpace(env.Getenv("SEQUENCER_DB_USER"))
	dbName := strings.TrimSpace(env.Getenv("SEQUENCER_DB_NAME"))
	sslMode := strings.TrimSpace(env.Getenv("SEQUENCER_DB_SSLMODE"))
	port := strings.TrimSpace(env.Getenv("SEQUENCER_DB_PORT"))
	if port == "" {
		port = "5432"
	}

	missing := []string{}
	if host == "" {
		missing = append(missing, "SEQUENCER_DB_HOST")
	}
	if user == "" {
		missing = append(missing, "SEQUENCER_DB_USER")
	}
	if dbName == "" {
		missing = append(missing, "SEQUENCER_DB_NAME")
	}
	if sslMode == "" {
		missing = append(missing, "SEQUENCER_DB_SSLMODE")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("component DB config is missing required vars: %s",
			strings.Join(missing, ", "))
	}

	passwordFile := strings.TrimSpace(env.Getenv("SEQUENCER_DB_PASSWORD_FILE"))
	// Do not TrimSpace passwordEnv: the password may legitimately contain
	// surrounding whitespace if the operator chose to.
	passwordEnv := env.Getenv("SEQUENCER_DB_PASSWORD")

	if passwordFile != "" && passwordEnv != "" {
		return nil, fmt.Errorf(
			"both SEQUENCER_DB_PASSWORD_FILE and SEQUENCER_DB_PASSWORD are set; " +
				"set exactly one (the file form is preferred and avoids leaking the " +
				"password into the process environment)")
	}

	var (
		password   string
		passSource string
	)
	switch {
	case passwordFile != "":
		raw, err := readFile(passwordFile)
		if err != nil {
			return nil, fmt.Errorf("read SEQUENCER_DB_PASSWORD_FILE %q: %w", passwordFile, err)
		}
		// Strip a single trailing newline (common with `echo "x" > secret`)
		// but preserve any other whitespace the operator put in the file.
		password = strings.TrimRight(string(raw), "\r\n")
		if password == "" {
			return nil, fmt.Errorf("SEQUENCER_DB_PASSWORD_FILE %q is empty", passwordFile)
		}
		passSource = "file:" + passwordFile
	case passwordEnv != "":
		password = passwordEnv
		passSource = "env:SEQUENCER_DB_PASSWORD"
	default:
		return nil, fmt.Errorf(
			"no DB password source: set SEQUENCER_DB_PASSWORD_FILE (preferred) or " +
				"SEQUENCER_DB_PASSWORD")
	}

	// Build a postgresql:// URL with the user info URL-encoded so that
	// passwords containing reserved characters (':', '@', '/', '?', '#')
	// are passed through correctly to lib/pq.
	u := &url.URL{
		Scheme: "postgresql",
		User:   url.UserPassword(user, password),
		Host:   host + ":" + port,
		Path:   "/" + dbName,
	}
	q := u.Query()
	q.Set("sslmode", sslMode)
	u.RawQuery = q.Encode()

	return &DBConfig{
		URL:            u.String(),
		PasswordSource: passSource,
	}, nil
}

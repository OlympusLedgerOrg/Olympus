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

	// Source describes where the password came from, for non-sensitive
	// startup logging. Always one of the constants below — a categorical
	// label, never a file path or env-var value, so logging it cannot
	// leak operator-controlled strings.
	Source SourceKind
}

// SourceKind enumerates the (categorical) ways the DB password may have
// reached the sequencer.
type SourceKind string

const (
	// SourceFile means the password was read from a file pointed at by
	// SEQUENCER_DB_PASSWORD_FILE.
	SourceFile SourceKind = "file"
	// SourceEnv means the password was read from the
	// SEQUENCER_DB_PASSWORD environment variable.
	SourceEnv SourceKind = "env"
	// SourceEmbedded means the password was embedded in a full
	// SEQUENCER_DB_URL connection string.
	SourceEmbedded SourceKind = "embedded"
)

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
			URL:    urlVar,
			Source: SourceEmbedded,
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
	// passwordFile is TrimSpace'd because it is a *path* — leading/trailing
	// whitespace is never meaningful in a filesystem path and almost always
	// indicates a copy-paste mistake in the env value.
	//
	// passwordEnv is intentionally NOT TrimSpace'd: it is the password
	// itself, and a password may legitimately contain leading or trailing
	// whitespace if the operator chose to use one.
	passwordEnv := env.Getenv("SEQUENCER_DB_PASSWORD")

	if passwordFile != "" && passwordEnv != "" {
		return nil, fmt.Errorf(
			"both SEQUENCER_DB_PASSWORD_FILE and SEQUENCER_DB_PASSWORD are set; " +
				"set exactly one (the file form is preferred and avoids leaking the " +
				"password into the process environment)")
	}

	var (
		password   string
		passSource SourceKind
	)
	switch {
	case passwordFile != "":
		raw, err := readFile(passwordFile)
		if err != nil {
			// Don't echo passwordFile here: it is sourced from an env var
			// whose name contains "PASSWORD", and CodeQL conservatively
			// taints anything derived from such variables. Returning a
			// scrubbed error keeps secrets/paths from later flowing into
			// log.Fatalf in main. Operators can recover the offending path
			// by inspecting their own SEQUENCER_DB_PASSWORD_FILE setting.
			return nil, fmt.Errorf("read SEQUENCER_DB_PASSWORD_FILE: %w", scrubPath(err, passwordFile))
		}
		// Strip any number of trailing CR / LF bytes — common with both
		// `echo "x" > secret` (one \n) and Windows-edited files (\r\n,
		// possibly multiples). All other whitespace inside the password
		// is preserved as-is.
		password = strings.TrimRight(string(raw), "\r\n")
		if password == "" {
			return nil, fmt.Errorf("SEQUENCER_DB_PASSWORD_FILE is empty")
		}
		passSource = SourceFile
	case passwordEnv != "":
		password = passwordEnv
		passSource = SourceEnv
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
		URL:    u.String(),
		Source: passSource,
	}, nil
}

// scrubPath returns a wrapped error whose Error() text has any occurrence
// of `path` (the file path read from SEQUENCER_DB_PASSWORD_FILE) replaced
// with a placeholder. os.ReadFile errors typically embed the path; without
// scrubbing, the path would flow through %w into errors logged elsewhere
// and trip CodeQL's clear-text-logging analyzer (the env var name contains
// "PASSWORD", so any value derived from it is treated as sensitive).
func scrubPath(err error, path string) error {
	if err == nil || path == "" {
		return err
	}
	scrubbed := strings.ReplaceAll(err.Error(), path, "[redacted-path]")
	return scrubbedErr{msg: scrubbed, wrapped: err}
}

// scrubbedErr is the small error type returned by scrubPath. It exposes a
// scrubbed Error() string but preserves Unwrap() so callers can still match
// underlying errors with errors.Is / errors.As.
type scrubbedErr struct {
	msg     string
	wrapped error
}

func (e scrubbedErr) Error() string { return e.msg }
func (e scrubbedErr) Unwrap() error { return e.wrapped }

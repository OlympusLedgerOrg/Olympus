package main

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestRedactedErr_RemovesFullURL(t *testing.T) {
	url := "postgresql://u:secret123@host:5432/db?sslmode=verify-full"
	in := errors.New("connect: failed to dial " + url + ": connection refused")
	got := redactedErr(in, url)
	if strings.Contains(got, url) {
		t.Errorf("full URL not redacted: %q", got)
	}
	if strings.Contains(got, "secret123") {
		t.Errorf("password leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED-DB-URL]") {
		t.Errorf("expected redaction marker, got %q", got)
	}
}

func TestRedactedErr_RemovesBarePassword(t *testing.T) {
	url := "postgresql://u:supersecret@host/db?sslmode=disable"
	in := errors.New("auth failed for password 'supersecret'")
	got := redactedErr(in, url)
	if strings.Contains(got, "supersecret") {
		t.Errorf("bare password leaked: %q", got)
	}
}

// Passwords containing characters that are also structural in a postgres
// URL ('@', '/', ':', '?', '#') must still be redacted from the bare form
// even when the URL itself appears percent-encoded in the error.
// dburl.go URL-encodes user info before building the URL, so the raw
// password may not appear verbatim inside the URL string — but it can
// still appear in any error layer that handled the password before
// encoding (e.g. a file-read or a libpq auth error).
func TestRedactedErr_RemovesBarePasswordWithSpecialChars(t *testing.T) {
	rawPassword := "p@ss/w0rd?#&"
	// Build the URL exactly as dburl.go would (url.UserPassword does the
	// percent-encoding), so the URL string does NOT contain the raw form.
	encoded := url.QueryEscape(rawPassword)
	dbURL := "postgresql://olympus:" + encoded + "@host:5432/db?sslmode=verify-full"

	if strings.Contains(dbURL, rawPassword) {
		t.Fatalf("test setup wrong: raw password appears verbatim in URL %q", dbURL)
	}

	// Simulate a libpq error that quotes the *raw* password back at us
	// (this is exactly the kind of error the URL-substring strip would
	// miss; only the bare-password fallback can catch it).
	in := errors.New("FATAL: password authentication failed for user \"olympus\" (raw='" + rawPassword + "')")
	got := redactedErr(in, dbURL)

	if strings.Contains(got, rawPassword) {
		t.Errorf("password with special chars leaked through: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected [REDACTED] marker, got %q", got)
	}
}

func TestRedactedErr_EmptySecretIsPassThrough(t *testing.T) {
	in := errors.New("some error")
	got := redactedErr(in, "")
	if got != "some error" {
		t.Errorf("unexpected mutation: %q", got)
	}
}

func TestRedactedErr_PreservesUnrelatedText(t *testing.T) {
	url := "postgresql://u:p@h/d?sslmode=verify-full"
	in := errors.New("dial tcp 10.0.0.1:5432: i/o timeout")
	got := redactedErr(in, url)
	if !strings.Contains(got, "i/o timeout") {
		t.Errorf("dropped useful diagnostic: %q", got)
	}
}

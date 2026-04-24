package main

import (
	"errors"
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

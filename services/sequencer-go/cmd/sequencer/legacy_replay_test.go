package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/storage"
)

// TestLegacyLeavesDetectedInStartupPath verifies that ErrLegacyLeaves is
// recognised via errors.Is so that main() can produce its operator-facing
// FATAL message instead of a generic "Failed to load leaves" message.
//
// The production path is:
//
//	store.GetLeaves() → ErrLegacyLeaves
//	main() → errors.Is(err, storage.ErrLegacyLeaves) → log.Fatalf("FATAL: …")
//
// This test exercises the sentinel identity contract (errors.Is) without
// needing a live Postgres connection.
func TestLegacyLeavesDetectedInStartupPath(t *testing.T) {
	// errors.Is must return true for the exact sentinel value.
	if !errors.Is(storage.ErrLegacyLeaves, storage.ErrLegacyLeaves) {
		t.Fatal("errors.Is(ErrLegacyLeaves, ErrLegacyLeaves) should be true")
	}

	// A properly fmt.Errorf %w-wrapped error must still unwrap to ErrLegacyLeaves.
	wrapped := fmt.Errorf("failed to load leaves for startup replay: %w", storage.ErrLegacyLeaves)
	if !errors.Is(wrapped, storage.ErrLegacyLeaves) {
		t.Fatal("fmt.Errorf %%w-wrapped error should satisfy errors.Is for the sentinel")
	}

	// A plain errors.New (no wrapping) must NOT satisfy errors.Is.
	notWrapped := errors.New("failed to load leaves: " + storage.ErrLegacyLeaves.Error())
	if errors.Is(notWrapped, storage.ErrLegacyLeaves) {
		t.Fatal("plain errors.New should not satisfy errors.Is for the sentinel")
	}
}

// TestLegacyLeavesErrorMessageContainsRemediationAction verifies the
// operator-facing message includes the remediation action so that a
// production support engineer reading logs knows exactly what to do.
func TestLegacyLeavesErrorMessageContainsRemediationAction(t *testing.T) {
	msg := storage.ErrLegacyLeaves.Error()
	required := []string{
		"ADR-0003",
		"parser_id",
		"canonical_parser_version",
		"Wipe/recreate",
		"silently rewriting provenance",
	}
	for _, s := range required {
		found := false
		for i := 0; i <= len(msg)-len(s); i++ {
			if msg[i:i+len(s)] == s {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ErrLegacyLeaves message missing %q; full message:\n%s", s, msg)
		}
	}
}

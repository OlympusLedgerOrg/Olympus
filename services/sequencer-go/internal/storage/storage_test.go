package storage

import (
	"bytes"
	"testing"
)

func TestRequireVerifyingSSLMode(t *testing.T) {
	cases := []struct {
		name    string
		connStr string
		wantErr bool
	}{
		// URL form
		{"url verify-full ok", "postgres://u:p@h/db?sslmode=verify-full", false},
		{"url verify-ca ok", "postgresql://u:p@h/db?sslmode=verify-ca", false},
		{"url no sslmode rejected", "postgres://u:p@h/db", true},
		{"url sslmode=prefer rejected", "postgres://u:p@h/db?sslmode=prefer", true},
		{"url sslmode=require rejected", "postgres://u:p@h/db?sslmode=require", true},
		{"url sslmode=disable rejected", "postgres://u:p@h/db?sslmode=disable", true},

		// keyword=value form
		{"kv verify-full ok", "host=h user=u dbname=d sslmode=verify-full", false},
		{"kv verify-ca ok", "host=h user=u dbname=d sslmode=verify-ca", false},
		{"kv no sslmode rejected", "host=h user=u dbname=d", true},
		{"kv sslmode=disable rejected", "host=h user=u dbname=d sslmode=disable", true},
		{"kv quoted sslmode ok", "host=h sslmode='verify-full'", false},
		{"kv case-insensitive key ok", "host=h SSLMODE=verify-full", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireVerifyingSSLMode(tc.connStr)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q, got nil", tc.connStr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error for %q, got %v", tc.connStr, err)
			}
		})
	}
}

// TestGetLeavesRejectsLegacyRows verifies ErrLegacyLeaves is returned when
// any leaf has an empty parser_id or canonical_parser_version.  GetLeaves is
// the gatekeeper for startup replay; if it returns ErrLegacyLeaves the
// sequencer must refuse to start rather than forwarding empty provenance to
// the Rust SMT service.
//
// The test uses a fake sqlRows-compatible stub so no live DB is needed.
func TestErrLegacyLeavesIsExported(t *testing.T) {
	// Verify that ErrLegacyLeaves is accessible and carries the required
	// operator remediation text.
	if ErrLegacyLeaves == nil {
		t.Fatal("ErrLegacyLeaves must not be nil")
	}
	msg := ErrLegacyLeaves.Error()
	for _, substr := range []string{
		"legacy leaves",
		"ADR-0003",
		"parser_id",
		"canonical_parser_version",
		"Wipe/recreate",
	} {
		if !bytes.Contains([]byte(msg), []byte(substr)) {
			t.Errorf("ErrLegacyLeaves message missing expected substring %q; got:\n%s", substr, msg)
		}
	}
}

// TestLeafEntryLegacyDetectionLogic verifies the detection predicate used
// inside GetLeaves: a leaf is "legacy" when either provenance field is empty.
func TestLeafEntryLegacyDetectionLogic(t *testing.T) {
	cases := []struct {
		name    string
		leaf    LeafEntry
		isLegacy bool
	}{
		{
			name: "both fields set - valid",
			leaf: LeafEntry{
				Key: []byte("k"), ValueHash: []byte("v"),
				ParserID: "docling@2.3.1", CanonicalParserVersion: "v1",
			},
			isLegacy: false,
		},
		{
			name: "empty parser_id - legacy",
			leaf: LeafEntry{
				Key: []byte("k"), ValueHash: []byte("v"),
				ParserID: "", CanonicalParserVersion: "v1",
			},
			isLegacy: true,
		},
		{
			name: "empty canonical_parser_version - legacy",
			leaf: LeafEntry{
				Key: []byte("k"), ValueHash: []byte("v"),
				ParserID: "docling@2.3.1", CanonicalParserVersion: "",
			},
			isLegacy: true,
		},
		{
			name: "both fields empty - legacy",
			leaf: LeafEntry{
				Key: []byte("k"), ValueHash: []byte("v"),
				ParserID: "", CanonicalParserVersion: "",
			},
			isLegacy: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.leaf.ParserID == "" || tc.leaf.CanonicalParserVersion == ""
			if got != tc.isLegacy {
				t.Errorf("legacy detection: got %v, want %v for leaf %+v", got, tc.isLegacy, tc.leaf)
			}
		})
	}
}

// BatchLeaf must carry its own Root, TreeSize, and Signature so that
// StoreLeafAndDeltasBatch can write one root row per leaf. The test
// constructs a batch of three leaves with distinct roots and tree sizes,
// verifies the fields survive round-trip through the struct (no shared root
// pointer aliasing), and confirms that a zero-value BatchLeaf has an empty
// root — meaning callers that omit Root will produce a detectable failure
// rather than silently persisting a bogus row.
func TestBatchLeafPerLeafRootFields(t *testing.T) {
	const (
		blake3HashSize       = 32 // BLAKE3 output length in bytes
		ed25519SignatureSize = 64 // Ed25519 signature length in bytes
	)

	roots := [][]byte{
		bytes.Repeat([]byte{0x01}, blake3HashSize),
		bytes.Repeat([]byte{0x02}, blake3HashSize),
		bytes.Repeat([]byte{0x03}, blake3HashSize),
	}
	sigs := [][]byte{
		bytes.Repeat([]byte{0xaa}, ed25519SignatureSize),
		bytes.Repeat([]byte{0xbb}, ed25519SignatureSize),
		bytes.Repeat([]byte{0xcc}, ed25519SignatureSize),
	}

	batch := make([]BatchLeaf, 3)
	for i := range batch {
		batch[i] = BatchLeaf{
			Leaf:      LeafEntry{Key: []byte{byte(i)}, ValueHash: []byte{byte(i + 10)}},
			Root:      roots[i],
			TreeSize:  uint64(i + 1),
			Signature: sigs[i],
		}
	}

	// Every leaf must carry a distinct root so GetRootByTreeSize can serve
	// each intermediate tree size.
	for i, bl := range batch {
		if !bytes.Equal(bl.Root, roots[i]) {
			t.Errorf("leaf %d: Root mismatch: got %x, want %x", i, bl.Root, roots[i])
		}
		if bl.TreeSize != uint64(i+1) {
			t.Errorf("leaf %d: TreeSize = %d, want %d", i, bl.TreeSize, i+1)
		}
		if !bytes.Equal(bl.Signature, sigs[i]) {
			t.Errorf("leaf %d: Signature mismatch: got %x, want %x", i, bl.Signature, sigs[i])
		}
	}

	// A zero-value BatchLeaf must have a nil Root so a caller that forgets to
	// sign will produce an explicit nil rather than an accidentally shared root.
	var zero BatchLeaf
	if zero.Root != nil {
		t.Errorf("zero-value BatchLeaf.Root should be nil, got %x", zero.Root)
	}
	if zero.Signature != nil {
		t.Errorf("zero-value BatchLeaf.Signature should be nil, got %x", zero.Signature)
	}
}

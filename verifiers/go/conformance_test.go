package verifier

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// vectorFile returns the path to vectors.json relative to this file.
func vectorFile(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	return filepath.Join(dir, "..", "test_vectors", "vectors.json")
}

func canonicalizerVectorFile(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	return filepath.Join(dir, "..", "test_vectors", "canonicalizer_vectors.tsv")
}

// --- JSON structures for parsing vectors.json ---

type Vectors struct {
	Blake3Raw           []Blake3RawVec           `json:"blake3_raw"`
	MerkleLeafHash      []LeafHashVec            `json:"merkle_leaf_hash"`
	MerkleParentHash    []ParentHashVec          `json:"merkle_parent_hash"`
	MerkleRoot          []MerkleRootVec          `json:"merkle_root"`
	MerkleProof         []MerkleProofVec         `json:"merkle_proof"`
	LedgerEntryHash     []LedgerEntryHashVec     `json:"ledger_entry_hash"`
	DualRootCommitment  []DualRootCommitmentVec  `json:"dual_root_commitment"`
}

type Blake3RawVec struct {
	Description string `json:"description"`
	InputUTF8   string `json:"input_utf8"`
	Hash        string `json:"hash"`
}

type LeafHashVec struct {
	Description string `json:"description"`
	InputUTF8   string `json:"input_utf8"`
	Hash        string `json:"hash"`
}

type ParentHashVec struct {
	Description string `json:"description"`
	LeftHash    string `json:"left_hash"`
	RightHash   string `json:"right_hash"`
	ParentHash  string `json:"parent_hash"`
}

type MerkleRootVec struct {
	Description string   `json:"description"`
	LeavesUTF8  []string `json:"leaves_utf8"`
	Root        string   `json:"root"`
}

type SiblingVec struct {
	Hash     string `json:"hash"`
	Position string `json:"position"`
}

type MerkleProofVec struct {
	Description   string       `json:"description"`
	LeafHash      string       `json:"leaf_hash"`
	LeafIndex     int          `json:"leaf_index"`
	Siblings      []SiblingVec `json:"siblings"`
	RootHash      string       `json:"root_hash"`
	ExpectedValid bool         `json:"expected_valid"`
}

type LedgerEntryHashVec struct {
	Description        string `json:"description"`
	CanonicalPayloadHex string `json:"canonical_payload_hex"`
	EntryHash          string `json:"entry_hash"`
}

// Blake3ProofVec mirrors the blake3_proof sub-object in dual_root_commitment vectors.
type Blake3ProofVec struct {
	LeafHash  string       `json:"leaf_hash"`
	LeafIndex int          `json:"leaf_index"`
	Siblings  []SiblingVec `json:"siblings"`
	RootHash  string       `json:"root_hash"`
}

// DualRootCommitmentVec represents one dual-root commitment conformance test case.
//
// Fields:
//   - DocumentPartsUTF8: ordered list of UTF-8 document sections used to build both trees.
//   - Blake3Root: BLAKE3 Merkle root (hex) of the leaf-hashed document parts.
//   - PoseidonRoot: Poseidon Merkle root (decimal BN128 field element string).
//   - DualCommitment: BLAKE3(OLY:LEDGER:V1 | "|" | blake3_root_bytes | "|" | poseidon_root_32be).
//   - Blake3Proof: optional BLAKE3 Merkle inclusion proof for a specific leaf.
//   - ExpectedValid: true iff both roots are consistent with the same document parts.
//   - ExpectedBlake3Consistent: true iff the stored blake3_root matches what is recomputed
//     from document_parts_utf8.  Go/Rust/JS verifiers use this field; Python checks the full
//     ExpectedValid (which also covers Poseidon consistency).
type DualRootCommitmentVec struct {
	Description              string          `json:"description"`
	DocumentPartsUTF8        []string        `json:"document_parts_utf8"`
	Blake3Root               string          `json:"blake3_root"`
	PoseidonRoot             string          `json:"poseidon_root"`
	DualCommitment           string          `json:"dual_commitment"`
	Blake3Proof              *Blake3ProofVec `json:"blake3_proof"`
	ExpectedValid            bool            `json:"expected_valid"`
	ExpectedBlake3Consistent bool            `json:"expected_blake3_consistent"`
}

type CanonicalizerHashVec struct {
	GroupID        string
	InputRaw       []byte
	CanonicalBytes []byte
	Hash           string
}

func loadVectors(t *testing.T) Vectors {
	t.Helper()
	data, err := os.ReadFile(vectorFile(t))
	if err != nil {
		t.Fatalf("Failed to read vectors.json: %v", err)
	}
	var v Vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("Failed to parse vectors.json: %v", err)
	}
	return v
}

func loadCanonicalizerVectors(t *testing.T) []CanonicalizerHashVec {
	t.Helper()
	data, err := os.ReadFile(canonicalizerVectorFile(t))
	if err != nil {
		t.Fatalf("Failed to read canonicalizer_vectors.tsv: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	rows := make([]CanonicalizerHashVec, 0, len(lines))
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			t.Fatalf("Malformed canonicalizer vector line: %q", line)
		}
		inputRaw, err := hex.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("Failed to decode input hex: %v", err)
		}
		canonicalBytes, err := hex.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("Failed to decode canonical hex: %v", err)
		}
		rows = append(rows, CanonicalizerHashVec{
			GroupID:        parts[0],
			InputRaw:       inputRaw,
			CanonicalBytes: canonicalBytes,
			Hash:           parts[3],
		})
	}
	return rows
}

func TestConformanceBlake3Raw(t *testing.T) {
	vectors := loadVectors(t)
	for _, vec := range vectors.Blake3Raw {
		t.Run(vec.Description, func(t *testing.T) {
			data := []byte(vec.InputUTF8)
			got := hex.EncodeToString(ComputeBlake3(data))
			if got != vec.Hash {
				t.Errorf("blake3_raw(%q):\n  got  %s\n  want %s", vec.InputUTF8, got, vec.Hash)
			}
		})
	}
}

func TestConformanceMerkleLeafHash(t *testing.T) {
	vectors := loadVectors(t)
	for _, vec := range vectors.MerkleLeafHash {
		t.Run(vec.Description, func(t *testing.T) {
			data := []byte(vec.InputUTF8)
			got := hex.EncodeToString(MerkleLeafHash(data))
			if got != vec.Hash {
				t.Errorf("merkle_leaf_hash(%q):\n  got  %s\n  want %s", vec.InputUTF8, got, vec.Hash)
			}
		})
	}
}

func TestConformanceMerkleParentHash(t *testing.T) {
	vectors := loadVectors(t)
	for _, vec := range vectors.MerkleParentHash {
		t.Run(vec.Description, func(t *testing.T) {
			left, err := hex.DecodeString(vec.LeftHash)
			if err != nil {
				t.Fatalf("bad left_hash: %v", err)
			}
			right, err := hex.DecodeString(vec.RightHash)
			if err != nil {
				t.Fatalf("bad right_hash: %v", err)
			}
			got := hex.EncodeToString(MerkleParentHash(left, right))
			if got != vec.ParentHash {
				t.Errorf("merkle_parent_hash:\n  got  %s\n  want %s", got, vec.ParentHash)
			}
		})
	}
}

func TestConformanceMerkleRoot(t *testing.T) {
	vectors := loadVectors(t)
	for _, vec := range vectors.MerkleRoot {
		t.Run(vec.Description, func(t *testing.T) {
			leaves := make([][]byte, len(vec.LeavesUTF8))
			for i, s := range vec.LeavesUTF8 {
				leaves[i] = []byte(s)
			}
			got, err := ComputeMerkleRoot(leaves)
			if err != nil {
				t.Fatalf("ComputeMerkleRoot error: %v", err)
			}
			if got != vec.Root {
				t.Errorf("merkle_root(%v):\n  got  %s\n  want %s", vec.LeavesUTF8, got, vec.Root)
			}
		})
	}
}

func TestConformanceMerkleProof(t *testing.T) {
	vectors := loadVectors(t)
	for _, vec := range vectors.MerkleProof {
		t.Run(vec.Description, func(t *testing.T) {
			leafHashBytes, err := hex.DecodeString(vec.LeafHash)
			if err != nil {
				t.Fatalf("bad leaf_hash: %v", err)
			}
			siblings := make([]MerkleSibling, len(vec.Siblings))
			for i, s := range vec.Siblings {
				siblings[i] = MerkleSibling{Hash: s.Hash, Position: s.Position}
			}
			proof := &MerkleProof{
				LeafHash: leafHashBytes,
				Siblings: siblings,
				RootHash: vec.RootHash,
			}
			got, err := VerifyMerkleProof(proof)
			if err != nil {
				t.Fatalf("VerifyMerkleProof error: %v", err)
			}
			if got != vec.ExpectedValid {
				t.Errorf("merkle_proof verify: got %v, want %v", got, vec.ExpectedValid)
			}
		})
	}
}

func TestConformanceCanonicalizerHash(t *testing.T) {
	vectors := loadCanonicalizerVectors(t)
	if len(vectors) < 500 {
		t.Fatalf("expected at least 500 canonicalizer vectors, got %d", len(vectors))
	}
	for _, vec := range vectors {
		t.Run(vec.GroupID, func(t *testing.T) {
			got := hex.EncodeToString(ComputeBlake3(vec.CanonicalBytes))
			if got != vec.Hash {
				t.Errorf("canonicalizer_hash(%s):\n  got  %s\n  want %s", vec.GroupID, got, vec.Hash)
			}
		})
	}
}

func TestConformanceLedgerEntryHash(t *testing.T) {
	vectors := loadVectors(t)
	for _, vec := range vectors.LedgerEntryHash {
		t.Run(vec.Description, func(t *testing.T) {
			payloadBytes, err := hex.DecodeString(vec.CanonicalPayloadHex)
			if err != nil {
				t.Fatalf("failed to decode canonical_payload_hex: %v", err)
			}
			got := hex.EncodeToString(ComputeLedgerEntryHash(payloadBytes))
			if got != vec.EntryHash {
				t.Errorf("ledger_entry_hash:\n  got  %s\n  want %s", got, vec.EntryHash)
			}
		})
	}
}

// TestConformanceDualRootCommitment validates the dual-root commitment formula and
// BLAKE3 root consistency against the test vectors in vectors.json.
//
// For each vector this test:
//  1. Recomputes the BLAKE3 Merkle root from document_parts_utf8 and checks it
//     matches blake3_root iff expected_blake3_consistent is true.
//  2. Recomputes the dual_commitment from the stored blake3_root + poseidon_root
//     and verifies it matches the committed dual_commitment value.
//  3. If a blake3_proof is present, verifies it is valid against the stored root.
//
// Note: Poseidon root consistency (expected_valid) is only checked by the Python
// conformance test, which has access to the full Poseidon hash implementation.
func TestConformanceDualRootCommitment(t *testing.T) {
	vectors := loadVectors(t)
	for _, vec := range vectors.DualRootCommitment {
		vec := vec // capture range variable
		t.Run(vec.Description, func(t *testing.T) {
			// 1. Recompute BLAKE3 root from document parts
			parts := make([][]byte, len(vec.DocumentPartsUTF8))
			for i, s := range vec.DocumentPartsUTF8 {
				parts[i] = []byte(s)
			}
			computedRoot, err := ComputeMerkleRoot(parts)
			if err != nil {
				t.Fatalf("ComputeMerkleRoot error: %v", err)
			}
			blake3Consistent := computedRoot == vec.Blake3Root
			if blake3Consistent != vec.ExpectedBlake3Consistent {
				t.Errorf(
					"expected_blake3_consistent=%v but computed root match=%v\n  computed: %s\n  vector:   %s",
					vec.ExpectedBlake3Consistent, blake3Consistent, computedRoot, vec.Blake3Root,
				)
			}

			// 2. Verify dual_commitment formula using the stored blake3_root + poseidon_root
			gotDual, err := ComputeDualCommitment(vec.Blake3Root, vec.PoseidonRoot)
			if err != nil {
				t.Fatalf("ComputeDualCommitment error: %v", err)
			}
			if gotDual != vec.DualCommitment {
				t.Errorf(
					"dual_commitment mismatch:\n  got  %s\n  want %s",
					gotDual, vec.DualCommitment,
				)
			}

			// 3. Verify blake3_proof when present
			if vec.Blake3Proof != nil {
				leafHashBytes, err := hex.DecodeString(vec.Blake3Proof.LeafHash)
				if err != nil {
					t.Fatalf("bad blake3_proof leaf_hash: %v", err)
				}
				siblings := make([]MerkleSibling, len(vec.Blake3Proof.Siblings))
				for i, s := range vec.Blake3Proof.Siblings {
					siblings[i] = MerkleSibling{Hash: s.Hash, Position: s.Position}
				}
				proof := &MerkleProof{
					LeafHash: leafHashBytes,
					Siblings: siblings,
					RootHash: vec.Blake3Proof.RootHash,
				}
				valid, err := VerifyMerkleProof(proof)
				if err != nil {
					t.Fatalf("VerifyMerkleProof error: %v", err)
				}
				if !valid {
					t.Errorf("blake3_proof verification failed for %q", vec.Description)
				}
			}
		})
	}
}

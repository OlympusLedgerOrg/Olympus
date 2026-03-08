package verifier

import (
	"encoding/hex"
	"testing"
)

func TestBlake3Verification(t *testing.T) {
	data := []byte("Hello, Olympus!")
	hash := ComputeBlake3(data)
	hexHash := hex.EncodeToString(hash)

	if !VerifyBlake3Hash(data, hexHash) {
		t.Error("BLAKE3 hash should verify")
	}

	if VerifyBlake3Hash(data, "invalid") {
		t.Error("Invalid hash should not verify")
	}
}

func TestMerkleRootComputation(t *testing.T) {
	leaves := [][]byte{
		[]byte("leaf1"),
		[]byte("leaf2"),
	}

	root, err := ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatalf("Failed to compute Merkle root: %v", err)
	}

	if len(root) != 64 {
		t.Errorf("Root should be 32 bytes (64 hex chars), got %d", len(root))
	}

	// Computing same root twice should give same result
	root2, err := ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatalf("Failed to compute Merkle root: %v", err)
	}

	if root != root2 {
		t.Error("Merkle root should be deterministic")
	}
}

func TestMerkleProofVerification(t *testing.T) {
	leaves := [][]byte{
		[]byte("alpha"),
		[]byte("beta"),
	}

	root, err := ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatalf("Failed to compute Merkle root: %v", err)
	}

	// Create a simple proof for the first leaf
	leafHash := MerkleLeafHash(leaves[0])
	leaf1Hash := MerkleLeafHash(leaves[1])

	proof := &MerkleProof{
		LeafHash: leafHash,
		Siblings: []MerkleSibling{
			{Hash: hex.EncodeToString(leaf1Hash), Position: "right"},
		},
		RootHash: root,
	}

	valid, err := VerifyMerkleProof(proof)
	if err != nil {
		t.Fatalf("Failed to verify proof: %v", err)
	}

	if !valid {
		t.Error("Proof should verify")
	}
}

func TestEmptyTree(t *testing.T) {
	leaves := [][]byte{}
	_, err := ComputeMerkleRoot(leaves)
	if err == nil {
		t.Error("Should error on empty tree")
	}
}

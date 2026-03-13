// Package verifier provides Olympus commitment verification for Go
package verifier

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/zeebo/blake3"
)

// Constants for domain separation - must match protocol/hashes.py
const (
	LeafPrefix    = "OLY:LEAF:V1"
	NodePrefix    = "OLY:NODE:V1"
	LedgerPrefix  = "OLY:LEDGER:V1"
	HashSeparator = "|"
)

// ComputeBlake3 computes the BLAKE3 hash of data
func ComputeBlake3(data []byte) []byte {
	hash := blake3.Sum256(data)
	return hash[:]
}

// VerifyBlake3Hash verifies a BLAKE3 hash
func VerifyBlake3Hash(data []byte, expectedHash string) bool {
	actualHash := ComputeBlake3(data)
	actualHex := hex.EncodeToString(actualHash)
	return actualHex == strings.ToLower(expectedHash)
}

// MerkleLeafHash computes the domain-separated hash of a leaf
func MerkleLeafHash(leafData []byte) []byte {
	// LEAF_PREFIX || HASH_SEPARATOR || leafData
	var buf bytes.Buffer
	buf.WriteString(LeafPrefix)
	buf.WriteString(HashSeparator)
	buf.Write(leafData)
	return ComputeBlake3(buf.Bytes())
}

// MerkleParentHash computes the hash of a parent node
func MerkleParentHash(leftHash, rightHash []byte) []byte {
	// NODE_PREFIX || HASH_SEPARATOR || left || HASH_SEPARATOR || right
	var buf bytes.Buffer
	buf.WriteString(NodePrefix)
	buf.WriteString(HashSeparator)
	buf.Write(leftHash)
	buf.WriteString(HashSeparator)
	buf.Write(rightHash)
	return ComputeBlake3(buf.Bytes())
}

// ComputeMerkleRoot computes the Merkle root from leaves
func ComputeMerkleRoot(leaves [][]byte) (string, error) {
	if len(leaves) == 0 {
		return "", errors.New("cannot compute Merkle root of empty tree")
	}

	// Hash all leaves with domain separation
	level := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		level[i] = MerkleLeafHash(leaf)
	}

	// Build tree bottom-up using CT-style promotion
	for len(level) > 1 {
		nextLevel := make([][]byte, 0, (len(level)+1)/2)

		for i := 0; i < len(level); i += 2 {
			left := level[i]
			if i+1 < len(level) {
				// Pair exists: hash left and right
				right := level[i+1]
				parent := MerkleParentHash(left, right)
				nextLevel = append(nextLevel, parent)
			} else {
				// CT-style promotion: lone node is promoted without hashing
				nextLevel = append(nextLevel, left)
			}
		}

		level = nextLevel
	}

	return hex.EncodeToString(level[0]), nil
}

// MerkleSibling represents a sibling in a Merkle proof
type MerkleSibling struct {
	Hash     string // Hex-encoded hash
	Position string // "left" or "right"
}

// MerkleProof represents a Merkle inclusion proof
type MerkleProof struct {
	LeafHash []byte
	Siblings []MerkleSibling
	RootHash string
}

// VerifyMerkleProof verifies a Merkle inclusion proof
func VerifyMerkleProof(proof *MerkleProof) (bool, error) {
	currentHash := proof.LeafHash

	for _, sibling := range proof.Siblings {
		siblingBytes, err := hex.DecodeString(sibling.Hash)
		if err != nil {
			return false, err
		}

		switch sibling.Position {
		case "left":
			currentHash = MerkleParentHash(siblingBytes, currentHash)
		case "right":
			currentHash = MerkleParentHash(currentHash, siblingBytes)
		default:
			return false, errors.New("invalid sibling position: " + sibling.Position)
		}
	}

	actualRoot := hex.EncodeToString(currentHash)
	return actualRoot == proof.RootHash, nil
}

// ComputeLedgerEntryHash computes the entry hash from pre-canonicalized payload bytes.
// Formula: BLAKE3(OLY:LEDGER:V1 || canonical_json_bytes(payload))
// The canonical_json_bytes must be produced by the Olympus canonical JSON encoder
// (JCS / RFC 8785 with BLAKE3-specific numeric rules — see protocol/canonical_json.py).
func ComputeLedgerEntryHash(canonicalPayloadBytes []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(LedgerPrefix)
	buf.Write(canonicalPayloadBytes)
	return ComputeBlake3(buf.Bytes())
}

// ComputeDualCommitment computes the dual-root commitment hash from BLAKE3 and Poseidon roots.
//
// Formula:
//
//	BLAKE3(OLY:LEDGER:V1 | "|" | blake3RootBytes | "|" | poseidonRoot32BEBytes)
//
// where poseidonRoot32BEBytes is the 32-byte big-endian encoding of the BN128 field
// element expressed as a decimal string.
//
// This matches the Python reference:
//
//	blake3_hash([LEDGER_PREFIX, SEP, blake3_root_bytes, SEP, poseidon_root_32be])
func ComputeDualCommitment(blake3RootHex string, poseidonRootDecimal string) (string, error) {
	blake3RootBytes, err := hex.DecodeString(blake3RootHex)
	if err != nil {
		return "", fmt.Errorf("invalid blake3_root hex: %w", err)
	}

	poseidonInt, ok := new(big.Int).SetString(poseidonRootDecimal, 10)
	if !ok {
		return "", fmt.Errorf("invalid poseidon_root decimal: %s", poseidonRootDecimal)
	}

	// Encode as 32-byte big-endian
	poseidonBytes := make([]byte, 32)
	poseidonBigEndian := poseidonInt.Bytes()
	if len(poseidonBigEndian) > 32 {
		return "", fmt.Errorf("poseidon_root exceeds 32 bytes")
	}
	copy(poseidonBytes[32-len(poseidonBigEndian):], poseidonBigEndian)

	var buf bytes.Buffer
	buf.WriteString(LedgerPrefix)
	buf.WriteString(HashSeparator)
	buf.Write(blake3RootBytes)
	buf.WriteString(HashSeparator)
	buf.Write(poseidonBytes)
	return hex.EncodeToString(ComputeBlake3(buf.Bytes())), nil
}

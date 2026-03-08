// Package verifier provides Olympus commitment verification for Go
package verifier

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/zeebo/blake3"
)

// Constants for domain separation
const (
	LeafPrefix = "LEAF"
	NodePrefix = "NODE"
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
	return actualHex == expectedHash
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

	// Build tree bottom-up
	for len(level) > 1 {
		nextLevel := make([][]byte, 0, (len(level)+1)/2)

		for i := 0; i < len(level); i += 2 {
			left := level[i]
			var right []byte
			if i+1 < len(level) {
				right = level[i+1]
			} else {
				right = level[i] // Duplicate last leaf if odd
			}
			parent := MerkleParentHash(left, right)
			nextLevel = append(nextLevel, parent)
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

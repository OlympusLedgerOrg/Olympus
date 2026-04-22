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

// ComputeDualCommitment computes the dual-root commitment binding hash (V2)
// from BLAKE3 and Poseidon roots.
//
// Formula:
//
//	BLAKE3(OLY:LEDGER:V1 | "|" | lenB3 | blake3RootBytes
//	                     | "|" | lenPos | poseidonRoot32BEBytes)
//
// where lenB3 and lenPos are 2-byte big-endian length prefixes (always
// 0x0020 = 32), and poseidonRoot32BEBytes is the 32-byte big-endian encoding
// of the BN128 field element expressed as a decimal string.
//
// This matches the Python reference (V2, PR 4: M-15 + M-14):
//
//	blake3_hash([LEDGER_PREFIX, SEP, lenB3, blake3_root_bytes,
//	             SEP, lenPos, poseidon_root_32be])
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

	lenB3 := []byte{byte(len(blake3RootBytes) >> 8), byte(len(blake3RootBytes) & 0xff)}
	lenPos := []byte{byte(len(poseidonBytes) >> 8), byte(len(poseidonBytes) & 0xff)}

	var buf bytes.Buffer
	buf.WriteString(LedgerPrefix)
	buf.WriteString(HashSeparator)
	buf.Write(lenB3)
	buf.Write(blake3RootBytes)
	buf.WriteString(HashSeparator)
	buf.Write(lenPos)
	buf.Write(poseidonBytes)
	return hex.EncodeToString(ComputeBlake3(buf.Bytes())), nil
}

// ---------------------------------------------------------------------------
// Sparse Merkle Tree (SSMF) cross-language verifier — ADR-0003
//
// Mirrors protocol/ssmf.py::verify_proof and verify_nonexistence_proof.
// Wire format: siblings are leaf-to-root (Siblings[0] = leaf-adjacent,
// Siblings[255] = root-adjacent). DO NOT model this on
// services/cdhs-smf-rust/src/smt.rs — that service uses the opposite
// (root-to-leaf) convention internally; this module follows the wire format
// used by verifiers/test_vectors/vectors.json and the Python reference.
// ---------------------------------------------------------------------------

const EmptyLeafPrefix = "OLY:EMPTY-LEAF:V1"

// SmtEmptyLeaf is BLAKE3(b"OLY:EMPTY-LEAF:V1") — must match
// protocol/ssmf.py::EMPTY_LEAF. Hardcoded for clarity; recomputed by
// TestSMTEmptyLeafConstant to guard against drift.
var SmtEmptyLeaf = [32]byte{
	0x0c, 0x51, 0xa9, 0xc6, 0xfd, 0x8d, 0xd8, 0x84,
	0x7b, 0xa1, 0x05, 0x3a, 0x17, 0xf6, 0x29, 0x43,
	0xc5, 0x90, 0x52, 0xf4, 0xe3, 0x11, 0xab, 0x4e,
	0x93, 0x86, 0x7c, 0x42, 0x80, 0x57, 0x9f, 0x29,
}

// SmtSibling is a 32-byte sibling hash in an SMT proof.
type SmtSibling = [32]byte

// SmtInclusionProof represents an SMT inclusion proof.
// Siblings are ordered leaf-to-root: Siblings[0] is leaf-adjacent,
// Siblings[255] is root-adjacent. Length must be exactly 256.
type SmtInclusionProof struct {
	Key                    [32]byte
	ValueHash              [32]byte
	ParserID               string
	CanonicalParserVersion string
	Siblings               []SmtSibling
	RootHash               [32]byte
}

// SmtNonInclusionProof represents an SMT non-inclusion proof.
// Siblings are ordered leaf-to-root. Length must be exactly 256.
type SmtNonInclusionProof struct {
	Key      [32]byte
	Siblings []SmtSibling
	RootHash [32]byte
}

// SmtLeafHash computes the SMT leaf hash with parser-identity binding (ADR-0003).
// Layout matches protocol/hashes.py::leaf_hash:
//
// BLAKE3(LEAF_PREFIX || SEP || key || SEP || value_hash || SEP ||
//
//	len(parser_id)[4B BE] || parser_id || SEP ||
//	len(canonical_parser_version)[4B BE] || canonical_parser_version)
func SmtLeafHash(key, valueHash [32]byte, parserID, canonicalParserVersion string) [32]byte {
	pid := []byte(parserID)
	cpv := []byte(canonicalParserVersion)
	pidLen := []byte{
		byte(len(pid) >> 24), byte(len(pid) >> 16), byte(len(pid) >> 8), byte(len(pid)),
	}
	cpvLen := []byte{
		byte(len(cpv) >> 24), byte(len(cpv) >> 16), byte(len(cpv) >> 8), byte(len(cpv)),
	}
	var buf bytes.Buffer
	buf.WriteString(LeafPrefix)
	buf.WriteString(HashSeparator)
	buf.Write(key[:])
	buf.WriteString(HashSeparator)
	buf.Write(valueHash[:])
	buf.WriteString(HashSeparator)
	buf.Write(pidLen)
	buf.Write(pid)
	buf.WriteString(HashSeparator)
	buf.Write(cpvLen)
	buf.Write(cpv)
	var out [32]byte
	copy(out[:], ComputeBlake3(buf.Bytes()))
	return out
}

// keyToPathBits converts a 32-byte key to a 256-bit MSB-first path.
// path[0] is the MSB of key[0]; path[255] is the LSB of key[31].
func keyToPathBits(key [32]byte) [256]byte {
	var path [256]byte
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		b := key[byteIdx]
		for bitInByte := 0; bitInByte < 8; bitInByte++ {
			path[byteIdx*8+bitInByte] = (b >> (7 - bitInByte)) & 1
		}
	}
	return path
}

// smtWalkAndCheck walks siblings (leaf-to-root) from start and reports
// whether the computed root matches root.
func smtWalkAndCheck(pathBits [256]byte, siblings []SmtSibling, start [32]byte, root [32]byte) bool {
	current := start
	for i := 0; i < 256; i++ {
		bit := pathBits[255-i]
		sib := siblings[i]
		if bit == 0 {
			var out [32]byte
			copy(out[:], MerkleParentHash(current[:], sib[:]))
			current = out
		} else {
			var out [32]byte
			copy(out[:], MerkleParentHash(sib[:], current[:]))
			current = out
		}
	}
	return current == root
}

// VerifySMTInclusion verifies an SMT inclusion proof.
// Returns false for any input-validation failure (matches the Python
// reference: never panics, never returns an error).
func VerifySMTInclusion(proof *SmtInclusionProof) bool {
	if proof == nil {
		return false
	}
	if len(proof.Siblings) != 256 {
		return false
	}
	if proof.ParserID == "" || proof.CanonicalParserVersion == "" {
		return false
	}
	pathBits := keyToPathBits(proof.Key)
	leaf := SmtLeafHash(proof.Key, proof.ValueHash, proof.ParserID, proof.CanonicalParserVersion)
	return smtWalkAndCheck(pathBits, proof.Siblings, leaf, proof.RootHash)
}

// VerifySMTNonInclusion verifies an SMT non-inclusion proof.
// Returns false for any input-validation failure.
func VerifySMTNonInclusion(proof *SmtNonInclusionProof) bool {
	if proof == nil {
		return false
	}
	if len(proof.Siblings) != 256 {
		return false
	}
	pathBits := keyToPathBits(proof.Key)
	return smtWalkAndCheck(pathBits, proof.Siblings, SmtEmptyLeaf, proof.RootHash)
}

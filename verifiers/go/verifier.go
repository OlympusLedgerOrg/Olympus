// Package verifier provides Olympus commitment verification for Go
package verifier

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/zeebo/blake3"
)

// Constants for domain separation - must match protocol/hashes.py
const (
	LeafPrefix       = "OLY:LEAF:V1"
	NodePrefix       = "OLY:NODE:V1"
	LedgerPrefix     = "OLY:LEDGER:V1"
	HashSeparator    = "|"
	emptyLeafPreimage = "OLY:EMPTY-LEAF:V1"
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
// Sparse Merkle Forest (SSMF / CD-HS-ST) verifier
// ---------------------------------------------------------------------------
//
// These functions verify existence and non-existence proofs produced by the
// 256-height sparse Merkle tree in protocol/ssmf.py. The leaf and node
// hashing rules below MUST stay byte-identical to:
//
//   - protocol.hashes.leaf_hash(key, value_hash, parser_id, canonical_parser_version)
//   - protocol.hashes.node_hash(left, right)
//   - protocol.ssmf.EMPTY_LEAF
//
// Sibling convention: ``siblings[0]`` is the leaf-end (level 0, paired with
// the leaf hash) and ``siblings[255]`` is the root-end. For level L the
// path bit consulted is ``key[bit_pos = 255 - L]`` (MSB-first). See
// protocol.ssmf.verify_proof / verify_nonexistence_proof.

// SSMFEmptyLeaf returns the domain-separated empty-leaf sentinel used by
// the sparse Merkle tree, BLAKE3(b"OLY:EMPTY-LEAF:V1").
func SSMFEmptyLeaf() []byte {
	h := blake3.Sum256([]byte(emptyLeafPreimage))
	return h[:]
}

// SSMFLeafHash computes the SMT leaf hash with parser-identity binding
// (ADR-0003). Layout matches protocol.hashes.leaf_hash:
//
//	BLAKE3(LEAF_PREFIX | "|" | key | "|" | value_hash | "|" |
//	       len(parser_id)[4B BE] | parser_id | "|" |
//	       len(canonical_parser_version)[4B BE] | canonical_parser_version)
//
// ``key`` and ``valueHash`` must be 32 bytes; ``parserID`` and
// ``canonicalParserVersion`` must be non-empty (returns nil and false).
func SSMFLeafHash(key, valueHash []byte, parserID, canonicalParserVersion string) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("ssmf: key must be 32 bytes, got %d", len(key))
	}
	if len(valueHash) != 32 {
		return nil, fmt.Errorf("ssmf: value_hash must be 32 bytes, got %d", len(valueHash))
	}
	if parserID == "" {
		return nil, errors.New("ssmf: parser_id must be a non-empty string")
	}
	if canonicalParserVersion == "" {
		return nil, errors.New("ssmf: canonical_parser_version must be a non-empty string")
	}

	pid := []byte(parserID)
	cpv := []byte(canonicalParserVersion)

	var lenPID [4]byte
	binary.BigEndian.PutUint32(lenPID[:], uint32(len(pid)))
	var lenCPV [4]byte
	binary.BigEndian.PutUint32(lenCPV[:], uint32(len(cpv)))

	var buf bytes.Buffer
	buf.WriteString(LeafPrefix)
	buf.WriteString(HashSeparator)
	buf.Write(key)
	buf.WriteString(HashSeparator)
	buf.Write(valueHash)
	buf.WriteString(HashSeparator)
	buf.Write(lenPID[:])
	buf.Write(pid)
	buf.WriteString(HashSeparator)
	buf.Write(lenCPV[:])
	buf.Write(cpv)
	return ComputeBlake3(buf.Bytes()), nil
}

// keyToPathBitsMSB returns the 256 path bits of a 32-byte key, MSB-first.
// Mirrors protocol.ssmf._key_to_path_bits.
func keyToPathBitsMSB(key []byte) ([256]byte, error) {
	var bits [256]byte
	if len(key) != 32 {
		return bits, fmt.Errorf("ssmf: key must be 32 bytes, got %d", len(key))
	}
	for i, b := range key {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = (b >> (7 - j)) & 1
		}
	}
	return bits, nil
}

// ssmfWalkPath walks ``current`` from the leaf level up to the root using
// the standard SSMF convention (ascending level, bit_pos = 255 - level,
// siblings[0] = leaf-end). Returns the reconstructed root hash.
func ssmfWalkPath(current []byte, key []byte, siblings [][]byte) ([]byte, error) {
	if len(siblings) != 256 {
		return nil, fmt.Errorf("ssmf: siblings must be length 256, got %d", len(siblings))
	}
	bits, err := keyToPathBitsMSB(key)
	if err != nil {
		return nil, err
	}
	cur := current
	for level := 0; level < 256; level++ {
		bitPos := 255 - level
		sib := siblings[level]
		if len(sib) != 32 {
			return nil, fmt.Errorf("ssmf: sibling[%d] must be 32 bytes, got %d", level, len(sib))
		}
		if bits[bitPos] == 0 {
			cur = MerkleParentHash(cur, sib)
		} else {
			cur = MerkleParentHash(sib, cur)
		}
	}
	return cur, nil
}

// SSMFExistenceProof represents an existence proof produced by
// protocol.ssmf.SparseMerkleTree.prove_existence.
type SSMFExistenceProof struct {
	Key                    []byte // 32 bytes
	ValueHash              []byte // 32 bytes
	ParserID               string
	CanonicalParserVersion string
	Siblings               [][]byte // 256 × 32 bytes, leaf-end first
	RootHash               []byte   // 32 bytes
}

// SSMFNonExistenceProof represents a non-existence proof produced by
// protocol.ssmf.SparseMerkleTree.prove_nonexistence.
type SSMFNonExistenceProof struct {
	Key      []byte   // 32 bytes
	Siblings [][]byte // 256 × 32 bytes, leaf-end first
	RootHash []byte   // 32 bytes
}

// VerifySSMFExistenceProof reconstructs the root from leaf_hash(key,
// value_hash, parser_id, canonical_parser_version) and the 256 siblings,
// returning true iff the reconstructed root matches RootHash.
//
// Mirrors protocol.ssmf.verify_proof.
func VerifySSMFExistenceProof(p *SSMFExistenceProof) (bool, error) {
	if p == nil {
		return false, errors.New("ssmf: nil existence proof")
	}
	if len(p.RootHash) != 32 {
		return false, fmt.Errorf("ssmf: root_hash must be 32 bytes, got %d", len(p.RootHash))
	}
	leaf, err := SSMFLeafHash(p.Key, p.ValueHash, p.ParserID, p.CanonicalParserVersion)
	if err != nil {
		return false, err
	}
	got, err := ssmfWalkPath(leaf, p.Key, p.Siblings)
	if err != nil {
		return false, err
	}
	return bytes.Equal(got, p.RootHash), nil
}

// VerifySSMFNonExistenceProof reconstructs the root from EMPTY_LEAF and the
// 256 siblings, returning true iff the reconstructed root matches RootHash.
//
// Mirrors protocol.ssmf.verify_nonexistence_proof.
func VerifySSMFNonExistenceProof(p *SSMFNonExistenceProof) (bool, error) {
	if p == nil {
		return false, errors.New("ssmf: nil non-existence proof")
	}
	if len(p.RootHash) != 32 {
		return false, fmt.Errorf("ssmf: root_hash must be 32 bytes, got %d", len(p.RootHash))
	}
	got, err := ssmfWalkPath(SSMFEmptyLeaf(), p.Key, p.Siblings)
	if err != nil {
		return false, err
	}
	return bytes.Equal(got, p.RootHash), nil
}

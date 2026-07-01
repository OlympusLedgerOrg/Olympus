//! Olympus Verifier for Rust
//!
//! High-performance implementation for verifying Olympus commitments.
//!
//! TODO (ADR-0031): mirror `olympus_crypto::persist_message`
//! (`OLY:SNAPSHOT:PERSIST:V1`) here once the BJJ-signed `TransitionAttestation`
//! is carried on a verifiable wire artifact. PR2 persists it on the local
//! `own_checkpoints` row only; it is intentionally NOT yet on the
//! `PeerCheckpoint` gossip envelope, so there is nothing offline to verify until
//! that wire change lands (a `PEER_CHECKPOINT_WIRE_VERSION` bump).

use blake3;
use hex;

/// Pedersen commitments on Baby Jubjub — cross-language verifier leg (issue #992).
pub mod pedersen;

/// Independent Groth16 verifier — red-team C1 / court-evidence.md §2.
pub mod groth16;

/// ADR-0030 V3 signed-Merkle redaction bundle offline verifier (Phase 3).
pub mod redaction;

/// Constants for domain separation - must match protocol/hashes.py
const LEAF_PREFIX: &[u8] = b"OLY:LEAF:V1";
const NODE_PREFIX: &[u8] = b"OLY:NODE:V1";
const LEDGER_PREFIX: &[u8] = b"OLY:LEDGER:V1";
const HASH_SEPARATOR: &[u8] = b"|";

/// SMT empty-leaf sentinel (BLAKE3(b"OLY:EMPTY-LEAF:V1")) — must match
/// `protocol/ssmf.py::EMPTY_LEAF`. Hardcoded for clarity; recomputed by
/// `conformance_smt_empty_leaf` test to guard against drift.
pub const SMT_EMPTY_LEAF: [u8; 32] = [
    0x0c, 0x51, 0xa9, 0xc6, 0xfd, 0x8d, 0xd8, 0x84, 0x7b, 0xa1, 0x05, 0x3a, 0x17, 0xf6, 0x29, 0x43,
    0xc5, 0x90, 0x52, 0xf4, 0xe3, 0x11, 0xab, 0x4e, 0x93, 0x86, 0x7c, 0x42, 0x80, 0x57, 0x9f, 0x29,
];

/// Compute BLAKE3 hash of data
pub fn compute_blake3(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Verify a BLAKE3 hash
pub fn verify_blake3_hash(data: &[u8], expected_hash: &str) -> bool {
    let actual_hash = compute_blake3(data);
    let actual_hex = hex::encode(actual_hash);
    actual_hex == expected_hash.to_lowercase()
}

/// Compute the domain-separated hash of a Merkle leaf
pub fn merkle_leaf_hash(leaf_data: &[u8]) -> [u8; 32] {
    let mut combined =
        Vec::with_capacity(LEAF_PREFIX.len() + HASH_SEPARATOR.len() + leaf_data.len());
    combined.extend_from_slice(LEAF_PREFIX);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(leaf_data);
    compute_blake3(&combined)
}

/// Compute the hash of a Merkle parent node
pub fn merkle_parent_hash(left_hash: &[u8; 32], right_hash: &[u8; 32]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(
        NODE_PREFIX.len() + HASH_SEPARATOR.len() + 32 + HASH_SEPARATOR.len() + 32,
    );
    combined.extend_from_slice(NODE_PREFIX);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(left_hash);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(right_hash);
    compute_blake3(&combined)
}

/// Compute Merkle tree root from leaves
pub fn compute_merkle_root(leaves: &[Vec<u8>]) -> Result<String, &'static str> {
    if leaves.is_empty() {
        return Err("Cannot compute Merkle root of empty tree");
    }

    // Hash all leaves with domain separation
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| merkle_leaf_hash(leaf)).collect();

    // Build tree bottom-up using CT-style promotion
    while level.len() > 1 {
        let mut next_level = Vec::with_capacity((level.len() + 1) / 2);

        for i in (0..level.len()).step_by(2) {
            let left = &level[i];
            if i + 1 < level.len() {
                // Pair exists: hash left and right
                let right = &level[i + 1];
                next_level.push(merkle_parent_hash(left, right));
            } else {
                // CT-style promotion: lone node is promoted without hashing
                next_level.push(*left);
            }
        }

        level = next_level;
    }

    Ok(hex::encode(level[0]))
}

/// Merkle sibling in a proof
#[derive(Debug, Clone)]
pub struct MerkleSibling {
    pub hash: String,
    pub position: String,
}

/// Merkle inclusion proof
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf_hash: [u8; 32],
    pub siblings: Vec<MerkleSibling>,
    pub root_hash: String,
}

/// Verify a Merkle inclusion proof
pub fn verify_merkle_proof(proof: &MerkleProof) -> Result<bool, String> {
    let mut current_hash = proof.leaf_hash;

    for sibling in &proof.siblings {
        let sibling_bytes = hex::decode(&sibling.hash)
            .map_err(|e| format!("Failed to decode sibling hash: {}", e))?;

        if sibling_bytes.len() != 32 {
            return Err("Sibling hash must be 32 bytes".to_string());
        }

        let sibling_array: [u8; 32] = sibling_bytes.try_into().unwrap();

        current_hash = match sibling.position.as_str() {
            "left" => merkle_parent_hash(&sibling_array, &current_hash),
            "right" => merkle_parent_hash(&current_hash, &sibling_array),
            _ => return Err(format!("Invalid sibling position: {}", sibling.position)),
        };
    }

    let actual_root = hex::encode(current_hash);
    Ok(actual_root == proof.root_hash.to_lowercase())
}

/// Compute the ledger entry hash from pre-canonicalized payload bytes.
/// Formula: BLAKE3(OLY:LEDGER:V1 || canonical_json_bytes(payload))
/// The canonical_json_bytes must be produced by the Olympus canonical JSON encoder
/// (JCS / RFC 8785 with BLAKE3-specific numeric rules — see protocol/canonical_json.py).
pub fn compute_ledger_entry_hash(canonical_payload_bytes: &[u8]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(LEDGER_PREFIX.len() + canonical_payload_bytes.len());
    combined.extend_from_slice(LEDGER_PREFIX);
    combined.extend_from_slice(canonical_payload_bytes);
    compute_blake3(&combined)
}

/// Compute the dual-root commitment binding hash (V2).
///
/// Formula:
///   BLAKE3(OLY:LEDGER:V1 | "|" | len_b3 | blake3_root_bytes
///                        | "|" | len_pos | poseidon_root_32be_bytes)
///
/// where `len_b3` and `len_pos` are 2-byte big-endian length prefixes (always
/// `0x0020 = 32`), and `poseidon_root_32be` is the 32-byte big-endian
/// encoding of the BN128 field element.
///
/// This matches the Python reference (V2, PR 4: M-15 + M-14):
///   `blake3_hash([LEDGER_PREFIX, SEP, len_b3, blake3_root,
///                 SEP, len_pos, poseidon_root_32be])`
pub fn compute_dual_commitment(blake3_root: &[u8; 32], poseidon_root_32be: &[u8; 32]) -> [u8; 32] {
    let len_b3 = (blake3_root.len() as u16).to_be_bytes();
    let len_pos = (poseidon_root_32be.len() as u16).to_be_bytes();
    let mut combined = Vec::with_capacity(
        LEDGER_PREFIX.len()
            + HASH_SEPARATOR.len()
            + len_b3.len()
            + 32
            + HASH_SEPARATOR.len()
            + len_pos.len()
            + 32,
    );
    combined.extend_from_slice(LEDGER_PREFIX);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(&len_b3);
    combined.extend_from_slice(blake3_root);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(&len_pos);
    combined.extend_from_slice(poseidon_root_32be);
    compute_blake3(&combined)
}

// ---------------------------------------------------------------------------
// Sparse Merkle Tree (SSMF) cross-language verifier — ADR-0003 / ADR-0004
//
// Mirrors the canonical `olympus_crypto::smt` verify path
// (`verify_existence_proof` / `verify_nonexistence_proof`). Wire format:
// siblings are leaf-to-root (siblings[0] = leaf-adjacent, siblings[255] =
// root-adjacent), matching `verifiers/test_vectors/vectors.json`. (The Python
// `protocol/` reference this once mirrored was retired with the FastAPI
// server in v0.9.0; `olympus_crypto` is now the sole canonical source.)
// ---------------------------------------------------------------------------

/// Compute the SMT leaf hash. Mirrors the canonical `olympus_crypto::leaf_hash`:
/// an ADR-0005 structured binary prefix (marker / namespace / object-type /
/// version, then the length-prefixed shard) followed by a count-framed body
/// binding parser provenance (ADR-0003) and the model hash (ADR-0004).
///
/// ```text
/// BLAKE3(
///     0x01 || "OLY" || 0x01 || 0x01 ||   // structured prefix: marker, namespace, type=LEAF, version=V1
///     lp(shard_id) ||
///     0x05 ||                              // body field count
///     lp(key) || value_hash ||            // value_hash raw (fixed 32 bytes)
///     lp(parser_id) || lp(canonical_parser_version) || lp(model_hash)
/// )
/// ```
/// where `lp(x)` is a 4-byte big-endian length prefix followed by `x`.
fn smt_leaf_hash(
    shard_id: &str,
    key: &[u8; 32],
    value_hash: &[u8; 32],
    parser_id: &str,
    canonical_parser_version: &str,
    model_hash: &str,
) -> [u8; 32] {
    fn push_lp(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
    }

    let mut buf: Vec<u8> = Vec::new();
    // ADR-0005 structured prefix.
    buf.push(0x01); // marker
    buf.extend_from_slice(b"OLY"); // namespace
    buf.push(0x01); // object type = LEAF
    buf.push(0x01); // version = V1
    push_lp(&mut buf, shard_id.as_bytes());
    // Count-framed body.
    buf.push(0x05);
    push_lp(&mut buf, key);
    buf.extend_from_slice(value_hash);
    push_lp(&mut buf, parser_id.as_bytes());
    push_lp(&mut buf, canonical_parser_version.as_bytes());
    push_lp(&mut buf, model_hash.as_bytes());
    compute_blake3(&buf)
}

/// The 64-bit shard prefix = first 8 bytes of `BLAKE3("OLY:SHARD-PREFIX:V1" || shard_id)`.
/// Mirrors `olympus_crypto::smt::shard_prefix`.
fn shard_prefix(shard_id: &str) -> [u8; 8] {
    let digest = compute_blake3(&[b"OLY:SHARD-PREFIX:V1", shard_id.as_bytes()].concat());
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// ADR-0005 authority link: `key`'s high 64 bits must be `shard_prefix(shard_id)`.
fn shard_id_matches_key(shard_id: &str, key: &[u8; 32]) -> bool {
    key[..8] == shard_prefix(shard_id)
}

/// Convert a 32-byte key to a 256-bit MSB-first path.
/// `path[0]` is the MSB of `key[0]` (root-level bit);
/// `path[255]` is the LSB of `key[31]` (leaf-level bit).
fn key_to_path_bits(key: &[u8; 32]) -> [u8; 256] {
    let mut path = [0u8; 256];
    for byte_idx in 0..32 {
        let b = key[byte_idx];
        for bit_in_byte in 0..8 {
            path[byte_idx * 8 + bit_in_byte] = (b >> (7 - bit_in_byte)) & 1;
        }
    }
    path
}

/// Walk siblings (leaf-to-root) from `start` and return whether the computed
/// root matches `root`. Shared between inclusion and non-inclusion paths.
fn smt_walk_and_check(
    path_bits: &[u8; 256],
    siblings: &[[u8; 32]],
    start: [u8; 32],
    root: &[u8; 32],
) -> bool {
    let mut current = start;
    for i in 0..256 {
        let bit = path_bits[255 - i];
        let sib = &siblings[i];
        current = if bit == 0 {
            merkle_parent_hash(&current, sib)
        } else {
            merkle_parent_hash(sib, &current)
        };
    }
    &current == root
}

/// SMT inclusion proof — siblings ordered leaf-to-root.
#[derive(Debug, Clone)]
pub struct SmtInclusionProof {
    pub key: [u8; 32],
    pub value_hash: [u8; 32],
    /// Shard identifier, bound into the leaf domain prefix (ADR-0005).
    pub shard_id: String,
    pub parser_id: String,
    pub canonical_parser_version: String,
    /// Parser model-artifact hash, bound into the leaf domain (ADR-0004).
    pub model_hash: String,
    /// Length must be exactly 256. `siblings[0]` = leaf-adjacent,
    /// `siblings[255]` = root-adjacent.
    pub siblings: Vec<[u8; 32]>,
    pub root_hash: [u8; 32],
}

/// SMT non-inclusion proof — siblings ordered leaf-to-root.
#[derive(Debug, Clone)]
pub struct SmtNonInclusionProof {
    pub key: [u8; 32],
    /// Length must be exactly 256.
    pub siblings: Vec<[u8; 32]>,
    pub root_hash: [u8; 32],
}

/// Verify an SMT inclusion proof. Returns `false` for any input-validation
/// failure (matches the Python reference's behavior — never panics, never
/// returns `Err`).
pub fn verify_smt_inclusion(proof: &SmtInclusionProof) -> bool {
    if proof.siblings.len() != 256 {
        return false;
    }
    if proof.shard_id.is_empty()
        || proof.parser_id.is_empty()
        || proof.canonical_parser_version.is_empty()
        || proof.model_hash.is_empty()
    {
        return false;
    }
    // ADR-0005 authority: the in-leaf shard_id must hash to the key's 64-bit
    // prefix, so a proof can't claim a shard that disagrees with its key.
    if !shard_id_matches_key(&proof.shard_id, &proof.key) {
        return false;
    }
    // Fixed-size arrays already enforce key/value_hash/root_hash lengths.
    let path_bits = key_to_path_bits(&proof.key);
    let leaf = smt_leaf_hash(
        &proof.shard_id,
        &proof.key,
        &proof.value_hash,
        &proof.parser_id,
        &proof.canonical_parser_version,
        &proof.model_hash,
    );
    smt_walk_and_check(&path_bits, &proof.siblings, leaf, &proof.root_hash)
}

/// Verify an SMT non-inclusion proof. Returns `false` for any input-validation
/// failure.
pub fn verify_smt_non_inclusion(proof: &SmtNonInclusionProof) -> bool {
    if proof.siblings.len() != 256 {
        return false;
    }
    let path_bits = key_to_path_bits(&proof.key);
    smt_walk_and_check(
        &path_bits,
        &proof.siblings,
        SMT_EMPTY_LEAF,
        &proof.root_hash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_verification() {
        let data = b"Hello, Olympus!";
        let hash = compute_blake3(data);
        let hex_hash = hex::encode(hash);

        assert!(verify_blake3_hash(data, &hex_hash));
        assert!(!verify_blake3_hash(data, "invalid"));
    }

    #[test]
    fn test_merkle_root_computation() {
        let leaves = vec![b"leaf1".to_vec(), b"leaf2".to_vec()];

        let root = compute_merkle_root(&leaves).unwrap();
        assert_eq!(root.len(), 64); // 32 bytes = 64 hex chars

        // Computing same root twice should give same result
        let root2 = compute_merkle_root(&leaves).unwrap();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves = vec![b"alpha".to_vec(), b"beta".to_vec()];

        let root = compute_merkle_root(&leaves).unwrap();

        // Create a simple proof for the first leaf
        let leaf_hash = merkle_leaf_hash(&leaves[0]);
        let leaf1_hash = merkle_leaf_hash(&leaves[1]);

        let proof = MerkleProof {
            leaf_hash,
            siblings: vec![MerkleSibling {
                hash: hex::encode(leaf1_hash),
                position: "right".to_string(),
            }],
            root_hash: root,
        };

        let valid = verify_merkle_proof(&proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_empty_tree() {
        let leaves: Vec<Vec<u8>> = vec![];
        let result = compute_merkle_root(&leaves);
        assert!(result.is_err());
    }

    // ---- Conformance tests against verifiers/test_vectors/vectors.json ----
    // Vectors are hard-coded here (generated from the Python reference implementation)
    // to avoid a file I/O dependency in the Rust test harness.

    #[test]
    fn conformance_blake3_raw() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"Hello, Olympus!",
                "31948d8be54169e9a5b9e4ebeeb02dc233a82778e8e07b41fb09c0925780c469",
            ),
            (
                b"",
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
        ];
        for (input, expected) in cases {
            let got = hex::encode(compute_blake3(input));
            assert_eq!(got, *expected, "blake3_raw({:?})", input);
        }
    }

    #[test]
    fn conformance_merkle_leaf_hash() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"leaf1",
                "ca49d51cdd54cf54fc89c04b1d2abda03f0e7474d0af83ce143e7520e2eff199",
            ),
            (
                b"alpha",
                "9cdaa796deeaec992a83d52101921e788ca4e2f959b47316a00fa43aa1ef9dc5",
            ),
            (
                b"beta",
                "23ffd41f2e47a101c0b510809770af0aefb2c293d5114989d69abe3384704720",
            ),
            (
                b"gamma",
                "9cc9d6578dab4333405bc3fd06579f13e41aeab1770b062617a2037acaa01626",
            ),
        ];
        for (input, expected) in cases {
            let got = hex::encode(merkle_leaf_hash(input));
            assert_eq!(got, *expected, "merkle_leaf_hash({:?})", input);
        }
    }

    #[test]
    fn conformance_merkle_parent_hash() {
        let left = hex::decode("9cdaa796deeaec992a83d52101921e788ca4e2f959b47316a00fa43aa1ef9dc5")
            .unwrap();
        let right = hex::decode("23ffd41f2e47a101c0b510809770af0aefb2c293d5114989d69abe3384704720")
            .unwrap();
        let left_arr: [u8; 32] = left.try_into().unwrap();
        let right_arr: [u8; 32] = right.try_into().unwrap();
        let got = hex::encode(merkle_parent_hash(&left_arr, &right_arr));
        assert_eq!(
            got,
            "b1463a3156ed73e5df9d0101533766d62381dbb6e0b5b23a4c1b651095ba36dc"
        );
    }

    #[test]
    fn conformance_merkle_root() {
        let cases: &[(&[&[u8]], &str)] = &[
            (
                &[b"solo"],
                "22997be8efb920766d4a869cb3c0562f7ad5b8020887bc501f58029964485a11",
            ),
            (
                &[b"alpha", b"beta"],
                "b1463a3156ed73e5df9d0101533766d62381dbb6e0b5b23a4c1b651095ba36dc",
            ),
            (
                &[b"alpha", b"beta", b"gamma"],
                "9f68b7c5e6fc491a2f926699a0d7bd0bda1cdda1285b60c5ada9fb7fa3a6dad9",
            ),
        ];
        for (leaves_raw, expected) in cases {
            let leaves: Vec<Vec<u8>> = leaves_raw.iter().map(|s| s.to_vec()).collect();
            let got = compute_merkle_root(&leaves).unwrap();
            assert_eq!(got, *expected, "merkle_root({:?})", leaves_raw);
        }
    }

    #[test]
    fn conformance_merkle_proof() {
        // Proof for leaf 0 in 2-leaf tree ['alpha','beta'] — valid
        let leaf_hash_0 =
            hex::decode("9cdaa796deeaec992a83d52101921e788ca4e2f959b47316a00fa43aa1ef9dc5")
                .unwrap();
        let proof_valid = MerkleProof {
            leaf_hash: leaf_hash_0.try_into().unwrap(),
            siblings: vec![MerkleSibling {
                hash: "23ffd41f2e47a101c0b510809770af0aefb2c293d5114989d69abe3384704720"
                    .to_string(),
                position: "right".to_string(),
            }],
            root_hash: "b1463a3156ed73e5df9d0101533766d62381dbb6e0b5b23a4c1b651095ba36dc"
                .to_string(),
        };
        assert!(
            verify_merkle_proof(&proof_valid).unwrap(),
            "valid proof should pass"
        );

        // Tampered proof — wrong root hash — must fail
        let leaf_hash_1 =
            hex::decode("9cdaa796deeaec992a83d52101921e788ca4e2f959b47316a00fa43aa1ef9dc5")
                .unwrap();
        let proof_tampered = MerkleProof {
            leaf_hash: leaf_hash_1.try_into().unwrap(),
            siblings: vec![MerkleSibling {
                hash: "23ffd41f2e47a101c0b510809770af0aefb2c293d5114989d69abe3384704720"
                    .to_string(),
                position: "right".to_string(),
            }],
            root_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        };
        assert!(
            !verify_merkle_proof(&proof_tampered).unwrap(),
            "tampered proof should fail"
        );

        // Proof for leaf 1 in 3-leaf tree ['alpha','beta','gamma'] — valid
        let leaf_hash_2 =
            hex::decode("23ffd41f2e47a101c0b510809770af0aefb2c293d5114989d69abe3384704720")
                .unwrap();
        let proof_3leaf = MerkleProof {
            leaf_hash: leaf_hash_2.try_into().unwrap(),
            siblings: vec![
                MerkleSibling {
                    hash: "9cdaa796deeaec992a83d52101921e788ca4e2f959b47316a00fa43aa1ef9dc5"
                        .to_string(),
                    position: "left".to_string(),
                },
                MerkleSibling {
                    hash: "079d81bba4942d4e0508ae6560571a309125872610956c26d93849e9dc119b30"
                        .to_string(),
                    position: "right".to_string(),
                },
            ],
            root_hash: "a75ef97f9f64aa774b70c281d2bbf8129a87dd224ba61cbaafbe6977885283e7"
                .to_string(),
        };
        assert!(
            verify_merkle_proof(&proof_3leaf).unwrap(),
            "3-leaf proof should pass"
        );
    }

    #[test]
    fn conformance_canonicalizer_hash() {
        let tsv = include_str!("../../test_vectors/canonicalizer_vectors.tsv");
        let rows: Vec<&str> = tsv
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        assert!(
            rows.len() >= 500,
            "expected at least 500 canonicalizer vectors, got {}",
            rows.len()
        );
        for row in rows {
            let parts: Vec<&str> = row.split('\t').collect();
            assert_eq!(parts.len(), 4, "malformed canonicalizer vector row");
            let group_id = parts[0];
            let canonical_bytes = hex::decode(parts[2]).expect("canonical hex must decode");
            let got = hex::encode(compute_blake3(&canonical_bytes));
            assert_eq!(got, parts[3], "canonicalizer_hash({})", group_id);
        }
    }

    #[test]
    fn conformance_ledger_entry_hash() {
        // Test vectors generated from the Python reference implementation.
        // canonical_payload_hex = canonical_json_bytes(payload).hex()
        // entry_hash = BLAKE3(OLY:LEDGER:V1 || canonical_payload_bytes).hex()
        let cases: &[(&str, &str)] = &[
            (
                // Genesis entry — no prev_entry_hash, no certificate
                "7b2263616e6f6e6963616c697a6174696f6e223a7b226d6f6465223a226a63735f7631222c2276657273696f6e223a22312e322e302d7374726963742d6e756d65726963227d2c22707265765f656e7472795f68617368223a22222c227265636f72645f68617368223a2261616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161222c2273686172645f6964223a2273686172642d30222c2273686172645f726f6f74223a2262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262222c227473223a22323032362d30312d30315430303a30303a30305a227d",
                "adb9e28763376377881ee19f70d565216ff78781e87106190f16b3311d31eba6",
            ),
            (
                // Chained entry — prev_entry_hash set to the genesis entry hash
                "7b2263616e6f6e6963616c697a6174696f6e223a7b226d6f6465223a226a63735f7631222c2276657273696f6e223a22312e322e302d7374726963742d6e756d65726963227d2c22707265765f656e7472795f68617368223a2261646239653238373633333736333737383831656531396637306435363532313666663738373831653837313036313930663136623333313164333165626136222c227265636f72645f68617368223a2263636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363222c2273686172645f6964223a2273686172642d30222c2273686172645f726f6f74223a2264646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464222c227473223a22323032362d30312d30315430303a30313a30305a227d",
                "cf49a42ee068d1c79fabb380968c2f4166b661f0d4dee94c5de0c6636a3ecbf5",
            ),
            (
                // Entry with federation_quorum_certificate
                "7b2263616e6f6e6963616c697a6174696f6e223a7b226d6f6465223a226a63735f7631222c2276657273696f6e223a22312e322e302d7374726963742d6e756d65726963227d2c2266656465726174696f6e5f71756f72756d5f6365727469666963617465223a7b2261636b6e6f776c6564676d656e7473223a5b7b226e6f64655f6964223a226e6f64652d61222c227369676e6174757265223a227369672d612d303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030227d2c7b226e6f64655f6964223a226e6f64652d62222c227369676e6174757265223a227369672d622d303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030227d5d2c226865616465725f68617368223a2231313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131222c2271756f72756d5f7468726573686f6c64223a322c2273686172645f6964223a2273686172642d31222c2274696d657374616d70223a22323032362d30312d30315430303a30323a30305a227d2c22707265765f656e7472795f68617368223a2263663439613432656530363864316337396661626233383039363863326634313636623636316630643464656539346335646530633636333661336563626635222c227265636f72645f68617368223a2265656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565222c2273686172645f6964223a2273686172642d31222c2273686172645f726f6f74223a2266666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666222c227473223a22323032362d30312d30315430303a30323a30305a227d",
                "297c46f43726e4be43b311a49bab4e6df31d5ea7fa9164e125e22158c2709cd5",
            ),
        ];
        for (payload_hex, expected_hash) in cases {
            let payload_bytes = hex::decode(payload_hex).expect("payload hex must decode");
            let got = hex::encode(compute_ledger_entry_hash(&payload_bytes));
            assert_eq!(got, *expected_hash, "ledger_entry_hash mismatch");
        }
    }

    #[test]
    fn conformance_dual_root_commitment() {
        // Dual-root commitment conformance vectors generated from the Python reference
        // implementation. Each case stores:
        //   blake3_root_hex      : BLAKE3 Merkle root of the document parts
        //   poseidon_root_32be   : Poseidon root encoded as 32-byte big-endian hex
        //   expected_dual        : BLAKE3(OLY:LEDGER:V1 | "|" | blake3_root | "|" | poseidon_root_32be)
        //   expected_blake3_consistent: whether blake3_root matches recomputed root from parts
        //   document_parts       : UTF-8 document sections used to rebuild the BLAKE3 root
        //
        // Note: Poseidon root consistency (expected_valid) requires the full Poseidon hash
        // implementation and is validated by the Python conformance test only.
        struct DualRootCommitmentVector {
            description: &'static str,
            document_parts: &'static [&'static str],
            blake3_root_hex: &'static str,
            poseidon_root_32be_hex: &'static str,
            expected_dual: &'static str,
            expected_blake3_consistent: bool,
        }
        let cases: &[DualRootCommitmentVector] = &[
            DualRootCommitmentVector {
                description: "Valid: both roots from same 3-section document",
                document_parts: &["section A", "section B", "section C"],
                blake3_root_hex: "487f19f5f9226d91d8b59732d51baff231710c4f171a170e8573e4ca1666967b",
                poseidon_root_32be_hex:
                    "18a53b4212bf0cf8cef46e92830204178bf8a3a266ddf389cce2cd4ae2e903e5",
                expected_dual: "11392f039f5823c9916749bcb55b03227c0c7700d5115ffab46f45965dc44993",
                expected_blake3_consistent: true,
            },
            DualRootCommitmentVector {
                description: "Invalid: Poseidon root from unrelated document",
                document_parts: &["section A", "section B", "section C"],
                blake3_root_hex: "487f19f5f9226d91d8b59732d51baff231710c4f171a170e8573e4ca1666967b",
                poseidon_root_32be_hex:
                    "08ce2263d65d7ea15782e3ef9029a934275e4be7b51a35e49a1ad74be1d934c1",
                expected_dual: "be6ee9795ca414471a3165267bff046112ca5257bc014536296f29a1695ab787",
                expected_blake3_consistent: true,
            },
            DualRootCommitmentVector {
                description: "Edge: single-leaf document",
                document_parts: &["minimal"],
                blake3_root_hex: "cf57382d603eef611238e86c5d0fc6175326570ecfa4d1a6445d65f8d0b40d7f",
                poseidon_root_32be_hex:
                    "16f987bf796eaea13eff0678e11b547e740e0490f01a3c3ef0dbf1027e649c99",
                expected_dual: "460901d08c75e68d1dba341f369b0dc7562d9d1f8cbc7826a0658afbc31f075f",
                expected_blake3_consistent: true,
            },
            DualRootCommitmentVector {
                description: "Malformed: corrupted BLAKE3 root",
                document_parts: &["section A", "section B", "section C"],
                blake3_root_hex: "deadbeefa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
                poseidon_root_32be_hex:
                    "18a53b4212bf0cf8cef46e92830204178bf8a3a266ddf389cce2cd4ae2e903e5",
                expected_dual: "899a4d503e790e3c9550fe8187492a2164909210e84e1ad46823c58661c14d84",
                expected_blake3_consistent: false,
            },
        ];

        for case in cases {
            // 1. Verify the dual_commitment formula
            let blake3_root_bytes = hex::decode(case.blake3_root_hex).expect("blake3_root hex");
            let poseidon_bytes = hex::decode(case.poseidon_root_32be_hex).expect("poseidon hex");
            let blake3_arr: [u8; 32] = blake3_root_bytes.try_into().expect("32 bytes");
            let pos_arr: [u8; 32] = poseidon_bytes.try_into().expect("32 bytes");
            let got_dual = hex::encode(compute_dual_commitment(&blake3_arr, &pos_arr));
            assert_eq!(
                got_dual, case.expected_dual,
                "dual_commitment formula mismatch for {:?}",
                case.description,
            );

            // 2. Verify BLAKE3 root consistency with document parts
            let leaves: Vec<Vec<u8>> = case
                .document_parts
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect();
            let computed_root = compute_merkle_root(&leaves).expect("merkle root");
            let blake3_consistent = computed_root == case.blake3_root_hex;
            assert_eq!(
                blake3_consistent, case.expected_blake3_consistent,
                "expected_blake3_consistent mismatch for {:?}: computed={}, vector={}",
                case.description, computed_root, case.blake3_root_hex,
            );
        }
    }

    // -------- SSMF / SMT cross-language verifier conformance --------
    //
    // Vectors are loaded directly from verifiers/test_vectors/vectors.json —
    // the single cross-language source of truth, the same file the JavaScript
    // verifier reads — rather than copy-pasted constants. Regenerate that file
    // after any leaf-hash domain change (ADR-0003 / ADR-0004) with:
    //   cargo run -p olympus-crypto --example gen_ssmf_vectors --features smt

    fn h32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).expect("hex");
        v.try_into().expect("32 bytes")
    }

    fn sibs_from(arr: &[String]) -> Vec<[u8; 32]> {
        arr.iter().map(|s| h32(s)).collect()
    }

    #[derive(serde::Deserialize)]
    struct ExistenceVec {
        key: String,
        value_hash: String,
        shard_id: String,
        parser_id: String,
        canonical_parser_version: String,
        model_hash: String,
        root_hash: String,
        siblings: Vec<String>,
        expected_valid: bool,
    }

    #[derive(serde::Deserialize)]
    struct NonExistenceVec {
        key: String,
        root_hash: String,
        siblings: Vec<String>,
        expected_valid: bool,
    }

    #[derive(serde::Deserialize)]
    struct SsmfVectors {
        ssmf_existence_proof: Vec<ExistenceVec>,
        ssmf_nonexistence_proof: Vec<NonExistenceVec>,
    }

    fn load_ssmf_vectors() -> SsmfVectors {
        let raw = include_str!("../../test_vectors/vectors.json");
        serde_json::from_str(raw).expect("parse vectors.json")
    }

    impl ExistenceVec {
        fn to_proof(&self) -> SmtInclusionProof {
            SmtInclusionProof {
                key: h32(&self.key),
                value_hash: h32(&self.value_hash),
                shard_id: self.shard_id.clone(),
                parser_id: self.parser_id.clone(),
                canonical_parser_version: self.canonical_parser_version.clone(),
                model_hash: self.model_hash.clone(),
                siblings: sibs_from(&self.siblings),
                root_hash: h32(&self.root_hash),
            }
        }
    }

    impl NonExistenceVec {
        fn to_proof(&self) -> SmtNonInclusionProof {
            SmtNonInclusionProof {
                key: h32(&self.key),
                siblings: sibs_from(&self.siblings),
                root_hash: h32(&self.root_hash),
            }
        }
    }

    #[test]
    fn conformance_smt_empty_leaf() {
        // SMT_EMPTY_LEAF is hardcoded; recompute from the prefix to guard against drift.
        let recomputed = compute_blake3(b"OLY:EMPTY-LEAF:V1");
        assert_eq!(
            recomputed, SMT_EMPTY_LEAF,
            "SMT_EMPTY_LEAF constant has drifted from BLAKE3(b\"OLY:EMPTY-LEAF:V1\")"
        );
        assert_eq!(
            hex::encode(SMT_EMPTY_LEAF),
            "0c51a9c6fd8dd8847ba1053a17f62943c59052f4e311ab4e93867c4280579f29",
        );
    }

    #[test]
    fn conformance_ssmf_existence_proof() {
        let vectors = load_ssmf_vectors();
        assert!(
            !vectors.ssmf_existence_proof.is_empty(),
            "no ssmf_existence_proof vectors found"
        );
        for (i, vec) in vectors.ssmf_existence_proof.iter().enumerate() {
            assert_eq!(
                verify_smt_inclusion(&vec.to_proof()),
                vec.expected_valid,
                "existence vector {i}"
            );
        }
    }

    #[test]
    fn conformance_ssmf_nonexistence_proof() {
        let vectors = load_ssmf_vectors();
        assert!(
            !vectors.ssmf_nonexistence_proof.is_empty(),
            "no ssmf_nonexistence_proof vectors found"
        );
        for (i, vec) in vectors.ssmf_nonexistence_proof.iter().enumerate() {
            assert_eq!(
                verify_smt_non_inclusion(&vec.to_proof()),
                vec.expected_valid,
                "non-existence vector {i}"
            );
        }
    }

    #[test]
    fn negatives_smt_inclusion() {
        let vectors = load_ssmf_vectors();
        let base = vectors.ssmf_existence_proof[0].to_proof();
        assert!(verify_smt_inclusion(&base), "baseline must verify");

        // 1) empty shard_id (ADR-0005)
        let mut p = base.clone();
        p.shard_id = String::new();
        assert!(!verify_smt_inclusion(&p), "empty shard_id must fail");

        // 2) tampered shard_id (ADR-0005): bound into the leaf prefix
        let mut p = base.clone();
        p.shard_id.push('x');
        assert!(!verify_smt_inclusion(&p), "tampered shard_id must fail");

        // 3) empty parser_id
        let mut p = base.clone();
        p.parser_id = String::new();
        assert!(!verify_smt_inclusion(&p), "empty parser_id must fail");

        // 2) empty canonical_parser_version
        let mut p = base.clone();
        p.canonical_parser_version = String::new();
        assert!(
            !verify_smt_inclusion(&p),
            "empty canonical_parser_version must fail"
        );

        // 3) empty model_hash (ADR-0004)
        let mut p = base.clone();
        p.model_hash = String::new();
        assert!(!verify_smt_inclusion(&p), "empty model_hash must fail");

        // 4) tampered model_hash (ADR-0004): bound into the leaf, so the root no longer reconstructs
        let mut p = base.clone();
        p.model_hash.push('x');
        assert!(!verify_smt_inclusion(&p), "tampered model_hash must fail");

        // 5) tampered root (flip one bit in byte 0)
        let mut p = base.clone();
        p.root_hash[0] ^= 0x01;
        assert!(!verify_smt_inclusion(&p), "tampered root must fail");

        // 6) wrong value_hash
        let mut p = base.clone();
        p.value_hash[31] ^= 0xff;
        assert!(!verify_smt_inclusion(&p), "wrong value_hash must fail");

        // 7) wrong number of siblings (255 instead of 256)
        let mut p = base.clone();
        p.siblings.pop();
        assert_eq!(p.siblings.len(), 255);
        assert!(!verify_smt_inclusion(&p), "255 siblings must fail");

        // 8) corrupted sibling (flip one bit in siblings[100])
        let mut p = base.clone();
        p.siblings[100][0] ^= 0x01;
        assert!(!verify_smt_inclusion(&p), "corrupted sibling must fail");
    }

    #[test]
    fn negatives_smt_non_inclusion() {
        let vectors = load_ssmf_vectors();
        let base = vectors.ssmf_nonexistence_proof[0].to_proof();
        assert!(verify_smt_non_inclusion(&base), "baseline must verify");

        // tampered root
        let mut p = base.clone();
        p.root_hash[0] ^= 0x01;
        assert!(!verify_smt_non_inclusion(&p), "tampered root must fail");

        // wrong number of siblings
        let mut p = base.clone();
        p.siblings.pop();
        assert!(!verify_smt_non_inclusion(&p), "255 siblings must fail");

        // corrupted sibling
        let mut p = base.clone();
        p.siblings[100][0] ^= 0x01;
        assert!(!verify_smt_non_inclusion(&p), "corrupted sibling must fail");
    }
}

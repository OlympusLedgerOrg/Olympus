//! Olympus Verifier for Rust
//!
//! High-performance implementation for verifying Olympus commitments.

use blake3;
use hex;

/// Constants for domain separation - must match protocol/hashes.py
const LEAF_PREFIX: &[u8] = b"OLY:LEAF:V1";
const NODE_PREFIX: &[u8] = b"OLY:NODE:V1";
const LEDGER_PREFIX: &[u8] = b"OLY:LEDGER:V1";
const HASH_SEPARATOR: &[u8] = b"|";

/// SMT empty-leaf sentinel (BLAKE3(b"OLY:EMPTY-LEAF:V1")) — must match
/// `protocol/ssmf.py::EMPTY_LEAF`. Hardcoded for clarity; recomputed by
/// `conformance_smt_empty_leaf` test to guard against drift.
pub const SMT_EMPTY_LEAF: [u8; 32] = [
    0x0c, 0x51, 0xa9, 0xc6, 0xfd, 0x8d, 0xd8, 0x84,
    0x7b, 0xa1, 0x05, 0x3a, 0x17, 0xf6, 0x29, 0x43,
    0xc5, 0x90, 0x52, 0xf4, 0xe3, 0x11, 0xab, 0x4e,
    0x93, 0x86, 0x7c, 0x42, 0x80, 0x57, 0x9f, 0x29,
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
    let mut combined = Vec::with_capacity(
        LEAF_PREFIX.len() + HASH_SEPARATOR.len() + leaf_data.len()
    );
    combined.extend_from_slice(LEAF_PREFIX);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(leaf_data);
    compute_blake3(&combined)
}

/// Compute the hash of a Merkle parent node
pub fn merkle_parent_hash(left_hash: &[u8; 32], right_hash: &[u8; 32]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(
        NODE_PREFIX.len() +
        HASH_SEPARATOR.len() +
        32 +
        HASH_SEPARATOR.len() +
        32
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
    let mut level: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| merkle_leaf_hash(leaf))
        .collect();

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
// Sparse Merkle Tree (SSMF) cross-language verifier — ADR-0003
//
// Mirrors `protocol/ssmf.py::verify_proof` and `verify_nonexistence_proof`.
// Wire format: siblings are leaf-to-root (siblings[0] = leaf-adjacent,
// siblings[255] = root-adjacent). DO NOT model this on
// `services/cdhs-smf-rust/src/smt.rs` — that service uses the opposite
// (root-to-leaf) convention internally; this module follows the wire format
// used by `verifiers/test_vectors/vectors.json` and the Python reference.
// ---------------------------------------------------------------------------

/// Compute the SMT leaf hash with parser-identity binding (ADR-0003).
///
/// Layout (matches `protocol/hashes.py::leaf_hash`):
/// ```text
/// BLAKE3(
///     LEAF_PREFIX || SEP ||
///     key || SEP ||
///     value_hash || SEP ||
///     len(parser_id)[4B BE] || parser_id || SEP ||
///     len(canonical_parser_version)[4B BE] || canonical_parser_version
/// )
/// ```
fn smt_leaf_hash(
    key: &[u8; 32],
    value_hash: &[u8; 32],
    parser_id: &str,
    canonical_parser_version: &str,
) -> [u8; 32] {
    let pid = parser_id.as_bytes();
    let cpv = canonical_parser_version.as_bytes();
    let pid_len = (pid.len() as u32).to_be_bytes();
    let cpv_len = (cpv.len() as u32).to_be_bytes();

    let mut buf = Vec::with_capacity(
        LEAF_PREFIX.len() + 1 + 32 + 1 + 32 + 1 + 4 + pid.len() + 1 + 4 + cpv.len(),
    );
    buf.extend_from_slice(LEAF_PREFIX);
    buf.extend_from_slice(HASH_SEPARATOR);
    buf.extend_from_slice(key);
    buf.extend_from_slice(HASH_SEPARATOR);
    buf.extend_from_slice(value_hash);
    buf.extend_from_slice(HASH_SEPARATOR);
    buf.extend_from_slice(&pid_len);
    buf.extend_from_slice(pid);
    buf.extend_from_slice(HASH_SEPARATOR);
    buf.extend_from_slice(&cpv_len);
    buf.extend_from_slice(cpv);
    compute_blake3(&buf)
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
    pub parser_id: String,
    pub canonical_parser_version: String,
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
    if proof.parser_id.is_empty() || proof.canonical_parser_version.is_empty() {
        return false;
    }
    // Fixed-size arrays already enforce key/value_hash/root_hash lengths.
    let path_bits = key_to_path_bits(&proof.key);
    let leaf = smt_leaf_hash(
        &proof.key,
        &proof.value_hash,
        &proof.parser_id,
        &proof.canonical_parser_version,
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
        let leaves = vec![
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
        ];

        let root = compute_merkle_root(&leaves).unwrap();
        assert_eq!(root.len(), 64); // 32 bytes = 64 hex chars

        // Computing same root twice should give same result
        let root2 = compute_merkle_root(&leaves).unwrap();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves = vec![
            b"alpha".to_vec(),
            b"beta".to_vec(),
        ];

        let root = compute_merkle_root(&leaves).unwrap();

        // Create a simple proof for the first leaf
        let leaf_hash = merkle_leaf_hash(&leaves[0]);
        let leaf1_hash = merkle_leaf_hash(&leaves[1]);

        let proof = MerkleProof {
            leaf_hash,
            siblings: vec![
                MerkleSibling {
                    hash: hex::encode(leaf1_hash),
                    position: "right".to_string(),
                },
            ],
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
            (b"Hello, Olympus!", "31948d8be54169e9a5b9e4ebeeb02dc233a82778e8e07b41fb09c0925780c469"),
            (b"", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
        ];
        for (input, expected) in cases {
            let got = hex::encode(compute_blake3(input));
            assert_eq!(got, *expected, "blake3_raw({:?})", input);
        }
    }

    #[test]
    fn conformance_merkle_leaf_hash() {
        let cases: &[(&[u8], &str)] = &[
            (b"leaf1", "ca49d51cdd54cf54fc89c04b1d2abda03f0e7474d0af83ce143e7520e2eff199"),
            (b"alpha", "9cdaa796deeaec992a83d52101921e788ca4e2f959b47316a00fa43aa1ef9dc5"),
            (b"beta",  "23ffd41f2e47a101c0b510809770af0aefb2c293d5114989d69abe3384704720"),
            (b"gamma", "9cc9d6578dab4333405bc3fd06579f13e41aeab1770b062617a2037acaa01626"),
        ];
        for (input, expected) in cases {
            let got = hex::encode(merkle_leaf_hash(input));
            assert_eq!(got, *expected, "merkle_leaf_hash({:?})", input);
        }
    }

    #[test]
    fn conformance_merkle_parent_hash() {
        let left  = hex::decode("9cdaa796deeaec992a83d52101921e788ca4e2f959b47316a00fa43aa1ef9dc5").unwrap();
        let right = hex::decode("23ffd41f2e47a101c0b510809770af0aefb2c293d5114989d69abe3384704720").unwrap();
        let left_arr: [u8; 32]  = left.try_into().unwrap();
        let right_arr: [u8; 32] = right.try_into().unwrap();
        let got = hex::encode(merkle_parent_hash(&left_arr, &right_arr));
        assert_eq!(got, "b1463a3156ed73e5df9d0101533766d62381dbb6e0b5b23a4c1b651095ba36dc");
    }

    #[test]
    fn conformance_merkle_root() {
        let cases: &[(&[&[u8]], &str)] = &[
            (&[b"solo"], "22997be8efb920766d4a869cb3c0562f7ad5b8020887bc501f58029964485a11"),
            (&[b"alpha", b"beta"], "b1463a3156ed73e5df9d0101533766d62381dbb6e0b5b23a4c1b651095ba36dc"),
            (&[b"alpha", b"beta", b"gamma"], "9f68b7c5e6fc491a2f926699a0d7bd0bda1cdda1285b60c5ada9fb7fa3a6dad9"),
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
        let leaf_hash_0 = hex::decode("9cdaa796deeaec992a83d52101921e788ca4e2f959b47316a00fa43aa1ef9dc5").unwrap();
        let proof_valid = MerkleProof {
            leaf_hash: leaf_hash_0.try_into().unwrap(),
            siblings: vec![MerkleSibling {
                hash: "23ffd41f2e47a101c0b510809770af0aefb2c293d5114989d69abe3384704720".to_string(),
                position: "right".to_string(),
            }],
            root_hash: "b1463a3156ed73e5df9d0101533766d62381dbb6e0b5b23a4c1b651095ba36dc".to_string(),
        };
        assert!(verify_merkle_proof(&proof_valid).unwrap(), "valid proof should pass");

        // Tampered proof — wrong root hash — must fail
        let leaf_hash_1 = hex::decode("9cdaa796deeaec992a83d52101921e788ca4e2f959b47316a00fa43aa1ef9dc5").unwrap();
        let proof_tampered = MerkleProof {
            leaf_hash: leaf_hash_1.try_into().unwrap(),
            siblings: vec![MerkleSibling {
                hash: "23ffd41f2e47a101c0b510809770af0aefb2c293d5114989d69abe3384704720".to_string(),
                position: "right".to_string(),
            }],
            root_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };
        assert!(!verify_merkle_proof(&proof_tampered).unwrap(), "tampered proof should fail");

        // Proof for leaf 1 in 3-leaf tree ['alpha','beta','gamma'] — valid
        let leaf_hash_2 = hex::decode("23ffd41f2e47a101c0b510809770af0aefb2c293d5114989d69abe3384704720").unwrap();
        let proof_3leaf = MerkleProof {
            leaf_hash: leaf_hash_2.try_into().unwrap(),
            siblings: vec![
                MerkleSibling {
                    hash: "9cdaa796deeaec992a83d52101921e788ca4e2f959b47316a00fa43aa1ef9dc5".to_string(),
                    position: "left".to_string(),
                },
                MerkleSibling {
                    hash: "079d81bba4942d4e0508ae6560571a309125872610956c26d93849e9dc119b30".to_string(),
                    position: "right".to_string(),
                },
            ],
            root_hash: "a75ef97f9f64aa774b70c281d2bbf8129a87dd224ba61cbaafbe6977885283e7".to_string(),
        };
        assert!(verify_merkle_proof(&proof_3leaf).unwrap(), "3-leaf proof should pass");
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
                poseidon_root_32be_hex: "18a53b4212bf0cf8cef46e92830204178bf8a3a266ddf389cce2cd4ae2e903e5",
                expected_dual: "11392f039f5823c9916749bcb55b03227c0c7700d5115ffab46f45965dc44993",
                expected_blake3_consistent: true,
            },
            DualRootCommitmentVector {
                description: "Invalid: Poseidon root from unrelated document",
                document_parts: &["section A", "section B", "section C"],
                blake3_root_hex: "487f19f5f9226d91d8b59732d51baff231710c4f171a170e8573e4ca1666967b",
                poseidon_root_32be_hex: "08ce2263d65d7ea15782e3ef9029a934275e4be7b51a35e49a1ad74be1d934c1",
                expected_dual: "be6ee9795ca414471a3165267bff046112ca5257bc014536296f29a1695ab787",
                expected_blake3_consistent: true,
            },
            DualRootCommitmentVector {
                description: "Edge: single-leaf document",
                document_parts: &["minimal"],
                blake3_root_hex: "cf57382d603eef611238e86c5d0fc6175326570ecfa4d1a6445d65f8d0b40d7f",
                poseidon_root_32be_hex: "16f987bf796eaea13eff0678e11b547e740e0490f01a3c3ef0dbf1027e649c99",
                expected_dual: "460901d08c75e68d1dba341f369b0dc7562d9d1f8cbc7826a0658afbc31f075f",
                expected_blake3_consistent: true,
            },
            DualRootCommitmentVector {
                description: "Malformed: corrupted BLAKE3 root",
                document_parts: &["section A", "section B", "section C"],
                blake3_root_hex: "deadbeefa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
                poseidon_root_32be_hex: "18a53b4212bf0cf8cef46e92830204178bf8a3a266ddf389cce2cd4ae2e903e5",
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
            let leaves: Vec<Vec<u8>> = case.document_parts.iter().map(|s| s.as_bytes().to_vec()).collect();
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
    // Vectors copy-pasted from verifiers/test_vectors/vectors.json
    // (3 inclusion + 3 non-inclusion). DO NOT regenerate by hand —
    // re-run the Python ssmf vector generator if vectors.json changes.

    fn h32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).expect("hex");
        v.try_into().expect("32 bytes")
    }

    fn sibs_from(arr: &[&str]) -> Vec<[u8; 32]> {
        arr.iter().map(|s| h32(s)).collect()
    }

    // Existence vector 0: Existence proof for key 0000000000000000000000000000000000000000000000000000000000000001
    const EXIST_KEY_0: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const EXIST_VAL_0: &str = "4141414141414141414141414141414141414141414141414141414141414141";
    const EXIST_PID_0: &str = "docling@2.3.1";
    const EXIST_CPV_0: &str = "v1";
    const EXIST_ROOT_0: &str = "f7beb01818ec9fe29f5316b6add63a010749f428b3f71f177f47b59a2f268bc5";
    const EXIST_SIBS_0: &[&str] = &[
        "0c51a9c6fd8dd8847ba1053a17f62943c59052f4e311ab4e93867c4280579f29",
        "3ea38b9533634972d7b4d2f9ded53321d7d080eb67d5b5f0d4ea8b95e991f21f",
        "59dfc03f234687956c138401b10edcd64642233704630146bb34c72eba11a08b",
        "43d66b4de4a949b7be017c58ab3ea9c9d62663645b0258391ce2f110aee7af27",
        "2c79daced5a64e3d21c92d4f4b6518bac4ca12aad1dabf838400f7770b3ca81c",
        "45eabf069297deac076b6cd53484f1b4909c090cac787b5e54cf1fc75cf733ac",
        "576424c7e4488dcaf988ccd7f1df5129f7e26f56b5493ac501b69f66e90f7d4e",
        "fdbd6e678614b8a1c24e5a2bc96569aa9aa56cd9576a2e55699130e9d7fe88f3",
        "76f88eccca303650ae6e704fc541c98e23307bd23fb5ad24ead77894ada86e47",
        "f9125609b79e56aab4b7e1c773b239712fc7776dd776a2909c76cd97886ffa52",
        "4d78a02e0d1828a30054119b94a3a4298583f6dd3ef7607d892079683655f1e8",
        "e236cc712e09d59458e2ec848ab19b807bfdf8d8d02de77fbd5c0a7b7a141836",
        "cab76db206af544ad6b6a84d8a030c07711938c6dd6c423580ae9c04f1db0ff6",
        "711a5f331bd040912ad85fbabf2685460011f89be6066e76528bc01c302fd358",
        "133420cca013ea2edf4c4546f91960c4f73c9092c0a775d43a2016f8ce36f671",
        "c581a45eb2ceb7567419e459bf3e739e12f714c7f8469e8e479fbaa8434f2877",
        "f00f5cec01054f28c176a3b0331696f4ff09c46e0b2b3d63c394c5c4fa8c7033",
        "a9da3bc38058e04f3ddf6961f59c111039440693597cfe84a37bed0e4f4082dc",
        "f4c4b845e4e175129a659b715a9c06e5144a2c96f8f6e827e541ee48702777b0",
        "b4806d77ffec8175de8aed7c1160515b9c58f9e466c248cb015b2236e70d2769",
        "d5144e319bf2f12d97779b9a83aaa6cedfc7cbf42512858a4eb4023887036fcb",
        "7507c0868e89bb148cdbbb608b5829cf5bbdea6d86d055728eb9a2d5aaf2d625",
        "281de96d976a6895c2614689d4988f7620e8093b6302cdc0cb005029b8472989",
        "c080d6bf352dcecb167121a1a35236a595551e909c8eed7dd2220e123addd361",
        "c55efd3763e9e65bbb132ee9e7ee45f19b557ea43875893c0018970775908135",
        "35504e641f1e5ef49858700b5ab52ceb5e3d354b9652e549e6e38e54bffb2b8f",
        "5fa1b4251e7b0e3131479f17b7de4c65ff46dcdf1720bbfa711708392898630c",
        "ae6d787e9b4a7ee9e1e2ed0323ae65fb17d4c707bf71c96b2298d0b2d5eaa5c4",
        "e3d45305e32fcb10069fb9238a9458e16cc4cbc0d4ec506be014ecc2291fb845",
        "361ca179b035a1dbbaffeb1f509bfee0f15afa64d76e7b9e67eadbd86727a932",
        "75fa8ebcd7024b65a0c69adb52ec73799636a592507eab85b6cbb329409cd2c2",
        "b49698faf87e9e2bde213222589bdf6d41a9c0aae2ddbc6a9fa5d6e0e900b8a0",
        "bb8a615dfcb2eba70a0312efde0e297b87a5d86c1cac2d50a97c182e65659b25",
        "657af470826babc0ca494179abef07ef8ba069bcb915e60bbc9853516c65676c",
        "2681601cd3992c6387eddae5e3493fb66ce4acb7888f625c6159bcd1f7d51d4e",
        "4d5d52ec0726655f634eba604085d1b9a274db2358d5bd2e43d28072f28e4d0f",
        "acdfaaa936a5ef2c552feaafc17d06faf10ce792b87e68e44f3d5293447110ad",
        "9803967ded03a85db08cb546b5cac2e8fc708a9584751810c415e847530bf12d",
        "255701fb5252f0f11f2014232d739477204680bbbe78b95fe22e257c7c3fa1c3",
        "522deafd551686dc437d0241d46dfc8ed9bb26672b946249dd5a674723cc1929",
        "64d4ba29e80f8f27248bb93e2be10446f32fb01e39563902db252bcbf609aad4",
        "cf8d37560fb3c362d0fad2e2e0ebbd2a214e2b4aec4acb1fa3805690119c76d5",
        "ab39d85c7efc8273bec98ed3e0933e0795abcb607e79daa4b32c76ac651aeda6",
        "a6399bcec0e2eea7caa73166f69e50c38e65faf87067ba88e51ef1c084b60178",
        "2902519fa5abb8f1c8e72fa98b651742ab8752d26ef3a6f150936a8f0216cb02",
        "1176fd190cde55c9ed750d31960c216f6d8b5a2608b111103ab4d9f61c2af836",
        "a1e87be6b964f11f1500f0409e394b24e4c60a2c1804becea8447fa38be2abbf",
        "510e56c502e3ccd90bde5c283c270b2f1adb9527e84cb7888861aee8277b425d",
        "76915cfa634971ebb5ca96a572989121b0f417435554e75cfd3caf1cc7538024",
        "7a08c762b99b74153b0ec7e17c47ab815c4e69c70a17f4c725df18d3c24ba938",
        "a7dceb5481fa19d145a3d854175eacb317f88d79cd858e8010b0cd388f2e59fd",
        "ec2d7b7ce77e2657011c615e6ddf88b499a35321622cf31b73ecea6b6d5ec9aa",
        "ba2061307e6e1e3ba1a1e772e5aaea89f81204e33082374abfe65727e9487df6",
        "2e6d0ab3b8b58f74e5e513f6102594788a96914cedd90fbf65c328c61c607503",
        "b8ec6f052a2fe798e1dd3bbfa765174e9e4b75d4cb3a60e1c70569205872983c",
        "98a9f11b47cce0d2838e5fa3f2c4284f678896aff1783493a31c72cf1929aa2d",
        "01da07349b99ceb0961bab0dd84fe57bc9bcf42567cbbaec8f23c6fa77ed6198",
        "4250d7b736d3856ef3e94ec4e2f55d09349a8afbb533dd6f4238922682520c67",
        "5c93174c5be3dde79005da679860f5e0fee64f22be9d3fc456b8503accd2bc9b",
        "933ce3a0ed1a23a0cb863203123e1a896a33a1ef642b0688e48d4ad70a358258",
        "88824f69d2635e5d284933a353391242664cf4fa4143a06c4c8ca5a2dc54d706",
        "24986d31ce8ee947faac22e84b0ebae096f95c483b4929344feb71f546e137b6",
        "ab5db659f5111094557078606b94bee35966dc68cc1e74902822bc56a858927f",
        "d47d817b4f940323a066a023ebb60cfb3d91c2323f745430350373dec691a495",
        "6bc1e691cfde1a785e8d525397912fab406f8848b729acc0f1f2c533c05b8a70",
        "131adff07acae209f02888efc42477b211cb738167465978e1a18fab6d12c23c",
        "ad84fe9df2638b1822dfd5f569370f3227bd036091a1c0fd0608301965178850",
        "1d742e9ba2e21e2eeaee8eb886e2e2f6142394f30e2a172fe23c554aa4d5c23a",
        "931cfc21b8dd1241487f51387f00d36e7f180540af972b063a885428e01a8cb1",
        "69d790f9907544fcf6a06532e4e6d6a89b9df31dbd3bc44523ba46b6fc3e271c",
        "32c37953b6af3578539c522624c512f34adc004c7f0ea9e6e76937d048771cbd",
        "b4e3871bed13313a51ad350802d9df7659b0df67674b18eaffb9fde780e6ad66",
        "06a3a211392d296b14f27ac01d24c3b63f5cca373763c7e3c296165f2e70cdf7",
        "5a234e319f3be87b143c7b8a1dcf5407e78ca0cd38b0dd819f7898403af09803",
        "72190009bba7beb174c1068b2013ce905fa457527a81a64742a789ee1a0c8e09",
        "9ed982dd1251bc8ecf345ec9ac6f15a94f63b42348a235681f83f52d6dfc6bbd",
        "d99b38772bb5236cc18159acae2e07d58fd839e8667202d4cc88fb88fd5b671c",
        "6e0e0224d787ed1a3a0b3b4dd32f05c63b3f177b6816506000ca140d99cb9e89",
        "ab2ebc2d00248d537d027b4cddaa2f909ec4ec505b7bd477e92c1e40751590bb",
        "c58ec9edc6394ee3972549d82cd6bcc604f50d17fbe0f09015630b193be19776",
        "fbd89acacbd52a70f83bade340e1ca5e374bbcace265358ecbb4a73ded58f98a",
        "cecad33b21242ebfef444f8c7eb061f157e28c0e327a931d49ea91a15580ac4f",
        "b11861e11ff2d465a48cb68efe2a3d2a582a97a058c9d9209d5a5ba2b666ee57",
        "ca29bc7497c4a0c9ca73cdb3efef66ee4e789b3d412c80aa29f052bcce36d20a",
        "72363d88e437c8b1cf91a8923d96190f27662a13f555b9444f79f773ba7c2986",
        "65bb2376f29cf89a1425a0907c2cf8e068a4ad9b932f3dc504e81a5410b469ad",
        "fc6358ea9287cba16386bbd613d4cb78bfe33c45ae3b445536cad2e565d66f10",
        "1fc658658ed72006c05fb78933926f2c62698811f6372fe6e154117303607b04",
        "14f104af45556b9d359fe901989c9610392eed4d2f13638977c10f9b9dffcf4d",
        "62bc677a59e6ea11f527644b80254b19e592401388d641a399820fcd9131d56b",
        "89a64819315750df19d21c810036e470be6462edfd8ac1a28f92e1cc8ca7acf4",
        "460fc1504227bb4ace26ca3c6a4e572f2e56f8682f5eb073265181899f3d3779",
        "dff32d95d6d42e0a4e6f66894978da2564ffe658d384c1968f6c3cd344cb6f45",
        "5acc732da44c24f760f791f2905e8f724c5defa08b31691a8a758abe6ef2b7c8",
        "ea886b9c1d2f5b8797a30503356fd39eb67ebeb4bd1e0bc9626ff7d80a18925a",
        "ff0431cf20dea7c53a04aeb1f996bedef591dff83916d7e5813b9c6d57e79738",
        "b4d6119b13b371caf6cc9e240c097138aa5b7009b0fad69ffc1c23b0ad7d4635",
        "278eb5e2d4f7b7f2b6145878f08e361e487b6397ddf11c3d19449f54ba720f2b",
        "87349e20a14b6d9ecf34e2f590cdeeb3fd4df6c943bd5b1c9439e1ff815c87ad",
        "42e9dbc450c8858c2fd80729eac862340c26d08409f7607e6a844a0285cb3a77",
        "adc069c2fd56a7669752e9e2ac19710821a3eecf7f134430200f93f6ffa92654",
        "97715248aa97f81c5b4f212775363f27f11c3c1a13e72a16cd356a42ec28fcf5",
        "5b1b2a976c582e23463b176adaac0a456ad346201e162bb6644d13b0369b1d62",
        "1d5db1116c484753f80436b4a4a7c10fbd6f8dae4cf35add44d2042025156293",
        "5066a0acdaee0540fbb842e02f4ea5d2988e99e464267ee2fe60552ac7bac636",
        "148f2e2ce405858ff7af17fd0d1951d1c82180c1dda3e95dda0f49cd32401222",
        "6f1b33ff8f3e5cb2bc59a9c1ebca8854d296f05e7c299bf930b1206d76c0ba35",
        "a9f85de9810e013de101803d18f217e13ee293917f8172d3390d32eda91d6b8c",
        "b53a3b8b21cc8659de0b031d1151f989d6f29dcfc42c29be25ebd1f3401d7abc",
        "325e183bb1d85857081f7e8c9ca8137582976e4fcedad40b9de7af9b424d805e",
        "c89497f90a27a688a9b8e5a7995720754cc09b447ecb7d455419b68cffe39f00",
        "1e8ac1a49b19a029db1bfcad973311f9bd0359660cbc1ef810af6f113921f90e",
        "8f58472c1fbc5240638528de80aff8fc1eedd8f2364bf90747256e10d3aa993d",
        "c74176e5ace2c83fb59481106d159bbdc0bce1d209c167c2ed2c8160346b1e08",
        "243ecea5a0787244d67bb452d2b4c10f37ac69668dcd71f5166c975b6d56a64e",
        "a52911600ea5a6b983e12f81a09949a4c1936807de4d76d98dc07d9a1218d309",
        "d751b66ad5f98380f1e66f1c0fb512b5da36c920552a06d06a1db064ca37ae13",
        "6488b23e0dccd736945f97e8922911798e450d7cb3d00b8212e46942618ed654",
        "1bce25783fa821b20103d186849a19dc5bbdc8638ddf1a447282d06c5b985b87",
        "9aa090fabe3dfa3c70417f54ae9e1f7f88679475665b3312b4a51dc8e2a89719",
        "bab72434e9a2a04cc8708a16ba96065ebc703a204f1d14e54b6381f7e41c6ec6",
        "d1ace25484265bf44ccc4ea9687967050d5a13e2399f151d0f03a25fc166bee3",
        "2a39690ec069e250bfc02e35c70946e16575c2c2e5c8ac3e63ad9ab43b3bef7d",
        "37d11ccdb9bedb8cee0894d606ee918c514dca043d3c70baff8908ac071968e2",
        "555c65be76315f4a7aa0d661ce613cc51d62fd5f88f0c3be5d6537bde9a64e6f",
        "1f2c6dbca5081b8a2b918d2b7a5b857945f0ec34634c54ab7d01cb7efdd10ef6",
        "a09d359159cf7862059c6b270dc6ac27677496a9806e3e1939ab69a5f4bd982b",
        "06569dacc84d3043e9389d609a7dadee797e1059858a3cf17083b976a6bcacb3",
        "bc4adc073674c546dc474967aff391281ca2cb9132063e6d1dccf92d3a7a9ad1",
        "1fe55a13d7251033f45cb7d9c7e0102c6bfc30f1c637fd7badf190bd507ab2b5",
        "32dce867d9b7ebba2db35302f725ae9b5f3fe414cd78685cb4b1c710af969e0d",
        "3df1c47f0edc8d43ff42fde59ea0fd134d2a74506790f8a631cff220d773c884",
        "79848b7eb23bab9d1ea68164b4c333ee275686fe8d116be12a4eccf2aadc60bd",
        "a1a53e76001e94abd450728ccfa2620590d525a16372d9108903667c18ff0a04",
        "5dbb7fff8de71fe0651f263dba1ce63dd81d5e18b921795ab83c02096050b13d",
        "f8ac2c33fee34bc7125fecb0e3b7401c5382938eac74deee788b3d34e154343e",
        "c612aca030a397d9153dafaf0741ba76424167258bb66bba076cc4be3bb5c1b4",
        "f0d761f170a03e7ff42bc44d9eb04c61d4e8a087b009a408d8173a52fc907074",
        "41211ef7e9dc75eccd79375e66b523ee137c51756475e426e671337a403e9182",
        "37659c89134d3f3fe38b0c9824f3687397709376367bb61e5f0109a17f090974",
        "b2f948c987c18eeeeade96b1a7177f8d92efa03d473b9bb2cf58b7044c49abe5",
        "ad9c893e51f6ed6d6b1ce753dce5667693a4cb5a76d6632fbb1b9251efc7f7a3",
        "bdc78758eafb5407cc6fcd444e21fe499f4763ee9886d5074adb043fb3f091be",
        "61aa3c8de9b4642b445c0bec3416c75045f976bdc8966af39b8a177413220c92",
        "9d4ec3301087738ca80c391e52f6f1b55916bee036fa2bff3bf040425b0fc440",
        "df43318f4dedf7bd1ceedaf4eeb05615526a8e84b9777cdefdbdd5e6137a7553",
        "22a787ec912240984aa483b88508f5d42f0709f03036412195c0dce558a13512",
        "281cfd66d19bf1de9ae0cc2b114d0dcc4eb6fd5bea42683cb87a88b9002a3cd4",
        "ee841e26b57372f5028a5ee3bb33d3e6a2b4b0c0475c32d9d521ed5538596d85",
        "5a3acfe2e3f96d31be1540fd4dc1b927d71abca91dc111a8ddfc064ef92daf77",
        "a42e5878bbbde777be1a847a949b357f6e977f62acb86b0df1b61d0111496080",
        "7aa1fd59b6da6a213a9cac65d9efd2bb0bfa3ade0e2d42a12563dee4cebe4c44",
        "d35539023ccf129418b2169c9794f3849af8d93d73f07ac9de4eb40a33bc4339",
        "091cc3c3533ffa3b783384b4bff05ebbbe3b8bddb93653be72e1552e53d37616",
        "f239114efa32b64bf0c0effc46bfde40a8f7fd28fcc5277fcc0965ac20281294",
        "0618c1f3b86e3fef92f45744bbc1ccc0a82db77f65868066dcb4ee9e3bef82b8",
        "f02528772cc6d6117249ed7a3e91570f1fa446d44c89aaed3fef345ad28a100c",
        "a1091b57c6151d8348a9cd335581ae5a52515ddee691b50f1c71753cff438a41",
        "0070f61d2999342097f9c2340361a6b2a47e21f0a48df9ee300c75b321cb12d9",
        "ce2260a82ea8dec0dd25f47db14dbd7a61bc4bdbe7dd103c621632bf7a5ba21b",
        "065b7cfda4b11c8fde342e7e0201d981b5a2acf5075368e4634815a693b3ee3e",
        "414a2cf5449a6ca94a15274008446728eff85074873fbe05ea562aab880d6313",
        "c22ac7cedbf84cb54d76714a832c7f93a74b2b02bba62452884684812e497f34",
        "776126fbc83693b322eed8640e9f703deabf9a1581cec80c8e963404e9f0f47d",
        "849f0790f592238600e9e4ae1ff12f3393d1657ca52b50727562c4183b8c2826",
        "8387956906c2f6a57b14fe940fb19616977ea996db9ca234343571ebf28929c0",
        "03215e51eeab80a70769641baffb7fa6111425ff88906bfc1af8ec9f042221b5",
        "c3d0f8683f5c6ffad349be2e6e9d8926706fd0e8bc6c3edde679642a121e82ed",
        "2438c056a82f448c12b23e4620358045493a170a76ec580f5fde290cd49e60df",
        "8ce595662a14047a28d8e9be28fcfc86fd5df18112513c43f85da64b73f9072c",
        "3b901c76325ea9738873e9dee1fc955f8068ae8bc5eede9cebe6f9776fe4b118",
        "5bb263cb618537c429d059bdd91e7bcb5d05f606a88e06cf2f25d2973ddbc113",
        "69750390d7a9a44a8e0c786a4cda7ddfd57ff3ea16937955cac8aa8ffda07219",
        "b2113668d4f27b38b29963a2d0c582f8fe95aad31c3b21cf626718ca94892482",
        "ab6b6d37269f90abd9a222f2b241cf3c7ca15904a13010144d108141d74e147e",
        "b3c532544e19d3297ad0654c92061b43d541becca6096fa253b7ed509d9ae189",
        "c264a7f21744ca68a07f39d01936638f420f3e1998d3269bbd1fac0557170c60",
        "42d4051ed6d2a2ba670b16a8d0f9d14b8ff5e38354c9f5e55d5102f0f292b1f3",
        "4d78737ace4f805cd5411ef1ae0a9e2a798b45bc11e9fff4d348dcfcee8f42c6",
        "0a2a01cc2506486a049c98df7b151b77d75cea67921224152fc10c53ea352b25",
        "337a92c293a11d777a82d85a6480994d3b8324fc78ed0d507c4ccf3dcd236a9e",
        "71997103ee3a1f016aea1595c8d3b7b778792cb037d03ce733ce67b27a08e0b5",
        "d61ff1cb4f2e157f248dac466b2ab297599367fda32a6a52c1842d750268dff5",
        "bbffef94731ef2f4a9ab21f90bf70a4d8e87d24a90406e5515db6cec99ddaa90",
        "1ef38ecf4b91592fb0f08f8382314d06d951270bf3760a2411965e0e82a0449c",
        "09c30b8533faa48e003280ec910ce77b2d4fe9293a8af1740c62be38146fdf60",
        "861dacde4967d2aa400c516800dac0a923daad6c040db5ba7b6dd020e6cb6b66",
        "56356e3420f88cf76e676e381fd9abe046240f1c5f3b9e0a0fa75efbacb7d190",
        "956d0e1e9fb913152afac367ffb432ec957784805f19d969592ee3eb7d4700df",
        "d440a82d19ac13c504a467be198256cca9edd95e613029a5b94b13033a19ee23",
        "e58e3b9f5704d845e8f5ffdba821d651b57d10ce94a23ee6bb9362d785377f6d",
        "652faecf6414f44a61f83a41bf7471ef8d857c62455c8e49fec8567c53e9cccf",
        "95215cf5f073b74b8cf9fa6193f0804b8bbdb7a8b280a3647943abb81320c8c6",
        "bb6a21ca848eebd050ee5acc2bec5d06334d206ce8a00d576a2235eb53e93ca3",
        "9ebf65c67fa011c4d5b0cc7be3ab146617badf2e313c7803a97eb60ac914ed61",
        "bcbe975936802665c69b490266303f2d6dea2a9730a3533b05fc5e9d662a50c7",
        "795c25ca0698c3c28039cd9346bb2d5e8cf61d8b7697a3c600defa6afd10b6d2",
        "dc7f1e32c5d23e0bad9233eb900f6b04633ce504f531e2df9f53d53e8b46c312",
        "76018dfe4c387b1de78730115700a45f71f75b822ada50ab5ebf35aa392f5119",
        "b2b52313d058516fdd52f4b3a5422bd5ad88e7ae0e21ec37ca094de16b65af4f",
        "dd63781fbe7179c0e97b67052d852023718b2d9d9fad77a20367901564c0df00",
        "b93ebcc14628777fbbfd21ea06defe3f723ae08477126cece38ae112074c9c59",
        "2639be3d392f3df20d9c77e07bff2861549c2e8e4f688af3f454d812759fbe7b",
        "f7d6f0b48ed2e333f6f566b158834e1726451c8a435ebc8376d98dc5b8987a9e",
        "002e294231f869bb73158ade98ad37203a8f46227e8613b1920dcafc55644b03",
        "e7a6ac4ea049a40ede51b6406581aae3aff2de5099fe49023348b588abce0dcb",
        "ce7586aa4434eaa1d531e130e82819cb5d9c8ea6c95b703565f604a8b15a14fa",
        "8195ec54a7a690c38bd2f535d313bbc7f1d1af8414108c7ca05431c79c0922d1",
        "58a1960343cab1c4977aca073b27d898dc8f5310dead52a57691429d389eb0bd",
        "bb95ed9edb2660359a44cfc70ebd5a9e442327d1ab7bb1cf14196a36a1c6aa27",
        "0bb250ece3f690723298898b0b0efc9442fbb7e8967138be20e29e04983075b3",
        "7092b0336fd60a1a6e24b62bf22244fc431eba64f213bd8f5d9de2865379da69",
        "5ee5252fba29d669205ce91153b443ddb21540f9da36da0e066e30cfbc85dfa3",
        "9e0dd4e1d4a0c7a6ec4a7ade373efc107f810377f1d3b0327490ef63dc865df6",
        "9dea4389f111c9fc3e370794b0da274de8d5d4dea3d593d8af45c3186a5139bd",
        "cbc538560908ba70b0b103101f05cee12bed8812dc01be3670d2b8634351a433",
        "9b4663f636ef04ac5756f673ecaeb166ce9b228ecfe9a79750d1fac91e9cfaa1",
        "edeed2f6b8acbb7081335a602c012b6d97e0393fc29d3ebeeab71465cbb20471",
        "97ae0bfe76a1554bdbd78c39cb9fbaf1567f274dc3901300fb8ec01e95e17c26",
        "a9646079729df8afbd182a588282c7ea65e7dab177cb5b1cef373700ed166d79",
        "22c78b424753cd7782cd7c38ecea7670323760c5a8ed21513bdd537e732985ee",
        "eb33e4b7f546160ceaa89f6a1adbb0aa1c324185a85aaf05f9e11dd3a30f8963",
        "c48f2b8c57afcce911b86d9027207b54abf304d18c8936f556039f34b420a22e",
        "cbc29bceff35b2c14d682667a78f56c76279dda0dea1d3567e699be211914b46",
        "3a0c64ab17e9b542e45cb1cd0c874d766fb945c309bc19f91c8b2d06b7a3bf86",
        "392a11bda08147c02e63bdf4421fdb54b72148cdd09026855fbdb25811e924db",
        "8a64d5244c4945230e6d979ceb0969f418119c9cdb7778bd93a74f0ed6f9ea68",
        "f148c9d0668baea63ce495ec2dd3b1fb46c1eebd6dc1d4c4d4851aaa8b53d8c3",
        "721e0bbcc3054385e2dac368b466e3c4ad636113d8667eda7c0e9a027f7d459b",
        "98a769b47312ace49da42ee3e1695e290c142f3109ef1f36928cac6af12246a2",
        "75e25a186e4bc987c6b365dca378ae777c07a3a2b4295a1ff12bb88de5121237",
        "7b0b452b0351674d1137d1ae22a56a6574885d41f000771f4c0e5cc27c030eb2",
        "49fc7e713bae4e7e37c0313319020ac243d46693b10ac3a273325d65964bcb73",
        "4421d386d3970949e03749c43bf28e4f2801400abdd466f96b925c34668f3686",
        "fd8c550467d4e471a3b6a27a74e95583d2b2938ca2c5f93ad4c3a18007fd2fd0",
        "50ad260fad06a4c851d004915feb9d42b0e96dc50f0cffc724d844b3d6e2cf08",
        "2756821e3e180586117a659330259fb8b7f59aaaa2c376eea90c9cd15a118f98",
        "7aa0baf58d27f0e589d066c16b06821aa573610f30d9420d4d7d6d906b42ca0d",
        "af8a25f12472deaadb721ac97740874bc410a52b57a7d4629e140c8548d0d777",
        "3113cbf56a24970b2560c0891223197a773acf3aa1bff62dfb4c93d416865388",
        "22ae2fd22720bf9ac91447b76ff82591d5acc4cd43ad243267ab4b722d537951",
        "45abd184ee741e6b2300d4e77cda05c55bac64902726b38514917c4be11a700f",
        "9a93beb5b1748349996c5a68f28e5db1b3dc43f35b53522ecb347035c45cc8f9",
        "9ed838276797a35681787184ac33677bd2c0b8847d57580c7110b45b86ab5552",
        "6bfc26bcf180f5e954f6b183bbf5f364d608ac715aa210a59b6569d44682f298",
        "9cd151509dd68fdd7a6aca93ddc1350c9dbe236bef141d0baaae4e0fee69a534",
        "86eb8328c8a48a7311d337418f8a23ffb79f5b38b08b9cfc8c07133a32b5d43a",
        "8bb6be0f033075b093368c1f3d5500037418cb5275a3beb9f71b417e791b4834",
        "25e73888097d609b4dfc49f856cee142847c5bb169cbef4f9b25c27958870435",
        "0ddd3c46363a727f314e5d8fe566177e69ed9f0efde27d249dde470587cf7f63",
        "be16d705d7ca159048dea82bc2752db8c8fb86c64c597754c609e9e9aba97b87",
        "0d8d72b0e270abf5c8951f1065fd97ba42f2879b58d940922ecc61afcd8c9896",
        "0b9315ebd59b4bf0bfa8aae499d808e32a68277a6d857517630cb026412a6047",
        "033db49568e184ae4c421f5b1524201c3f289517a26e9eeb8d0e1b8594118807",
        "f77f2c428e39f86861bb5eab724b6b191975ea1623a9010f73aa8536ff1cecec",
        "57d9fe07581fac965c7b1577bb4d5389871af714cd6490c9bcb0ea313dd438c5",
    ];

    // Existence vector 1: Existence proof for key 0000000000000000000000000000000000000000000000000000000000000002
    const EXIST_KEY_1: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const EXIST_VAL_1: &str = "4242424242424242424242424242424242424242424242424242424242424242";
    const EXIST_PID_1: &str = "docling@2.3.1";
    const EXIST_CPV_1: &str = "v1";
    const EXIST_ROOT_1: &str = "f7beb01818ec9fe29f5316b6add63a010749f428b3f71f177f47b59a2f268bc5";
    const EXIST_SIBS_1: &[&str] = &[
        "0c51a9c6fd8dd8847ba1053a17f62943c59052f4e311ab4e93867c4280579f29",
        "07b81b1dc127e2141448bc74d3e2acbb1f88945808bad8711850ced7ce1c6039",
        "59dfc03f234687956c138401b10edcd64642233704630146bb34c72eba11a08b",
        "43d66b4de4a949b7be017c58ab3ea9c9d62663645b0258391ce2f110aee7af27",
        "2c79daced5a64e3d21c92d4f4b6518bac4ca12aad1dabf838400f7770b3ca81c",
        "45eabf069297deac076b6cd53484f1b4909c090cac787b5e54cf1fc75cf733ac",
        "576424c7e4488dcaf988ccd7f1df5129f7e26f56b5493ac501b69f66e90f7d4e",
        "fdbd6e678614b8a1c24e5a2bc96569aa9aa56cd9576a2e55699130e9d7fe88f3",
        "76f88eccca303650ae6e704fc541c98e23307bd23fb5ad24ead77894ada86e47",
        "f9125609b79e56aab4b7e1c773b239712fc7776dd776a2909c76cd97886ffa52",
        "4d78a02e0d1828a30054119b94a3a4298583f6dd3ef7607d892079683655f1e8",
        "e236cc712e09d59458e2ec848ab19b807bfdf8d8d02de77fbd5c0a7b7a141836",
        "cab76db206af544ad6b6a84d8a030c07711938c6dd6c423580ae9c04f1db0ff6",
        "711a5f331bd040912ad85fbabf2685460011f89be6066e76528bc01c302fd358",
        "133420cca013ea2edf4c4546f91960c4f73c9092c0a775d43a2016f8ce36f671",
        "c581a45eb2ceb7567419e459bf3e739e12f714c7f8469e8e479fbaa8434f2877",
        "f00f5cec01054f28c176a3b0331696f4ff09c46e0b2b3d63c394c5c4fa8c7033",
        "a9da3bc38058e04f3ddf6961f59c111039440693597cfe84a37bed0e4f4082dc",
        "f4c4b845e4e175129a659b715a9c06e5144a2c96f8f6e827e541ee48702777b0",
        "b4806d77ffec8175de8aed7c1160515b9c58f9e466c248cb015b2236e70d2769",
        "d5144e319bf2f12d97779b9a83aaa6cedfc7cbf42512858a4eb4023887036fcb",
        "7507c0868e89bb148cdbbb608b5829cf5bbdea6d86d055728eb9a2d5aaf2d625",
        "281de96d976a6895c2614689d4988f7620e8093b6302cdc0cb005029b8472989",
        "c080d6bf352dcecb167121a1a35236a595551e909c8eed7dd2220e123addd361",
        "c55efd3763e9e65bbb132ee9e7ee45f19b557ea43875893c0018970775908135",
        "35504e641f1e5ef49858700b5ab52ceb5e3d354b9652e549e6e38e54bffb2b8f",
        "5fa1b4251e7b0e3131479f17b7de4c65ff46dcdf1720bbfa711708392898630c",
        "ae6d787e9b4a7ee9e1e2ed0323ae65fb17d4c707bf71c96b2298d0b2d5eaa5c4",
        "e3d45305e32fcb10069fb9238a9458e16cc4cbc0d4ec506be014ecc2291fb845",
        "361ca179b035a1dbbaffeb1f509bfee0f15afa64d76e7b9e67eadbd86727a932",
        "75fa8ebcd7024b65a0c69adb52ec73799636a592507eab85b6cbb329409cd2c2",
        "b49698faf87e9e2bde213222589bdf6d41a9c0aae2ddbc6a9fa5d6e0e900b8a0",
        "bb8a615dfcb2eba70a0312efde0e297b87a5d86c1cac2d50a97c182e65659b25",
        "657af470826babc0ca494179abef07ef8ba069bcb915e60bbc9853516c65676c",
        "2681601cd3992c6387eddae5e3493fb66ce4acb7888f625c6159bcd1f7d51d4e",
        "4d5d52ec0726655f634eba604085d1b9a274db2358d5bd2e43d28072f28e4d0f",
        "acdfaaa936a5ef2c552feaafc17d06faf10ce792b87e68e44f3d5293447110ad",
        "9803967ded03a85db08cb546b5cac2e8fc708a9584751810c415e847530bf12d",
        "255701fb5252f0f11f2014232d739477204680bbbe78b95fe22e257c7c3fa1c3",
        "522deafd551686dc437d0241d46dfc8ed9bb26672b946249dd5a674723cc1929",
        "64d4ba29e80f8f27248bb93e2be10446f32fb01e39563902db252bcbf609aad4",
        "cf8d37560fb3c362d0fad2e2e0ebbd2a214e2b4aec4acb1fa3805690119c76d5",
        "ab39d85c7efc8273bec98ed3e0933e0795abcb607e79daa4b32c76ac651aeda6",
        "a6399bcec0e2eea7caa73166f69e50c38e65faf87067ba88e51ef1c084b60178",
        "2902519fa5abb8f1c8e72fa98b651742ab8752d26ef3a6f150936a8f0216cb02",
        "1176fd190cde55c9ed750d31960c216f6d8b5a2608b111103ab4d9f61c2af836",
        "a1e87be6b964f11f1500f0409e394b24e4c60a2c1804becea8447fa38be2abbf",
        "510e56c502e3ccd90bde5c283c270b2f1adb9527e84cb7888861aee8277b425d",
        "76915cfa634971ebb5ca96a572989121b0f417435554e75cfd3caf1cc7538024",
        "7a08c762b99b74153b0ec7e17c47ab815c4e69c70a17f4c725df18d3c24ba938",
        "a7dceb5481fa19d145a3d854175eacb317f88d79cd858e8010b0cd388f2e59fd",
        "ec2d7b7ce77e2657011c615e6ddf88b499a35321622cf31b73ecea6b6d5ec9aa",
        "ba2061307e6e1e3ba1a1e772e5aaea89f81204e33082374abfe65727e9487df6",
        "2e6d0ab3b8b58f74e5e513f6102594788a96914cedd90fbf65c328c61c607503",
        "b8ec6f052a2fe798e1dd3bbfa765174e9e4b75d4cb3a60e1c70569205872983c",
        "98a9f11b47cce0d2838e5fa3f2c4284f678896aff1783493a31c72cf1929aa2d",
        "01da07349b99ceb0961bab0dd84fe57bc9bcf42567cbbaec8f23c6fa77ed6198",
        "4250d7b736d3856ef3e94ec4e2f55d09349a8afbb533dd6f4238922682520c67",
        "5c93174c5be3dde79005da679860f5e0fee64f22be9d3fc456b8503accd2bc9b",
        "933ce3a0ed1a23a0cb863203123e1a896a33a1ef642b0688e48d4ad70a358258",
        "88824f69d2635e5d284933a353391242664cf4fa4143a06c4c8ca5a2dc54d706",
        "24986d31ce8ee947faac22e84b0ebae096f95c483b4929344feb71f546e137b6",
        "ab5db659f5111094557078606b94bee35966dc68cc1e74902822bc56a858927f",
        "d47d817b4f940323a066a023ebb60cfb3d91c2323f745430350373dec691a495",
        "6bc1e691cfde1a785e8d525397912fab406f8848b729acc0f1f2c533c05b8a70",
        "131adff07acae209f02888efc42477b211cb738167465978e1a18fab6d12c23c",
        "ad84fe9df2638b1822dfd5f569370f3227bd036091a1c0fd0608301965178850",
        "1d742e9ba2e21e2eeaee8eb886e2e2f6142394f30e2a172fe23c554aa4d5c23a",
        "931cfc21b8dd1241487f51387f00d36e7f180540af972b063a885428e01a8cb1",
        "69d790f9907544fcf6a06532e4e6d6a89b9df31dbd3bc44523ba46b6fc3e271c",
        "32c37953b6af3578539c522624c512f34adc004c7f0ea9e6e76937d048771cbd",
        "b4e3871bed13313a51ad350802d9df7659b0df67674b18eaffb9fde780e6ad66",
        "06a3a211392d296b14f27ac01d24c3b63f5cca373763c7e3c296165f2e70cdf7",
        "5a234e319f3be87b143c7b8a1dcf5407e78ca0cd38b0dd819f7898403af09803",
        "72190009bba7beb174c1068b2013ce905fa457527a81a64742a789ee1a0c8e09",
        "9ed982dd1251bc8ecf345ec9ac6f15a94f63b42348a235681f83f52d6dfc6bbd",
        "d99b38772bb5236cc18159acae2e07d58fd839e8667202d4cc88fb88fd5b671c",
        "6e0e0224d787ed1a3a0b3b4dd32f05c63b3f177b6816506000ca140d99cb9e89",
        "ab2ebc2d00248d537d027b4cddaa2f909ec4ec505b7bd477e92c1e40751590bb",
        "c58ec9edc6394ee3972549d82cd6bcc604f50d17fbe0f09015630b193be19776",
        "fbd89acacbd52a70f83bade340e1ca5e374bbcace265358ecbb4a73ded58f98a",
        "cecad33b21242ebfef444f8c7eb061f157e28c0e327a931d49ea91a15580ac4f",
        "b11861e11ff2d465a48cb68efe2a3d2a582a97a058c9d9209d5a5ba2b666ee57",
        "ca29bc7497c4a0c9ca73cdb3efef66ee4e789b3d412c80aa29f052bcce36d20a",
        "72363d88e437c8b1cf91a8923d96190f27662a13f555b9444f79f773ba7c2986",
        "65bb2376f29cf89a1425a0907c2cf8e068a4ad9b932f3dc504e81a5410b469ad",
        "fc6358ea9287cba16386bbd613d4cb78bfe33c45ae3b445536cad2e565d66f10",
        "1fc658658ed72006c05fb78933926f2c62698811f6372fe6e154117303607b04",
        "14f104af45556b9d359fe901989c9610392eed4d2f13638977c10f9b9dffcf4d",
        "62bc677a59e6ea11f527644b80254b19e592401388d641a399820fcd9131d56b",
        "89a64819315750df19d21c810036e470be6462edfd8ac1a28f92e1cc8ca7acf4",
        "460fc1504227bb4ace26ca3c6a4e572f2e56f8682f5eb073265181899f3d3779",
        "dff32d95d6d42e0a4e6f66894978da2564ffe658d384c1968f6c3cd344cb6f45",
        "5acc732da44c24f760f791f2905e8f724c5defa08b31691a8a758abe6ef2b7c8",
        "ea886b9c1d2f5b8797a30503356fd39eb67ebeb4bd1e0bc9626ff7d80a18925a",
        "ff0431cf20dea7c53a04aeb1f996bedef591dff83916d7e5813b9c6d57e79738",
        "b4d6119b13b371caf6cc9e240c097138aa5b7009b0fad69ffc1c23b0ad7d4635",
        "278eb5e2d4f7b7f2b6145878f08e361e487b6397ddf11c3d19449f54ba720f2b",
        "87349e20a14b6d9ecf34e2f590cdeeb3fd4df6c943bd5b1c9439e1ff815c87ad",
        "42e9dbc450c8858c2fd80729eac862340c26d08409f7607e6a844a0285cb3a77",
        "adc069c2fd56a7669752e9e2ac19710821a3eecf7f134430200f93f6ffa92654",
        "97715248aa97f81c5b4f212775363f27f11c3c1a13e72a16cd356a42ec28fcf5",
        "5b1b2a976c582e23463b176adaac0a456ad346201e162bb6644d13b0369b1d62",
        "1d5db1116c484753f80436b4a4a7c10fbd6f8dae4cf35add44d2042025156293",
        "5066a0acdaee0540fbb842e02f4ea5d2988e99e464267ee2fe60552ac7bac636",
        "148f2e2ce405858ff7af17fd0d1951d1c82180c1dda3e95dda0f49cd32401222",
        "6f1b33ff8f3e5cb2bc59a9c1ebca8854d296f05e7c299bf930b1206d76c0ba35",
        "a9f85de9810e013de101803d18f217e13ee293917f8172d3390d32eda91d6b8c",
        "b53a3b8b21cc8659de0b031d1151f989d6f29dcfc42c29be25ebd1f3401d7abc",
        "325e183bb1d85857081f7e8c9ca8137582976e4fcedad40b9de7af9b424d805e",
        "c89497f90a27a688a9b8e5a7995720754cc09b447ecb7d455419b68cffe39f00",
        "1e8ac1a49b19a029db1bfcad973311f9bd0359660cbc1ef810af6f113921f90e",
        "8f58472c1fbc5240638528de80aff8fc1eedd8f2364bf90747256e10d3aa993d",
        "c74176e5ace2c83fb59481106d159bbdc0bce1d209c167c2ed2c8160346b1e08",
        "243ecea5a0787244d67bb452d2b4c10f37ac69668dcd71f5166c975b6d56a64e",
        "a52911600ea5a6b983e12f81a09949a4c1936807de4d76d98dc07d9a1218d309",
        "d751b66ad5f98380f1e66f1c0fb512b5da36c920552a06d06a1db064ca37ae13",
        "6488b23e0dccd736945f97e8922911798e450d7cb3d00b8212e46942618ed654",
        "1bce25783fa821b20103d186849a19dc5bbdc8638ddf1a447282d06c5b985b87",
        "9aa090fabe3dfa3c70417f54ae9e1f7f88679475665b3312b4a51dc8e2a89719",
        "bab72434e9a2a04cc8708a16ba96065ebc703a204f1d14e54b6381f7e41c6ec6",
        "d1ace25484265bf44ccc4ea9687967050d5a13e2399f151d0f03a25fc166bee3",
        "2a39690ec069e250bfc02e35c70946e16575c2c2e5c8ac3e63ad9ab43b3bef7d",
        "37d11ccdb9bedb8cee0894d606ee918c514dca043d3c70baff8908ac071968e2",
        "555c65be76315f4a7aa0d661ce613cc51d62fd5f88f0c3be5d6537bde9a64e6f",
        "1f2c6dbca5081b8a2b918d2b7a5b857945f0ec34634c54ab7d01cb7efdd10ef6",
        "a09d359159cf7862059c6b270dc6ac27677496a9806e3e1939ab69a5f4bd982b",
        "06569dacc84d3043e9389d609a7dadee797e1059858a3cf17083b976a6bcacb3",
        "bc4adc073674c546dc474967aff391281ca2cb9132063e6d1dccf92d3a7a9ad1",
        "1fe55a13d7251033f45cb7d9c7e0102c6bfc30f1c637fd7badf190bd507ab2b5",
        "32dce867d9b7ebba2db35302f725ae9b5f3fe414cd78685cb4b1c710af969e0d",
        "3df1c47f0edc8d43ff42fde59ea0fd134d2a74506790f8a631cff220d773c884",
        "79848b7eb23bab9d1ea68164b4c333ee275686fe8d116be12a4eccf2aadc60bd",
        "a1a53e76001e94abd450728ccfa2620590d525a16372d9108903667c18ff0a04",
        "5dbb7fff8de71fe0651f263dba1ce63dd81d5e18b921795ab83c02096050b13d",
        "f8ac2c33fee34bc7125fecb0e3b7401c5382938eac74deee788b3d34e154343e",
        "c612aca030a397d9153dafaf0741ba76424167258bb66bba076cc4be3bb5c1b4",
        "f0d761f170a03e7ff42bc44d9eb04c61d4e8a087b009a408d8173a52fc907074",
        "41211ef7e9dc75eccd79375e66b523ee137c51756475e426e671337a403e9182",
        "37659c89134d3f3fe38b0c9824f3687397709376367bb61e5f0109a17f090974",
        "b2f948c987c18eeeeade96b1a7177f8d92efa03d473b9bb2cf58b7044c49abe5",
        "ad9c893e51f6ed6d6b1ce753dce5667693a4cb5a76d6632fbb1b9251efc7f7a3",
        "bdc78758eafb5407cc6fcd444e21fe499f4763ee9886d5074adb043fb3f091be",
        "61aa3c8de9b4642b445c0bec3416c75045f976bdc8966af39b8a177413220c92",
        "9d4ec3301087738ca80c391e52f6f1b55916bee036fa2bff3bf040425b0fc440",
        "df43318f4dedf7bd1ceedaf4eeb05615526a8e84b9777cdefdbdd5e6137a7553",
        "22a787ec912240984aa483b88508f5d42f0709f03036412195c0dce558a13512",
        "281cfd66d19bf1de9ae0cc2b114d0dcc4eb6fd5bea42683cb87a88b9002a3cd4",
        "ee841e26b57372f5028a5ee3bb33d3e6a2b4b0c0475c32d9d521ed5538596d85",
        "5a3acfe2e3f96d31be1540fd4dc1b927d71abca91dc111a8ddfc064ef92daf77",
        "a42e5878bbbde777be1a847a949b357f6e977f62acb86b0df1b61d0111496080",
        "7aa1fd59b6da6a213a9cac65d9efd2bb0bfa3ade0e2d42a12563dee4cebe4c44",
        "d35539023ccf129418b2169c9794f3849af8d93d73f07ac9de4eb40a33bc4339",
        "091cc3c3533ffa3b783384b4bff05ebbbe3b8bddb93653be72e1552e53d37616",
        "f239114efa32b64bf0c0effc46bfde40a8f7fd28fcc5277fcc0965ac20281294",
        "0618c1f3b86e3fef92f45744bbc1ccc0a82db77f65868066dcb4ee9e3bef82b8",
        "f02528772cc6d6117249ed7a3e91570f1fa446d44c89aaed3fef345ad28a100c",
        "a1091b57c6151d8348a9cd335581ae5a52515ddee691b50f1c71753cff438a41",
        "0070f61d2999342097f9c2340361a6b2a47e21f0a48df9ee300c75b321cb12d9",
        "ce2260a82ea8dec0dd25f47db14dbd7a61bc4bdbe7dd103c621632bf7a5ba21b",
        "065b7cfda4b11c8fde342e7e0201d981b5a2acf5075368e4634815a693b3ee3e",
        "414a2cf5449a6ca94a15274008446728eff85074873fbe05ea562aab880d6313",
        "c22ac7cedbf84cb54d76714a832c7f93a74b2b02bba62452884684812e497f34",
        "776126fbc83693b322eed8640e9f703deabf9a1581cec80c8e963404e9f0f47d",
        "849f0790f592238600e9e4ae1ff12f3393d1657ca52b50727562c4183b8c2826",
        "8387956906c2f6a57b14fe940fb19616977ea996db9ca234343571ebf28929c0",
        "03215e51eeab80a70769641baffb7fa6111425ff88906bfc1af8ec9f042221b5",
        "c3d0f8683f5c6ffad349be2e6e9d8926706fd0e8bc6c3edde679642a121e82ed",
        "2438c056a82f448c12b23e4620358045493a170a76ec580f5fde290cd49e60df",
        "8ce595662a14047a28d8e9be28fcfc86fd5df18112513c43f85da64b73f9072c",
        "3b901c76325ea9738873e9dee1fc955f8068ae8bc5eede9cebe6f9776fe4b118",
        "5bb263cb618537c429d059bdd91e7bcb5d05f606a88e06cf2f25d2973ddbc113",
        "69750390d7a9a44a8e0c786a4cda7ddfd57ff3ea16937955cac8aa8ffda07219",
        "b2113668d4f27b38b29963a2d0c582f8fe95aad31c3b21cf626718ca94892482",
        "ab6b6d37269f90abd9a222f2b241cf3c7ca15904a13010144d108141d74e147e",
        "b3c532544e19d3297ad0654c92061b43d541becca6096fa253b7ed509d9ae189",
        "c264a7f21744ca68a07f39d01936638f420f3e1998d3269bbd1fac0557170c60",
        "42d4051ed6d2a2ba670b16a8d0f9d14b8ff5e38354c9f5e55d5102f0f292b1f3",
        "4d78737ace4f805cd5411ef1ae0a9e2a798b45bc11e9fff4d348dcfcee8f42c6",
        "0a2a01cc2506486a049c98df7b151b77d75cea67921224152fc10c53ea352b25",
        "337a92c293a11d777a82d85a6480994d3b8324fc78ed0d507c4ccf3dcd236a9e",
        "71997103ee3a1f016aea1595c8d3b7b778792cb037d03ce733ce67b27a08e0b5",
        "d61ff1cb4f2e157f248dac466b2ab297599367fda32a6a52c1842d750268dff5",
        "bbffef94731ef2f4a9ab21f90bf70a4d8e87d24a90406e5515db6cec99ddaa90",
        "1ef38ecf4b91592fb0f08f8382314d06d951270bf3760a2411965e0e82a0449c",
        "09c30b8533faa48e003280ec910ce77b2d4fe9293a8af1740c62be38146fdf60",
        "861dacde4967d2aa400c516800dac0a923daad6c040db5ba7b6dd020e6cb6b66",
        "56356e3420f88cf76e676e381fd9abe046240f1c5f3b9e0a0fa75efbacb7d190",
        "956d0e1e9fb913152afac367ffb432ec957784805f19d969592ee3eb7d4700df",
        "d440a82d19ac13c504a467be198256cca9edd95e613029a5b94b13033a19ee23",
        "e58e3b9f5704d845e8f5ffdba821d651b57d10ce94a23ee6bb9362d785377f6d",
        "652faecf6414f44a61f83a41bf7471ef8d857c62455c8e49fec8567c53e9cccf",
        "95215cf5f073b74b8cf9fa6193f0804b8bbdb7a8b280a3647943abb81320c8c6",
        "bb6a21ca848eebd050ee5acc2bec5d06334d206ce8a00d576a2235eb53e93ca3",
        "9ebf65c67fa011c4d5b0cc7be3ab146617badf2e313c7803a97eb60ac914ed61",
        "bcbe975936802665c69b490266303f2d6dea2a9730a3533b05fc5e9d662a50c7",
        "795c25ca0698c3c28039cd9346bb2d5e8cf61d8b7697a3c600defa6afd10b6d2",
        "dc7f1e32c5d23e0bad9233eb900f6b04633ce504f531e2df9f53d53e8b46c312",
        "76018dfe4c387b1de78730115700a45f71f75b822ada50ab5ebf35aa392f5119",
        "b2b52313d058516fdd52f4b3a5422bd5ad88e7ae0e21ec37ca094de16b65af4f",
        "dd63781fbe7179c0e97b67052d852023718b2d9d9fad77a20367901564c0df00",
        "b93ebcc14628777fbbfd21ea06defe3f723ae08477126cece38ae112074c9c59",
        "2639be3d392f3df20d9c77e07bff2861549c2e8e4f688af3f454d812759fbe7b",
        "f7d6f0b48ed2e333f6f566b158834e1726451c8a435ebc8376d98dc5b8987a9e",
        "002e294231f869bb73158ade98ad37203a8f46227e8613b1920dcafc55644b03",
        "e7a6ac4ea049a40ede51b6406581aae3aff2de5099fe49023348b588abce0dcb",
        "ce7586aa4434eaa1d531e130e82819cb5d9c8ea6c95b703565f604a8b15a14fa",
        "8195ec54a7a690c38bd2f535d313bbc7f1d1af8414108c7ca05431c79c0922d1",
        "58a1960343cab1c4977aca073b27d898dc8f5310dead52a57691429d389eb0bd",
        "bb95ed9edb2660359a44cfc70ebd5a9e442327d1ab7bb1cf14196a36a1c6aa27",
        "0bb250ece3f690723298898b0b0efc9442fbb7e8967138be20e29e04983075b3",
        "7092b0336fd60a1a6e24b62bf22244fc431eba64f213bd8f5d9de2865379da69",
        "5ee5252fba29d669205ce91153b443ddb21540f9da36da0e066e30cfbc85dfa3",
        "9e0dd4e1d4a0c7a6ec4a7ade373efc107f810377f1d3b0327490ef63dc865df6",
        "9dea4389f111c9fc3e370794b0da274de8d5d4dea3d593d8af45c3186a5139bd",
        "cbc538560908ba70b0b103101f05cee12bed8812dc01be3670d2b8634351a433",
        "9b4663f636ef04ac5756f673ecaeb166ce9b228ecfe9a79750d1fac91e9cfaa1",
        "edeed2f6b8acbb7081335a602c012b6d97e0393fc29d3ebeeab71465cbb20471",
        "97ae0bfe76a1554bdbd78c39cb9fbaf1567f274dc3901300fb8ec01e95e17c26",
        "a9646079729df8afbd182a588282c7ea65e7dab177cb5b1cef373700ed166d79",
        "22c78b424753cd7782cd7c38ecea7670323760c5a8ed21513bdd537e732985ee",
        "eb33e4b7f546160ceaa89f6a1adbb0aa1c324185a85aaf05f9e11dd3a30f8963",
        "c48f2b8c57afcce911b86d9027207b54abf304d18c8936f556039f34b420a22e",
        "cbc29bceff35b2c14d682667a78f56c76279dda0dea1d3567e699be211914b46",
        "3a0c64ab17e9b542e45cb1cd0c874d766fb945c309bc19f91c8b2d06b7a3bf86",
        "392a11bda08147c02e63bdf4421fdb54b72148cdd09026855fbdb25811e924db",
        "8a64d5244c4945230e6d979ceb0969f418119c9cdb7778bd93a74f0ed6f9ea68",
        "f148c9d0668baea63ce495ec2dd3b1fb46c1eebd6dc1d4c4d4851aaa8b53d8c3",
        "721e0bbcc3054385e2dac368b466e3c4ad636113d8667eda7c0e9a027f7d459b",
        "98a769b47312ace49da42ee3e1695e290c142f3109ef1f36928cac6af12246a2",
        "75e25a186e4bc987c6b365dca378ae777c07a3a2b4295a1ff12bb88de5121237",
        "7b0b452b0351674d1137d1ae22a56a6574885d41f000771f4c0e5cc27c030eb2",
        "49fc7e713bae4e7e37c0313319020ac243d46693b10ac3a273325d65964bcb73",
        "4421d386d3970949e03749c43bf28e4f2801400abdd466f96b925c34668f3686",
        "fd8c550467d4e471a3b6a27a74e95583d2b2938ca2c5f93ad4c3a18007fd2fd0",
        "50ad260fad06a4c851d004915feb9d42b0e96dc50f0cffc724d844b3d6e2cf08",
        "2756821e3e180586117a659330259fb8b7f59aaaa2c376eea90c9cd15a118f98",
        "7aa0baf58d27f0e589d066c16b06821aa573610f30d9420d4d7d6d906b42ca0d",
        "af8a25f12472deaadb721ac97740874bc410a52b57a7d4629e140c8548d0d777",
        "3113cbf56a24970b2560c0891223197a773acf3aa1bff62dfb4c93d416865388",
        "22ae2fd22720bf9ac91447b76ff82591d5acc4cd43ad243267ab4b722d537951",
        "45abd184ee741e6b2300d4e77cda05c55bac64902726b38514917c4be11a700f",
        "9a93beb5b1748349996c5a68f28e5db1b3dc43f35b53522ecb347035c45cc8f9",
        "9ed838276797a35681787184ac33677bd2c0b8847d57580c7110b45b86ab5552",
        "6bfc26bcf180f5e954f6b183bbf5f364d608ac715aa210a59b6569d44682f298",
        "9cd151509dd68fdd7a6aca93ddc1350c9dbe236bef141d0baaae4e0fee69a534",
        "86eb8328c8a48a7311d337418f8a23ffb79f5b38b08b9cfc8c07133a32b5d43a",
        "8bb6be0f033075b093368c1f3d5500037418cb5275a3beb9f71b417e791b4834",
        "25e73888097d609b4dfc49f856cee142847c5bb169cbef4f9b25c27958870435",
        "0ddd3c46363a727f314e5d8fe566177e69ed9f0efde27d249dde470587cf7f63",
        "be16d705d7ca159048dea82bc2752db8c8fb86c64c597754c609e9e9aba97b87",
        "0d8d72b0e270abf5c8951f1065fd97ba42f2879b58d940922ecc61afcd8c9896",
        "0b9315ebd59b4bf0bfa8aae499d808e32a68277a6d857517630cb026412a6047",
        "033db49568e184ae4c421f5b1524201c3f289517a26e9eeb8d0e1b8594118807",
        "f77f2c428e39f86861bb5eab724b6b191975ea1623a9010f73aa8536ff1cecec",
        "57d9fe07581fac965c7b1577bb4d5389871af714cd6490c9bcb0ea313dd438c5",
    ];

    // Existence vector 2: Existence proof for key fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
    const EXIST_KEY_2: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe";
    const EXIST_VAL_2: &str = "4343434343434343434343434343434343434343434343434343434343434343";
    const EXIST_PID_2: &str = "docling@2.3.1";
    const EXIST_CPV_2: &str = "v1";
    const EXIST_ROOT_2: &str = "f7beb01818ec9fe29f5316b6add63a010749f428b3f71f177f47b59a2f268bc5";
    const EXIST_SIBS_2: &[&str] = &[
        "0c51a9c6fd8dd8847ba1053a17f62943c59052f4e311ab4e93867c4280579f29",
        "852685c9f513ed3320b29181465d8c6be247a8fd62998720e2ff275f47d84ded",
        "59dfc03f234687956c138401b10edcd64642233704630146bb34c72eba11a08b",
        "43d66b4de4a949b7be017c58ab3ea9c9d62663645b0258391ce2f110aee7af27",
        "2c79daced5a64e3d21c92d4f4b6518bac4ca12aad1dabf838400f7770b3ca81c",
        "45eabf069297deac076b6cd53484f1b4909c090cac787b5e54cf1fc75cf733ac",
        "576424c7e4488dcaf988ccd7f1df5129f7e26f56b5493ac501b69f66e90f7d4e",
        "fdbd6e678614b8a1c24e5a2bc96569aa9aa56cd9576a2e55699130e9d7fe88f3",
        "76f88eccca303650ae6e704fc541c98e23307bd23fb5ad24ead77894ada86e47",
        "f9125609b79e56aab4b7e1c773b239712fc7776dd776a2909c76cd97886ffa52",
        "4d78a02e0d1828a30054119b94a3a4298583f6dd3ef7607d892079683655f1e8",
        "e236cc712e09d59458e2ec848ab19b807bfdf8d8d02de77fbd5c0a7b7a141836",
        "cab76db206af544ad6b6a84d8a030c07711938c6dd6c423580ae9c04f1db0ff6",
        "711a5f331bd040912ad85fbabf2685460011f89be6066e76528bc01c302fd358",
        "133420cca013ea2edf4c4546f91960c4f73c9092c0a775d43a2016f8ce36f671",
        "c581a45eb2ceb7567419e459bf3e739e12f714c7f8469e8e479fbaa8434f2877",
        "f00f5cec01054f28c176a3b0331696f4ff09c46e0b2b3d63c394c5c4fa8c7033",
        "a9da3bc38058e04f3ddf6961f59c111039440693597cfe84a37bed0e4f4082dc",
        "f4c4b845e4e175129a659b715a9c06e5144a2c96f8f6e827e541ee48702777b0",
        "b4806d77ffec8175de8aed7c1160515b9c58f9e466c248cb015b2236e70d2769",
        "d5144e319bf2f12d97779b9a83aaa6cedfc7cbf42512858a4eb4023887036fcb",
        "7507c0868e89bb148cdbbb608b5829cf5bbdea6d86d055728eb9a2d5aaf2d625",
        "281de96d976a6895c2614689d4988f7620e8093b6302cdc0cb005029b8472989",
        "c080d6bf352dcecb167121a1a35236a595551e909c8eed7dd2220e123addd361",
        "c55efd3763e9e65bbb132ee9e7ee45f19b557ea43875893c0018970775908135",
        "35504e641f1e5ef49858700b5ab52ceb5e3d354b9652e549e6e38e54bffb2b8f",
        "5fa1b4251e7b0e3131479f17b7de4c65ff46dcdf1720bbfa711708392898630c",
        "ae6d787e9b4a7ee9e1e2ed0323ae65fb17d4c707bf71c96b2298d0b2d5eaa5c4",
        "e3d45305e32fcb10069fb9238a9458e16cc4cbc0d4ec506be014ecc2291fb845",
        "361ca179b035a1dbbaffeb1f509bfee0f15afa64d76e7b9e67eadbd86727a932",
        "75fa8ebcd7024b65a0c69adb52ec73799636a592507eab85b6cbb329409cd2c2",
        "b49698faf87e9e2bde213222589bdf6d41a9c0aae2ddbc6a9fa5d6e0e900b8a0",
        "bb8a615dfcb2eba70a0312efde0e297b87a5d86c1cac2d50a97c182e65659b25",
        "657af470826babc0ca494179abef07ef8ba069bcb915e60bbc9853516c65676c",
        "2681601cd3992c6387eddae5e3493fb66ce4acb7888f625c6159bcd1f7d51d4e",
        "4d5d52ec0726655f634eba604085d1b9a274db2358d5bd2e43d28072f28e4d0f",
        "acdfaaa936a5ef2c552feaafc17d06faf10ce792b87e68e44f3d5293447110ad",
        "9803967ded03a85db08cb546b5cac2e8fc708a9584751810c415e847530bf12d",
        "255701fb5252f0f11f2014232d739477204680bbbe78b95fe22e257c7c3fa1c3",
        "522deafd551686dc437d0241d46dfc8ed9bb26672b946249dd5a674723cc1929",
        "64d4ba29e80f8f27248bb93e2be10446f32fb01e39563902db252bcbf609aad4",
        "cf8d37560fb3c362d0fad2e2e0ebbd2a214e2b4aec4acb1fa3805690119c76d5",
        "ab39d85c7efc8273bec98ed3e0933e0795abcb607e79daa4b32c76ac651aeda6",
        "a6399bcec0e2eea7caa73166f69e50c38e65faf87067ba88e51ef1c084b60178",
        "2902519fa5abb8f1c8e72fa98b651742ab8752d26ef3a6f150936a8f0216cb02",
        "1176fd190cde55c9ed750d31960c216f6d8b5a2608b111103ab4d9f61c2af836",
        "a1e87be6b964f11f1500f0409e394b24e4c60a2c1804becea8447fa38be2abbf",
        "510e56c502e3ccd90bde5c283c270b2f1adb9527e84cb7888861aee8277b425d",
        "76915cfa634971ebb5ca96a572989121b0f417435554e75cfd3caf1cc7538024",
        "7a08c762b99b74153b0ec7e17c47ab815c4e69c70a17f4c725df18d3c24ba938",
        "a7dceb5481fa19d145a3d854175eacb317f88d79cd858e8010b0cd388f2e59fd",
        "ec2d7b7ce77e2657011c615e6ddf88b499a35321622cf31b73ecea6b6d5ec9aa",
        "ba2061307e6e1e3ba1a1e772e5aaea89f81204e33082374abfe65727e9487df6",
        "2e6d0ab3b8b58f74e5e513f6102594788a96914cedd90fbf65c328c61c607503",
        "b8ec6f052a2fe798e1dd3bbfa765174e9e4b75d4cb3a60e1c70569205872983c",
        "98a9f11b47cce0d2838e5fa3f2c4284f678896aff1783493a31c72cf1929aa2d",
        "01da07349b99ceb0961bab0dd84fe57bc9bcf42567cbbaec8f23c6fa77ed6198",
        "4250d7b736d3856ef3e94ec4e2f55d09349a8afbb533dd6f4238922682520c67",
        "5c93174c5be3dde79005da679860f5e0fee64f22be9d3fc456b8503accd2bc9b",
        "933ce3a0ed1a23a0cb863203123e1a896a33a1ef642b0688e48d4ad70a358258",
        "88824f69d2635e5d284933a353391242664cf4fa4143a06c4c8ca5a2dc54d706",
        "24986d31ce8ee947faac22e84b0ebae096f95c483b4929344feb71f546e137b6",
        "ab5db659f5111094557078606b94bee35966dc68cc1e74902822bc56a858927f",
        "d47d817b4f940323a066a023ebb60cfb3d91c2323f745430350373dec691a495",
        "6bc1e691cfde1a785e8d525397912fab406f8848b729acc0f1f2c533c05b8a70",
        "131adff07acae209f02888efc42477b211cb738167465978e1a18fab6d12c23c",
        "ad84fe9df2638b1822dfd5f569370f3227bd036091a1c0fd0608301965178850",
        "1d742e9ba2e21e2eeaee8eb886e2e2f6142394f30e2a172fe23c554aa4d5c23a",
        "931cfc21b8dd1241487f51387f00d36e7f180540af972b063a885428e01a8cb1",
        "69d790f9907544fcf6a06532e4e6d6a89b9df31dbd3bc44523ba46b6fc3e271c",
        "32c37953b6af3578539c522624c512f34adc004c7f0ea9e6e76937d048771cbd",
        "b4e3871bed13313a51ad350802d9df7659b0df67674b18eaffb9fde780e6ad66",
        "06a3a211392d296b14f27ac01d24c3b63f5cca373763c7e3c296165f2e70cdf7",
        "5a234e319f3be87b143c7b8a1dcf5407e78ca0cd38b0dd819f7898403af09803",
        "72190009bba7beb174c1068b2013ce905fa457527a81a64742a789ee1a0c8e09",
        "9ed982dd1251bc8ecf345ec9ac6f15a94f63b42348a235681f83f52d6dfc6bbd",
        "d99b38772bb5236cc18159acae2e07d58fd839e8667202d4cc88fb88fd5b671c",
        "6e0e0224d787ed1a3a0b3b4dd32f05c63b3f177b6816506000ca140d99cb9e89",
        "ab2ebc2d00248d537d027b4cddaa2f909ec4ec505b7bd477e92c1e40751590bb",
        "c58ec9edc6394ee3972549d82cd6bcc604f50d17fbe0f09015630b193be19776",
        "fbd89acacbd52a70f83bade340e1ca5e374bbcace265358ecbb4a73ded58f98a",
        "cecad33b21242ebfef444f8c7eb061f157e28c0e327a931d49ea91a15580ac4f",
        "b11861e11ff2d465a48cb68efe2a3d2a582a97a058c9d9209d5a5ba2b666ee57",
        "ca29bc7497c4a0c9ca73cdb3efef66ee4e789b3d412c80aa29f052bcce36d20a",
        "72363d88e437c8b1cf91a8923d96190f27662a13f555b9444f79f773ba7c2986",
        "65bb2376f29cf89a1425a0907c2cf8e068a4ad9b932f3dc504e81a5410b469ad",
        "fc6358ea9287cba16386bbd613d4cb78bfe33c45ae3b445536cad2e565d66f10",
        "1fc658658ed72006c05fb78933926f2c62698811f6372fe6e154117303607b04",
        "14f104af45556b9d359fe901989c9610392eed4d2f13638977c10f9b9dffcf4d",
        "62bc677a59e6ea11f527644b80254b19e592401388d641a399820fcd9131d56b",
        "89a64819315750df19d21c810036e470be6462edfd8ac1a28f92e1cc8ca7acf4",
        "460fc1504227bb4ace26ca3c6a4e572f2e56f8682f5eb073265181899f3d3779",
        "dff32d95d6d42e0a4e6f66894978da2564ffe658d384c1968f6c3cd344cb6f45",
        "5acc732da44c24f760f791f2905e8f724c5defa08b31691a8a758abe6ef2b7c8",
        "ea886b9c1d2f5b8797a30503356fd39eb67ebeb4bd1e0bc9626ff7d80a18925a",
        "ff0431cf20dea7c53a04aeb1f996bedef591dff83916d7e5813b9c6d57e79738",
        "b4d6119b13b371caf6cc9e240c097138aa5b7009b0fad69ffc1c23b0ad7d4635",
        "278eb5e2d4f7b7f2b6145878f08e361e487b6397ddf11c3d19449f54ba720f2b",
        "87349e20a14b6d9ecf34e2f590cdeeb3fd4df6c943bd5b1c9439e1ff815c87ad",
        "42e9dbc450c8858c2fd80729eac862340c26d08409f7607e6a844a0285cb3a77",
        "adc069c2fd56a7669752e9e2ac19710821a3eecf7f134430200f93f6ffa92654",
        "97715248aa97f81c5b4f212775363f27f11c3c1a13e72a16cd356a42ec28fcf5",
        "5b1b2a976c582e23463b176adaac0a456ad346201e162bb6644d13b0369b1d62",
        "1d5db1116c484753f80436b4a4a7c10fbd6f8dae4cf35add44d2042025156293",
        "5066a0acdaee0540fbb842e02f4ea5d2988e99e464267ee2fe60552ac7bac636",
        "148f2e2ce405858ff7af17fd0d1951d1c82180c1dda3e95dda0f49cd32401222",
        "6f1b33ff8f3e5cb2bc59a9c1ebca8854d296f05e7c299bf930b1206d76c0ba35",
        "a9f85de9810e013de101803d18f217e13ee293917f8172d3390d32eda91d6b8c",
        "b53a3b8b21cc8659de0b031d1151f989d6f29dcfc42c29be25ebd1f3401d7abc",
        "325e183bb1d85857081f7e8c9ca8137582976e4fcedad40b9de7af9b424d805e",
        "c89497f90a27a688a9b8e5a7995720754cc09b447ecb7d455419b68cffe39f00",
        "1e8ac1a49b19a029db1bfcad973311f9bd0359660cbc1ef810af6f113921f90e",
        "8f58472c1fbc5240638528de80aff8fc1eedd8f2364bf90747256e10d3aa993d",
        "c74176e5ace2c83fb59481106d159bbdc0bce1d209c167c2ed2c8160346b1e08",
        "243ecea5a0787244d67bb452d2b4c10f37ac69668dcd71f5166c975b6d56a64e",
        "a52911600ea5a6b983e12f81a09949a4c1936807de4d76d98dc07d9a1218d309",
        "d751b66ad5f98380f1e66f1c0fb512b5da36c920552a06d06a1db064ca37ae13",
        "6488b23e0dccd736945f97e8922911798e450d7cb3d00b8212e46942618ed654",
        "1bce25783fa821b20103d186849a19dc5bbdc8638ddf1a447282d06c5b985b87",
        "9aa090fabe3dfa3c70417f54ae9e1f7f88679475665b3312b4a51dc8e2a89719",
        "bab72434e9a2a04cc8708a16ba96065ebc703a204f1d14e54b6381f7e41c6ec6",
        "d1ace25484265bf44ccc4ea9687967050d5a13e2399f151d0f03a25fc166bee3",
        "2a39690ec069e250bfc02e35c70946e16575c2c2e5c8ac3e63ad9ab43b3bef7d",
        "37d11ccdb9bedb8cee0894d606ee918c514dca043d3c70baff8908ac071968e2",
        "555c65be76315f4a7aa0d661ce613cc51d62fd5f88f0c3be5d6537bde9a64e6f",
        "1f2c6dbca5081b8a2b918d2b7a5b857945f0ec34634c54ab7d01cb7efdd10ef6",
        "a09d359159cf7862059c6b270dc6ac27677496a9806e3e1939ab69a5f4bd982b",
        "06569dacc84d3043e9389d609a7dadee797e1059858a3cf17083b976a6bcacb3",
        "bc4adc073674c546dc474967aff391281ca2cb9132063e6d1dccf92d3a7a9ad1",
        "1fe55a13d7251033f45cb7d9c7e0102c6bfc30f1c637fd7badf190bd507ab2b5",
        "32dce867d9b7ebba2db35302f725ae9b5f3fe414cd78685cb4b1c710af969e0d",
        "3df1c47f0edc8d43ff42fde59ea0fd134d2a74506790f8a631cff220d773c884",
        "79848b7eb23bab9d1ea68164b4c333ee275686fe8d116be12a4eccf2aadc60bd",
        "a1a53e76001e94abd450728ccfa2620590d525a16372d9108903667c18ff0a04",
        "5dbb7fff8de71fe0651f263dba1ce63dd81d5e18b921795ab83c02096050b13d",
        "f8ac2c33fee34bc7125fecb0e3b7401c5382938eac74deee788b3d34e154343e",
        "c612aca030a397d9153dafaf0741ba76424167258bb66bba076cc4be3bb5c1b4",
        "f0d761f170a03e7ff42bc44d9eb04c61d4e8a087b009a408d8173a52fc907074",
        "41211ef7e9dc75eccd79375e66b523ee137c51756475e426e671337a403e9182",
        "37659c89134d3f3fe38b0c9824f3687397709376367bb61e5f0109a17f090974",
        "b2f948c987c18eeeeade96b1a7177f8d92efa03d473b9bb2cf58b7044c49abe5",
        "ad9c893e51f6ed6d6b1ce753dce5667693a4cb5a76d6632fbb1b9251efc7f7a3",
        "bdc78758eafb5407cc6fcd444e21fe499f4763ee9886d5074adb043fb3f091be",
        "61aa3c8de9b4642b445c0bec3416c75045f976bdc8966af39b8a177413220c92",
        "9d4ec3301087738ca80c391e52f6f1b55916bee036fa2bff3bf040425b0fc440",
        "df43318f4dedf7bd1ceedaf4eeb05615526a8e84b9777cdefdbdd5e6137a7553",
        "22a787ec912240984aa483b88508f5d42f0709f03036412195c0dce558a13512",
        "281cfd66d19bf1de9ae0cc2b114d0dcc4eb6fd5bea42683cb87a88b9002a3cd4",
        "ee841e26b57372f5028a5ee3bb33d3e6a2b4b0c0475c32d9d521ed5538596d85",
        "5a3acfe2e3f96d31be1540fd4dc1b927d71abca91dc111a8ddfc064ef92daf77",
        "a42e5878bbbde777be1a847a949b357f6e977f62acb86b0df1b61d0111496080",
        "7aa1fd59b6da6a213a9cac65d9efd2bb0bfa3ade0e2d42a12563dee4cebe4c44",
        "d35539023ccf129418b2169c9794f3849af8d93d73f07ac9de4eb40a33bc4339",
        "091cc3c3533ffa3b783384b4bff05ebbbe3b8bddb93653be72e1552e53d37616",
        "f239114efa32b64bf0c0effc46bfde40a8f7fd28fcc5277fcc0965ac20281294",
        "0618c1f3b86e3fef92f45744bbc1ccc0a82db77f65868066dcb4ee9e3bef82b8",
        "f02528772cc6d6117249ed7a3e91570f1fa446d44c89aaed3fef345ad28a100c",
        "a1091b57c6151d8348a9cd335581ae5a52515ddee691b50f1c71753cff438a41",
        "0070f61d2999342097f9c2340361a6b2a47e21f0a48df9ee300c75b321cb12d9",
        "ce2260a82ea8dec0dd25f47db14dbd7a61bc4bdbe7dd103c621632bf7a5ba21b",
        "065b7cfda4b11c8fde342e7e0201d981b5a2acf5075368e4634815a693b3ee3e",
        "414a2cf5449a6ca94a15274008446728eff85074873fbe05ea562aab880d6313",
        "c22ac7cedbf84cb54d76714a832c7f93a74b2b02bba62452884684812e497f34",
        "776126fbc83693b322eed8640e9f703deabf9a1581cec80c8e963404e9f0f47d",
        "849f0790f592238600e9e4ae1ff12f3393d1657ca52b50727562c4183b8c2826",
        "8387956906c2f6a57b14fe940fb19616977ea996db9ca234343571ebf28929c0",
        "03215e51eeab80a70769641baffb7fa6111425ff88906bfc1af8ec9f042221b5",
        "c3d0f8683f5c6ffad349be2e6e9d8926706fd0e8bc6c3edde679642a121e82ed",
        "2438c056a82f448c12b23e4620358045493a170a76ec580f5fde290cd49e60df",
        "8ce595662a14047a28d8e9be28fcfc86fd5df18112513c43f85da64b73f9072c",
        "3b901c76325ea9738873e9dee1fc955f8068ae8bc5eede9cebe6f9776fe4b118",
        "5bb263cb618537c429d059bdd91e7bcb5d05f606a88e06cf2f25d2973ddbc113",
        "69750390d7a9a44a8e0c786a4cda7ddfd57ff3ea16937955cac8aa8ffda07219",
        "b2113668d4f27b38b29963a2d0c582f8fe95aad31c3b21cf626718ca94892482",
        "ab6b6d37269f90abd9a222f2b241cf3c7ca15904a13010144d108141d74e147e",
        "b3c532544e19d3297ad0654c92061b43d541becca6096fa253b7ed509d9ae189",
        "c264a7f21744ca68a07f39d01936638f420f3e1998d3269bbd1fac0557170c60",
        "42d4051ed6d2a2ba670b16a8d0f9d14b8ff5e38354c9f5e55d5102f0f292b1f3",
        "4d78737ace4f805cd5411ef1ae0a9e2a798b45bc11e9fff4d348dcfcee8f42c6",
        "0a2a01cc2506486a049c98df7b151b77d75cea67921224152fc10c53ea352b25",
        "337a92c293a11d777a82d85a6480994d3b8324fc78ed0d507c4ccf3dcd236a9e",
        "71997103ee3a1f016aea1595c8d3b7b778792cb037d03ce733ce67b27a08e0b5",
        "d61ff1cb4f2e157f248dac466b2ab297599367fda32a6a52c1842d750268dff5",
        "bbffef94731ef2f4a9ab21f90bf70a4d8e87d24a90406e5515db6cec99ddaa90",
        "1ef38ecf4b91592fb0f08f8382314d06d951270bf3760a2411965e0e82a0449c",
        "09c30b8533faa48e003280ec910ce77b2d4fe9293a8af1740c62be38146fdf60",
        "861dacde4967d2aa400c516800dac0a923daad6c040db5ba7b6dd020e6cb6b66",
        "56356e3420f88cf76e676e381fd9abe046240f1c5f3b9e0a0fa75efbacb7d190",
        "956d0e1e9fb913152afac367ffb432ec957784805f19d969592ee3eb7d4700df",
        "d440a82d19ac13c504a467be198256cca9edd95e613029a5b94b13033a19ee23",
        "e58e3b9f5704d845e8f5ffdba821d651b57d10ce94a23ee6bb9362d785377f6d",
        "652faecf6414f44a61f83a41bf7471ef8d857c62455c8e49fec8567c53e9cccf",
        "95215cf5f073b74b8cf9fa6193f0804b8bbdb7a8b280a3647943abb81320c8c6",
        "bb6a21ca848eebd050ee5acc2bec5d06334d206ce8a00d576a2235eb53e93ca3",
        "9ebf65c67fa011c4d5b0cc7be3ab146617badf2e313c7803a97eb60ac914ed61",
        "bcbe975936802665c69b490266303f2d6dea2a9730a3533b05fc5e9d662a50c7",
        "795c25ca0698c3c28039cd9346bb2d5e8cf61d8b7697a3c600defa6afd10b6d2",
        "dc7f1e32c5d23e0bad9233eb900f6b04633ce504f531e2df9f53d53e8b46c312",
        "76018dfe4c387b1de78730115700a45f71f75b822ada50ab5ebf35aa392f5119",
        "b2b52313d058516fdd52f4b3a5422bd5ad88e7ae0e21ec37ca094de16b65af4f",
        "dd63781fbe7179c0e97b67052d852023718b2d9d9fad77a20367901564c0df00",
        "b93ebcc14628777fbbfd21ea06defe3f723ae08477126cece38ae112074c9c59",
        "2639be3d392f3df20d9c77e07bff2861549c2e8e4f688af3f454d812759fbe7b",
        "f7d6f0b48ed2e333f6f566b158834e1726451c8a435ebc8376d98dc5b8987a9e",
        "002e294231f869bb73158ade98ad37203a8f46227e8613b1920dcafc55644b03",
        "e7a6ac4ea049a40ede51b6406581aae3aff2de5099fe49023348b588abce0dcb",
        "ce7586aa4434eaa1d531e130e82819cb5d9c8ea6c95b703565f604a8b15a14fa",
        "8195ec54a7a690c38bd2f535d313bbc7f1d1af8414108c7ca05431c79c0922d1",
        "58a1960343cab1c4977aca073b27d898dc8f5310dead52a57691429d389eb0bd",
        "bb95ed9edb2660359a44cfc70ebd5a9e442327d1ab7bb1cf14196a36a1c6aa27",
        "0bb250ece3f690723298898b0b0efc9442fbb7e8967138be20e29e04983075b3",
        "7092b0336fd60a1a6e24b62bf22244fc431eba64f213bd8f5d9de2865379da69",
        "5ee5252fba29d669205ce91153b443ddb21540f9da36da0e066e30cfbc85dfa3",
        "9e0dd4e1d4a0c7a6ec4a7ade373efc107f810377f1d3b0327490ef63dc865df6",
        "9dea4389f111c9fc3e370794b0da274de8d5d4dea3d593d8af45c3186a5139bd",
        "cbc538560908ba70b0b103101f05cee12bed8812dc01be3670d2b8634351a433",
        "9b4663f636ef04ac5756f673ecaeb166ce9b228ecfe9a79750d1fac91e9cfaa1",
        "edeed2f6b8acbb7081335a602c012b6d97e0393fc29d3ebeeab71465cbb20471",
        "97ae0bfe76a1554bdbd78c39cb9fbaf1567f274dc3901300fb8ec01e95e17c26",
        "a9646079729df8afbd182a588282c7ea65e7dab177cb5b1cef373700ed166d79",
        "22c78b424753cd7782cd7c38ecea7670323760c5a8ed21513bdd537e732985ee",
        "eb33e4b7f546160ceaa89f6a1adbb0aa1c324185a85aaf05f9e11dd3a30f8963",
        "c48f2b8c57afcce911b86d9027207b54abf304d18c8936f556039f34b420a22e",
        "cbc29bceff35b2c14d682667a78f56c76279dda0dea1d3567e699be211914b46",
        "3a0c64ab17e9b542e45cb1cd0c874d766fb945c309bc19f91c8b2d06b7a3bf86",
        "392a11bda08147c02e63bdf4421fdb54b72148cdd09026855fbdb25811e924db",
        "8a64d5244c4945230e6d979ceb0969f418119c9cdb7778bd93a74f0ed6f9ea68",
        "f148c9d0668baea63ce495ec2dd3b1fb46c1eebd6dc1d4c4d4851aaa8b53d8c3",
        "721e0bbcc3054385e2dac368b466e3c4ad636113d8667eda7c0e9a027f7d459b",
        "98a769b47312ace49da42ee3e1695e290c142f3109ef1f36928cac6af12246a2",
        "75e25a186e4bc987c6b365dca378ae777c07a3a2b4295a1ff12bb88de5121237",
        "7b0b452b0351674d1137d1ae22a56a6574885d41f000771f4c0e5cc27c030eb2",
        "49fc7e713bae4e7e37c0313319020ac243d46693b10ac3a273325d65964bcb73",
        "4421d386d3970949e03749c43bf28e4f2801400abdd466f96b925c34668f3686",
        "fd8c550467d4e471a3b6a27a74e95583d2b2938ca2c5f93ad4c3a18007fd2fd0",
        "50ad260fad06a4c851d004915feb9d42b0e96dc50f0cffc724d844b3d6e2cf08",
        "2756821e3e180586117a659330259fb8b7f59aaaa2c376eea90c9cd15a118f98",
        "7aa0baf58d27f0e589d066c16b06821aa573610f30d9420d4d7d6d906b42ca0d",
        "af8a25f12472deaadb721ac97740874bc410a52b57a7d4629e140c8548d0d777",
        "3113cbf56a24970b2560c0891223197a773acf3aa1bff62dfb4c93d416865388",
        "22ae2fd22720bf9ac91447b76ff82591d5acc4cd43ad243267ab4b722d537951",
        "45abd184ee741e6b2300d4e77cda05c55bac64902726b38514917c4be11a700f",
        "9a93beb5b1748349996c5a68f28e5db1b3dc43f35b53522ecb347035c45cc8f9",
        "9ed838276797a35681787184ac33677bd2c0b8847d57580c7110b45b86ab5552",
        "6bfc26bcf180f5e954f6b183bbf5f364d608ac715aa210a59b6569d44682f298",
        "9cd151509dd68fdd7a6aca93ddc1350c9dbe236bef141d0baaae4e0fee69a534",
        "86eb8328c8a48a7311d337418f8a23ffb79f5b38b08b9cfc8c07133a32b5d43a",
        "8bb6be0f033075b093368c1f3d5500037418cb5275a3beb9f71b417e791b4834",
        "25e73888097d609b4dfc49f856cee142847c5bb169cbef4f9b25c27958870435",
        "0ddd3c46363a727f314e5d8fe566177e69ed9f0efde27d249dde470587cf7f63",
        "be16d705d7ca159048dea82bc2752db8c8fb86c64c597754c609e9e9aba97b87",
        "0d8d72b0e270abf5c8951f1065fd97ba42f2879b58d940922ecc61afcd8c9896",
        "0b9315ebd59b4bf0bfa8aae499d808e32a68277a6d857517630cb026412a6047",
        "033db49568e184ae4c421f5b1524201c3f289517a26e9eeb8d0e1b8594118807",
        "f77f2c428e39f86861bb5eab724b6b191975ea1623a9010f73aa8536ff1cecec",
        "6e1c4ec1c410ed99582c1a1b45175a3bf62d9bf77ac71a6d567ca5f9a1bf6b9a",
    ];

    // Non-existence vector 0: Non-existence proof for key 0000000000000000000000000000000000000000000000000000000000000000
    const NONEX_KEY_0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const NONEX_ROOT_0: &str = "f7beb01818ec9fe29f5316b6add63a010749f428b3f71f177f47b59a2f268bc5";
    const NONEX_SIBS_0: &[&str] = &[
        "8e366410ee5792bf8e8d8e6abc9093c2a50a083238c2f8b8558655df00e8547c",
        "3ea38b9533634972d7b4d2f9ded53321d7d080eb67d5b5f0d4ea8b95e991f21f",
        "59dfc03f234687956c138401b10edcd64642233704630146bb34c72eba11a08b",
        "43d66b4de4a949b7be017c58ab3ea9c9d62663645b0258391ce2f110aee7af27",
        "2c79daced5a64e3d21c92d4f4b6518bac4ca12aad1dabf838400f7770b3ca81c",
        "45eabf069297deac076b6cd53484f1b4909c090cac787b5e54cf1fc75cf733ac",
        "576424c7e4488dcaf988ccd7f1df5129f7e26f56b5493ac501b69f66e90f7d4e",
        "fdbd6e678614b8a1c24e5a2bc96569aa9aa56cd9576a2e55699130e9d7fe88f3",
        "76f88eccca303650ae6e704fc541c98e23307bd23fb5ad24ead77894ada86e47",
        "f9125609b79e56aab4b7e1c773b239712fc7776dd776a2909c76cd97886ffa52",
        "4d78a02e0d1828a30054119b94a3a4298583f6dd3ef7607d892079683655f1e8",
        "e236cc712e09d59458e2ec848ab19b807bfdf8d8d02de77fbd5c0a7b7a141836",
        "cab76db206af544ad6b6a84d8a030c07711938c6dd6c423580ae9c04f1db0ff6",
        "711a5f331bd040912ad85fbabf2685460011f89be6066e76528bc01c302fd358",
        "133420cca013ea2edf4c4546f91960c4f73c9092c0a775d43a2016f8ce36f671",
        "c581a45eb2ceb7567419e459bf3e739e12f714c7f8469e8e479fbaa8434f2877",
        "f00f5cec01054f28c176a3b0331696f4ff09c46e0b2b3d63c394c5c4fa8c7033",
        "a9da3bc38058e04f3ddf6961f59c111039440693597cfe84a37bed0e4f4082dc",
        "f4c4b845e4e175129a659b715a9c06e5144a2c96f8f6e827e541ee48702777b0",
        "b4806d77ffec8175de8aed7c1160515b9c58f9e466c248cb015b2236e70d2769",
        "d5144e319bf2f12d97779b9a83aaa6cedfc7cbf42512858a4eb4023887036fcb",
        "7507c0868e89bb148cdbbb608b5829cf5bbdea6d86d055728eb9a2d5aaf2d625",
        "281de96d976a6895c2614689d4988f7620e8093b6302cdc0cb005029b8472989",
        "c080d6bf352dcecb167121a1a35236a595551e909c8eed7dd2220e123addd361",
        "c55efd3763e9e65bbb132ee9e7ee45f19b557ea43875893c0018970775908135",
        "35504e641f1e5ef49858700b5ab52ceb5e3d354b9652e549e6e38e54bffb2b8f",
        "5fa1b4251e7b0e3131479f17b7de4c65ff46dcdf1720bbfa711708392898630c",
        "ae6d787e9b4a7ee9e1e2ed0323ae65fb17d4c707bf71c96b2298d0b2d5eaa5c4",
        "e3d45305e32fcb10069fb9238a9458e16cc4cbc0d4ec506be014ecc2291fb845",
        "361ca179b035a1dbbaffeb1f509bfee0f15afa64d76e7b9e67eadbd86727a932",
        "75fa8ebcd7024b65a0c69adb52ec73799636a592507eab85b6cbb329409cd2c2",
        "b49698faf87e9e2bde213222589bdf6d41a9c0aae2ddbc6a9fa5d6e0e900b8a0",
        "bb8a615dfcb2eba70a0312efde0e297b87a5d86c1cac2d50a97c182e65659b25",
        "657af470826babc0ca494179abef07ef8ba069bcb915e60bbc9853516c65676c",
        "2681601cd3992c6387eddae5e3493fb66ce4acb7888f625c6159bcd1f7d51d4e",
        "4d5d52ec0726655f634eba604085d1b9a274db2358d5bd2e43d28072f28e4d0f",
        "acdfaaa936a5ef2c552feaafc17d06faf10ce792b87e68e44f3d5293447110ad",
        "9803967ded03a85db08cb546b5cac2e8fc708a9584751810c415e847530bf12d",
        "255701fb5252f0f11f2014232d739477204680bbbe78b95fe22e257c7c3fa1c3",
        "522deafd551686dc437d0241d46dfc8ed9bb26672b946249dd5a674723cc1929",
        "64d4ba29e80f8f27248bb93e2be10446f32fb01e39563902db252bcbf609aad4",
        "cf8d37560fb3c362d0fad2e2e0ebbd2a214e2b4aec4acb1fa3805690119c76d5",
        "ab39d85c7efc8273bec98ed3e0933e0795abcb607e79daa4b32c76ac651aeda6",
        "a6399bcec0e2eea7caa73166f69e50c38e65faf87067ba88e51ef1c084b60178",
        "2902519fa5abb8f1c8e72fa98b651742ab8752d26ef3a6f150936a8f0216cb02",
        "1176fd190cde55c9ed750d31960c216f6d8b5a2608b111103ab4d9f61c2af836",
        "a1e87be6b964f11f1500f0409e394b24e4c60a2c1804becea8447fa38be2abbf",
        "510e56c502e3ccd90bde5c283c270b2f1adb9527e84cb7888861aee8277b425d",
        "76915cfa634971ebb5ca96a572989121b0f417435554e75cfd3caf1cc7538024",
        "7a08c762b99b74153b0ec7e17c47ab815c4e69c70a17f4c725df18d3c24ba938",
        "a7dceb5481fa19d145a3d854175eacb317f88d79cd858e8010b0cd388f2e59fd",
        "ec2d7b7ce77e2657011c615e6ddf88b499a35321622cf31b73ecea6b6d5ec9aa",
        "ba2061307e6e1e3ba1a1e772e5aaea89f81204e33082374abfe65727e9487df6",
        "2e6d0ab3b8b58f74e5e513f6102594788a96914cedd90fbf65c328c61c607503",
        "b8ec6f052a2fe798e1dd3bbfa765174e9e4b75d4cb3a60e1c70569205872983c",
        "98a9f11b47cce0d2838e5fa3f2c4284f678896aff1783493a31c72cf1929aa2d",
        "01da07349b99ceb0961bab0dd84fe57bc9bcf42567cbbaec8f23c6fa77ed6198",
        "4250d7b736d3856ef3e94ec4e2f55d09349a8afbb533dd6f4238922682520c67",
        "5c93174c5be3dde79005da679860f5e0fee64f22be9d3fc456b8503accd2bc9b",
        "933ce3a0ed1a23a0cb863203123e1a896a33a1ef642b0688e48d4ad70a358258",
        "88824f69d2635e5d284933a353391242664cf4fa4143a06c4c8ca5a2dc54d706",
        "24986d31ce8ee947faac22e84b0ebae096f95c483b4929344feb71f546e137b6",
        "ab5db659f5111094557078606b94bee35966dc68cc1e74902822bc56a858927f",
        "d47d817b4f940323a066a023ebb60cfb3d91c2323f745430350373dec691a495",
        "6bc1e691cfde1a785e8d525397912fab406f8848b729acc0f1f2c533c05b8a70",
        "131adff07acae209f02888efc42477b211cb738167465978e1a18fab6d12c23c",
        "ad84fe9df2638b1822dfd5f569370f3227bd036091a1c0fd0608301965178850",
        "1d742e9ba2e21e2eeaee8eb886e2e2f6142394f30e2a172fe23c554aa4d5c23a",
        "931cfc21b8dd1241487f51387f00d36e7f180540af972b063a885428e01a8cb1",
        "69d790f9907544fcf6a06532e4e6d6a89b9df31dbd3bc44523ba46b6fc3e271c",
        "32c37953b6af3578539c522624c512f34adc004c7f0ea9e6e76937d048771cbd",
        "b4e3871bed13313a51ad350802d9df7659b0df67674b18eaffb9fde780e6ad66",
        "06a3a211392d296b14f27ac01d24c3b63f5cca373763c7e3c296165f2e70cdf7",
        "5a234e319f3be87b143c7b8a1dcf5407e78ca0cd38b0dd819f7898403af09803",
        "72190009bba7beb174c1068b2013ce905fa457527a81a64742a789ee1a0c8e09",
        "9ed982dd1251bc8ecf345ec9ac6f15a94f63b42348a235681f83f52d6dfc6bbd",
        "d99b38772bb5236cc18159acae2e07d58fd839e8667202d4cc88fb88fd5b671c",
        "6e0e0224d787ed1a3a0b3b4dd32f05c63b3f177b6816506000ca140d99cb9e89",
        "ab2ebc2d00248d537d027b4cddaa2f909ec4ec505b7bd477e92c1e40751590bb",
        "c58ec9edc6394ee3972549d82cd6bcc604f50d17fbe0f09015630b193be19776",
        "fbd89acacbd52a70f83bade340e1ca5e374bbcace265358ecbb4a73ded58f98a",
        "cecad33b21242ebfef444f8c7eb061f157e28c0e327a931d49ea91a15580ac4f",
        "b11861e11ff2d465a48cb68efe2a3d2a582a97a058c9d9209d5a5ba2b666ee57",
        "ca29bc7497c4a0c9ca73cdb3efef66ee4e789b3d412c80aa29f052bcce36d20a",
        "72363d88e437c8b1cf91a8923d96190f27662a13f555b9444f79f773ba7c2986",
        "65bb2376f29cf89a1425a0907c2cf8e068a4ad9b932f3dc504e81a5410b469ad",
        "fc6358ea9287cba16386bbd613d4cb78bfe33c45ae3b445536cad2e565d66f10",
        "1fc658658ed72006c05fb78933926f2c62698811f6372fe6e154117303607b04",
        "14f104af45556b9d359fe901989c9610392eed4d2f13638977c10f9b9dffcf4d",
        "62bc677a59e6ea11f527644b80254b19e592401388d641a399820fcd9131d56b",
        "89a64819315750df19d21c810036e470be6462edfd8ac1a28f92e1cc8ca7acf4",
        "460fc1504227bb4ace26ca3c6a4e572f2e56f8682f5eb073265181899f3d3779",
        "dff32d95d6d42e0a4e6f66894978da2564ffe658d384c1968f6c3cd344cb6f45",
        "5acc732da44c24f760f791f2905e8f724c5defa08b31691a8a758abe6ef2b7c8",
        "ea886b9c1d2f5b8797a30503356fd39eb67ebeb4bd1e0bc9626ff7d80a18925a",
        "ff0431cf20dea7c53a04aeb1f996bedef591dff83916d7e5813b9c6d57e79738",
        "b4d6119b13b371caf6cc9e240c097138aa5b7009b0fad69ffc1c23b0ad7d4635",
        "278eb5e2d4f7b7f2b6145878f08e361e487b6397ddf11c3d19449f54ba720f2b",
        "87349e20a14b6d9ecf34e2f590cdeeb3fd4df6c943bd5b1c9439e1ff815c87ad",
        "42e9dbc450c8858c2fd80729eac862340c26d08409f7607e6a844a0285cb3a77",
        "adc069c2fd56a7669752e9e2ac19710821a3eecf7f134430200f93f6ffa92654",
        "97715248aa97f81c5b4f212775363f27f11c3c1a13e72a16cd356a42ec28fcf5",
        "5b1b2a976c582e23463b176adaac0a456ad346201e162bb6644d13b0369b1d62",
        "1d5db1116c484753f80436b4a4a7c10fbd6f8dae4cf35add44d2042025156293",
        "5066a0acdaee0540fbb842e02f4ea5d2988e99e464267ee2fe60552ac7bac636",
        "148f2e2ce405858ff7af17fd0d1951d1c82180c1dda3e95dda0f49cd32401222",
        "6f1b33ff8f3e5cb2bc59a9c1ebca8854d296f05e7c299bf930b1206d76c0ba35",
        "a9f85de9810e013de101803d18f217e13ee293917f8172d3390d32eda91d6b8c",
        "b53a3b8b21cc8659de0b031d1151f989d6f29dcfc42c29be25ebd1f3401d7abc",
        "325e183bb1d85857081f7e8c9ca8137582976e4fcedad40b9de7af9b424d805e",
        "c89497f90a27a688a9b8e5a7995720754cc09b447ecb7d455419b68cffe39f00",
        "1e8ac1a49b19a029db1bfcad973311f9bd0359660cbc1ef810af6f113921f90e",
        "8f58472c1fbc5240638528de80aff8fc1eedd8f2364bf90747256e10d3aa993d",
        "c74176e5ace2c83fb59481106d159bbdc0bce1d209c167c2ed2c8160346b1e08",
        "243ecea5a0787244d67bb452d2b4c10f37ac69668dcd71f5166c975b6d56a64e",
        "a52911600ea5a6b983e12f81a09949a4c1936807de4d76d98dc07d9a1218d309",
        "d751b66ad5f98380f1e66f1c0fb512b5da36c920552a06d06a1db064ca37ae13",
        "6488b23e0dccd736945f97e8922911798e450d7cb3d00b8212e46942618ed654",
        "1bce25783fa821b20103d186849a19dc5bbdc8638ddf1a447282d06c5b985b87",
        "9aa090fabe3dfa3c70417f54ae9e1f7f88679475665b3312b4a51dc8e2a89719",
        "bab72434e9a2a04cc8708a16ba96065ebc703a204f1d14e54b6381f7e41c6ec6",
        "d1ace25484265bf44ccc4ea9687967050d5a13e2399f151d0f03a25fc166bee3",
        "2a39690ec069e250bfc02e35c70946e16575c2c2e5c8ac3e63ad9ab43b3bef7d",
        "37d11ccdb9bedb8cee0894d606ee918c514dca043d3c70baff8908ac071968e2",
        "555c65be76315f4a7aa0d661ce613cc51d62fd5f88f0c3be5d6537bde9a64e6f",
        "1f2c6dbca5081b8a2b918d2b7a5b857945f0ec34634c54ab7d01cb7efdd10ef6",
        "a09d359159cf7862059c6b270dc6ac27677496a9806e3e1939ab69a5f4bd982b",
        "06569dacc84d3043e9389d609a7dadee797e1059858a3cf17083b976a6bcacb3",
        "bc4adc073674c546dc474967aff391281ca2cb9132063e6d1dccf92d3a7a9ad1",
        "1fe55a13d7251033f45cb7d9c7e0102c6bfc30f1c637fd7badf190bd507ab2b5",
        "32dce867d9b7ebba2db35302f725ae9b5f3fe414cd78685cb4b1c710af969e0d",
        "3df1c47f0edc8d43ff42fde59ea0fd134d2a74506790f8a631cff220d773c884",
        "79848b7eb23bab9d1ea68164b4c333ee275686fe8d116be12a4eccf2aadc60bd",
        "a1a53e76001e94abd450728ccfa2620590d525a16372d9108903667c18ff0a04",
        "5dbb7fff8de71fe0651f263dba1ce63dd81d5e18b921795ab83c02096050b13d",
        "f8ac2c33fee34bc7125fecb0e3b7401c5382938eac74deee788b3d34e154343e",
        "c612aca030a397d9153dafaf0741ba76424167258bb66bba076cc4be3bb5c1b4",
        "f0d761f170a03e7ff42bc44d9eb04c61d4e8a087b009a408d8173a52fc907074",
        "41211ef7e9dc75eccd79375e66b523ee137c51756475e426e671337a403e9182",
        "37659c89134d3f3fe38b0c9824f3687397709376367bb61e5f0109a17f090974",
        "b2f948c987c18eeeeade96b1a7177f8d92efa03d473b9bb2cf58b7044c49abe5",
        "ad9c893e51f6ed6d6b1ce753dce5667693a4cb5a76d6632fbb1b9251efc7f7a3",
        "bdc78758eafb5407cc6fcd444e21fe499f4763ee9886d5074adb043fb3f091be",
        "61aa3c8de9b4642b445c0bec3416c75045f976bdc8966af39b8a177413220c92",
        "9d4ec3301087738ca80c391e52f6f1b55916bee036fa2bff3bf040425b0fc440",
        "df43318f4dedf7bd1ceedaf4eeb05615526a8e84b9777cdefdbdd5e6137a7553",
        "22a787ec912240984aa483b88508f5d42f0709f03036412195c0dce558a13512",
        "281cfd66d19bf1de9ae0cc2b114d0dcc4eb6fd5bea42683cb87a88b9002a3cd4",
        "ee841e26b57372f5028a5ee3bb33d3e6a2b4b0c0475c32d9d521ed5538596d85",
        "5a3acfe2e3f96d31be1540fd4dc1b927d71abca91dc111a8ddfc064ef92daf77",
        "a42e5878bbbde777be1a847a949b357f6e977f62acb86b0df1b61d0111496080",
        "7aa1fd59b6da6a213a9cac65d9efd2bb0bfa3ade0e2d42a12563dee4cebe4c44",
        "d35539023ccf129418b2169c9794f3849af8d93d73f07ac9de4eb40a33bc4339",
        "091cc3c3533ffa3b783384b4bff05ebbbe3b8bddb93653be72e1552e53d37616",
        "f239114efa32b64bf0c0effc46bfde40a8f7fd28fcc5277fcc0965ac20281294",
        "0618c1f3b86e3fef92f45744bbc1ccc0a82db77f65868066dcb4ee9e3bef82b8",
        "f02528772cc6d6117249ed7a3e91570f1fa446d44c89aaed3fef345ad28a100c",
        "a1091b57c6151d8348a9cd335581ae5a52515ddee691b50f1c71753cff438a41",
        "0070f61d2999342097f9c2340361a6b2a47e21f0a48df9ee300c75b321cb12d9",
        "ce2260a82ea8dec0dd25f47db14dbd7a61bc4bdbe7dd103c621632bf7a5ba21b",
        "065b7cfda4b11c8fde342e7e0201d981b5a2acf5075368e4634815a693b3ee3e",
        "414a2cf5449a6ca94a15274008446728eff85074873fbe05ea562aab880d6313",
        "c22ac7cedbf84cb54d76714a832c7f93a74b2b02bba62452884684812e497f34",
        "776126fbc83693b322eed8640e9f703deabf9a1581cec80c8e963404e9f0f47d",
        "849f0790f592238600e9e4ae1ff12f3393d1657ca52b50727562c4183b8c2826",
        "8387956906c2f6a57b14fe940fb19616977ea996db9ca234343571ebf28929c0",
        "03215e51eeab80a70769641baffb7fa6111425ff88906bfc1af8ec9f042221b5",
        "c3d0f8683f5c6ffad349be2e6e9d8926706fd0e8bc6c3edde679642a121e82ed",
        "2438c056a82f448c12b23e4620358045493a170a76ec580f5fde290cd49e60df",
        "8ce595662a14047a28d8e9be28fcfc86fd5df18112513c43f85da64b73f9072c",
        "3b901c76325ea9738873e9dee1fc955f8068ae8bc5eede9cebe6f9776fe4b118",
        "5bb263cb618537c429d059bdd91e7bcb5d05f606a88e06cf2f25d2973ddbc113",
        "69750390d7a9a44a8e0c786a4cda7ddfd57ff3ea16937955cac8aa8ffda07219",
        "b2113668d4f27b38b29963a2d0c582f8fe95aad31c3b21cf626718ca94892482",
        "ab6b6d37269f90abd9a222f2b241cf3c7ca15904a13010144d108141d74e147e",
        "b3c532544e19d3297ad0654c92061b43d541becca6096fa253b7ed509d9ae189",
        "c264a7f21744ca68a07f39d01936638f420f3e1998d3269bbd1fac0557170c60",
        "42d4051ed6d2a2ba670b16a8d0f9d14b8ff5e38354c9f5e55d5102f0f292b1f3",
        "4d78737ace4f805cd5411ef1ae0a9e2a798b45bc11e9fff4d348dcfcee8f42c6",
        "0a2a01cc2506486a049c98df7b151b77d75cea67921224152fc10c53ea352b25",
        "337a92c293a11d777a82d85a6480994d3b8324fc78ed0d507c4ccf3dcd236a9e",
        "71997103ee3a1f016aea1595c8d3b7b778792cb037d03ce733ce67b27a08e0b5",
        "d61ff1cb4f2e157f248dac466b2ab297599367fda32a6a52c1842d750268dff5",
        "bbffef94731ef2f4a9ab21f90bf70a4d8e87d24a90406e5515db6cec99ddaa90",
        "1ef38ecf4b91592fb0f08f8382314d06d951270bf3760a2411965e0e82a0449c",
        "09c30b8533faa48e003280ec910ce77b2d4fe9293a8af1740c62be38146fdf60",
        "861dacde4967d2aa400c516800dac0a923daad6c040db5ba7b6dd020e6cb6b66",
        "56356e3420f88cf76e676e381fd9abe046240f1c5f3b9e0a0fa75efbacb7d190",
        "956d0e1e9fb913152afac367ffb432ec957784805f19d969592ee3eb7d4700df",
        "d440a82d19ac13c504a467be198256cca9edd95e613029a5b94b13033a19ee23",
        "e58e3b9f5704d845e8f5ffdba821d651b57d10ce94a23ee6bb9362d785377f6d",
        "652faecf6414f44a61f83a41bf7471ef8d857c62455c8e49fec8567c53e9cccf",
        "95215cf5f073b74b8cf9fa6193f0804b8bbdb7a8b280a3647943abb81320c8c6",
        "bb6a21ca848eebd050ee5acc2bec5d06334d206ce8a00d576a2235eb53e93ca3",
        "9ebf65c67fa011c4d5b0cc7be3ab146617badf2e313c7803a97eb60ac914ed61",
        "bcbe975936802665c69b490266303f2d6dea2a9730a3533b05fc5e9d662a50c7",
        "795c25ca0698c3c28039cd9346bb2d5e8cf61d8b7697a3c600defa6afd10b6d2",
        "dc7f1e32c5d23e0bad9233eb900f6b04633ce504f531e2df9f53d53e8b46c312",
        "76018dfe4c387b1de78730115700a45f71f75b822ada50ab5ebf35aa392f5119",
        "b2b52313d058516fdd52f4b3a5422bd5ad88e7ae0e21ec37ca094de16b65af4f",
        "dd63781fbe7179c0e97b67052d852023718b2d9d9fad77a20367901564c0df00",
        "b93ebcc14628777fbbfd21ea06defe3f723ae08477126cece38ae112074c9c59",
        "2639be3d392f3df20d9c77e07bff2861549c2e8e4f688af3f454d812759fbe7b",
        "f7d6f0b48ed2e333f6f566b158834e1726451c8a435ebc8376d98dc5b8987a9e",
        "002e294231f869bb73158ade98ad37203a8f46227e8613b1920dcafc55644b03",
        "e7a6ac4ea049a40ede51b6406581aae3aff2de5099fe49023348b588abce0dcb",
        "ce7586aa4434eaa1d531e130e82819cb5d9c8ea6c95b703565f604a8b15a14fa",
        "8195ec54a7a690c38bd2f535d313bbc7f1d1af8414108c7ca05431c79c0922d1",
        "58a1960343cab1c4977aca073b27d898dc8f5310dead52a57691429d389eb0bd",
        "bb95ed9edb2660359a44cfc70ebd5a9e442327d1ab7bb1cf14196a36a1c6aa27",
        "0bb250ece3f690723298898b0b0efc9442fbb7e8967138be20e29e04983075b3",
        "7092b0336fd60a1a6e24b62bf22244fc431eba64f213bd8f5d9de2865379da69",
        "5ee5252fba29d669205ce91153b443ddb21540f9da36da0e066e30cfbc85dfa3",
        "9e0dd4e1d4a0c7a6ec4a7ade373efc107f810377f1d3b0327490ef63dc865df6",
        "9dea4389f111c9fc3e370794b0da274de8d5d4dea3d593d8af45c3186a5139bd",
        "cbc538560908ba70b0b103101f05cee12bed8812dc01be3670d2b8634351a433",
        "9b4663f636ef04ac5756f673ecaeb166ce9b228ecfe9a79750d1fac91e9cfaa1",
        "edeed2f6b8acbb7081335a602c012b6d97e0393fc29d3ebeeab71465cbb20471",
        "97ae0bfe76a1554bdbd78c39cb9fbaf1567f274dc3901300fb8ec01e95e17c26",
        "a9646079729df8afbd182a588282c7ea65e7dab177cb5b1cef373700ed166d79",
        "22c78b424753cd7782cd7c38ecea7670323760c5a8ed21513bdd537e732985ee",
        "eb33e4b7f546160ceaa89f6a1adbb0aa1c324185a85aaf05f9e11dd3a30f8963",
        "c48f2b8c57afcce911b86d9027207b54abf304d18c8936f556039f34b420a22e",
        "cbc29bceff35b2c14d682667a78f56c76279dda0dea1d3567e699be211914b46",
        "3a0c64ab17e9b542e45cb1cd0c874d766fb945c309bc19f91c8b2d06b7a3bf86",
        "392a11bda08147c02e63bdf4421fdb54b72148cdd09026855fbdb25811e924db",
        "8a64d5244c4945230e6d979ceb0969f418119c9cdb7778bd93a74f0ed6f9ea68",
        "f148c9d0668baea63ce495ec2dd3b1fb46c1eebd6dc1d4c4d4851aaa8b53d8c3",
        "721e0bbcc3054385e2dac368b466e3c4ad636113d8667eda7c0e9a027f7d459b",
        "98a769b47312ace49da42ee3e1695e290c142f3109ef1f36928cac6af12246a2",
        "75e25a186e4bc987c6b365dca378ae777c07a3a2b4295a1ff12bb88de5121237",
        "7b0b452b0351674d1137d1ae22a56a6574885d41f000771f4c0e5cc27c030eb2",
        "49fc7e713bae4e7e37c0313319020ac243d46693b10ac3a273325d65964bcb73",
        "4421d386d3970949e03749c43bf28e4f2801400abdd466f96b925c34668f3686",
        "fd8c550467d4e471a3b6a27a74e95583d2b2938ca2c5f93ad4c3a18007fd2fd0",
        "50ad260fad06a4c851d004915feb9d42b0e96dc50f0cffc724d844b3d6e2cf08",
        "2756821e3e180586117a659330259fb8b7f59aaaa2c376eea90c9cd15a118f98",
        "7aa0baf58d27f0e589d066c16b06821aa573610f30d9420d4d7d6d906b42ca0d",
        "af8a25f12472deaadb721ac97740874bc410a52b57a7d4629e140c8548d0d777",
        "3113cbf56a24970b2560c0891223197a773acf3aa1bff62dfb4c93d416865388",
        "22ae2fd22720bf9ac91447b76ff82591d5acc4cd43ad243267ab4b722d537951",
        "45abd184ee741e6b2300d4e77cda05c55bac64902726b38514917c4be11a700f",
        "9a93beb5b1748349996c5a68f28e5db1b3dc43f35b53522ecb347035c45cc8f9",
        "9ed838276797a35681787184ac33677bd2c0b8847d57580c7110b45b86ab5552",
        "6bfc26bcf180f5e954f6b183bbf5f364d608ac715aa210a59b6569d44682f298",
        "9cd151509dd68fdd7a6aca93ddc1350c9dbe236bef141d0baaae4e0fee69a534",
        "86eb8328c8a48a7311d337418f8a23ffb79f5b38b08b9cfc8c07133a32b5d43a",
        "8bb6be0f033075b093368c1f3d5500037418cb5275a3beb9f71b417e791b4834",
        "25e73888097d609b4dfc49f856cee142847c5bb169cbef4f9b25c27958870435",
        "0ddd3c46363a727f314e5d8fe566177e69ed9f0efde27d249dde470587cf7f63",
        "be16d705d7ca159048dea82bc2752db8c8fb86c64c597754c609e9e9aba97b87",
        "0d8d72b0e270abf5c8951f1065fd97ba42f2879b58d940922ecc61afcd8c9896",
        "0b9315ebd59b4bf0bfa8aae499d808e32a68277a6d857517630cb026412a6047",
        "033db49568e184ae4c421f5b1524201c3f289517a26e9eeb8d0e1b8594118807",
        "f77f2c428e39f86861bb5eab724b6b191975ea1623a9010f73aa8536ff1cecec",
        "57d9fe07581fac965c7b1577bb4d5389871af714cd6490c9bcb0ea313dd438c5",
    ];

    // Non-existence vector 1: Non-existence proof for key ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    const NONEX_KEY_1: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const NONEX_ROOT_1: &str = "f7beb01818ec9fe29f5316b6add63a010749f428b3f71f177f47b59a2f268bc5";
    const NONEX_SIBS_1: &[&str] = &[
        "07eeb849ecdbb08cee230250cfb7358c2801275bf7b462d9981ba700db4f5d08",
        "852685c9f513ed3320b29181465d8c6be247a8fd62998720e2ff275f47d84ded",
        "59dfc03f234687956c138401b10edcd64642233704630146bb34c72eba11a08b",
        "43d66b4de4a949b7be017c58ab3ea9c9d62663645b0258391ce2f110aee7af27",
        "2c79daced5a64e3d21c92d4f4b6518bac4ca12aad1dabf838400f7770b3ca81c",
        "45eabf069297deac076b6cd53484f1b4909c090cac787b5e54cf1fc75cf733ac",
        "576424c7e4488dcaf988ccd7f1df5129f7e26f56b5493ac501b69f66e90f7d4e",
        "fdbd6e678614b8a1c24e5a2bc96569aa9aa56cd9576a2e55699130e9d7fe88f3",
        "76f88eccca303650ae6e704fc541c98e23307bd23fb5ad24ead77894ada86e47",
        "f9125609b79e56aab4b7e1c773b239712fc7776dd776a2909c76cd97886ffa52",
        "4d78a02e0d1828a30054119b94a3a4298583f6dd3ef7607d892079683655f1e8",
        "e236cc712e09d59458e2ec848ab19b807bfdf8d8d02de77fbd5c0a7b7a141836",
        "cab76db206af544ad6b6a84d8a030c07711938c6dd6c423580ae9c04f1db0ff6",
        "711a5f331bd040912ad85fbabf2685460011f89be6066e76528bc01c302fd358",
        "133420cca013ea2edf4c4546f91960c4f73c9092c0a775d43a2016f8ce36f671",
        "c581a45eb2ceb7567419e459bf3e739e12f714c7f8469e8e479fbaa8434f2877",
        "f00f5cec01054f28c176a3b0331696f4ff09c46e0b2b3d63c394c5c4fa8c7033",
        "a9da3bc38058e04f3ddf6961f59c111039440693597cfe84a37bed0e4f4082dc",
        "f4c4b845e4e175129a659b715a9c06e5144a2c96f8f6e827e541ee48702777b0",
        "b4806d77ffec8175de8aed7c1160515b9c58f9e466c248cb015b2236e70d2769",
        "d5144e319bf2f12d97779b9a83aaa6cedfc7cbf42512858a4eb4023887036fcb",
        "7507c0868e89bb148cdbbb608b5829cf5bbdea6d86d055728eb9a2d5aaf2d625",
        "281de96d976a6895c2614689d4988f7620e8093b6302cdc0cb005029b8472989",
        "c080d6bf352dcecb167121a1a35236a595551e909c8eed7dd2220e123addd361",
        "c55efd3763e9e65bbb132ee9e7ee45f19b557ea43875893c0018970775908135",
        "35504e641f1e5ef49858700b5ab52ceb5e3d354b9652e549e6e38e54bffb2b8f",
        "5fa1b4251e7b0e3131479f17b7de4c65ff46dcdf1720bbfa711708392898630c",
        "ae6d787e9b4a7ee9e1e2ed0323ae65fb17d4c707bf71c96b2298d0b2d5eaa5c4",
        "e3d45305e32fcb10069fb9238a9458e16cc4cbc0d4ec506be014ecc2291fb845",
        "361ca179b035a1dbbaffeb1f509bfee0f15afa64d76e7b9e67eadbd86727a932",
        "75fa8ebcd7024b65a0c69adb52ec73799636a592507eab85b6cbb329409cd2c2",
        "b49698faf87e9e2bde213222589bdf6d41a9c0aae2ddbc6a9fa5d6e0e900b8a0",
        "bb8a615dfcb2eba70a0312efde0e297b87a5d86c1cac2d50a97c182e65659b25",
        "657af470826babc0ca494179abef07ef8ba069bcb915e60bbc9853516c65676c",
        "2681601cd3992c6387eddae5e3493fb66ce4acb7888f625c6159bcd1f7d51d4e",
        "4d5d52ec0726655f634eba604085d1b9a274db2358d5bd2e43d28072f28e4d0f",
        "acdfaaa936a5ef2c552feaafc17d06faf10ce792b87e68e44f3d5293447110ad",
        "9803967ded03a85db08cb546b5cac2e8fc708a9584751810c415e847530bf12d",
        "255701fb5252f0f11f2014232d739477204680bbbe78b95fe22e257c7c3fa1c3",
        "522deafd551686dc437d0241d46dfc8ed9bb26672b946249dd5a674723cc1929",
        "64d4ba29e80f8f27248bb93e2be10446f32fb01e39563902db252bcbf609aad4",
        "cf8d37560fb3c362d0fad2e2e0ebbd2a214e2b4aec4acb1fa3805690119c76d5",
        "ab39d85c7efc8273bec98ed3e0933e0795abcb607e79daa4b32c76ac651aeda6",
        "a6399bcec0e2eea7caa73166f69e50c38e65faf87067ba88e51ef1c084b60178",
        "2902519fa5abb8f1c8e72fa98b651742ab8752d26ef3a6f150936a8f0216cb02",
        "1176fd190cde55c9ed750d31960c216f6d8b5a2608b111103ab4d9f61c2af836",
        "a1e87be6b964f11f1500f0409e394b24e4c60a2c1804becea8447fa38be2abbf",
        "510e56c502e3ccd90bde5c283c270b2f1adb9527e84cb7888861aee8277b425d",
        "76915cfa634971ebb5ca96a572989121b0f417435554e75cfd3caf1cc7538024",
        "7a08c762b99b74153b0ec7e17c47ab815c4e69c70a17f4c725df18d3c24ba938",
        "a7dceb5481fa19d145a3d854175eacb317f88d79cd858e8010b0cd388f2e59fd",
        "ec2d7b7ce77e2657011c615e6ddf88b499a35321622cf31b73ecea6b6d5ec9aa",
        "ba2061307e6e1e3ba1a1e772e5aaea89f81204e33082374abfe65727e9487df6",
        "2e6d0ab3b8b58f74e5e513f6102594788a96914cedd90fbf65c328c61c607503",
        "b8ec6f052a2fe798e1dd3bbfa765174e9e4b75d4cb3a60e1c70569205872983c",
        "98a9f11b47cce0d2838e5fa3f2c4284f678896aff1783493a31c72cf1929aa2d",
        "01da07349b99ceb0961bab0dd84fe57bc9bcf42567cbbaec8f23c6fa77ed6198",
        "4250d7b736d3856ef3e94ec4e2f55d09349a8afbb533dd6f4238922682520c67",
        "5c93174c5be3dde79005da679860f5e0fee64f22be9d3fc456b8503accd2bc9b",
        "933ce3a0ed1a23a0cb863203123e1a896a33a1ef642b0688e48d4ad70a358258",
        "88824f69d2635e5d284933a353391242664cf4fa4143a06c4c8ca5a2dc54d706",
        "24986d31ce8ee947faac22e84b0ebae096f95c483b4929344feb71f546e137b6",
        "ab5db659f5111094557078606b94bee35966dc68cc1e74902822bc56a858927f",
        "d47d817b4f940323a066a023ebb60cfb3d91c2323f745430350373dec691a495",
        "6bc1e691cfde1a785e8d525397912fab406f8848b729acc0f1f2c533c05b8a70",
        "131adff07acae209f02888efc42477b211cb738167465978e1a18fab6d12c23c",
        "ad84fe9df2638b1822dfd5f569370f3227bd036091a1c0fd0608301965178850",
        "1d742e9ba2e21e2eeaee8eb886e2e2f6142394f30e2a172fe23c554aa4d5c23a",
        "931cfc21b8dd1241487f51387f00d36e7f180540af972b063a885428e01a8cb1",
        "69d790f9907544fcf6a06532e4e6d6a89b9df31dbd3bc44523ba46b6fc3e271c",
        "32c37953b6af3578539c522624c512f34adc004c7f0ea9e6e76937d048771cbd",
        "b4e3871bed13313a51ad350802d9df7659b0df67674b18eaffb9fde780e6ad66",
        "06a3a211392d296b14f27ac01d24c3b63f5cca373763c7e3c296165f2e70cdf7",
        "5a234e319f3be87b143c7b8a1dcf5407e78ca0cd38b0dd819f7898403af09803",
        "72190009bba7beb174c1068b2013ce905fa457527a81a64742a789ee1a0c8e09",
        "9ed982dd1251bc8ecf345ec9ac6f15a94f63b42348a235681f83f52d6dfc6bbd",
        "d99b38772bb5236cc18159acae2e07d58fd839e8667202d4cc88fb88fd5b671c",
        "6e0e0224d787ed1a3a0b3b4dd32f05c63b3f177b6816506000ca140d99cb9e89",
        "ab2ebc2d00248d537d027b4cddaa2f909ec4ec505b7bd477e92c1e40751590bb",
        "c58ec9edc6394ee3972549d82cd6bcc604f50d17fbe0f09015630b193be19776",
        "fbd89acacbd52a70f83bade340e1ca5e374bbcace265358ecbb4a73ded58f98a",
        "cecad33b21242ebfef444f8c7eb061f157e28c0e327a931d49ea91a15580ac4f",
        "b11861e11ff2d465a48cb68efe2a3d2a582a97a058c9d9209d5a5ba2b666ee57",
        "ca29bc7497c4a0c9ca73cdb3efef66ee4e789b3d412c80aa29f052bcce36d20a",
        "72363d88e437c8b1cf91a8923d96190f27662a13f555b9444f79f773ba7c2986",
        "65bb2376f29cf89a1425a0907c2cf8e068a4ad9b932f3dc504e81a5410b469ad",
        "fc6358ea9287cba16386bbd613d4cb78bfe33c45ae3b445536cad2e565d66f10",
        "1fc658658ed72006c05fb78933926f2c62698811f6372fe6e154117303607b04",
        "14f104af45556b9d359fe901989c9610392eed4d2f13638977c10f9b9dffcf4d",
        "62bc677a59e6ea11f527644b80254b19e592401388d641a399820fcd9131d56b",
        "89a64819315750df19d21c810036e470be6462edfd8ac1a28f92e1cc8ca7acf4",
        "460fc1504227bb4ace26ca3c6a4e572f2e56f8682f5eb073265181899f3d3779",
        "dff32d95d6d42e0a4e6f66894978da2564ffe658d384c1968f6c3cd344cb6f45",
        "5acc732da44c24f760f791f2905e8f724c5defa08b31691a8a758abe6ef2b7c8",
        "ea886b9c1d2f5b8797a30503356fd39eb67ebeb4bd1e0bc9626ff7d80a18925a",
        "ff0431cf20dea7c53a04aeb1f996bedef591dff83916d7e5813b9c6d57e79738",
        "b4d6119b13b371caf6cc9e240c097138aa5b7009b0fad69ffc1c23b0ad7d4635",
        "278eb5e2d4f7b7f2b6145878f08e361e487b6397ddf11c3d19449f54ba720f2b",
        "87349e20a14b6d9ecf34e2f590cdeeb3fd4df6c943bd5b1c9439e1ff815c87ad",
        "42e9dbc450c8858c2fd80729eac862340c26d08409f7607e6a844a0285cb3a77",
        "adc069c2fd56a7669752e9e2ac19710821a3eecf7f134430200f93f6ffa92654",
        "97715248aa97f81c5b4f212775363f27f11c3c1a13e72a16cd356a42ec28fcf5",
        "5b1b2a976c582e23463b176adaac0a456ad346201e162bb6644d13b0369b1d62",
        "1d5db1116c484753f80436b4a4a7c10fbd6f8dae4cf35add44d2042025156293",
        "5066a0acdaee0540fbb842e02f4ea5d2988e99e464267ee2fe60552ac7bac636",
        "148f2e2ce405858ff7af17fd0d1951d1c82180c1dda3e95dda0f49cd32401222",
        "6f1b33ff8f3e5cb2bc59a9c1ebca8854d296f05e7c299bf930b1206d76c0ba35",
        "a9f85de9810e013de101803d18f217e13ee293917f8172d3390d32eda91d6b8c",
        "b53a3b8b21cc8659de0b031d1151f989d6f29dcfc42c29be25ebd1f3401d7abc",
        "325e183bb1d85857081f7e8c9ca8137582976e4fcedad40b9de7af9b424d805e",
        "c89497f90a27a688a9b8e5a7995720754cc09b447ecb7d455419b68cffe39f00",
        "1e8ac1a49b19a029db1bfcad973311f9bd0359660cbc1ef810af6f113921f90e",
        "8f58472c1fbc5240638528de80aff8fc1eedd8f2364bf90747256e10d3aa993d",
        "c74176e5ace2c83fb59481106d159bbdc0bce1d209c167c2ed2c8160346b1e08",
        "243ecea5a0787244d67bb452d2b4c10f37ac69668dcd71f5166c975b6d56a64e",
        "a52911600ea5a6b983e12f81a09949a4c1936807de4d76d98dc07d9a1218d309",
        "d751b66ad5f98380f1e66f1c0fb512b5da36c920552a06d06a1db064ca37ae13",
        "6488b23e0dccd736945f97e8922911798e450d7cb3d00b8212e46942618ed654",
        "1bce25783fa821b20103d186849a19dc5bbdc8638ddf1a447282d06c5b985b87",
        "9aa090fabe3dfa3c70417f54ae9e1f7f88679475665b3312b4a51dc8e2a89719",
        "bab72434e9a2a04cc8708a16ba96065ebc703a204f1d14e54b6381f7e41c6ec6",
        "d1ace25484265bf44ccc4ea9687967050d5a13e2399f151d0f03a25fc166bee3",
        "2a39690ec069e250bfc02e35c70946e16575c2c2e5c8ac3e63ad9ab43b3bef7d",
        "37d11ccdb9bedb8cee0894d606ee918c514dca043d3c70baff8908ac071968e2",
        "555c65be76315f4a7aa0d661ce613cc51d62fd5f88f0c3be5d6537bde9a64e6f",
        "1f2c6dbca5081b8a2b918d2b7a5b857945f0ec34634c54ab7d01cb7efdd10ef6",
        "a09d359159cf7862059c6b270dc6ac27677496a9806e3e1939ab69a5f4bd982b",
        "06569dacc84d3043e9389d609a7dadee797e1059858a3cf17083b976a6bcacb3",
        "bc4adc073674c546dc474967aff391281ca2cb9132063e6d1dccf92d3a7a9ad1",
        "1fe55a13d7251033f45cb7d9c7e0102c6bfc30f1c637fd7badf190bd507ab2b5",
        "32dce867d9b7ebba2db35302f725ae9b5f3fe414cd78685cb4b1c710af969e0d",
        "3df1c47f0edc8d43ff42fde59ea0fd134d2a74506790f8a631cff220d773c884",
        "79848b7eb23bab9d1ea68164b4c333ee275686fe8d116be12a4eccf2aadc60bd",
        "a1a53e76001e94abd450728ccfa2620590d525a16372d9108903667c18ff0a04",
        "5dbb7fff8de71fe0651f263dba1ce63dd81d5e18b921795ab83c02096050b13d",
        "f8ac2c33fee34bc7125fecb0e3b7401c5382938eac74deee788b3d34e154343e",
        "c612aca030a397d9153dafaf0741ba76424167258bb66bba076cc4be3bb5c1b4",
        "f0d761f170a03e7ff42bc44d9eb04c61d4e8a087b009a408d8173a52fc907074",
        "41211ef7e9dc75eccd79375e66b523ee137c51756475e426e671337a403e9182",
        "37659c89134d3f3fe38b0c9824f3687397709376367bb61e5f0109a17f090974",
        "b2f948c987c18eeeeade96b1a7177f8d92efa03d473b9bb2cf58b7044c49abe5",
        "ad9c893e51f6ed6d6b1ce753dce5667693a4cb5a76d6632fbb1b9251efc7f7a3",
        "bdc78758eafb5407cc6fcd444e21fe499f4763ee9886d5074adb043fb3f091be",
        "61aa3c8de9b4642b445c0bec3416c75045f976bdc8966af39b8a177413220c92",
        "9d4ec3301087738ca80c391e52f6f1b55916bee036fa2bff3bf040425b0fc440",
        "df43318f4dedf7bd1ceedaf4eeb05615526a8e84b9777cdefdbdd5e6137a7553",
        "22a787ec912240984aa483b88508f5d42f0709f03036412195c0dce558a13512",
        "281cfd66d19bf1de9ae0cc2b114d0dcc4eb6fd5bea42683cb87a88b9002a3cd4",
        "ee841e26b57372f5028a5ee3bb33d3e6a2b4b0c0475c32d9d521ed5538596d85",
        "5a3acfe2e3f96d31be1540fd4dc1b927d71abca91dc111a8ddfc064ef92daf77",
        "a42e5878bbbde777be1a847a949b357f6e977f62acb86b0df1b61d0111496080",
        "7aa1fd59b6da6a213a9cac65d9efd2bb0bfa3ade0e2d42a12563dee4cebe4c44",
        "d35539023ccf129418b2169c9794f3849af8d93d73f07ac9de4eb40a33bc4339",
        "091cc3c3533ffa3b783384b4bff05ebbbe3b8bddb93653be72e1552e53d37616",
        "f239114efa32b64bf0c0effc46bfde40a8f7fd28fcc5277fcc0965ac20281294",
        "0618c1f3b86e3fef92f45744bbc1ccc0a82db77f65868066dcb4ee9e3bef82b8",
        "f02528772cc6d6117249ed7a3e91570f1fa446d44c89aaed3fef345ad28a100c",
        "a1091b57c6151d8348a9cd335581ae5a52515ddee691b50f1c71753cff438a41",
        "0070f61d2999342097f9c2340361a6b2a47e21f0a48df9ee300c75b321cb12d9",
        "ce2260a82ea8dec0dd25f47db14dbd7a61bc4bdbe7dd103c621632bf7a5ba21b",
        "065b7cfda4b11c8fde342e7e0201d981b5a2acf5075368e4634815a693b3ee3e",
        "414a2cf5449a6ca94a15274008446728eff85074873fbe05ea562aab880d6313",
        "c22ac7cedbf84cb54d76714a832c7f93a74b2b02bba62452884684812e497f34",
        "776126fbc83693b322eed8640e9f703deabf9a1581cec80c8e963404e9f0f47d",
        "849f0790f592238600e9e4ae1ff12f3393d1657ca52b50727562c4183b8c2826",
        "8387956906c2f6a57b14fe940fb19616977ea996db9ca234343571ebf28929c0",
        "03215e51eeab80a70769641baffb7fa6111425ff88906bfc1af8ec9f042221b5",
        "c3d0f8683f5c6ffad349be2e6e9d8926706fd0e8bc6c3edde679642a121e82ed",
        "2438c056a82f448c12b23e4620358045493a170a76ec580f5fde290cd49e60df",
        "8ce595662a14047a28d8e9be28fcfc86fd5df18112513c43f85da64b73f9072c",
        "3b901c76325ea9738873e9dee1fc955f8068ae8bc5eede9cebe6f9776fe4b118",
        "5bb263cb618537c429d059bdd91e7bcb5d05f606a88e06cf2f25d2973ddbc113",
        "69750390d7a9a44a8e0c786a4cda7ddfd57ff3ea16937955cac8aa8ffda07219",
        "b2113668d4f27b38b29963a2d0c582f8fe95aad31c3b21cf626718ca94892482",
        "ab6b6d37269f90abd9a222f2b241cf3c7ca15904a13010144d108141d74e147e",
        "b3c532544e19d3297ad0654c92061b43d541becca6096fa253b7ed509d9ae189",
        "c264a7f21744ca68a07f39d01936638f420f3e1998d3269bbd1fac0557170c60",
        "42d4051ed6d2a2ba670b16a8d0f9d14b8ff5e38354c9f5e55d5102f0f292b1f3",
        "4d78737ace4f805cd5411ef1ae0a9e2a798b45bc11e9fff4d348dcfcee8f42c6",
        "0a2a01cc2506486a049c98df7b151b77d75cea67921224152fc10c53ea352b25",
        "337a92c293a11d777a82d85a6480994d3b8324fc78ed0d507c4ccf3dcd236a9e",
        "71997103ee3a1f016aea1595c8d3b7b778792cb037d03ce733ce67b27a08e0b5",
        "d61ff1cb4f2e157f248dac466b2ab297599367fda32a6a52c1842d750268dff5",
        "bbffef94731ef2f4a9ab21f90bf70a4d8e87d24a90406e5515db6cec99ddaa90",
        "1ef38ecf4b91592fb0f08f8382314d06d951270bf3760a2411965e0e82a0449c",
        "09c30b8533faa48e003280ec910ce77b2d4fe9293a8af1740c62be38146fdf60",
        "861dacde4967d2aa400c516800dac0a923daad6c040db5ba7b6dd020e6cb6b66",
        "56356e3420f88cf76e676e381fd9abe046240f1c5f3b9e0a0fa75efbacb7d190",
        "956d0e1e9fb913152afac367ffb432ec957784805f19d969592ee3eb7d4700df",
        "d440a82d19ac13c504a467be198256cca9edd95e613029a5b94b13033a19ee23",
        "e58e3b9f5704d845e8f5ffdba821d651b57d10ce94a23ee6bb9362d785377f6d",
        "652faecf6414f44a61f83a41bf7471ef8d857c62455c8e49fec8567c53e9cccf",
        "95215cf5f073b74b8cf9fa6193f0804b8bbdb7a8b280a3647943abb81320c8c6",
        "bb6a21ca848eebd050ee5acc2bec5d06334d206ce8a00d576a2235eb53e93ca3",
        "9ebf65c67fa011c4d5b0cc7be3ab146617badf2e313c7803a97eb60ac914ed61",
        "bcbe975936802665c69b490266303f2d6dea2a9730a3533b05fc5e9d662a50c7",
        "795c25ca0698c3c28039cd9346bb2d5e8cf61d8b7697a3c600defa6afd10b6d2",
        "dc7f1e32c5d23e0bad9233eb900f6b04633ce504f531e2df9f53d53e8b46c312",
        "76018dfe4c387b1de78730115700a45f71f75b822ada50ab5ebf35aa392f5119",
        "b2b52313d058516fdd52f4b3a5422bd5ad88e7ae0e21ec37ca094de16b65af4f",
        "dd63781fbe7179c0e97b67052d852023718b2d9d9fad77a20367901564c0df00",
        "b93ebcc14628777fbbfd21ea06defe3f723ae08477126cece38ae112074c9c59",
        "2639be3d392f3df20d9c77e07bff2861549c2e8e4f688af3f454d812759fbe7b",
        "f7d6f0b48ed2e333f6f566b158834e1726451c8a435ebc8376d98dc5b8987a9e",
        "002e294231f869bb73158ade98ad37203a8f46227e8613b1920dcafc55644b03",
        "e7a6ac4ea049a40ede51b6406581aae3aff2de5099fe49023348b588abce0dcb",
        "ce7586aa4434eaa1d531e130e82819cb5d9c8ea6c95b703565f604a8b15a14fa",
        "8195ec54a7a690c38bd2f535d313bbc7f1d1af8414108c7ca05431c79c0922d1",
        "58a1960343cab1c4977aca073b27d898dc8f5310dead52a57691429d389eb0bd",
        "bb95ed9edb2660359a44cfc70ebd5a9e442327d1ab7bb1cf14196a36a1c6aa27",
        "0bb250ece3f690723298898b0b0efc9442fbb7e8967138be20e29e04983075b3",
        "7092b0336fd60a1a6e24b62bf22244fc431eba64f213bd8f5d9de2865379da69",
        "5ee5252fba29d669205ce91153b443ddb21540f9da36da0e066e30cfbc85dfa3",
        "9e0dd4e1d4a0c7a6ec4a7ade373efc107f810377f1d3b0327490ef63dc865df6",
        "9dea4389f111c9fc3e370794b0da274de8d5d4dea3d593d8af45c3186a5139bd",
        "cbc538560908ba70b0b103101f05cee12bed8812dc01be3670d2b8634351a433",
        "9b4663f636ef04ac5756f673ecaeb166ce9b228ecfe9a79750d1fac91e9cfaa1",
        "edeed2f6b8acbb7081335a602c012b6d97e0393fc29d3ebeeab71465cbb20471",
        "97ae0bfe76a1554bdbd78c39cb9fbaf1567f274dc3901300fb8ec01e95e17c26",
        "a9646079729df8afbd182a588282c7ea65e7dab177cb5b1cef373700ed166d79",
        "22c78b424753cd7782cd7c38ecea7670323760c5a8ed21513bdd537e732985ee",
        "eb33e4b7f546160ceaa89f6a1adbb0aa1c324185a85aaf05f9e11dd3a30f8963",
        "c48f2b8c57afcce911b86d9027207b54abf304d18c8936f556039f34b420a22e",
        "cbc29bceff35b2c14d682667a78f56c76279dda0dea1d3567e699be211914b46",
        "3a0c64ab17e9b542e45cb1cd0c874d766fb945c309bc19f91c8b2d06b7a3bf86",
        "392a11bda08147c02e63bdf4421fdb54b72148cdd09026855fbdb25811e924db",
        "8a64d5244c4945230e6d979ceb0969f418119c9cdb7778bd93a74f0ed6f9ea68",
        "f148c9d0668baea63ce495ec2dd3b1fb46c1eebd6dc1d4c4d4851aaa8b53d8c3",
        "721e0bbcc3054385e2dac368b466e3c4ad636113d8667eda7c0e9a027f7d459b",
        "98a769b47312ace49da42ee3e1695e290c142f3109ef1f36928cac6af12246a2",
        "75e25a186e4bc987c6b365dca378ae777c07a3a2b4295a1ff12bb88de5121237",
        "7b0b452b0351674d1137d1ae22a56a6574885d41f000771f4c0e5cc27c030eb2",
        "49fc7e713bae4e7e37c0313319020ac243d46693b10ac3a273325d65964bcb73",
        "4421d386d3970949e03749c43bf28e4f2801400abdd466f96b925c34668f3686",
        "fd8c550467d4e471a3b6a27a74e95583d2b2938ca2c5f93ad4c3a18007fd2fd0",
        "50ad260fad06a4c851d004915feb9d42b0e96dc50f0cffc724d844b3d6e2cf08",
        "2756821e3e180586117a659330259fb8b7f59aaaa2c376eea90c9cd15a118f98",
        "7aa0baf58d27f0e589d066c16b06821aa573610f30d9420d4d7d6d906b42ca0d",
        "af8a25f12472deaadb721ac97740874bc410a52b57a7d4629e140c8548d0d777",
        "3113cbf56a24970b2560c0891223197a773acf3aa1bff62dfb4c93d416865388",
        "22ae2fd22720bf9ac91447b76ff82591d5acc4cd43ad243267ab4b722d537951",
        "45abd184ee741e6b2300d4e77cda05c55bac64902726b38514917c4be11a700f",
        "9a93beb5b1748349996c5a68f28e5db1b3dc43f35b53522ecb347035c45cc8f9",
        "9ed838276797a35681787184ac33677bd2c0b8847d57580c7110b45b86ab5552",
        "6bfc26bcf180f5e954f6b183bbf5f364d608ac715aa210a59b6569d44682f298",
        "9cd151509dd68fdd7a6aca93ddc1350c9dbe236bef141d0baaae4e0fee69a534",
        "86eb8328c8a48a7311d337418f8a23ffb79f5b38b08b9cfc8c07133a32b5d43a",
        "8bb6be0f033075b093368c1f3d5500037418cb5275a3beb9f71b417e791b4834",
        "25e73888097d609b4dfc49f856cee142847c5bb169cbef4f9b25c27958870435",
        "0ddd3c46363a727f314e5d8fe566177e69ed9f0efde27d249dde470587cf7f63",
        "be16d705d7ca159048dea82bc2752db8c8fb86c64c597754c609e9e9aba97b87",
        "0d8d72b0e270abf5c8951f1065fd97ba42f2879b58d940922ecc61afcd8c9896",
        "0b9315ebd59b4bf0bfa8aae499d808e32a68277a6d857517630cb026412a6047",
        "033db49568e184ae4c421f5b1524201c3f289517a26e9eeb8d0e1b8594118807",
        "f77f2c428e39f86861bb5eab724b6b191975ea1623a9010f73aa8536ff1cecec",
        "6e1c4ec1c410ed99582c1a1b45175a3bf62d9bf77ac71a6d567ca5f9a1bf6b9a",
    ];

    // Non-existence vector 2: Non-existence proof for key 0000000000000000000000000000000000000000000000000000000000000003
    const NONEX_KEY_2: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const NONEX_ROOT_2: &str = "f7beb01818ec9fe29f5316b6add63a010749f428b3f71f177f47b59a2f268bc5";
    const NONEX_SIBS_2: &[&str] = &[
        "73bbd97d1d7bd82a92d24638bdb03e419c3fdacf8a561aba3fdb6ab0bfcfb5db",
        "07b81b1dc127e2141448bc74d3e2acbb1f88945808bad8711850ced7ce1c6039",
        "59dfc03f234687956c138401b10edcd64642233704630146bb34c72eba11a08b",
        "43d66b4de4a949b7be017c58ab3ea9c9d62663645b0258391ce2f110aee7af27",
        "2c79daced5a64e3d21c92d4f4b6518bac4ca12aad1dabf838400f7770b3ca81c",
        "45eabf069297deac076b6cd53484f1b4909c090cac787b5e54cf1fc75cf733ac",
        "576424c7e4488dcaf988ccd7f1df5129f7e26f56b5493ac501b69f66e90f7d4e",
        "fdbd6e678614b8a1c24e5a2bc96569aa9aa56cd9576a2e55699130e9d7fe88f3",
        "76f88eccca303650ae6e704fc541c98e23307bd23fb5ad24ead77894ada86e47",
        "f9125609b79e56aab4b7e1c773b239712fc7776dd776a2909c76cd97886ffa52",
        "4d78a02e0d1828a30054119b94a3a4298583f6dd3ef7607d892079683655f1e8",
        "e236cc712e09d59458e2ec848ab19b807bfdf8d8d02de77fbd5c0a7b7a141836",
        "cab76db206af544ad6b6a84d8a030c07711938c6dd6c423580ae9c04f1db0ff6",
        "711a5f331bd040912ad85fbabf2685460011f89be6066e76528bc01c302fd358",
        "133420cca013ea2edf4c4546f91960c4f73c9092c0a775d43a2016f8ce36f671",
        "c581a45eb2ceb7567419e459bf3e739e12f714c7f8469e8e479fbaa8434f2877",
        "f00f5cec01054f28c176a3b0331696f4ff09c46e0b2b3d63c394c5c4fa8c7033",
        "a9da3bc38058e04f3ddf6961f59c111039440693597cfe84a37bed0e4f4082dc",
        "f4c4b845e4e175129a659b715a9c06e5144a2c96f8f6e827e541ee48702777b0",
        "b4806d77ffec8175de8aed7c1160515b9c58f9e466c248cb015b2236e70d2769",
        "d5144e319bf2f12d97779b9a83aaa6cedfc7cbf42512858a4eb4023887036fcb",
        "7507c0868e89bb148cdbbb608b5829cf5bbdea6d86d055728eb9a2d5aaf2d625",
        "281de96d976a6895c2614689d4988f7620e8093b6302cdc0cb005029b8472989",
        "c080d6bf352dcecb167121a1a35236a595551e909c8eed7dd2220e123addd361",
        "c55efd3763e9e65bbb132ee9e7ee45f19b557ea43875893c0018970775908135",
        "35504e641f1e5ef49858700b5ab52ceb5e3d354b9652e549e6e38e54bffb2b8f",
        "5fa1b4251e7b0e3131479f17b7de4c65ff46dcdf1720bbfa711708392898630c",
        "ae6d787e9b4a7ee9e1e2ed0323ae65fb17d4c707bf71c96b2298d0b2d5eaa5c4",
        "e3d45305e32fcb10069fb9238a9458e16cc4cbc0d4ec506be014ecc2291fb845",
        "361ca179b035a1dbbaffeb1f509bfee0f15afa64d76e7b9e67eadbd86727a932",
        "75fa8ebcd7024b65a0c69adb52ec73799636a592507eab85b6cbb329409cd2c2",
        "b49698faf87e9e2bde213222589bdf6d41a9c0aae2ddbc6a9fa5d6e0e900b8a0",
        "bb8a615dfcb2eba70a0312efde0e297b87a5d86c1cac2d50a97c182e65659b25",
        "657af470826babc0ca494179abef07ef8ba069bcb915e60bbc9853516c65676c",
        "2681601cd3992c6387eddae5e3493fb66ce4acb7888f625c6159bcd1f7d51d4e",
        "4d5d52ec0726655f634eba604085d1b9a274db2358d5bd2e43d28072f28e4d0f",
        "acdfaaa936a5ef2c552feaafc17d06faf10ce792b87e68e44f3d5293447110ad",
        "9803967ded03a85db08cb546b5cac2e8fc708a9584751810c415e847530bf12d",
        "255701fb5252f0f11f2014232d739477204680bbbe78b95fe22e257c7c3fa1c3",
        "522deafd551686dc437d0241d46dfc8ed9bb26672b946249dd5a674723cc1929",
        "64d4ba29e80f8f27248bb93e2be10446f32fb01e39563902db252bcbf609aad4",
        "cf8d37560fb3c362d0fad2e2e0ebbd2a214e2b4aec4acb1fa3805690119c76d5",
        "ab39d85c7efc8273bec98ed3e0933e0795abcb607e79daa4b32c76ac651aeda6",
        "a6399bcec0e2eea7caa73166f69e50c38e65faf87067ba88e51ef1c084b60178",
        "2902519fa5abb8f1c8e72fa98b651742ab8752d26ef3a6f150936a8f0216cb02",
        "1176fd190cde55c9ed750d31960c216f6d8b5a2608b111103ab4d9f61c2af836",
        "a1e87be6b964f11f1500f0409e394b24e4c60a2c1804becea8447fa38be2abbf",
        "510e56c502e3ccd90bde5c283c270b2f1adb9527e84cb7888861aee8277b425d",
        "76915cfa634971ebb5ca96a572989121b0f417435554e75cfd3caf1cc7538024",
        "7a08c762b99b74153b0ec7e17c47ab815c4e69c70a17f4c725df18d3c24ba938",
        "a7dceb5481fa19d145a3d854175eacb317f88d79cd858e8010b0cd388f2e59fd",
        "ec2d7b7ce77e2657011c615e6ddf88b499a35321622cf31b73ecea6b6d5ec9aa",
        "ba2061307e6e1e3ba1a1e772e5aaea89f81204e33082374abfe65727e9487df6",
        "2e6d0ab3b8b58f74e5e513f6102594788a96914cedd90fbf65c328c61c607503",
        "b8ec6f052a2fe798e1dd3bbfa765174e9e4b75d4cb3a60e1c70569205872983c",
        "98a9f11b47cce0d2838e5fa3f2c4284f678896aff1783493a31c72cf1929aa2d",
        "01da07349b99ceb0961bab0dd84fe57bc9bcf42567cbbaec8f23c6fa77ed6198",
        "4250d7b736d3856ef3e94ec4e2f55d09349a8afbb533dd6f4238922682520c67",
        "5c93174c5be3dde79005da679860f5e0fee64f22be9d3fc456b8503accd2bc9b",
        "933ce3a0ed1a23a0cb863203123e1a896a33a1ef642b0688e48d4ad70a358258",
        "88824f69d2635e5d284933a353391242664cf4fa4143a06c4c8ca5a2dc54d706",
        "24986d31ce8ee947faac22e84b0ebae096f95c483b4929344feb71f546e137b6",
        "ab5db659f5111094557078606b94bee35966dc68cc1e74902822bc56a858927f",
        "d47d817b4f940323a066a023ebb60cfb3d91c2323f745430350373dec691a495",
        "6bc1e691cfde1a785e8d525397912fab406f8848b729acc0f1f2c533c05b8a70",
        "131adff07acae209f02888efc42477b211cb738167465978e1a18fab6d12c23c",
        "ad84fe9df2638b1822dfd5f569370f3227bd036091a1c0fd0608301965178850",
        "1d742e9ba2e21e2eeaee8eb886e2e2f6142394f30e2a172fe23c554aa4d5c23a",
        "931cfc21b8dd1241487f51387f00d36e7f180540af972b063a885428e01a8cb1",
        "69d790f9907544fcf6a06532e4e6d6a89b9df31dbd3bc44523ba46b6fc3e271c",
        "32c37953b6af3578539c522624c512f34adc004c7f0ea9e6e76937d048771cbd",
        "b4e3871bed13313a51ad350802d9df7659b0df67674b18eaffb9fde780e6ad66",
        "06a3a211392d296b14f27ac01d24c3b63f5cca373763c7e3c296165f2e70cdf7",
        "5a234e319f3be87b143c7b8a1dcf5407e78ca0cd38b0dd819f7898403af09803",
        "72190009bba7beb174c1068b2013ce905fa457527a81a64742a789ee1a0c8e09",
        "9ed982dd1251bc8ecf345ec9ac6f15a94f63b42348a235681f83f52d6dfc6bbd",
        "d99b38772bb5236cc18159acae2e07d58fd839e8667202d4cc88fb88fd5b671c",
        "6e0e0224d787ed1a3a0b3b4dd32f05c63b3f177b6816506000ca140d99cb9e89",
        "ab2ebc2d00248d537d027b4cddaa2f909ec4ec505b7bd477e92c1e40751590bb",
        "c58ec9edc6394ee3972549d82cd6bcc604f50d17fbe0f09015630b193be19776",
        "fbd89acacbd52a70f83bade340e1ca5e374bbcace265358ecbb4a73ded58f98a",
        "cecad33b21242ebfef444f8c7eb061f157e28c0e327a931d49ea91a15580ac4f",
        "b11861e11ff2d465a48cb68efe2a3d2a582a97a058c9d9209d5a5ba2b666ee57",
        "ca29bc7497c4a0c9ca73cdb3efef66ee4e789b3d412c80aa29f052bcce36d20a",
        "72363d88e437c8b1cf91a8923d96190f27662a13f555b9444f79f773ba7c2986",
        "65bb2376f29cf89a1425a0907c2cf8e068a4ad9b932f3dc504e81a5410b469ad",
        "fc6358ea9287cba16386bbd613d4cb78bfe33c45ae3b445536cad2e565d66f10",
        "1fc658658ed72006c05fb78933926f2c62698811f6372fe6e154117303607b04",
        "14f104af45556b9d359fe901989c9610392eed4d2f13638977c10f9b9dffcf4d",
        "62bc677a59e6ea11f527644b80254b19e592401388d641a399820fcd9131d56b",
        "89a64819315750df19d21c810036e470be6462edfd8ac1a28f92e1cc8ca7acf4",
        "460fc1504227bb4ace26ca3c6a4e572f2e56f8682f5eb073265181899f3d3779",
        "dff32d95d6d42e0a4e6f66894978da2564ffe658d384c1968f6c3cd344cb6f45",
        "5acc732da44c24f760f791f2905e8f724c5defa08b31691a8a758abe6ef2b7c8",
        "ea886b9c1d2f5b8797a30503356fd39eb67ebeb4bd1e0bc9626ff7d80a18925a",
        "ff0431cf20dea7c53a04aeb1f996bedef591dff83916d7e5813b9c6d57e79738",
        "b4d6119b13b371caf6cc9e240c097138aa5b7009b0fad69ffc1c23b0ad7d4635",
        "278eb5e2d4f7b7f2b6145878f08e361e487b6397ddf11c3d19449f54ba720f2b",
        "87349e20a14b6d9ecf34e2f590cdeeb3fd4df6c943bd5b1c9439e1ff815c87ad",
        "42e9dbc450c8858c2fd80729eac862340c26d08409f7607e6a844a0285cb3a77",
        "adc069c2fd56a7669752e9e2ac19710821a3eecf7f134430200f93f6ffa92654",
        "97715248aa97f81c5b4f212775363f27f11c3c1a13e72a16cd356a42ec28fcf5",
        "5b1b2a976c582e23463b176adaac0a456ad346201e162bb6644d13b0369b1d62",
        "1d5db1116c484753f80436b4a4a7c10fbd6f8dae4cf35add44d2042025156293",
        "5066a0acdaee0540fbb842e02f4ea5d2988e99e464267ee2fe60552ac7bac636",
        "148f2e2ce405858ff7af17fd0d1951d1c82180c1dda3e95dda0f49cd32401222",
        "6f1b33ff8f3e5cb2bc59a9c1ebca8854d296f05e7c299bf930b1206d76c0ba35",
        "a9f85de9810e013de101803d18f217e13ee293917f8172d3390d32eda91d6b8c",
        "b53a3b8b21cc8659de0b031d1151f989d6f29dcfc42c29be25ebd1f3401d7abc",
        "325e183bb1d85857081f7e8c9ca8137582976e4fcedad40b9de7af9b424d805e",
        "c89497f90a27a688a9b8e5a7995720754cc09b447ecb7d455419b68cffe39f00",
        "1e8ac1a49b19a029db1bfcad973311f9bd0359660cbc1ef810af6f113921f90e",
        "8f58472c1fbc5240638528de80aff8fc1eedd8f2364bf90747256e10d3aa993d",
        "c74176e5ace2c83fb59481106d159bbdc0bce1d209c167c2ed2c8160346b1e08",
        "243ecea5a0787244d67bb452d2b4c10f37ac69668dcd71f5166c975b6d56a64e",
        "a52911600ea5a6b983e12f81a09949a4c1936807de4d76d98dc07d9a1218d309",
        "d751b66ad5f98380f1e66f1c0fb512b5da36c920552a06d06a1db064ca37ae13",
        "6488b23e0dccd736945f97e8922911798e450d7cb3d00b8212e46942618ed654",
        "1bce25783fa821b20103d186849a19dc5bbdc8638ddf1a447282d06c5b985b87",
        "9aa090fabe3dfa3c70417f54ae9e1f7f88679475665b3312b4a51dc8e2a89719",
        "bab72434e9a2a04cc8708a16ba96065ebc703a204f1d14e54b6381f7e41c6ec6",
        "d1ace25484265bf44ccc4ea9687967050d5a13e2399f151d0f03a25fc166bee3",
        "2a39690ec069e250bfc02e35c70946e16575c2c2e5c8ac3e63ad9ab43b3bef7d",
        "37d11ccdb9bedb8cee0894d606ee918c514dca043d3c70baff8908ac071968e2",
        "555c65be76315f4a7aa0d661ce613cc51d62fd5f88f0c3be5d6537bde9a64e6f",
        "1f2c6dbca5081b8a2b918d2b7a5b857945f0ec34634c54ab7d01cb7efdd10ef6",
        "a09d359159cf7862059c6b270dc6ac27677496a9806e3e1939ab69a5f4bd982b",
        "06569dacc84d3043e9389d609a7dadee797e1059858a3cf17083b976a6bcacb3",
        "bc4adc073674c546dc474967aff391281ca2cb9132063e6d1dccf92d3a7a9ad1",
        "1fe55a13d7251033f45cb7d9c7e0102c6bfc30f1c637fd7badf190bd507ab2b5",
        "32dce867d9b7ebba2db35302f725ae9b5f3fe414cd78685cb4b1c710af969e0d",
        "3df1c47f0edc8d43ff42fde59ea0fd134d2a74506790f8a631cff220d773c884",
        "79848b7eb23bab9d1ea68164b4c333ee275686fe8d116be12a4eccf2aadc60bd",
        "a1a53e76001e94abd450728ccfa2620590d525a16372d9108903667c18ff0a04",
        "5dbb7fff8de71fe0651f263dba1ce63dd81d5e18b921795ab83c02096050b13d",
        "f8ac2c33fee34bc7125fecb0e3b7401c5382938eac74deee788b3d34e154343e",
        "c612aca030a397d9153dafaf0741ba76424167258bb66bba076cc4be3bb5c1b4",
        "f0d761f170a03e7ff42bc44d9eb04c61d4e8a087b009a408d8173a52fc907074",
        "41211ef7e9dc75eccd79375e66b523ee137c51756475e426e671337a403e9182",
        "37659c89134d3f3fe38b0c9824f3687397709376367bb61e5f0109a17f090974",
        "b2f948c987c18eeeeade96b1a7177f8d92efa03d473b9bb2cf58b7044c49abe5",
        "ad9c893e51f6ed6d6b1ce753dce5667693a4cb5a76d6632fbb1b9251efc7f7a3",
        "bdc78758eafb5407cc6fcd444e21fe499f4763ee9886d5074adb043fb3f091be",
        "61aa3c8de9b4642b445c0bec3416c75045f976bdc8966af39b8a177413220c92",
        "9d4ec3301087738ca80c391e52f6f1b55916bee036fa2bff3bf040425b0fc440",
        "df43318f4dedf7bd1ceedaf4eeb05615526a8e84b9777cdefdbdd5e6137a7553",
        "22a787ec912240984aa483b88508f5d42f0709f03036412195c0dce558a13512",
        "281cfd66d19bf1de9ae0cc2b114d0dcc4eb6fd5bea42683cb87a88b9002a3cd4",
        "ee841e26b57372f5028a5ee3bb33d3e6a2b4b0c0475c32d9d521ed5538596d85",
        "5a3acfe2e3f96d31be1540fd4dc1b927d71abca91dc111a8ddfc064ef92daf77",
        "a42e5878bbbde777be1a847a949b357f6e977f62acb86b0df1b61d0111496080",
        "7aa1fd59b6da6a213a9cac65d9efd2bb0bfa3ade0e2d42a12563dee4cebe4c44",
        "d35539023ccf129418b2169c9794f3849af8d93d73f07ac9de4eb40a33bc4339",
        "091cc3c3533ffa3b783384b4bff05ebbbe3b8bddb93653be72e1552e53d37616",
        "f239114efa32b64bf0c0effc46bfde40a8f7fd28fcc5277fcc0965ac20281294",
        "0618c1f3b86e3fef92f45744bbc1ccc0a82db77f65868066dcb4ee9e3bef82b8",
        "f02528772cc6d6117249ed7a3e91570f1fa446d44c89aaed3fef345ad28a100c",
        "a1091b57c6151d8348a9cd335581ae5a52515ddee691b50f1c71753cff438a41",
        "0070f61d2999342097f9c2340361a6b2a47e21f0a48df9ee300c75b321cb12d9",
        "ce2260a82ea8dec0dd25f47db14dbd7a61bc4bdbe7dd103c621632bf7a5ba21b",
        "065b7cfda4b11c8fde342e7e0201d981b5a2acf5075368e4634815a693b3ee3e",
        "414a2cf5449a6ca94a15274008446728eff85074873fbe05ea562aab880d6313",
        "c22ac7cedbf84cb54d76714a832c7f93a74b2b02bba62452884684812e497f34",
        "776126fbc83693b322eed8640e9f703deabf9a1581cec80c8e963404e9f0f47d",
        "849f0790f592238600e9e4ae1ff12f3393d1657ca52b50727562c4183b8c2826",
        "8387956906c2f6a57b14fe940fb19616977ea996db9ca234343571ebf28929c0",
        "03215e51eeab80a70769641baffb7fa6111425ff88906bfc1af8ec9f042221b5",
        "c3d0f8683f5c6ffad349be2e6e9d8926706fd0e8bc6c3edde679642a121e82ed",
        "2438c056a82f448c12b23e4620358045493a170a76ec580f5fde290cd49e60df",
        "8ce595662a14047a28d8e9be28fcfc86fd5df18112513c43f85da64b73f9072c",
        "3b901c76325ea9738873e9dee1fc955f8068ae8bc5eede9cebe6f9776fe4b118",
        "5bb263cb618537c429d059bdd91e7bcb5d05f606a88e06cf2f25d2973ddbc113",
        "69750390d7a9a44a8e0c786a4cda7ddfd57ff3ea16937955cac8aa8ffda07219",
        "b2113668d4f27b38b29963a2d0c582f8fe95aad31c3b21cf626718ca94892482",
        "ab6b6d37269f90abd9a222f2b241cf3c7ca15904a13010144d108141d74e147e",
        "b3c532544e19d3297ad0654c92061b43d541becca6096fa253b7ed509d9ae189",
        "c264a7f21744ca68a07f39d01936638f420f3e1998d3269bbd1fac0557170c60",
        "42d4051ed6d2a2ba670b16a8d0f9d14b8ff5e38354c9f5e55d5102f0f292b1f3",
        "4d78737ace4f805cd5411ef1ae0a9e2a798b45bc11e9fff4d348dcfcee8f42c6",
        "0a2a01cc2506486a049c98df7b151b77d75cea67921224152fc10c53ea352b25",
        "337a92c293a11d777a82d85a6480994d3b8324fc78ed0d507c4ccf3dcd236a9e",
        "71997103ee3a1f016aea1595c8d3b7b778792cb037d03ce733ce67b27a08e0b5",
        "d61ff1cb4f2e157f248dac466b2ab297599367fda32a6a52c1842d750268dff5",
        "bbffef94731ef2f4a9ab21f90bf70a4d8e87d24a90406e5515db6cec99ddaa90",
        "1ef38ecf4b91592fb0f08f8382314d06d951270bf3760a2411965e0e82a0449c",
        "09c30b8533faa48e003280ec910ce77b2d4fe9293a8af1740c62be38146fdf60",
        "861dacde4967d2aa400c516800dac0a923daad6c040db5ba7b6dd020e6cb6b66",
        "56356e3420f88cf76e676e381fd9abe046240f1c5f3b9e0a0fa75efbacb7d190",
        "956d0e1e9fb913152afac367ffb432ec957784805f19d969592ee3eb7d4700df",
        "d440a82d19ac13c504a467be198256cca9edd95e613029a5b94b13033a19ee23",
        "e58e3b9f5704d845e8f5ffdba821d651b57d10ce94a23ee6bb9362d785377f6d",
        "652faecf6414f44a61f83a41bf7471ef8d857c62455c8e49fec8567c53e9cccf",
        "95215cf5f073b74b8cf9fa6193f0804b8bbdb7a8b280a3647943abb81320c8c6",
        "bb6a21ca848eebd050ee5acc2bec5d06334d206ce8a00d576a2235eb53e93ca3",
        "9ebf65c67fa011c4d5b0cc7be3ab146617badf2e313c7803a97eb60ac914ed61",
        "bcbe975936802665c69b490266303f2d6dea2a9730a3533b05fc5e9d662a50c7",
        "795c25ca0698c3c28039cd9346bb2d5e8cf61d8b7697a3c600defa6afd10b6d2",
        "dc7f1e32c5d23e0bad9233eb900f6b04633ce504f531e2df9f53d53e8b46c312",
        "76018dfe4c387b1de78730115700a45f71f75b822ada50ab5ebf35aa392f5119",
        "b2b52313d058516fdd52f4b3a5422bd5ad88e7ae0e21ec37ca094de16b65af4f",
        "dd63781fbe7179c0e97b67052d852023718b2d9d9fad77a20367901564c0df00",
        "b93ebcc14628777fbbfd21ea06defe3f723ae08477126cece38ae112074c9c59",
        "2639be3d392f3df20d9c77e07bff2861549c2e8e4f688af3f454d812759fbe7b",
        "f7d6f0b48ed2e333f6f566b158834e1726451c8a435ebc8376d98dc5b8987a9e",
        "002e294231f869bb73158ade98ad37203a8f46227e8613b1920dcafc55644b03",
        "e7a6ac4ea049a40ede51b6406581aae3aff2de5099fe49023348b588abce0dcb",
        "ce7586aa4434eaa1d531e130e82819cb5d9c8ea6c95b703565f604a8b15a14fa",
        "8195ec54a7a690c38bd2f535d313bbc7f1d1af8414108c7ca05431c79c0922d1",
        "58a1960343cab1c4977aca073b27d898dc8f5310dead52a57691429d389eb0bd",
        "bb95ed9edb2660359a44cfc70ebd5a9e442327d1ab7bb1cf14196a36a1c6aa27",
        "0bb250ece3f690723298898b0b0efc9442fbb7e8967138be20e29e04983075b3",
        "7092b0336fd60a1a6e24b62bf22244fc431eba64f213bd8f5d9de2865379da69",
        "5ee5252fba29d669205ce91153b443ddb21540f9da36da0e066e30cfbc85dfa3",
        "9e0dd4e1d4a0c7a6ec4a7ade373efc107f810377f1d3b0327490ef63dc865df6",
        "9dea4389f111c9fc3e370794b0da274de8d5d4dea3d593d8af45c3186a5139bd",
        "cbc538560908ba70b0b103101f05cee12bed8812dc01be3670d2b8634351a433",
        "9b4663f636ef04ac5756f673ecaeb166ce9b228ecfe9a79750d1fac91e9cfaa1",
        "edeed2f6b8acbb7081335a602c012b6d97e0393fc29d3ebeeab71465cbb20471",
        "97ae0bfe76a1554bdbd78c39cb9fbaf1567f274dc3901300fb8ec01e95e17c26",
        "a9646079729df8afbd182a588282c7ea65e7dab177cb5b1cef373700ed166d79",
        "22c78b424753cd7782cd7c38ecea7670323760c5a8ed21513bdd537e732985ee",
        "eb33e4b7f546160ceaa89f6a1adbb0aa1c324185a85aaf05f9e11dd3a30f8963",
        "c48f2b8c57afcce911b86d9027207b54abf304d18c8936f556039f34b420a22e",
        "cbc29bceff35b2c14d682667a78f56c76279dda0dea1d3567e699be211914b46",
        "3a0c64ab17e9b542e45cb1cd0c874d766fb945c309bc19f91c8b2d06b7a3bf86",
        "392a11bda08147c02e63bdf4421fdb54b72148cdd09026855fbdb25811e924db",
        "8a64d5244c4945230e6d979ceb0969f418119c9cdb7778bd93a74f0ed6f9ea68",
        "f148c9d0668baea63ce495ec2dd3b1fb46c1eebd6dc1d4c4d4851aaa8b53d8c3",
        "721e0bbcc3054385e2dac368b466e3c4ad636113d8667eda7c0e9a027f7d459b",
        "98a769b47312ace49da42ee3e1695e290c142f3109ef1f36928cac6af12246a2",
        "75e25a186e4bc987c6b365dca378ae777c07a3a2b4295a1ff12bb88de5121237",
        "7b0b452b0351674d1137d1ae22a56a6574885d41f000771f4c0e5cc27c030eb2",
        "49fc7e713bae4e7e37c0313319020ac243d46693b10ac3a273325d65964bcb73",
        "4421d386d3970949e03749c43bf28e4f2801400abdd466f96b925c34668f3686",
        "fd8c550467d4e471a3b6a27a74e95583d2b2938ca2c5f93ad4c3a18007fd2fd0",
        "50ad260fad06a4c851d004915feb9d42b0e96dc50f0cffc724d844b3d6e2cf08",
        "2756821e3e180586117a659330259fb8b7f59aaaa2c376eea90c9cd15a118f98",
        "7aa0baf58d27f0e589d066c16b06821aa573610f30d9420d4d7d6d906b42ca0d",
        "af8a25f12472deaadb721ac97740874bc410a52b57a7d4629e140c8548d0d777",
        "3113cbf56a24970b2560c0891223197a773acf3aa1bff62dfb4c93d416865388",
        "22ae2fd22720bf9ac91447b76ff82591d5acc4cd43ad243267ab4b722d537951",
        "45abd184ee741e6b2300d4e77cda05c55bac64902726b38514917c4be11a700f",
        "9a93beb5b1748349996c5a68f28e5db1b3dc43f35b53522ecb347035c45cc8f9",
        "9ed838276797a35681787184ac33677bd2c0b8847d57580c7110b45b86ab5552",
        "6bfc26bcf180f5e954f6b183bbf5f364d608ac715aa210a59b6569d44682f298",
        "9cd151509dd68fdd7a6aca93ddc1350c9dbe236bef141d0baaae4e0fee69a534",
        "86eb8328c8a48a7311d337418f8a23ffb79f5b38b08b9cfc8c07133a32b5d43a",
        "8bb6be0f033075b093368c1f3d5500037418cb5275a3beb9f71b417e791b4834",
        "25e73888097d609b4dfc49f856cee142847c5bb169cbef4f9b25c27958870435",
        "0ddd3c46363a727f314e5d8fe566177e69ed9f0efde27d249dde470587cf7f63",
        "be16d705d7ca159048dea82bc2752db8c8fb86c64c597754c609e9e9aba97b87",
        "0d8d72b0e270abf5c8951f1065fd97ba42f2879b58d940922ecc61afcd8c9896",
        "0b9315ebd59b4bf0bfa8aae499d808e32a68277a6d857517630cb026412a6047",
        "033db49568e184ae4c421f5b1524201c3f289517a26e9eeb8d0e1b8594118807",
        "f77f2c428e39f86861bb5eab724b6b191975ea1623a9010f73aa8536ff1cecec",
        "57d9fe07581fac965c7b1577bb4d5389871af714cd6490c9bcb0ea313dd438c5",
    ];


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

    fn make_inclusion(
        key: &str, val: &str, pid: &str, cpv: &str, root: &str, sibs: &[&str],
    ) -> SmtInclusionProof {
        SmtInclusionProof {
            key: h32(key),
            value_hash: h32(val),
            parser_id: pid.to_string(),
            canonical_parser_version: cpv.to_string(),
            siblings: sibs_from(sibs),
            root_hash: h32(root),
        }
    }

    fn make_non_inclusion(key: &str, root: &str, sibs: &[&str]) -> SmtNonInclusionProof {
        SmtNonInclusionProof {
            key: h32(key),
            siblings: sibs_from(sibs),
            root_hash: h32(root),
        }
    }

    #[test]
    fn conformance_ssmf_existence_proof() {
        let cases = [
            make_inclusion(EXIST_KEY_0, EXIST_VAL_0, EXIST_PID_0, EXIST_CPV_0, EXIST_ROOT_0, EXIST_SIBS_0),
            make_inclusion(EXIST_KEY_1, EXIST_VAL_1, EXIST_PID_1, EXIST_CPV_1, EXIST_ROOT_1, EXIST_SIBS_1),
            make_inclusion(EXIST_KEY_2, EXIST_VAL_2, EXIST_PID_2, EXIST_CPV_2, EXIST_ROOT_2, EXIST_SIBS_2),
        ];
        for (i, p) in cases.iter().enumerate() {
            assert!(verify_smt_inclusion(p), "existence vector {i} failed");
        }
    }

    #[test]
    fn conformance_ssmf_nonexistence_proof() {
        let cases = [
            make_non_inclusion(NONEX_KEY_0, NONEX_ROOT_0, NONEX_SIBS_0),
            make_non_inclusion(NONEX_KEY_1, NONEX_ROOT_1, NONEX_SIBS_1),
            make_non_inclusion(NONEX_KEY_2, NONEX_ROOT_2, NONEX_SIBS_2),
        ];
        for (i, p) in cases.iter().enumerate() {
            assert!(verify_smt_non_inclusion(p), "non-existence vector {i} failed");
        }
    }

    #[test]
    fn negatives_smt_inclusion() {
        let base = make_inclusion(
            EXIST_KEY_0, EXIST_VAL_0, EXIST_PID_0, EXIST_CPV_0, EXIST_ROOT_0, EXIST_SIBS_0,
        );
        assert!(verify_smt_inclusion(&base), "baseline must verify");

        // 1) empty parser_id
        let mut p = base.clone();
        p.parser_id = String::new();
        assert!(!verify_smt_inclusion(&p), "empty parser_id must fail");

        // 2) empty canonical_parser_version
        let mut p = base.clone();
        p.canonical_parser_version = String::new();
        assert!(!verify_smt_inclusion(&p), "empty canonical_parser_version must fail");

        // 3) tampered root (flip one bit in byte 0)
        let mut p = base.clone();
        p.root_hash[0] ^= 0x01;
        assert!(!verify_smt_inclusion(&p), "tampered root must fail");

        // 4) wrong value_hash
        let mut p = base.clone();
        p.value_hash[31] ^= 0xff;
        assert!(!verify_smt_inclusion(&p), "wrong value_hash must fail");

        // 5) wrong number of siblings (255 instead of 256)
        let mut p = base.clone();
        p.siblings.pop();
        assert_eq!(p.siblings.len(), 255);
        assert!(!verify_smt_inclusion(&p), "255 siblings must fail");

        // 6) corrupted sibling (flip one bit in siblings[100])
        let mut p = base.clone();
        p.siblings[100][0] ^= 0x01;
        assert!(!verify_smt_inclusion(&p), "corrupted sibling must fail");
    }

    #[test]
    fn negatives_smt_non_inclusion() {
        let base = make_non_inclusion(NONEX_KEY_0, NONEX_ROOT_0, NONEX_SIBS_0);
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

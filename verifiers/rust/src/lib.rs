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

/// Compute the dual-root commitment hash from BLAKE3 and Poseidon roots.
///
/// Formula:
///   BLAKE3(OLY:LEDGER:V1 | "|" | blake3_root_bytes | "|" | poseidon_root_32be_bytes)
///
/// where `poseidon_root_32be` is the 32-byte big-endian encoding of the BN128 field element.
///
/// This matches the Python reference:
///   `blake3_hash([LEDGER_PREFIX, SEP, blake3_root_bytes, SEP, poseidon_root_32be])`
pub fn compute_dual_commitment(blake3_root: &[u8; 32], poseidon_root_32be: &[u8; 32]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(
        LEDGER_PREFIX.len() + HASH_SEPARATOR.len() + 32 + HASH_SEPARATOR.len() + 32,
    );
    combined.extend_from_slice(LEDGER_PREFIX);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(blake3_root);
    combined.extend_from_slice(HASH_SEPARATOR);
    combined.extend_from_slice(poseidon_root_32be);
    compute_blake3(&combined)
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
                expected_dual: "ab1cde209598faa9cac0f8273d4d35a778893c849e71d5dca737ce7cf822825a",
                expected_blake3_consistent: true,
            },
            DualRootCommitmentVector {
                description: "Invalid: Poseidon root from unrelated document",
                document_parts: &["section A", "section B", "section C"],
                blake3_root_hex: "487f19f5f9226d91d8b59732d51baff231710c4f171a170e8573e4ca1666967b",
                poseidon_root_32be_hex: "08ce2263d65d7ea15782e3ef9029a934275e4be7b51a35e49a1ad74be1d934c1",
                expected_dual: "dd05613ebe944c29c840a5b61f948922b7759c1ad8857390fffad22712f3bdeb",
                expected_blake3_consistent: true,
            },
            DualRootCommitmentVector {
                description: "Edge: single-leaf document",
                document_parts: &["minimal"],
                blake3_root_hex: "cf57382d603eef611238e86c5d0fc6175326570ecfa4d1a6445d65f8d0b40d7f",
                poseidon_root_32be_hex: "16f987bf796eaea13eff0678e11b547e740e0490f01a3c3ef0dbf1027e649c99",
                expected_dual: "12c485379ad537098b351369c04b886a9ec40ca250943f2031cb7801c179e502",
                expected_blake3_consistent: true,
            },
            DualRootCommitmentVector {
                description: "Malformed: corrupted BLAKE3 root",
                document_parts: &["section A", "section B", "section C"],
                blake3_root_hex: "deadbeefa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
                poseidon_root_32be_hex: "18a53b4212bf0cf8cef46e92830204178bf8a3a266ddf389cce2cd4ae2e903e5",
                expected_dual: "b566feebc0ed143b717acd637f14ebd6ef5adf02d0d40ab9e5e4e90da2921660",
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
}

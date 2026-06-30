//! Witness JSON → typed-witness parsers for `POST /zk/prove`.
//!
//! Each parser turns the caller-supplied `witness` JSON object into a strongly
//! typed `crate::zk::witness::*` value, mapping every malformed-input case to a
//! `400 Bad Request` (`PAYLOAD_TOO_LARGE` for the array-length cap). The
//! functions are pure with respect to AppState — the only side input is the BJJ
//! authority keypair threaded through the redaction / unified parsers so the
//! issuer signature can be produced in-process (audit M-2). They are split out
//! of the route module so the bounds-checking logic can be unit-tested in
//! isolation.
//!
//! The whole module is gated behind the `prover` feature (declared
//! `#[cfg(feature = "prover")] mod parse;` in the parent), so no per-item cfg
//! attributes are needed here.

use axum::http::StatusCode;

use super::{err, ApiError};
use crate::zk::proof::parse_fr;

/// Maximum acceptable length for any witness JSON array, applied at parse
/// time before any per-element allocation. Real circuit witnesses are tiny
/// (≤256 Merkle siblings for the largest SMT depth, ≤16 redaction leaves,
/// ≤4096 unified-circuit document sections). The cap protects against a
/// pathological witness body (still within the 128 MB request limit) that
/// would otherwise drive serde + Vec<Fr> allocation before the strict
/// per-circuit length check in `Witness::new` could fire. Audit finding F-13.
const MAX_WITNESS_ARRAY_LEN: usize = 4096;

fn check_witness_array_len(field: &str, len: usize) -> Result<(), ApiError> {
    if len > MAX_WITNESS_ARRAY_LEN {
        return Err(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!(
                "{field}: array length {len} exceeds witness cap {MAX_WITNESS_ARRAY_LEN} \
                 (audit F-13)"
            ),
        ));
    }
    Ok(())
}

pub(super) fn parse_existence_witness(
    v: &serde_json::Value,
) -> Result<crate::zk::witness::ExistenceWitness, ApiError> {
    let root = parse_fr(
        v.get("root")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.root"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("root: {e}")))?;

    let leaf = parse_fr(
        v.get("leaf")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.leaf"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("leaf: {e}")))?;

    let leaf_index = v
        .get("leafIndex")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.leafIndex"))?;
    let tree_size = v
        .get("treeSize")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.treeSize"))?;

    let path_elements = parse_fr_array(v, "pathElements")?;
    let path_indices_arr = v
        .get("pathIndices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.pathIndices"))?;
    check_witness_array_len("pathIndices", path_indices_arr.len())?;
    let path_indices = path_indices_arr
        .iter()
        .map(|v| {
            v.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "pathIndices: not u8"))
        })
        .collect::<Result<Vec<u8>, _>>()?;

    crate::zk::witness::ExistenceWitness::new(
        root,
        leaf_index,
        tree_size,
        leaf,
        path_elements,
        path_indices,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

pub(super) fn parse_non_existence_witness(
    v: &serde_json::Value,
) -> Result<crate::zk::witness::NonExistenceWitness, ApiError> {
    let root = parse_fr(
        v.get("root")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.root"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("root: {e}")))?;

    let key_arr = v.get("key").and_then(|v| v.as_array()).ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "missing witness.key (32-byte array)",
        )
    })?;
    if key_arr.len() != 32 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("key must be 32 bytes, got {}", key_arr.len()),
        ));
    }
    let mut key = [0u8; 32];
    for (i, val) in key_arr.iter().enumerate() {
        key[i] = val
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("key[{i}]: not u8")))?;
    }

    let path_elements = parse_fr_array(v, "pathElements")?;

    crate::zk::witness::NonExistenceWitness::new(root, key, path_elements)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

fn parse_fr_array(v: &serde_json::Value, field: &str) -> Result<Vec<ark_bn254::Fr>, ApiError> {
    let arr = v
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("missing witness.{field}")))?;
    check_witness_array_len(field, arr.len())?;
    arr.iter()
        .enumerate()
        .map(|(i, val)| {
            parse_fr(val.as_str().ok_or_else(|| {
                err(
                    StatusCode::BAD_REQUEST,
                    &format!("{field}[{i}]: not string"),
                )
            })?)
            .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("{field}[{i}]: {e}")))
        })
        .collect()
}

pub(super) fn parse_unified_witness(
    v: &serde_json::Value,
    bjj_priv: &[u8; 32],
    bjj_pub: crate::zk::witness::baby_jubjub::BabyJubJubPubKey,
) -> Result<crate::zk::witness::UnifiedWitness, ApiError> {
    let canonical_hash = parse_fr(
        v.get("canonicalHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.canonicalHash"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("canonicalHash: {e}")))?;

    let merkle_root = parse_fr(
        v.get("merkleRoot")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.merkleRoot"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("merkleRoot: {e}")))?;

    let ledger_root = parse_fr(
        v.get("ledgerRoot")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.ledgerRoot"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("ledgerRoot: {e}")))?;

    let tree_size = v
        .get("treeSize")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.treeSize"))?;
    let checkpoint_timestamp = v
        .get("checkpointTimestamp")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "missing witness.checkpointTimestamp",
            )
        })?;
    let section_count = v
        .get("sectionCount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.sectionCount"))?;
    let leaf_index = v
        .get("leafIndex")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.leafIndex"))?;

    let document_sections = parse_fr_array(v, "documentSections")?;
    let section_hashes = parse_fr_array(v, "sectionHashes")?;
    let merkle_path = parse_fr_array(v, "merklePath")?;
    let ledger_path_elements = parse_fr_array(v, "ledgerPathElements")?;

    let section_lengths_arr = v
        .get("sectionLengths")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.sectionLengths"))?;
    check_witness_array_len("sectionLengths", section_lengths_arr.len())?;
    let section_lengths = section_lengths_arr
        .iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "sectionLengths: not u64"))
        })
        .collect::<Result<Vec<u64>, _>>()?;

    let merkle_indices = parse_u8_array(v, "merkleIndices")?;
    let ledger_key_vec = parse_u8_array(v, "ledgerKey")?;
    let ledger_key: [u8; 32] = ledger_key_vec.try_into().map_err(|v: Vec<u8>| {
        err(
            StatusCode::BAD_REQUEST,
            &format!("ledgerKey must have length 32, got {}", v.len()),
        )
    })?;

    let signature = crate::zk::witness::unified::UnifiedWitness::sign_checkpoint(
        bjj_priv,
        ledger_root,
        checkpoint_timestamp,
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("BJJ sign: {e}")))?;

    crate::zk::witness::UnifiedWitness::new(
        canonical_hash,
        merkle_root,
        ledger_root,
        tree_size,
        checkpoint_timestamp,
        bjj_pub,
        document_sections,
        section_count,
        section_lengths,
        section_hashes,
        merkle_path,
        merkle_indices,
        leaf_index,
        ledger_path_elements,
        ledger_key,
        signature,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

fn parse_u8_array(v: &serde_json::Value, field: &str) -> Result<Vec<u8>, ApiError> {
    let arr = v
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("missing witness.{field}")))?;
    check_witness_array_len(field, arr.len())?;
    arr.iter()
        .map(|v| {
            let n = v
                .as_u64()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("{field}: not u8")))?;
            u8::try_from(n).map_err(|_| {
                err(
                    StatusCode::BAD_REQUEST,
                    &format!("{field}: value {n} exceeds u8 range"),
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use serde_json::json;

    /// `"1"` is a canonical, in-field Fr decimal string accepted by `parse_fr`.
    const FR_ONE: &str = "1";

    /// Assert a parser returned an error with the expected status, without
    /// requiring the success type to be `Debug` (the witness structs are not).
    fn assert_err_status<T>(r: Result<T, ApiError>, want: StatusCode) {
        match r {
            Ok(_) => panic!("expected error {want}, got Ok"),
            Err((status, _)) => assert_eq!(status, want),
        }
    }

    // ── parse_existence_witness ────────────────────────────────────────────

    #[test]
    fn existence_happy_path() {
        // `ExistenceWitness::new` enforces `path_*.len() == DEPTH` (20), so a
        // witness that parses all the way through must supply a full path.
        let depth = crate::zk::witness::existence::DEPTH;
        let path_elements: Vec<&str> = std::iter::repeat_n(FR_ONE, depth).collect();
        let path_indices: Vec<u8> = vec![0u8; depth];
        let v = json!({
            "root": FR_ONE,
            "leaf": FR_ONE,
            "leafIndex": 0,
            "treeSize": 1,
            "pathElements": path_elements,
            "pathIndices": path_indices,
        });
        let w = parse_existence_witness(&v).expect("valid existence witness should parse");
        assert_eq!(w.path_elements.len(), depth);
        assert_eq!(w.path_indices.len(), depth);
    }

    #[test]
    fn existence_missing_root_is_400() {
        let v = json!({
            "leaf": FR_ONE,
            "leafIndex": 0,
            "treeSize": 1,
            "pathElements": [FR_ONE],
            "pathIndices": [0],
        });
        assert_err_status(parse_existence_witness(&v), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn existence_path_index_out_of_u8_range_is_400() {
        let v = json!({
            "root": FR_ONE,
            "leaf": FR_ONE,
            "leafIndex": 0,
            "treeSize": 1,
            "pathElements": [FR_ONE],
            "pathIndices": [256], // > u8::MAX
        });
        assert_err_status(parse_existence_witness(&v), StatusCode::BAD_REQUEST);
    }

    // ── parse_non_existence_witness ────────────────────────────────────────

    #[test]
    fn non_existence_rejects_wrong_key_length() {
        // `key` must be exactly 32 bytes; 31 is rejected before any Fr work.
        let key: Vec<u8> = vec![0u8; 31];
        let v = json!({
            "root": FR_ONE,
            "key": key,
            "pathElements": [FR_ONE],
        });
        assert_err_status(parse_non_existence_witness(&v), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn non_existence_missing_key_is_400() {
        let v = json!({
            "root": FR_ONE,
            "pathElements": [FR_ONE],
        });
        assert_err_status(parse_non_existence_witness(&v), StatusCode::BAD_REQUEST);
    }

    // ── parse_unified_witness ─────────────────────────────────────────────

    fn unified_json_with_ledger_key(ledger_key: Vec<u8>) -> serde_json::Value {
        let max_sections = crate::zk::witness::unified::MAX_SECTIONS;
        let merkle_depth = crate::zk::witness::unified::MERKLE_DEPTH;
        let smt_depth = crate::zk::witness::unified::SMT_DEPTH;
        json!({
            "canonicalHash": FR_ONE,
            "merkleRoot": FR_ONE,
            "ledgerRoot": FR_ONE,
            "treeSize": 1,
            "checkpointTimestamp": 123,
            "sectionCount": 1,
            "leafIndex": 0,
            "documentSections": vec![FR_ONE; max_sections],
            "sectionLengths": vec![1u64; max_sections],
            "sectionHashes": vec![FR_ONE; max_sections],
            "merklePath": vec![FR_ONE; merkle_depth],
            "merkleIndices": vec![0u8; merkle_depth],
            "ledgerPathElements": vec![FR_ONE; smt_depth],
            "ledgerKey": ledger_key,
        })
    }

    #[test]
    fn unified_accepts_32_byte_ledger_key() {
        let bjj_priv = [7u8; 32];
        let bjj_pub = crate::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&bjj_priv)
            .expect("valid BJJ private key");
        let ledger_key: Vec<u8> = (0u8..32).collect();
        let v = unified_json_with_ledger_key(ledger_key.clone());

        let w = parse_unified_witness(&v, &bjj_priv, bjj_pub)
            .expect("valid unified witness should parse");
        assert_eq!(w.ledger_key, ledger_key.as_slice());
        assert_eq!(w.public_signals().len(), 5);
    }

    #[test]
    fn unified_rejects_short_ledger_key() {
        let bjj_priv = [7u8; 32];
        let bjj_pub = crate::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&bjj_priv)
            .expect("valid BJJ private key");
        let v = unified_json_with_ledger_key(vec![0u8; 31]);

        assert_err_status(
            parse_unified_witness(&v, &bjj_priv, bjj_pub),
            StatusCode::BAD_REQUEST,
        );
    }

    // ── array-length cap (audit F-13) ──────────────────────────────────────

    #[test]
    fn fr_array_over_cap_is_413() {
        // A `pathElements` array one past the cap must trip the F-13 guard
        // with PAYLOAD_TOO_LARGE, before per-element Fr parsing.
        let big: Vec<&str> = std::iter::repeat_n(FR_ONE, MAX_WITNESS_ARRAY_LEN + 1).collect();
        let v = json!({
            "root": FR_ONE,
            "leaf": FR_ONE,
            "leafIndex": 0,
            "treeSize": 1,
            "pathElements": big,
            "pathIndices": [0],
        });
        assert_err_status(parse_existence_witness(&v), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn check_witness_array_len_boundary() {
        // Exactly at the cap is allowed; one past is not.
        assert!(check_witness_array_len("f", MAX_WITNESS_ARRAY_LEN).is_ok());
        assert_err_status(
            check_witness_array_len("f", MAX_WITNESS_ARRAY_LEN + 1),
            StatusCode::PAYLOAD_TOO_LARGE,
        );
    }

    // ── parse_u8_array ─────────────────────────────────────────────────────

    #[test]
    fn u8_array_rejects_out_of_range() {
        let v = json!({ "merkleIndices": [0, 1, 300] });
        assert_err_status(parse_u8_array(&v, "merkleIndices"), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn u8_array_happy_path() {
        let v = json!({ "merkleIndices": [0, 1, 0, 255] });
        let out = parse_u8_array(&v, "merkleIndices").expect("valid u8 array");
        assert_eq!(out, vec![0u8, 1, 0, 255]);
    }

    #[test]
    fn u8_array_missing_field_is_400() {
        let v = json!({});
        assert_err_status(parse_u8_array(&v, "merkleIndices"), StatusCode::BAD_REQUEST);
    }

    // ── parse_fr_array ─────────────────────────────────────────────────────

    #[test]
    fn fr_array_non_string_element_is_400() {
        // A numeric (non-string) element is rejected: Fr inputs are decimal
        // strings, never JSON numbers.
        let v = json!({ "pathElements": [1] });
        assert_err_status(parse_fr_array(&v, "pathElements"), StatusCode::BAD_REQUEST);
    }
}

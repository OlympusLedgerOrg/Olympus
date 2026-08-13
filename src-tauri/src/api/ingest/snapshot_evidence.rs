// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared lookup + parse of a committed record's stored Poseidon
//! ledger-snapshot inclusion witness (migration 0029's `snapshot_*` columns).
//!
//! Split out of `proof_verify.rs` (`POST /ingest/proofs/verify`, which
//! verifies the stored snapshot server-side and returns only a verdict) so
//! `api::monitor::proof` (which serves the raw witness for third-party
//! offline verification, per ADR-0021's Monitor API) can reuse the exact same
//! row-fetch and JSON-shape parsing instead of maintaining a second copy that
//! could drift from `build_snapshot_in_tx`'s producer shape
//! (`src-tauri/src/api/ingest/files/snapshot.rs`).
//!
//! `parse_stored_snapshot` is deliberately pure (no DB, no I/O) so the JSON
//! shape it accepts is unit-testable without a pool.

use chrono::NaiveDateTime;
use olympus_crypto::ledger_snapshot::LedgerSnapshot;
use sqlx::PgPool;

use crate::api::ingest::SNAPSHOT_SIG_ALG;

/// One `ingest_records` row's snapshot-relevant columns, as stored.
#[derive(sqlx::FromRow)]
pub(crate) struct SnapshotRow {
    pub(crate) proof_id: String,
    pub(crate) shard_id: String,
    pub(crate) record_type: String,
    /// Ingest-commit time (server clock, naive UTC) — the moment this record
    /// became part of the ledger. Used by `api::monitor::mmd` as the "MMD
    /// clock start"; unused by `proof_verify`/`monitor::proof`.
    pub(crate) ts: NaiveDateTime,
    pub(crate) original_root: Option<String>,
    pub(crate) snapshot_root: Option<String>,
    pub(crate) snapshot_index: Option<i64>,
    pub(crate) snapshot_size: Option<i64>,
    pub(crate) snapshot_path: Option<serde_json::Value>,
    pub(crate) snapshot_sig: Option<String>,
    pub(crate) snapshot_sig_legacy: bool,
}

/// Fetch the earliest-committed row for `content_hash` (per-shard-unique
/// only — audit A1: earliest-wins), or `None` if the hash isn't in the
/// ledger at all.
pub(crate) async fn fetch_snapshot_row(
    pool: &PgPool,
    content_hash: &str,
) -> Result<Option<SnapshotRow>, sqlx::Error> {
    sqlx::query_as::<_, SnapshotRow>(
        "SELECT proof_id, shard_id, record_type, ts, original_root, snapshot_root, \
                snapshot_index, snapshot_size, snapshot_path, snapshot_sig, \
                snapshot_sig_legacy \
         FROM ingest_records WHERE content_hash = $1 \
         ORDER BY ts ASC, proof_id ASC LIMIT 1",
    )
    .bind(content_hash)
    .fetch_optional(pool)
    .await
}

/// Why a row's snapshot evidence isn't available to parse/verify, mirroring
/// [`crate::api::ingest::SnapshotVerifyStatus`]'s `Pending` reasons.
pub(crate) fn pending_detail(record_type: &str) -> &'static str {
    if record_type != "file" && record_type != "redaction" {
        "Record exists but has no Poseidon snapshot — non-file records \
         (legacy JSON commits from the pre-H-5 route) are not anchored \
         in the chunked ledger tree."
    } else {
        "Record exists but has no Poseidon snapshot yet — legacy row from \
         before atomic-ingest. Re-upload the original bytes through \
         /ingest/files to back-fill the snapshot columns."
    }
}

/// Parse a row's `original_root` + `snapshot_root`/`_index`/`_size` +
/// `snapshot_path` (JSON `{path_elements, path_indices}`) + `snapshot_sig`
/// (JSON `{alg, r8x, r8y, s, signed_at?}`) into a verifiable
/// [`LedgerSnapshot`] plus the leaf (`original_root`).
///
/// Callers must check `snapshot_sig_legacy` themselves first (a legacy
/// Ed25519-era signature is a distinct, non-parseable case this function
/// does not classify) and must have already confirmed every snapshot column
/// is `Some` (a `None` column means `Pending`, not malformed).
///
/// Returns `Err(detail)` on any structurally malformed field — matches
/// `proof_verify.rs`'s prior inline behavior message-for-message so its
/// `SnapshotVerifyStatus::Invalid` responses are unchanged by this refactor.
#[allow(clippy::too_many_arguments)]
pub(crate) fn parse_stored_snapshot(
    snapshot_root: &str,
    snapshot_index: i64,
    snapshot_size: i64,
    snapshot_path: &serde_json::Value,
    snapshot_sig: &str,
) -> Result<LedgerSnapshot, &'static str> {
    let path_obj = snapshot_path
        .as_object()
        .ok_or("Stored snapshot_path is not a JSON object.")?;
    let path_elements_hex: Vec<String> = path_obj
        .get("path_elements")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(|s| s.to_owned()))
                .collect()
        })
        .ok_or("Stored snapshot_path.path_elements is missing or malformed.")?;
    let path_indices: Vec<u8> = path_obj
        .get("path_indices")
        .and_then(|v| v.as_array())
        .and_then(|a| {
            // Each index is a binary-tree direction bit (0 or 1). Reject
            // non-integers and out-of-domain values instead of silently
            // truncating with `as u8` (e.g. 256 -> 0) or dropping bad
            // elements — corruption must surface as an error, not a wrong
            // proof.
            a.iter()
                .map(|e| match e.as_u64() {
                    Some(n) if n <= 1 => Some(n as u8),
                    _ => None,
                })
                .collect::<Option<Vec<u8>>>()
        })
        .ok_or("Stored snapshot_path.path_indices is missing or malformed.")?;

    let sig_json: serde_json::Value =
        serde_json::from_str(snapshot_sig).map_err(|_| "Stored snapshot_sig is not valid JSON.")?;
    // Algorithm discriminator MUST match the producer (`build_snapshot_in_tx`).
    // Without this gate, an attacker who can write to `snapshot_sig` could
    // swap in r8x/r8y/s values from a different signature scheme and the
    // verifier would happily attempt BJJ verification on them — a
    // confused-deputy on the sig family.
    match sig_json.get("alg").and_then(|v| v.as_str()) {
        Some(SNAPSHOT_SIG_ALG) => {}
        _ => return Err("Stored snapshot_sig has wrong or missing alg discriminator."),
    }
    let (sig_r8x, sig_r8y, sig_s) = match (
        sig_json.get("r8x").and_then(|v| v.as_str()),
        sig_json.get("r8y").and_then(|v| v.as_str()),
        sig_json.get("s").and_then(|v| v.as_str()),
    ) {
        (Some(x), Some(y), Some(s)) => (x.to_owned(), y.to_owned(), s.to_owned()),
        _ => return Err("Stored snapshot_sig is missing r8x/r8y/s."),
    };
    // Optional authenticated signing time (V2 snapshots). Present → the V2
    // signing digest covers it; absent → legacy V1 row. A present-but-non-
    // integer value is corruption, not legacy.
    let signed_at_unix: Option<i64> = match sig_json.get("signed_at") {
        None => None,
        Some(v) => Some(
            v.as_i64()
                .ok_or("Stored snapshot_sig.signed_at is not an integer.")?,
        ),
    };

    Ok(LedgerSnapshot {
        snapshot_root: snapshot_root.to_owned(),
        snapshot_index: snapshot_index as u64,
        snapshot_size: snapshot_size as u64,
        path_elements_hex,
        path_indices,
        signature_r8x: sig_r8x,
        signature_r8y: sig_r8y,
        signature_s: sig_s,
        signed_at_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig_json(extra: &str) -> String {
        format!(
            r#"{{"alg":"bjj-eddsa-poseidon","r8x":"aa","r8y":"bb","s":"cc"{}}}"#,
            extra
        )
    }

    #[test]
    fn parses_a_well_formed_v1_snapshot() {
        let path = serde_json::json!({
            "path_elements": ["11".repeat(32), "22".repeat(32)],
            "path_indices": [0, 1],
        });
        let snap = parse_stored_snapshot("aa".repeat(32).as_str(), 5, 6, &path, &sig_json(""))
            .expect("well-formed snapshot parses");
        assert_eq!(snap.snapshot_index, 5);
        assert_eq!(snap.snapshot_size, 6);
        assert_eq!(snap.path_elements_hex.len(), 2);
        assert_eq!(snap.path_indices, vec![0, 1]);
        assert_eq!(snap.signature_r8x, "aa");
        assert!(snap.signed_at_unix.is_none());
    }

    #[test]
    fn parses_a_well_formed_v2_snapshot_with_signed_at() {
        let path = serde_json::json!({"path_elements": [], "path_indices": []});
        let snap = parse_stored_snapshot(
            "aa".repeat(32).as_str(),
            0,
            1,
            &path,
            &sig_json(r#","signed_at":1700000000"#),
        )
        .expect("v2 snapshot parses");
        assert_eq!(snap.signed_at_unix, Some(1_700_000_000));
    }

    #[test]
    fn rejects_wrong_alg_discriminator() {
        let path = serde_json::json!({"path_elements": [], "path_indices": []});
        let bad = r#"{"alg":"ed25519","r8x":"aa","r8y":"bb","s":"cc"}"#;
        assert_eq!(
            parse_stored_snapshot("aa".repeat(32).as_str(), 0, 0, &path, bad),
            Err("Stored snapshot_sig has wrong or missing alg discriminator.")
        );
    }

    #[test]
    fn rejects_out_of_domain_path_index() {
        let path = serde_json::json!({"path_elements": ["11".repeat(32)], "path_indices": [2]});
        assert_eq!(
            parse_stored_snapshot("aa".repeat(32).as_str(), 0, 1, &path, &sig_json("")),
            Err("Stored snapshot_path.path_indices is missing or malformed.")
        );
    }

    #[test]
    fn rejects_non_integer_signed_at() {
        let path = serde_json::json!({"path_elements": [], "path_indices": []});
        let bad = sig_json(r#","signed_at":"soon""#);
        assert_eq!(
            parse_stored_snapshot("aa".repeat(32).as_str(), 0, 0, &path, &bad),
            Err("Stored snapshot_sig.signed_at is not an integer.")
        );
    }

    #[test]
    fn rejects_malformed_sig_json() {
        let path = serde_json::json!({"path_elements": [], "path_indices": []});
        assert_eq!(
            parse_stored_snapshot("aa".repeat(32).as_str(), 0, 0, &path, "not json"),
            Err("Stored snapshot_sig is not valid JSON.")
        );
    }
}

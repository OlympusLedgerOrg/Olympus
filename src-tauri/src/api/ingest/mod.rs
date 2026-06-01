//! Ingest and hash-verification routes — port of `api/routers/ledger.py` ingest paths.
//!
//! Routes
//! ------
//! POST /ingest/files                            — commit a file (server hashes bytes)
//! GET  /ingest/records/hash/{hash}/verify       — look up a record by content hash
//! GET  /ingest/records/{proof_id}               — fetch full record detail by proof_id
//!
//! Audit H-5: the JSON `POST /ingest/records` endpoint was removed in
//! this revision. That route accepted a client-supplied `content.blake3`
//! attestation without ever seeing the file bytes — a "verifiable
//! ledger" cannot have a front door that takes anyone's word for the
//! hash of the data they're attesting to. Clients that need to commit
//! a record now MUST upload bytes through `/ingest/files`, which hashes
//! them server-side and is the only ingress that produces a binding
//! between content and on-ledger commitment.
//! POST /ingest/proofs/verify                    — offline proof bundle verification

use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

mod files;
mod proof_verify;
mod read;
mod zk_bundle;

use files::ingest_file;
use proof_verify::verify_proof_bundle;
use read::{get_record, verify_by_hash};
use zk_bundle::issue_zk_bundle;
// ── Error helper ──────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail})))
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

fn naive_utc() -> NaiveDateTime {
    Utc::now().naive_utc()
}

// ── DB row ────────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct IngestRow {
    proof_id: String,
    record_id: String,
    shard_id: String,
    record_type: String,
    content_hash: String,
    merkle_root: Option<String>,
    ledger_entry_hash: String,
    ts: NaiveDateTime,
    batch_id: Option<String>,
    poseidon_root: Option<String>,
    canonicalization: Option<String>,
    merkle_proof_json: Option<String>,
    original_hash: Option<String>,
}

// ── Request / Response schemas ─────────────────────────────────────────────────
//
// Audit H-5: `RecordContent`, `IngestRecord`, `IngestRequest`, and
// `IngestResponse` were removed alongside the `POST /ingest/records`
// route — they only existed to deserialise client-attested blake3
// hashes, which is the exact pattern H-5 closes. The remaining
// `CommitResult` is reused by `POST /ingest/files` (server hashes the
// bytes), the only sanctioned commit ingress.

#[derive(Serialize)]
pub struct CommitResult {
    pub proof_id: String,
    pub content_hash: String,
    pub record_id: String,
    pub shard_id: String,
    pub deduplicated: bool,
}

/// Response for GET /ingest/records/hash/{hash}/verify and GET /ingest/records/{proof_id}
#[derive(Serialize)]
pub struct RecordProofResponse {
    pub proof_id: String,
    pub record_id: String,
    pub shard_id: String,
    pub record_type: String,
    pub content_hash: String,
    pub merkle_root: String,
    pub ledger_entry_hash: String,
    pub timestamp: String,
    pub batch_id: Option<String>,
    pub poseidon_root: Option<String>,
    pub canonicalization: Option<serde_json::Value>,
    pub merkle_proof: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_proof_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_hash: Option<String>,
    pub is_redacted: bool,
}

/// POST /ingest/proofs/verify
///
/// The legacy binary Merkle proof bundle (removed with the binary tree itself)
/// is no longer required in the request — clients only need to supply the
/// `content_hash` they want a snapshot decision for. `proof_id`,
/// `merkle_root`, and `merkle_proof` are accepted for backwards compatibility
/// and ignored.
#[derive(Deserialize)]
pub struct ProofVerifyRequest {
    pub proof_id: Option<String>,
    pub content_hash: String,
    #[serde(default)]
    pub merkle_root: Option<String>,
    #[serde(default)]
    pub merkle_proof: Option<serde_json::Value>,
}

/// Snapshot-verification outcome. Explicit enum so a client never has to
/// disambiguate "the snapshot proves nothing" (pending / unknown) from "the
/// snapshot is actively invalid" (tampered / wrong key) — the legacy flat
/// `merkle_proof_valid: false` conflated the two.
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotVerifyStatus {
    /// Record has a snapshot, the path reconstructs `snapshot_root`, and the
    /// authority's Ed25519 signature over the canonical payload is valid.
    Verified,
    /// Record exists but has no Poseidon snapshot yet (JSON-record commits
    /// today have no chunkable bytes, and file commits where the snapshot
    /// build failed leave the columns NULL). The hash IS in the ledger; the
    /// inclusion witness just isn't anchored yet. NOT a rejection.
    Pending,
    /// Snapshot columns are present but `verify_snapshot` rejected: the
    /// reconstructed root didn't match, the signature didn't verify under
    /// the authority pubkey, or a field was malformed. This is the only
    /// state a client should treat as "the server is contradicting itself".
    Invalid,
    /// `content_hash` is not in the ledger at all.
    Unknown,
}

#[derive(Serialize)]
pub struct ProofVerifyResponse {
    pub proof_id: Option<String>,
    pub content_hash: String,
    /// Authoritative state — see [`SnapshotVerifyStatus`].
    pub status: SnapshotVerifyStatus,
    /// Human-readable explanation for the status (UI display).
    pub detail: String,
    /// True iff a record with this `content_hash` exists in the ledger.
    pub known_to_server: bool,
    /// Snapshot fields, when present. All `None` for `pending`/`unknown`.
    pub snapshot_root: Option<String>,
    pub snapshot_index: Option<u64>,
    pub snapshot_size: Option<u64>,
    /// Legacy compatibility:
    /// - `Some(true)`  → verified
    /// - `Some(false)` → invalid (server-stored snapshot fails verification)
    /// - `None`        → pending / unknown (NOT a rejection)
    ///
    /// New clients should read `status` instead.
    pub merkle_proof_valid: Option<bool>,
    /// Legacy mirror of `snapshot_root` (binary Merkle root is retired).
    pub merkle_root: String,
    /// Legacy alias for `snapshot_root`.
    pub poseidon_root: Option<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn sanitize_shard(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-'))
}

fn zero_root() -> String {
    "0000000000000000000000000000000000000000000000000000000000000000".to_owned()
}

fn row_to_proof_response(row: &IngestRow, _for_verify: bool) -> RecordProofResponse {
    let canon: Option<serde_json::Value> = row
        .canonicalization
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());

    let proof_val: serde_json::Value = row
        .merkle_proof_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::json!({}));

    let root = row.merkle_root.clone().unwrap_or_else(zero_root);

    let is_redacted = row.record_type == "redaction" || row.original_hash.is_some();

    RecordProofResponse {
        proof_id: row.proof_id.clone(),
        record_id: row.record_id.clone(),
        shard_id: row.shard_id.clone(),
        record_type: row.record_type.clone(),
        content_hash: row.content_hash.clone(),
        merkle_root: root,
        ledger_entry_hash: row.ledger_entry_hash.clone(),
        timestamp: row.ts.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        batch_id: row.batch_id.clone(),
        poseidon_root: row.poseidon_root.clone(),
        canonicalization: canon,
        merkle_proof: proof_val,
        // Binary Merkle proofs were removed; authoritative inclusion is now the
        // signed Poseidon ledger snapshot (zk::snapshot).
        merkle_proof_valid: None,
        original_hash: row.original_hash.clone(),
        is_redacted,
    }
}

// ── Shared snapshot-signature discriminator ─────────────────────────────────────

/// Algorithm discriminator stored in the `snapshot_sig` JSON object's `alg`
/// field. The producer (`files::build_snapshot_in_tx`) and the verifier
/// (`proof_verify::verify_proof_bundle`) both reference this constant so the
/// on-disk shape is bound to a single signature scheme — the verifier refuses
/// to attempt BJJ verification against bytes labelled with any other algorithm.
pub(super) const SNAPSHOT_SIG_ALG: &str = "bjj-eddsa-poseidon";
// ── Route: POST /ingest/records (REMOVED — audit H-5) ───────────────────
//
// The JSON commit endpoint that accepted a client-supplied
// `content.blake3` attestation was removed. It violated the headline
// integrity claim of the system: the ledger committed to a hash that
// the server never saw the preimage of, so a malicious or buggy client
// could anchor "evidence" whose actual bytes never existed.
//
// Legitimate use cases:
//   * Committing a file → POST /ingest/files (server hashes the bytes).
//   * Re-anchoring an existing record → no API needed; the existing
//     row is already on-ledger.
//   * Proving non-membership of an arbitrary hash → /zk/prove with
//     `non_existence` circuit (no commit required).
//
// If a future workflow truly needs a "client-attests-to-bytes" path,
// it MUST come with an in-circuit proof-of-preimage (the existing
// chunk-tree + snapshot infrastructure provides ~80% of what's needed).
// Until then, keep this surface closed.
// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    // Audit H-5: `/ingest/records` (POST, JSON-attestation commit) is
    // intentionally NOT registered. See the module docstring + the
    // `// ── Route: POST /ingest/records (REMOVED — audit H-5) ──` block
    // above for the rationale. Clients should use `/ingest/files`
    // (server-hashed bytes) instead.
    Router::new()
        .route("/ingest/files", post(ingest_file))
        // The hash routes MUST be registered before the /{proof_id} catch-all.
        .route("/ingest/records/hash/{hash}/verify", get(verify_by_hash))
        .route(
            "/ingest/records/hash/{hash}/zk_bundle",
            get(issue_zk_bundle),
        )
        .route("/ingest/records/{proof_id}", get(get_record))
        .route("/ingest/proofs/verify", post(verify_proof_bundle))
}

/// Read/verify-only subset safe to expose over the federation Tor onion
/// service. Excludes writes (`/ingest/files`, `/ingest/records`) and the
/// bundle-issuing `zk_bundle` route. The hash route stays registered before
/// the `/{proof_id}` catch-all.
#[cfg(feature = "federation")]
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/ingest/records/hash/{hash}/verify", get(verify_by_hash))
        .route("/ingest/records/{proof_id}", get(get_record))
        .route("/ingest/proofs/verify", post(verify_proof_bundle))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_shard_accepts_valid() {
        assert!(sanitize_shard("files"));
        assert!(sanitize_shard("shard-1"));
        assert!(sanitize_shard("0x4F3A"));
        assert!(sanitize_shard("us:east.1"));
    }

    #[test]
    fn sanitize_shard_rejects_invalid() {
        assert!(!sanitize_shard(""));
        assert!(!sanitize_shard("has space"));
        assert!(!sanitize_shard("../escape"));
        assert!(!sanitize_shard(&"x".repeat(129)));
    }

    #[test]
    fn zero_root_is_64_hex_zeros() {
        let r = zero_root();
        assert_eq!(r.len(), 64);
        assert!(r.chars().all(|c| c == '0'));
    }

    // ── row_to_proof_response ───────────────────────────────────────────────

    /// A minimal non-redacted "file" row with all optional columns NULL.
    fn sample_row() -> IngestRow {
        IngestRow {
            proof_id: "proof-1".into(),
            record_id: "rec-1".into(),
            shard_id: "files".into(),
            record_type: "file".into(),
            content_hash: "ab".repeat(32),
            merkle_root: None,
            ledger_entry_hash: "leh".into(),
            ts: naive_utc(),
            batch_id: None,
            poseidon_root: None,
            canonicalization: None,
            merkle_proof_json: None,
            original_hash: None,
        }
    }

    #[test]
    fn row_to_proof_response_defaults_and_non_redacted() {
        let resp = row_to_proof_response(&sample_row(), false);
        // NULL merkle_root falls back to the all-zero root sentinel.
        assert_eq!(resp.merkle_root, zero_root());
        // Plain "file" with no original_hash is not a redaction.
        assert!(!resp.is_redacted);
        // Binary Merkle proofs are retired -> validity is always None.
        assert_eq!(resp.merkle_proof_valid, None);
        // NULL canonicalization -> None; NULL proof JSON -> empty object.
        assert!(resp.canonicalization.is_none());
        assert_eq!(resp.merkle_proof, serde_json::json!({}));
    }

    #[test]
    fn row_to_proof_response_redaction_by_type() {
        let mut row = sample_row();
        row.record_type = "redaction".into();
        assert!(row_to_proof_response(&row, false).is_redacted);
    }

    #[test]
    fn row_to_proof_response_redaction_by_original_hash() {
        // A "file" row carrying an original_hash is still a redaction.
        let mut row = sample_row();
        row.original_hash = Some("cd".repeat(32));
        let resp = row_to_proof_response(&row, false);
        assert!(resp.is_redacted);
        assert_eq!(resp.original_hash, Some("cd".repeat(32)));
    }

    #[test]
    fn row_to_proof_response_parses_canonicalization_and_proof() {
        let mut row = sample_row();
        row.merkle_root = Some("ff".repeat(32));
        row.canonicalization = Some(r#"{"scheme":"jcs"}"#.into());
        row.merkle_proof_json = Some(r#"{"path":[]}"#.into());
        let resp = row_to_proof_response(&row, true);
        assert_eq!(resp.merkle_root, "ff".repeat(32));
        assert_eq!(resp.canonicalization, Some(serde_json::json!({"scheme": "jcs"})));
        assert_eq!(resp.merkle_proof, serde_json::json!({"path": []}));
    }

    #[test]
    fn row_to_proof_response_malformed_json_falls_back() {
        // Malformed stored JSON must not panic: canonicalization -> None,
        // merkle_proof -> empty object.
        let mut row = sample_row();
        row.canonicalization = Some("not json".into());
        row.merkle_proof_json = Some("also not json".into());
        let resp = row_to_proof_response(&row, false);
        assert!(resp.canonicalization.is_none());
        assert_eq!(resp.merkle_proof, serde_json::json!({}));
    }
}

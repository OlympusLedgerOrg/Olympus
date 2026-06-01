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
    extract::{Multipart, Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization as _;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::ingest_provenance::IngestProvenance;
use crate::smt::{LeafUpdate, PersistentSmt, PgBackend};
use crate::state::AppState;
use crate::zk::chunk::{chunk_tree_from_bytes, fr_to_hex};
use crate::zk::snapshot::{snapshot_new_record, LedgerSnapshot};

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
// ── Route: GET /ingest/records/hash/{hash}/verify ─────────────────────────────

async fn verify_by_hash(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(hash): Path<String>,
) -> Result<Json<RecordProofResponse>, ApiError> {
    let hash = hash.trim().to_lowercase();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Hash must be a 64-character hex string.",
        ));
    }

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    // Audit A1: content_hash is unique only per shard (migration 0038), so the
    // same bytes may exist in several shards. Resolve deterministically to the
    // EARLIEST commit (earliest-wins) so a later commit under another shard —
    // e.g. an attacker's — can never shadow the original's verify response.
    let row = sqlx::query_as::<_, IngestRow>(
        "SELECT proof_id, record_id, shard_id, record_type, content_hash, merkle_root,
                ledger_entry_hash, ts, batch_id, poseidon_root, canonicalization, merkle_proof_json, original_hash
         FROM ingest_records
         WHERE content_hash = $1
         ORDER BY ts ASC, proof_id ASC
         LIMIT 1",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Hash not found in ledger."))?;

    Ok(Json(row_to_proof_response(&row, true)))
}

// ── Route: GET /ingest/records/{proof_id} ────────────────────────────────────

async fn get_record(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(proof_id): Path<String>,
) -> Result<Json<RecordProofResponse>, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let row = sqlx::query_as::<_, IngestRow>(
        "SELECT proof_id, record_id, shard_id, record_type, content_hash, merkle_root,
                ledger_entry_hash, ts, batch_id, poseidon_root, canonicalization, merkle_proof_json, original_hash
         FROM ingest_records
         WHERE proof_id = $1
         LIMIT 1",
    )
    .bind(&proof_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Record not found."))?;

    Ok(Json(row_to_proof_response(&row, false)))
}

// ── Route: POST /ingest/proofs/verify ────────────────────────────────────────

async fn verify_proof_bundle(
    State(state): State<AppState>,
    _rl: RateLimit,
    Json(body): Json<ProofVerifyRequest>,
) -> Result<Json<ProofVerifyResponse>, ApiError> {
    use olympus_crypto::ledger_snapshot::{verify_snapshot, LedgerSnapshot as CryptoSnapshot};

    let content_hash = body.content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    // Pull the row + every snapshot column in one go. NULL snapshot columns
    // mean the record exists but the inclusion witness hasn't been built
    // (legacy rows from pre-migration-0029 or the removed pre-H-5 JSON
    // commit path — new ingests through /ingest/files always populate the
    // snapshot atomically with the row INSERT). That's `Pending`, NOT
    // `Invalid`.
    #[derive(sqlx::FromRow)]
    struct Row {
        proof_id: String,
        record_type: String,
        original_root: Option<String>,
        snapshot_root: Option<String>,
        snapshot_index: Option<i64>,
        snapshot_size: Option<i64>,
        snapshot_path: Option<serde_json::Value>,
        snapshot_sig: Option<String>,
        snapshot_sig_legacy: bool,
    }
    let row_opt: Option<Row> = sqlx::query_as::<_, Row>(
        // Audit A1: earliest-wins — content_hash is per-shard unique only.
        "SELECT proof_id, record_type, original_root, snapshot_root, snapshot_index, \
                snapshot_size, snapshot_path, snapshot_sig, snapshot_sig_legacy \
         FROM ingest_records WHERE content_hash = $1 \
         ORDER BY ts ASC, proof_id ASC LIMIT 1",
    )
    .bind(&content_hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    // Helper to assemble a response — keeps the legacy fields populated from
    // the new authoritative ones so existing clients don't 500.
    #[allow(clippy::too_many_arguments)] // wide ProofVerifyResponse shape; refactoring out of scope here
    fn build(
        body_proof_id: Option<String>,
        row_proof_id: Option<String>,
        content_hash: String,
        status: SnapshotVerifyStatus,
        detail: &str,
        snapshot_root: Option<String>,
        snapshot_index: Option<u64>,
        snapshot_size: Option<u64>,
    ) -> ProofVerifyResponse {
        let merkle_proof_valid = match status {
            SnapshotVerifyStatus::Verified => Some(true),
            SnapshotVerifyStatus::Invalid => Some(false),
            SnapshotVerifyStatus::Pending | SnapshotVerifyStatus::Unknown => None,
        };
        let known_to_server = row_proof_id.is_some();
        let merkle_root = snapshot_root.clone().unwrap_or_else(zero_root);
        ProofVerifyResponse {
            proof_id: body_proof_id.or(row_proof_id),
            content_hash,
            status,
            detail: detail.to_owned(),
            known_to_server,
            snapshot_root: snapshot_root.clone(),
            snapshot_index,
            snapshot_size,
            merkle_proof_valid,
            merkle_root,
            poseidon_root: snapshot_root,
        }
    }

    let row = match row_opt {
        Some(r) => r,
        None => {
            return Ok(Json(build(
                body.proof_id,
                None,
                content_hash,
                SnapshotVerifyStatus::Unknown,
                "content_hash is not present in the ledger.",
                None,
                None,
                None,
            )));
        }
    };

    // Legacy Ed25519-era snapshot: the attestation bytes are preserved on
    // disk (so a future operator restoring the old authority pubkey can
    // cross-check offline) but the current BJJ verifier can't validate
    // them. Surface as pending with a clear reason so clients don't
    // misread it as a cryptographic failure.
    if row.snapshot_sig_legacy {
        return Ok(Json(build(
            body.proof_id,
            Some(row.proof_id),
            content_hash,
            SnapshotVerifyStatus::Pending,
            "Record carries a pre-BJJ (Ed25519-era) snapshot signature that the current \
             verifier cannot validate. The attestation data is preserved; the record will \
             need to be re-snapshotted under the BJJ authority for an inclusion witness.",
            row.snapshot_root.clone(),
            row.snapshot_index.map(|i| i as u64),
            row.snapshot_size.map(|i| i as u64),
        )));
    }

    // Snapshot columns are all-or-nothing — if any required field is NULL we
    // can't verify, but the record IS known. Surface `pending` with a reason
    // that distinguishes legacy non-file records (no chunkable bytes) from
    // legacy-file rows that simply need re-upload to back-fill.
    let (
        original_root,
        snapshot_root_str,
        snapshot_index_i,
        snapshot_size_i,
        snapshot_path_json,
        snapshot_sig_hex,
    ) = match (
        row.original_root.as_deref(),
        row.snapshot_root.as_deref(),
        row.snapshot_index,
        row.snapshot_size,
        row.snapshot_path.as_ref(),
        row.snapshot_sig.as_deref(),
    ) {
        (Some(or), Some(sr), Some(si), Some(sz), Some(sp), Some(sg)) => (
            or.to_owned(),
            sr.to_owned(),
            si,
            sz,
            sp.clone(),
            sg.to_owned(),
        ),
        _ => {
            let detail = if row.record_type != "file" && row.record_type != "redaction" {
                "Record exists but has no Poseidon snapshot — non-file records \
                     (legacy JSON commits from the pre-H-5 route) are not anchored \
                     in the chunked ledger tree."
            } else {
                "Record exists but has no Poseidon snapshot yet — legacy row from \
                     before atomic-ingest. Re-upload the original bytes through \
                     /ingest/files to back-fill the snapshot columns."
            };
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Pending,
                detail,
                None,
                None,
                None,
            )));
        }
    };

    // Parse the stored snapshot_path JSON shape produced by
    // `build_snapshot_in_tx`: { path_elements: [hex…], path_indices: [u8…] }.
    let path_obj = match snapshot_path_json.as_object() {
        Some(o) => o,
        None => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                "Stored snapshot_path is not a JSON object.",
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    };
    let path_elements_hex: Vec<String> = match path_obj
        .get("path_elements")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(|s| s.to_owned()))
                .collect()
        }) {
        Some(v) => v,
        None => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                "Stored snapshot_path.path_elements is missing or malformed.",
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    };
    let path_indices: Vec<u8> = {
        let arr = match path_obj.get("path_indices").and_then(|v| v.as_array()) {
            Some(a) => a,
            None => {
                return Ok(Json(build(
                    body.proof_id,
                    Some(row.proof_id),
                    content_hash,
                    SnapshotVerifyStatus::Invalid,
                    "Stored snapshot_path.path_indices is missing or malformed.",
                    Some(snapshot_root_str),
                    Some(snapshot_index_i as u64),
                    Some(snapshot_size_i as u64),
                )))
            }
        };
        let mut out: Vec<u8> = Vec::with_capacity(arr.len());
        for e in arr {
            // Binary-tree path indices are bits: only 0 or 1 are valid. Reject
            // non-integers and out-of-range values rather than silently
            // truncating (e.g. `260u64 as u8 == 4`) or dropping them, which
            // would mask corruption of the stored snapshot path.
            match e.as_u64() {
                Some(n) if n <= 1 => out.push(n as u8),
                _ => {
                    return Ok(Json(build(
                        body.proof_id,
                        Some(row.proof_id),
                        content_hash,
                        SnapshotVerifyStatus::Invalid,
                        "Stored snapshot_path.path_indices is missing or malformed.",
                        Some(snapshot_root_str),
                        Some(snapshot_index_i as u64),
                        Some(snapshot_size_i as u64),
                    )));
                }
            }
        }
        out
    };

    // The stored `snapshot_sig` is a JSON object — see
    // `build_snapshot_in_tx` for the producer shape.
    let sig_json: serde_json::Value = match serde_json::from_str(&snapshot_sig_hex) {
        Ok(v) => v,
        Err(_) => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                "Stored snapshot_sig is not valid JSON.",
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    };
    // Algorithm discriminator MUST match the producer (`build_snapshot_in_tx`).
    // Without this gate, an attacker who can write to `snapshot_sig` could swap in
    // r8x/r8y/s values from a different signature scheme and the verifier would
    // happily attempt BJJ verification on them — a confused-deputy on the sig
    // family. The discriminator binds the on-disk payload to this verifier.
    match sig_json.get("alg").and_then(|v| v.as_str()) {
        Some(SNAPSHOT_SIG_ALG) => {}
        _ => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                "Stored snapshot_sig has wrong or missing alg discriminator.",
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    }
    let (sig_r8x, sig_r8y, sig_s) = match (
        sig_json.get("r8x").and_then(|v| v.as_str()),
        sig_json.get("r8y").and_then(|v| v.as_str()),
        sig_json.get("s").and_then(|v| v.as_str()),
    ) {
        (Some(x), Some(y), Some(s)) => (x.to_owned(), y.to_owned(), s.to_owned()),
        _ => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                "Stored snapshot_sig is missing r8x/r8y/s.",
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    };

    let snapshot = CryptoSnapshot {
        snapshot_root: snapshot_root_str.clone(),
        snapshot_index: snapshot_index_i as u64,
        snapshot_size: snapshot_size_i as u64,
        path_elements_hex,
        path_indices,
        signature_r8x: sig_r8x,
        signature_r8y: sig_r8y,
        signature_s: sig_s,
    };

    // Trust anchor: try every entry in the trusted-issuer set, not just the
    // current authority pubkey. This is the symmetric counterpart of the
    // redaction-side issuer check — it makes rotation work (an old snapshot
    // signed by a now-retired key still verifies if that key is in the
    // trusted set with a `valid_until` covering the snapshot's signing time)
    // and lets federation members verify snapshots signed by their peers.
    //
    // The bootstrap-minted key is always entry 0 of `bjj_trusted_issuers`,
    // so the default single-operator case keeps the exact previous behavior.
    if state.bjj_trusted_issuers.is_empty() {
        tracing::error!("verify_proof_bundle: trusted-issuer set is empty");
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Snapshot signing key is not configured on this server; cannot verify.",
        ));
    }
    let ok = state.bjj_trusted_issuers.iter().any(|issuer| {
        verify_snapshot(
            &snapshot,
            &content_hash,
            &original_root,
            issuer.pubkey.x,
            issuer.pubkey.y,
        )
    });
    let (status, detail) = if ok {
        (
            SnapshotVerifyStatus::Verified,
            "Snapshot path reconstructs the stored ledger root and the authority \
          signature is valid.",
        )
    } else {
        (
            SnapshotVerifyStatus::Invalid,
            "Stored snapshot failed verification: path reconstruction or authority \
          signature check did not pass.",
        )
    };

    Ok(Json(build(
        body.proof_id,
        Some(row.proof_id),
        content_hash,
        status,
        detail,
        Some(snapshot_root_str),
        Some(snapshot_index_i as u64),
        Some(snapshot_size_i as u64),
    )))
}

// ── Route: POST /ingest/files ─────────────────────────────────────────────────
//
// Multipart file upload. content_hash = plain BLAKE3 of raw file bytes —
// identical to what the in-browser hasher computes, so the same file always
// produces the same hash and round-trip verifies.

const FILE_MAX_BYTES: usize = 100 * 1024 * 1024; // 100 MB

/// Algorithm discriminator stored in the `snapshot_sig` JSON object's `alg`
/// field. Producer and verifier both reference this constant so the on-disk
/// shape is bound to a single signature scheme — verifier refuses to attempt
/// BJJ verification against bytes labelled with any other algorithm.
const SNAPSHOT_SIG_ALG: &str = "bjj-eddsa-poseidon";

/// Domain tag for the per-record ledger entry hash (audit finding 7).
///
/// V2 binds the record's full location (`shard_id`, `record_id`, `record_type`,
/// `version`) and identity (`content_hash`, `proof_id`), each length-prefixed so
/// no field boundary is ambiguous. V1 hashed only `content_hash` and `proof_id`
/// joined with raw `|` separators — injection-ambiguous and blind to which
/// shard/record the entry belonged to.
const LEDGER_ENTRY_DOMAIN: &[u8] = b"OLY:LEDGER_ENTRY:V2";

/// `classid` for the per-shard snapshot advisory lock, taken in the two-int
/// `pg_advisory_xact_lock(int4, int4)` form (audit finding 8).
///
/// Postgres tracks the one-arg `(bigint)` and two-arg `(int4, int4)` advisory-
/// lock forms in separate keyspaces, so this lock can never collide with the
/// SMT writer lock (`smt::backend::SMT_WRITE_LOCK_KEY`, a single 64-bit key)
/// regardless of bit values. The objid half is derived from the shard.
const SNAPSHOT_LOCK_CLASSID: i32 = 0x4F4C_5331; // "OLS1" — Olympus Ledger Snapshot v1

/// Compute the depth-20 Poseidon snapshot for a newly-committed file and
/// UPDATE the just-INSERTed row with the result. Runs inside the caller's
/// transaction so the INSERT and the snapshot persistence are atomic — a
/// row never ends up half-written (record present, snapshot columns NULL).
///
/// The caller MUST have already acquired the per-shard advisory lock
/// (`acquire_shard_lock`) on the same transaction before calling this so
/// concurrent commits assign monotonic `snapshot_index` values without
/// colliding. Different shards never block each other.
///
/// Errors are returned as `ApiError` (HTTP 500). Because the caller has
/// not yet committed, propagating an error rolls back the INSERT — the
/// ingest fails atomically rather than leaving an un-provable row behind.
async fn build_snapshot_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    bjj_priv: &[u8; 32],
    shard_id: &str,
    content_hash: &str,
    proof_id: &str,
    bytes: &[u8],
) -> Result<(), ApiError> {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    let chunk_tree = chunk_tree_from_bytes(bytes).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("snapshot: chunk tree for {content_hash}: {e}"),
        )
    })?;
    let original_root_hex = fr_to_hex(chunk_tree.original_root);
    let chunk_hashes_json = serde_json::Value::Array(
        chunk_tree
            .chunk_hashes_hex
            .iter()
            .map(|h| serde_json::Value::String(h.clone()))
            .collect(),
    );

    // Read existing leaves in their canonical insertion order. The
    // just-INSERTed row carries NULL original_root at this point, so the
    // `original_root IS NOT NULL` filter excludes it without needing a
    // content_hash predicate. Legacy rows without snapshot_index sort to
    // the end via NULLS LAST and would contribute to the leaf set in
    // insertion order if any survive — none should under the atomic
    // pipeline this function is part of. The per-shard advisory lock that
    // serialises snapshot-index assignment is held by the caller via
    // `acquire_shard_lock` on this same `tx` (audit finding 8: two-int
    // lock form, keyspace-disjoint from the SMT writer lock).
    let existing_roots: Vec<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT original_root FROM ingest_records \
         WHERE shard_id = $1 \
           AND original_root IS NOT NULL \
         ORDER BY snapshot_index ASC NULLS LAST",
    )
    .bind(shard_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("snapshot: read existing leaves: {e}"),
        )
    })?
    .into_iter()
    .flatten()
    .collect();

    let existing_leaves: Vec<Fr> = existing_roots
        .iter()
        .filter_map(|h| {
            let decoded = hex::decode(h).ok()?;
            // A root is a 32-byte field element. Anything longer is a
            // corrupt/oversized stored value: skip it rather than index past
            // the end of `bytes` (copy_from_slice would panic out-of-bounds).
            if decoded.len() > 32 {
                tracing::warn!(
                    len = decoded.len(),
                    "snapshot: skipping oversized original_root (> 32 bytes)"
                );
                return None;
            }
            let mut bytes = [0u8; 32];
            let off = 32usize - decoded.len();
            bytes[off..].copy_from_slice(&decoded);
            Some(Fr::from_be_bytes_mod_order(&bytes))
        })
        .collect();
    let new_leaf_index = existing_leaves.len() as u64;

    let snap: LedgerSnapshot = snapshot_new_record(
        bjj_priv,
        &existing_leaves,
        chunk_tree.original_root,
        new_leaf_index,
        content_hash,
        &original_root_hex,
    )
    .map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("snapshot: build/sign for {content_hash}: {e}"),
        )
    })?;

    let snapshot_path_json = serde_json::json!({
        "path_elements": snap.path_elements_hex,
        "path_indices": snap.path_indices,
    });

    // BJJ signature is three field-element hex strings; serialise as a
    // self-describing JSON object so the existing TEXT `snapshot_sig`
    // column carries the triple without a schema change. Verifier parses
    // the same shape.
    let snapshot_sig_json = serde_json::json!({
        "alg": SNAPSHOT_SIG_ALG,
        "r8x": snap.signature_r8x,
        "r8y": snap.signature_r8y,
        "s":   snap.signature_s,
    })
    .to_string();

    // `snapshot_committed = TRUE` records that the snapshot write completed
    // (audit finding 2); under this atomic pipeline it is always TRUE once the
    // enclosing tx commits. `zk_bundle = NULL` invalidates any previously-cached
    // existence proof bundle (audit finding 3): a bundle pins the old
    // snapshot_root + signature, so whenever the snapshot is (re)written — e.g.
    // a legacy-row back-fill — the cached bundle must be discarded or a stale
    // proof would be served forever.
    sqlx::query(
        "UPDATE ingest_records SET \
             chunk_hashes = $1, \
             original_root = $2, \
             snapshot_root = $3, \
             snapshot_index = $4, \
             snapshot_size = $5, \
             snapshot_path = $6, \
             snapshot_sig = $7, \
             snapshot_committed = TRUE, \
             zk_bundle = NULL \
         WHERE proof_id = $8",
    )
    .bind(&chunk_hashes_json)
    .bind(&original_root_hex)
    .bind(&snap.snapshot_root)
    .bind(snap.snapshot_index as i64)
    .bind(snap.snapshot_size as i64)
    .bind(&snapshot_path_json)
    .bind(&snapshot_sig_json)
    .bind(proof_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("snapshot: update snapshot fields: {e}"),
        )
    })?;

    Ok(())
}

/// Acquire the per-shard advisory lock on `tx`. Held for the lifetime of
/// the transaction (`xact_lock`), so concurrent ingests in the same shard
/// serialize for snapshot-index assignment without blocking other shards.
async fn acquire_shard_lock(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    shard_id: &str,
) -> Result<(), ApiError> {
    // Audit finding 8: use the two-int advisory-lock form (classid =
    // snapshot namespace, objid = shard digest) so this lock lives in a
    // Postgres keyspace disjoint from the SMT writer lock, which uses the
    // single 64-bit form — the two can never collide regardless of bit values.
    let shard_digest = blake3::hash(shard_id.as_bytes());
    let lock_objid = i32::from_le_bytes(shard_digest.as_bytes()[..4].try_into().unwrap());
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(SNAPSHOT_LOCK_CLASSID)
        .bind(lock_objid)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("snapshot: advisory lock: {e}"),
            )
        })?;
    Ok(())
}

/// Commit a newly-ingested record into the parser-bound Sparse Merkle Tree
/// (ADR-0003 / ADR-0004). This is the live consumer of the parser-version +
/// model-hash leaf binding: every record becomes a leaf keyed by its identity
/// (`shard_record_key(shard_id, record_key(type, id, version))`) whose value
/// is the committed `content_hash`, stamped with the resolved
/// [`IngestProvenance`] triple. Returns the new BLAKE3 SMT root for logging.
///
/// Soft / non-fatal: any error
/// is logged and swallowed so the ingest response is unaffected. The Poseidon
/// snapshot tree remains the primary signed/anchored ledger structure; this
/// BLAKE3 SMT is a parallel parser-provenance index.
/// Identity + content for a single parser-SMT leaf commit. Groups the
/// record-identity fields so [`commit_to_parser_smt`] stays a 3-argument call.
struct ParserLeafCommit<'a> {
    shard_id: &'a str,
    record_type: &'a str,
    record_id: &'a str,
    version: i32,
    content_hash: &'a str,
    proof_id: &'a str,
}

async fn commit_to_parser_smt(
    pool: &sqlx::PgPool,
    provenance: &IngestProvenance,
    leaf: ParserLeafCommit<'_>,
) {
    let ParserLeafCommit {
        shard_id,
        record_type,
        record_id,
        version,
        content_hash,
        proof_id,
    } = leaf;

    // value_hash is the 32-byte content hash (the file's BLAKE3 digest).
    let value_hash: [u8; 32] = match hex::decode(content_hash) {
        Ok(b) if b.len() == 32 => b.try_into().expect("len checked"),
        _ => {
            tracing::warn!("parser-smt: content_hash {content_hash} is not 32-byte hex; skipping");
            return;
        }
    };

    // Tree key binds record identity. Reject a negative version rather than
    // coercing it to 0 (which would collide -1 and 0 onto the same key).
    let Ok(version_u64) = u64::try_from(version) else {
        tracing::warn!("parser-smt: negative version {version} for {content_hash}; skipping");
        return;
    };
    let rk = olympus_crypto::record_key(record_type, record_id, version_u64);
    let key = olympus_crypto::smt::shard_record_key(shard_id, &rk);

    // Audit finding 9: open without loading the hot cache. `update_batch`
    // re-loads the hot cache under the write lock before it reads any cached
    // node (H-4 part 2), so the eager top-CACHE_DEPTH SELECT that `open` does
    // is pure waste on this write-only path.
    let mut tree = PersistentSmt::open_deferred(PgBackend::new(pool.clone()));

    // Audit finding 1: the parser-provenance leaf is write-once at a given
    // record identity — silently moving a committed leaf preimage would
    // invalidate every SMT inclusion proof previously issued against the old
    // root. `update_batch_write_once` enforces this *atomically under the SMT
    // write lock* (the existence check and the write share one lock), so there
    // is no get-then-update TOCTOU. An identical re-commit is a harmless no-op.
    let update = LeafUpdate {
        key,
        value_hash,
        shard_id: shard_id.to_string(),
        parser_id: provenance.parser_id.clone(),
        canonical_parser_version: provenance.canonical_parser_version.clone(),
        model_hash: provenance.model_hash.clone(),
    };
    match tree
        .update_batch_write_once(std::slice::from_ref(&update))
        .await
    {
        Ok(root) => {
            tracing::debug!(
                "parser-smt: committed {content_hash} (parser_id={}, cpv={}, model_hash={}); root={}",
                provenance.parser_id,
                provenance.canonical_parser_version,
                provenance.model_hash,
                hex::encode(root),
            );
            // Audit finding 2: flag the soft write as complete so a row with
            // smt_committed=false is a queryable backfill target, not a
            // silent gap between ingest_records and the parser SMT.
            if let Err(e) =
                sqlx::query("UPDATE ingest_records SET smt_committed = TRUE WHERE proof_id = $1")
                    .bind(proof_id)
                    .execute(pool)
                    .await
            {
                tracing::warn!("parser-smt: set smt_committed for {content_hash}: {e}");
            }
        }
        Err(e) => tracing::warn!("parser-smt: update_batch for {content_hash}: {e}"),
    }
}

async fn ingest_file(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<CommitResult>), ApiError> {
    if !auth.has_scope("write") && !auth.has_scope("ingest") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope (write, ingest, or admin).",
        ));
    }
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut shard_id = "files".to_owned();
    let mut record_id_opt: Option<String> = None;
    let mut version: i32 = 1;
    let mut original_hash_opt: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            &format!("Multipart read error: {e}"),
        )
    })? {
        let name = field.name().unwrap_or("").to_owned();
        match name.as_str() {
            "file" => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("File read error: {e}")))?;
                if bytes.len() > FILE_MAX_BYTES {
                    return Err(err(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "File exceeds 100 MB limit.",
                    ));
                }
                file_bytes = Some(bytes.to_vec());
            }
            "shard_id" => {
                // F-8: same validator the legacy `commit_records` handler
                // (removed under H-5) used, applied at the
                // multipart parse boundary so a non-empty but malformed
                // shard_id can't reach downstream canonicalization or SQL.
                // Propagate a UTF-8 / multipart decode failure as 400 instead
                // of silently substituting an empty string (CodeRabbit
                // review on PR #1054) — otherwise malformed bytes would
                // bypass `sanitize_shard` and fall through to the default.
                let text = field.text().await.map_err(|e| {
                    err(
                        StatusCode::BAD_REQUEST,
                        &format!("shard_id field decode error: {e}"),
                    )
                })?;
                if !text.is_empty() {
                    if !sanitize_shard(&text) {
                        return Err(err(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "shard_id must be 1–128 chars of [A-Za-z0-9:._-] (audit F-8)",
                        ));
                    }
                    shard_id = text;
                }
            }
            "record_id" => {
                // F-8: cap record_id to a sane upper bound and reject control
                // chars / non-printable input before it lands in any log line,
                // canonical JSON blob, or DB row. Same decode-error rule as
                // shard_id (see above).
                let text = field.text().await.map_err(|e| {
                    err(
                        StatusCode::BAD_REQUEST,
                        &format!("record_id field decode error: {e}"),
                    )
                })?;
                if !text.is_empty() {
                    if text.len() > 256 || text.chars().any(|c| c.is_control()) {
                        return Err(err(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "record_id must be ≤256 chars and contain no control characters (audit F-8)",
                        ));
                    }
                    record_id_opt = Some(text);
                }
            }
            "version" => {
                // Audit finding 6: don't silently coerce a malformed version
                // to 1 — that collapses an empty/garbage version and an
                // explicit "1" onto the same record key. Empty/absent keeps
                // the default; anything present must parse to a positive int.
                let text = field.text().await.map_err(|e| {
                    err(
                        StatusCode::BAD_REQUEST,
                        &format!("version field decode error: {e}"),
                    )
                })?;
                let text = text.trim();
                if !text.is_empty() {
                    match text.parse::<i32>() {
                        Ok(v) if v >= 1 => version = v,
                        _ => {
                            return Err(err(
                                StatusCode::UNPROCESSABLE_ENTITY,
                                "version must be a positive integer.",
                            ))
                        }
                    }
                }
            }
            "original_hash" => {
                let text = field.text().await.unwrap_or_default().trim().to_lowercase();
                // The field was explicitly supplied: a malformed value is a
                // client error. Reject it instead of silently dropping it and
                // committing the upload as a plain (non-redaction) file.
                if text.len() != 64 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(err(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "original_hash must be 64 hex characters.",
                    ));
                }
                original_hash_opt = Some(text);
            }
            _ => {
                let _ = field.bytes().await;
            } // discard unknown fields
        }
    }

    let bytes =
        file_bytes.ok_or_else(|| err(StatusCode::UNPROCESSABLE_ENTITY, "Missing 'file' field."))?;
    if !sanitize_shard(&shard_id) {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "Invalid shard_id."));
    }

    // Operator-controlled shard creation (fail-closed): the target shard must be
    // registered + active, and this key must be authorized to write to it.
    // Checked before any DB write or snapshot work. See api::shards.
    crate::api::shards::authorize_write(&state, &auth, &shard_id).await?;

    // Plain BLAKE3 of raw bytes — no domain prefix, matching the browser hasher.
    let content_hash = blake3::hash(&bytes).to_hex().to_string();
    // Audit finding 1: default the record identity to the content hash. Two
    // distinct files committed without an explicit record_id previously both
    // got record_id="record" and so collided on a single parser-SMT key
    // (shard/type/"record"/version), where the second silently overwrote the
    // first's leaf. Defaulting to the content hash gives each distinct file a
    // distinct identity (and keeps identical bytes idempotent).
    let record_id = record_id_opt.unwrap_or_else(|| content_hash.clone());
    let proof_id = Uuid::new_v4().to_string();
    let now = naive_utc();

    let record_type = if original_hash_opt.is_some() {
        "redaction"
    } else {
        "file"
    };

    // Audit finding 7: bind the entry hash to the record's full location and
    // identity. Each string field is length-prefixed (`lp`) so field boundaries
    // are unambiguous — the V1 form joined only content_hash + proof_id with raw
    // `|` separators, which is both injection-ambiguous and silent about which
    // shard/record the entry belongs to. `version` is a fixed-width big-endian
    // u64 (guaranteed ≥ 1 by the parse above).
    let ledger_entry_hash = {
        use olympus_crypto::length_prefixed as lp;
        let mut h = blake3::Hasher::new();
        h.update(LEDGER_ENTRY_DOMAIN);
        h.update(&lp(shard_id.as_bytes()));
        h.update(&lp(record_id.as_bytes()));
        h.update(&lp(record_type.as_bytes()));
        h.update(&(version as u64).to_be_bytes());
        h.update(&lp(content_hash.as_bytes()));
        h.update(&lp(proof_id.as_bytes()));
        h.finalize().to_hex().to_string()
    };

    #[derive(sqlx::FromRow)]
    struct UpsertResult {
        proof_id: String,
        record_id: String,
        shard_id: String,
        content_hash: String,
        is_new: bool,
        /// True iff the row already existed AND has a NULL `original_root`.
        /// Used to back-fill the Poseidon snapshot for legacy rows
        /// (pre-migration-0029 or pre-audit-H-5 JSON commits) on re-upload
        /// of the original bytes — the BLAKE3 content_hash matches, so the
        /// re-upload is a safe rematerialisation of the same logical record.
        needs_snapshot_backfill: bool,
    }

    // Single atomic transaction: advisory-lock the shard, INSERT the record,
    // then (if newly inserted) compute the Poseidon snapshot and UPDATE the
    // same row with all snapshot columns populated. Either the row is fully
    // written (record + snapshot) or nothing is written — there is no
    // intermediate "row present, snapshot NULL" state that would make
    // /zk_bundle return 503 for a freshly-committed record. The advisory
    // lock is also what serializes snapshot_index assignment across
    // concurrent ingests in the same shard.
    //
    // BJJ authority key is required for new ingests because the snapshot
    // signature is what makes the row provable. If bootstrap hasn't loaded
    // one, refuse the ingest rather than persisting an un-provable row.
    let bjj_priv = if state.bjj_authority_key.is_some() {
        state.bjj_authority_key
    } else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "BJJ authority key not loaded; cannot mint Poseidon snapshot for new ingest.",
        ));
    };

    let mut tx = pool.begin().await.map_err(|e| {
        tracing::error!("ingest_file begin tx: {e}");
        err(StatusCode::INTERNAL_SERVER_ERROR, "Ingest failed.")
    })?;
    acquire_shard_lock(&mut tx, &shard_id).await?;

    let row: UpsertResult = sqlx::query_as::<_, UpsertResult>(
        r#"
        WITH ins AS (
            INSERT INTO ingest_records
                (proof_id, shard_id, record_type, record_id, version,
                 content_hash, ledger_entry_hash, merkle_root,
                 batch_id, poseidon_root, canonicalization, original_hash, ts)
            VALUES ($1, $2, $8, $3, $4, $5, $6, NULL, NULL, NULL, NULL, $9, $7)
            ON CONFLICT (content_hash, shard_id) DO NOTHING
            RETURNING proof_id, record_id, shard_id, content_hash,
                      TRUE AS is_new, FALSE AS needs_snapshot_backfill
        )
        SELECT proof_id, record_id, shard_id, content_hash,
               is_new, needs_snapshot_backfill
        FROM ins
        UNION ALL
        SELECT proof_id, record_id, shard_id, content_hash,
               FALSE AS is_new,
               (original_root IS NULL) AS needs_snapshot_backfill
        FROM ingest_records
        WHERE content_hash = $5
          AND shard_id = $2
          AND NOT EXISTS (SELECT 1 FROM ins)
        LIMIT 1
        "#,
    )
    .bind(&proof_id)
    .bind(&shard_id)
    .bind(&record_id)
    .bind(version)
    .bind(&content_hash)
    .bind(&ledger_entry_hash)
    .bind(now)
    .bind(record_type)
    .bind(&original_hash_opt)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("ingest_file upsert failed: {e}");
        err(StatusCode::INTERNAL_SERVER_ERROR, "Ingest failed.")
    })?;

    // Compute the depth-20 Poseidon snapshot + BJJ EdDSA-Poseidon sig.
    // Runs in two cases:
    //   * `is_new` — the freshly-INSERTed row. Propagating an error here
    //     rolls back the INSERT via the surrounding tx, so the ingest
    //     fails atomically rather than leaving an un-provable row behind.
    //     This was the source of the user-visible "Record has no Poseidon
    //     snapshot" 503 from /zk_bundle.
    //   * `needs_snapshot_backfill` — the row already existed but has a
    //     NULL `original_root` (legacy pre-0029 or pre-H-5 JSON commit).
    //     The re-upload's BLAKE3 content_hash matches the existing row,
    //     so we can safely rematerialise the snapshot from the supplied
    //     bytes and back-fill the columns. The legacy row joins the leaf
    //     set as the most recent leaf (snapshot_index = current non-NULL
    //     leaf count); existing inclusion proofs remain valid because we
    //     only append.
    if row.is_new || row.needs_snapshot_backfill {
        let bjj_priv = bjj_priv.expect("BJJ key presence checked above");
        build_snapshot_in_tx(
            &mut tx,
            &bjj_priv,
            &row.shard_id,
            &row.content_hash,
            &row.proof_id,
            &bytes,
        )
        .await?;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("ingest_file commit tx: {e}");
        err(StatusCode::INTERNAL_SERVER_ERROR, "Ingest failed.")
    })?;

    // ADR-0003 / ADR-0004: also commit the record into the parser-bound
    // BLAKE3 SMT, stamped with the resolved provenance triple. Soft /
    // non-fatal — never blocks the ingest response. Runs AFTER the
    // Poseidon-snapshot commit so the row is durable before the
    // secondary index references it.
    if row.is_new {
        commit_to_parser_smt(
            pool,
            &state.ingest_provenance,
            ParserLeafCommit {
                shard_id: &row.shard_id,
                record_type,
                record_id: &row.record_id,
                version,
                content_hash: &row.content_hash,
                proof_id: &row.proof_id,
            },
        )
        .await;
    }

    let status = if row.is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(CommitResult {
            proof_id: row.proof_id,
            content_hash: row.content_hash,
            record_id: row.record_id,
            shard_id: row.shard_id,
            deduplicated: !row.is_new,
        }),
    ))
}

// ── Route: GET /ingest/records/hash/{hash}/zk_bundle ─────────────────────────
//
// Lazy ZK existence-proof issuance.  Returns the Groth16 proof bundle for a
// committed record, generating it on the first request and caching the
// result back to `ingest_records.zk_bundle` so subsequent requests are
// instant.  Requires the snapshot columns added by migration 0029 — older
// records (or JSON-record commits) without `snapshot_root` return 503.
//
// Auth: `verify`, `read`, or `admin` scope, same gate as `/zk/verify`.
// Since the API key is BLAKE3-derived from the BJJ private key (PR #945),
// "holder of API key" == "holder of BJJ private key" — the natural
// re-download path for the original committer.

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZkBundleResponse {
    circuit: String,
    proof_json: serde_json::Value,
    public_signals: Vec<String>,
    content_hash: String,
    original_root: String,
    snapshot_root: String,
    snapshot_index: i64,
    snapshot_size: i64,
    snapshot_sig: String,
}

#[derive(sqlx::FromRow)]
struct ZkBundleRow {
    proof_id: String,
    content_hash: String,
    original_root: Option<String>,
    snapshot_root: Option<String>,
    snapshot_index: Option<i64>,
    snapshot_size: Option<i64>,
    snapshot_path: Option<serde_json::Value>,
    snapshot_sig: Option<String>,
    zk_bundle: Option<serde_json::Value>,
}

async fn issue_zk_bundle(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(hash): Path<String>,
) -> Result<Json<ZkBundleResponse>, ApiError> {
    if !auth.has_scope("verify") && !auth.has_scope("read") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: one of 'verify', 'read', or 'admin'",
        ));
    }

    let hash = hash.trim().to_lowercase();
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Hash must be a 64-character hex string.",
        ));
    }

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let row: ZkBundleRow = sqlx::query_as::<_, ZkBundleRow>(
        // Audit A1: earliest-wins — content_hash is per-shard unique only.
        "SELECT proof_id, content_hash, original_root, snapshot_root, snapshot_index, \
                snapshot_size, snapshot_path, snapshot_sig, zk_bundle \
         FROM ingest_records WHERE content_hash = $1 \
         ORDER BY ts ASC, proof_id ASC LIMIT 1",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "Hash not found in ledger."))?;

    // Cache hit: return the previously-generated bundle verbatim.
    if let Some(cached) = row.zk_bundle.as_ref() {
        if let Ok(resp) = serde_json::from_value::<ZkBundleResponse>(cached.clone()) {
            return Ok(Json(resp));
        }
        // Fall through and regenerate if the cached blob is malformed.
        tracing::warn!("zk_bundle cache for {hash} is malformed; regenerating");
    }

    // Snapshot must be populated to generate a proof. After the atomic-ingest
    // refactor, every new commit through /ingest/files writes the snapshot in
    // the same transaction as the row INSERT — so a NULL `original_root` can
    // only mean a legacy row predating migration 0029 (or the removed
    // /ingest/records JSON path under audit H-5). Those rows aren't
    // re-snapshottable without their original bytes, which the server does
    // not retain; the only remedy is to re-upload the file through
    // /ingest/files, which will dedupe by content_hash and back-fill the
    // snapshot columns on insert.
    let original_root = row.original_root.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record has no Poseidon snapshot — legacy row (pre-migration-0029 or \
             pre-audit-H-5 JSON commit). Re-upload the original bytes through \
             /ingest/files to back-fill the snapshot.",
        )
    })?;
    let snapshot_root = row.snapshot_root.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record is missing snapshot_root.",
        )
    })?;
    let snapshot_index = row.snapshot_index.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record is missing snapshot_index.",
        )
    })?;
    let snapshot_size = row.snapshot_size.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record is missing snapshot_size.",
        )
    })?;
    let snapshot_path = row.snapshot_path.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record is missing snapshot_path.",
        )
    })?;
    let snapshot_sig = row.snapshot_sig.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record is missing snapshot_sig.",
        )
    })?;

    let (proof_json, public_signals) = generate_existence_bundle(
        state.proofs_dir.clone(),
        &original_root,
        &snapshot_root,
        snapshot_index as u64,
        snapshot_size as u64,
        &snapshot_path,
    )
    .await?;

    let response = ZkBundleResponse {
        circuit: "document_existence".to_string(),
        proof_json,
        public_signals,
        content_hash: row.content_hash.clone(),
        original_root,
        snapshot_root,
        snapshot_index,
        snapshot_size,
        snapshot_sig,
    };

    // Cache the generated bundle so subsequent requests are instant.
    // Failure to cache is non-fatal — the bundle is already constructed.
    let cache_value = match serde_json::to_value(&response) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("zk_bundle cache serialise: {e}");
            None
        }
    };
    if let Some(v) = cache_value {
        if let Err(e) = sqlx::query("UPDATE ingest_records SET zk_bundle = $1 WHERE proof_id = $2")
            .bind(&v)
            .bind(&row.proof_id)
            .execute(pool)
            .await
        {
            tracing::warn!("zk_bundle cache write: {e}");
        }
    }

    Ok(Json(response))
}

/// Build the `ExistenceWitness` from the stored snapshot, run
/// `prove_existence` on a blocking task, and return the snarkjs-shape
/// proof JSON + decimal public signals.
async fn generate_existence_bundle(
    proofs_dir: Option<std::path::PathBuf>,
    original_root_hex: &str,
    snapshot_root_hex: &str,
    snapshot_index: u64,
    snapshot_size: u64,
    snapshot_path: &serde_json::Value,
) -> Result<(serde_json::Value, Vec<String>), ApiError> {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    fn hex_to_fr(h: &str) -> Result<Fr, ApiError> {
        let mut bytes = [0u8; 32];
        let decoded = hex::decode(h).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("hex decode: {e}"),
            )
        })?;
        if decoded.len() > 32 {
            return Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("hex value too long: {} bytes (max 32)", decoded.len()),
            ));
        }
        let off = 32usize.saturating_sub(decoded.len());
        bytes[off..off + decoded.len()].copy_from_slice(&decoded);
        Ok(Fr::from_be_bytes_mod_order(&bytes))
    }

    let root = hex_to_fr(snapshot_root_hex)?;
    let leaf = hex_to_fr(original_root_hex)?;

    let path_obj = snapshot_path.as_object().ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "snapshot_path is not an object",
        )
    })?;
    let path_elements_arr = path_obj
        .get("path_elements")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "snapshot_path.path_elements missing",
            )
        })?;
    let path_indices_arr = path_obj
        .get("path_indices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "snapshot_path.path_indices missing",
            )
        })?;

    let mut path_elements: Vec<Fr> = Vec::with_capacity(path_elements_arr.len());
    for (i, v) in path_elements_arr.iter().enumerate() {
        let s = v.as_str().ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("path_elements[{}] is not a string", i),
            )
        })?;
        path_elements.push(hex_to_fr(s)?);
    }
    let mut path_indices: Vec<u8> = Vec::with_capacity(path_indices_arr.len());
    for (i, v) in path_indices_arr.iter().enumerate() {
        let n = v.as_u64().ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("path_indices[{}] is not a number", i),
            )
        })?;
        let idx = u8::try_from(n).map_err(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("path_indices[{}] is out of range for u8: {}", i, n),
            )
        })?;
        path_indices.push(idx);
    }

    let witness = crate::zk::witness::ExistenceWitness::new(
        root,
        snapshot_index,
        snapshot_size,
        leaf,
        path_elements,
        path_indices,
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("witness: {e}")))?;

    let keys_dir = proofs_dir.unwrap_or_else(|| std::path::PathBuf::from("proofs/keys"));

    #[cfg(feature = "prover")]
    {
        use crate::zk::Circuit;
        let circuit = Circuit::DocumentExistence;
        let wasm = circuit.wasm_path(&keys_dir);
        let r1cs = circuit.r1cs_path(&keys_dir);
        let zkey = circuit.ark_zkey_path(&keys_dir);
        for (label, path) in [("wasm", &wasm), ("r1cs", &r1cs), ("zkey", &zkey)] {
            if !path.exists() {
                return Err(err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!("circuit artifact missing: {label} at {}", path.display()),
                ));
            }
        }

        let (proof, public_signals) = tokio::task::spawn_blocking(move || {
            crate::zk::prove::prove_existence(&witness, &wasm, &r1cs, &zkey)
        })
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join: {e}")))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("prove: {e}")))?;

        let proof_json = groth16_proof_to_json(&proof);
        let public_signals_dec: Vec<String> = public_signals.iter().map(fr_to_decimal).collect();
        Ok((proof_json, public_signals_dec))
    }
    #[cfg(not(feature = "prover"))]
    {
        let _ = (keys_dir, witness);
        Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "ZK prover feature not compiled in this build",
        ))
    }
}

#[cfg(feature = "prover")]
fn fr_to_decimal(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

#[cfg(feature = "prover")]
fn groth16_proof_to_json(proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> serde_json::Value {
    use ark_serialize::CanonicalSerialize;
    fn g1(p: &ark_bn254::G1Affine) -> Vec<String> {
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        let x = num_bigint::BigUint::from_bytes_le(&buf[..32]);
        let y = num_bigint::BigUint::from_bytes_le(&buf[32..64]);
        vec![x.to_string(), y.to_string(), "1".into()]
    }
    fn g2(p: &ark_bn254::G2Affine) -> Vec<Vec<String>> {
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        let x_c0 = num_bigint::BigUint::from_bytes_le(&buf[..32]);
        let x_c1 = num_bigint::BigUint::from_bytes_le(&buf[32..64]);
        let y_c0 = num_bigint::BigUint::from_bytes_le(&buf[64..96]);
        let y_c1 = num_bigint::BigUint::from_bytes_le(&buf[96..128]);
        vec![
            vec![x_c0.to_string(), x_c1.to_string()],
            vec![y_c0.to_string(), y_c1.to_string()],
            vec!["1".into(), "0".into()],
        ]
    }
    serde_json::json!({
        "pi_a": g1(&proof.a),
        "pi_b": g2(&proof.b),
        "pi_c": g1(&proof.c),
        "protocol": "groth16",
        "curve": "bn128",
    })
}

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
}

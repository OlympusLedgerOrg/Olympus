//! `POST /ingest/files` handler: multipart parsing/validation, the
//! unconditional shard-authorization gate, and the atomic ingest transaction
//! (advisory lock → upsert → snapshot → commit). Moved verbatim out of
//! `files.rs` (pure code motion).

use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use super::parser_smt::{commit_to_parser_smt, ParserLeafCommit};
use super::snapshot::{acquire_shard_lock, build_snapshot_in_tx};
use crate::api::ingest::*;
use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;

// ── Route: POST /ingest/files ─────────────────────────────────────────────────
//
// Multipart file upload. content_hash = plain BLAKE3 of raw file bytes —
// identical to what the in-browser hasher computes, so the same file always
// produces the same hash and round-trip verifies.

const FILE_MAX_BYTES: usize = 100 * 1024 * 1024; // 100 MB

/// Domain tag for the per-record ledger entry hash (audit finding 7).
///
/// V2 binds the record's full location (`shard_id`, `record_id`, `record_type`,
/// `version`) and identity (`content_hash`, `proof_id`), each length-prefixed so
/// no field boundary is ambiguous. V1 hashed only `content_hash` and `proof_id`
/// joined with raw `|` separators — injection-ambiguous and blind to which
/// shard/record the entry belonged to.
const LEDGER_ENTRY_DOMAIN: &[u8] = b"OLY:LEDGER_ENTRY:V2";

pub(in crate::api::ingest) async fn ingest_file(
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
                // Mirror the other text fields: a multipart decode failure is a
                // client error (400), not a silently-empty value.
                let text = field.text().await.map_err(|e| {
                    err(
                        StatusCode::BAD_REQUEST,
                        &format!("original_hash field decode error: {e}"),
                    )
                })?;
                let text = text.trim().to_lowercase();
                // Empty/absent => not a redaction (unchanged). A present,
                // non-empty value must be a valid 64-char hex digest — reject a
                // malformed one with 422 instead of silently committing the
                // file as a normal upload (consistent with shard_id/record_id).
                if !text.is_empty() {
                    if text.len() != 64 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err(err(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "original_hash must be a 64-character hex string.",
                        ));
                    }
                    original_hash_opt = Some(text);
                }
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

    // ingest-01: the parser-bound SMT (parser_smt.rs) enforces record-identity
    // write-once, but its commit runs AFTER this transaction commits — so a
    // same-identity / different-content upload would otherwise get its Poseidon
    // snapshot signed and committed and only THEN be rejected 409, leaving a
    // durable signed row behind for an ingest we refused. Pre-check the committed
    // parser-SMT leaf for this identity here, inside the tx, and bail (rolling
    // back the INSERT — `acquire_shard_lock` is `pg_advisory_xact_lock`, released
    // on rollback) before any snapshot work. The post-commit
    // `update_batch_write_once` stays the atomic backstop for the (shard-
    // serialised) concurrent edge. A probe READ ERROR fails closed (rolls the tx
    // back with a 500) rather than falling through: silently proceeding would
    // sign + commit the snapshot and only hit the conflict post-commit — exactly
    // the durable-signed-row-behind-409 this guard exists to prevent.
    if row.is_new {
        let new_vh = hex::decode(&row.content_hash)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        if let Some(new_vh) = new_vh {
            let rk = olympus_crypto::record_key(record_type, &row.record_id, version as u64);
            let identity_key = olympus_crypto::smt::shard_record_key(&row.shard_id, &rk);
            let probe =
                crate::smt::PersistentSmt::open_deferred(crate::smt::PgBackend::new(pool.clone()));
            match probe.get(&identity_key).await {
                // A committed leaf already binds this identity to *different*
                // content — insert-only refuses to overwrite it.
                Ok(Some(existing)) if existing != new_vh => {
                    return Err(err(
                        StatusCode::CONFLICT,
                        "Record identity already committed with different content; the \
                         ledger is insert-only and refuses to overwrite a committed key \
                         (ADR-0031).",
                    ));
                }
                // No committed leaf, or the same content (idempotent) — proceed.
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("ingest_file identity write-once pre-check probe failed: {e}");
                    return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "Ingest failed."));
                }
            }
        }
    }

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
            state.redaction_blind_secret.as_ref(),
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
    // BLAKE3 SMT, stamped with the resolved provenance triple. Runs AFTER the
    // Poseidon-snapshot commit so the row is durable before the secondary index
    // references it.
    //
    // ADR-0031 §2 (insert-only ledger): a *write-once conflict* on the
    // record-identity key (same shard/type/record_id/version already holds a
    // different content_hash) is a genuine, non-retryable client conflict —
    // surface it as 409. Every other (transient) parser-SMT failure stays soft:
    // it leaves `smt_committed = FALSE` as a queryable backfill target and does
    // not block this response.
    if row.is_new
        && commit_to_parser_smt(
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
        .await
        .is_err()
    {
        return Err(err(
            StatusCode::CONFLICT,
            "Record identity already committed with different content; the ledger is \
             insert-only and refuses to overwrite a committed key (ADR-0031).",
        ));
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

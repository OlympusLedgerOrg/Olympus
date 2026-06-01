//! `POST /ingest/files` — the only sanctioned commit ingress (server hashes
//! the uploaded bytes). Owns the atomic ingest transaction: per-shard advisory
//! lock, row upsert, Poseidon snapshot build/sign, and the soft parser-bound
//! SMT commit. Split out of the ingest module.

use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use super::*;
use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::ingest_provenance::IngestProvenance;
use crate::smt::{LeafUpdate, PersistentSmt, PgBackend};
use crate::state::AppState;
use crate::zk::chunk::{chunk_tree_from_bytes, fr_to_hex};
use crate::zk::snapshot::{snapshot_new_record, LedgerSnapshot};

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

    let mut existing_leaves: Vec<Fr> = Vec::with_capacity(existing_roots.len());
    for h in &existing_roots {
        let decoded = match hex::decode(h) {
            Ok(v) => v,
            // A non-hex stored root is corruption, but it never contributed a
            // field element to begin with; skipping it does not perturb the
            // ordering of the valid roots that follow.
            Err(_) => continue,
        };
        // `original_root` is always 32-byte `fr_to_hex` output. An oversized
        // value can only be DB corruption. Fail closed rather than silently
        // dropping it: dropping would shift `new_leaf_index` (computed from the
        // filtered length below) and produce a non-canonical snapshot chain.
        if decoded.len() > 32 {
            return Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "snapshot: stored original_root is {} bytes (> 32); refusing to build snapshot",
                    decoded.len()
                ),
            ));
        }
        let mut bytes = [0u8; 32];
        let off = 32usize - decoded.len();
        bytes[off..].copy_from_slice(&decoded);
        existing_leaves.push(Fr::from_be_bytes_mod_order(&bytes));
    }
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

pub(super) async fn ingest_file(
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

//! Poseidon-snapshot persistence stage: per-shard advisory lock + the
//! in-transaction snapshot build/sign/UPDATE. Moved verbatim out of
//! `files.rs` (pure code motion).

use axum::http::StatusCode;

use crate::api::ingest::*;
use crate::zk::chunk::{chunk_tree_from_bytes, fr_to_hex};
use crate::zk::segment::SegmentManifest;
use crate::zk::snapshot::{snapshot_new_record, LedgerSnapshot};

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
pub(super) async fn build_snapshot_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    bjj_priv: &[u8; 32],
    blind_secret: Option<&[u8; 32]>,
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
    let chunk_root_hex = fr_to_hex(chunk_tree.original_root);
    let chunk_hashes_json = serde_json::Value::Array(
        chunk_tree
            .chunk_hashes_hex
            .iter()
            .map(|h| serde_json::Value::String(h.clone()))
            .collect(),
    );

    // ADR-0026: commit the **object/segment-level** root for any format we can
    // segment (traditional-xref PDF, UTF-8 text/Markdown; OOXML in Phase 3) and
    // persist the per-segment manifest so `/redaction/issue` can rebuild the
    // 1024-leaf witness from a content_hash. A `detect_format` returning `None`
    // (opaque binary, ZIP/Office until Phase 3) — OR a detected-but-unparseable
    // document (a modern cross-reference-stream PDF, whose `extract` errors) — OR
    // a missing `blind_secret` falls back to the chunk root: it ingests fine but
    // is not object-redactable. The fallback is explicit, never silent.
    let hex_to_fr = |h: &str| -> Option<Fr> {
        let decoded = hex::decode(h).ok()?;
        if decoded.len() > 32 {
            return None;
        }
        let mut b = [0u8; 32];
        b[32 - decoded.len()..].copy_from_slice(&decoded);
        Some(Fr::from_be_bytes_mod_order(&b))
    };
    let segment_manifest: Option<SegmentManifest> =
        blind_secret.and_then(|s| match crate::zk::segment::segment_document(bytes, s) {
            Ok(m) => Some(m),
            Err(e) => {
                tracing::info!(
                    content_hash = %content_hash,
                    error = %e,
                    "document not object-redactable; committing chunk root"
                );
                None
            }
        });
    let (original_root, original_root_hex) = match segment_manifest
        .as_ref()
        .and_then(|m| hex_to_fr(&m.original_root_hex).map(|fr| (fr, m.original_root_hex.clone())))
    {
        Some((root_fr, hex)) => (root_fr, hex),
        None => (chunk_tree.original_root, chunk_root_hex),
    };

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
        let decoded =
            match hex::decode(h) {
                Ok(v) => v,
                // A non-hex stored root is DB corruption. Skipping it would shrink
                // the filtered length and shift `new_leaf_index` (computed below),
                // producing a non-canonical snapshot chain — the same hazard the
                // oversized check guards against. Fail closed for consistency.
                Err(_) => return Err(err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "snapshot: stored original_root is not valid hex; refusing to build snapshot",
                )),
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
        original_root,
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

    // ADR-0026: persist the segment manifest so `/redaction/issue` can rebuild the
    // witness from a content_hash. Insert-or-ignore keyed by (content_hash,
    // shard_id): blindings are re-derived (deterministic), so a duplicate ingest
    // reproduces the same root and must NOT overwrite an existing manifest. The
    // `obj_id` JSON key is the generic segment id (kept for schema back-compat);
    // `label` is the producer-facing line range (null for PDF).
    if let Some(m) = segment_manifest {
        let segments = serde_json::Value::Array(
            m.segments
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "obj_id": s.segment_id,
                        "byte_offset": s.byte_offset,
                        "byte_length": s.byte_length,
                        "leaf_hex": s.leaf_hex,
                        "label": s.label,
                    })
                })
                .collect(),
        );
        sqlx::query(
            "INSERT INTO redaction_segment_manifests \
                 (content_hash, shard_id, format, original_root, tree_depth, max_leaves, segments) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (content_hash, shard_id) DO NOTHING",
        )
        .bind(content_hash)
        .bind(shard_id)
        .bind(m.format.as_tag())
        .bind(&m.original_root_hex)
        .bind(m.tree_depth as i32)
        .bind(m.max_leaves as i32)
        .bind(&segments)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("snapshot: persist redaction manifest: {e}"),
            )
        })?;
    }

    Ok(())
}

/// Acquire the per-shard advisory lock on `tx`. Held for the lifetime of
/// the transaction (`xact_lock`), so concurrent ingests in the same shard
/// serialize for snapshot-index assignment without blocking other shards.
pub(super) async fn acquire_shard_lock(
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

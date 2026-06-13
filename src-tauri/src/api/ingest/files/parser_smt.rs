//! Parser-bound BLAKE3 SMT commit stage (ADR-0003 / ADR-0004). Soft /
//! non-fatal secondary index. Moved verbatim out of `files.rs` (pure code
//! motion).

use crate::ingest_provenance::IngestProvenance;
use crate::smt::{LeafUpdate, PersistentSmt, PgBackend};

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
pub(super) struct ParserLeafCommit<'a> {
    pub(super) shard_id: &'a str,
    pub(super) record_type: &'a str,
    pub(super) record_id: &'a str,
    pub(super) version: i32,
    pub(super) content_hash: &'a str,
    pub(super) proof_id: &'a str,
}

pub(super) async fn commit_to_parser_smt(
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

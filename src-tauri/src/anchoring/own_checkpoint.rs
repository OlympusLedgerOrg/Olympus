//! Canonical "this node's own checkpoint" producer.
//!
//! Red-team CR-5 + CR-7: before this module existed, the anchor cron read
//! `ingest_records.merkle_root` (BLAKE3) — a column the v0.9 ingest path
//! never writes — and federation `build_own_checkpoint` separately read
//! `ingest_records.snapshot_root` (Poseidon). Two different hash families
//! committed to the same logical state, the anchor row could never join
//! back to a persisted checkpoint, and the cron was inert.
//!
//! This module unifies the producer: one always-built function reads the
//! latest ingest snapshot, builds the existence witness, runs the
//! Groth16 prove, signs the Poseidon `snapshot_root` under the BJJ
//! authority key, computes the domain-separated anchor digest, and
//! inserts a single row in `own_checkpoints`. Both the anchor cron AND
//! the federation `build_own_checkpoint` consume the resulting row.
//!
//! No federation feature gate — the producer runs in default ship
//! builds whenever `OLYMPUS_ANCHOR_*` env vars are configured. The
//! federation feature only controls whether the row is then gossiped
//! over Tor.

use std::path::Path;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use sqlx::PgPool;
use uuid::Uuid;

use crate::zk::witness::baby_jubjub::BabyJubJubPubKey;

/// One persisted row in `own_checkpoints`. The cron's anchor pipeline
/// reads `anchor_hash` and `id`; federation's gossip reads everything
/// (sig, public_signals, proof) to assemble the wire envelope.
#[derive(Debug, Clone)]
pub struct OwnCheckpointRow {
    pub id: Uuid,
    pub ledger_root: String,
    pub tree_size: i64,
    pub checkpoint_timestamp: i64,
    pub authority_pubkey_hash: Option<String>,
    pub sig_r8x: Option<String>,
    pub sig_r8y: Option<String>,
    pub sig_s: Option<String>,
    pub anchor_hash: [u8; 32],
    pub groth16_proof: Option<serde_json::Value>,
    pub public_signals: Option<Vec<String>>,
    // Red-team C1 / migration 0042: Ed25519 signature over `anchor_hash`.
    // Pinned at checkpoint emission time so re-export via the bundle
    // producer is byte-identical even after key rotation. NULL when no
    // OLYMPUS_INGEST_SIGNING_KEY is loaded.
    pub ed25519_pubkey_hex: Option<String>,
    pub ed25519_signature_hex: Option<String>,
}

/// Resolve the Ed25519 signing key from the same env var precedence
/// `anchoring::rekor` uses (dedicated `OLYMPUS_ANCHOR_SIGN_KEY` →
/// fallback `OLYMPUS_INGEST_SIGNING_KEY`). Returns `None` only when
/// neither is set — we don't refuse to write the checkpoint row in
/// that case; the bundle producer just won't emit a bundle for it.
fn resolve_ed25519_signing_key() -> Option<ed25519_dalek::SigningKey> {
    use ed25519_dalek::SigningKey;
    let hex_str = std::env::var("OLYMPUS_ANCHOR_SIGN_KEY")
        .or_else(|_| std::env::var("OLYMPUS_INGEST_SIGNING_KEY"))
        .ok()?;
    let bytes = hex::decode(hex_str.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(SigningKey::from_bytes(&arr))
}

/// Ed25519-sign `anchor_hash` with the resolved signing key. Returns
/// `(pubkey_hex, signature_hex)`. The bundle producer reads both back
/// from the row verbatim; verification is RFC 8032 (`@noble/ed25519`
/// in the JS verifier).
fn sign_anchor_hash_ed25519(anchor_hash: &[u8; 32]) -> Option<(String, String)> {
    use ed25519_dalek::Signer;
    let sk = resolve_ed25519_signing_key()?;
    let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
    let sig_hex = hex::encode(sk.sign(anchor_hash).to_bytes());
    Some((pubkey_hex, sig_hex))
}

/// Build a fresh own-checkpoint row from the latest ingest snapshot and
/// persist it. Returns:
///   - `Ok(None)` — the database has no ingest record with a complete
///     Poseidon snapshot yet (fresh node, or all rows pre-migration
///     0029).
///   - `Ok(Some(row))` — successfully built and inserted. Row id is the
///     `checkpoint_id` to pass downstream to `anchor_all`.
///   - `Err(_)` — DB or prove failure. Caller (cron) logs and skips
///     the tick; federation surfaces to the gossip loop.
///
/// `proofs_dir = None` is honoured for the "no Groth16, no signature"
/// degenerate case: a checkpoint row is still written so the anchor
/// receipts can join to *something*, but the row's `groth16_proof`,
/// `public_signals`, and sig fields are NULL. Federation refuses to
/// gossip such a row (H-11/M-5 null-proof rejection still applies).
pub async fn build_and_persist(
    pool: &PgPool,
    bjj_key: Option<&[u8; 32]>,
    bjj_pubkey: Option<&BabyJubJubPubKey>,
    proofs_dir: Option<&Path>,
) -> Result<Option<OwnCheckpointRow>, String> {
    // 1. Pull the latest ingest snapshot. Match the federation query
    //    shape exactly so cron + federation read the same predicate.
    let snap: Option<Snapshot> = sqlx::query_as(
        "SELECT original_root, snapshot_root, snapshot_index, snapshot_size, snapshot_path
         FROM ingest_records
         WHERE original_root IS NOT NULL
           AND snapshot_root  IS NOT NULL
           AND snapshot_index IS NOT NULL
           AND snapshot_size  IS NOT NULL
           AND snapshot_path  IS NOT NULL
         ORDER BY ts DESC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("query latest snapshot: {e}"))?;

    let Some(snap) = snap else {
        return Ok(None);
    };

    // 1b. Dedup. The cron ticks on a fixed interval; if no new ingest has
    //     landed since the last tick, the snapshot `(ledger_root, tree_size)`
    //     is unchanged. Re-running the ~5-15s Groth16 prove and inserting
    //     another row for the identical state wastes CPU and accumulates
    //     duplicate checkpoints. Reuse the existing row instead. The cron is
    //     the sole, serialized producer (one task, ticks awaited in sequence),
    //     so this check-then-insert needs no extra locking.
    if let Some(existing) =
        fetch_existing_for_snapshot(pool, &snap.snapshot_root, snap.snapshot_size).await?
    {
        return Ok(Some(existing));
    }

    // 2. Decode the snapshot's hex Fr fields once.
    let root_fr = hex_to_fr(&snap.snapshot_root)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // 3. Try to build the Groth16 proof if BJJ key + proofs_dir are both
    //    available. The proof is optional at the row level — a row
    //    without a proof can still be anchored (cron just wants the
    //    digest), but federation will refuse to gossip it.
    //
    //    The proof-build path is only available with the `prover` feature
    //    (which is on by default for the desktop binary). Builds that
    //    compile this crate without `prover` (e.g. when downstream tooling
    //    consumes `olympus-desktop` as a library) still produce a
    //    correctly-signed, anchorable row via the sign-only fallback
    //    below — they just cannot gossip it.
    let (groth16_proof, public_signals_dec, sig_fields, authority_hash_dec) =
        match (bjj_key, bjj_pubkey, proofs_dir) {
            #[cfg(feature = "prover")]
            (Some(key), Some(pubkey), Some(dir)) => {
                let proved =
                    try_build_proof_and_sign(&snap, root_fr, key, pubkey, dir, now).await?;
                let (proof_json, signals, sig, auth_hash) = proved;
                (Some(proof_json), Some(signals), Some(sig), Some(auth_hash))
            }
            _ => {
                // Sign-only fallback when proofs_dir is missing (e.g.
                // operator hasn't run setup_circuits.sh yet) but a BJJ
                // key IS loaded. Still writes the row so anchor receipts
                // have something to join to; the row is non-gossipable.
                let sig_and_hash = match (bjj_key, bjj_pubkey) {
                    (Some(key), Some(pubkey)) => Some(sign_only(root_fr, key, pubkey, now)?),
                    _ => None,
                };
                let (sig, auth) = match sig_and_hash {
                    Some((s, a)) => (Some(s), Some(a)),
                    None => (None, None),
                };
                (None, None, sig, auth)
            }
        };

    // 4. Compute the domain-separated anchor digest from the same
    //    fields the cron previously hashed. Empty strings stand in for
    //    missing fields — that's the same convention `checkpoint_anchor_hash`
    //    uses; tests in `anchoring/mod.rs::tests::checkpoint_anchor_hash_*`
    //    cover both presence and absence of sig fields.
    let anchor_hash = super::checkpoint_anchor_hash(
        &snap.snapshot_root,
        snap.snapshot_size,
        now,
        authority_hash_dec.as_deref().unwrap_or(""),
        sig_fields.as_ref().map(|s| s.0.as_str()),
        sig_fields.as_ref().map(|s| s.1.as_str()),
        sig_fields.as_ref().map(|s| s.2.as_str()),
    );

    // 4b. Ed25519-sign the anchor_hash with the resolved ingest signing
    //     key. Pinned here at emission time so the bundle producer can
    //     re-export bit-identical bundles after key rotation — the
    //     chain of custody requires the signature to be created once
    //     and never recomputed (court-evidence.md §6).
    let (ed25519_pubkey_hex, ed25519_signature_hex) = match sign_anchor_hash_ed25519(&anchor_hash) {
        Some((pk, sig)) => (Some(pk), Some(sig)),
        None => (None, None),
    };

    // 5. Insert. UUID generated in Rust so the return value carries it
    //    without a second round-trip.
    let id = Uuid::new_v4();
    let signals_json: Option<serde_json::Value> =
        public_signals_dec.as_ref().map(|v| serde_json::json!(v));
    sqlx::query(
        "INSERT INTO own_checkpoints
            (id, ledger_root, tree_size, checkpoint_timestamp,
             authority_pubkey_hash, sig_r8x, sig_r8y, sig_s,
             anchor_hash, groth16_proof, public_signals,
             ed25519_pubkey_hex, ed25519_signature_hex)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(id)
    .bind(&snap.snapshot_root)
    .bind(snap.snapshot_size)
    .bind(now)
    .bind(authority_hash_dec.as_deref())
    .bind(sig_fields.as_ref().map(|s| s.0.as_str()))
    .bind(sig_fields.as_ref().map(|s| s.1.as_str()))
    .bind(sig_fields.as_ref().map(|s| s.2.as_str()))
    .bind(&anchor_hash[..])
    .bind(&groth16_proof)
    .bind(&signals_json)
    .bind(ed25519_pubkey_hex.as_deref())
    .bind(ed25519_signature_hex.as_deref())
    .execute(pool)
    .await
    .map_err(|e| format!("insert own_checkpoints: {e}"))?;

    let (sig_r8x, sig_r8y, sig_s) = match sig_fields {
        Some((a, b, c)) => (Some(a), Some(b), Some(c)),
        None => (None, None, None),
    };
    Ok(Some(OwnCheckpointRow {
        id,
        ledger_root: snap.snapshot_root,
        tree_size: snap.snapshot_size,
        checkpoint_timestamp: now,
        authority_pubkey_hash: authority_hash_dec,
        sig_r8x,
        sig_r8y,
        sig_s,
        anchor_hash,
        groth16_proof,
        public_signals: public_signals_dec,
        ed25519_pubkey_hex,
        ed25519_signature_hex,
    }))
}

/// Fetch a single row by id. Used by the admin bundle producer
/// (`GET /api/admin/checkpoints/{id}/bundle`); the row's BJJ sig +
/// Groth16 proof + Ed25519 sig are checked separately by the caller
/// and a missing field surfaces as `409 Conflict` rather than `404`.
pub async fn fetch_by_id(pool: &PgPool, id: Uuid) -> Result<Option<OwnCheckpointRow>, String> {
    let row: Option<CheckpointDbRow> = sqlx::query_as(
        "SELECT id, ledger_root, tree_size, checkpoint_timestamp,
                authority_pubkey_hash, sig_r8x, sig_r8y, sig_s,
                anchor_hash, groth16_proof, public_signals,
                ed25519_pubkey_hex, ed25519_signature_hex
         FROM own_checkpoints
         WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("query own_checkpoint by id: {e}"))?;

    row.map(row_to_own_checkpoint).transpose()
}

/// All columns of `own_checkpoints`, as read back from the DB.
#[derive(sqlx::FromRow)]
struct CheckpointDbRow {
    id: Uuid,
    ledger_root: String,
    tree_size: i64,
    checkpoint_timestamp: i64,
    authority_pubkey_hash: Option<String>,
    sig_r8x: Option<String>,
    sig_r8y: Option<String>,
    sig_s: Option<String>,
    anchor_hash: Vec<u8>,
    groth16_proof: Option<serde_json::Value>,
    public_signals: Option<serde_json::Value>,
    // Red-team C1 / migration 0042: Ed25519 leg of the checkpoint bundle.
    ed25519_pubkey_hex: Option<String>,
    ed25519_signature_hex: Option<String>,
}

/// Map a raw DB row into an [`OwnCheckpointRow`], enforcing the schema
/// invariants the gossip/anchor consumers rely on:
///   - `anchor_hash` must be exactly 32 bytes;
///   - `public_signals`, when present, MUST be a JSON array of strings —
///     a non-string element is rejected rather than silently dropped, since
///     a truncated signals vector would desync the Groth16 proof's public
///     inputs and yield a malformed gossip envelope. (`NULL` is allowed here:
///     sig-only / no-proof rows legitimately carry no signals. The
///     gossipable selector additionally filters `public_signals IS NOT NULL`.)
fn row_to_own_checkpoint(r: CheckpointDbRow) -> Result<OwnCheckpointRow, String> {
    if r.anchor_hash.len() != 32 {
        return Err(format!(
            "own_checkpoints.anchor_hash is {} bytes; expected 32 (schema invariant)",
            r.anchor_hash.len()
        ));
    }
    let mut anchor_hash = [0u8; 32];
    anchor_hash.copy_from_slice(&r.anchor_hash);

    let public_signals = match r.public_signals {
        None => None,
        Some(v) => {
            let arr = v.as_array().ok_or_else(|| {
                "own_checkpoints.public_signals is not a JSON array (schema invariant)".to_owned()
            })?;
            let mut out = Vec::with_capacity(arr.len());
            for (i, x) in arr.iter().enumerate() {
                let s = x.as_str().ok_or_else(|| {
                    format!(
                        "own_checkpoints.public_signals[{i}] is not a string (schema invariant)"
                    )
                })?;
                out.push(s.to_owned());
            }
            Some(out)
        }
    };

    Ok(OwnCheckpointRow {
        id: r.id,
        ledger_root: r.ledger_root,
        tree_size: r.tree_size,
        checkpoint_timestamp: r.checkpoint_timestamp,
        authority_pubkey_hash: r.authority_pubkey_hash,
        sig_r8x: r.sig_r8x,
        sig_r8y: r.sig_r8y,
        sig_s: r.sig_s,
        anchor_hash,
        groth16_proof: r.groth16_proof,
        public_signals,
        ed25519_pubkey_hex: r.ed25519_pubkey_hex,
        ed25519_signature_hex: r.ed25519_signature_hex,
    })
}

/// Fetch the most recent own_checkpoints row whose Groth16 proof, public
/// signals, and BJJ signature are all present — i.e. the latest gossipable
/// row. Federation's `build_own_checkpoint` reads this when the gossip loop
/// needs an envelope to push.
pub async fn fetch_latest_gossipable(pool: &PgPool) -> Result<Option<OwnCheckpointRow>, String> {
    // `public_signals IS NOT NULL` is required alongside `groth16_proof`: a
    // gossip envelope without the proof's public inputs cannot be verified by
    // peers, so such a row is not gossipable even though it carries a proof.
    let row: Option<CheckpointDbRow> = sqlx::query_as(
        "SELECT id, ledger_root, tree_size, checkpoint_timestamp,
                authority_pubkey_hash, sig_r8x, sig_r8y, sig_s,
                anchor_hash, groth16_proof, public_signals,
                ed25519_pubkey_hex, ed25519_signature_hex
         FROM own_checkpoints
         WHERE groth16_proof IS NOT NULL
           AND public_signals IS NOT NULL
           AND sig_r8x IS NOT NULL
           AND sig_r8y IS NOT NULL
           AND sig_s   IS NOT NULL
           AND authority_pubkey_hash IS NOT NULL
         ORDER BY checkpoint_timestamp DESC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("query latest own_checkpoint: {e}"))?;

    row.map(row_to_own_checkpoint).transpose()
}

/// Fetch an existing checkpoint for a given `(ledger_root, tree_size)`
/// snapshot, if one was already persisted. Used by [`build_and_persist`] to
/// dedup repeated cron ticks over an unchanged ledger snapshot.
async fn fetch_existing_for_snapshot(
    pool: &PgPool,
    ledger_root: &str,
    tree_size: i64,
) -> Result<Option<OwnCheckpointRow>, String> {
    let row: Option<CheckpointDbRow> = sqlx::query_as(
        "SELECT id, ledger_root, tree_size, checkpoint_timestamp,
                authority_pubkey_hash, sig_r8x, sig_r8y, sig_s,
                anchor_hash, groth16_proof, public_signals,
                ed25519_pubkey_hex, ed25519_signature_hex
         FROM own_checkpoints
         WHERE ledger_root = $1 AND tree_size = $2
         ORDER BY checkpoint_timestamp DESC
         LIMIT 1",
    )
    .bind(ledger_root)
    .bind(tree_size)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("query existing own_checkpoint: {e}"))?;

    row.map(row_to_own_checkpoint).transpose()
}

// ── Internal helpers ──────────────────────────────────────────────────

type SigTriple = (String, String, String); // (r8x, r8y, s) as decimal Fr

#[cfg(feature = "prover")]
async fn try_build_proof_and_sign(
    snap: &Snapshot,
    root_fr: Fr,
    bjj_key: &[u8; 32],
    bjj_pubkey: &BabyJubJubPubKey,
    proofs_dir: &Path,
    now_unix: i64,
) -> Result<(serde_json::Value, Vec<String>, SigTriple, String), String> {
    // Build the ExistenceWitness — same hex_to_fr / snapshot_path
    // shape `api::ingest::generate_existence_bundle` uses so a future
    // `/zk_bundle` query and a federation gossip render-from-the-same-row
    // would produce identical proofs.
    let leaf = hex_to_fr(&snap.original_root)?;
    let (path_elements, path_indices) = parse_snapshot_path(&snap.snapshot_path)?;
    let witness = crate::zk::witness::ExistenceWitness::new(
        root_fr,
        snap.snapshot_index as u64,
        snap.snapshot_size as u64,
        leaf,
        path_elements,
        path_indices,
    )
    .map_err(|e| format!("existence witness: {e}"))?;

    use crate::zk::Circuit;
    let circuit = Circuit::DocumentExistence;
    let wasm = circuit.wasm_path(proofs_dir);
    let r1cs = circuit.r1cs_path(proofs_dir);
    let zkey = circuit.ark_zkey_path(proofs_dir);
    for (label, path) in [("wasm", &wasm), ("r1cs", &r1cs), ("zkey", &zkey)] {
        if !path.exists() {
            return Err(format!(
                "document_existence {label} missing at {} — run `setup_circuits.sh`",
                path.display()
            ));
        }
    }

    let (proof, public_signals) = tokio::task::spawn_blocking(move || {
        crate::zk::prove::prove_existence(&witness, &wasm, &r1cs, &zkey)
    })
    .await
    .map_err(|e| format!("prove join: {e}"))?
    .map_err(|e| format!("prove existence: {e}"))?;
    let proof_json = crate::zk::proof::proof_to_snarkjs_json(&proof);
    let signals_dec: Vec<String> = public_signals.iter().map(fr_to_decimal).collect();

    let (sig, auth_hash) = sign_only(root_fr, bjj_key, bjj_pubkey, now_unix)?;
    Ok((proof_json, signals_dec, sig, auth_hash))
}

fn sign_only(
    root_fr: Fr,
    bjj_key: &[u8; 32],
    bjj_pubkey: &BabyJubJubPubKey,
    now_unix: i64,
) -> Result<(SigTriple, String), String> {
    let sig = crate::zk::witness::unified::UnifiedWitness::sign_checkpoint(
        bjj_key,
        root_fr,
        now_unix.max(0) as u64,
    )
    .map_err(|e| format!("BJJ sign: {e}"))?;
    let auth_hash = bjj_pubkey
        .authority_hash()
        .map_err(|e| format!("pubkey authority_hash: {e}"))?;
    Ok((
        (
            fr_to_decimal(&sig.r8x),
            fr_to_decimal(&sig.r8y),
            fr_to_decimal(&sig.s),
        ),
        fr_to_decimal(&auth_hash),
    ))
}

#[derive(sqlx::FromRow)]
struct Snapshot {
    original_root: String,
    snapshot_root: String,
    snapshot_index: i64,
    snapshot_size: i64,
    snapshot_path: serde_json::Value,
}

#[cfg(feature = "prover")]
fn parse_snapshot_path(v: &serde_json::Value) -> Result<(Vec<Fr>, Vec<u8>), String> {
    let path_obj = v
        .as_object()
        .ok_or_else(|| "snapshot_path is not a JSON object".to_owned())?;
    let elements_arr = path_obj
        .get("path_elements")
        .and_then(|x| x.as_array())
        .ok_or_else(|| "snapshot_path.path_elements missing or wrong type".to_owned())?;
    let indices_arr = path_obj
        .get("path_indices")
        .and_then(|x| x.as_array())
        .ok_or_else(|| "snapshot_path.path_indices missing or wrong type".to_owned())?;
    let mut elements: Vec<Fr> = Vec::with_capacity(elements_arr.len());
    for (i, x) in elements_arr.iter().enumerate() {
        let s = x
            .as_str()
            .ok_or_else(|| format!("snapshot_path.path_elements[{i}] is not a string"))?;
        elements.push(hex_to_fr(s)?);
    }
    let mut indices: Vec<u8> = Vec::with_capacity(indices_arr.len());
    for (i, x) in indices_arr.iter().enumerate() {
        let n = x
            .as_u64()
            .ok_or_else(|| format!("snapshot_path.path_indices[{i}] is not a number"))?;
        // SMT inclusion paths are strictly binary (0 = go left / current
        // is left child, 1 = right). Anything else is corrupt snapshot
        // JSON — reject before the silent `as u8` truncation can wrap a
        // bad value (e.g. 257 → 1) into a witness the prover would
        // happily consume and produce a misleading proof from.
        if n > 1 {
            return Err(format!(
                "snapshot_path.path_indices[{i}] is {n}; expected 0 or 1 (binary SMT path bit)"
            ));
        }
        indices.push(n as u8);
    }
    Ok((elements, indices))
}

fn hex_to_fr(h: &str) -> Result<Fr, String> {
    let decoded = hex::decode(h).map_err(|e| format!("hex decode: {e}"))?;
    if decoded.len() > 32 {
        return Err(format!(
            "hex value is {} bytes; expected at most 32",
            decoded.len()
        ));
    }
    let mut bytes = [0u8; 32];
    let off = 32usize.saturating_sub(decoded.len());
    bytes[off..off + decoded.len()].copy_from_slice(&decoded);
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

fn fr_to_decimal(f: &Fr) -> String {
    use ark_ff::BigInteger;
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

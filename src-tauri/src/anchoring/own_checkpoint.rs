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
    let (groth16_proof, public_signals_dec, sig_fields, authority_hash_dec) =
        match (bjj_key, bjj_pubkey, proofs_dir) {
            (Some(key), Some(pubkey), Some(dir)) => {
                let proved = try_build_proof_and_sign(&snap, root_fr, key, pubkey, dir, now)
                    .await?;
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

    // 5. Insert. UUID generated in Rust so the return value carries it
    //    without a second round-trip.
    let id = Uuid::new_v4();
    let signals_json: Option<serde_json::Value> =
        public_signals_dec.as_ref().map(|v| serde_json::json!(v));
    sqlx::query(
        "INSERT INTO own_checkpoints
            (id, ledger_root, tree_size, checkpoint_timestamp,
             authority_pubkey_hash, sig_r8x, sig_r8y, sig_s,
             anchor_hash, groth16_proof, public_signals)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
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
    }))
}

/// Fetch the most recent own_checkpoints row whose Groth16 proof and BJJ
/// signature are both present — i.e. the latest gossipable row.
/// Federation's `build_own_checkpoint` reads this when the gossip loop
/// needs an envelope to push.
pub async fn fetch_latest_gossipable(
    pool: &PgPool,
) -> Result<Option<OwnCheckpointRow>, String> {
    #[derive(sqlx::FromRow)]
    struct Row {
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
    }
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, ledger_root, tree_size, checkpoint_timestamp,
                authority_pubkey_hash, sig_r8x, sig_r8y, sig_s,
                anchor_hash, groth16_proof, public_signals
         FROM own_checkpoints
         WHERE groth16_proof IS NOT NULL
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

    let Some(r) = row else { return Ok(None) };
    if r.anchor_hash.len() != 32 {
        return Err(format!(
            "own_checkpoints.anchor_hash is {} bytes; expected 32 (schema invariant)",
            r.anchor_hash.len()
        ));
    }
    let mut anchor_hash = [0u8; 32];
    anchor_hash.copy_from_slice(&r.anchor_hash);
    let public_signals = r
        .public_signals
        .and_then(|v| v.as_array().cloned())
        .map(|a| {
            a.into_iter()
                .filter_map(|x| x.as_str().map(|s| s.to_owned()))
                .collect::<Vec<_>>()
        });
    Ok(Some(OwnCheckpointRow {
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
    }))
}

// ── Internal helpers ──────────────────────────────────────────────────

type SigTriple = (String, String, String); // (r8x, r8y, s) as decimal Fr

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
    let proof_json = proof_to_snarkjs_json(&proof);
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

/// snarkjs-shape Groth16 proof JSON. Identical to the in-tree copies in
/// `api::zk`, `api::ingest`, `api::redaction`, `federation::checkpoint`.
/// Worth extracting into a shared `zk::proof_json` module in a future
/// cleanup pass.
fn proof_to_snarkjs_json(proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> serde_json::Value {
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

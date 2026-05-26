//! Checkpoint creation, storage, and exchange.
//!
//! A checkpoint bundles this node's latest ledger state with a Groth16 proof
//! and BJJ signature so peers can verify without seeing the data.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Wire format for checkpoint exchange between peers.
///
/// Audit L-F1: carries an explicit [`Self::wire_version`] so future
/// shape changes can be detected at the verify layer instead of being
/// silently misparsed as the current shape. Defaults to the current
/// version on deserialise so checkpoints emitted before the field
/// landed continue to round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCheckpoint {
    /// Wire-format version. See [`super::PEER_CHECKPOINT_WIRE_VERSION`].
    /// `verify_and_store` rejects checkpoints whose version doesn't
    /// match the current constant.
    #[serde(default = "default_wire_version")]
    pub wire_version: u8,
    pub ledger_root: String,
    pub tree_size: i64,
    pub checkpoint_timestamp: i64,
    pub authority_pubkey_hash: String,
    pub groth16_proof: serde_json::Value,
    pub public_signals: Vec<String>,
    pub bjj_signature: Option<BjjSignatureWire>,
}

fn default_wire_version() -> u8 {
    super::PEER_CHECKPOINT_WIRE_VERSION
}

impl PeerCheckpoint {
    /// Current wire-format version. Use when constructing a new
    /// outbound checkpoint so the field is set explicitly rather than
    /// relying on the serde default.
    pub fn current_version() -> u8 {
        super::PEER_CHECKPOINT_WIRE_VERSION
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BjjSignatureWire {
    pub r8x: String,
    pub r8y: String,
    pub s: String,
}

/// Stored checkpoint from a peer.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct StoredCheckpoint {
    pub id: Uuid,
    pub peer_id: Uuid,
    pub ledger_root: String,
    pub tree_size: i64,
    pub checkpoint_timestamp: i64,
    pub authority_pubkey_hash: String,
    pub groth16_proof: serde_json::Value,
    pub public_signals: serde_json::Value,
    pub bjj_signature_r8x: Option<String>,
    pub bjj_signature_r8y: Option<String>,
    pub bjj_signature_s: Option<String>,
    pub verified: bool,
    pub equivocation_detected: bool,
    pub received_at: chrono::NaiveDateTime,
}

pub fn fr_to_decimal(f: &Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

/// Strict canonical-JSON receive gate.
///
/// Re-canonicalises the received bytes and rejects the envelope if the
/// canonical form differs from what was actually transmitted — i.e. the
/// sender used a non-conformant JSON serializer. Then deserialises the
/// canonical bytes into a `PeerCheckpoint`. Pair to
/// [`canonical_checkpoint_bytes`]: producers emit canonical, receivers
/// require canonical, full-stop. Closes the CodeRabbit "JCS on the wire"
/// finding on both sides.
///
/// Rejecting non-canonical envelopes is stricter than necessary for the
/// current downstream code path (which consumes the parsed struct, not
/// the bytes) but matches CLAUDE.md's invariant and prevents a future
/// contributor from accidentally hashing/anchoring/persisting raw wire
/// bytes that aren't byte-identical across federation peers.
pub fn parse_canonical_checkpoint(bytes: &[u8]) -> Result<PeerCheckpoint, String> {
    let canonical = olympus_crypto::canonical::canonicalize_bytes(bytes)
        .map_err(|e| format!("canonicalize received envelope: {e}"))?;
    if canonical != bytes {
        return Err(
            "checkpoint wire bytes are not RFC 8785 / JCS canonical \
             (re-canonicalisation produced different bytes) — rejecting \
             non-canonical envelope"
                .to_owned(),
        );
    }
    serde_json::from_slice(&canonical).map_err(|e| format!("parse: {e}"))
}

/// Serialize a `PeerCheckpoint` to JCS / RFC 8785 canonical JSON bytes.
///
/// Used by both federation wire emission paths — gossip push
/// (`gossip::push_checkpoint`) and the GET-latest endpoint
/// (`api::get_latest_checkpoint`) — so that every checkpoint that
/// crosses the federation wire is byte-identical for the same logical
/// content. Enforces the project-wide JCS invariant in `CLAUDE.md`
/// ("Canonical JSON: Always JCS/RFC 8785 raw UTF-8") on this
/// transport. Follows the same pattern as
/// `api::credentials::canonical_details_bytes`.
pub fn canonical_checkpoint_bytes(cp: &PeerCheckpoint) -> Result<Vec<u8>, String> {
    let raw = serde_json::to_vec(cp).map_err(|e| format!("serialize: {e}"))?;
    olympus_crypto::canonical::canonicalize_bytes(&raw)
        .map_err(|e| format!("canonicalize: {e}"))
}

/// Check if a peer's BJJ pubkey matches a given authority_pubkey_hash.
pub fn peer_matches_authority_hash(peer: &super::peer::PeerNode, authority_hash: &str) -> bool {
    use ark_bn254::Fr;
    let Ok(x) = crate::zk::proof::parse_fr(&peer.bjj_pubkey_x) else { return false };
    let Ok(y) = crate::zk::proof::parse_fr(&peer.bjj_pubkey_y) else { return false };
    let pubkey = crate::zk::witness::baby_jubjub::BabyJubJubPubKey { x, y };
    let Ok(hash) = pubkey.authority_hash() else { return false };
    fr_to_decimal(&hash) == authority_hash
}

/// Build this node's latest checkpoint from the database.
///
/// Returns `None` if no ingest record has a Poseidon snapshot yet
/// (`snapshot_root IS NULL` on all rows — typically a fresh node, or a
/// node whose pre-migration-0029 rows haven't been backfilled).
///
/// **H-11 / M-5 closure (producer side).** The checkpoint embeds a real
/// Groth16 `document_existence` proof attesting that the latest record's
/// `original_root` is at `snapshot_index` in a Poseidon Merkle tree of
/// size `snapshot_size` rooted at `snapshot_root`. The BJJ-EdDSA
/// signature additionally binds the operator's authority key to that
/// `ledger_root` + `checkpoint_timestamp`. Receivers
/// (`verify::verify_and_store`) hard-reject null proofs, so a checkpoint
/// without proof would never be accepted anyway.
///
/// **Why `document_existence` and not `prove_unified`.** The unified
/// circuit was designed for a tree topology v0.9 ingest doesn't ship:
/// it expects a depth-20 *per-document* Merkle tree, a depth-256 SMT
/// over those per-doc roots, and an 8-section domain-3 canonicalization
/// chain. Production stores a 16-chunk per-doc tree → `original_root`,
/// then a single depth-20 *ledger* Merkle tree → `snapshot_root` (no
/// SMT, no canonicalization chain) — which is exactly what
/// `document_existence` (`DOCUMENT_MERKLE_DEPTH = 20`) consumes. Calling
/// `prove_unified` here would require either (a) reshaping ingest to
/// produce the unified circuit's tree topology or (b) recompiling the
/// unified circuit + Phase 2 ceremony to match production. Both are
/// out of scope for closing H-11/M-5; the existence circuit is the
/// already-existing primitive whose shape matches the on-disk data.
///
/// **Cost.** One Groth16 prove call per checkpoint emission; the
/// existence circuit takes ~5-15s on modest hardware. Run inside
/// `tokio::task::spawn_blocking` so the gossip runtime stays responsive
/// during the prove.
pub async fn build_own_checkpoint(
    pool: &PgPool,
    bjj_key: &[u8; 32],
    bjj_pubkey: &crate::zk::witness::baby_jubjub::BabyJubJubPubKey,
    proofs_dir: Option<&std::path::Path>,
) -> Result<Option<PeerCheckpoint>, String> {
    // Latest record with a complete snapshot — everything we need to
    // build an ExistenceWitness in one query. Records committed before
    // migration 0029 have NULLs here; they're invisible to federation
    // until backfilled, which mirrors the `/zk_bundle` endpoint's
    // behaviour (503 on those records).
    #[derive(sqlx::FromRow)]
    struct Snapshot {
        original_root: String,
        snapshot_root: String,
        snapshot_index: i64,
        snapshot_size: i64,
        snapshot_path: serde_json::Value,
    }
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
    .map_err(|e| format!("DB error: {e}"))?;

    let snap = match snap {
        Some(s) => s,
        None => return Ok(None),
    };

    let proofs_dir = proofs_dir.ok_or_else(|| {
        "proofs_dir not configured — cannot build Groth16 existence proof for checkpoint"
            .to_owned()
    })?;

    // Build the existence witness from the stored snapshot. The two
    // hex_to_fr conversions and the snapshot_path deserialisation
    // mirror `api::ingest::generate_existence_bundle` so the wire
    // format of stored snapshots stays in lockstep with the
    // federation producer.
    let root = hex_to_fr(&snap.snapshot_root)?;
    let leaf = hex_to_fr(&snap.original_root)?;
    let path_obj = snap
        .snapshot_path
        .as_object()
        .ok_or_else(|| "snapshot_path is not a JSON object".to_owned())?;
    let path_elements_arr = path_obj
        .get("path_elements")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "snapshot_path.path_elements missing or wrong type".to_owned())?;
    let path_indices_arr = path_obj
        .get("path_indices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "snapshot_path.path_indices missing or wrong type".to_owned())?;

    let mut path_elements: Vec<ark_bn254::Fr> = Vec::with_capacity(path_elements_arr.len());
    for (i, v) in path_elements_arr.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| format!("snapshot_path.path_elements[{i}] is not a string"))?;
        path_elements.push(hex_to_fr(s)?);
    }
    let mut path_indices: Vec<u8> = Vec::with_capacity(path_indices_arr.len());
    for (i, v) in path_indices_arr.iter().enumerate() {
        let n = v
            .as_u64()
            .ok_or_else(|| format!("snapshot_path.path_indices[{i}] is not a number"))?;
        path_indices.push(n as u8);
    }

    let witness = crate::zk::witness::ExistenceWitness::new(
        root,
        snap.snapshot_index as u64,
        snap.snapshot_size as u64,
        leaf,
        path_elements,
        path_indices,
    )
    .map_err(|e| format!("existence witness: {e}"))?;

    // Resolve circuit artifacts; surface a clear error rather than a
    // panic if the build is missing the existence circuit. Production
    // refuses to start with placeholder stubs under OLYMPUS_ENV=production,
    // so any artifact missing here under prod-mode means an out-of-band
    // delete; under dev-mode it means the operator hasn't run
    // `setup_circuits.sh` yet.
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

    // Run prove_existence inside spawn_blocking — the prove is CPU-bound
    // and would otherwise stall the tokio reactor for the gossip task.
    let (proof, public_signals) = tokio::task::spawn_blocking(move || {
        crate::zk::prove::prove_existence(&witness, &wasm, &r1cs, &zkey)
    })
    .await
    .map_err(|e| format!("prove join: {e}"))?
    .map_err(|e| format!("prove existence: {e}"))?;

    let groth16_proof_json = proof_to_snarkjs_json(&proof);

    // Sign the new ledger_root (= snapshot_root, the real Poseidon ledger
    // tree root) under the BJJ authority key for the BJJ-EdDSA-Poseidon
    // checkpoint signature. The receiver re-verifies this signature
    // against the sender's pinned authority pubkey.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let sig = crate::zk::witness::unified::UnifiedWitness::sign_checkpoint(
        bjj_key,
        root,
        now as u64,
    )
    .map_err(|e| format!("BJJ sign: {e}"))?;

    let authority_hash = bjj_pubkey
        .authority_hash()
        .map_err(|e| format!("pubkey hash: {e}"))?;

    Ok(Some(PeerCheckpoint {
        wire_version: PeerCheckpoint::current_version(),
        ledger_root: snap.snapshot_root.clone(),
        tree_size: snap.snapshot_size,
        checkpoint_timestamp: now,
        authority_pubkey_hash: fr_to_decimal(&authority_hash),
        groth16_proof: groth16_proof_json,
        // document_existence emits public signals in order
        // [root, leafIndex, treeSize] (see prove.rs::prove_existence
        // docstring). Re-encode from the Fr returned by ark-groth16 so
        // the wire form is the snarkjs-style decimal Fr string.
        public_signals: public_signals.iter().map(fr_to_decimal).collect(),
        bjj_signature: Some(BjjSignatureWire {
            r8x: fr_to_decimal(&sig.r8x),
            r8y: fr_to_decimal(&sig.r8y),
            s: fr_to_decimal(&sig.s),
        }),
    }))
}

/// Hex (BLAKE3-shaped) → Fr (BN254 scalar via mod-order reduction).
///
/// Same mapping `api::ingest::generate_existence_bundle` uses so the
/// federation producer and the local `/zk_bundle` endpoint agree on the
/// Fr embedding of `snapshot_root` / `original_root` / path elements.
fn hex_to_fr(h: &str) -> Result<ark_bn254::Fr, String> {
    use ark_ff::PrimeField;
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
    Ok(ark_bn254::Fr::from_be_bytes_mod_order(&bytes))
}

/// snarkjs-shape Groth16 proof JSON (`pi_a`/`pi_b`/`pi_c` decimal-string
/// affine coordinates).
///
/// Locally duplicated from `api::zk::proof_to_json` /
/// `api::ingest::groth16_proof_to_json` / `api::redaction::groth16_proof_to_json`.
/// Worth a future cleanup pass into a shared `zk::proof_json` module;
/// kept localized here to keep the H-11/M-5 closure to a single file
/// change.
fn proof_to_snarkjs_json(
    proof: &ark_groth16::Proof<ark_bn254::Bn254>,
) -> serde_json::Value {
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

/// Submit a checkpoint to every configured external anchor (RFC 3161 / Rekor
/// / OTS) and persist the resulting receipts linked back to a checkpoint
/// row id. Failure on any single anchor is logged but does not abort —
/// the three are intentionally redundant.
///
/// Call this after `store_peer_checkpoint` (or after `build_own_checkpoint`
/// for the local node's own checkpoint, once it's been persisted with a
/// row id) so the receipts have a stable `checkpoint_id` to link to.
pub async fn anchor_checkpoint(
    pool: &sqlx::PgPool,
    cfg: &crate::anchoring::AnchoringConfig,
    http: &reqwest::Client,
    cp: &PeerCheckpoint,
    checkpoint_id: Option<Uuid>,
) -> (usize, usize) {
    if !cfg.any_enabled() {
        return (0, 0);
    }
    let sig = cp.bjj_signature.as_ref();
    let hash = crate::anchoring::checkpoint_anchor_hash(
        &cp.ledger_root,
        cp.tree_size,
        cp.checkpoint_timestamp,
        &cp.authority_pubkey_hash,
        sig.map(|s| s.r8x.as_str()),
        sig.map(|s| s.r8y.as_str()),
        sig.map(|s| s.s.as_str()),
    );
    let (ok, errs) = crate::anchoring::anchor_all(pool, cfg, http, hash, checkpoint_id).await;
    for (kind, e) in &errs {
        tracing::warn!(
            "federation: anchor {} failed for checkpoint {:?}: {}",
            kind.as_str(),
            checkpoint_id,
            e
        );
    }
    (ok.len(), errs.len())
}

/// Store a checkpoint received from a peer.
pub async fn store_peer_checkpoint(
    pool: &PgPool,
    peer_id: Uuid,
    cp: &PeerCheckpoint,
    verified: bool,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    let sig = cp.bjj_signature.as_ref();

    sqlx::query(
        "INSERT INTO peer_checkpoints
             (id, peer_id, ledger_root, tree_size, checkpoint_timestamp,
              authority_pubkey_hash, groth16_proof, public_signals,
              bjj_signature_r8x, bjj_signature_r8y, bjj_signature_s,
              verified, received_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
         ON CONFLICT (peer_id, checkpoint_timestamp, ledger_root) DO NOTHING",
    )
    .bind(id)
    .bind(peer_id)
    .bind(&cp.ledger_root)
    .bind(cp.tree_size)
    .bind(cp.checkpoint_timestamp)
    .bind(&cp.authority_pubkey_hash)
    .bind(&cp.groth16_proof)
    .bind(serde_json::to_value(&cp.public_signals).unwrap_or_default())
    .bind(sig.map(|s| &s.r8x))
    .bind(sig.map(|s| &s.r8y))
    .bind(sig.map(|s| &s.s))
    .bind(verified)
    .execute(pool)
    .await?;

    Ok(id)
}

#[cfg(test)]
mod wire_tests {
    //! Audit L-F1: pin the wire-version behaviour so any future change
    //! to the serialised shape has to be conscious.
    use super::*;

    fn fixture_payload_without_version() -> serde_json::Value {
        // Mirrors a v0 emission (no `wire_version` field).
        serde_json::json!({
            "ledger_root": "1",
            "tree_size": 1,
            "checkpoint_timestamp": 1700000000,
            "authority_pubkey_hash": "0",
            "groth16_proof": null,
            "public_signals": [],
            "bjj_signature": null,
        })
    }

    /// Build a valid `PeerCheckpoint` and return its canonical JSON
    /// bytes — the byte-exact form a conformant peer would emit.
    fn canonical_fixture_bytes() -> Vec<u8> {
        let cp = PeerCheckpoint {
            wire_version: PeerCheckpoint::current_version(),
            ledger_root: "1".to_owned(),
            tree_size: 1,
            checkpoint_timestamp: 1_700_000_000,
            authority_pubkey_hash: "0".to_owned(),
            groth16_proof: serde_json::json!({"pi_a": [], "pi_b": [], "pi_c": []}),
            public_signals: vec!["1".to_owned()],
            bjj_signature: None,
        };
        canonical_checkpoint_bytes(&cp).expect("canonicalize fixture")
    }

    #[test]
    fn parse_canonical_accepts_canonical_bytes() {
        // Round-trip: emitter produces canonical bytes; receiver
        // accepts them. This is the happy path between two
        // JCS-conformant peers.
        let bytes = canonical_fixture_bytes();
        let cp = parse_canonical_checkpoint(&bytes).expect("canonical bytes must parse");
        assert_eq!(cp.ledger_root, "1");
        assert_eq!(cp.tree_size, 1);
    }

    #[test]
    fn parse_canonical_rejects_non_canonical_bytes() {
        // A peer emitting "valid JSON but not canonical" (e.g. with
        // whitespace, or keys out of canonical order) gets rejected.
        // JCS sorts object keys by UTF-16 code-unit order; this
        // hand-rolled form sorts keys differently and adds whitespace.
        let non_canonical = br#"{
  "wire_version": 1,
  "ledger_root": "1",
  "tree_size": 1,
  "checkpoint_timestamp": 1700000000,
  "authority_pubkey_hash": "0",
  "public_signals": ["1"],
  "groth16_proof": {"pi_a": [], "pi_b": [], "pi_c": []},
  "bjj_signature": null
}"#;
        let err = parse_canonical_checkpoint(non_canonical)
            .expect_err("non-canonical envelope must be rejected");
        assert!(
            err.contains("not RFC 8785 / JCS canonical"),
            "error should call out JCS violation, got: {err}"
        );
    }

    #[test]
    fn parse_canonical_rejects_invalid_json() {
        let err = parse_canonical_checkpoint(b"not even json")
            .expect_err("garbage bytes must be rejected");
        // Either the canonicalize step or the parse step fails — both
        // are acceptable since both are JCS-enforcement failures.
        assert!(
            err.contains("canonicalize") || err.contains("parse"),
            "error should indicate JCS or parse failure, got: {err}"
        );
    }

    #[test]
    fn current_version_constant_is_one() {
        // Wire version is currently 1. Any bump is intentional — this
        // test exists so the bump shows up in code review.
        assert_eq!(PeerCheckpoint::current_version(), 1);
        assert_eq!(default_wire_version(), 1);
    }

    #[test]
    fn deserialise_defaults_missing_wire_version_to_current() {
        // Peers emitting the pre-L-F1 shape (no `wire_version`) must
        // continue to deserialise at the current version so a partial
        // upgrade doesn't drop every checkpoint at the wire boundary.
        // verify_and_store still rejects mismatched versions; this is
        // only about parse-side compat.
        let cp: PeerCheckpoint =
            serde_json::from_value(fixture_payload_without_version()).expect("deserialise");
        assert_eq!(cp.wire_version, PeerCheckpoint::current_version());
    }

    #[test]
    fn explicit_wire_version_round_trips() {
        let mut payload = fixture_payload_without_version();
        payload["wire_version"] = serde_json::json!(7);
        let cp: PeerCheckpoint = serde_json::from_value(payload).unwrap();
        assert_eq!(cp.wire_version, 7);
        // Serialise → re-deserialise preserves the value.
        let json = serde_json::to_value(&cp).unwrap();
        assert_eq!(json["wire_version"], 7);
    }
}

/// List checkpoints from a specific peer, newest first.
pub async fn list_peer_checkpoints(
    pool: &PgPool,
    peer_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<StoredCheckpoint>, sqlx::Error> {
    if let Some(pid) = peer_id {
        sqlx::query_as::<_, StoredCheckpoint>(
            "SELECT * FROM peer_checkpoints WHERE peer_id = $1
             ORDER BY received_at DESC LIMIT $2",
        )
        .bind(pid)
        .bind(limit)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, StoredCheckpoint>(
            "SELECT * FROM peer_checkpoints ORDER BY received_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}

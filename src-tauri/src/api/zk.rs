//! ZK Groth16 prove + verify HTTP routes.
//!
//! POST /zk/verify  — verify a Groth16 proof against embedded vkeys
//! POST /zk/prove   — generate a Groth16 proof from witness data

use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::proof::{parse_fr, parse_signals_slice};
use crate::zk::verify::{existence_verifier, non_existence_verifier, redaction_verifier};

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": detail })))
}

// ── POST /zk/verify ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest {
    circuit: String,
    proof_json: String,
    public_signals: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyResponse {
    valid: bool,
    circuit: String,
}

async fn verify(
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    if !auth.has_scope("verify") && !auth.has_scope("read") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: one of 'verify', 'read', or 'admin'",
        ));
    }
    let circuit = req.circuit.clone();
    let proof_json = req.proof_json.clone();
    let signals_raw = req.public_signals.clone();

    let result = tokio::task::spawn_blocking(move || {
        let signals = parse_signals_slice(&signals_raw)
            .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("signal parse: {e}")))?;

        let valid = match circuit.as_str() {
            "document_existence" => existence_verifier()
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("verifier init: {e}")))?
                .verify(&proof_json, &signals)
                .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("verify: {e}")))?,
            "non_existence" => non_existence_verifier()
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("verifier init: {e}")))?
                .verify(&proof_json, &signals)
                .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("verify: {e}")))?,
            "redaction_validity" => redaction_verifier()
                .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("verifier init: {e}")))?
                .verify(&proof_json, &signals)
                .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("verify: {e}")))?,
            other => return Err(err(StatusCode::BAD_REQUEST, &format!("unknown circuit: {other}"))),
        };

        Ok(VerifyResponse { valid, circuit })
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("thread join: {e}")))?;

    result.map(Json)
}

// ── POST /zk/prove ───────────────────────────────────────────────────────────

#[cfg(feature = "prover")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProveRequest {
    circuit: String,
    #[serde(default)]
    keys_dir: Option<String>,
    witness: serde_json::Value,
}

#[cfg(feature = "prover")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProveResponse {
    circuit: String,
    proof: serde_json::Value,
    public_signals: Vec<String>,
}

#[cfg(feature = "prover")]
fn fr_to_decimal(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

#[cfg(feature = "prover")]
fn proof_to_json(proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> serde_json::Value {
    use ark_serialize::CanonicalSerialize;
    fn g1_strings(p: &ark_bn254::G1Affine) -> Vec<String> {
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        let x = num_bigint::BigUint::from_bytes_le(&buf[..32]);
        let y = num_bigint::BigUint::from_bytes_le(&buf[32..64]);
        vec![x.to_string(), y.to_string(), "1".into()]
    }
    fn g2_strings(p: &ark_bn254::G2Affine) -> Vec<Vec<String>> {
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
        "pi_a": g1_strings(&proof.a),
        "pi_b": g2_strings(&proof.b),
        "pi_c": g1_strings(&proof.c),
        "protocol": "groth16",
        "curve": "bn128",
    })
}

#[cfg(feature = "prover")]
async fn prove(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, ApiError> {
    if !auth.has_scope("prove") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: one of 'prove' or 'admin'",
        ));
    }

    // Resolve where the circuit artifacts live. Order: explicit request override
    // → resolved-at-startup state.proofs_dir → repo-relative dev fallback. The
    // startup path checks for a populated `verification_keys/` subdir before
    // accepting a candidate, so falling through to the dev fallback only
    // happens for an external (non-Tauri) embedding that never set the field.
    let keys_dir = match req.keys_dir.as_deref() {
        Some(p) => std::path::PathBuf::from(p),
        None => state
            .proofs_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("proofs/keys")),
    };

    let circuit_name = req.circuit.clone();
    let witness_val = req.witness.clone();
    let bjj_key = state.bjj_authority_key;
    let bjj_pubkey = state.bjj_authority_pubkey;

    let result = tokio::task::spawn_blocking(move || {
        use crate::zk::Circuit;

        let circuit = match circuit_name.as_str() {
            "document_existence" => Circuit::DocumentExistence,
            "non_existence" => Circuit::NonExistence,
            "redaction_validity" => Circuit::RedactionValidity,
            "unified_canonicalization_inclusion_root_sign" => {
                Circuit::UnifiedCanonicalizationInclusionRootSign
            }
            other => return Err(err(StatusCode::BAD_REQUEST, &format!("unknown circuit: {other}"))),
        };

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

        let (proof, public_signals) = match circuit_name.as_str() {
            "document_existence" => {
                let w = parse_existence_witness(&witness_val)?;
                crate::zk::prove::prove_existence(&w, &wasm, &r1cs, &zkey)
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("prove: {e}")))?
            }
            "non_existence" => {
                let w = parse_non_existence_witness(&witness_val)?;
                crate::zk::prove::prove_non_existence(&w, &wasm, &r1cs, &zkey)
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("prove: {e}")))?
            }
            "redaction_validity" => {
                let w = parse_redaction_witness(&witness_val)?;
                crate::zk::prove::prove_redaction(&w, &wasm, &r1cs, &zkey)
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("prove: {e}")))?
            }
            "unified_canonicalization_inclusion_root_sign" => {
                let bjj_priv = bjj_key.ok_or_else(|| err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "OLYMPUS_BJJ_AUTHORITY_KEY not configured — cannot sign unified proofs",
                ))?;
                let bjj_pub = bjj_pubkey.ok_or_else(|| err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "BJJ authority pubkey not available",
                ))?;
                let w = parse_unified_witness(&witness_val, &bjj_priv, bjj_pub)?;
                crate::zk::prove::prove_unified(&w, &wasm, &r1cs, &zkey)
                    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("prove: {e}")))?
            }
            _ => unreachable!(),
        };

        let signals_str: Vec<String> = public_signals.iter().map(fr_to_decimal).collect();

        Ok(ProveResponse {
            circuit: circuit_name,
            proof: proof_to_json(&proof),
            public_signals: signals_str,
        })
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("thread join: {e}")))?;

    result.map(Json)
}

// ── Witness parsers ──────────────────────────────────────────────────────────

#[cfg(feature = "prover")]
fn parse_existence_witness(
    v: &serde_json::Value,
) -> Result<crate::zk::witness::ExistenceWitness, ApiError> {
    let root = parse_fr(
        v.get("root").and_then(|v| v.as_str()).ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.root"))?,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("root: {e}")))?;

    let leaf = parse_fr(
        v.get("leaf").and_then(|v| v.as_str()).ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.leaf"))?,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("leaf: {e}")))?;

    let leaf_index = v.get("leafIndex").and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.leafIndex"))?;
    let tree_size = v.get("treeSize").and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.treeSize"))?;

    let path_elements = parse_fr_array(v, "pathElements")?;
    let path_indices = v.get("pathIndices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.pathIndices"))?
        .iter()
        .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()).ok_or_else(|| err(StatusCode::BAD_REQUEST, "pathIndices: not u8")))
        .collect::<Result<Vec<u8>, _>>()?;

    crate::zk::witness::ExistenceWitness::new(root, leaf_index, tree_size, leaf, path_elements, path_indices)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

#[cfg(feature = "prover")]
fn parse_non_existence_witness(
    v: &serde_json::Value,
) -> Result<crate::zk::witness::NonExistenceWitness, ApiError> {
    let root = parse_fr(
        v.get("root").and_then(|v| v.as_str()).ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.root"))?,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("root: {e}")))?;

    let key_arr = v.get("key")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.key (32-byte array)"))?;
    if key_arr.len() != 32 {
        return Err(err(StatusCode::BAD_REQUEST, &format!("key must be 32 bytes, got {}", key_arr.len())));
    }
    let mut key = [0u8; 32];
    for (i, val) in key_arr.iter().enumerate() {
        key[i] = val.as_u64().and_then(|n| u8::try_from(n).ok())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("key[{i}]: not u8")))?;
    }

    let path_elements = parse_fr_array(v, "pathElements")?;

    crate::zk::witness::NonExistenceWitness::new(root, key, path_elements)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

#[cfg(feature = "prover")]
fn parse_redaction_witness(
    v: &serde_json::Value,
) -> Result<crate::zk::witness::RedactionWitness, ApiError> {
    let original_root = parse_fr(
        v.get("originalRoot").and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.originalRoot"))?,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("originalRoot: {e}")))?;

    let recipient_id = parse_fr(
        v.get("recipientId").and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.recipientId"))?,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("recipientId: {e}")))?;

    let original_leaves = parse_fr_array(v, "originalLeaves")?;

    let reveal_mask = v.get("revealMask")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.revealMask"))?
        .iter()
        .map(|v| match v.as_u64() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(err(StatusCode::BAD_REQUEST, "revealMask: values must be 0 or 1")),
        })
        .collect::<Result<Vec<bool>, _>>()?;

    let path_elements = parse_fr_2d_array(v, "pathElements")?;
    let path_indices = v.get("pathIndices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.pathIndices"))?
        .iter()
        .map(|row| {
            row.as_array()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "pathIndices: expected 2D array"))?
                .iter()
                .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()).ok_or_else(|| err(StatusCode::BAD_REQUEST, "pathIndices: not u8")))
                .collect::<Result<Vec<u8>, _>>()
        })
        .collect::<Result<Vec<Vec<u8>>, _>>()?;

    crate::zk::witness::RedactionWitness::new(
        original_root, original_leaves, reveal_mask, path_elements, path_indices, recipient_id,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

#[cfg(feature = "prover")]
fn parse_fr_array(v: &serde_json::Value, field: &str) -> Result<Vec<ark_bn254::Fr>, ApiError> {
    v.get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("missing witness.{field}")))?
        .iter()
        .enumerate()
        .map(|(i, val)| {
            parse_fr(val.as_str().ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("{field}[{i}]: not string")))?)
                .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("{field}[{i}]: {e}")))
        })
        .collect()
}

#[cfg(feature = "prover")]
fn parse_unified_witness(
    v: &serde_json::Value,
    bjj_priv: &[u8; 32],
    bjj_pub: crate::zk::witness::baby_jubjub::BabyJubJubPubKey,
) -> Result<crate::zk::witness::UnifiedWitness, ApiError> {
    let canonical_hash = parse_fr(
        v.get("canonicalHash").and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.canonicalHash"))?,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("canonicalHash: {e}")))?;

    let merkle_root = parse_fr(
        v.get("merkleRoot").and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.merkleRoot"))?,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("merkleRoot: {e}")))?;

    let ledger_root = parse_fr(
        v.get("ledgerRoot").and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.ledgerRoot"))?,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("ledgerRoot: {e}")))?;

    let tree_size = v.get("treeSize").and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.treeSize"))?;
    let checkpoint_timestamp = v.get("checkpointTimestamp").and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.checkpointTimestamp"))?;
    let section_count = v.get("sectionCount").and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.sectionCount"))?;
    let leaf_index = v.get("leafIndex").and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.leafIndex"))?;

    let document_sections = parse_fr_array(v, "documentSections")?;
    let section_hashes = parse_fr_array(v, "sectionHashes")?;
    let merkle_path = parse_fr_array(v, "merklePath")?;
    let ledger_path_elements = parse_fr_array(v, "ledgerPathElements")?;

    let section_lengths = v.get("sectionLengths")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.sectionLengths"))?
        .iter()
        .map(|v| v.as_u64().ok_or_else(|| err(StatusCode::BAD_REQUEST, "sectionLengths: not u64")))
        .collect::<Result<Vec<u64>, _>>()?;

    let merkle_indices = parse_u8_array(v, "merkleIndices")?;
    let ledger_path_indices = parse_u8_array(v, "ledgerPathIndices")?;

    let signature = crate::zk::witness::unified::UnifiedWitness::sign_checkpoint(
        bjj_priv, ledger_root, checkpoint_timestamp,
    ).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("BJJ sign: {e}")))?;

    crate::zk::witness::UnifiedWitness::new(
        canonical_hash,
        merkle_root,
        ledger_root,
        tree_size,
        checkpoint_timestamp,
        bjj_pub,
        document_sections,
        section_count,
        section_lengths,
        section_hashes,
        merkle_path,
        merkle_indices,
        leaf_index,
        ledger_path_elements,
        ledger_path_indices,
        signature,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

#[cfg(feature = "prover")]
fn parse_u8_array(v: &serde_json::Value, field: &str) -> Result<Vec<u8>, ApiError> {
    v.get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("missing witness.{field}")))?
        .iter()
        .map(|v| {
            let n = v.as_u64().ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("{field}: not u8")))?;
            u8::try_from(n).map_err(|_| err(StatusCode::BAD_REQUEST, &format!("{field}: value {n} exceeds u8 range")))
        })
        .collect()
}

#[cfg(feature = "prover")]
fn parse_fr_2d_array(v: &serde_json::Value, field: &str) -> Result<Vec<Vec<ark_bn254::Fr>>, ApiError> {
    v.get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("missing witness.{field}")))?
        .iter()
        .enumerate()
        .map(|(i, row)| {
            row.as_array()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("{field}[{i}]: expected array")))?
                .iter()
                .enumerate()
                .map(|(j, val)| {
                    parse_fr(val.as_str().ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("{field}[{i}][{j}]: not string")))?)
                        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("{field}[{i}][{j}]: {e}")))
                })
                .collect()
        })
        .collect()
}

// ── Router ───────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    let r = Router::new()
        .route("/zk/verify", post(verify));
    #[cfg(feature = "prover")]
    let r = r.route("/zk/prove", post(prove));
    r
}

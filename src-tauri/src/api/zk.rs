//! ZK Groth16 prove + verify HTTP routes.
//!
//! POST /zk/verify  — verify a Groth16 proof against embedded vkeys
//! POST /zk/prove   — generate a Groth16 proof from witness data

use axum::{
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};

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

async fn verify(Json(req): Json<VerifyRequest>) -> Result<Json<VerifyResponse>, ApiError> {
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

        Ok(VerifyResponse { valid, circuit: req.circuit })
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("thread join: {e}")))?;

    result.map(Json)
}

// ── POST /zk/prove ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProveRequest {
    circuit: String,
    #[serde(default)]
    keys_dir: Option<String>,
    witness: serde_json::Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProveResponse {
    circuit: String,
    proof: serde_json::Value,
    public_signals: Vec<String>,
}

fn fr_to_decimal(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

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

async fn prove(Json(req): Json<ProveRequest>) -> Result<Json<ProveResponse>, ApiError> {
    let keys_dir = std::path::PathBuf::from(
        req.keys_dir.as_deref().unwrap_or("proofs/keys"),
    );

    let circuit_name = req.circuit.clone();
    let witness_val = req.witness.clone();

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
                return Err(err(
                    StatusCode::NOT_IMPLEMENTED,
                    "unified circuit proving via HTTP is not yet supported — use the Tauri command",
                ));
            }
            _ => unreachable!(),
        };

        let signals_str: Vec<String> = public_signals.iter().map(fr_to_decimal).collect();

        Ok(ProveResponse {
            circuit: req.circuit,
            proof: proof_to_json(&proof),
            public_signals: signals_str,
        })
    })
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("thread join: {e}")))?;

    result.map(Json)
}

// ── Witness parsers ──────────────────────────────────────────────────────────

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
        .map(|v| v.as_u64().map(|n| n as u8).ok_or_else(|| err(StatusCode::BAD_REQUEST, "pathIndices: not u8")))
        .collect::<Result<Vec<u8>, _>>()?;

    crate::zk::witness::ExistenceWitness::new(root, leaf_index, tree_size, leaf, path_elements, path_indices)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

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
        key[i] = val.as_u64().map(|n| n as u8)
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("key[{i}]: not u8")))?;
    }

    let path_elements = parse_fr_array(v, "pathElements")?;

    crate::zk::witness::NonExistenceWitness::new(root, key, path_elements)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

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
                .map(|v| v.as_u64().map(|n| n as u8).ok_or_else(|| err(StatusCode::BAD_REQUEST, "pathIndices: not u8")))
                .collect::<Result<Vec<u8>, _>>()
        })
        .collect::<Result<Vec<Vec<u8>>, _>>()?;

    crate::zk::witness::RedactionWitness::new(
        original_root, original_leaves, reveal_mask, path_elements, path_indices, recipient_id,
    ).map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

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
    Router::new()
        .route("/zk/verify", post(verify))
        .route("/zk/prove", post(prove))
}

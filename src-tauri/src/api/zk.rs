//! ZK Groth16 prove + verify HTTP routes.
//!
//! POST /zk/verify  — verify a Groth16 proof against embedded vkeys
//! POST /zk/prove   — generate a Groth16 proof from witness data

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::proof::{parse_fr, parse_signals_slice};
use crate::zk::verify::{
    existence_verifier, non_existence_verifier, redaction_verifier, unified_verifier,
};

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": detail })))
}

/// Audit H-2 helper: when `signals[tree_size_idx]` is zero, the in-circuit
/// `leafIndex < treeSize` bounds check is disabled. The circuit docstring
/// requires off-chain verifiers to reject this case unless `signals[root_idx]`
/// equals the precomputed empty-tree root. Without this guard, a caller can
/// submit `treeSize=0` together with any non-empty root and an arbitrary
/// `leafIndex < 2^depth` and the pairing check will pass for an inclusion
/// claim at an out-of-range index.
fn enforce_empty_tree_invariant(
    signals: &[ark_bn254::Fr],
    root_idx: usize,
    tree_size_idx: usize,
) -> Result<(), ApiError> {
    use ark_ff::Zero;
    let Some(tree_size) = signals.get(tree_size_idx) else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "public signals missing treeSize",
        ));
    };
    if !tree_size.is_zero() {
        return Ok(());
    }
    let Some(root) = signals.get(root_idx) else {
        return Err(err(StatusCode::BAD_REQUEST, "public signals missing root"));
    };
    let empty = crate::zk::poseidon::empty_doc_existence_root().map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("empty-tree root resolve: {e}"),
        )
    })?;
    if *root != empty {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "treeSize=0 requires root == empty-tree root (audit H-2): \
             rejecting inclusion proof against a non-empty root with treeSize=0",
        ));
    }
    Ok(())
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
            "document_existence" => {
                // Audit H-2: the circuit's `leafIndex < treeSize` bounds
                // check is disabled when `treeSize == 0`. The circuit's
                // own docstring says off-chain verifiers MUST reject
                // `treeSize == 0` unless `root` is the empty-tree root.
                // Public signal order: [root, leafIndex, treeSize].
                enforce_empty_tree_invariant(&signals, 0, 2)?;
                existence_verifier()
                    .map_err(|e| {
                        err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("verifier init: {e}"),
                        )
                    })?
                    .verify(&proof_json, &signals)
                    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("verify: {e}")))?
            }
            "non_existence" => non_existence_verifier()
                .map_err(|e| {
                    err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("verifier init: {e}"),
                    )
                })?
                .verify(&proof_json, &signals)
                .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("verify: {e}")))?,
            "redaction_validity" => redaction_verifier()
                .map_err(|e| {
                    err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("verifier init: {e}"),
                    )
                })?
                .verify(&proof_json, &signals)
                .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("verify: {e}")))?,
            "unified_canonicalization_inclusion_root_sign" => {
                // Same H-2 invariant: signal order
                // [canonicalHash, merkleRoot, ledgerRoot, treeSize].
                // The bounds check inside the unified circuit is gated on
                // merkleRoot's tree, so we enforce against `merkleRoot`
                // (index 1) and treeSize (index 3).
                enforce_empty_tree_invariant(&signals, 1, 3)?;
                unified_verifier()
                    .map_err(|e| {
                        err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("verifier init: {e}"),
                        )
                    })?
                    .verify(&proof_json, &signals)
                    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("verify: {e}")))?
            }
            other => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    &format!("unknown circuit: {other}"),
                ))
            }
        };

        Ok(VerifyResponse { valid, circuit })
    })
    .await
    .map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("thread join: {e}"),
        )
    })?;

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
    // Audit (TOB-OLY-08): the request-supplied `keys_dir` lets a caller point
    // artifact loading at an arbitrary local path. Honor it only outside
    // production; in production always use the startup-resolved directory.
    let is_prod = std::env::var("OLYMPUS_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false);
    let keys_dir = match req.keys_dir.as_deref() {
        Some(p) if !is_prod => std::path::PathBuf::from(p),
        _ => state
            .proofs_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("proofs/keys")),
    };

    let circuit_name = req.circuit.clone();
    let witness_val = req.witness.clone();
    let bjj_key = state.bjj_authority_key;
    let bjj_pubkey = state.bjj_authority_pubkey;

    // Defense in depth: bound how long the HTTP handler awaits a single
    // prove attempt. The /zk/prove route is already wrapped by a 300-second
    // `TimeoutLayer` in server/mod.rs; this matching `tokio::time::timeout`
    // returns 504 to the client at the same wall-clock budget.
    //
    // NOTE — this does NOT cancel the underlying spawn_blocking work.
    // `tokio::time::timeout` on a `JoinHandle` only bounds the await; the
    // blocking closure keeps running until it completes (or panics), which
    // means the `WasmSemaphore` slot acquired inside `prove_with_inputs`
    // stays held until then. The semaphore's own 120-second acquire
    // timeout (see `WasmSemaphore::acquire` in zk/prove.rs) is what
    // bounds the worst-case "all 4 slots stuck" recovery — a fifth caller
    // gets `WasmConcurrencyTimeout` rather than waiting forever.
    // CodeRabbit review on PR #1054 corrected an earlier comment that
    // claimed this timeout aborted the worker. Audit finding F-11.
    const PROVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

    let join_handle = tokio::task::spawn_blocking(move || {
        use crate::zk::Circuit;

        let circuit = match circuit_name.as_str() {
            "document_existence" => Circuit::DocumentExistence,
            "non_existence" => Circuit::NonExistence,
            "redaction_validity" => Circuit::RedactionValidity,
            "unified_canonicalization_inclusion_root_sign" => {
                Circuit::UnifiedCanonicalizationInclusionRootSign
            }
            other => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    &format!("unknown circuit: {other}"),
                ))
            }
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

        // Map ProveError → HTTP status. `WitnessInvalid` is produced by the
        // native pre-check helpers (`verify_inputs` / `verify_all_paths`)
        // when the caller supplied a malformed witness — that's a 400, not
        // a 500. Every other variant (WASM concurrency timeout, zkey load
        // failure, ark-groth16 internal error, …) is server-side. M-Z1
        // pre-check (PR #1060) makes this matter on `prove_unified` too.
        let prove_err = |e: crate::zk::prove::ProveError| {
            let status = match e {
                crate::zk::prove::ProveError::WitnessInvalid(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            err(status, &format!("prove: {e}"))
        };

        let (proof, public_signals) = match circuit_name.as_str() {
            "document_existence" => {
                let w = parse_existence_witness(&witness_val)?;
                crate::zk::prove::prove_existence(&w, &wasm, &r1cs, &zkey).map_err(prove_err)?
            }
            "non_existence" => {
                let w = parse_non_existence_witness(&witness_val)?;
                crate::zk::prove::prove_non_existence(&w, &wasm, &r1cs, &zkey).map_err(prove_err)?
            }
            "redaction_validity" => {
                let bjj_priv = bjj_key.ok_or_else(|| err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "OLYMPUS_BJJ_AUTHORITY_KEY not configured — cannot sign redaction proofs (audit M-2)",
                ))?;
                let bjj_pub = bjj_pubkey.ok_or_else(|| {
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "BJJ authority pubkey not available",
                    )
                })?;
                let w = parse_redaction_witness(&witness_val, &bjj_priv, bjj_pub)?;
                crate::zk::prove::prove_redaction(&w, &wasm, &r1cs, &zkey).map_err(prove_err)?
            }
            "unified_canonicalization_inclusion_root_sign" => {
                let bjj_priv = bjj_key.ok_or_else(|| {
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "OLYMPUS_BJJ_AUTHORITY_KEY not configured — cannot sign unified proofs",
                    )
                })?;
                let bjj_pub = bjj_pubkey.ok_or_else(|| {
                    err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "BJJ authority pubkey not available",
                    )
                })?;
                let w = parse_unified_witness(&witness_val, &bjj_priv, bjj_pub)?;
                crate::zk::prove::prove_unified(&w, &wasm, &r1cs, &zkey).map_err(prove_err)?
            }
            _ => unreachable!(),
        };

        let signals_str: Vec<String> = public_signals.iter().map(fr_to_decimal).collect();

        Ok(ProveResponse {
            circuit: circuit_name,
            proof: proof_to_json(&proof),
            public_signals: signals_str,
        })
    });

    let result = match tokio::time::timeout(PROVE_TIMEOUT, join_handle).await {
        Ok(Ok(inner)) => inner,
        Ok(Err(e)) => {
            return Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("thread join: {e}"),
            ))
        }
        Err(_elapsed) => {
            return Err(err(
                StatusCode::GATEWAY_TIMEOUT,
                &format!(
                    "prove exceeded {}s budget — see audit F-11",
                    PROVE_TIMEOUT.as_secs()
                ),
            ));
        }
    };

    result.map(Json)
}

// ── Witness parsers ──────────────────────────────────────────────────────────

/// Maximum acceptable length for any witness JSON array, applied at parse
/// time before any per-element allocation. Real circuit witnesses are tiny
/// (≤256 Merkle siblings for the largest SMT depth, ≤16 redaction leaves,
/// ≤4096 unified-circuit document sections). The cap protects against a
/// pathological witness body (still within the 128 MB request limit) that
/// would otherwise drive serde + Vec<Fr> allocation before the strict
/// per-circuit length check in `Witness::new` could fire. Audit finding F-13.
#[cfg(feature = "prover")]
const MAX_WITNESS_ARRAY_LEN: usize = 4096;

#[cfg(feature = "prover")]
fn check_witness_array_len(field: &str, len: usize) -> Result<(), ApiError> {
    if len > MAX_WITNESS_ARRAY_LEN {
        return Err(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!(
                "{field}: array length {len} exceeds witness cap {MAX_WITNESS_ARRAY_LEN} \
                 (audit F-13)"
            ),
        ));
    }
    Ok(())
}

#[cfg(feature = "prover")]
fn parse_existence_witness(
    v: &serde_json::Value,
) -> Result<crate::zk::witness::ExistenceWitness, ApiError> {
    let root = parse_fr(
        v.get("root")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.root"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("root: {e}")))?;

    let leaf = parse_fr(
        v.get("leaf")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.leaf"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("leaf: {e}")))?;

    let leaf_index = v
        .get("leafIndex")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.leafIndex"))?;
    let tree_size = v
        .get("treeSize")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.treeSize"))?;

    let path_elements = parse_fr_array(v, "pathElements")?;
    let path_indices_arr = v
        .get("pathIndices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.pathIndices"))?;
    check_witness_array_len("pathIndices", path_indices_arr.len())?;
    let path_indices = path_indices_arr
        .iter()
        .map(|v| {
            v.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "pathIndices: not u8"))
        })
        .collect::<Result<Vec<u8>, _>>()?;

    crate::zk::witness::ExistenceWitness::new(
        root,
        leaf_index,
        tree_size,
        leaf,
        path_elements,
        path_indices,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

#[cfg(feature = "prover")]
fn parse_non_existence_witness(
    v: &serde_json::Value,
) -> Result<crate::zk::witness::NonExistenceWitness, ApiError> {
    let root = parse_fr(
        v.get("root")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.root"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("root: {e}")))?;

    let key_arr = v.get("key").and_then(|v| v.as_array()).ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "missing witness.key (32-byte array)",
        )
    })?;
    if key_arr.len() != 32 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("key must be 32 bytes, got {}", key_arr.len()),
        ));
    }
    let mut key = [0u8; 32];
    for (i, val) in key_arr.iter().enumerate() {
        key[i] = val
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("key[{i}]: not u8")))?;
    }

    let path_elements = parse_fr_array(v, "pathElements")?;

    crate::zk::witness::NonExistenceWitness::new(root, key, path_elements)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

#[cfg(feature = "prover")]
fn parse_redaction_witness(
    v: &serde_json::Value,
    bjj_priv: &[u8; 32],
    bjj_pub: crate::zk::witness::baby_jubjub::BabyJubJubPubKey,
) -> Result<crate::zk::witness::RedactionWitness, ApiError> {
    let original_root = parse_fr(
        v.get("originalRoot")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.originalRoot"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("originalRoot: {e}")))?;

    let recipient_id = parse_fr(
        v.get("recipientId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.recipientId"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("recipientId: {e}")))?;

    let original_leaves = parse_fr_array(v, "originalLeaves")?;

    let reveal_mask_arr = v
        .get("revealMask")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.revealMask"))?;
    check_witness_array_len("revealMask", reveal_mask_arr.len())?;
    let reveal_mask = reveal_mask_arr
        .iter()
        .map(|v| match v.as_u64() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(err(
                StatusCode::BAD_REQUEST,
                "revealMask: values must be 0 or 1",
            )),
        })
        .collect::<Result<Vec<bool>, _>>()?;

    let path_elements = parse_fr_2d_array(v, "pathElements")?;
    let path_indices_arr = v
        .get("pathIndices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.pathIndices"))?;
    check_witness_array_len("pathIndices", path_indices_arr.len())?;
    let path_indices = path_indices_arr
        .iter()
        .map(|row| {
            let row_arr = row
                .as_array()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "pathIndices: expected 2D array"))?;
            check_witness_array_len("pathIndices[row]", row_arr.len())?;
            row_arr
                .iter()
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "pathIndices: not u8"))
                })
                .collect::<Result<Vec<u8>, _>>()
        })
        .collect::<Result<Vec<Vec<u8>>, _>>()?;

    // Audit M-2: compute the nullifier digest and sign it with the
    // server-side BJJ authority key. The circuit's
    // EdDSAPoseidonVerifier will re-check the same signature in-circuit.
    let redacted_commitment = crate::zk::poseidon::redaction_commitment(
        reveal_mask.iter().filter(|&&b| b).count() as u64,
        &original_leaves,
        &reveal_mask,
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("commit: {e}")))?;
    let nullifier_msg =
        crate::zk::poseidon::hash_n(&[original_root, redacted_commitment, recipient_id]).map_err(
            |e| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("nullifier: {e}"),
                )
            },
        )?;
    let issuer_sig = crate::zk::witness::baby_jubjub::sign(bjj_priv, nullifier_msg)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("BJJ sign: {e}")))?;

    crate::zk::witness::RedactionWitness::new(
        original_root,
        original_leaves,
        reveal_mask,
        path_elements,
        path_indices,
        recipient_id,
        bjj_pub,
        issuer_sig,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

#[cfg(feature = "prover")]
fn parse_fr_array(v: &serde_json::Value, field: &str) -> Result<Vec<ark_bn254::Fr>, ApiError> {
    let arr = v
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("missing witness.{field}")))?;
    check_witness_array_len(field, arr.len())?;
    arr.iter()
        .enumerate()
        .map(|(i, val)| {
            parse_fr(val.as_str().ok_or_else(|| {
                err(
                    StatusCode::BAD_REQUEST,
                    &format!("{field}[{i}]: not string"),
                )
            })?)
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
        v.get("canonicalHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.canonicalHash"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("canonicalHash: {e}")))?;

    let merkle_root = parse_fr(
        v.get("merkleRoot")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.merkleRoot"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("merkleRoot: {e}")))?;

    let ledger_root = parse_fr(
        v.get("ledgerRoot")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.ledgerRoot"))?,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("ledgerRoot: {e}")))?;

    let tree_size = v
        .get("treeSize")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.treeSize"))?;
    let checkpoint_timestamp = v
        .get("checkpointTimestamp")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "missing witness.checkpointTimestamp",
            )
        })?;
    let section_count = v
        .get("sectionCount")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.sectionCount"))?;
    let leaf_index = v
        .get("leafIndex")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.leafIndex"))?;

    let document_sections = parse_fr_array(v, "documentSections")?;
    let section_hashes = parse_fr_array(v, "sectionHashes")?;
    let merkle_path = parse_fr_array(v, "merklePath")?;
    let ledger_path_elements = parse_fr_array(v, "ledgerPathElements")?;

    let section_lengths_arr = v
        .get("sectionLengths")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing witness.sectionLengths"))?;
    check_witness_array_len("sectionLengths", section_lengths_arr.len())?;
    let section_lengths = section_lengths_arr
        .iter()
        .map(|v| {
            v.as_u64()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, "sectionLengths: not u64"))
        })
        .collect::<Result<Vec<u64>, _>>()?;

    let merkle_indices = parse_u8_array(v, "merkleIndices")?;
    let ledger_path_indices = parse_u8_array(v, "ledgerPathIndices")?;

    let signature = crate::zk::witness::unified::UnifiedWitness::sign_checkpoint(
        bjj_priv,
        ledger_root,
        checkpoint_timestamp,
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("BJJ sign: {e}")))?;

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
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("witness: {e}")))
}

#[cfg(feature = "prover")]
fn parse_u8_array(v: &serde_json::Value, field: &str) -> Result<Vec<u8>, ApiError> {
    let arr = v
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("missing witness.{field}")))?;
    check_witness_array_len(field, arr.len())?;
    arr.iter()
        .map(|v| {
            let n = v
                .as_u64()
                .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("{field}: not u8")))?;
            u8::try_from(n).map_err(|_| {
                err(
                    StatusCode::BAD_REQUEST,
                    &format!("{field}: value {n} exceeds u8 range"),
                )
            })
        })
        .collect()
}

#[cfg(feature = "prover")]
fn parse_fr_2d_array(
    v: &serde_json::Value,
    field: &str,
) -> Result<Vec<Vec<ark_bn254::Fr>>, ApiError> {
    let arr = v
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, &format!("missing witness.{field}")))?;
    check_witness_array_len(field, arr.len())?;
    arr.iter()
        .enumerate()
        .map(|(i, row)| {
            let row_arr = row.as_array().ok_or_else(|| {
                err(
                    StatusCode::BAD_REQUEST,
                    &format!("{field}[{i}]: expected array"),
                )
            })?;
            check_witness_array_len(&format!("{field}[{i}]"), row_arr.len())?;
            row_arr
                .iter()
                .enumerate()
                .map(|(j, val)| {
                    parse_fr(val.as_str().ok_or_else(|| {
                        err(
                            StatusCode::BAD_REQUEST,
                            &format!("{field}[{i}][{j}]: not string"),
                        )
                    })?)
                    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("{field}[{i}][{j}]: {e}")))
                })
                .collect()
        })
        .collect()
}

// ── Router ───────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    let r = Router::new().route("/zk/verify", post(verify));
    #[cfg(feature = "prover")]
    let r = r.route("/zk/prove", post(prove));
    r
}

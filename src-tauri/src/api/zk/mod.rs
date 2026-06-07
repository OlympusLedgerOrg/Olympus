//! ZK Groth16 prove + verify HTTP routes.
//!
//! POST /zk/verify  — verify a Groth16 proof against embedded vkeys
//! POST /zk/prove   — generate a Groth16 proof from witness data
//!
//! The witness JSON → typed-witness parsers used by `/zk/prove` live in the
//! `parse` submodule (gated behind the `prover` feature alongside the prove
//! handler) so the bounds-checking logic can be unit-tested in isolation.

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::proof::parse_signals_slice;
use crate::zk::verify::{
    existence_verifier, non_existence_verifier, redaction_verifier, unified_verifier,
};

#[cfg(feature = "prover")]
mod parse;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": detail })))
}

/// Audit H-2 wrapper: thin adapter from the shared
/// `zk::verify::enforce_empty_tree_invariant` (red-team F-RT-1 made the
/// shared helper necessary so the federation receive path enforces the
/// same invariant the HTTP `/zk/verify` route does). Wraps the helper's
/// `String` error in this module's `ApiError` shape with the right
/// status code: `BAD_REQUEST` for the caller-shape errors, the parse
/// failure stays `INTERNAL_SERVER_ERROR` to match the prior contract on
/// the empty-tree-root resolve step.
fn enforce_empty_tree_invariant(
    signals: &[ark_bn254::Fr],
    root_idx: usize,
    tree_size_idx: usize,
) -> Result<(), ApiError> {
    crate::zk::verify::enforce_empty_tree_invariant(signals, root_idx, tree_size_idx).map_err(|e| {
        // The "empty-tree root resolve: …" branch is the only
        // server-internal failure path; everything else is
        // caller-shape and maps to 400.
        let status = if e.starts_with("empty-tree root resolve") {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::BAD_REQUEST
        };
        err(status, &e)
    })
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
    State(state): State<AppState>,
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
    // Snapshot the trusted-issuer set for the closure. Cheap clone — typical
    // sets are 1–3 entries, each ~80 bytes of pre-canonicalised metadata.
    let trusted_issuers = state.bjj_trusted_issuers.clone();

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
            "redaction_validity" => {
                let pairing_valid = redaction_verifier()
                    .map_err(|e| {
                        err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("verifier init: {e}"),
                        )
                    })?
                    .verify(&proof_json, &signals)
                    .map_err(|e| err(StatusCode::BAD_REQUEST, &format!("verify: {e}")))?;

                // Trust-anchor the issuer pubkey (audit M-2 follow-up).
                //
                // Post-M-2 redaction proofs declare `issuerAx`/`issuerAy` as
                // public inputs at signal indices 4 and 5. The in-circuit
                // EdDSAPoseidonVerifier proves the issuer signed the
                // nullifier digest under THAT pubkey — but says nothing
                // about whether that pubkey is one we trust. Without this
                // check, a self-signed proof from any BJJ keypair would
                // verify identically to a proof signed by the configured
                // authority.
                //
                // Pre-M-2 bundles (4 signals total) lack the issuer pubkey
                // entirely; for those we have to fall back to "math only"
                // and log a warning. Those bundles are historical only —
                // current code paths always emit 6 signals.
                if pairing_valid && signals.len() >= 6 {
                    // Empty trusted-issuer set is a server misconfiguration,
                    // not a bundle problem — fail-closed with 503 so the
                    // caller can distinguish "your proof is rejected" (400)
                    // from "this server cannot anchor anyone" (503).
                    if trusted_issuers.is_empty() {
                        return Err(err(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "verify: trusted-issuer set is empty on this server — \
                             cannot trust-anchor any redaction proof. Configure \
                             OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON or ensure the \
                             bootstrap BJJ key is loaded.",
                        ));
                    }
                    let issuer_x = &signals[4];
                    let issuer_y = &signals[5];
                    // Audit ZK M-1: match the pubkey AND honor the issuer's
                    // validity window. `TrustedIssuer` carries
                    // `valid_from`/`valid_until` precisely to support key
                    // rotation; the ceremony-manifest coordinator check
                    // already gates on `covers(...)`, but this path did not,
                    // so a key that had been time-windowed out (e.g. rotated
                    // and retired, but still listed for historical reasons)
                    // would still verify as `valid: true`. Anchor against the
                    // current time — a redaction proof is only acceptable if
                    // signed by a key that is trusted *now*.
                    let now_unix = chrono::Utc::now().timestamp();
                    let trusted = trusted_issuers.iter().any(|t| {
                        &t.pubkey.x == issuer_x
                            && &t.pubkey.y == issuer_y
                            && t.covers(now_unix)
                    });
                    if !trusted {
                        return Err(err(
                            StatusCode::BAD_REQUEST,
                            "verify: redaction proof's issuer pubkey (issuerAx, issuerAy) \
                             is not in the trusted-issuer set or its validity window does \
                             not cover the current time — refusing to accept. Add the \
                             issuer to OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON (with an \
                             appropriate valid_from/valid_until) if the pubkey is \
                             authorised.",
                        ));
                    }
                } else if pairing_valid && signals.len() < 6 {
                    // Audit (red-team): fail closed. A redaction proof carrying
                    // fewer than 6 public signals predates the M-2 layout and
                    // has no issuer pubkey (issuerAx/issuerAy at indices 4/5) to
                    // trust-anchor. Accepting it on "proof-math only" would let a
                    // self-signed proof from ANY Baby Jubjub keypair verify
                    // identically to an authority-signed one — so a non-anchored
                    // proof must never be serialized as `valid: true`. Refuse it.
                    //
                    // Against the current nPublic=6 redaction vkey this branch is
                    // also unreachable (the pairing check rejects a mismatched
                    // public-input count first), but the trust-anchor guarantee
                    // must not rest implicitly on the vkey's input count.
                    return Err(err(
                        StatusCode::BAD_REQUEST,
                        "verify: redaction proof uses the pre-M-2 signal layout \
                         (fewer than 6 public signals) and carries no issuer \
                         pubkey to trust-anchor; refusing. Re-prove under the \
                         current redaction circuit so issuerAx and issuerAy are \
                         bound as public inputs.",
                    ));
                }

                pairing_valid
            }
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
use crate::zk::proof::fr_to_decimal;

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
                let w = parse::parse_existence_witness(&witness_val)?;
                crate::zk::prove::prove_existence(&w, &wasm, &r1cs, &zkey).map_err(prove_err)?
            }
            "non_existence" => {
                let w = parse::parse_non_existence_witness(&witness_val)?;
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
                let w = parse::parse_redaction_witness(&witness_val, &bjj_priv, bjj_pub)?;
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
                let w = parse::parse_unified_witness(&witness_val, &bjj_priv, bjj_pub)?;
                crate::zk::prove::prove_unified(&w, &wasm, &r1cs, &zkey).map_err(prove_err)?
            }
            _ => unreachable!(),
        };

        let signals_str: Vec<String> = public_signals.iter().map(fr_to_decimal).collect();

        Ok(ProveResponse {
            circuit: circuit_name,
            proof: crate::zk::proof::proof_to_snarkjs_json(&proof),
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

// ── Router ───────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    let r = Router::new().route("/zk/verify", post(verify));
    #[cfg(feature = "prover")]
    let r = r.route("/zk/prove", post(prove));
    r
}

/// Verify-only subset safe to expose over the federation Tor onion service.
/// Excludes `/zk/prove` — proving is heavy and authority-bound, never a
/// remotely reachable surface.
#[cfg(feature = "federation")]
pub fn public_router() -> Router<AppState> {
    Router::new().route("/zk/verify", post(verify))
}

//! ZK Groth16 prove + verify HTTP routes.
//!
//! POST /zk/verify  — verify a Groth16 proof against embedded vkeys
//! POST /zk/prove   — generate a Groth16 proof from witness data
//!
//! The witness JSON → typed-witness parsers used by `/zk/prove` live in the
//! `parse` submodule (gated behind the `prover` feature alongside the prove
//! handler) so the bounds-checking logic can be unit-tested in isolation.

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::proof::parse_signals_slice;
use crate::zk::verify::{existence_verifier, non_existence_verifier, unified_verifier};

#[cfg(feature = "federation")]
const MAX_CONCURRENT_PUBLIC_VERIFICATIONS: usize = 4;
#[cfg(feature = "federation")]
static PUBLIC_VERIFY_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_PUBLIC_VERIFICATIONS);

#[cfg(feature = "prover")]
mod parse;

type ApiError = (StatusCode, Json<serde_json::Value>);

// A 16 MiB serialized receipt expands to about 21.4 MiB in base64. Keep this
// route below the server-wide body cap so JSON extraction cannot allocate the
// full global allowance before receipt-specific checks run.
const VERIFY_BODY_LIMIT: usize = 24 * 1024 * 1024;
const MAX_CIRCUIT_ID_BYTES: usize = 64;
const MAX_PROOF_JSON_BYTES: usize = 64 * 1024;
const MAX_PUBLIC_SIGNALS: usize = 5;
const MAX_FIELD_DECIMAL_BYTES: usize = 77;
const MAX_SOURCE_COMMITMENT_BYTES: usize = 64;
const MAX_CANONICALIZATION_RECEIPT_BASE64_BYTES: usize =
    olympus_crypto::canonical_proof::MAX_CANONICAL_RECEIPT_BYTES.div_ceil(3) * 4;
const CANONICALIZATION_VERIFY_QUEUE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);
static CANONICALIZATION_VERIFY_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(2);

#[cfg(all(feature = "prover", feature = "zkvm-prover"))]
const CANONICALIZATION_PROVE_QUEUE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(120);
#[cfg(all(feature = "prover", feature = "zkvm-prover"))]
static CANONICALIZATION_PROVE_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(1);

/// Historical false claim retained only to return a precise 410 response.
const RETIRED_UNIFIED_CANONICALIZATION_ID: &str = "unified_canonicalization_inclusion_root_sign";
/// Combined protocol: a RISC Zero receipt proves the exact Rust
/// JCS/NFC/decimal canonicalizer ran, and the existing Groth16 proof binds the
/// receipt's section commitment into Merkle/SMT roots.
const UNIFIED_CANONICALIZATION_ID: &str = "unified_canonicalization_inclusion_root";
const UNIFIED_SECTION_COMMITMENT_ID: &str = "unified_section_commitment_inclusion_root";

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": detail })))
}

fn retired_unified_canonicalization_error() -> ApiError {
    err(
        StatusCode::GONE,
        "unified_canonicalization_inclusion_root_sign is retired: no circuit verifies a \
         checkpoint signature. Use unified_canonicalization_inclusion_root with a verified \
         canonicalizationReceipt and sourceCommitment.",
    )
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
    /// Required for the combined canonicalization protocol; ignored by the
    /// standalone Groth16 circuits.
    #[serde(default)]
    canonicalization_receipt: Option<String>,
    /// Canonical lowercase hex commitment to the private source bytes. The
    /// combined verifier requires it so a valid receipt for some unrelated
    /// private JSON cannot satisfy the caller's statement.
    #[serde(default)]
    source_commitment: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyResponse {
    valid: bool,
    circuit: String,
}

fn ensure_bounded(field: &'static str, actual: usize, maximum: usize) -> Result<(), ApiError> {
    if actual > maximum {
        return Err(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("{field} exceeds its verification limit"),
        ));
    }
    Ok(())
}

fn expected_public_signal_count(circuit: &str) -> Result<usize, ApiError> {
    match circuit {
        "document_existence" => Ok(3),
        "non_existence" => Ok(2),
        UNIFIED_CANONICALIZATION_ID | UNIFIED_SECTION_COMMITMENT_ID => Ok(5),
        RETIRED_UNIFIED_CANONICALIZATION_ID => Err(retired_unified_canonicalization_error()),
        _ => Err(err(StatusCode::BAD_REQUEST, "unknown circuit identifier")),
    }
}

/// Reject malformed or resource-heavy verification requests before acquiring a
/// native-verifier permit or dispatching a blocking worker.
fn validate_verify_request(req: &VerifyRequest) -> Result<(), ApiError> {
    if req.circuit.is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "circuit identifier must not be empty",
        ));
    }
    ensure_bounded(
        "circuit identifier",
        req.circuit.len(),
        MAX_CIRCUIT_ID_BYTES,
    )?;
    let expected_signals = expected_public_signal_count(&req.circuit)?;

    ensure_bounded("proofJson", req.proof_json.len(), MAX_PROOF_JSON_BYTES)?;
    ensure_bounded(
        "publicSignals",
        req.public_signals.len(),
        MAX_PUBLIC_SIGNALS,
    )?;
    if req.public_signals.len() != expected_signals {
        return Err(err(
            StatusCode::BAD_REQUEST,
            &format!("circuit requires exactly {expected_signals} public signals"),
        ));
    }
    for signal in &req.public_signals {
        ensure_bounded("public signal", signal.len(), MAX_FIELD_DECIMAL_BYTES)?;
    }

    if let Some(receipt) = &req.canonicalization_receipt {
        ensure_bounded(
            "canonicalizationReceipt",
            receipt.len(),
            MAX_CANONICALIZATION_RECEIPT_BASE64_BYTES,
        )?;
    }
    if let Some(commitment) = &req.source_commitment {
        ensure_bounded(
            "sourceCommitment",
            commitment.len(),
            MAX_SOURCE_COMMITMENT_BYTES,
        )?;
    }
    if req.circuit == UNIFIED_CANONICALIZATION_ID {
        if req.canonicalization_receipt.is_none() {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "canonicalizationReceipt is required for the combined circuit",
            ));
        }
        if req.source_commitment.is_none() {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "sourceCommitment is required for the combined circuit",
            ));
        }
    }
    Ok(())
}

async fn verify(
    State(_state): State<AppState>,
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
    verify_request(req, None).await
}

/// Tor/public verification variant. It exposes only deterministic proof
/// checking and carries the same rate limit and timeout as the authenticated
/// local route; no node secret or mutable state is involved.
#[cfg(feature = "federation")]
async fn verify_public(
    State(_state): State<AppState>,
    _rl: RateLimit,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let permit = PUBLIC_VERIFY_PERMITS.acquire().await.map_err(|_| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Public verification is unavailable.",
        )
    })?;
    verify_request(req, Some(permit)).await
}

async fn verify_request(
    req: VerifyRequest,
    public_permit: Option<tokio::sync::SemaphorePermit<'static>>,
) -> Result<Json<VerifyResponse>, ApiError> {
    validate_verify_request(&req)?;
    let VerifyRequest {
        circuit,
        proof_json,
        public_signals: signals_raw,
        canonicalization_receipt,
        source_commitment,
    } = req;

    let canonicalization_permit = if circuit == UNIFIED_CANONICALIZATION_ID {
        Some(
            tokio::time::timeout(
                CANONICALIZATION_VERIFY_QUEUE_TIMEOUT,
                CANONICALIZATION_VERIFY_PERMITS.acquire(),
            )
            .await
            .map_err(|_| {
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "canonicalization verifier queue exceeded its 30s budget",
                )
            })?
            .map_err(|_| {
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "canonicalization verifier is unavailable",
                )
            })?,
        )
    } else {
        None
    };

    let result = tokio::task::spawn_blocking(move || {
        // Keep both permits in the blocking worker. Dropping the async
        // JoinHandle (for example when the Tor request timeout expires) cannot
        // release either permit while proof verification is still consuming
        // CPU.
        let _public_permit = public_permit;
        let _canonicalization_permit = canonicalization_permit;
        let signals = parse_signals_slice(&signals_raw)
            .map_err(|_| err(StatusCode::BAD_REQUEST, "public signal encoding is invalid"))?;

        let valid = match circuit.as_str() {
            "document_existence" => {
                // Audit H-2: the circuit's `leafIndex < treeSize` bounds
                // check is disabled when `treeSize == 0`. The circuit's
                // own docstring says off-chain verifiers MUST reject
                // `treeSize == 0` unless `root` is the empty-tree root.
                // Public signal order: [root, leafIndex, treeSize].
                enforce_empty_tree_invariant(&signals, 0, 2)?;
                existence_verifier()
                    .map_err(|_| {
                        err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "verification key is unavailable",
                        )
                    })?
                    .verify(&proof_json, &signals)
                    .map_err(|_| err(StatusCode::BAD_REQUEST, "proof encoding is invalid"))?
            }
            "non_existence" => non_existence_verifier()
                .map_err(|_| {
                    err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "verification key is unavailable",
                    )
                })?
                .verify(&proof_json, &signals)
                .map_err(|_| err(StatusCode::BAD_REQUEST, "proof encoding is invalid"))?,
            RETIRED_UNIFIED_CANONICALIZATION_ID => {
                return Err(retired_unified_canonicalization_error())
            }
            UNIFIED_CANONICALIZATION_ID => {
                // Combined proof order is security-critical: authenticate the
                // zkVM receipt and bind its derived commitment to public signal
                // 0 before accepting the Groth16 inclusion proof.
                if signals.len() != 5 {
                    return Err(err(
                        StatusCode::BAD_REQUEST,
                        "combined circuit requires exactly 5 public signals",
                    ));
                }
                enforce_empty_tree_invariant(&signals, 1, 3)?;
                let receipt = canonicalization_receipt.as_deref().ok_or_else(|| {
                    err(
                        StatusCode::BAD_REQUEST,
                        "canonicalizationReceipt is required for the combined circuit",
                    )
                })?;
                let expected_source = source_commitment.as_deref().ok_or_else(|| {
                    err(
                        StatusCode::BAD_REQUEST,
                        "sourceCommitment is required for the combined circuit",
                    )
                })?;
                let canonical_hash = *signals.first().ok_or_else(|| {
                    err(
                        StatusCode::BAD_REQUEST,
                        "combined circuit requires canonicalHash public signal",
                    )
                })?;
                let verified =
                    crate::zk::canonicalization::verify_receipt_binding(receipt, canonical_hash)
                        .map_err(map_canonicalization_receipt_error)?;
                verify_source_commitment(expected_source, &verified.claim.source_commitment)?;
                unified_verifier()
                    .map_err(|_| {
                        err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "verification key is unavailable",
                        )
                    })?
                    .verify(&proof_json, &signals)
                    .map_err(|_| err(StatusCode::BAD_REQUEST, "proof encoding is invalid"))?
            }
            UNIFIED_SECTION_COMMITMENT_ID => {
                // Same H-2 invariant: signal order
                // [canonicalHash, merkleRoot, ledgerRoot, treeSize, ledgerKeyHash].
                // The bounds check inside the unified circuit is gated on
                // merkleRoot's tree, so we enforce against `merkleRoot`
                // (index 1) and treeSize (index 3).
                enforce_empty_tree_invariant(&signals, 1, 3)?;
                unified_verifier()
                    .map_err(|_| {
                        err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "verification key is unavailable",
                        )
                    })?
                    .verify(&proof_json, &signals)
                    .map_err(|_| err(StatusCode::BAD_REQUEST, "proof encoding is invalid"))?
            }
            _ => return Err(err(StatusCode::BAD_REQUEST, "unknown circuit identifier")),
        };

        Ok(VerifyResponse { valid, circuit })
    })
    .await
    .map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "verification worker failed",
        )
    })?;

    result.map(Json)
}

fn map_canonicalization_receipt_error(
    error: crate::zk::canonicalization::CanonicalizationReceiptError,
) -> ApiError {
    use crate::zk::canonicalization::CanonicalizationReceiptError;

    let status = match error {
        CanonicalizationReceiptError::PlaceholderArtifact
        | CanonicalizationReceiptError::InvalidGuestImage(_)
        | CanonicalizationReceiptError::GuestImageIdMismatch
        | CanonicalizationReceiptError::Poseidon(_) => StatusCode::SERVICE_UNAVAILABLE,
        CanonicalizationReceiptError::ReceiptTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        #[cfg(feature = "zkvm-prover")]
        CanonicalizationReceiptError::Proving(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    err(status, &format!("canonicalization receipt: {error}"))
}

fn verify_source_commitment(expected_hex: &str, actual: &[u8; 32]) -> Result<(), ApiError> {
    if expected_hex.len() != 64
        || !expected_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "sourceCommitment must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    let decoded = hex::decode(expected_hex).map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "sourceCommitment must be exactly 64 lowercase hexadecimal characters",
        )
    })?;
    if decoded.as_slice() != actual {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "sourceCommitment does not match the canonicalization receipt",
        ));
    }
    Ok(())
}

#[cfg(all(feature = "prover", feature = "zkvm-prover"))]
fn decode_canonicalization_source(witness: &serde_json::Value) -> Result<Vec<u8>, ApiError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use olympus_crypto::canonical_proof::MAX_CANONICAL_SOURCE_BYTES;

    let encoded = witness
        .get("sourceDocumentBase64")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "missing witness.sourceDocumentBase64 for canonicalization proof",
            )
        })?;
    let max_encoded = MAX_CANONICAL_SOURCE_BYTES.div_ceil(3) * 4;
    if encoded.len() > max_encoded {
        return Err(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "witness.sourceDocumentBase64 exceeds the canonicalization proof limit",
        ));
    }
    let source = BASE64.decode(encoded).map_err(|error| {
        err(
            StatusCode::BAD_REQUEST,
            &format!("witness.sourceDocumentBase64: {error}"),
        )
    })?;
    if source.len() > MAX_CANONICAL_SOURCE_BYTES {
        return Err(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "source document exceeds the canonicalization proof limit",
        ));
    }
    if BASE64.encode(&source) != encoded {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "witness.sourceDocumentBase64 is not canonical base64",
        ));
    }
    Ok(source)
}

#[cfg(all(feature = "prover", feature = "zkvm-prover"))]
fn inject_canonicalization_witness(
    witness: &mut serde_json::Value,
    verified: &crate::zk::canonicalization::VerifiedCanonicalization,
) -> Result<(), ApiError> {
    let object = witness.as_object_mut().ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "witness must be an object for canonicalization proof",
        )
    })?;
    object.insert(
        "canonicalHash".to_owned(),
        serde_json::Value::String(crate::zk::proof::fr_to_decimal(&verified.canonical_hash)),
    );
    object.insert(
        "documentSections".to_owned(),
        serde_json::Value::Array(
            verified
                .document_sections
                .iter()
                .map(|value| serde_json::Value::String(crate::zk::proof::fr_to_decimal(value)))
                .collect(),
        ),
    );
    object.insert("sectionCount".to_owned(), serde_json::Value::from(1u8));
    let mut section_lengths = vec![0u32; crate::zk::witness::unified::MAX_SECTIONS];
    section_lengths[0] = verified.claim.canonical_len as u32;
    object.insert(
        "sectionLengths".to_owned(),
        serde_json::Value::Array(
            section_lengths
                .iter()
                .copied()
                .map(serde_json::Value::from)
                .collect(),
        ),
    );
    object.insert(
        "sectionHashes".to_owned(),
        serde_json::Value::Array(
            verified
                .section_hashes
                .iter()
                .map(|value| serde_json::Value::String(crate::zk::proof::fr_to_decimal(value)))
                .collect(),
        ),
    );
    Ok(())
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
    #[serde(skip_serializing_if = "Option::is_none")]
    canonicalization_receipt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_commitment: Option<String>,
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
    let is_prod = crate::env::is_production();
    let keys_dir = match req.keys_dir.as_deref() {
        Some(p) if !is_prod => std::path::PathBuf::from(p),
        _ => state
            .proofs_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("proofs/keys")),
    };

    let circuit_name = req.circuit.clone();
    let witness_val = req.witness.clone();

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

    // RISC Zero proving is materially heavier than the existing Groth16
    // witness path. Queue at most one local canonicalization proof at a time,
    // and move the permit into the blocking worker so an HTTP timeout cannot
    // release it while the native prover is still running.
    #[cfg(feature = "zkvm-prover")]
    let zkvm_permit = if circuit_name == UNIFIED_CANONICALIZATION_ID {
        Some(
            tokio::time::timeout(
                CANONICALIZATION_PROVE_QUEUE_TIMEOUT,
                CANONICALIZATION_PROVE_PERMITS.acquire(),
            )
            .await
            .map_err(|_| {
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "canonicalization prover queue exceeded its 120s budget",
                )
            })?
            .map_err(|_| {
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "canonicalization prover is unavailable",
                )
            })?,
        )
    } else {
        None
    };

    let join_handle = tokio::task::spawn_blocking(move || {
        use crate::zk::Circuit;

        let circuit = match circuit_name.as_str() {
            "document_existence" => Circuit::DocumentExistence,
            "non_existence" => Circuit::NonExistence,
            RETIRED_UNIFIED_CANONICALIZATION_ID => {
                return Err(retired_unified_canonicalization_error())
            }
            UNIFIED_CANONICALIZATION_ID | UNIFIED_SECTION_COMMITMENT_ID => {
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

        let (proof, public_signals, canonicalization_output): (_, _, Option<(String, String)>) =
            match circuit_name.as_str() {
                "document_existence" => {
                    let w = parse::parse_existence_witness(&witness_val)?;
                    let output = crate::zk::prove::prove_existence(&w, &wasm, &r1cs, &zkey)
                        .map_err(prove_err)?;
                    (output.0, output.1, None)
                }
                "non_existence" => {
                    let w = parse::parse_non_existence_witness(&witness_val)?;
                    let output = crate::zk::prove::prove_non_existence(&w, &wasm, &r1cs, &zkey)
                        .map_err(prove_err)?;
                    (output.0, output.1, None)
                }
                UNIFIED_SECTION_COMMITMENT_ID => {
                    let w = parse::parse_unified_witness(&witness_val)?;
                    enforce_empty_tree_invariant(&w.public_signals(), 1, 3)?;
                    let output = crate::zk::prove::prove_unified(&w, &wasm, &r1cs, &zkey)
                        .map_err(prove_err)?;
                    (output.0, output.1, None)
                }
                UNIFIED_CANONICALIZATION_ID => {
                    #[cfg(not(feature = "zkvm-prover"))]
                    {
                        return Err(err(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "local canonicalization proving requires a Linux/WSL2 build with the \
                         zkvm-prover feature; native Windows verification remains available",
                        ));
                    }
                    #[cfg(feature = "zkvm-prover")]
                    {
                        let source = decode_canonicalization_source(&witness_val)?;

                        // Reject malformed source and inconsistent inclusion paths
                        // before starting the expensive zkVM prover. This native
                        // claim is only a pre-check; the response is still derived
                        // from, and accepted only with, a verified receipt.
                        let native_claim =
                            olympus_crypto::canonical_proof::canonicalization_claim(&source)
                                .map_err(|error| {
                                    use olympus_crypto::canonical_proof::{
                                        CanonicalClaimError, ProveCanonicalizationError,
                                    };

                                    let status = match &error {
                                        ProveCanonicalizationError::Claim(
                                            CanonicalClaimError::SourceTooLarge(_)
                                            | CanonicalClaimError::CanonicalTooLarge(_),
                                        ) => StatusCode::PAYLOAD_TOO_LARGE,
                                        _ => StatusCode::BAD_REQUEST,
                                    };
                                    err(status, &format!("canonicalization source: {error}"))
                                })?;
                        let native_verified =
                            crate::zk::canonicalization::verified_from_claim(native_claim)
                                .map_err(|error| {
                                    err(
                                        StatusCode::SERVICE_UNAVAILABLE,
                                        &format!("canonicalization commitment: {error}"),
                                    )
                                })?;
                        let mut derived_witness = witness_val.clone();
                        inject_canonicalization_witness(&mut derived_witness, &native_verified)?;

                        let w = parse::parse_unified_witness(&derived_witness)?;
                        w.verify_inputs().map_err(|error| {
                            err(
                                StatusCode::BAD_REQUEST,
                                &format!("unified witness pre-check: {error}"),
                            )
                        })?;
                        enforce_empty_tree_invariant(&w.public_signals(), 1, 3)?;

                        let prover_permit = zkvm_permit.ok_or_else(|| {
                            err(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "canonicalization prover permit was not acquired",
                            )
                        })?;
                        let (receipt, verified) =
                            crate::zk::canonicalization::prove_source_base64(&source)
                                .map_err(map_canonicalization_receipt_error)?;
                        drop(prover_permit);
                        if verified.claim != native_verified.claim {
                            return Err(err(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "canonicalization guest journal disagrees with the host pre-check",
                            ));
                        }

                        let output = crate::zk::prove::prove_unified(&w, &wasm, &r1cs, &zkey)
                            .map_err(prove_err)?;
                        (
                            output.0,
                            output.1,
                            Some((receipt, hex::encode(verified.claim.source_commitment))),
                        )
                    }
                }
                _ => unreachable!(),
            };

        let signals_str: Vec<String> = public_signals.iter().map(fr_to_decimal).collect();

        Ok(ProveResponse {
            circuit: circuit_name,
            proof: crate::zk::proof::proof_to_snarkjs_json(&proof),
            public_signals: signals_str,
            canonicalization_receipt: canonicalization_output
                .as_ref()
                .map(|(receipt, _)| receipt.clone()),
            source_commitment: canonicalization_output.map(|(_, commitment)| commitment),
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
    let r = Router::new().route(
        "/zk/verify",
        post(verify).layer(DefaultBodyLimit::max(VERIFY_BODY_LIMIT)),
    );
    #[cfg(feature = "prover")]
    let r = r.route("/zk/prove", post(prove));
    r
}

/// Verify-only subset safe to expose over the federation Tor onion service.
/// Excludes `/zk/prove` because local proving is deliberately not a remotely
/// reachable resource-intensive surface.
#[cfg(feature = "federation")]
pub fn public_router() -> Router<AppState> {
    Router::new().route(
        "/zk/verify",
        post(verify_public).layer(DefaultBodyLimit::max(VERIFY_BODY_LIMIT)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verification_request(circuit: &str, signal_count: usize) -> VerifyRequest {
        VerifyRequest {
            circuit: circuit.to_owned(),
            proof_json: "{}".to_owned(),
            public_signals: vec!["0".to_owned(); signal_count],
            canonicalization_receipt: None,
            source_commitment: None,
        }
    }

    fn api_error_detail(error: &ApiError) -> &str {
        error
            .1
             .0
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("API error detail")
    }

    #[test]
    fn verify_preflight_enforces_circuit_specific_signal_arity() {
        for (circuit, count) in [
            ("document_existence", 3),
            ("non_existence", 2),
            (UNIFIED_SECTION_COMMITMENT_ID, 5),
        ] {
            assert!(validate_verify_request(&verification_request(circuit, count)).is_ok());
            let error = validate_verify_request(&verification_request(circuit, count - 1))
                .expect_err("wrong arity must fail before dispatch");
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn verify_preflight_rejects_oversized_fields_before_dispatch() {
        let mut request = verification_request("document_existence", 3);
        request.proof_json = "x".repeat(MAX_PROOF_JSON_BYTES + 1);
        assert_eq!(
            validate_verify_request(&request).unwrap_err().0,
            StatusCode::PAYLOAD_TOO_LARGE
        );

        let mut request = verification_request("document_existence", 3);
        request.public_signals[0] = "9".repeat(MAX_FIELD_DECIMAL_BYTES + 1);
        assert_eq!(
            validate_verify_request(&request).unwrap_err().0,
            StatusCode::PAYLOAD_TOO_LARGE
        );

        assert!(ensure_bounded(
            "canonicalizationReceipt",
            MAX_CANONICALIZATION_RECEIPT_BASE64_BYTES + 1,
            MAX_CANONICALIZATION_RECEIPT_BASE64_BYTES,
        )
        .is_err());
    }

    #[test]
    fn verify_preflight_does_not_reflect_unknown_circuit_input() {
        let marker = "attacker-controlled-circuit-marker";
        let error = validate_verify_request(&verification_request(marker, 0))
            .expect_err("unknown circuit must fail");
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(!api_error_detail(&error).contains(marker));
    }

    #[test]
    fn source_commitment_requires_exact_lowercase_hex_and_value() {
        let actual = [0xabu8; 32];
        let expected = hex::encode(actual);
        assert!(verify_source_commitment(&expected, &actual).is_ok());
        assert!(verify_source_commitment(&expected.to_uppercase(), &actual).is_err());
        assert!(verify_source_commitment(&expected[..62], &actual).is_err());
        assert!(verify_source_commitment(&"00".repeat(32), &actual).is_err());
    }

    #[tokio::test]
    async fn combined_verification_rejects_signal_count_before_dispatch() {
        let request = VerifyRequest {
            circuit: UNIFIED_CANONICALIZATION_ID.to_owned(),
            proof_json: "{}".to_owned(),
            public_signals: Vec::new(),
            canonicalization_receipt: None,
            source_commitment: None,
        };
        assert!(matches!(
            verify_request(request, None).await,
            Err((StatusCode::BAD_REQUEST, _))
        ));
    }

    #[cfg(all(feature = "prover", feature = "zkvm-prover"))]
    #[test]
    fn source_document_base64_is_bounded_and_canonical() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

        let witness = serde_json::json!({ "sourceDocumentBase64": BASE64.encode(b"{}") });
        assert_eq!(decode_canonicalization_source(&witness).unwrap(), b"{}");

        let noncanonical = serde_json::json!({ "sourceDocumentBase64": "e30" });
        assert!(decode_canonicalization_source(&noncanonical).is_err());
    }
}

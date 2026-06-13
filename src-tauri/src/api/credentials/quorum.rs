//! Quorum-issuance support: signer-set assembly, local + peer co-signature
//! collection, and the (best-effort, feature-gated) Groth16 quorum proof.
//! Pure code-motion from `credentials/mod.rs` — digest construction lives in
//! `crate::quorum` and is untouched.

use axum::http::StatusCode;

use crate::quorum::{self, CollectedSignature, QuorumSigner, QuorumStatus};
use crate::state::AppState;
use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey};

use super::crypto::fr_to_decimal;
use super::{db_err, err, ApiError};

/// Everything a quorum issuance produces, threaded back into the INSERT and
/// the post-insert signature persistence.
pub(super) struct QuorumBuilt {
    pub(super) threshold: i32,
    pub(super) signers_json: serde_json::Value,
    pub(super) collected: Vec<CollectedSignature>,
    pub(super) status: QuorumStatus,
    pub(super) proof: Option<serde_json::Value>,
    pub(super) proof_signals: Option<serde_json::Value>,
}

/// Assemble the pinned signer set, gather the local + peer co-signatures, and
/// (best-effort) build the ZK quorum proof. Returns a 409 if the quorum can't
/// be reached, or a 422 if the requested threshold exceeds the signer set.
#[allow(clippy::too_many_arguments)]
pub(super) async fn build_quorum(
    state: &AppState,
    pool: &sqlx::PgPool,
    bjj_key: &[u8; 32],
    bjj_pubkey: &BabyJubJubPubKey,
    commit_id_bytes: &[u8; 32],
    threshold_req: Option<u32>,
    holder_key: &str,
    credential_type: &str,
    issued_at_unix: i64,
    details_for_cosign: Option<&serde_json::Value>,
    commitment_for_cosign: Option<(&str, &str)>,
) -> Result<QuorumBuilt, ApiError> {
    let authority_signer = QuorumSigner {
        x: fr_to_decimal(&bjj_pubkey.x),
        y: fr_to_decimal(&bjj_pubkey.y),
    };

    // Pinned signer set N = authority + trusted peers (federation builds), or
    // just the authority (vanilla build — only threshold 1 is reachable).
    #[cfg(feature = "federation")]
    let pinned = quorum::trusted_signer_set(pool, bjj_pubkey)
        .await
        .map_err(db_err)?;
    #[cfg(not(feature = "federation"))]
    let pinned = vec![authority_signer.clone()];

    let threshold = threshold_req
        .unwrap_or_else(quorum::configured_threshold)
        .max(1);
    // Redteam follow-up: a "quorum" credential with threshold 1 is satisfiable
    // by the issuing node alone. That is legitimate and unavoidable in a vanilla
    // (non-federation) build where the pinned set is just the authority key, but
    // when a real multi-signer set IS pinned, threshold 1 is almost certainly a
    // misconfiguration (unset OLYMPUS_FEDERATION_QUORUM_THRESHOLD / omitted
    // per-request threshold) silently degrading the quorum to single-signer.
    // Surface it loudly rather than failing closed, so the legitimate M=1 case
    // (and the vanilla build) keep working while the footgun stops being silent.
    if pinned.len() > 1 && threshold == 1 {
        tracing::warn!(
            credential_type = %credential_type,
            pinned_signers = pinned.len(),
            "issuing a QUORUM credential with threshold=1 over a {}-signer set — \
             the issuing node alone satisfies it; set {} (or pass an explicit \
             quorum_threshold >= 2) for a genuine multi-party quorum",
            pinned.len(),
            quorum::QUORUM_THRESHOLD_ENV,
        );
    }
    if threshold as usize > pinned.len() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "quorum_threshold {threshold} exceeds the pinned signer-set size {} \
                 (authority + trusted peers); register more peers or lower the threshold",
                pinned.len()
            ),
        ));
    }

    // The issuing node's own quorum signature is always one of the signers.
    // The message binds threshold + the pinned set so neither can be altered
    // after issuance without invalidating it (audit R3-01).
    let msg = quorum::quorum_cosign_message(commit_id_bytes, threshold as usize, &pinned);
    let local_sig = baby_jubjub::sign(bjj_key, msg).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("BJJ quorum sign: {e}"),
        )
    })?;
    // `mut` is used only in the federation build (peer co-signatures are
    // appended); the vanilla build leaves it as the lone authority signature.
    #[allow(unused_mut)]
    let mut collected = vec![CollectedSignature {
        signer: authority_signer,
        r8x: fr_to_decimal(&local_sig.r8x),
        r8y: fr_to_decimal(&local_sig.r8y),
        s: fr_to_decimal(&local_sig.s),
    }];

    // Collect co-signatures from peers over Tor (federation builds only).
    #[cfg(feature = "federation")]
    {
        let remaining = (threshold as usize).saturating_sub(collected.len());
        if remaining > 0 {
            match crate::federation::cosign::collect_cosignatures(
                state,
                commit_id_bytes,
                holder_key,
                credential_type,
                issued_at_unix,
                details_for_cosign,
                commitment_for_cosign,
                threshold as usize,
                &pinned,
                remaining,
            )
            .await
            {
                Ok(mut remote) => collected.append(&mut remote),
                Err(e) => tracing::warn!("quorum: peer co-sign collection failed: {e}"),
            }
        }
    }
    // Silence unused-variable warnings in the non-federation build (peer
    // collection is the only consumer of these).
    #[cfg(not(feature = "federation"))]
    let _ = (
        pool,
        holder_key,
        credential_type,
        issued_at_unix,
        details_for_cosign,
        commitment_for_cosign,
    );

    let status = quorum::verify_quorum(commit_id_bytes, &pinned, threshold as usize, &collected);
    if !status.satisfied {
        return Err(err(
            StatusCode::CONFLICT,
            &format!(
                "federation quorum not reached: collected {} of {} required signatures \
                 from {} pinned signers",
                status.valid_signatures, status.threshold, status.total_signers
            ),
        ));
    }

    let (proof, proof_signals) = maybe_build_quorum_proof(
        state,
        commit_id_bytes,
        &pinned,
        threshold as u64,
        &collected,
    )
    .await;

    Ok(QuorumBuilt {
        threshold: threshold as i32,
        signers_json: quorum::signers_to_json(&pinned),
        collected,
        status,
        proof,
        proof_signals,
    })
}

/// Best-effort: build a Groth16 `federation_quorum` proof. Returns
/// `(None, None)` whenever the proof can't be produced — set too large for the
/// circuit, `proofs_dir` unset, artifacts still placeholders (pre-ceremony), or
/// any prove error. The explicit signature-set remains the authoritative check;
/// the proof is an optional privacy layer.
///
/// Gated behind `quorum-circuit` (next-phase, ceremony-pending) AND `prover`
/// (the Groth16 prover that pulls in `ark-circom`). The no-op stubs below keep
/// the issuance path identical when either feature is off.
#[cfg(all(feature = "quorum-circuit", feature = "prover"))]
async fn maybe_build_quorum_proof(
    state: &AppState,
    commit_id_bytes: &[u8; 32],
    pinned: &[QuorumSigner],
    threshold: u64,
    collected: &[CollectedSignature],
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    use crate::zk::witness::quorum::QuorumProofWitness;
    use crate::zk::Circuit;

    if pinned.len() > quorum::FEDERATION_QUORUM_N {
        return (None, None);
    }
    let Some(proofs_dir) = state.proofs_dir.clone() else {
        return (None, None);
    };
    let witness =
        match QuorumProofWitness::from_quorum(commit_id_bytes, pinned, threshold, collected) {
            Ok(w) => w,
            Err(e) => {
                tracing::debug!("quorum proof: witness build skipped: {e}");
                return (None, None);
            }
        };

    let circuit = Circuit::FederationQuorum;
    let wasm = circuit.wasm_path(&proofs_dir);
    let r1cs = circuit.r1cs_path(&proofs_dir);
    let zkey = circuit.ark_zkey_path(&proofs_dir);
    // Cheap pre-flight: skip the heavy prove path when artifacts are missing or
    // still placeholder stubs (the trusted-setup ceremony hasn't run).
    for p in [&wasm, &r1cs, &zkey] {
        if !p.exists() || file_is_placeholder(p) {
            return (None, None);
        }
    }

    let signals_for_witness = witness.public_signals();
    let proof_res = tokio::task::spawn_blocking(move || {
        crate::zk::prove::prove_quorum(&witness, &wasm, &r1cs, &zkey)
    })
    .await;

    match proof_res {
        Ok(Ok((proof, _signals))) => {
            let proof_json = crate::zk::proof::proof_to_snarkjs_json(&proof);
            let signals_json = serde_json::Value::Array(
                signals_for_witness
                    .iter()
                    .map(|f| serde_json::Value::String(fr_to_decimal(f)))
                    .collect(),
            );
            (Some(proof_json), Some(signals_json))
        }
        Ok(Err(e)) => {
            tracing::warn!("quorum proof: prove_quorum failed: {e}");
            (None, None)
        }
        Err(e) => {
            tracing::warn!("quorum proof: prove join failed: {e}");
            (None, None)
        }
    }
}

/// No-op stub when `quorum-circuit` is on but the `prover` feature is off:
/// without the in-process Groth16 prover there is no prove path, so the ZK
/// attestation is simply skipped. The explicit signature set remains
/// authoritative, so quorum credentials still issue and verify.
#[cfg(all(feature = "quorum-circuit", not(feature = "prover")))]
async fn maybe_build_quorum_proof(
    _state: &AppState,
    _commit_id_bytes: &[u8; 32],
    _pinned: &[QuorumSigner],
    _threshold: u64,
    _collected: &[CollectedSignature],
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    (None, None)
}

/// No-op stub when the `quorum-circuit` feature is off: quorum credentials
/// still issue/verify via the explicit signature set, just without the
/// (next-phase) ZK attestation.
#[cfg(not(feature = "quorum-circuit"))]
async fn maybe_build_quorum_proof(
    _state: &AppState,
    _commit_id_bytes: &[u8; 32],
    _pinned: &[QuorumSigner],
    _threshold: u64,
    _collected: &[CollectedSignature],
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    (None, None)
}

/// Return true if the file begins with the `PLACEHOLDER` magic that
/// `build.rs` writes for un-built ZK artifacts. Only used by the prover-side
/// quorum proof path.
#[cfg(all(feature = "quorum-circuit", feature = "prover"))]
fn file_is_placeholder(p: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(p) else {
        return false;
    };
    let mut head = [0u8; 11];
    let n = f.read(&mut head).unwrap_or(0);
    n >= 11 && &head[..11] == b"PLACEHOLDER"
}

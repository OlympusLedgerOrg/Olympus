//! Verify-then-store pipeline for inbound peer checkpoints.
//!
//! Audit H-11 / M-5 / H-12 share a root cause: `receive_checkpoint`
//! (push) and `process_received_checkpoint` (pull) each had their own
//! ad-hoc handling that skipped signature verification, ran equivocation
//! detection on unverified data, and silently fell back to the wrong
//! Groth16 verifier on missing artifacts. Centralise the contract here
//! so push and pull both get the same gates in the same order:
//!
//!   1. **BJJ signature must verify** against the peer's pinned pubkey
//!      and a canonical message digest (`Poseidon(ledger_root,
//!      checkpoint_timestamp)`). A missing or invalid signature fails
//!      closed — store nothing, run no equivocation logic.
//!   2. **Groth16 proof must verify** under the **document_existence**
//!      circuit's vkey — the same circuit `build_own_checkpoint` emits.
//!      The historical `.or_else(existence_verifier)` *fallback chain*
//!      (audit H-5) is removed — different circuits have incompatible
//!      public-signal shapes, and silently demoting creates a
//!      verification hole. There is exactly one fixed verifier here, not
//!      a fallback; if its vkey isn't staged the call hard-errors.
//!   3. **Equivocation detection** runs only on verified checkpoints.
//!      The previous code flagged any conflict, then optionally
//!      auto-blocked the peer — letting an attacker who knew a peer's
//!      pubkey-but-not-priv-key push a forged equivocation and get the
//!      peer auto-blocked (audit H-12 / F-3).
//!   4. **Auto-block** still gates on the config flag, but only fires
//!      when (a) the inbound checkpoint verified AND (b) equivocation
//!      was detected. Both must be true. `auto_block_equivocators` also
//!      defaults to `false` now (audit H-12 default change).

use ark_bn254::Fr;
use sqlx::PgPool;
use uuid::Uuid;

use super::checkpoint::{self, PeerCheckpoint};
use super::equivocation;
use super::peer::PeerNode;
use super::FederationConfig;
use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey, BabyJubJubSignature};

/// Reject a checkpoint whose `groth16_proof` field is JSON null (audit
/// H-11 / M-5). Factored out so a unit test can exercise the rejection
/// without spinning up Postgres; the full `verify_and_store` pipeline
/// awaits a workspace-wide pg_embed test harness.
fn reject_null_proof(cp: &super::checkpoint::PeerCheckpoint) -> Result<(), String> {
    if cp.groth16_proof.is_null() {
        return Err("checkpoint has no Groth16 proof (groth16_proof is null) — \
             unattested checkpoints are not accepted (audit H-11/M-5)"
            .to_owned());
    }
    Ok(())
}

/// Outcome of [`verify_and_store`]. Caller can use these flags for
/// metrics / response bodies; the function itself is fail-closed and
/// will Err out on any verification failure before storing.
#[derive(Debug)]
pub struct VerifyOutcome {
    pub checkpoint_id: Uuid,
    /// Always `true` on success — kept in the response shape so a
    /// future "store-as-unverified" mode (e.g. backfill) can flip it
    /// without changing the API.
    pub signature_verified: bool,
    /// `true` iff the Groth16 proof verified under the `document_existence`
    /// circuit. Null proofs are rejected before this point.
    pub proof_verified: bool,
    /// `true` iff this checkpoint conflicts with a previously-stored one
    /// from the same peer at the same timestamp. Only meaningful when
    /// `signature_verified == true`.
    pub equivocation_detected: bool,
    /// Whether the auto-block actually fired. Always implies
    /// `signature_verified && equivocation_detected &&
    /// config.auto_block_equivocators`.
    pub auto_blocked: bool,
}

/// Verify a checkpoint received from `peer` and, only if verification
/// succeeds, persist it + run equivocation detection.
///
/// Used by both the push handler (`api::receive_checkpoint`) and the
/// pull loop (`gossip::process_received_checkpoint`).
pub async fn verify_and_store(
    pool: &PgPool,
    config: &FederationConfig,
    peer: &PeerNode,
    cp: &PeerCheckpoint,
) -> Result<VerifyOutcome, String> {
    // 0. Wire-version gate (audit L-F1). A mismatched version means
    //    either the peer is on an older protocol (whose field semantics
    //    we no longer match exactly) or a forward-compat envelope we
    //    can't safely parse — either way, fail fast with a clear error
    //    rather than silently treating the bytes as the current shape.
    let expected = super::PEER_CHECKPOINT_WIRE_VERSION;
    if cp.wire_version != expected {
        return Err(format!(
            "checkpoint wire_version {} not supported (expected {expected})",
            cp.wire_version
        ));
    }

    // 1. BJJ signature — fail closed on any missing or invalid field.
    verify_checkpoint_signature(peer, cp)?;

    // 2. Groth16 proof. Three cases, two of them fail-closed:
    //    - `Ok(true)`  → verified ✓
    //    - `Ok(false)` → the verifier accepted the proof's shape and
    //                    parsed it, then ran the SNARK check and
    //                    rejected. This is a forged/invalid proof on a
    //                    correctly-signed envelope — never store. Fail
    //                    closed (audit H-11).
    //    - `Err(_)`    → verifier-init or witness-parse error, already
    //                    propagated via `?`.
    //    - `is_null()` → no proof attached. Reject — H-11/M-5 closure:
    //                    a checkpoint without a Groth16 proof is not
    //                    cryptographically attested even if the BJJ
    //                    envelope is valid, so the verify pipeline
    //                    fails closed. Producers must attach a real
    //                    proof; the dual-side fix lives in
    //                    `checkpoint::build_own_checkpoint`, which now
    //                    returns Err rather than emitting an
    //                    unverifiable null-proof envelope.
    //    Verifies against the document_existence circuit — the one the
    //    producer (`build_own_checkpoint`) emits. No fallback chain
    //    (audit H-5: a silent unified→existence demotion verified against
    //    the wrong constraint system); a single fixed verifier instead.
    reject_null_proof(cp)?;
    let cp_clone = cp.clone();
    let ok = tokio::task::spawn_blocking(move || verify_checkpoint_proof(&cp_clone))
        .await
        .map_err(|e| format!("verify join: {e}"))?
        .map_err(|e| format!("Groth16 verify: {e}"))?;
    if !ok {
        return Err("Groth16 proof verification returned false (proof is invalid)".to_owned());
    }
    let proof_verified = true;

    // Steps 3-5 are ATOMIC and per-peer serialized (audit A1-03(a)). The
    // previous code ran equivocation detection in its own committed
    // transaction and THEN stored the row in a separate one. Two concurrent
    // pushes from the same peer with the same timestamp but different roots
    // each detected-before-the-other-stored, so neither saw a conflict and
    // both landed `equivocation_detected = false`. Running detect + store in
    // one transaction, gated by a per-peer transaction-scoped advisory lock,
    // forces those pushes to serialise: the second waits for the first to
    // commit, then sees the now-stored conflicting row.
    let mut tx = pool.begin().await.map_err(|e| format!("begin tx: {e}"))?;

    // Per-peer transaction-scoped advisory lock — released automatically on
    // commit/rollback. `hashtext(peer_id::text)` is a stable i32 key; two
    // verify_and_store calls for the same peer take the same lock and run
    // strictly one-after-another, while different peers don't contend.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(peer.id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("advisory lock: {e}"))?;

    // 3. Equivocation detection (only on verified checkpoints). Runs BEFORE
    //    the store INSERT so it sees prior rows, not itself; broadened to
    //    flag conflicts at the same timestamp OR the same tree_size (audit
    //    A1-03(b)).
    // `&mut *tx` reborrows the transaction as the `&mut PgConnection` these
    // helpers take, leaving `tx` usable for the later `commit()`.
    let equivocated = equivocation::check_and_flag(
        &mut tx,
        peer.id,
        cp.checkpoint_timestamp,
        cp.tree_size,
        &cp.ledger_root,
    )
    .await
    .map_err(|e| format!("equivocation check: {e}"))?;

    // 4. Auto-block — only when BOTH the sig was valid AND equivocation
    //    was detected AND the operator opted in. In-tx so it's atomic with
    //    detection + store.
    let auto_blocked = if equivocated && config.auto_block_equivocators {
        equivocation::auto_block_peer(&mut tx, peer.id)
            .await
            .map_err(|e| format!("auto-block: {e}"))?;
        true
    } else {
        false
    };

    // 5. Store — flag the row as `verified = proof_verified` so the UI can
    //    distinguish "sig OK, proof OK" from "sig OK, proof absent", and
    //    stamp `equivocation_detected = equivocated` so a row landing into an
    //    already-detected conflict is itself flagged.
    let checkpoint_id =
        checkpoint::store_peer_checkpoint(&mut tx, peer.id, cp, proof_verified, equivocated)
            .await
            .map_err(|e| format!("store: {e}"))?;

    tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;

    Ok(VerifyOutcome {
        checkpoint_id,
        signature_verified: true,
        proof_verified,
        equivocation_detected: equivocated,
        auto_blocked,
    })
}

/// Verify the BJJ-EdDSA signature on a peer checkpoint.
///
/// Returns `Ok(())` on success; otherwise an explanatory `Err(String)`.
/// Fails closed on:
///   - missing `bjj_signature` block,
///   - any signature/pubkey field that isn't a parseable Fr,
///   - signature verification rejection by `baby_jubjub::verify_signature`
///     (which itself enforces R8 + pubkey subgroup membership before
///     delegating to iden3 — audit M-1).
fn verify_checkpoint_signature(peer: &PeerNode, cp: &PeerCheckpoint) -> Result<(), String> {
    let sig_wire = cp
        .bjj_signature
        .as_ref()
        .ok_or_else(|| "checkpoint missing bjj_signature".to_owned())?;

    // Parse the peer's pinned pubkey (from peer_nodes row).
    let px = crate::zk::proof::parse_fr(&peer.bjj_pubkey_x)
        .map_err(|e| format!("peer pubkey x parse: {e}"))?;
    let py = crate::zk::proof::parse_fr(&peer.bjj_pubkey_y)
        .map_err(|e| format!("peer pubkey y parse: {e}"))?;
    let pubkey = BabyJubJubPubKey { x: px, y: py };

    // Parse signature components.
    let r8x =
        crate::zk::proof::parse_fr(&sig_wire.r8x).map_err(|e| format!("sig r8x parse: {e}"))?;
    let r8y =
        crate::zk::proof::parse_fr(&sig_wire.r8y).map_err(|e| format!("sig r8y parse: {e}"))?;
    let s = crate::zk::proof::parse_fr(&sig_wire.s).map_err(|e| format!("sig s parse: {e}"))?;
    let signature = BabyJubJubSignature { r8x, r8y, s };

    // Canonical message: Poseidon(ledger_root, checkpoint_timestamp).
    // Matches the producer in `checkpoint::build_own_checkpoint` —
    // changing this format requires bumping the wire version on both sides.
    let ledger_root = crate::zk::proof::parse_fr(&cp.ledger_root)
        .map_err(|e| format!("ledger_root parse: {e}"))?;
    // `checkpoint_timestamp` is wire-typed `i64`. `as u64` would silently
    // wrap a negative value into a huge `u64` and produce a Poseidon input
    // that the signer never used — verification would then fail "for the
    // wrong reason" (alleged sig mismatch instead of "timestamp invalid").
    // Reject negatives explicitly so the error class is honest.
    let ts: u64 = cp.checkpoint_timestamp.try_into().map_err(|_| {
        format!(
            "checkpoint_timestamp must be non-negative (got {})",
            cp.checkpoint_timestamp
        )
    })?;
    let ts_fr = Fr::from(ts);
    let msg =
        crate::zk::poseidon::hash2(ledger_root, ts_fr).map_err(|e| format!("poseidon: {e}"))?;

    if !baby_jubjub::verify_signature(&pubkey, &signature, msg) {
        return Err("BJJ signature verification failed".to_owned());
    }
    Ok(())
}

/// Verify the Groth16 proof attached to a peer checkpoint against the
/// **document_existence** circuit's vkey.
///
/// This must match the producer. `checkpoint::build_own_checkpoint` runs
/// `prove_existence` (the `document_existence` circuit) and emits its
/// `[root, leafIndex, treeSize]` public signals — see the rationale there
/// for why existence and not the unified circuit. Verifying that proof
/// under any other circuit's vkey rejects every honest peer's checkpoint,
/// because the public-signal contract differs (CodeRabbit critical: the
/// producer/verifier were on different circuits).
///
/// Audit H-5 is still honoured: the historical bug was a *silent fallback*
/// chain (`unified().or_else(existence)`) that could verify a proof against
/// the wrong constraint system. There is no fallback here — a single
/// verifier, fixed to the one circuit checkpoints actually use. A missing
/// vkey hard-errors rather than demoting.
fn verify_checkpoint_proof(cp: &PeerCheckpoint) -> Result<bool, String> {
    use crate::zk::proof::{parse_fr, parse_signals_slice};

    let signals =
        parse_signals_slice(&cp.public_signals).map_err(|e| format!("signal parse: {e}"))?;
    let proof_json =
        serde_json::to_string(&cp.groth16_proof).map_err(|e| format!("proof json: {e}"))?;

    // Red-team F-1 + F-RT-1: BIND the proof's public signals to the
    // checkpoint envelope BEFORE verifying. The Groth16 pairing check
    // confirms the proof is well-formed for *some* (root, leafIndex,
    // treeSize) triple — without the next two binds, a trusted peer
    // could sign one `cp.ledger_root` with their BJJ key and supply a
    // proof attesting an entirely different root, and the receiver
    // would happily write `verified=true` for a forged claim.
    //
    // The `document_existence` circuit declares public-signal order
    // `[root, leafIndex, treeSize]` (proofs/circuits/document_existence.circom:114).
    let expected_root =
        parse_fr(&cp.ledger_root).map_err(|e| format!("envelope ledger_root parse: {e}"))?;
    let Some(proof_root) = signals.first() else {
        return Err("public signals missing root (signals[0])".to_owned());
    };
    if *proof_root != expected_root {
        return Err(
            "checkpoint Groth16 proof root does not match BJJ-signed envelope \
             ledger_root — signals[0] != parse_fr(cp.ledger_root) (red-team F-1)"
                .to_owned(),
        );
    }
    let Some(proof_tree_size) = signals.get(2) else {
        return Err("public signals missing treeSize (signals[2])".to_owned());
    };
    // `cp.tree_size` is i64 on the envelope; the producer guarantees it
    // is non-negative when emitted (`checkpoint.rs` writes COUNT(*)).
    // A negative wire value would already fail parse upstream, but cast
    // defensively.
    if cp.tree_size < 0 {
        return Err("envelope tree_size is negative".to_owned());
    }
    let expected_tree_size = ark_bn254::Fr::from(cp.tree_size as u64);
    if *proof_tree_size != expected_tree_size {
        return Err("checkpoint Groth16 proof treeSize does not match envelope \
             tree_size — signals[2] != Fr::from(cp.tree_size) (red-team F-1)"
            .to_owned());
    }

    // Audit H-2 / red-team F-RT-1: apply the same empty-tree invariant
    // the `/zk/verify` route enforces. Without this, a peer can produce
    // a real Groth16 proof with `tree_size=0` and an arbitrary
    // non-empty root, and the bounds check `leafIndex < tree_size` is
    // disabled in-circuit so the proof verifies. The earlier binding
    // checks now require `expected_root == proof_root`, but if a peer
    // chooses `cp.ledger_root = X` and `cp.tree_size = 0` with a proof
    // for that same X, the invariant catches the X != empty-tree-root
    // case here.
    crate::zk::verify::enforce_empty_tree_invariant(&signals, 0, 2)?;

    let verifier = crate::zk::verify::existence_verifier()
        .map_err(|e| format!("document_existence verifier init: {e}"))?;
    verifier
        .verify(&proof_json, &signals)
        .map_err(|e| format!("verify: {e}"))
}

#[cfg(test)]
mod tests {
    //! Audit M-F1: federation hardening from #1050 (H-11, H-5, H-12, M-1)
    //! was previously untested at the unit level — any future refactor
    //! could silently regress those fixes. These tests cover the
    //! pure-function pieces of the verify pipeline that don't need a
    //! live Postgres; the DB-bound `verify_and_store` + equivocation
    //! detection await a workspace-wide pg_embed test harness.
    use super::*;
    use crate::federation::checkpoint::{BjjSignatureWire, PeerCheckpoint};
    use crate::federation::peer::PeerNode;
    use crate::zk::witness::baby_jubjub;
    use chrono::Utc;
    use uuid::Uuid;

    use crate::zk::proof::fr_to_decimal;

    /// Build a checkpoint signed by the given key, with `ledger_root`
    /// as the wire field. Mirrors the producer in
    /// `checkpoint::build_own_checkpoint` so the verify path sees the
    /// same canonical message shape.
    fn signed_checkpoint(priv_key: &[u8; 32], ledger_root_dec: &str, ts: i64) -> PeerCheckpoint {
        let ledger_root = crate::zk::proof::parse_fr(ledger_root_dec).unwrap();
        let sig = crate::zk::witness::unified::UnifiedWitness::sign_checkpoint(
            priv_key,
            ledger_root,
            ts as u64,
        )
        .unwrap();
        PeerCheckpoint {
            wire_version: PeerCheckpoint::current_version(),
            ledger_root: ledger_root_dec.to_owned(),
            tree_size: 1,
            checkpoint_timestamp: ts,
            authority_pubkey_hash: "0".to_owned(),
            groth16_proof: serde_json::json!(null),
            public_signals: vec![],
            bjj_signature: Some(BjjSignatureWire {
                r8x: fr_to_decimal(&sig.r8x),
                r8y: fr_to_decimal(&sig.r8y),
                s: fr_to_decimal(&sig.s),
            }),
        }
    }

    fn peer_for(pubkey: &baby_jubjub::BabyJubJubPubKey) -> PeerNode {
        PeerNode {
            id: Uuid::new_v4(),
            name: Some("test".to_owned()),
            onion_address: "abcd.onion".to_owned(),
            bjj_pubkey_x: fr_to_decimal(&pubkey.x),
            bjj_pubkey_y: fr_to_decimal(&pubkey.y),
            trust_status: "trusted".to_owned(),
            last_seen_at: None,
            added_at: Utc::now().naive_utc(),
            last_pull_error_at: None,
            last_pull_error_msg: None,
        }
    }

    #[test]
    fn reject_null_proof_rejects_null_groth16() {
        // H-11 / M-5: a checkpoint with `groth16_proof: null` must be
        // rejected regardless of BJJ-signature validity. This is the
        // closure of the H-11/M-5 transitional-state hole — before
        // this PR, the verify pipeline stored such envelopes with
        // `proof_verified=false` instead of failing closed.
        let cp = PeerCheckpoint {
            wire_version: PeerCheckpoint::current_version(),
            ledger_root: "1".to_owned(),
            tree_size: 1,
            checkpoint_timestamp: 1_700_000_000,
            authority_pubkey_hash: "0".to_owned(),
            groth16_proof: serde_json::json!(null),
            public_signals: vec![],
            bjj_signature: None,
        };
        let err = reject_null_proof(&cp).expect_err("must reject null");
        assert!(
            err.contains("H-11/M-5"),
            "error should cite audit ID, got: {err}"
        );
    }

    #[test]
    fn reject_null_proof_accepts_non_null_groth16() {
        let cp = PeerCheckpoint {
            wire_version: PeerCheckpoint::current_version(),
            ledger_root: "1".to_owned(),
            tree_size: 1,
            checkpoint_timestamp: 1_700_000_000,
            authority_pubkey_hash: "0".to_owned(),
            // Any non-null JSON value passes the presence check; the
            // actual Groth16 verify runs later in verify_and_store.
            groth16_proof: serde_json::json!({"pi_a": []}),
            public_signals: vec![],
            bjj_signature: None,
        };
        reject_null_proof(&cp).expect("non-null proof must pass presence check");
    }

    #[test]
    fn verify_signature_accepts_valid_checkpoint() {
        // Audit M-F1 baseline: a checkpoint produced via the documented
        // build_own_checkpoint pipeline (Poseidon(ledger_root, ts) + BJJ
        // sign with authority key, verifier checks against the same
        // recipe) must verify. Catches accidental reshuffles of the
        // canonical message recipe on either the producer or verifier
        // side.
        let priv_key = [7u8; 32];
        let pubkey = baby_jubjub::BabyJubJubPubKey::from_private(&priv_key).unwrap();
        let cp = signed_checkpoint(&priv_key, "1234567890", 1_700_000_000);
        let peer = peer_for(&pubkey);
        assert!(verify_checkpoint_signature(&peer, &cp).is_ok());
    }

    #[test]
    fn verify_signature_rejects_tampered_ledger_root() {
        // Audit M-F1: flipping the ledger_root after signing must break
        // verification. The previous BJJ-EdDSA hardening (M-1) is
        // pointless if a downstream refactor lets a tampered root through.
        let priv_key = [11u8; 32];
        let pubkey = baby_jubjub::BabyJubJubPubKey::from_private(&priv_key).unwrap();
        let mut cp = signed_checkpoint(&priv_key, "1234567890", 1_700_000_000);
        cp.ledger_root = "9999999999".to_owned();
        let peer = peer_for(&pubkey);
        let err = verify_checkpoint_signature(&peer, &cp).expect_err("tamper must reject");
        assert!(err.contains("verification failed"), "got: {err}");
    }

    #[test]
    fn verify_signature_fails_closed_on_missing_signature() {
        // Audit M-F1: a missing bjj_signature field must fail closed
        // — never "no signature provided, default to trusted." The
        // verify pipeline rejects upfront so equivocation detection
        // never runs on unverified data (audit H-12 / F-3 prerequisite).
        let priv_key = [13u8; 32];
        let pubkey = baby_jubjub::BabyJubJubPubKey::from_private(&priv_key).unwrap();
        let mut cp = signed_checkpoint(&priv_key, "1234567890", 1_700_000_000);
        cp.bjj_signature = None;
        let peer = peer_for(&pubkey);
        let err = verify_checkpoint_signature(&peer, &cp).expect_err("missing sig must reject");
        assert!(err.contains("missing bjj_signature"), "got: {err}");
    }

    #[test]
    fn verify_signature_rejects_wrong_peer_pubkey() {
        // Audit M-F1: a checkpoint signed by key A must not verify
        // under peer B's pinned pubkey. Catches a regression where
        // peer.bjj_pubkey_{x,y} stopped being used in the verify path.
        let priv_a = [21u8; 32];
        let priv_b = [22u8; 32];
        let pub_b = baby_jubjub::BabyJubJubPubKey::from_private(&priv_b).unwrap();
        let cp_signed_by_a = signed_checkpoint(&priv_a, "1234567890", 1_700_000_000);
        let peer_b = peer_for(&pub_b);
        assert!(verify_checkpoint_signature(&peer_b, &cp_signed_by_a).is_err());
    }

    /// Build a checkpoint envelope with caller-controlled `ledger_root`,
    /// `tree_size`, and `public_signals` (decimal-Fr strings). For the
    /// red-team F-1 / F-RT-1 binding tests, the Groth16 proof bytes are
    /// a placeholder — the binding checks fire before any pairing check
    /// runs, so the tests never need a real proof.
    fn envelope_for_binding_tests(
        ledger_root_dec: &str,
        tree_size: i64,
        signals: Vec<String>,
    ) -> PeerCheckpoint {
        PeerCheckpoint {
            wire_version: PeerCheckpoint::current_version(),
            ledger_root: ledger_root_dec.to_owned(),
            tree_size,
            checkpoint_timestamp: 1_700_000_000,
            authority_pubkey_hash: "0".to_owned(),
            // Non-null so `reject_null_proof` (called elsewhere) would
            // pass; the binding checks fire before any verify.
            groth16_proof: serde_json::json!({"pi_a": [], "pi_b": [], "pi_c": []}),
            public_signals: signals,
            bjj_signature: None,
        }
    }

    #[test]
    fn verify_checkpoint_proof_rejects_root_envelope_mismatch() {
        // Red-team F-1 kill chain. Producer signs `cp.ledger_root = X`
        // honestly with their BJJ key, then supplies a Groth16 proof
        // whose `signals[0]` is some DIFFERENT chosen root Y. Without
        // this check the verifier would happily accept "valid proof of
        // wrong fact." `verify_checkpoint_proof` must reject before
        // running the pairing check.
        //
        // Decimal Fr literals: "1" and "2" are distinct in-field values.
        let cp = envelope_for_binding_tests(
            "1",
            1,
            vec!["2".to_owned(), "0".to_owned(), "1".to_owned()],
        );
        let err = verify_checkpoint_proof(&cp).expect_err("mismatched proof root must reject");
        assert!(
            err.contains("signals[0] != parse_fr(cp.ledger_root)") || err.contains("F-1"),
            "error should cite the binding finding, got: {err}"
        );
    }

    #[test]
    fn verify_checkpoint_proof_rejects_tree_size_envelope_mismatch() {
        // Red-team F-1: same binding bug applies to `tree_size`. Without
        // the second binding check, a peer could sign `cp.tree_size = 5`
        // and supply a proof for `signals[2] = 99`.
        let cp = envelope_for_binding_tests(
            "1",
            5,
            // signals[0] matches ledger_root, but signals[2] is 99 not 5
            vec!["1".to_owned(), "0".to_owned(), "99".to_owned()],
        );
        let err = verify_checkpoint_proof(&cp).expect_err("mismatched proof tree_size must reject");
        assert!(
            err.contains("signals[2] != Fr::from(cp.tree_size)") || err.contains("F-1"),
            "error should cite the binding finding, got: {err}"
        );
    }

    #[test]
    fn verify_checkpoint_proof_rejects_tree_size_zero_with_non_empty_root() {
        // Red-team F-RT-1 / audit H-2. Even after the binding checks
        // pass (signals[0] == ledger_root and signals[2] == tree_size),
        // a `tree_size = 0` proof against a NON-EMPTY root would be
        // accepted by the existence circuit because the `leafIndex <
        // treeSize` bounds check is disabled. `enforce_empty_tree_invariant`
        // (newly shared from `zk::verify`) closes this on the federation
        // receive path.
        //
        // "1" is decidedly not the empty-doc-existence root.
        let cp = envelope_for_binding_tests(
            "1",
            0,
            vec!["1".to_owned(), "0".to_owned(), "0".to_owned()],
        );
        let err =
            verify_checkpoint_proof(&cp).expect_err("tree_size=0 with non-empty root must reject");
        assert!(
            err.contains("treeSize=0") || err.contains("H-2"),
            "error should cite the empty-tree invariant, got: {err}"
        );
    }

    #[test]
    fn verify_signature_rejects_negative_timestamp() {
        // Audit M-F1 + verify.rs:195: negative timestamps used to wrap
        // via `as u64` and produce a Poseidon input the signer never
        // used; verify would fail "for the wrong reason." Now rejected
        // with an honest error class.
        let priv_key = [31u8; 32];
        let pubkey = baby_jubjub::BabyJubJubPubKey::from_private(&priv_key).unwrap();
        let mut cp = signed_checkpoint(&priv_key, "1234567890", 1_700_000_000);
        cp.checkpoint_timestamp = -1;
        let peer = peer_for(&pubkey);
        let err = verify_checkpoint_signature(&peer, &cp).expect_err("negative ts must reject");
        assert!(err.contains("non-negative"), "got: {err}");
    }
}

// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! ADR-0041 §3/§4/§6 conformance for the trust-transition store: immutable
//! staged candidates, atomic serialised acceptance with append-only
//! lifecycle events, ordered activation, startup reconciliation, and
//! trust-state reconstruction from the immutable rows.
//!
//! Database: boots an embedded Postgres (pg_embed, as CI does) by default,
//! or connects to `OLYMPUS_TEST_PG_URL` when set (a throwaway database).
//!
//! The trust chain is a per-database singleton (`next_sequence` is UNIQUE),
//! so these tests serialise on one async mutex and each begins by truncating
//! the three trust tables — which no other test binary touches — rather than
//! namespacing rows. Everything else in the shared database is left alone.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgPool;
use uuid::Uuid;

use olympus_crypto::trust_list::{
    snapshot_digest, GenesisApprovalPolicy, RotationPolicy, RotationPolicyProfile,
    TrustListSnapshotV1, TrustPubKey, TrustResolver, TrustRole, TrustTransitionKind,
    TrustedIssuerEntry,
};
use olympus_crypto::trust_wire::{TrustApprovalWire, TrustTransitionFile};
use olympus_tauri_lib::quorum::trust::{approve_trust_genesis, approve_trust_rotation};
use olympus_tauri_lib::quorum::CollectedSignature;
use olympus_tauri_lib::trust::{
    accept_candidate, activate_transition, load_accepted_chain, reconcile_at_startup,
    stage_candidate, FreshnessLimit, TrustFreshnessConfig, TrustReconcileOutcome,
    TrustTransitionError,
};

// ── Fixtures ─────────────────────────────────────────────────────────────

const ROT1: [u8; 32] = [10u8; 32];
const ROT2: [u8; 32] = [11u8; 32];
const RECOVERY: [u8; 32] = [200u8; 32];
const GEN1: [u8; 32] = [20u8; 32];
const GEN2: [u8; 32] = [21u8; 32];
const ISSUER: [u8; 32] = [1u8; 32];

/// Base clock: genesis is issued at `t0()`, sequence `n` at
/// `t0() + (n-1)*1000`. Anchored to the real wall clock (minus the 2 000 s
/// that [`now`] adds back) rather than a fixed epoch because
/// `reconcile_at_startup` hands back a resolver on the **system** clock —
/// fixtures dated in the past would look expired to it even though every
/// store API takes an explicit `now`.
fn t0() -> i64 {
    static T0: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *T0.get_or_init(|| {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        wall - 2_000
    })
}

/// The fixture decision time — within every fixture snapshot's freshness
/// window, and equal to the real wall clock at first use (see [`t0`]).
fn now() -> i64 {
    t0() + 2_000
}

fn trust_key_for(priv_key: &[u8; 32]) -> TrustPubKey {
    use ark_ff::{BigInteger, PrimeField};
    let pk = olympus_tauri_lib::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(priv_key)
        .expect("pubkey");
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&pk.x.into_bigint().to_bytes_be());
    y.copy_from_slice(&pk.y.into_bigint().to_bytes_be());
    TrustPubKey::new(x, y)
}

fn sorted_keys(seeds: &[[u8; 32]]) -> Vec<TrustPubKey> {
    let mut keys: Vec<_> = seeds.iter().map(trust_key_for).collect();
    keys.sort_unstable();
    keys
}

fn base_snapshot(sequence: u64, previous: Option<[u8; 32]>) -> TrustListSnapshotV1 {
    let role = TrustRole::CredentialAuthority;
    let issued_at = t0() + (sequence as i64 - 1) * 1_000;
    TrustListSnapshotV1 {
        format_version: 1,
        sequence,
        issued_at,
        expires_at: issued_at + 90_000,
        activation_at: issued_at + 500,
        previous_snapshot_digest: previous,
        active_roles: BTreeSet::from([role]),
        entries: vec![TrustedIssuerEntry {
            pubkey: trust_key_for(&ISSUER),
            roles: BTreeSet::from([role]),
            valid_from: issued_at + 100,
            valid_until: issued_at + 80_000,
        }],
        rotation_policies: BTreeMap::from([(
            role,
            RotationPolicy {
                profile: RotationPolicyProfile::Production,
                signers: sorted_keys(&[ROT1, ROT2]),
                threshold: 2,
            },
        )]),
        recovery_keys: BTreeMap::from([(role, trust_key_for(&RECOVERY))]),
    }
}

fn approval_wire(sig: CollectedSignature) -> TrustApprovalWire {
    TrustApprovalWire {
        x: sig.signer.x,
        y: sig.signer.y,
        r8x: sig.r8x,
        r8y: sig.r8y,
        s: sig.s,
    }
}

fn genesis_policy() -> GenesisApprovalPolicy {
    GenesisApprovalPolicy {
        profile: RotationPolicyProfile::Production,
        signers: sorted_keys(&[GEN1, GEN2]),
        threshold: 2,
    }
}

/// A fully signed genesis file. `mutate` runs before signing, so the
/// approvals always cover the final snapshot body.
fn genesis_file_with(mutate: impl FnOnce(&mut TrustListSnapshotV1)) -> TrustTransitionFile {
    let mut snapshot = base_snapshot(1, None);
    mutate(&mut snapshot);
    let policy = genesis_policy();
    let approvals = [GEN1, GEN2]
        .iter()
        .map(|key| approval_wire(approve_trust_genesis(key, &snapshot, &policy).expect("sign")))
        .collect();
    TrustTransitionFile {
        kind: TrustTransitionKind::Genesis,
        snapshot,
        approvals,
        recovery: None,
        genesis_approval_policy: Some(policy),
    }
}

fn genesis_file() -> TrustTransitionFile {
    genesis_file_with(|_| {})
}

/// A fully signed 2-of-2 rotation from `(prev_sequence, prev_digest)` to a
/// mutated successor snapshot. `mutate` runs before signing.
fn rotation_file(
    prev_sequence: u64,
    prev_digest: [u8; 32],
    mutate: impl FnOnce(&mut TrustListSnapshotV1),
) -> TrustTransitionFile {
    let mut snapshot = base_snapshot(prev_sequence + 1, Some(prev_digest));
    mutate(&mut snapshot);
    let digest = snapshot_digest(&snapshot);
    let approvals = [ROT1, ROT2]
        .iter()
        .map(|key| {
            approval_wire(
                approve_trust_rotation(
                    key,
                    &prev_digest,
                    &digest,
                    prev_sequence,
                    snapshot.sequence,
                    snapshot.activation_at,
                )
                .expect("sign"),
            )
        })
        .collect();
    TrustTransitionFile {
        kind: TrustTransitionKind::Rotation,
        snapshot,
        approvals,
        recovery: None,
        genesis_approval_policy: None,
    }
}

fn dev_config() -> TrustFreshnessConfig {
    TrustFreshnessConfig {
        max_age: FreshnessLimit::Unset,
        max_lifetime: FreshnessLimit::Unset,
    }
}

/// Serialises the trust-table tests: the chain is a database singleton, so
/// concurrent tests would race the advisory lock and each other's TRUNCATE.
static TRUST_DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn clean_slate(pool: &PgPool) {
    sqlx::query(
        "TRUNCATE trust_candidate_events, trust_accepted_transitions, \
         trust_transition_candidates CASCADE",
    )
    .execute(pool)
    .await
    .expect("truncate trust tables");
}

// ── Tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn genesis_stage_accept_reconcile_and_resolve() {
    let _guard = TRUST_DB_LOCK.lock().await;
    let (pool, _pg) = open_pool().await;
    clean_slate(&pool).await;
    let config = dev_config();

    // Empty chain → reconciliation reports NoAcceptedGenesis and nothing else.
    match reconcile_at_startup(&pool, &config, now(), false).await {
        Ok(TrustReconcileOutcome::NoAcceptedGenesis) => {}
        other => panic!("expected NoAcceptedGenesis, got {:?}", other.err()),
    }

    let file = genesis_file();
    let staged = stage_candidate(&pool, &file, now(), &config, false)
        .await
        .expect("stage genesis");
    assert_eq!(staged.next_sequence, 1);
    assert_eq!(staged.next_snapshot_digest, snapshot_digest(&file.snapshot));

    let accepted = accept_candidate(&pool, staged.candidate_id, now(), &config, false)
        .await
        .expect("accept genesis");
    assert_eq!(accepted.sequence, 1);
    assert!(!accepted.activated);

    // Reconciliation activates the genesis (its signed activation_at,
    // t0()+500, has passed) and hands back a resolver over it.
    let outcome = reconcile_at_startup(&pool, &config, now(), false)
        .await
        .expect("reconcile");
    let TrustReconcileOutcome::ChainActive {
        resolver,
        activated_now,
        pending_successors,
    } = outcome
    else {
        panic!("expected ChainActive after accepting genesis");
    };
    assert_eq!(activated_now, 1);
    assert_eq!(pending_successors, 0);
    assert_eq!(resolver.snapshot_sequence(), 1);
    assert_eq!(resolver.snapshot_digest(), staged.next_snapshot_digest);
    assert!(resolver.issuer_is_active_for(
        &trust_key_for(&ISSUER),
        TrustRole::CredentialAuthority,
        now()
    ));
    // Role separation: the issuer holds no other role.
    assert!(!resolver.issuer_is_active_for(
        &trust_key_for(&ISSUER),
        TrustRole::CheckpointAuthority,
        now()
    ));

    // Idempotence: a second reconcile activates nothing further.
    match reconcile_at_startup(&pool, &config, now(), false).await {
        Ok(TrustReconcileOutcome::ChainActive { activated_now, .. }) => {
            assert_eq!(activated_now, 0)
        }
        other => panic!("expected ChainActive, got {:?}", other.err()),
    }
}

#[tokio::test]
async fn staged_candidates_do_not_reserve_the_slot_and_acceptance_is_atomic() {
    let _guard = TRUST_DB_LOCK.lock().await;
    let (pool, _pg) = open_pool().await;
    clean_slate(&pool).await;
    let config = dev_config();

    let genesis = genesis_file();
    let g = stage_candidate(&pool, &genesis, now(), &config, false)
        .await
        .expect("stage genesis");
    accept_candidate(&pool, g.candidate_id, now(), &config, false)
        .await
        .expect("accept genesis");
    activate_transition(&pool, g.candidate_id, now(), &config, false)
        .await
        .expect("activate genesis");
    let genesis_digest = g.next_snapshot_digest;

    // Two DIFFERENT candidates for successor slot 2 both stage fine — a
    // Staged candidate reserves nothing (ADR-0041 §3).
    let file_a = rotation_file(1, genesis_digest, |s| s.expires_at += 1);
    let file_b = rotation_file(1, genesis_digest, |s| s.expires_at += 2);
    let a = stage_candidate(&pool, &file_a, now(), &config, false)
        .await
        .expect("stage candidate A");
    let b = stage_candidate(&pool, &file_b, now(), &config, false)
        .await
        .expect("stage candidate B");
    assert_eq!(a.next_sequence, 2);
    assert_eq!(b.next_sequence, 2);
    assert_ne!(a.next_snapshot_digest, b.next_snapshot_digest);

    // Snapshot B's immutable row before the race, to prove loser rows are
    // never mutated.
    let b_row_before: (String, serde_json::Value) = sqlx::query_as(
        "SELECT next_snapshot_digest, snapshot_json FROM trust_transition_candidates \
         WHERE candidate_id = $1",
    )
    .bind(b.candidate_id)
    .fetch_one(&pool)
    .await
    .expect("candidate B row");

    // A wins the slot; B is superseded with a reference to the winner.
    accept_candidate(&pool, a.candidate_id, now(), &config, false)
        .await
        .expect("accept candidate A");
    let err = accept_candidate(&pool, b.candidate_id, now(), &config, false)
        .await
        .expect_err("candidate B must lose the slot");
    match err {
        TrustTransitionError::SupersededByAcceptedWinner { winner, sequence } => {
            assert_eq!(winner, a.candidate_id);
            assert_eq!(sequence, 2);
        }
        other => panic!("expected SupersededByAcceptedWinner, got {other}"),
    }

    // The superseded event exists, references the winner, and the loser's
    // candidate row is byte-identical to before.
    let event: (String, Option<Uuid>) = sqlx::query_as(
        "SELECT event_kind, winning_candidate_id FROM trust_candidate_events \
         WHERE candidate_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(b.candidate_id)
    .fetch_one(&pool)
    .await
    .expect("candidate B event");
    assert_eq!(event.0, "superseded");
    assert_eq!(event.1, Some(a.candidate_id));

    let b_row_after: (String, serde_json::Value) = sqlx::query_as(
        "SELECT next_snapshot_digest, snapshot_json FROM trust_transition_candidates \
         WHERE candidate_id = $1",
    )
    .bind(b.candidate_id)
    .fetch_one(&pool)
    .await
    .expect("candidate B row after");
    assert_eq!(
        b_row_before, b_row_after,
        "loser candidate row must be untouched"
    );

    // Supersession is terminal: B can never be accepted later, even though
    // its slot conflict is the only thing wrong with it.
    let err = accept_candidate(&pool, b.candidate_id, now(), &config, false)
        .await
        .expect_err("terminal candidate");
    assert!(
        matches!(err, TrustTransitionError::CandidateTerminal { ref event_kind, .. } if event_kind == "superseded"),
        "expected CandidateTerminal(superseded), got {err}"
    );

    // ...and the winner is idempotently already-accepted.
    let err = accept_candidate(&pool, a.candidate_id, now(), &config, false)
        .await
        .expect_err("winner is already accepted");
    assert!(matches!(
        err,
        TrustTransitionError::CandidateAlreadyAccepted { candidate_id } if candidate_id == a.candidate_id
    ));
}

#[tokio::test]
async fn rollback_skip_wrong_predecessor_and_equivocation_are_rejected() {
    let _guard = TRUST_DB_LOCK.lock().await;
    let (pool, _pg) = open_pool().await;
    clean_slate(&pool).await;
    let config = dev_config();

    let genesis = genesis_file();
    let g = stage_candidate(&pool, &genesis, now(), &config, false)
        .await
        .expect("stage genesis");
    accept_candidate(&pool, g.candidate_id, now(), &config, false)
        .await
        .expect("accept genesis");
    let rotation = rotation_file(1, g.next_snapshot_digest, |_| {});
    let r = stage_candidate(&pool, &rotation, now(), &config, false)
        .await
        .expect("stage rotation");
    accept_candidate(&pool, r.candidate_id, now(), &config, false)
        .await
        .expect("accept rotation");
    // Accepted tip is now sequence 2.

    // Rollback: a rotation claiming sequence 1 (behind the accepted tip).
    let mut old = rotation_file(1, g.next_snapshot_digest, |_| {});
    old.snapshot = genesis.snapshot.clone();
    old.snapshot.issued_at += 7; // different content than the accepted genesis
    let err = stage_candidate(&pool, &old, now(), &config, false)
        .await
        .expect_err("rollback must be rejected");
    assert!(
        matches!(
            err,
            TrustTransitionError::RollbackToOlderSequence {
                candidate: 1,
                accepted: 2
            }
        ),
        "expected RollbackToOlderSequence, got {err}"
    );

    // Same-sequence equivocation: different content at the accepted tip's
    // own sequence.
    let equivocating = rotation_file(1, g.next_snapshot_digest, |s| s.expires_at += 12_345);
    let err = stage_candidate(&pool, &equivocating, now(), &config, false)
        .await
        .expect_err("equivocation must be rejected");
    assert!(
        matches!(
            err,
            TrustTransitionError::SameSequenceEquivocation { sequence: 2 }
        ),
        "expected SameSequenceEquivocation, got {err}"
    );

    // Skipped sequence: 4 on a tip of 2. The envelope is pulled back inside
    // the fixture clock's freshness window so the SEQUENCE check is what
    // fires, not the future-dated gate (`base_snapshot(4)` would otherwise
    // be issued 1 000 s ahead of `now()`).
    let skipped = rotation_file(3, snapshot_digest(&rotation.snapshot), |s| {
        s.issued_at = t0();
        s.expires_at = t0() + 90_000;
        s.activation_at = t0() + 1_600;
        s.entries[0].valid_from = t0() + 100;
        s.entries[0].valid_until = t0() + 80_000;
    });
    let err = stage_candidate(&pool, &skipped, now(), &config, false)
        .await
        .expect_err("skip must be rejected");
    assert!(
        matches!(
            err,
            TrustTransitionError::SkippedSequence {
                candidate: 4,
                accepted: 2
            }
        ),
        "expected SkippedSequence, got {err}"
    );

    // Wrong predecessor digest at the correct next sequence.
    let wrong_pred = rotation_file(2, [9u8; 32], |_| {});
    let err = stage_candidate(&pool, &wrong_pred, now(), &config, false)
        .await
        .expect_err("wrong predecessor must be rejected");
    assert!(
        matches!(err, TrustTransitionError::WrongPredecessorDigest { .. }),
        "expected WrongPredecessorDigest, got {err}"
    );

    // A second genesis once one is accepted.
    let err = stage_candidate(
        &pool,
        &genesis_file_with(|s| s.expires_at += 1),
        now(),
        &config,
        false,
    )
    .await
    .expect_err("second genesis must be rejected");
    assert!(
        matches!(
            err,
            TrustTransitionError::GenesisAlreadyExists {
                accepted_sequence: 2
            }
        ),
        "expected GenesisAlreadyExists, got {err}"
    );

    // Decreasing signed activation_at on an otherwise-valid successor.
    let tip_digest = snapshot_digest(&rotation.snapshot);
    let decreasing = rotation_file(2, tip_digest, |s| {
        s.issued_at = t0();
        s.expires_at = t0() + 90_000;
        s.activation_at = rotation.snapshot.activation_at - 1;
        s.entries[0].valid_from = s.issued_at + 100;
        s.entries[0].valid_until = s.issued_at + 80_000;
    });
    let err = stage_candidate(&pool, &decreasing, now(), &config, false)
        .await
        .expect_err("decreasing activation_at must be rejected");
    assert!(
        matches!(err, TrustTransitionError::DecreasingActivationTime { .. }),
        "expected DecreasingActivationTime, got {err}"
    );
}

#[tokio::test]
async fn acceptance_revalidates_under_the_lock_and_appends_a_rejected_event() {
    let _guard = TRUST_DB_LOCK.lock().await;
    let (pool, _pg) = open_pool().await;
    clean_slate(&pool).await;
    let config = dev_config();

    // Stage a perfectly valid genesis…
    let file = genesis_file();
    let staged = stage_candidate(&pool, &file, now(), &config, false)
        .await
        .expect("stage genesis");

    // …but accept it after its snapshot has expired: the under-lock
    // re-validation must reject it and append a `rejected` event carrying
    // the reason, leaving the candidate row itself untouched.
    let after_expiry = file.snapshot.expires_at + 1;
    let err = accept_candidate(&pool, staged.candidate_id, after_expiry, &config, false)
        .await
        .expect_err("expired candidate must be rejected at acceptance");
    assert!(
        matches!(
            err,
            TrustTransitionError::SnapshotNotFresh(
                olympus_tauri_lib::trust::config::FreshnessViolation::Expired { .. }
            )
        ),
        "expected SnapshotNotFresh(Expired), got {err}"
    );

    let event: (String, Option<String>) = sqlx::query_as(
        "SELECT event_kind, reason FROM trust_candidate_events WHERE candidate_id = $1",
    )
    .bind(staged.candidate_id)
    .fetch_one(&pool)
    .await
    .expect("rejected event");
    assert_eq!(event.0, "rejected");
    assert!(
        event.1.as_deref().unwrap_or("").contains("expired"),
        "rejected event must carry the stable reason, got {:?}",
        event.1
    );

    // No accepted state was created.
    let chain = load_accepted_chain(&pool).await.expect("chain loads");
    assert!(chain.links.is_empty());

    // Rejection is terminal for this candidate even at a valid time.
    let err = accept_candidate(&pool, staged.candidate_id, now(), &config, false)
        .await
        .expect_err("terminal candidate");
    assert!(matches!(
        err,
        TrustTransitionError::CandidateTerminal { .. }
    ));
}

#[tokio::test]
async fn activation_is_ordered_and_reconciliation_resumes_across_restarts() {
    let _guard = TRUST_DB_LOCK.lock().await;
    let (pool, _pg) = open_pool().await;
    clean_slate(&pool).await;
    let config = dev_config();

    // Accept genesis (activation t0()+500) and rotation 2 (activation
    // t0()+1_500) without activating either — simulating a node that accepted
    // both and crashed before activation.
    let genesis = genesis_file();
    let g = stage_candidate(&pool, &genesis, now(), &config, false)
        .await
        .expect("stage genesis");
    accept_candidate(&pool, g.candidate_id, now(), &config, false)
        .await
        .expect("accept genesis");
    let rotation2 = rotation_file(1, g.next_snapshot_digest, |_| {});
    let r2 = stage_candidate(&pool, &rotation2, now(), &config, false)
        .await
        .expect("stage rotation 2");
    accept_candidate(&pool, r2.candidate_id, now(), &config, false)
        .await
        .expect("accept rotation 2");

    // Ordered activation: the successor cannot activate while its
    // predecessor is not Active.
    let err = activate_transition(&pool, r2.candidate_id, now(), &config, false)
        .await
        .expect_err("successor before predecessor");
    assert!(
        matches!(
            err,
            TrustTransitionError::PredecessorNotActive {
                predecessor_sequence: 1
            }
        ),
        "expected PredecessorNotActive, got {err}"
    );

    // A candidate that was never accepted cannot activate at all.
    let err = activate_transition(&pool, Uuid::new_v4(), now(), &config, false)
        .await
        .expect_err("unaccepted candidate");
    assert!(matches!(err, TrustTransitionError::NotAccepted { .. }));

    // Restart reconciliation activates both, in order, and lands on 2.
    let outcome = reconcile_at_startup(&pool, &config, now(), false)
        .await
        .expect("reconcile");
    let TrustReconcileOutcome::ChainActive {
        resolver,
        activated_now,
        pending_successors,
    } = outcome
    else {
        panic!("expected ChainActive");
    };
    assert_eq!(activated_now, 2);
    assert_eq!(pending_successors, 0);
    assert_eq!(resolver.snapshot_sequence(), 2);

    // Accept rotation 3 with a FUTURE signed activation_at: reconciliation
    // must leave it pending (Accepted, not Active) and keep 2 Active.
    let far_future_activation = now() + 50_000;
    let rotation3 = rotation_file(2, r2.next_snapshot_digest, |s| {
        s.activation_at = far_future_activation;
        s.expires_at = far_future_activation + 40_000;
        s.entries[0].valid_until = far_future_activation + 30_000;
    });
    let r3 = stage_candidate(&pool, &rotation3, now(), &config, false)
        .await
        .expect("stage rotation 3");
    accept_candidate(&pool, r3.candidate_id, now(), &config, false)
        .await
        .expect("accept rotation 3");

    let err = activate_transition(&pool, r3.candidate_id, now(), &config, false)
        .await
        .expect_err("activation before its signed time");
    assert!(
        matches!(
            err,
            TrustTransitionError::ActivationTimeNotReached { activation_at, .. }
                if activation_at == far_future_activation
        ),
        "expected ActivationTimeNotReached, got {err}"
    );

    match reconcile_at_startup(&pool, &config, now(), false).await {
        Ok(TrustReconcileOutcome::ChainActive {
            resolver,
            activated_now,
            pending_successors,
        }) => {
            assert_eq!(activated_now, 0);
            assert_eq!(pending_successors, 1);
            assert_eq!(resolver.snapshot_sequence(), 2, "3 must stay pending");
        }
        other => panic!("expected ChainActive, got {:?}", other.err()),
    }

    // A later restart, after the signed activation_at, promotes 3.
    match reconcile_at_startup(&pool, &config, far_future_activation + 1, false).await {
        Ok(TrustReconcileOutcome::ChainActive {
            resolver,
            activated_now,
            pending_successors,
        }) => {
            assert_eq!(activated_now, 1);
            assert_eq!(pending_successors, 0);
            assert_eq!(resolver.snapshot_sequence(), 3);
        }
        other => panic!("expected ChainActive at sequence 3, got {:?}", other.err()),
    }

    // Double activation is refused.
    let err = activate_transition(
        &pool,
        r3.candidate_id,
        far_future_activation + 2,
        &config,
        false,
    )
    .await
    .expect_err("double activation");
    assert!(matches!(err, TrustTransitionError::AlreadyActivated { .. }));
}

#[tokio::test]
async fn continuous_max_age_fails_an_already_active_snapshot_at_reconciliation() {
    let _guard = TRUST_DB_LOCK.lock().await;
    let (pool, _pg) = open_pool().await;
    clean_slate(&pool).await;
    let config = dev_config();

    let file = genesis_file();
    let g = stage_candidate(&pool, &file, now(), &config, false)
        .await
        .expect("stage genesis");
    accept_candidate(&pool, g.candidate_id, now(), &config, false)
        .await
        .expect("accept genesis");
    activate_transition(&pool, g.candidate_id, now(), &config, false)
        .await
        .expect("activate genesis");

    // With a max-age bound, a restart AFTER issued_at + max_age (but well
    // before expires_at) must refuse to expose the stale Active snapshot
    // (security invariant 18) — typed as TooOld, not Expired.
    let bounded = TrustFreshnessConfig {
        max_age: FreshnessLimit::Limited(1_000),
        max_lifetime: FreshnessLimit::Unset,
    };
    let stale_now = file.snapshot.issued_at + 1_001;
    assert!(stale_now < file.snapshot.expires_at);
    let err = reconcile_at_startup(&pool, &bounded, stale_now, false)
        .await
        .expect_err("stale Active snapshot must fail reconciliation");
    assert!(
        matches!(
            err,
            TrustTransitionError::SnapshotNotFresh(
                olympus_tauri_lib::trust::config::FreshnessViolation::TooOld { .. }
            )
        ),
        "expected SnapshotNotFresh(TooOld), got {err}"
    );

    // The same chain under the same bound at a fresh-enough clock is fine.
    match reconcile_at_startup(&pool, &bounded, file.snapshot.issued_at + 999, false).await {
        Ok(TrustReconcileOutcome::ChainActive { resolver, .. }) => {
            assert_eq!(resolver.snapshot_sequence(), 1)
        }
        other => panic!("expected ChainActive, got {:?}", other.err()),
    }
}

#[tokio::test]
async fn accepted_chain_reconstructs_equal_to_what_was_accepted() {
    let _guard = TRUST_DB_LOCK.lock().await;
    let (pool, _pg) = open_pool().await;
    clean_slate(&pool).await;
    let config = dev_config();

    let genesis = genesis_file();
    let g = stage_candidate(&pool, &genesis, now(), &config, false)
        .await
        .expect("stage genesis");
    accept_candidate(&pool, g.candidate_id, now(), &config, false)
        .await
        .expect("accept genesis");
    let rotation = rotation_file(1, g.next_snapshot_digest, |_| {});
    let r = stage_candidate(&pool, &rotation, now(), &config, false)
        .await
        .expect("stage rotation");
    accept_candidate(&pool, r.candidate_id, now(), &config, false)
        .await
        .expect("accept rotation");

    // Reconstruction from the immutable rows equals the accepted inputs —
    // snapshots, digests, kinds, linkage (security invariant 14).
    let chain = load_accepted_chain(&pool).await.expect("chain loads");
    assert_eq!(chain.links.len(), 2);
    assert_eq!(chain.links[0].kind, TrustTransitionKind::Genesis);
    assert_eq!(chain.links[0].snapshot, genesis.snapshot);
    assert_eq!(chain.links[0].digest, snapshot_digest(&genesis.snapshot));
    assert_eq!(chain.links[1].kind, TrustTransitionKind::Rotation);
    assert_eq!(chain.links[1].snapshot, rotation.snapshot);
    assert_eq!(chain.links[1].previous_digest, Some(chain.links[0].digest));
    assert!(chain.links.iter().all(|l| !l.activated));

    // Tampering with a stored approval breaks reconstruction: swap the
    // rotation's approvals for the OTHER candidate domain's signatures
    // (structurally valid JSON, cryptographically wrong), and the loader's
    // authorization re-verification must fail closed. This is superuser SQL
    // standing in for storage corruption — the runtime role cannot UPDATE.
    sqlx::query(
        "UPDATE trust_transition_candidates SET approvals_json = $1 WHERE candidate_id = $2",
    )
    .bind(serde_json::to_value(&genesis.approvals).expect("encode"))
    .bind(r.candidate_id)
    .execute(&pool)
    .await
    .expect("tamper approvals");
    let err = load_accepted_chain(&pool)
        .await
        .expect_err("tampered approvals must fail reconstruction");
    assert!(
        matches!(
            err,
            TrustTransitionError::ChainAuthorizationInvalid { sequence: 2, .. }
        ),
        "expected ChainAuthorizationInvalid at sequence 2, got {err}"
    );

    // ...and a tampered snapshot body fails on digest recomputation before
    // any signature checking.
    sqlx::query(
        "UPDATE trust_transition_candidates
            SET approvals_json = $1,
                snapshot_json = jsonb_set(snapshot_json, '{activation_at}', '9999999999')
          WHERE candidate_id = $2",
    )
    .bind(serde_json::to_value(&rotation.approvals).expect("encode"))
    .bind(r.candidate_id)
    .execute(&pool)
    .await
    .expect("tamper snapshot body");
    let err = load_accepted_chain(&pool)
        .await
        .expect_err("tampered snapshot body must fail reconstruction");
    assert!(
        matches!(err, TrustTransitionError::CandidateDigestMismatch { .. }),
        "expected CandidateDigestMismatch, got {err}"
    );
}

// ── Embedded Postgres boot (same pattern as tests/smt_pg_backend.rs) ──────────

async fn open_pool() -> (PgPool, Option<pg_embed::postgres::PgEmbed>) {
    if let Ok(url) = std::env::var("OLYMPUS_TEST_PG_URL") {
        let pool = PgPool::connect(&url)
            .await
            .expect("connect OLYMPUS_TEST_PG_URL");
        sqlx::migrate!("../migrations")
            .run(&pool)
            .await
            .expect("migrate provided db");
        return (pool, None);
    }
    let mut last_err = None;
    for _ in 0..5 {
        match try_boot_embedded().await {
            Ok(pair) => return pair,
            Err(e) => last_err = Some(e),
        }
    }
    panic!("embedded postgres failed to boot after retries: {last_err:?}");
}

async fn try_boot_embedded() -> anyhow::Result<(PgPool, Option<pg_embed::postgres::PgEmbed>)> {
    use pg_embed::pg_enums::PgAuthMethod;
    use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
    use pg_embed::postgres::{PgEmbed, PgSettings};
    use std::time::Duration;

    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let dir = std::env::temp_dir().join(format!("olympus-trust-pgtest-{port}")); // nosemgrep: rust.lang.security.temp-dir.temp-dir
    let settings = PgSettings {
        database_dir: dir.clone(),
        port,
        user: "olympus".into(),
        password: "olympus".into(),
        auth_method: PgAuthMethod::Plain,
        persistent: true,
        timeout: Some(Duration::from_secs(60)),
        migration_dir: None,
    };
    let fetch = PgFetchSettings {
        version: PG_V15,
        ..Default::default()
    };
    let mut pg = PgEmbed::new(settings, fetch).await?;
    pg.setup().await?;
    {
        use std::io::Write;
        let conf = dir.join("postgresql.conf");
        let existing = std::fs::read_to_string(&conf).unwrap_or_default();
        if !existing.contains("listen_addresses = '127.0.0.1'") {
            let mut f = std::fs::OpenOptions::new().append(true).open(&conf)?;
            writeln!(f, "\nlisten_addresses = '127.0.0.1'\nport = {port}")?;
        }
    }
    pg.start_db().await?;
    if !pg.database_exists("olympus").await? {
        pg.create_database("olympus").await?;
    }
    let pool = PgPool::connect(&pg.full_db_uri("olympus")).await?;
    sqlx::migrate!("../migrations").run(&pool).await?;
    Ok((pool, Some(pg)))
}

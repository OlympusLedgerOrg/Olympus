// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Snapshot-backed [`TrustResolver`] (ADR-0041 §9) with the continuous
//! decision-time staleness gate (security invariant 18).
//!
//! The resolver wraps one Active snapshot. **Every** trust decision first
//! re-evaluates the snapshot's freshness against the wall clock — not the
//! caller's `at` — and fails closed (no issuers, `false`) once the snapshot
//! is expired *or* older than `OLYMPUS_TRUST_LIST_MAX_AGE_SECS`, even while
//! `expires_at` is still in the future. Staleness is therefore not a
//! property checked once at load or activation: a resolver held in
//! `AppState` for days goes dark on its own the moment the bound is crossed.
//!
//! `at` remains the caller's decision-time clock for *issuer-window*
//! evaluation (`valid_from <= at < valid_until`), per §9: a consumer may
//! pass a cryptographically signed artifact timestamp there, but never an
//! unsigned one.
//!
//! No consumer resolves trust through this type yet — switchover from the
//! legacy `api::trusted_issuers` set is a later PR (see the module docs on
//! [`super`]).

use std::sync::Arc;

use olympus_crypto::trust_list::{
    TrustListSnapshotV1, TrustPubKey, TrustResolver, TrustRole, TrustedIssuerEntry,
};

use super::config::{snapshot_freshness_violation, TrustFreshnessConfig};

/// Shared wall-clock source. Injectable so staleness transitions are
/// testable without real waiting; production uses the system clock.
type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

fn system_clock() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// A [`TrustResolver`] over one Active snapshot. Cheap to clone (the
/// snapshot is behind an `Arc`), so it can live in `AppState`.
#[derive(Clone)]
pub struct SnapshotTrustResolver {
    snapshot: Arc<TrustListSnapshotV1>,
    digest: [u8; 32],
    config: TrustFreshnessConfig,
    clock: Clock,
}

impl std::fmt::Debug for SnapshotTrustResolver {
    // Manual because `clock` is an opaque closure; identity fields are what
    // a log or test failure needs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotTrustResolver")
            .field("sequence", &self.snapshot.sequence)
            .field("digest", &hex::encode(self.digest))
            .finish_non_exhaustive()
    }
}

impl SnapshotTrustResolver {
    /// Wrap an Active snapshot with the operator's freshness bounds and the
    /// system clock. `digest` is the snapshot's canonical digest as verified
    /// by the chain loader — taken as a parameter (rather than recomputed)
    /// so the resolver reports exactly the digest the accepted chain proved.
    pub fn new(
        snapshot: TrustListSnapshotV1,
        digest: [u8; 32],
        config: TrustFreshnessConfig,
    ) -> Self {
        Self::with_clock(snapshot, digest, config, Arc::new(system_clock))
    }

    /// Test constructor with an injected clock.
    pub fn with_clock(
        snapshot: TrustListSnapshotV1,
        digest: [u8; 32],
        config: TrustFreshnessConfig,
        clock: Clock,
    ) -> Self {
        Self {
            snapshot: Arc::new(snapshot),
            digest,
            config,
            clock,
        }
    }

    /// The continuous §4 freshness gate, evaluated at the wall clock now.
    fn fresh_now(&self) -> bool {
        snapshot_freshness_violation(&self.snapshot, (self.clock)(), &self.config).is_none()
    }
}

impl TrustResolver for SnapshotTrustResolver {
    fn issuer_is_active_for(&self, pubkey: &TrustPubKey, role: TrustRole, at: i64) -> bool {
        if !self.fresh_now() {
            return false;
        }
        // Roles not in `active_roles` grant no runtime authority even when
        // entries carry them for staged migration (ADR-0041 §1).
        if !self.snapshot.active_roles.contains(&role) {
            return false;
        }
        self.snapshot.entries.iter().any(|entry| {
            entry.pubkey == *pubkey
                && entry.roles.contains(&role)
                && entry.valid_from <= at
                && at < entry.valid_until
        })
    }

    fn active_issuers_for(&self, role: TrustRole, at: i64) -> Vec<&TrustedIssuerEntry> {
        if !self.fresh_now() || !self.snapshot.active_roles.contains(&role) {
            return Vec::new();
        }
        self.snapshot
            .entries
            .iter()
            .filter(|entry| {
                entry.roles.contains(&role) && entry.valid_from <= at && at < entry.valid_until
            })
            .collect()
    }

    fn snapshot_sequence(&self) -> u64 {
        self.snapshot.sequence
    }

    fn snapshot_digest(&self) -> [u8; 32] {
        self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::config::FreshnessLimit;
    use olympus_crypto::trust_list::{
        snapshot_digest, RotationPolicy, RotationPolicyProfile, TrustListSnapshotV1,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicI64, Ordering};

    fn key(seed: u8) -> TrustPubKey {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x[31] = seed;
        y[30] = 1;
        y[31] = seed;
        TrustPubKey::new(x, y)
    }

    /// Snapshot with CredentialAuthority active (issuer `key(1)`, window
    /// [100_100, 180_000)) and RealmAuthority granted on the entry but NOT
    /// active.
    fn snapshot() -> TrustListSnapshotV1 {
        let role = TrustRole::CredentialAuthority;
        TrustListSnapshotV1 {
            format_version: 1,
            sequence: 3,
            issued_at: 100_000,
            expires_at: 200_000,
            activation_at: 100_500,
            previous_snapshot_digest: Some([7u8; 32]),
            active_roles: BTreeSet::from([role]),
            entries: vec![olympus_crypto::trust_list::TrustedIssuerEntry {
                pubkey: key(1),
                roles: BTreeSet::from([role, TrustRole::RealmAuthority]),
                valid_from: 100_100,
                valid_until: 180_000,
            }],
            rotation_policies: BTreeMap::from([(
                role,
                RotationPolicy {
                    profile: RotationPolicyProfile::Production,
                    signers: vec![key(10), key(11)],
                    threshold: 2,
                },
            )]),
            recovery_keys: BTreeMap::from([(role, key(200))]),
        }
    }

    fn resolver_at(now: &'static AtomicI64, max_age: Option<i64>) -> SnapshotTrustResolver {
        let snap = snapshot();
        let digest = snapshot_digest(&snap);
        SnapshotTrustResolver::with_clock(
            snap,
            digest,
            TrustFreshnessConfig {
                max_age: match max_age {
                    Some(s) => FreshnessLimit::Limited(s),
                    None => FreshnessLimit::Unset,
                },
                max_lifetime: FreshnessLimit::Unset,
            },
            Arc::new(|| now.load(Ordering::SeqCst)),
        )
    }

    #[test]
    fn resolves_roles_and_windows_while_fresh() {
        static NOW: AtomicI64 = AtomicI64::new(101_000);
        let resolver = resolver_at(&NOW, Some(50_000));

        let role = TrustRole::CredentialAuthority;
        assert!(resolver.issuer_is_active_for(&key(1), role, 101_000));
        // Outside the issuer window.
        assert!(!resolver.issuer_is_active_for(&key(1), role, 100_099));
        assert!(!resolver.issuer_is_active_for(&key(1), role, 180_000));
        // Unknown key.
        assert!(!resolver.issuer_is_active_for(&key(9), role, 101_000));
        // Granted-but-inactive role gives nothing (ADR-0041 §1).
        assert!(!resolver.issuer_is_active_for(&key(1), TrustRole::RealmAuthority, 101_000));
        assert!(resolver
            .active_issuers_for(TrustRole::RealmAuthority, 101_000)
            .is_empty());

        assert_eq!(
            resolver
                .active_issuers_for(role, 101_000)
                .into_iter()
                .map(|e| e.pubkey)
                .collect::<Vec<_>>(),
            vec![key(1)]
        );
        assert_eq!(resolver.snapshot_sequence(), 3);
        assert_eq!(resolver.snapshot_digest(), snapshot_digest(&snapshot()));
    }

    #[test]
    fn continuous_max_age_fails_closed_mid_lifetime() {
        // Security invariant 18: the SAME resolver instance answers before
        // the max-age boundary and goes dark after it — with expires_at
        // (200_000) still far in the future — purely because the wall clock
        // advanced.
        static NOW: AtomicI64 = AtomicI64::new(101_000);
        let resolver = resolver_at(&NOW, Some(50_000));
        let role = TrustRole::CredentialAuthority;

        assert!(resolver.issuer_is_active_for(&key(1), role, 101_000));
        assert!(!resolver.active_issuers_for(role, 101_000).is_empty());

        // Cross the max-age boundary: issued_at 100_000 + max_age 50_000.
        NOW.store(150_001, Ordering::SeqCst);
        assert!(
            !resolver.issuer_is_active_for(&key(1), role, 101_000),
            "stale snapshot must fail closed even for a historical `at`"
        );
        assert!(resolver.active_issuers_for(role, 101_000).is_empty());

        // Identity getters are not trust decisions and stay readable for
        // diagnostics.
        assert_eq!(resolver.snapshot_sequence(), 3);

        // Step back before the boundary: fresh again (the gate is a pure
        // function of the clock, holding no latched state).
        NOW.store(150_000, Ordering::SeqCst);
        assert!(resolver.issuer_is_active_for(&key(1), role, 101_000));
    }

    #[test]
    fn expiry_fails_closed_even_without_a_configured_max_age() {
        static NOW: AtomicI64 = AtomicI64::new(199_999);
        let resolver = resolver_at(&NOW, None);
        let role = TrustRole::CredentialAuthority;
        assert!(resolver.issuer_is_active_for(&key(1), role, 101_000));
        NOW.store(200_000, Ordering::SeqCst);
        assert!(!resolver.issuer_is_active_for(&key(1), role, 101_000));
    }
}

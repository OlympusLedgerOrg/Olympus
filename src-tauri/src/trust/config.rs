// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Trust-list freshness configuration (ADR-0041 §4), resolved once at
//! startup.
//!
//! Two operator bounds govern how long a signed snapshot may remain
//! load-bearing:
//!
//! * `OLYMPUS_TRUST_LIST_MAX_AGE_SECS` — the continuous decision-time cap on
//!   `now - issued_at`. This is **not** an acceptance-time check: every trust
//!   decision re-evaluates it and fails closed once exceeded, even while
//!   `expires_at` is still in the future (security invariant 18).
//! * `OLYMPUS_TRUST_LIST_MAX_LIFETIME_SECS` — the cap on a snapshot's own
//!   declared `expires_at - issued_at`.
//!
//! Both are **required in production once an accepted genesis exists** —
//! reconciliation fails (exit 2) rather than running an unbounded trust
//! list. Before genesis exists the snapshot machinery is inert, so the
//! variables are not demanded from today's deployments. Development relaxes
//! a missing value to "unbounded" with a warning (ADR-0041 §4 permits
//! relaxing *missing freshness configuration* in dev — never signature,
//! predecessor, equivocation, or canonicalization failures).
//!
//! A present-but-invalid value is deliberately tracked as [`FreshnessLimit::Invalid`]
//! rather than silently falling back: for `OLYMPUS_MMD_SECONDS` a garbage
//! value degrades to a sane default policy, but a garbage *security bound*
//! degrading to "unbounded" would disable rollback/staleness protection with
//! no signal, so production refuses it.

use olympus_crypto::trust_list::TrustListSnapshotV1;

/// Env var: continuous maximum age (seconds) of an Accepted/Active snapshot.
pub const TRUST_LIST_MAX_AGE_ENV: &str = "OLYMPUS_TRUST_LIST_MAX_AGE_SECS";
/// Env var: maximum declared lifetime (seconds) of a snapshot.
pub const TRUST_LIST_MAX_LIFETIME_ENV: &str = "OLYMPUS_TRUST_LIST_MAX_LIFETIME_SECS";

/// Tolerated backward clock skew when judging `now >= issued_at` (ADR-0041
/// §4's `permitted_clock_skew`). Five minutes: generous enough that ordinary
/// NTP drift between the machine that signed a snapshot and the machine
/// accepting it never rejects an honest just-issued snapshot, and far too
/// small to matter against the hours-to-days scale of real max-age policy.
pub const PERMITTED_CLOCK_SKEW_SECS: i64 = 300;

/// One resolved freshness bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshnessLimit {
    /// Variable absent. Dev: unbounded (warned). Prod + genesis: fatal.
    Unset,
    /// Variable present but not a positive integer — never silently
    /// unbounded; carries the raw value for the operator-facing error.
    Invalid(String),
    /// A positive number of seconds.
    Limited(i64),
}

impl FreshnessLimit {
    /// The enforceable bound, if any. `Invalid` yields `None` here — callers
    /// that must distinguish it (production reconciliation) match on the
    /// variant instead.
    pub fn seconds(&self) -> Option<i64> {
        match self {
            FreshnessLimit::Limited(s) => Some(*s),
            FreshnessLimit::Unset | FreshnessLimit::Invalid(_) => None,
        }
    }
}

/// Freshness configuration resolved once at startup (the
/// `mmd::MmdPolicy::from_env` pattern: env read at the boundary, parsing
/// pure and testable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustFreshnessConfig {
    pub max_age: FreshnessLimit,
    pub max_lifetime: FreshnessLimit,
}

impl TrustFreshnessConfig {
    pub fn from_env() -> Self {
        Self {
            max_age: Self::parse(std::env::var(TRUST_LIST_MAX_AGE_ENV).ok().as_deref()),
            max_lifetime: Self::parse(std::env::var(TRUST_LIST_MAX_LIFETIME_ENV).ok().as_deref()),
        }
    }

    /// Pure parsing behind [`Self::from_env`]. A bound must be a positive
    /// integer number of seconds; zero and negatives are `Invalid` (a
    /// zero-second max age would reject every snapshot ever issued, which is
    /// a misconfiguration to surface, not a policy to enforce).
    fn parse(raw: Option<&str>) -> FreshnessLimit {
        match raw {
            None => FreshnessLimit::Unset,
            Some(v) => match v.trim().parse::<i64>() {
                Ok(n) if n > 0 => FreshnessLimit::Limited(n),
                _ => FreshnessLimit::Invalid(v.to_owned()),
            },
        }
    }

    /// Production-fatal configuration problems, as operator-facing reasons.
    /// Empty in a correctly configured production environment. Only consulted
    /// once an accepted genesis exists (see the module docs).
    pub fn production_errors(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (name, limit) in [
            (TRUST_LIST_MAX_AGE_ENV, &self.max_age),
            (TRUST_LIST_MAX_LIFETIME_ENV, &self.max_lifetime),
        ] {
            match limit {
                FreshnessLimit::Limited(_) => {}
                FreshnessLimit::Unset => out.push(format!(
                    "{name} is required in production once an accepted trust genesis exists \
                     (ADR-0041 §4)"
                )),
                FreshnessLimit::Invalid(raw) => out.push(format!(
                    "{name}={raw:?} is not a positive integer number of seconds"
                )),
            }
        }
        out
    }
}

/// Why a snapshot fails the continuous ADR-0041 §4 freshness conditions at a
/// given decision time. `None` from [`snapshot_freshness_violation`] means
/// every configured condition holds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FreshnessViolation {
    #[error(
        "snapshot issued_at {issued_at} is implausibly future-dated \
         (now {now}, permitted skew {PERMITTED_CLOCK_SKEW_SECS}s)"
    )]
    FutureDated { issued_at: i64, now: i64 },
    #[error("snapshot expired at {expires_at} (now {now})")]
    Expired { expires_at: i64, now: i64 },
    #[error(
        "snapshot age {age}s exceeds {TRUST_LIST_MAX_AGE_ENV}={max_age}s — \
         stale even though expires_at has not passed (security invariant 18)"
    )]
    TooOld { age: i64, max_age: i64 },
    #[error("snapshot lifetime {lifetime}s exceeds {TRUST_LIST_MAX_LIFETIME_ENV}={max_lifetime}s")]
    LifetimeTooLong { lifetime: i64, max_lifetime: i64 },
}

/// Evaluate the continuous freshness conditions of ADR-0041 §4 for
/// `snapshot` at decision time `now`:
///
/// ```text
/// now >= issued_at - permitted_clock_skew
/// now <  expires_at
/// now -  issued_at <= max_age          (when configured)
/// expires_at - issued_at <= max_lifetime  (when configured)
/// ```
///
/// Shared by acceptance, activation, startup reconciliation, and the
/// resolver's per-decision staleness gate, so "fresh" cannot drift between
/// the write path and the read path.
pub fn snapshot_freshness_violation(
    snapshot: &TrustListSnapshotV1,
    now: i64,
    config: &TrustFreshnessConfig,
) -> Option<FreshnessViolation> {
    if now < snapshot.issued_at.saturating_sub(PERMITTED_CLOCK_SKEW_SECS) {
        return Some(FreshnessViolation::FutureDated {
            issued_at: snapshot.issued_at,
            now,
        });
    }
    if now >= snapshot.expires_at {
        return Some(FreshnessViolation::Expired {
            expires_at: snapshot.expires_at,
            now,
        });
    }
    if let Some(max_age) = config.max_age.seconds() {
        let age = now.saturating_sub(snapshot.issued_at);
        if age > max_age {
            return Some(FreshnessViolation::TooOld { age, max_age });
        }
    }
    if let Some(max_lifetime) = config.max_lifetime.seconds() {
        let lifetime = snapshot.expires_at.saturating_sub(snapshot.issued_at);
        if lifetime > max_lifetime {
            return Some(FreshnessViolation::LifetimeTooLong {
                lifetime,
                max_lifetime,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use olympus_crypto::trust_list::{TrustListSnapshotV1, TrustRole};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn parse_distinguishes_unset_invalid_and_valid() {
        assert_eq!(TrustFreshnessConfig::parse(None), FreshnessLimit::Unset);
        assert_eq!(
            TrustFreshnessConfig::parse(Some("86400")),
            FreshnessLimit::Limited(86_400)
        );
        assert_eq!(
            TrustFreshnessConfig::parse(Some("  86400  ")),
            FreshnessLimit::Limited(86_400),
            "trimmed value wins"
        );
        // Zero, negatives, and garbage are Invalid — NOT unbounded.
        for raw in ["0", "-5", "1d", "", "many"] {
            assert_eq!(
                TrustFreshnessConfig::parse(Some(raw)),
                FreshnessLimit::Invalid(raw.to_owned()),
                "{raw:?} must be Invalid"
            );
        }
    }

    #[test]
    fn production_errors_flag_unset_and_invalid_bounds() {
        let ok = TrustFreshnessConfig {
            max_age: FreshnessLimit::Limited(1),
            max_lifetime: FreshnessLimit::Limited(2),
        };
        assert!(ok.production_errors().is_empty());

        let broken = TrustFreshnessConfig {
            max_age: FreshnessLimit::Unset,
            max_lifetime: FreshnessLimit::Invalid("1d".into()),
        };
        let errors = broken.production_errors();
        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains(TRUST_LIST_MAX_AGE_ENV));
        assert!(errors[1].contains(TRUST_LIST_MAX_LIFETIME_ENV));
    }

    /// Minimal snapshot for freshness-window tests; only the timestamps
    /// matter to `snapshot_freshness_violation`.
    fn snapshot(issued_at: i64, expires_at: i64) -> TrustListSnapshotV1 {
        TrustListSnapshotV1 {
            format_version: 1,
            sequence: 1,
            issued_at,
            expires_at,
            activation_at: issued_at,
            previous_snapshot_digest: None,
            active_roles: BTreeSet::<TrustRole>::new(),
            entries: Vec::new(),
            rotation_policies: BTreeMap::new(),
            recovery_keys: BTreeMap::new(),
        }
    }

    fn config(max_age: Option<i64>, max_lifetime: Option<i64>) -> TrustFreshnessConfig {
        let limit = |v: Option<i64>| match v {
            Some(s) => FreshnessLimit::Limited(s),
            None => FreshnessLimit::Unset,
        };
        TrustFreshnessConfig {
            max_age: limit(max_age),
            max_lifetime: limit(max_lifetime),
        }
    }

    #[test]
    fn freshness_violations_carry_their_reason() {
        let snap = snapshot(1_000_000, 1_100_000);

        // Future-dated beyond skew.
        assert!(matches!(
            snapshot_freshness_violation(
                &snap,
                1_000_000 - PERMITTED_CLOCK_SKEW_SECS - 1,
                &config(None, None)
            ),
            Some(FreshnessViolation::FutureDated { .. })
        ));
        // Exactly at the skew boundary is accepted.
        assert_eq!(
            snapshot_freshness_violation(
                &snap,
                1_000_000 - PERMITTED_CLOCK_SKEW_SECS,
                &config(None, None)
            ),
            None
        );

        // Expiry is half-open: now == expires_at is already expired.
        assert!(matches!(
            snapshot_freshness_violation(&snap, 1_100_000, &config(None, None)),
            Some(FreshnessViolation::Expired { .. })
        ));
        assert_eq!(
            snapshot_freshness_violation(&snap, 1_099_999, &config(None, None)),
            None
        );

        // Security invariant 18: max age bites while expires_at is still in
        // the future.
        assert!(matches!(
            snapshot_freshness_violation(&snap, 1_050_001, &config(Some(50_000), None)),
            Some(FreshnessViolation::TooOld {
                age: 50_001,
                max_age: 50_000
            })
        ));
        assert_eq!(
            snapshot_freshness_violation(&snap, 1_050_000, &config(Some(50_000), None)),
            None,
            "age exactly at the bound is still fresh"
        );

        // Declared lifetime over the configured maximum.
        assert!(matches!(
            snapshot_freshness_violation(&snap, 1_000_100, &config(None, Some(99_999))),
            Some(FreshnessViolation::LifetimeTooLong {
                lifetime: 100_000,
                max_lifetime: 99_999
            })
        ));
        assert_eq!(
            snapshot_freshness_violation(&snap, 1_000_100, &config(None, Some(100_000))),
            None
        );
    }
}

//! Trusted-issuer set for SBT scope resolution.
//!
//! Audit M-3: the v0.9 scope resolver originally accepted exactly one BJJ
//! authority pubkey — the bootstrap-minted `olympus:system` key. If that
//! key was ever lost, leaked, or rotated, every existing SBT became
//! unverifiable in one shot. This module lets operators carry additional,
//! historical, or rotation-window issuer pubkeys without losing any
//! existing credentials.
//!
//! ## Loading
//!
//! At startup `main.rs` calls [`load_trusted_issuers`]. The function:
//!
//! 1. Builds the primary entry from `bjj_authority_pubkey` (the bootstrap
//!    key) with no validity window — the bootstrap key is *always* trusted
//!    for the lifetime of this process unless explicitly revoked offline.
//! 2. Reads `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` (a JSON array of entries,
//!    `[{"x":"...","y":"...","valid_from":<unix?>,"valid_until":<unix?>}]`)
//!    and appends each parsed entry whose coordinates parse and whose
//!    window (if set) is non-degenerate.
//! 3. De-duplicates by `(x, y)` keeping the first occurrence — so the
//!    primary entry always wins over an env-loaded duplicate.
//!
//! ## Scope-resolver use
//!
//! `auth.rs::resolve_sbt_scopes` walks the resolved set, and for each row
//! accepts the *first* issuer pubkey whose `(x, y)` matches the row's
//! `issuer_pubkey_{x,y}` AND whose validity window (if set) covers the
//! row's `issued_at`. A signature check still runs against that issuer's
//! pubkey — i.e. presence in the trusted set is necessary but not
//! sufficient.

use serde::Deserialize;

use crate::zk::witness::baby_jubjub::BabyJubJubPubKey;

/// A single trusted issuer entry with an optional validity window.
#[derive(Debug, Clone)]
pub struct TrustedIssuer {
    pub pubkey: BabyJubJubPubKey,
    /// Pre-canonicalised decimal `x` coordinate. Cached so the resolver
    /// can string-compare without re-parsing per row.
    pub x_dec: String,
    /// Pre-canonicalised decimal `y` coordinate.
    pub y_dec: String,
    /// Earliest `issued_at` (Unix seconds) this issuer was authorised to
    /// sign. `None` = always-valid lower bound.
    pub valid_from: Option<i64>,
    /// Latest `issued_at` (Unix seconds) this issuer was authorised to
    /// sign. `None` = always-valid upper bound.
    pub valid_until: Option<i64>,
}

impl TrustedIssuer {
    /// True iff this issuer was authorised at `issued_at_unix`.
    pub fn covers(&self, issued_at_unix: i64) -> bool {
        if let Some(lo) = self.valid_from {
            if issued_at_unix < lo {
                return false;
            }
        }
        if let Some(hi) = self.valid_until {
            if issued_at_unix > hi {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    x: String,
    y: String,
    #[serde(default)]
    valid_from: Option<i64>,
    #[serde(default)]
    valid_until: Option<i64>,
}

/// Env var name carrying additional trusted-issuer entries (JSON array).
pub const TRUSTED_ISSUERS_ENV: &str = "OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON";

/// Load the trusted-issuer set. The bootstrap-minted `primary` is always
/// the first entry. Returns an empty Vec when no primary is configured —
/// callers (the scope resolver) treat that as "no SBT-derived scopes".
pub fn load_trusted_issuers(primary: Option<&BabyJubJubPubKey>) -> Vec<TrustedIssuer> {
    let mut out: Vec<TrustedIssuer> = Vec::new();
    if let Some(p) = primary {
        out.push(TrustedIssuer {
            pubkey: BabyJubJubPubKey { x: p.x, y: p.y },
            x_dec: fr_to_decimal(&p.x),
            y_dec: fr_to_decimal(&p.y),
            valid_from: None,
            valid_until: None,
        });
    }

    if let Ok(raw) = std::env::var(TRUSTED_ISSUERS_ENV) {
        match serde_json::from_str::<Vec<RawEntry>>(&raw) {
            Ok(entries) => {
                for e in entries {
                    let Some(issuer) = parse_entry(&e) else {
                        tracing::warn!(
                            "trusted_issuers: dropping malformed entry (x={}, y={}) from {TRUSTED_ISSUERS_ENV}",
                            e.x, e.y
                        );
                        continue;
                    };
                    if out
                        .iter()
                        .any(|i| i.x_dec == issuer.x_dec && i.y_dec == issuer.y_dec)
                    {
                        continue;
                    }
                    out.push(issuer);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "trusted_issuers: failed to parse {TRUSTED_ISSUERS_ENV} as JSON array: {e}"
                );
            }
        }
    }

    out
}

fn parse_entry(e: &RawEntry) -> Option<TrustedIssuer> {
    use crate::api::credentials::parse_fr_decimal;
    let x = parse_fr_decimal(&e.x)?;
    let y = parse_fr_decimal(&e.y)?;
    // Non-degenerate window.
    if let (Some(lo), Some(hi)) = (e.valid_from, e.valid_until) {
        if lo > hi {
            return None;
        }
    }
    Some(TrustedIssuer {
        pubkey: BabyJubJubPubKey { x, y },
        x_dec: fr_to_decimal(&x),
        y_dec: fr_to_decimal(&y),
        valid_from: e.valid_from,
        valid_until: e.valid_until,
    })
}

use crate::zk::proof::fr_to_decimal;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    fn pubkey(x: u64, y: u64) -> BabyJubJubPubKey {
        BabyJubJubPubKey {
            x: Fr::from(x),
            y: Fr::from(y),
        }
    }

    #[test]
    fn empty_when_no_primary_and_no_env() {
        // Ensure env var is unset for this test.
        std::env::remove_var(TRUSTED_ISSUERS_ENV);
        assert!(load_trusted_issuers(None).is_empty());
    }

    #[test]
    fn primary_is_always_first_and_has_no_window() {
        std::env::remove_var(TRUSTED_ISSUERS_ENV);
        let p = pubkey(7, 11);
        let v = load_trusted_issuers(Some(&p));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].x_dec, "7");
        assert_eq!(v[0].y_dec, "11");
        assert!(v[0].valid_from.is_none());
        assert!(v[0].valid_until.is_none());
    }

    #[test]
    fn covers_respects_window_bounds() {
        let i = TrustedIssuer {
            pubkey: pubkey(1, 2),
            x_dec: "1".into(),
            y_dec: "2".into(),
            valid_from: Some(100),
            valid_until: Some(200),
        };
        assert!(!i.covers(99));
        assert!(i.covers(100));
        assert!(i.covers(150));
        assert!(i.covers(200));
        assert!(!i.covers(201));
    }

    #[test]
    fn covers_unbounded_window_accepts_everything() {
        let i = TrustedIssuer {
            pubkey: pubkey(1, 2),
            x_dec: "1".into(),
            y_dec: "2".into(),
            valid_from: None,
            valid_until: None,
        };
        assert!(i.covers(i64::MIN));
        assert!(i.covers(0));
        assert!(i.covers(i64::MAX));
    }
}

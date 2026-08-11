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
//!    `[{"x":"...","y":"...","valid_from":<unix?>,"valid_until":<unix?>,
//!    "roles":[<tag>...]?}]`) and appends each parsed entry whose
//!    coordinates parse, whose window (if set) is non-degenerate, and
//!    whose optional `roles` tags all parse.
//! 3. De-duplicates by `(x, y)` keeping the first occurrence — so the
//!    primary entry always wins over an env-loaded duplicate.
//!
//! ## Roles (ADR-0041 subset)
//!
//! Every entry carries a set of [`TrustRole`] grants. An env entry may
//! restrict itself with a `"roles"` array of ADR-0041 wire tags
//! (`"credential_authority"`, `"ceremony_coordinator"`, …, exactly
//! `TrustRole::wire_tag`), so e.g. a ceremony-coordinator key can be listed
//! without implicitly becoming a trusted SBT issuer. An **absent or empty**
//! `roles` array grants ALL roles — the pre-role-separation status quo, so
//! every existing deployment keeps working unchanged. An entry naming an
//! unknown role tag is dropped with a warning (fail closed, like any other
//! malformed entry). The bootstrap primary and authority-registry rows
//! always carry all roles (the single-key deployment status quo).
//! Role-scoped consumers filter the shared set with [`issuers_for_role`] /
//! [`TrustedIssuer::has_role`].
//!
//! ## Scope-resolver use
//!
//! `auth.rs::resolve_sbt_scopes` walks the resolved set, and for each row
//! accepts the *first* issuer pubkey that grants
//! `TrustRole::CredentialAuthority`, whose `(x, y)` matches the row's
//! `issuer_pubkey_{x,y}` AND whose validity window (if set) covers the
//! row's `issued_at`. A signature check still runs against that issuer's
//! pubkey — i.e. presence in the trusted set is necessary but not
//! sufficient.

use olympus_crypto::trust_list::TrustRole;
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
    /// [`TrustRole`] grants (ADR-0041 subset). An **empty** vector means
    /// ALL roles — the pre-role-separation default carried by the bootstrap
    /// primary, authority-registry rows, and env entries without a
    /// `"roles"` array. A non-empty vector restricts this issuer to exactly
    /// the listed roles.
    pub roles: Vec<TrustRole>,
}

impl TrustedIssuer {
    /// True iff this issuer is granted `role`. An empty [`Self::roles`]
    /// vector grants every role (see the field docs).
    pub fn has_role(&self, role: TrustRole) -> bool {
        self.roles.is_empty() || self.roles.contains(&role)
    }

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

/// Issuers in `issuers` granting `role`, in set order.
///
/// The shared `AppState` set stays role-unsplit; each verification site
/// narrows it through this filter (or [`TrustedIssuer::has_role`] inline)
/// so a coordinator-only entry never doubles as, say, a credential issuer.
pub fn issuers_for_role(
    issuers: &[TrustedIssuer],
    role: TrustRole,
) -> impl Iterator<Item = &TrustedIssuer> {
    issuers.iter().filter(move |i| i.has_role(role))
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    x: String,
    y: String,
    #[serde(default)]
    valid_from: Option<i64>,
    #[serde(default)]
    valid_until: Option<i64>,
    /// Optional ADR-0041 role tags ([`TrustRole::wire_tag`] strings).
    /// Absent (or empty) = all roles.
    #[serde(default)]
    roles: Option<Vec<String>>,
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
            // Bootstrap primary: ALL roles (the single-key deployment
            // status quo — empty = all, see the field docs).
            roles: Vec::new(),
        });
    }

    if let Ok(raw) = std::env::var(TRUSTED_ISSUERS_ENV) {
        for issuer in entries_from_env_json(&raw) {
            if out
                .iter()
                .any(|i| i.x_dec == issuer.x_dec && i.y_dec == issuer.y_dec)
            {
                continue;
            }
            out.push(issuer);
        }
    }

    out
}

/// Parse the `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` payload into issuer entries.
///
/// Malformed JSON, and individually malformed entries (bad coordinates,
/// degenerate windows, unknown role tags), are dropped with a
/// `tracing::warn!` — fail closed, never a startup failure. Factored out of
/// [`load_trusted_issuers`] so entry parsing is testable without mutating
/// process-global env vars.
fn entries_from_env_json(raw: &str) -> Vec<TrustedIssuer> {
    match serde_json::from_str::<Vec<RawEntry>>(raw) {
        Ok(entries) => entries
            .iter()
            .filter_map(|e| {
                let issuer = parse_entry(e);
                if issuer.is_none() {
                    tracing::warn!(
                        "trusted_issuers: dropping malformed entry (x={}, y={}) from {TRUSTED_ISSUERS_ENV}",
                        e.x, e.y
                    );
                }
                issuer
            })
            .collect(),
        Err(e) => {
            tracing::warn!(
                "trusted_issuers: failed to parse {TRUSTED_ISSUERS_ENV} as JSON array: {e}"
            );
            Vec::new()
        }
    }
}

/// Load the full trusted-issuer set: bootstrap primary (entry 0, unbounded)
/// → env-var entries (operator overrides win over registry rows on the same
/// pubkey via first-wins dedup) → authority-registry rows from
/// `account_signing_keys` (the supersession chain written by
/// `bootstrap::rotate_authority`; migration 0056). Registry rows carry their
/// `valid_from`/`valid_until` windows — a revoked predecessor falls back to
/// `revoked_at` as its upper bound when `valid_until` was never stamped — so
/// credentials issued under a retired authority keep verifying without the
/// operator hand-crafting `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` entries.
pub async fn load_trusted_issuers_with_registry(
    primary: Option<&BabyJubJubPubKey>,
    pool: Option<&sqlx::PgPool>,
) -> Vec<TrustedIssuer> {
    let mut out = load_trusted_issuers(primary);
    let Some(pool) = pool else {
        return out;
    };
    /// `(x_dec, y_dec, valid_from, valid_until, revoked_at)` as stored on an
    /// authority registry row.
    type RegistryRow = (
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<chrono::DateTime<chrono::Utc>>,
    );
    let rows: Vec<RegistryRow> = match sqlx::query_as(
        "SELECT bjj_pubkey_x, bjj_pubkey_y, valid_from, valid_until, revoked_at
           FROM account_signing_keys
          WHERE purpose = 'authority' AND bjj_pubkey_x IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("trusted_issuers: registry query failed ({e}) — env-only set in use");
            return out;
        }
    };
    // Env entries are operator overrides: any registry interval for coords the
    // env var names is dropped in its favour (e.g. bounding a compromised key
    // earlier than its rotation time). The primary is different — when the
    // ACTIVE registry row matches it, its window is tightened to the
    // registry-recorded one instead of staying unbounded, so the active key
    // does not cover timestamps from before it became the authority.
    let primary_dec = primary.map(|p| (fr_to_decimal(&p.x), fr_to_decimal(&p.y)));
    let env_start = usize::from(primary_dec.is_some());
    let env_coords: std::collections::HashSet<(String, String)> = out[env_start..]
        .iter()
        .map(|i| (i.x_dec.clone(), i.y_dec.clone()))
        .collect();
    for (x, y, valid_from, valid_until, revoked_at) in rows {
        let entry = RawEntry {
            x,
            y,
            valid_from: valid_from.map(|t| t.timestamp()),
            valid_until: valid_until.or(revoked_at).map(|t| t.timestamp()),
            // Registry rows: ALL roles (the single-key deployment status
            // quo — the registry records authority supersession, not
            // role-scoped grants).
            roles: None,
        };
        let Some(issuer) = parse_entry(&entry) else {
            tracing::warn!(
                "trusted_issuers: dropping malformed registry row (x={}, y={})",
                entry.x,
                entry.y
            );
            continue;
        };
        if env_coords.contains(&(issuer.x_dec.clone(), issuer.y_dec.clone())) {
            continue;
        }
        if revoked_at.is_none()
            && primary_dec
                .as_ref()
                .is_some_and(|(px, py)| *px == issuer.x_dec && *py == issuer.y_dec)
        {
            out[0].valid_from = issuer.valid_from;
            out[0].valid_until = issuer.valid_until;
            continue;
        }
        // Retired intervals are pushed even when their coordinates repeat
        // (A→B→A re-adoption yields two disjoint windows for A); every
        // consumer scans the whole set with `covers`, so multiple entries
        // per pubkey compose correctly.
        if out.iter().any(|i| {
            i.x_dec == issuer.x_dec
                && i.y_dec == issuer.y_dec
                && i.valid_from == issuer.valid_from
                && i.valid_until == issuer.valid_until
        }) {
            continue;
        }
        out.push(issuer);
    }
    out
}

fn parse_entry(e: &RawEntry) -> Option<TrustedIssuer> {
    use crate::api::credentials::parse_fr_decimal;
    let x = parse_fr_decimal(&e.x)?;
    let y = parse_fr_decimal(&e.y)?;
    // Reject identity / off-curve / wrong-subgroup keys outright — a trusted
    // issuer that fails BJJ subgroup validation could never produce a valid
    // signature, and listing it would only mask a corrupt row or env entry.
    crate::zk::witness::baby_jubjub::validate_pubkey_subgroup(&BabyJubJubPubKey { x, y }).ok()?;
    // Non-degenerate window.
    if let (Some(lo), Some(hi)) = (e.valid_from, e.valid_until) {
        if lo > hi {
            return None;
        }
    }
    // ADR-0041 role tags. Absent/empty = all roles (empty Vec, see the
    // `TrustedIssuer::roles` docs). Any unknown tag drops the whole entry
    // (fail closed): silently ignoring it could either widen (tag meant to
    // restrict) or lose (typo of the intended grant) the operator's intent.
    let mut roles: Vec<TrustRole> = Vec::new();
    for tag in e.roles.as_deref().unwrap_or_default() {
        let Some(role) = TrustRole::from_wire_tag(tag) else {
            tracing::warn!(
                "trusted_issuers: unknown role tag {tag:?} on entry (x={}, y={})",
                e.x,
                e.y
            );
            return None;
        };
        if !roles.contains(&role) {
            roles.push(role);
        }
    }
    Some(TrustedIssuer {
        pubkey: BabyJubJubPubKey { x, y },
        x_dec: fr_to_decimal(&x),
        y_dec: fr_to_decimal(&y),
        valid_from: e.valid_from,
        valid_until: e.valid_until,
        roles,
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
        // The bootstrap primary carries ALL roles (single-key status quo).
        for role in TrustRole::ALL {
            assert!(v[0].has_role(role), "primary must grant {role:?}");
        }
    }

    /// Deterministic real Baby Jubjub key (subgroup-valid, unlike the raw
    /// `pubkey()` coordinates) so entries survive `parse_entry`'s
    /// `validate_pubkey_subgroup` gate. Returns `(x_dec, y_dec)`.
    fn real_key_dec(seed: u8) -> (String, String) {
        let pk = BabyJubJubPubKey::from_private(&[seed; 32]).expect("pubkey derive");
        (fr_to_decimal(&pk.x), fr_to_decimal(&pk.y))
    }

    #[test]
    fn env_entry_with_coordinator_role_grants_only_that_role() {
        let (x, y) = real_key_dec(0x41);
        let raw = format!(r#"[{{"x":"{x}","y":"{y}","roles":["ceremony_coordinator"]}}]"#);
        let v = entries_from_env_json(&raw);
        assert_eq!(v.len(), 1);
        assert!(v[0].has_role(TrustRole::CeremonyCoordinator));
        // The point of role separation: a coordinator-only key is NOT a
        // credential issuer (or anything else).
        assert!(!v[0].has_role(TrustRole::CredentialAuthority));
        assert!(!v[0].has_role(TrustRole::RevocationAuthority));
        assert!(!v[0].has_role(TrustRole::CheckpointAuthority));
        assert!(!v[0].has_role(TrustRole::FederationAuthority));
        assert!(!v[0].has_role(TrustRole::RealmAuthority));
    }

    #[test]
    fn env_entry_without_roles_grants_all_roles() {
        let (x, y) = real_key_dec(0x42);
        // Absent `roles` key…
        let absent = entries_from_env_json(&format!(r#"[{{"x":"{x}","y":"{y}"}}]"#));
        // …and an explicit empty array both mean ALL roles (back-compat).
        let empty = entries_from_env_json(&format!(r#"[{{"x":"{x}","y":"{y}","roles":[]}}]"#));
        for v in [absent, empty] {
            assert_eq!(v.len(), 1);
            for role in TrustRole::ALL {
                assert!(
                    v[0].has_role(role),
                    "unrestricted entry must grant {role:?}"
                );
            }
        }
    }

    #[test]
    fn env_entry_with_unknown_role_tag_is_dropped() {
        let (good_x, good_y) = real_key_dec(0x43);
        let (bad_x, bad_y) = real_key_dec(0x44);
        // "coordinator" is NOT a wire tag ("ceremony_coordinator" is): the
        // entry must be dropped entirely — fail closed — not granted all
        // roles, and not silently granted the tags that did parse.
        let raw = format!(
            r#"[{{"x":"{good_x}","y":"{good_y}","roles":["ceremony_coordinator"]}},
                {{"x":"{bad_x}","y":"{bad_y}","roles":["ceremony_coordinator","coordinator"]}}]"#
        );
        let v = entries_from_env_json(&raw);
        // The sibling valid entry survives, proving the drop is per-entry
        // (an unknown tag, not a whole-payload parse failure).
        assert_eq!(v.len(), 1);
        assert_eq!(
            (v[0].x_dec.as_str(), v[0].y_dec.as_str()),
            (good_x.as_str(), good_y.as_str())
        );
        assert!(
            !v.iter().any(|i| i.x_dec == bad_x && i.y_dec == bad_y),
            "entry with an unknown role tag must be absent from the set"
        );
    }

    #[test]
    fn registry_shaped_entry_carries_all_roles() {
        // `load_trusted_issuers_with_registry` builds each registry row as a
        // `RawEntry { roles: None, .. }` and feeds it through `parse_entry` —
        // this pins that `roles: None` shape to the all-roles grant.
        let (x, y) = real_key_dec(0x45);
        let issuer = parse_entry(&RawEntry {
            x,
            y,
            valid_from: Some(100),
            valid_until: Some(200),
            roles: None,
        })
        .expect("registry-shaped entry must parse");
        for role in TrustRole::ALL {
            assert!(issuer.has_role(role), "registry row must grant {role:?}");
        }
    }

    #[test]
    fn issuers_for_role_separates_coordinator_from_credential_authority() {
        let all_roles = TrustedIssuer {
            pubkey: pubkey(1, 2),
            x_dec: "1".into(),
            y_dec: "2".into(),
            valid_from: None,
            valid_until: None,
            roles: Vec::new(),
        };
        let coordinator_only = TrustedIssuer {
            pubkey: pubkey(3, 4),
            x_dec: "3".into(),
            y_dec: "4".into(),
            valid_from: None,
            valid_until: None,
            roles: vec![TrustRole::CeremonyCoordinator],
        };
        let set = vec![all_roles, coordinator_only];

        let credential: Vec<&str> = issuers_for_role(&set, TrustRole::CredentialAuthority)
            .map(|i| i.x_dec.as_str())
            .collect();
        assert_eq!(
            credential,
            vec!["1"],
            "coordinator-only entry must be excluded from CredentialAuthority"
        );

        let coordinator: Vec<&str> = issuers_for_role(&set, TrustRole::CeremonyCoordinator)
            .map(|i| i.x_dec.as_str())
            .collect();
        assert_eq!(
            coordinator,
            vec!["1", "3"],
            "both the all-roles and the coordinator-only entry serve CeremonyCoordinator"
        );
    }

    #[test]
    fn covers_respects_window_bounds() {
        let i = TrustedIssuer {
            pubkey: pubkey(1, 2),
            x_dec: "1".into(),
            y_dec: "2".into(),
            valid_from: Some(100),
            valid_until: Some(200),
            roles: Vec::new(),
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
            roles: Vec::new(),
        };
        assert!(i.covers(i64::MIN));
        assert!(i.covers(0));
        assert!(i.covers(i64::MAX));
    }
}

//! Unit tests for the user-auth module (moved verbatim from the former
//! single-file `mod.rs` `#[cfg(test)] mod tests`).

use std::collections::HashSet;

use axum::http::StatusCode;

use super::helpers::{
    normalize_email, should_bootstrap_public_admin, validate_scopes, DEFAULT_EXPIRY_DAYS,
    VALID_SCOPES,
};
use super::types::{default_expiry, parse_expires};

#[test]
fn default_expiry_is_short_window_not_year_2099() {
    let exp_str = default_expiry();
    let parsed = parse_expires(&exp_str).expect("default_expiry must be well-formed");
    let now = chrono::Utc::now().naive_utc();
    let delta = parsed.signed_duration_since(now);
    let days = delta.num_days();
    assert!(
        (DEFAULT_EXPIRY_DAYS - 1..=DEFAULT_EXPIRY_DAYS + 1).contains(&days),
        "default_expiry should land within ±1 day of DEFAULT_EXPIRY_DAYS \
         ({DEFAULT_EXPIRY_DAYS}); got {days} days from now"
    );
    // Belt-and-braces: the legacy sentinel year is never the default.
    assert!(
        !exp_str.starts_with("2099"),
        "default_expiry must not regress to the legacy year-2099 sentinel"
    );
}
#[test]
fn validate_scopes_rejects_unknown() {
    let allowed: HashSet<&str> = ["read", "verify"].iter().copied().collect();
    let res = validate_scopes(&["read".to_owned(), "bogus".to_owned()], &allowed, "test");
    assert!(res.is_err());
    let (status, _) = res.unwrap_err();
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[test]
fn validate_scopes_rejects_out_of_context() {
    let allowed: HashSet<&str> = ["read", "verify"].iter().copied().collect();
    let res = validate_scopes(&["admin".to_owned()], &allowed, "test");
    assert!(res.is_err());
    let (status, _) = res.unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
}
#[test]
fn prove_is_a_known_scope_on_auth_routes() {
    // Regression: the /auth/* scope list had drifted to omit `prove`, so the
    // scope was a 400 "unknown" everywhere in user-auth while both admin
    // routes accepted it. After unification on VALID_API_SCOPES it must be
    // *known* (403 out-of-context when the route's allowed-set excludes it,
    // never 400 unknown) and grantable when the allowed-set contains it.
    assert!(
        VALID_SCOPES.contains(&"prove"),
        "user-auth VALID_SCOPES must alias the crate-wide list including `prove`"
    );
    let allowed: HashSet<&str> = ["read", "verify"].iter().copied().collect();
    let res = validate_scopes(&["prove".to_owned()], &allowed, "test");
    let (status, _) = res.unwrap_err();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "`prove` outside the allowed-set must be out-of-context (403), not unknown (400)"
    );
    let allowed: HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let granted = validate_scopes(&["prove".to_owned()], &allowed, "test").unwrap();
    assert_eq!(granted, vec!["prove"]);
}

#[test]
fn validate_scopes_deduplicates() {
    let allowed: HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let scopes = vec!["read".to_owned(), "read".to_owned(), "verify".to_owned()];
    let result = validate_scopes(&scopes, &allowed, "test").unwrap();
    assert_eq!(result, vec!["read", "verify"]);
}

#[test]
fn configured_operator_key_disables_first_public_admin_bootstrap() {
    assert!(!should_bootstrap_public_admin(true, true));
    assert!(should_bootstrap_public_admin(true, false));
    assert!(!should_bootstrap_public_admin(false, false));
}

#[test]
fn normalize_email_trims_and_lowercases() {
    // Storage and every lookup go through this; casing/whitespace variants
    // must collapse to one canonical form so they map to a single account
    // (paired with the case-insensitive UNIQUE index in migration 0046).
    assert_eq!(normalize_email("  Alice@Example.COM "), "alice@example.com");
    assert_eq!(normalize_email("alice@example.com"), "alice@example.com");
    assert_eq!(
        normalize_email("Alice@Example.COM"),
        normalize_email("alice@example.com")
    );
}

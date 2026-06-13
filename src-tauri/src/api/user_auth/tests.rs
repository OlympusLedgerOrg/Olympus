//! Unit tests for the user-auth module (moved verbatim from the former
//! single-file `mod.rs` `#[cfg(test)] mod tests`).

use std::collections::HashSet;

use axum::http::StatusCode;

use super::helpers::{
    normalize_email, registration_approval_payload, validate_scopes, DEFAULT_EXPIRY_DAYS,
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
fn validate_scopes_deduplicates() {
    let allowed: HashSet<&str> = VALID_SCOPES.iter().copied().collect();
    let scopes = vec!["read".to_owned(), "read".to_owned(), "verify".to_owned()];
    let result = validate_scopes(&scopes, &allowed, "test").unwrap();
    assert_eq!(result, vec!["read", "verify"]);
}

#[test]
fn registration_approval_payload_is_canonical() {
    // The HMAC payload must be stable regardless of how the caller cased
    // the email or ordered/duplicated the scopes: email lowercased+trimmed,
    // scopes sorted + deduped, pipe-joined with the expiry. A drift here
    // would silently invalidate every admin-signed approval header.
    let p = registration_approval_payload(
        "  Alice@Example.COM ",
        &["verify".to_owned(), "read".to_owned(), "verify".to_owned()],
        "2099-01-01T00:00:00Z",
    );
    assert_eq!(p, "alice@example.com|read,verify|2099-01-01T00:00:00Z");
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

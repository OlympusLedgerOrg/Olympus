//! Resolve a Rekor transparency-log public key from Sigstore's vendored trust
//! root, so the key `rekor::verify_set` checks against has reviewed provenance
//! instead of being transcribed into an environment variable by hand.
//!
//! The bundle is embedded at compile time from
//! `src-tauri/vendor/sigstore/trusted_root.json`; see the `PROVENANCE.md` beside
//! it for the pin, how it was corroborated, and why this is vendored rather than
//! fetched through a runtime TUF client. Nothing here touches the network.
//!
//! Selection is keyed on the log's own identity, never on position or name:
//! Sigstore defines `logId = sha256(DER SubjectPublicKeyInfo)`, and Rekor echoes
//! that digest back as the hex `logID` on every entry. So the key used to verify
//! a receipt is the one the receipt itself names, and a receipt from a log this
//! bundle does not carry fails closed rather than falling back to some other key.

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::AnchorError;

/// Sigstore's trust bundle, pinned in-tree. See `vendor/sigstore/PROVENANCE.md`.
const TRUSTED_ROOT_JSON: &str = include_str!("../../vendor/sigstore/trusted_root.json");

/// The only algorithm `rekor::verify_set` can check. Sigstore's 2025 log is
/// Ed25519, which this resolver reports as unsupported rather than returning a
/// key the verifier would then misuse.
const SUPPORTED_KEY_DETAILS: &str = "PKIX_ECDSA_P256_SHA_256";

#[derive(Debug, Deserialize)]
struct TrustedRoot {
    #[serde(default)]
    tlogs: Vec<Tlog>,
}

#[derive(Debug, Deserialize)]
struct Tlog {
    #[serde(rename = "baseUrl", default)]
    base_url: String,
    #[serde(rename = "publicKey")]
    public_key: TlogPublicKey,
}

#[derive(Debug, Deserialize)]
struct TlogPublicKey {
    /// Base64 DER `SubjectPublicKeyInfo`.
    #[serde(rename = "rawBytes", default)]
    raw_bytes: String,
    #[serde(rename = "keyDetails", default)]
    key_details: String,
    #[serde(rename = "validFor", default)]
    valid_for: Option<ValidFor>,
}

/// RFC 3339 validity window. `end` absent means "still valid".
#[derive(Debug, Deserialize)]
struct ValidFor {
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
}

/// A transparency-log key resolved out of the bundle.
#[derive(Debug)]
pub struct ResolvedTlogKey {
    /// PEM `SubjectPublicKeyInfo`, the shape `verify_set` consumes.
    pub pem: String,
    /// Which log it came from, for operator-facing messages.
    pub base_url: String,
}

/// Parse an RFC 3339 timestamp into unix seconds.
///
/// Deliberately narrow: these are Sigstore-authored `validFor` bounds in the
/// vendored bundle, always `YYYY-MM-DDTHH:MM:SSZ`. A parser that silently
/// accepted something else would widen a validity window, so anything not
/// matching that exact shape is an error.
fn rfc3339_to_unix(value: &str) -> Result<i64, AnchorError> {
    let bad = || {
        AnchorError::Parse(format!(
            "sigstore trusted root: unparseable validFor timestamp {value:?}"
        ))
    };
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[19] != b'Z'
    {
        return Err(bad());
    }
    let num = |range: std::ops::Range<usize>| -> Result<i64, AnchorError> {
        value
            .get(range)
            .ok_or_else(bad)?
            .parse::<i64>()
            .map_err(|_| bad())
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return Err(bad());
    }

    // Days since the unix epoch (civil-from-days, Howard Hinnant's algorithm).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(days * 86_400 + h * 3_600 + mi * 60 + s)
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

/// Resolve the log key for a Rekor entry.
///
/// `log_id_hex` is the entry's `logID`; `integrated_time` is its
/// `integratedTime` in unix seconds, checked against the key's validity window
/// so a key rotated out cannot verify an entry from after its retirement (or a
/// backdated one from before it existed).
pub fn rekor_key_for(
    log_id_hex: &str,
    integrated_time: i64,
) -> Result<ResolvedTlogKey, AnchorError> {
    let root: TrustedRoot = serde_json::from_str(TRUSTED_ROOT_JSON)
        .map_err(|e| AnchorError::Parse(format!("sigstore trusted root is not parseable: {e}")))?;

    let wanted = log_id_hex.trim().to_ascii_lowercase();
    if wanted.is_empty() {
        return Err(AnchorError::Parse(
            "Rekor entry has an empty logID; cannot select a verification key".into(),
        ));
    }

    let mut seen_but_wrong_algorithm = None;
    let mut seen_but_out_of_window = None;

    for tlog in &root.tlogs {
        let der = base64::engine::general_purpose::STANDARD
            .decode(tlog.public_key.raw_bytes.as_bytes())
            .map_err(|e| {
                AnchorError::Parse(format!(
                    "sigstore trusted root: tlog {} has undecodable rawBytes: {e}",
                    tlog.base_url
                ))
            })?;
        // Sigstore's own identity relation. Recomputing it (rather than reading
        // the bundle's `logId` field) means a tampered bundle whose logId and
        // key disagree cannot steer us onto the wrong key.
        if hex::encode(Sha256::digest(&der)) != wanted {
            continue;
        }

        if let Some(window) = &tlog.public_key.valid_for {
            if let Some(start) = window.start.as_deref() {
                if integrated_time < rfc3339_to_unix(start)? {
                    seen_but_out_of_window = Some(tlog.base_url.clone());
                    continue;
                }
            }
            if let Some(end) = window.end.as_deref() {
                if integrated_time > rfc3339_to_unix(end)? {
                    seen_but_out_of_window = Some(tlog.base_url.clone());
                    continue;
                }
            }
        }

        if tlog.public_key.key_details != SUPPORTED_KEY_DETAILS {
            seen_but_wrong_algorithm =
                Some((tlog.base_url.clone(), tlog.public_key.key_details.clone()));
            continue;
        }

        return Ok(ResolvedTlogKey {
            pem: der_to_pem(&der),
            base_url: tlog.base_url.clone(),
        });
    }

    if let Some((base_url, algorithm)) = seen_but_wrong_algorithm {
        return Err(AnchorError::NotConfigured(format!(
            "Rekor log {base_url} (logID {wanted}) uses {algorithm}, which this build cannot \
             verify — signed entry timestamps are checked with ECDSA P-256 only. Supporting it \
             needs a verifier for that algorithm, not a re-vendored trust root."
        )));
    }
    if let Some(base_url) = seen_but_out_of_window {
        return Err(AnchorError::NotConfigured(format!(
            "Rekor log {base_url} (logID {wanted}) is in the vendored Sigstore trust root, but \
             its key was not valid at integratedTime {integrated_time}; refusing to verify a \
             receipt against a key outside its validity window."
        )));
    }
    Err(AnchorError::NotConfigured(format!(
        "no Rekor log with logID {wanted} in the vendored Sigstore trust root \
         (src-tauri/vendor/sigstore/trusted_root.json). If this is a private Rekor instance, set \
         OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM to its log key; if Sigstore has rotated, re-vendor the \
         trust root per vendor/sigstore/PROVENANCE.md."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public-good Rekor log, keyed by the logID Rekor stamps on entries.
    const REKOR_V1_LOG_ID: &str =
        "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";
    /// 2023-01-01T00:00:00Z — inside the P-256 log's window (opens 2021-01-12).
    const IN_WINDOW: i64 = 1_672_531_200;

    #[test]
    fn vendored_root_parses_and_every_log_id_matches_its_key() {
        let root: TrustedRoot = serde_json::from_str(TRUSTED_ROOT_JSON).expect("parse");
        assert!(!root.tlogs.is_empty(), "trust root carries no tlogs");
        for tlog in &root.tlogs {
            let der = base64::engine::general_purpose::STANDARD
                .decode(tlog.public_key.raw_bytes.as_bytes())
                .expect("rawBytes decodes");
            assert!(!der.is_empty(), "{} has an empty key", tlog.base_url);
            // Catches a truncated or malformed re-vendor.
            assert_eq!(hex::encode(Sha256::digest(&der)).len(), 64);
        }
    }

    #[test]
    fn resolves_the_public_good_rekor_key() {
        let key = rekor_key_for(REKOR_V1_LOG_ID, IN_WINDOW).expect("resolves");
        assert_eq!(key.base_url, "https://rekor.sigstore.dev");
        assert!(key.pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(key.pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
        // The PEM must be loadable by the verifier that will consume it.
        use p256::pkcs8::DecodePublicKey;
        p256::ecdsa::VerifyingKey::from_public_key_pem(&key.pem).expect("verifier accepts the PEM");
    }

    #[test]
    fn log_id_is_matched_case_insensitively() {
        let upper = REKOR_V1_LOG_ID.to_ascii_uppercase();
        assert_eq!(
            rekor_key_for(&upper, IN_WINDOW).expect("resolves").base_url,
            "https://rekor.sigstore.dev"
        );
    }

    #[test]
    fn unknown_log_id_fails_closed() {
        let err = rekor_key_for(&"ab".repeat(32), IN_WINDOW).expect_err("must not resolve");
        assert!(
            format!("{err}").contains("no Rekor log with logID"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn entry_predating_the_key_is_rejected() {
        // 2020-01-01, before the P-256 log's 2021-01-12 start.
        let err = rekor_key_for(REKOR_V1_LOG_ID, 1_577_836_800).expect_err("must not resolve");
        assert!(
            format!("{err}").contains("validity window"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn empty_log_id_is_rejected() {
        let err = rekor_key_for("   ", IN_WINDOW).expect_err("must not resolve");
        assert!(
            format!("{err}").contains("empty logID"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rfc3339_parses_known_instants() {
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            rfc3339_to_unix("2021-01-12T11:53:27Z").unwrap(),
            1_610_452_407
        );
        assert_eq!(
            rfc3339_to_unix("2025-09-23T00:00:00Z").unwrap(),
            1_758_585_600
        );
        for bad in ["", "2021-01-12", "2021-01-12T11:53:27+00:00", "not-a-time"] {
            assert!(rfc3339_to_unix(bad).is_err(), "{bad:?} must not parse");
        }
    }
}

// SPDX-License-Identifier: Apache-2.0

//! Resolve a Rekor transparency-log public key from Sigstore's vendored trust
//! root, so the key `rekor::verify_set` checks against has reviewed provenance
//! instead of being transcribed into an environment variable by hand.
//!
//! The bundle is embedded at compile time from
//! `src-tauri/vendor/sigstore/trusted_root.json`; see the `PROVENANCE.md` beside
//! it for the pin, how it was corroborated, and why this is vendored rather than
//! fetched through a runtime TUF client. Nothing here touches the network.
//!
//! Selection is keyed on the log's own identity, never on position or name: for
//! the classic Rekor log, `logId = sha256(DER SubjectPublicKeyInfo)`, and Rekor
//! echoes that digest back as the hex `logID` on every entry. So the key used to
//! verify a receipt is the one the receipt itself names, and a receipt from a log
//! this bundle does not carry fails closed rather than falling back to another
//! key.
//!
//! That relation is NOT universal, and the vendored bundle proves it: the 2025
//! log's declared `logId` is not `sha256` of its own `rawBytes`, because Rekor v2
//! tile-backed logs derive their id under the C2SP signed-note scheme. Such logs
//! are therefore never selectable here. They are also Ed25519, which
//! `verify_set` cannot check, so the practical effect is nil — but the resolver
//! recognises them by their declared id purely to say so, instead of claiming a
//! log the bundle plainly contains is absent from it.

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
    #[serde(rename = "logId", default)]
    log_id: Option<LogId>,
    #[serde(rename = "publicKey")]
    public_key: TlogPublicKey,
}

/// The bundle's own declaration of a log's identity: base64
/// `sha256(DER SubjectPublicKeyInfo)`.
#[derive(Debug, Deserialize)]
struct LogId {
    #[serde(rename = "keyId", default)]
    key_id: String,
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
    // A log that is in the bundle under this `logID` but whose key identity is
    // not `sha256(SPKI)` — Rekor v2 tile-backed logs derive their id under the
    // C2SP signed-note scheme instead, so they are never selectable here.
    let mut declared_but_unselectable: Option<(String, String)> = None;

    for tlog in &root.tlogs {
        let der = base64::engine::general_purpose::STANDARD
            .decode(tlog.public_key.raw_bytes.as_bytes())
            .map_err(|e| {
                AnchorError::Parse(format!(
                    "sigstore trusted root: tlog {} has undecodable rawBytes: {e}",
                    tlog.base_url
                ))
            })?;
        let computed = Sha256::digest(&der);

        // Selection is on the recomputed digest, never on the bundle's declared
        // `logId`, so a file whose two halves disagree cannot steer us onto a
        // key the entry did not name.
        if hex::encode(computed) != wanted {
            // The declared id is still worth reading — but only to tell the
            // operator *which* log this was, never to hand back its key. See
            // `declared_but_unselectable` below.
            if tlog
                .log_id
                .as_ref()
                .and_then(|id| {
                    base64::engine::general_purpose::STANDARD
                        .decode(id.key_id.as_bytes())
                        .ok()
                })
                .is_some_and(|declared| hex::encode(declared) == wanted)
            {
                declared_but_unselectable =
                    Some((tlog.base_url.clone(), tlog.public_key.key_details.clone()));
            }
            continue;
        }

        // For a log we *did* select, the two claims must agree.
        if let Some(declared) = tlog.log_id.as_ref().map(|id| id.key_id.as_str()) {
            let declared_bytes = base64::engine::general_purpose::STANDARD
                .decode(declared.as_bytes())
                .map_err(|e| {
                    AnchorError::Parse(format!(
                        "sigstore trusted root: tlog {} has an undecodable logId.keyId: {e}",
                        tlog.base_url
                    ))
                })?;
            if declared_bytes.as_slice() != computed.as_slice() {
                return Err(AnchorError::Parse(format!(
                    "sigstore trusted root: tlog {} declares a logId that is not \
                     sha256 of its own publicKey.rawBytes; refusing to use this bundle",
                    tlog.base_url
                )));
            }
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
    if let Some((base_url, algorithm)) = declared_but_unselectable {
        return Err(AnchorError::NotConfigured(format!(
            "Rekor log {base_url} (logID {wanted}) is in the vendored Sigstore trust root, but \
             its key identity does not follow sha256(SubjectPublicKeyInfo) — Rekor v2 logs derive \
             their id under the C2SP signed-note scheme — and its key is {algorithm}, which this \
             build cannot verify (ECDSA P-256 only). Supporting that log needs both a signed-note \
             log-id derivation and a verifier for its algorithm."
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
    fn vendored_root_parses_and_has_at_least_one_selectable_log() {
        let root: TrustedRoot = serde_json::from_str(TRUSTED_ROOT_JSON).expect("parse");
        assert!(!root.tlogs.is_empty(), "trust root carries no tlogs");

        let mut selectable = 0;
        for tlog in &root.tlogs {
            let der = base64::engine::general_purpose::STANDARD
                .decode(tlog.public_key.raw_bytes.as_bytes())
                .expect("rawBytes decodes");
            assert!(!der.is_empty(), "{} has an empty key", tlog.base_url);
            let declared = base64::engine::general_purpose::STANDARD
                .decode(
                    tlog.log_id
                        .as_ref()
                        .unwrap_or_else(|| panic!("{} has no logId", tlog.base_url))
                        .key_id
                        .as_bytes(),
                )
                .expect("logId.keyId decodes");

            // Only sha256(SPKI)-keyed logs are reachable by this resolver.
            // Rekor v2 tile-backed logs use the C2SP signed-note derivation, so
            // asserting the relation for *every* tlog fails against the genuine
            // bundle — which is how this test found that out.
            if declared.as_slice() == Sha256::digest(&der).as_slice() {
                selectable += 1;
            }
        }
        assert!(
            selectable > 0,
            "no tlog is selectable by sha256(SPKI); rekor_key_for could never resolve a key"
        );
    }

    /// Pins the exact relation the resolver relies on for the log it serves.
    /// Comparing the declared identifier against the recomputed digest is what
    /// catches a truncated or swapped re-vendor; asserting on the digest's
    /// *length* would hold for any input at all.
    #[test]
    fn the_public_good_log_id_is_sha256_of_its_own_key() {
        let root: TrustedRoot = serde_json::from_str(TRUSTED_ROOT_JSON).expect("parse");
        let tlog = root
            .tlogs
            .iter()
            .find(|t| t.base_url == "https://rekor.sigstore.dev")
            .expect("public-good Rekor log present");
        let der = base64::engine::general_purpose::STANDARD
            .decode(tlog.public_key.raw_bytes.as_bytes())
            .expect("rawBytes decodes");
        let declared = base64::engine::general_purpose::STANDARD
            .decode(tlog.log_id.as_ref().expect("logId").key_id.as_bytes())
            .expect("keyId decodes");
        assert_eq!(
            declared,
            Sha256::digest(&der).as_slice(),
            "public-good logId must be sha256 of its own publicKey.rawBytes"
        );
        assert_eq!(hex::encode(&declared), REKOR_V1_LOG_ID);
    }

    /// The Ed25519 2025 log is in the bundle but unreachable by sha256(SPKI).
    /// It must produce a diagnostic naming it, not "no such log".
    #[test]
    fn a_declared_but_unselectable_log_is_named_in_the_error() {
        let root: TrustedRoot = serde_json::from_str(TRUSTED_ROOT_JSON).expect("parse");
        let v2 = root
            .tlogs
            .iter()
            .find(|t| {
                let der = base64::engine::general_purpose::STANDARD
                    .decode(t.public_key.raw_bytes.as_bytes())
                    .expect("decodes");
                let declared = base64::engine::general_purpose::STANDARD
                    .decode(t.log_id.as_ref().expect("logId").key_id.as_bytes())
                    .expect("decodes");
                declared.as_slice() != Sha256::digest(&der).as_slice()
            })
            .expect("bundle carries a non-sha256-keyed log");
        let declared_hex = hex::encode(
            base64::engine::general_purpose::STANDARD
                .decode(v2.log_id.as_ref().expect("logId").key_id.as_bytes())
                .expect("decodes"),
        );

        let err = rekor_key_for(&declared_hex, IN_WINDOW).expect_err("must not resolve");
        let text = format!("{err}");
        assert!(
            text.contains(&v2.base_url),
            "error must name the log: {text}"
        );
        assert!(
            text.contains("signed-note"),
            "error must explain why it is unselectable: {text}"
        );
        // A wrapped message assembled without `\` continuations renders with
        // runs of indentation embedded in it. Operators read these strings.
        assert!(
            !text.contains("  "),
            "error text must not contain whitespace runs: {text:?}"
        );
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

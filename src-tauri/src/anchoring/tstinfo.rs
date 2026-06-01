//! RFC 3161 `TSTInfo` parsing + verification.
//!
//! The submitter (`submit_with_nonce` in `rfc3161.rs`) sends a TSA a
//! `TimeStampReq` with a fixed SHA-256 message imprint and a 63-bit
//! random nonce. The TSA replies with a `TimeStampResp` whose
//! `timeStampToken` is a CMS `SignedData` whose `eContent` is a
//! DER-encoded `TSTInfo` (RFC 3161 §2.4.2). The `TSTInfo` is what
//! actually binds the receipt to **our** data:
//!
//!   - `tstInfo.messageImprint.hashAlgorithm` MUST be SHA-256
//!     (otherwise the TSA signed a different hash than we requested).
//!   - `tstInfo.messageImprint.hashedMessage` MUST equal the 32 bytes
//!     we put in our request. **This is the critical bind — without it
//!     a TSA (or MITM) could reply with a perfectly-valid receipt for
//!     a completely different document and we'd file it as "anchored
//!     hash X" while the receipt actually proves hash Y.**
//!   - `tstInfo.nonce` MUST equal our request nonce. Stricter than the
//!     existing M-A1 substring check because it walks the structure;
//!     the substring guard catches replay-with-foreign-receipt but a
//!     malicious TSA could in principle craft a payload where our
//!     nonce bytes appear elsewhere (probability ~2⁻⁵⁵ per blob byte,
//!     but the strict parse closes the gap entirely).
//!
//! What this module does NOT do (deliberate, audit-tracked):
//!
//!   - Verify the CMS `SignedData` signature against the TSA's
//!     embedded certificate. That requires RSA + ECDSA + cert-chain
//!     validation against a configured trust anchor — a larger PR. The
//!     court-evidence packet relies on offline `openssl ts -verify`
//!     for that step, and the `metadata.tst_info_verified: true`
//!     marker emitted here tells the operator the structural binding
//!     between our hash and the TSA-asserted timestamp has been
//!     confirmed.

use der::{Decode, Encode};
use x509_tsp::{TimeStampResp, TstInfo};

use super::AnchorError;

/// SHA-256 OID `2.16.840.1.101.3.4.2.1`.
const ID_SHA_256: &str = "2.16.840.1.101.3.4.2.1";

/// RFC 3161 §2.4.2 content-type OID for TSTInfo (`id-ct-TSTInfo`).
const ID_CT_TSTINFO: &str = "1.2.840.113549.1.9.16.1.4";

/// Output of a successful TST parse — surfaced into `AnchorReceipt.metadata`
/// so operators can see the timestamp at a glance + so the offline
/// verifier has the canonical fields available without re-parsing the DER.
#[derive(Debug, Clone)]
pub struct VerifiedTstInfo {
    /// `tstInfo.genTime` as a Unix-epoch second count (UTC).
    pub gen_time_unix_secs: u64,
    /// TSA-chosen serial number, hex-encoded.
    pub serial_number_hex: String,
    /// TSA policy OID (dotted-decimal).
    pub policy_oid: String,
}

/// Parse a raw `TimeStampResp` DER blob (the TSA reply body) and
/// verify that the embedded `TSTInfo` actually binds to `expected_hash`
/// and `expected_nonce`.
///
/// Returns `VerifiedTstInfo` with the TSA-asserted fields on success.
/// Any structural / status / mismatch error short-circuits with an
/// `AnchorError::Parse` carrying a precise reason — the message goes
/// straight into operator-facing logs so a bad TSA is diagnosable
/// without a hex dump.
pub fn parse_and_verify(
    body: &[u8],
    expected_hash: &[u8; 32],
    expected_nonce: u64,
) -> Result<VerifiedTstInfo, AnchorError> {
    // ── 1. Decode the outer TimeStampResp ──────────────────────────────
    let resp = TimeStampResp::from_der(body).map_err(|e| {
        AnchorError::Parse(format!("failed to decode TimeStampResp DER: {e}"))
    })?;

    // RFC 3161 §2.4.2 PKIStatus integer encoding: 0 = granted, 1 = grantedWithMods.
    // Anything else (2 = rejection, 3 = waiting, 4 = revocationWarning,
    // 5 = revocationNotification) means there's NO timeStampToken to verify
    // and we should refuse the receipt outright.
    let status_int = resp.status.status as i32;
    if status_int != 0 && status_int != 1 {
        return Err(AnchorError::Parse(format!(
            "TSA rejected the request: PKIStatus={status_int} (not granted/grantedWithMods)"
        )));
    }

    // ── 2. Navigate to TSTInfo ─────────────────────────────────────────
    // TimeStampToken is an alias for CMS ContentInfo whose content is
    // SignedData; the inner eContent of SignedData carries the DER-encoded
    // TSTInfo. The crate's `response_test` reference walks the same path.
    let token = resp.time_stamp_token.as_ref().ok_or_else(|| {
        AnchorError::Parse("TimeStampResp accepted but timeStampToken is absent".into())
    })?;
    let content_der = token.content.to_der().map_err(|e| {
        AnchorError::Parse(format!("re-encoding ContentInfo.content failed: {e}"))
    })?;
    let signed_data = cms::signed_data::SignedData::from_der(&content_der).map_err(|e| {
        AnchorError::Parse(format!("failed to decode CMS SignedData: {e}"))
    })?;
    // RFC 3161 §2.4.2: TimeStampToken's encapContentInfo MUST carry the
    // `id-ct-TSTInfo` content type. Without this check, a SignedData whose
    // eContent happens to be TSTInfo-shaped bytes labeled with a different
    // OID would parse, bind to our hash + nonce, and silently pass — the
    // semantic meaning of the token would be whatever the foreign OID
    // claims, not "trusted timestamp." Reject loudly.
    let econtent_type = signed_data.encap_content_info.econtent_type.to_string();
    if econtent_type != ID_CT_TSTINFO {
        return Err(AnchorError::Parse(format!(
            "CMS encapContentInfo.eContentType is {econtent_type}, expected \
             id-ct-TSTInfo ({ID_CT_TSTINFO}) — TSA returned a token of the wrong type"
        )));
    }
    let econtent = signed_data.encap_content_info.econtent.ok_or_else(|| {
        AnchorError::Parse(
            "CMS SignedData.encapContentInfo.eContent is absent — TSA returned a detached signature?"
                .into(),
        )
    })?;
    let tst = TstInfo::from_der(econtent.value()).map_err(|e| {
        AnchorError::Parse(format!("failed to decode inner TSTInfo: {e}"))
    })?;

    // ── 3. Bind messageImprint to OUR hash + algorithm ──────────────────
    let alg_oid = tst.message_imprint.hash_algorithm.oid.to_string();
    if alg_oid != ID_SHA_256 {
        return Err(AnchorError::Parse(format!(
            "TSTInfo.messageImprint.hashAlgorithm is {alg_oid}, expected SHA-256 ({ID_SHA_256}) — \
             TSA signed a different hash family than requested"
        )));
    }
    let imprint = tst.message_imprint.hashed_message.as_bytes();
    if imprint != expected_hash {
        return Err(AnchorError::Parse(format!(
            "TSTInfo.messageImprint.hashedMessage does not match request: \
             receipt asserts {} but we anchored {}. \
             Receipt is for a DIFFERENT document — refusing.",
            hex_short(imprint),
            hex_short(expected_hash),
        )));
    }

    // ── 4. Bind nonce ──────────────────────────────────────────────────
    let nonce_bytes = tst
        .nonce
        .as_ref()
        .ok_or_else(|| {
            AnchorError::Parse(
                "TSTInfo.nonce is absent — RFC 3161 §2.4.2 requires it when the request \
                 included one (we always send a nonce)"
                    .into(),
            )
        })?
        .as_bytes();
    // The crate decodes INTEGER as a sign-magnitude byte string; the bytes
    // are the canonical DER body of the INTEGER value (leading 0x00 stripped
    // for positive values, kept when the MSB is set to avoid a sign flip).
    // Re-derive what we'd write to a request body via the same helper
    // `rfc3161.rs::encode_nonce_der` uses, then compare the value portion.
    let expected_nonce_body = nonce_to_der_body(expected_nonce);
    if nonce_bytes != expected_nonce_body.as_slice() {
        return Err(AnchorError::Parse(format!(
            "TSTInfo.nonce does not match request: receipt has {}, we sent {} — \
             possible replay or splice attack",
            hex_short(nonce_bytes),
            hex_short(&expected_nonce_body),
        )));
    }

    // ── 5. Lift metadata for the receipt ───────────────────────────────
    // `to_unix_duration()` is panic-free here: `der`'s `GeneralizedTime`
    // only accepts years 1970..=9999 at decode time (anything earlier fails
    // `TstInfo::from_der` above with an out-of-range error), so the returned
    // `Duration` is always non-negative and `as_secs()` cannot underflow.
    // No `chrono`/`checked_` guard is needed — the type already enforces it.
    let gen_time_unix_secs = tst.gen_time.to_unix_duration().as_secs();
    let serial_number_hex = hex_encode(tst.serial_number.as_bytes());
    let policy_oid = tst.policy.to_string();

    Ok(VerifiedTstInfo {
        gen_time_unix_secs,
        serial_number_hex,
        policy_oid,
    })
}

/// Canonical DER body for a `u64` nonce — matches the encoding rules
/// `rfc3161.rs::encode_nonce_der` uses on the request side so the
/// receipt's bytes compare exactly. Mirrors that helper minus the
/// outer TLV header (we want just the integer value bytes here, because
/// `Int::as_bytes()` returns those without the tag/length prefix).
fn nonce_to_der_body(nonce: u64) -> Vec<u8> {
    let nonce_be = nonce.to_be_bytes();
    let mut bytes: Vec<u8> = nonce_be.iter().copied().skip_while(|b| *b == 0).collect();
    if bytes.is_empty() {
        bytes.push(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    bytes
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Operator-facing short form: first 16 hex chars (8 bytes) + ellipsis
/// for long blobs, full hex for short ones. Keeps error messages
/// scannable in log output without burying the screen in 64-char hashes.
fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        hex_encode(bytes)
    } else {
        format!("{}…", hex_encode(&bytes[..8]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The TSR fixture + its pinned hash/nonce live in the shared
    // `test_fixtures` module so this file and `rfc3161.rs` can't drift
    // apart if the vector is ever regenerated.
    use crate::anchoring::test_fixtures::{
        fixture_hash, fixture_tsr as fixture_body, FIXTURE_NONCE,
    };

    #[test]
    fn happy_path_extracts_metadata_and_passes_binding_checks() {
        let body = fixture_body();
        let v = parse_and_verify(&body, &fixture_hash(), FIXTURE_NONCE)
            .expect("real openssl-ts fixture should parse + verify");
        assert_eq!(v.gen_time_unix_secs, 1_686_137_186);
        assert_eq!(v.policy_oid, "1.2.3.4.1");
        // serial in the fixture is the single byte 0x04
        assert_eq!(v.serial_number_hex, "04");
    }

    #[test]
    fn rejects_wrong_hash() {
        let body = fixture_body();
        let mut wrong = fixture_hash();
        wrong[0] ^= 0xff; // flip a bit so the imprint doesn't match
        let err = parse_and_verify(&body, &wrong, FIXTURE_NONCE).unwrap_err();
        match err {
            AnchorError::Parse(msg) => {
                assert!(
                    msg.contains("hashedMessage does not match"),
                    "expected hash-mismatch error, got: {msg}"
                );
                assert!(msg.contains("DIFFERENT document"));
            }
            _ => panic!("expected Parse error"),
        }
    }

    #[test]
    fn rejects_wrong_nonce() {
        let body = fixture_body();
        let err =
            parse_and_verify(&body, &fixture_hash(), FIXTURE_NONCE.wrapping_add(1)).unwrap_err();
        match err {
            AnchorError::Parse(msg) => {
                assert!(
                    msg.contains("nonce does not match"),
                    "expected nonce-mismatch error, got: {msg}"
                );
            }
            _ => panic!("expected Parse error"),
        }
    }

    #[test]
    fn rejects_garbage_body() {
        let body = vec![0xff; 64];
        let err = parse_and_verify(&body, &fixture_hash(), FIXTURE_NONCE).unwrap_err();
        match err {
            AnchorError::Parse(msg) => {
                assert!(msg.contains("TimeStampResp"));
            }
            _ => panic!("expected Parse error"),
        }
    }

    #[test]
    fn nonce_der_body_encoding_matches_request_side() {
        // Positive value with high bit clear → no leading zero pad.
        assert_eq!(nonce_to_der_body(0x12_34), vec![0x12, 0x34]);
        // High bit set on the MSB → MUST prepend a 0x00 byte so the
        // value isn't misread as a negative INTEGER.
        assert_eq!(nonce_to_der_body(0x80), vec![0x00, 0x80]);
        // Zero → single 0x00 byte (DER canonical form).
        assert_eq!(nonce_to_der_body(0), vec![0x00]);
        // Sanity vs the request-side helper for a value we've used in tests.
        assert_eq!(
            nonce_to_der_body(0x0123_4567_89ab_cdef),
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }
}

//! Minimal OpenTimestamps binary-format parser for the upgrade path.
//!
//! Red-team A-1 (PR F): `ots::try_upgrade` previously built a URL of the
//! form `<calendar>/timestamp/` (empty path segment) and POSTed the
//! pending bytes back. Real OTS calendars expect
//! `GET <calendar>/timestamp/<commitment_hex>` — where `<commitment>`
//! is the per-calendar commitment at the tip of the operations chain in
//! the pending receipt, NOT the user's originally-submitted SHA-256.
//!
//! This module implements just enough of the OTS binary format to walk
//! the receipt tree, accumulate the running `msg`, and return the
//! commitment recorded at a PendingAttestation matching a given
//! calendar URL.
//!
//! Format reference: <https://github.com/opentimestamps/python-opentimestamps>
//! and the spec at <https://opentimestamps.org/>.
//!
//! ## Wire shape
//!
//! A `Timestamp` is serialized as a sequence:
//!   - Zero or more **attestations**, each prefixed by the marker byte
//!     `0x00`, followed by an 8-byte type tag and a varbytes payload.
//!     Pending-attestation tag is
//!     `0x83 0xdf 0xe3 0x0d 0x2e 0xf9 0x0c 0x8e`; payload is the calendar
//!     URL as varbytes.
//!   - Zero or more **operations**, each a 1-byte tag (plus a varbytes
//!     argument for the variable-arg ops `APPEND`/`PREPEND`), followed
//!     by the **child Timestamp** that consumed the op's output.
//!   - Branch points (>1 child) are marked by `0xff` before each op
//!     except the last. A linear (single-child) chain has no markers.
//!
//! `varbytes` and `varint` are the standard LEB128-style encoding used
//! throughout the OTS binary format (see python-opentimestamps
//! `serialize.py`).

/// All errors produced while walking a pending receipt.
#[derive(Debug, thiserror::Error)]
pub enum OtsParseError {
    #[error("truncated input at offset {offset}: expected {expected} more byte(s)")]
    Truncated { offset: usize, expected: usize },
    #[error("varint exceeds 8 bytes at offset {offset} — OTS spec cap")]
    VarintTooLong { offset: usize },
    #[error("unknown operation tag 0x{tag:02x} at offset {offset}")]
    UnknownOpTag { tag: u8, offset: usize },
    #[error("recursion depth exceeded ({max}) at offset {offset} — refusing potentially adversarial receipt")]
    DepthExceeded { max: usize, offset: usize },
    #[error("no PendingAttestation matching URL {url:?} found in pending receipt")]
    UrlNotFound { url: String },
    #[error("attestation length exceeds receipt body bound: {len} bytes")]
    AttestationTooLong { len: usize },
    #[error("upgraded OTS receipt has no Bitcoin block-header attestation on the anchored commitment path")]
    MissingBitcoinAttestation,
    #[error("Bitcoin block-header attestation has an invalid varuint payload ({len} byte(s))")]
    InvalidBitcoinAttestation { len: usize },
    #[error("OTS operation produced a message longer than the protocol bound: {len} bytes")]
    MessageTooLong { len: usize },
    #[error("malformed OTS timestamp: {detail}")]
    Malformed { detail: String },
}

/// Hard cap on receipt size — guards against runaway resource use on a
/// malicious calendar response. Real pending receipts are < 1 KiB.
pub const MAX_RECEIPT_BYTES: usize = 64 * 1024;

/// OpenTimestamps `BitcoinBlockHeaderAttestation` tag used by fixtures below.
/// Production parsing lives in the bounded Timestamp-tree parser.
#[cfg(test)]
const BITCOIN_BLOCK_HEADER_ATTESTATION_TAG: [u8; 8] =
    [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];

/// Walk a pending OTS receipt and return the per-calendar commitment
/// recorded at the PendingAttestation whose URL matches `calendar_url`.
///
/// `initial_msg` is the value the calendar was first given — for a
/// pending receipt returned from `POST /digest`, that's the SHA-256 we
/// submitted. The walker applies each operation in order, mutating the
/// running `msg`, and returns the `msg` at the moment a matching
/// `PendingAttestation` is encountered. That `msg` is the commitment to
/// send in `GET <calendar>/timestamp/<commitment_hex>`.
///
/// `calendar_url` matching is exact byte equality after trimming
/// trailing slashes — OTS calendar URLs are case-sensitive and the
/// PendingAttestation's URL is the URL the operator configured (so a
/// caller submitting to `https://alice.calendar.example` won't match an
/// attestation that says `https://bob.calendar.example`).
pub fn extract_commitment(
    receipt: &[u8],
    initial_msg: &[u8; 32],
    calendar_url: &str,
) -> Result<Vec<u8>, OtsParseError> {
    super::ots_tree::extract_pending_commitment(receipt, initial_msg, calendar_url)
}

/// Prove that an alleged upgrade both extends `expected_commitment` and reaches
/// a Bitcoin block-header attestation on that same receipt branch.
///
/// Merely returning the original pending receipt (or appending unrelated data)
/// must not transition a database row to `phase=upgraded`/`verified_at`: a
/// pending attestation contains no independently verifiable Bitcoin claim
/// (H-11). The returned height is metadata only; a court-side OTS verifier must
/// still validate the referenced block against its trusted Bitcoin chain.
pub fn require_bitcoin_attestation(
    receipt: &[u8],
    initial_msg: &[u8],
    expected_commitment: &[u8],
) -> Result<u64, OtsParseError> {
    Ok(
        super::ots_tree::require_bitcoin_after(receipt, initial_msg, expected_commitment)?
            .block_height,
    )
}

/// Calendar response merged into the pending receipt, plus the structural
/// Bitcoin claim found on the commitment-rooted upgrade branch.
pub struct MergedUpgrade {
    pub receipt_blob: Vec<u8>,
    pub bitcoin_block_height: u64,
    pub bitcoin_merkle_root: [u8; 32],
}

pub fn merge_upgraded_timestamp(
    pending_receipt: &[u8],
    original_hash: &[u8; 32],
    calendar_url: &str,
    calendar_response: &[u8],
) -> Result<MergedUpgrade, OtsParseError> {
    let (receipt_blob, bitcoin) = super::ots_tree::merge_calendar_upgrade(
        pending_receipt,
        original_hash,
        calendar_url,
        calendar_response,
    )?;
    Ok(MergedUpgrade {
        receipt_blob,
        bitcoin_block_height: bitcoin.block_height,
        bitcoin_merkle_root: bitcoin.merkle_root,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// PendingAttestation type tag (8 bytes) — fixture data for building
    /// synthetic receipts; the live parser's copy is in `ots_tree`.
    const PENDING_ATTESTATION_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];

    /// Build a minimal pending receipt: one APPEND + SHA256 followed by
    /// a PendingAttestation. The commitment-at-tip is
    /// SHA-256(initial_msg || append_arg).
    fn build_minimal_receipt(initial_msg: &[u8; 32], append_arg: &[u8], url: &str) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        // OP_APPEND
        buf.push(0xf0);
        write_varint(&mut buf, append_arg.len());
        buf.extend_from_slice(append_arg);
        // Required following OP_SHA256
        buf.push(0x08);
        // PendingAttestation
        buf.push(0x00); // attestation marker
        buf.extend_from_slice(&PENDING_ATTESTATION_TAG);
        let mut payload: Vec<u8> = Vec::new();
        // payload is varbytes-wrapped URL
        write_varint(&mut payload, url.len());
        payload.extend_from_slice(url.as_bytes());
        write_varint(&mut buf, payload.len());
        buf.extend_from_slice(&payload);
        let _ = initial_msg;
        buf
    }

    fn build_bitcoin_receipt(append_arg: &[u8], height: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0xf0);
        write_varint(&mut buf, append_arg.len());
        buf.extend_from_slice(append_arg);
        buf.push(0x08);
        buf.push(0x00);
        buf.extend_from_slice(&BITCOIN_BLOCK_HEADER_ATTESTATION_TAG);
        let mut payload = Vec::new();
        write_varint(&mut payload, height as usize);
        write_varint(&mut buf, payload.len());
        buf.extend_from_slice(&payload);
        buf
    }

    fn write_varint(buf: &mut Vec<u8>, mut value: usize) {
        if value == 0 {
            buf.push(0);
            return;
        }
        while value > 0 {
            let mut b = (value & 0x7f) as u8;
            value >>= 7;
            if value > 0 {
                b |= 0x80;
            }
            buf.push(b);
        }
    }

    #[test]
    fn extracts_commitment_for_append_then_sha256_chain() {
        let initial: [u8; 32] = [0x42; 32];
        let arg = b"calendar-aggregation-suffix";
        let url = "https://example.calendar.test";
        let receipt = build_minimal_receipt(&initial, arg, url);

        // Expected commitment = SHA-256(initial || arg).
        let mut expected = Vec::new();
        expected.extend_from_slice(&initial);
        expected.extend_from_slice(arg);
        let want: [u8; 32] = Sha256::digest(&expected).into();

        let got = extract_commitment(&receipt, &initial, url).expect("must extract");
        assert_eq!(got, want, "commitment must match SHA-256(initial || arg)");
    }

    #[test]
    fn requires_bitcoin_attestation_after_expected_commitment() {
        let initial = [0x42; 32];
        let arg = b"suffix";
        let expected: [u8; 32] = Sha256::digest([initial.as_slice(), arg].concat()).into();
        let receipt = build_bitcoin_receipt(arg, 840_000);
        assert_eq!(
            require_bitcoin_attestation(&receipt, &initial, &expected).unwrap(),
            840_000
        );
    }

    #[test]
    fn pending_attestation_is_not_an_upgrade() {
        let initial = [0x42; 32];
        let arg = b"suffix";
        let expected: [u8; 32] = Sha256::digest([initial.as_slice(), arg].concat()).into();
        let receipt = build_minimal_receipt(&initial, arg, "https://calendar.test");
        assert!(matches!(
            require_bitcoin_attestation(&receipt, &initial, &expected),
            Err(OtsParseError::MissingBitcoinAttestation)
        ));
    }

    #[test]
    fn bitcoin_attestation_on_different_commitment_is_rejected() {
        let initial = [0x42; 32];
        let expected: [u8; 32] = Sha256::digest([initial.as_slice(), b"right"].concat()).into();
        let receipt = build_bitcoin_receipt(b"wrong", 840_001);
        assert!(matches!(
            require_bitcoin_attestation(&receipt, &initial, &expected),
            Err(OtsParseError::MissingBitcoinAttestation)
        ));
    }

    #[test]
    fn errors_on_url_not_found() {
        let initial: [u8; 32] = [0x42; 32];
        let receipt = build_minimal_receipt(&initial, b"x", "https://alice.calendar.test");
        let err = extract_commitment(&receipt, &initial, "https://bob.calendar.test")
            .expect_err("mismatched URL must error");
        assert!(matches!(err, OtsParseError::UrlNotFound { .. }));
    }

    #[test]
    fn errors_on_truncated_input() {
        // Stop after the OP_APPEND tag (missing length/bytes).
        let receipt = vec![0xf0];
        let err = extract_commitment(&receipt, &[0; 32], "x").expect_err("truncated must error");
        assert!(matches!(err, OtsParseError::Truncated { .. }));
    }

    #[test]
    fn errors_on_unknown_op() {
        // 0x99 is not a valid OTS op tag.
        let receipt = vec![0x99];
        let err = extract_commitment(&receipt, &[0; 32], "x").expect_err("unknown op must error");
        assert!(matches!(err, OtsParseError::UnknownOpTag { .. }));
    }

    #[test]
    fn errors_on_too_large_input() {
        let huge = vec![0u8; MAX_RECEIPT_BYTES + 1];
        let err =
            extract_commitment(&huge, &[0; 32], "x").expect_err("oversize receipt must error");
        assert!(matches!(err, OtsParseError::AttestationTooLong { .. }));
    }

    #[test]
    fn accepts_unhashed_pending_commitment() {
        // APPEND/PREPEND produce variable-length messages and need not be
        // followed by a hash before a PendingAttestation.
        let initial = [0x11; 32];
        let mut buf = vec![0xf0];
        write_varint(&mut buf, 1);
        buf.push(0xaa);
        buf.push(0x00);
        buf.extend_from_slice(&PENDING_ATTESTATION_TAG);
        let mut payload = Vec::new();
        write_varint(&mut payload, 1);
        payload.push(b'x');
        write_varint(&mut buf, payload.len());
        buf.extend_from_slice(&payload);
        let commitment = extract_commitment(&buf, &initial, "x").expect("valid pending receipt");
        assert_eq!(commitment, [initial.as_slice(), &[0xaa]].concat());
    }

    #[test]
    fn skips_non_pending_attestation_and_continues() {
        // Build: APPEND-SHA256 → UNKNOWN attestation → no PENDING.
        // Result: UrlNotFound (not a parse error).
        let mut buf: Vec<u8> = Vec::new();
        buf.push(0xf0);
        write_varint(&mut buf, 1);
        buf.push(0x00);
        buf.push(0x08);
        // Attestation marker + unknown tag + empty varbytes payload.
        buf.push(0x00);
        buf.extend_from_slice(&[0xaa; 8]);
        write_varint(&mut buf, 0);
        let err = extract_commitment(&buf, &[0; 32], "x").expect_err("no PENDING → UrlNotFound");
        assert!(matches!(err, OtsParseError::UrlNotFound { .. }));
    }

    #[test]
    fn matches_url_with_trailing_slash_in_attestation() {
        // The PendingAttestation includes a trailing slash; our caller
        // passes the URL without one. They should match.
        let initial: [u8; 32] = [0x01; 32];
        let receipt = build_minimal_receipt(&initial, b"y", "https://x.test/");
        let got = extract_commitment(&receipt, &initial, "https://x.test").expect("match");
        // Confirm a non-trivial commitment.
        let mut expected = Vec::new();
        expected.extend_from_slice(&initial);
        expected.extend_from_slice(b"y");
        let want: [u8; 32] = Sha256::digest(&expected).into();
        assert_eq!(got, want);
    }
}

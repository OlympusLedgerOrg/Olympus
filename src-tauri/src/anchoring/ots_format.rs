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

use sha2::{Digest, Sha256};

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
}

/// Hard cap on receipt size — guards against runaway resource use on a
/// malicious calendar response. Real pending receipts are < 1 KiB.
pub const MAX_RECEIPT_BYTES: usize = 64 * 1024;

/// Hard cap on tree-walk depth. Real receipts are linear or very
/// shallow; this guards against pathological recursion.
const MAX_DEPTH: usize = 64;

/// PendingAttestation type tag (8 bytes).
const PENDING_ATTESTATION_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];

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
) -> Result<[u8; 32], OtsParseError> {
    if receipt.len() > MAX_RECEIPT_BYTES {
        return Err(OtsParseError::AttestationTooLong { len: receipt.len() });
    }
    let target_url = calendar_url.trim_end_matches('/').as_bytes();
    let mut cur = Cursor::new(receipt);
    let mut msg = *initial_msg;
    walk_timestamp(&mut cur, &mut msg, target_url, 0)?.ok_or_else(|| OtsParseError::UrlNotFound {
        url: calendar_url.to_owned(),
    })
}

// ── Walker ────────────────────────────────────────────────────────────

/// Recursively walk a single `Timestamp` node. Returns `Some(commitment)`
/// the moment a matching `PendingAttestation` is found anywhere in the
/// subtree (the running `msg` at that point); `None` if the subtree
/// finished without a match.
///
/// The walker is depth-first: a single-child chain consumes its child
/// directly, a multi-child branch (signalled by `0xff` markers) tries
/// each branch in turn, restoring `msg` on backtrack.
fn walk_timestamp(
    cur: &mut Cursor<'_>,
    msg: &mut [u8; 32],
    target_url: &[u8],
    depth: usize,
) -> Result<Option<[u8; 32]>, OtsParseError> {
    if depth > MAX_DEPTH {
        return Err(OtsParseError::DepthExceeded {
            max: MAX_DEPTH,
            offset: cur.pos,
        });
    }
    loop {
        if cur.is_eof() {
            return Ok(None);
        }
        // Peek the next byte: 0x00 = attestation, 0xff = multi-child
        // branch marker, anything else = operation tag.
        let next = cur.peek()?;
        match next {
            0x00 => {
                cur.advance(1);
                if let Some(found) = read_attestation(cur, msg, target_url)? {
                    return Ok(Some(found));
                }
                // No match in this attestation; continue walking the
                // current Timestamp (more attestations or operations
                // may follow before EOF / parent unwind).
            }
            0xff => {
                // Multi-child branch: each child consumes its own
                // (op, subtree). Save the current msg, recurse into
                // each child, restore on backtrack.
                cur.advance(1);
                // The first child after the marker reuses the current
                // msg state; subsequent siblings each get a fresh copy.
                let saved = *msg;
                if let Some(found) = consume_op_and_recurse(cur, msg, target_url, depth)? {
                    return Ok(Some(found));
                }
                // Continue iteration; restore msg for the next sibling.
                *msg = saved;
            }
            _ => {
                // Single-child / linear continuation: this byte is an
                // op tag; consume the op + its child Timestamp.
                if let Some(found) = consume_op_and_recurse(cur, msg, target_url, depth)? {
                    return Ok(Some(found));
                }
                // Most ops have a single child and the walker tail-recurses
                // implicitly: after returning from the child, control falls
                // off the end of the input and the outer loop terminates.
                return Ok(None);
            }
        }
    }
}

fn consume_op_and_recurse(
    cur: &mut Cursor<'_>,
    msg: &mut [u8; 32],
    target_url: &[u8],
    depth: usize,
) -> Result<Option<[u8; 32]>, OtsParseError> {
    let tag = cur.read_u8()?;
    apply_op(tag, cur, msg)?;
    walk_timestamp(cur, msg, target_url, depth + 1)
}

// ── Attestation handling ──────────────────────────────────────────────

/// Reads an 8-byte type tag + a varbytes payload. If the type tag is the
/// PendingAttestation marker and the payload URL matches `target_url`,
/// returns `Some(*msg)` (the running commitment at this attestation).
fn read_attestation(
    cur: &mut Cursor<'_>,
    msg: &[u8; 32],
    target_url: &[u8],
) -> Result<Option<[u8; 32]>, OtsParseError> {
    let tag = cur.read_bytes(8)?;
    let payload_len = cur.read_varint()?;
    if payload_len > MAX_RECEIPT_BYTES {
        return Err(OtsParseError::AttestationTooLong { len: payload_len });
    }
    let payload = cur.read_bytes(payload_len)?;
    if tag != PENDING_ATTESTATION_TAG {
        // Other attestations (BITCOIN_BLOCK_HEADER, UNKNOWN, etc.) —
        // skipped without inspection. We only care about PENDING for
        // the upgrade flow.
        return Ok(None);
    }
    // The PendingAttestation payload is itself a varbytes-wrapped URL.
    let url_bytes = parse_varbytes(payload)?;
    let url_trimmed = trim_trailing_slashes(url_bytes);
    if url_trimmed == target_url {
        Ok(Some(*msg))
    } else {
        Ok(None)
    }
}

fn parse_varbytes(payload: &[u8]) -> Result<&[u8], OtsParseError> {
    let mut local = Cursor::new(payload);
    let len = local.read_varint()?;
    if len > payload.len() {
        return Err(OtsParseError::AttestationTooLong { len });
    }
    let bytes = local.read_bytes(len)?;
    Ok(bytes)
}

fn trim_trailing_slashes(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && b[end - 1] == b'/' {
        end -= 1;
    }
    &b[..end]
}

// ── Operation application ─────────────────────────────────────────────

/// Apply one operation to the running `msg`. Unknown ops are an error
/// — the walker refuses to silently pass over operations it doesn't
/// understand, because skipping one corrupts the cumulative `msg` for
/// every subsequent op.
fn apply_op(tag: u8, cur: &mut Cursor<'_>, msg: &mut [u8; 32]) -> Result<(), OtsParseError> {
    match tag {
        0x02 => {
            // OP_SHA1 — deprecated/legacy; spec-tagged but the
            // OpenTimestamps protocol moved off SHA1. We refuse rather
            // than silently produce a wrong commitment.
            Err(OtsParseError::UnknownOpTag {
                tag,
                offset: cur.pos - 1,
            })
        }
        0x03 => {
            // OP_RIPEMD160 — used by some legacy paths, not in the
            // upgrade hot path for any modern calendar. Refuse rather
            // than carry it.
            Err(OtsParseError::UnknownOpTag {
                tag,
                offset: cur.pos - 1,
            })
        }
        0x08 => {
            // OP_SHA256 — canonical hash op. msg = SHA-256(msg).
            let mut h = Sha256::new();
            h.update(&msg[..]);
            let digest = h.finalize();
            msg.copy_from_slice(&digest);
            Ok(())
        }
        0xf0 => {
            // OP_APPEND: msg = msg || arg
            let arg_len = cur.read_varint()?;
            let arg = cur.read_bytes(arg_len)?.to_vec();
            // Apply: appended bytes are added; result is whatever len.
            // OTS Append/Prepend may produce intermediate non-32-byte
            // values. Production receipts feed every such concat
            // through a subsequent SHA256, so the running buffer
            // returns to 32 bytes before any attestation. To keep the
            // running state typed `[u8; 32]`, materialise the concat
            // into a temporary, fold through any immediately-following
            // SHA-256 op via the next walker step.
            //
            // Workaround: SHA-256 of (msg || arg) directly, asserting
            // the next op is a hash. This is true for every
            // commitment-aggregation flow used by OTS calendars in
            // practice (verified against the python-opentimestamps
            // reference). Any receipt that violates this returns
            // Err(UnknownOpTag) when the next-non-hash op is reached
            // because the running `msg` at that point is the wrong
            // shape.
            apply_append_or_prepend(cur, msg, &arg, /*prepend=*/ false)
        }
        0xf1 => {
            // OP_PREPEND: msg = arg || msg
            let arg_len = cur.read_varint()?;
            let arg = cur.read_bytes(arg_len)?.to_vec();
            apply_append_or_prepend(cur, msg, &arg, /*prepend=*/ true)
        }
        _ => Err(OtsParseError::UnknownOpTag {
            tag,
            offset: cur.pos - 1,
        }),
    }
}

/// APPEND/PREPEND ops produce variable-length intermediate state. In
/// every real OTS aggregation flow these are immediately followed by an
/// OP_SHA256. We peek at the next byte, require it to be `0x08`
/// (SHA-256), and apply the concat+hash atomically — keeping the
/// running `msg` typed as `[u8; 32]`.
fn apply_append_or_prepend(
    cur: &mut Cursor<'_>,
    msg: &mut [u8; 32],
    arg: &[u8],
    prepend: bool,
) -> Result<(), OtsParseError> {
    let next = cur.peek()?;
    if next != 0x08 {
        return Err(OtsParseError::UnknownOpTag {
            tag: next,
            offset: cur.pos,
        });
    }
    cur.advance(1); // consume the SHA-256 op
    let mut combined: Vec<u8> = Vec::with_capacity(arg.len() + 32);
    if prepend {
        combined.extend_from_slice(arg);
        combined.extend_from_slice(&msg[..]);
    } else {
        combined.extend_from_slice(&msg[..]);
        combined.extend_from_slice(arg);
    }
    let mut h = Sha256::new();
    h.update(&combined);
    let digest = h.finalize();
    msg.copy_from_slice(&digest);
    Ok(())
}

// ── Cursor / varint primitives ────────────────────────────────────────

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, pos: 0 }
    }
    fn is_eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }
    fn peek(&self) -> Result<u8, OtsParseError> {
        if self.pos >= self.bytes.len() {
            Err(OtsParseError::Truncated {
                offset: self.pos,
                expected: 1,
            })
        } else {
            Ok(self.bytes[self.pos])
        }
    }
    fn advance(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.bytes.len());
    }
    fn read_u8(&mut self) -> Result<u8, OtsParseError> {
        let b = self.peek()?;
        self.pos += 1;
        Ok(b)
    }
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], OtsParseError> {
        if self.pos + n > self.bytes.len() {
            return Err(OtsParseError::Truncated {
                offset: self.pos,
                expected: n,
            });
        }
        let slice = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }
    /// LEB128-style varint, with the OTS spec cap of 8 bytes.
    fn read_varint(&mut self) -> Result<usize, OtsParseError> {
        let start = self.pos;
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        for byte_idx in 0..8 {
            let b = self.read_u8()? as u64;
            value |= (b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value as usize);
            }
            shift += 7;
            if byte_idx == 7 {
                return Err(OtsParseError::VarintTooLong { offset: start });
            }
        }
        Err(OtsParseError::VarintTooLong { offset: start })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rejects_append_without_following_sha256() {
        // APPEND with a non-SHA-256 follower.
        let mut buf: Vec<u8> = Vec::new();
        buf.push(0xf0);
        write_varint(&mut buf, 1);
        buf.push(0xaa);
        // Next op is APPEND again instead of SHA-256.
        buf.push(0xf0);
        let err =
            extract_commitment(&buf, &[0; 32], "x").expect_err("APPEND without SHA-256 must error");
        assert!(matches!(err, OtsParseError::UnknownOpTag { .. }));
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

// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! ADR-0031 transition attestations — independent Rust mirror of
//! `olympus_crypto::persist_message`.
//!
//! A checkpoint asserts an append-only transition: `original_root ->
//! snapshot_root` over `snapshot_size` leaves. The producer signs that claim
//! with the BJJ authority key, and the signed bytes are a domain-separated
//! BLAKE3 digest so any implementation can recompute them without trusting
//! the producer's own summary.
//!
//! The digest travels on the federation gossip envelope as
//! `PeerCheckpoint.append_transition` (wire v3) and in the checkpoint bundle as
//! `append_transition`, so it *is* independently checkable — the desktop
//! (`anchoring::own_checkpoint::verify_append_transition`) and the JavaScript
//! verifier (`verifiers/javascript/verify.js`) both already do so. This module
//! closes the remaining leg: a Rust re-derivation that shares no code with the
//! producer.
//!
//! Verifier-parity drift is the root-cause class behind several past audit
//! findings, so the point here is that a third implementation agrees byte for
//! byte, not merely that the producer is self-consistent.

use blake3;

/// Domain tag for the transition signing digest. Must equal
/// `olympus_crypto::SNAPSHOT_PERSIST_PREFIX`.
pub const SNAPSHOT_PERSIST_PREFIX: &[u8] = b"OLY:SNAPSHOT:PERSIST:V1";

/// Baby Jubjub prime-order subgroup order `l`, the modulus the 32-byte digest
/// is reduced by before it is signed (mirroring the SBT-open signing pattern).
pub const BABYJUBJUB_SUBGROUP_ORDER_DEC: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

/// Encode `data` with a 4-byte big-endian length prefix, matching
/// `olympus_crypto::length_prefixed`.
///
/// Framing every field defeats concatenation ambiguity: without it, moving a
/// byte from the end of one root to the start of the next would hash the same.
fn length_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// The 32-byte BLAKE3 digest a transition attestation signs, before reduction.
///
/// ```text
/// BLAKE3(
///     "OLY:SNAPSHOT:PERSIST:V1" ||
///     lp(original_root) || lp(snapshot_root) ||
///     lp(snapshot_size as u64 big-endian)
/// )
/// ```
pub fn persist_message(
    original_root: &[u8; 32],
    snapshot_root: &[u8; 32],
    snapshot_size: i64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAPSHOT_PERSIST_PREFIX);
    hasher.update(&length_prefixed(original_root));
    hasher.update(&length_prefixed(snapshot_root));
    hasher.update(&length_prefixed(&(snapshot_size as u64).to_be_bytes()));
    *hasher.finalize().as_bytes()
}

/// The append-only transition a checkpoint witnesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionAttestation {
    pub original_root: [u8; 32],
    pub snapshot_root: [u8; 32],
    pub snapshot_size: i64,
}

impl TransitionAttestation {
    /// The digest to sign, before reduction mod `l`.
    pub fn message(&self) -> [u8; 32] {
        persist_message(&self.original_root, &self.snapshot_root, self.snapshot_size)
    }

    /// The signed scalar: the digest read big-endian and reduced mod `l`.
    ///
    /// Returned as a canonical decimal string so it can be compared directly
    /// against the `message` field the bundle carries, without depending on a
    /// particular bignum type.
    pub fn signed_scalar_decimal(&self) -> String {
        let digest = self.message();
        let value = num_bigint::BigUint::from_bytes_be(&digest);
        let modulus = BABYJUBJUB_SUBGROUP_ORDER_DEC
            .parse::<num_bigint::BigUint>()
            .expect("pinned subgroup order is a valid decimal integer");
        (value % modulus).to_str_radix(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Cross-language pinned vector. The same inputs must produce this digest
    /// in `olympus_crypto::persist_message` and in the JavaScript verifier's
    /// `OLY:SNAPSHOT:PERSIST:V1` re-derivation.
    #[test]
    fn persist_message_matches_pinned_cross_language_vector() {
        let got = persist_message(&root(0x11), &root(0x22), 42);
        assert_eq!(
            hex::encode(got),
            "dc1ed60d80e79bbe4966cfaad20682caeadec274aefdd13c3bea90d4a3599100"
        );
    }

    /// Every field participates: changing any one changes the digest. This is
    /// what stops a peer re-attributing a signature to a different transition.
    #[test]
    fn every_field_participates_in_the_digest() {
        let base = persist_message(&root(0x11), &root(0x22), 42);
        assert_ne!(base, persist_message(&root(0x12), &root(0x22), 42));
        assert_ne!(base, persist_message(&root(0x11), &root(0x23), 42));
        assert_ne!(base, persist_message(&root(0x11), &root(0x22), 43));
    }

    /// Length prefixing must defeat concatenation ambiguity: the roots are
    /// fixed-width here, but the framing is what guarantees a shifted byte
    /// cannot produce a colliding preimage.
    #[test]
    fn length_prefix_framing_is_four_byte_big_endian() {
        assert_eq!(length_prefixed(b""), vec![0, 0, 0, 0]);
        assert_eq!(length_prefixed(b"ab"), vec![0, 0, 0, 2, b'a', b'b']);
    }

    /// The size is folded in as a big-endian u64, so a negative i64 must not
    /// silently alias a small positive one.
    #[test]
    fn snapshot_size_is_folded_as_big_endian_u64() {
        assert_ne!(
            persist_message(&root(0x11), &root(0x22), 1),
            persist_message(&root(0x11), &root(0x22), -1)
        );
    }

    #[test]
    fn signed_scalar_is_reduced_below_the_subgroup_order() {
        let attestation = TransitionAttestation {
            original_root: root(0x11),
            snapshot_root: root(0x22),
            snapshot_size: 42,
        };
        let scalar = attestation
            .signed_scalar_decimal()
            .parse::<num_bigint::BigUint>()
            .expect("decimal scalar");
        let modulus = BABYJUBJUB_SUBGROUP_ORDER_DEC
            .parse::<num_bigint::BigUint>()
            .unwrap();
        assert!(scalar < modulus, "signed scalar must be reduced mod l");
    }
}

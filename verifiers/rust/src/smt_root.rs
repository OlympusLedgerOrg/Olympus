// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! ADR-0044 SMT root attestations — independent Rust mirror of
//! `olympus_crypto::smt_root_attest_message`.
//!
//! A checkpoint asserts a joint statement about the BLAKE3 CD-HS-ST
//! parser-bound SMT: "for `shard_id`, at ledger snapshot `(ledger_root,
//! tree_size)`, the shard's BLAKE3 SMT subtree root is `blake3_smt_root`".
//! The producer signs that claim with the BJJ authority key, and the signed
//! bytes are a domain-separated BLAKE3 digest so any implementation can
//! recompute them without trusting the producer's own summary.
//!
//! The digest travels in the checkpoint bundle as `smt_root_attestation`, so
//! it is independently checkable — the desktop
//! (`anchoring::own_checkpoint::verify_smt_root_attestation`) and the
//! JavaScript verifier (`verifiers/javascript/verify.js`) both already do so.
//! This module closes the remaining leg: a Rust re-derivation that shares no
//! code with the producer.
//!
//! [`verify_smt_root_attestation`] closes the loop: it re-derives the digest
//! from the claimed shard/roots/size and then authenticates the signature
//! over it via [`crate::eddsa`], so a peer cannot supply the digest its
//! signature happens to cover.

use blake3;

/// Domain tag for the SMT root attestation signing digest. Must equal
/// `olympus_crypto::SMT_ROOT_ATTEST_PREFIX`.
pub const SMT_ROOT_ATTEST_PREFIX: &[u8] = b"OLY:SMT:ROOT:V1";

/// Baby Jubjub prime-order subgroup order `l`, the modulus the 32-byte digest
/// is reduced by before it is signed (mirroring the transition-attestation
/// and SBT-open signing patterns).
pub const BABYJUBJUB_SUBGROUP_ORDER_DEC: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

/// Encode `data` with a 4-byte big-endian length prefix, matching
/// `olympus_crypto::length_prefixed`.
///
/// Framing every field defeats concatenation ambiguity: without it, moving a
/// byte from the end of one field to the start of the next would hash the
/// same.
fn length_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// The 32-byte BLAKE3 digest an SMT root attestation signs, before
/// reduction.
///
/// ```text
/// BLAKE3(
///     "OLY:SMT:ROOT:V1" ||
///     lp(shard_id) || lp(ledger_root) ||
///     lp(tree_size as u64 big-endian) || lp(blake3_smt_root)
/// )
/// ```
pub fn smt_root_attest_message(
    shard_id: &[u8],
    ledger_root: &[u8; 32],
    tree_size: i64,
    blake3_smt_root: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SMT_ROOT_ATTEST_PREFIX);
    hasher.update(&length_prefixed(shard_id));
    hasher.update(&length_prefixed(ledger_root));
    hasher.update(&length_prefixed(&(tree_size as u64).to_be_bytes()));
    hasher.update(&length_prefixed(blake3_smt_root));
    *hasher.finalize().as_bytes()
}

/// The joint statement a checkpoint witnesses about the BLAKE3 CD-HS-ST SMT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtRootAttestation {
    pub shard_id: Vec<u8>,
    pub ledger_root: [u8; 32],
    pub tree_size: i64,
    pub blake3_smt_root: [u8; 32],
}

impl SmtRootAttestation {
    /// The digest to sign, before reduction mod `l`.
    pub fn message(&self) -> [u8; 32] {
        smt_root_attest_message(
            &self.shard_id,
            &self.ledger_root,
            self.tree_size,
            &self.blake3_smt_root,
        )
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

/// Authenticate an SMT root attestation end to end: re-derive the signing
/// digest from the claimed shard/roots/size, then verify the BJJ-EdDSA
/// signature over it.
///
/// This is the whole point of the module — a peer's `smt_root_attestation` is
/// only evidence if the signature covers a digest *we* computed from the
/// statement it claims, not one the peer supplied.
pub fn verify_smt_root_attestation(
    curve: &crate::pedersen::Curve,
    pubkey: &crate::pedersen::Point,
    signature: &crate::eddsa::Signature,
    attestation: &SmtRootAttestation,
) -> Result<(), crate::eddsa::EddsaError> {
    let message = attestation
        .signed_scalar_decimal()
        .parse::<num_bigint::BigUint>()
        .expect("reduced scalar is a valid decimal integer");
    crate::eddsa::verify(curve, pubkey, signature, &message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Cross-language pinned vector, shared with
    /// `olympus_crypto::smt_root_attest_message`'s golden vector test. The
    /// same inputs must produce this digest in both implementations and in
    /// the JavaScript verifier's `OLY:SMT:ROOT:V1` re-derivation.
    #[test]
    fn smt_root_attest_message_matches_pinned_cross_language_vector() {
        let got = smt_root_attest_message(b"files", &root(0x33), 9, &root(0x44));
        assert_eq!(
            hex::encode(got),
            "41c42858816b0938b8f3d6530988a5c48f5609b8e5ff9a8c6dd3fe94d3a76a33"
        );
    }

    /// Every field participates: changing any one changes the digest. This is
    /// what stops a peer re-attributing a signature to a different
    /// statement.
    #[test]
    fn every_field_participates_in_the_digest() {
        let base = smt_root_attest_message(b"files", &root(0x33), 9, &root(0x44));
        assert_ne!(
            base,
            smt_root_attest_message(b"other", &root(0x33), 9, &root(0x44))
        );
        assert_ne!(
            base,
            smt_root_attest_message(b"files", &root(0x34), 9, &root(0x44))
        );
        assert_ne!(
            base,
            smt_root_attest_message(b"files", &root(0x33), 10, &root(0x44))
        );
        assert_ne!(
            base,
            smt_root_attest_message(b"files", &root(0x33), 9, &root(0x45))
        );
    }

    /// Length prefixing must defeat concatenation ambiguity.
    #[test]
    fn length_prefix_framing_is_four_byte_big_endian() {
        assert_eq!(length_prefixed(b""), vec![0, 0, 0, 0]);
        assert_eq!(length_prefixed(b"ab"), vec![0, 0, 0, 2, b'a', b'b']);
    }

    /// The size is folded in as a big-endian u64, so a negative i64 must not
    /// silently alias a small positive one.
    #[test]
    fn tree_size_is_folded_as_big_endian_u64() {
        assert_ne!(
            smt_root_attest_message(b"files", &root(0x33), 1, &root(0x44)),
            smt_root_attest_message(b"files", &root(0x33), -1, &root(0x44))
        );
    }

    /// The scalar that is actually signed, pinned to the same vector as the
    /// digest above.
    ///
    /// A bound check alone is not enough — reading the digest with the wrong
    /// endianness or reducing by the wrong modulus can also happen to land
    /// under the subgroup order. Only a pinned value catches that.
    const EXPECTED_SIGNED_SCALAR_DEC: &str =
        "2386612048768280567511525556694515839130077996387322938210448993954161222857";

    #[test]
    fn signed_scalar_is_reduced_below_the_subgroup_order() {
        let attestation = SmtRootAttestation {
            shard_id: b"files".to_vec(),
            ledger_root: root(0x33),
            tree_size: 9,
            blake3_smt_root: root(0x44),
        };
        let scalar = attestation
            .signed_scalar_decimal()
            .parse::<num_bigint::BigUint>()
            .expect("decimal scalar");
        assert_eq!(
            scalar.to_str_radix(10),
            EXPECTED_SIGNED_SCALAR_DEC,
            "signed scalar must match the pinned big-endian reduction"
        );
        let modulus = BABYJUBJUB_SUBGROUP_ORDER_DEC
            .parse::<num_bigint::BigUint>()
            .unwrap();
        assert!(scalar < modulus, "signed scalar must be reduced mod l");
    }
}

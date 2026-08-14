// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Independent offline verifier for the Olympus **SBT credential** M-of-N quorum
//! (`OLY:SBT:QUORUM:V2`).
//!
//! `src-tauri/src/quorum/mod.rs` promises that "anyone holding the N pubkeys can
//! re-verify the quorum offline". The sibling [`crate::eddsa`] tests already give
//! that guarantee for the *checkpoint* quorum; this module closes the same gap
//! for the security-load-bearing *credential* quorum, whose satisfaction drives
//! scope elevation (audit L6).
//!
//! It re-derives the **full** `OLY:SBT:QUORUM:V2` pre-image from scratch —
//! BLAKE3 over the length-prefixed framing of `(commit_id_hex, threshold,
//! canonical signer set)`, then an `Fr_le` reduction — and re-runs the M-of-N
//! counting (member-only, distinct-by-pubkey, BJJ-EdDSA verified) exactly as
//! `quorum::verify_generic_quorum` does. Nothing here trusts the vector's
//! `expected.message`: the conformance test asserts the independently
//! reconstructed message *equals* it, so a byte-layout divergence fails.
//!
//! # Pre-image (mirrors `quorum::quorum_cosign_message`)
//!
//! ```text
//! msg = Fr_le( BLAKE3(
//!     "OLY:SBT:QUORUM:V2"
//!   | u32_be(len(commit_id_hex)) || commit_id_hex        // hex STRING (64 chars), not the 32 raw bytes
//!   | u32_be(threshold)
//!   | u32_be(N) || for each canonical signer (deduped, sorted by (x,y) decimal):
//!                    u32_be(len(x)) || x || u32_be(len(y)) || y
//! ) )
//! ```
//!
//! This is disjoint from the checkpoint domain `OLY:CHECKPOINT:QUORUM:V2`: the
//! prefix enters the BLAKE3 pre-image, so a checkpoint co-signature yields a
//! different field element and is rejected by the verification equation here —
//! not merely by a membership miss. The `cross_domain_checkpoint_sig_rejected`
//! vector pins exactly that.

use std::collections::BTreeSet;

use num_bigint::BigUint;

use crate::eddsa::{self, Signature};
use crate::pedersen::{parse_dec, Curve, Point};

/// Domain tag for SBT credential quorum co-signatures.
/// Must equal `quorum::QUORUM_COSIGN_PREFIX` in the desktop crate.
pub const SBT_QUORUM_PREFIX: &[u8] = b"OLY:SBT:QUORUM:V2";

/// A pinned federation signer's BJJ pubkey coordinates (canonical decimal `Fr`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Signer {
    pub x: String,
    pub y: String,
}

/// One collected BJJ-EdDSA co-signature over the SBT quorum message.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CoSignature {
    pub x: String,
    pub y: String,
    pub r8x: String,
    pub r8y: String,
    pub s: String,
}

/// Outcome of [`verify_sbt_quorum`]. Mirrors `quorum::QuorumStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumOutcome {
    pub valid_signatures: usize,
    pub total_signers: usize,
    pub satisfied: bool,
}

/// Push a `u32` big-endian length prefix followed by `data` — the framing every
/// variable-length field in the pre-image uses.
fn push_lp(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Canonicalise one field-element coordinate exactly as the desktop `parse_fr`
/// (`src-tauri/src/zk/proof.rs`) followed by `fr_to_decimal`: a canonical
/// unsigned decimal (no leading zeros, ≤ 77 digits) strictly `< r`. Returns the
/// canonical decimal string, or `None` for any non-canonical / out-of-field
/// input — which is then dropped, matching `normalize_signer`'s `filter_map`.
fn canon_coord(s: &str, modulus: &BigUint) -> Option<String> {
    if s.is_empty()
        || s.len() > 77
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    let n = parse_dec(s)?;
    if n >= *modulus {
        return None;
    }
    Some(n.to_string())
}

/// Normalise a signer to its canonical `(x_dec, y_dec)` membership/distinctness
/// key, or `None` if either coordinate is non-canonical. Mirrors
/// `quorum::normalize_signer`.
fn normalize(modulus: &BigUint, x: &str, y: &str) -> Option<(String, String)> {
    Some((canon_coord(x, modulus)?, canon_coord(y, modulus)?))
}

/// The canonical, deduped, sorted signer set — the same `BTreeSet<(x,y)>` the
/// desktop verifier builds as its eligible set and hashes into the message.
fn canonical_set(modulus: &BigUint, signers: &[Signer]) -> BTreeSet<(String, String)> {
    signers
        .iter()
        .filter_map(|s| normalize(modulus, &s.x, &s.y))
        .collect()
}

/// Re-derive the `OLY:SBT:QUORUM:V2` message field element (in `[0, r)`) from
/// `(commit_id_hex, threshold, signers)`. Independent of any `expected.message`.
pub fn sbt_quorum_message(
    curve: &Curve,
    commit_id_hex: &str,
    threshold: u32,
    signers: &[Signer],
) -> BigUint {
    let canonical = canonical_set(&curve.p, signers);

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(SBT_QUORUM_PREFIX);
    push_lp(&mut buf, commit_id_hex.as_bytes());
    buf.extend_from_slice(&threshold.to_be_bytes());
    buf.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
    for (x, y) in &canonical {
        push_lp(&mut buf, x.as_bytes());
        push_lp(&mut buf, y.as_bytes());
    }
    let digest = blake3::hash(&buf);
    // Fr::from_le_bytes_mod_order: interpret the 32-byte digest as a
    // little-endian integer, reduce mod the BN254 scalar field r.
    BigUint::from_bytes_le(digest.as_bytes()) % &curve.p
}

/// Parse a co-signature's pubkey + signature into curve types, or `None` on any
/// non-canonical field element (fail-closed, matching the desktop verifier).
fn cosig_parts(cs: &CoSignature) -> Option<(Point, Signature)> {
    let pubkey = Point {
        x: parse_dec(&cs.x)?,
        y: parse_dec(&cs.y)?,
    };
    let sig = Signature {
        r8: Point {
            x: parse_dec(&cs.r8x)?,
            y: parse_dec(&cs.r8y)?,
        },
        s: parse_dec(&cs.s)?,
    };
    Some((pubkey, sig))
}

/// Verify an M-of-N SBT credential quorum over `commit_id_hex` against the pinned
/// `signers`. A co-signature counts iff its signer is a pinned member, the
/// BJJ-EdDSA signature verifies over [`sbt_quorum_message`], and that signer has
/// not already been counted. Mirrors `quorum::verify_generic_quorum`:
/// `satisfied` requires `valid >= threshold` **and** `threshold >= 1` (no ≥2
/// floor — that policy lives in the desktop acceptance path, not the core loop).
pub fn verify_sbt_quorum(
    curve: &Curve,
    commit_id_hex: &str,
    threshold: u32,
    signers: &[Signer],
    cosigs: &[CoSignature],
) -> QuorumOutcome {
    let msg = sbt_quorum_message(curve, commit_id_hex, threshold, signers);
    let allowed = canonical_set(&curve.p, signers);

    let mut counted: BTreeSet<(String, String)> = BTreeSet::new();
    for cs in cosigs {
        let Some(id) = normalize(&curve.p, &cs.x, &cs.y) else {
            continue;
        };
        if !allowed.contains(&id) || counted.contains(&id) {
            continue;
        }
        let Some((pubkey, sig)) = cosig_parts(cs) else {
            continue;
        };
        if eddsa::verify(curve, &pubkey, &sig, &msg).is_ok() {
            counted.insert(id);
        }
    }

    let valid_signatures = counted.len();
    QuorumOutcome {
        valid_signatures,
        total_signers: allowed.len(),
        satisfied: threshold >= 1 && valid_signatures >= threshold as usize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eddsa::EddsaError;

    #[derive(serde::Deserialize)]
    struct Expected {
        message: String,
        satisfied: bool,
        valid_signatures: u64,
        total_signers: u64,
    }

    #[derive(serde::Deserialize)]
    struct Case {
        name: String,
        commit_id: String,
        threshold: u32,
        signers: Vec<Signer>,
        cosignatures: Vec<CoSignature>,
        expected: Expected,
    }

    #[derive(serde::Deserialize)]
    struct Vectors {
        domain: String,
        cases: Vec<Case>,
    }

    fn load() -> Vectors {
        let raw = std::fs::read_to_string("../test_vectors/sbt_quorum_vectors.json")
            .expect("read sbt_quorum_vectors.json");
        serde_json::from_str(&raw).expect("parse sbt_quorum_vectors.json")
    }

    fn case_by_name<'a>(v: &'a Vectors, name: &str) -> &'a Case {
        v.cases
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing case `{name}`"))
    }

    /// Independent re-derivation ↔ Rust producer, byte-for-byte, plus the M-of-N
    /// counting outcome for every case (positive and negative alike).
    #[test]
    fn committed_sbt_quorum_vectors_verify() {
        let vectors = load();
        assert_eq!(vectors.domain, "OLY:SBT:QUORUM:V2", "domain tag");
        assert!(!vectors.cases.is_empty(), "vectors must not be empty");
        let curve = Curve::baby_jubjub();

        for c in &vectors.cases {
            // (1) Full pre-image byte-layout parity — nothing trusts expected.message.
            let msg = sbt_quorum_message(&curve, &c.commit_id, c.threshold, &c.signers);
            assert_eq!(
                msg.to_string(),
                c.expected.message,
                "case `{}`: re-derived message diverges from the Rust vector",
                c.name
            );

            // (2) M-of-N counting.
            let outcome = verify_sbt_quorum(
                &curve,
                &c.commit_id,
                c.threshold,
                &c.signers,
                &c.cosignatures,
            );
            assert_eq!(
                outcome.valid_signatures as u64, c.expected.valid_signatures,
                "case `{}`: valid_signatures",
                c.name
            );
            assert_eq!(
                outcome.total_signers as u64, c.expected.total_signers,
                "case `{}`: total_signers",
                c.name
            );
            assert_eq!(
                outcome.satisfied, c.expected.satisfied,
                "case `{}`: satisfied",
                c.name
            );
        }
    }

    /// Verify a single co-signature (by index) of a named case against that
    /// case's reconstructed SBT message. Returns the eddsa result plus whether
    /// the co-signer is a pinned member — so each negative can assert its
    /// *specific* rejection reason (equation vs. membership vs. distinctness).
    fn verify_one(
        curve: &Curve,
        v: &Vectors,
        name: &str,
        idx: usize,
    ) -> (Result<(), EddsaError>, bool) {
        let c = case_by_name(v, name);
        let msg = sbt_quorum_message(curve, &c.commit_id, c.threshold, &c.signers);
        let allowed = canonical_set(&curve.p, &c.signers);
        let cs = &c.cosignatures[idx];
        let is_member = normalize(&curve.p, &cs.x, &cs.y)
            .map(|id| allowed.contains(&id))
            .unwrap_or(false);
        let (pubkey, sig) = cosig_parts(cs).expect("cosignature parses");
        (eddsa::verify(curve, &pubkey, &sig, &msg), is_member)
    }

    /// A checkpoint-domain co-signature by a pinned SBT signer must be rejected
    /// by the verification *equation* (disjoint domain ⇒ different message), NOT
    /// by a membership miss.
    #[test]
    fn cross_domain_checkpoint_signature_rejected_by_equation_not_membership() {
        let vectors = load();
        let curve = Curve::baby_jubjub();
        let (result, is_member) =
            verify_one(&curve, &vectors, "cross_domain_checkpoint_sig_rejected", 0);
        assert!(
            is_member,
            "the checkpoint co-signer is a pinned member — the rejection must come from the domain, not membership"
        );
        assert_eq!(
            result,
            Err(EddsaError::Rejected),
            "a checkpoint-domain signature must fail the SBT verification equation"
        );
    }

    /// R3-01: threshold downgrade / signer-set tamper / signer-set shrink /
    /// wrong commit_id all change the bound message, so honest (still-member)
    /// signatures fail the equation — a specific `Rejected`, not a parse error.
    #[test]
    fn r3_01_rebinding_breaks_member_signatures_by_equation() {
        let vectors = load();
        let curve = Curve::baby_jubjub();
        for name in [
            "threshold_downgrade_breaks_quorum",
            "signer_set_tampered_rejected",
            "signer_set_dropped_rejected",
            "wrong_commit_id_rejected",
        ] {
            let c = case_by_name(&vectors, name);
            for idx in 0..c.cosignatures.len() {
                let (result, is_member) = verify_one(&curve, &vectors, name, idx);
                assert!(
                    is_member,
                    "case `{name}` cosig {idx}: signer must still be a pinned member so the failure is the equation"
                );
                assert_eq!(
                    result,
                    Err(EddsaError::Rejected),
                    "case `{name}` cosig {idx}: must fail the equation (rebound message)"
                );
            }
        }
    }

    /// A mutated `S` scalar (still reduced mod l) reaches the equation and is
    /// refused there — `Rejected`, not `NonCanonicalS` and not a parse error.
    #[test]
    fn tampered_signature_rejected_by_equation() {
        let vectors = load();
        let curve = Curve::baby_jubjub();
        let (result, is_member) = verify_one(&curve, &vectors, "tampered_signature_rejected", 0);
        assert!(is_member, "signer is pinned");
        assert_eq!(result, Err(EddsaError::Rejected));
    }

    /// A non-member's signature is a genuinely valid signature over the message,
    /// dropped only by the membership filter — the distinguishing reason.
    #[test]
    fn non_member_signature_verifies_but_is_not_a_member() {
        let vectors = load();
        let curve = Curve::baby_jubjub();
        let c = case_by_name(&vectors, "non_member_ignored");
        // cosignature[1] is the outsider (see the generator).
        let (result, is_member) = verify_one(&curve, &vectors, "non_member_ignored", 1);
        assert!(
            result.is_ok(),
            "the outsider's signature is valid over the message"
        );
        assert!(
            !is_member,
            "the outsider is not in the pinned set, so it must not count"
        );
        // And the member's signature does count.
        let (member_result, member_is_member) =
            verify_one(&curve, &vectors, "non_member_ignored", 0);
        assert!(member_result.is_ok() && member_is_member);
        assert_eq!(c.expected.valid_signatures, 1);
    }

    /// Two valid signatures from the same key are both individually valid, but
    /// collapse to one distinct signer — below the threshold of 2.
    #[test]
    fn duplicate_signer_counts_once() {
        let vectors = load();
        let curve = Curve::baby_jubjub();
        let (r0, m0) = verify_one(&curve, &vectors, "duplicate_signer_counts_once", 0);
        let (r1, m1) = verify_one(&curve, &vectors, "duplicate_signer_counts_once", 1);
        assert!(
            r0.is_ok() && r1.is_ok() && m0 && m1,
            "both signatures are individually valid member signatures"
        );
        let c = case_by_name(&vectors, "duplicate_signer_counts_once");
        let outcome = verify_sbt_quorum(
            &curve,
            &c.commit_id,
            c.threshold,
            &c.signers,
            &c.cosignatures,
        );
        assert_eq!(outcome.valid_signatures, 1, "distinctness collapses to one");
        assert!(!outcome.satisfied, "1 < threshold 2");
    }

    /// Reordering the pinned set is a no-op (canonical sort): the reconstructed
    /// message is byte-identical to the honest case, so the quorum still holds.
    #[test]
    fn reorder_is_message_invariant() {
        let vectors = load();
        let curve = Curve::baby_jubjub();
        let honest = case_by_name(&vectors, "valid_2_of_3");
        let reordered = case_by_name(&vectors, "signer_reorder_still_satisfied");
        let m_honest =
            sbt_quorum_message(&curve, &honest.commit_id, honest.threshold, &honest.signers);
        let m_reordered = sbt_quorum_message(
            &curve,
            &reordered.commit_id,
            reordered.threshold,
            &reordered.signers,
        );
        assert_eq!(
            m_honest, m_reordered,
            "reordering the pinned set must not change the message"
        );
        let outcome = verify_sbt_quorum(
            &curve,
            &reordered.commit_id,
            reordered.threshold,
            &reordered.signers,
            &reordered.cosignatures,
        );
        assert!(outcome.satisfied && outcome.valid_signatures == 2);
    }
}

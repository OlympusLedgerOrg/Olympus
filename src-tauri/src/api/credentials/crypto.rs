//! Deterministic credential digests and Fr-scalar helpers.
//!
//! Pure functions only — no HTTP/`AppError` surface. Split out of the
//! credentials module so the commit-id / revoke-digest domain separation and
//! the strict `parse_fr_decimal` decoder can be unit-tested in isolation and
//! reused across the crate (bootstrap, federation co-sign, auth, ZK manifest).

// ── Commit-hash helper ──────────────────────────────────────────────────────

/// RFC 8785 JCS canonical encoding of `details` for digest binding.
///
/// Canonicalises via `olympus_crypto::canonical` so the digest is reproducible
/// off-box by any conformant JCS implementation (the Python/JS verifiers), not
/// only by replicating serde_json's ordering. `details` is already a parsed
/// `serde_json::Value`, so this round-trips Value → JSON → canonical, which is
/// byte-exact for the scalar/string/object values SBT `details` carry. Falls
/// back to the raw serialization only if canonicalisation fails (e.g. nesting
/// beyond the shared depth cap of 64) — such details are not JCS-verifiable
/// off-box in *any* implementation, so this loses no parity versus before.
fn canonical_details_bytes(details: &serde_json::Value) -> Vec<u8> {
    let raw = serde_json::to_vec(details).unwrap_or_default();
    olympus_crypto::canonical::canonicalize_bytes(&raw).unwrap_or(raw)
}

/// Compute the deterministic `commit_id` for a credential.
///
/// Length-prefixing every variable-length component prevents
/// field-boundary collisions: a malicious issuer can't construct two
/// `(holder, type, details)` triples that hash to the same `commit_id`
/// by shuffling delimiters.
pub fn compute_commit_id(
    holder_key: &str,
    credential_type: &str,
    issued_at_unix: i64,
    details: &serde_json::Value,
) -> [u8; 32] {
    let details_bytes = canonical_details_bytes(details);
    let mut h = blake3::Hasher::new();
    h.update(b"OLY:SBT:V1");
    h.update(&(holder_key.len() as u32).to_be_bytes());
    h.update(holder_key.as_bytes());
    h.update(&(credential_type.len() as u32).to_be_bytes());
    h.update(credential_type.as_bytes());
    h.update(&issued_at_unix.to_be_bytes());
    h.update(&(details_bytes.len() as u32).to_be_bytes());
    h.update(&details_bytes);
    *h.finalize().as_bytes()
}

/// Compute the deterministic `commit_id` for a Pedersen-committed
/// credential.  For committed rows the server has no cleartext `details`
/// to hash, so the commit_id binds the COMMITMENT instead — domain-tagged
/// with `OLY:SBT:COMMIT:V1` so it can never collide with a plaintext-row
/// `commit_id` (which is tagged `OLY:SBT:V1`).
///
/// `commit_id = BLAKE3(
///     "OLY:SBT:COMMIT:V1"
///     | len(holder_key) || holder_key
///     | len(credential_type) || credential_type
///     | issued_at_unix (BE i64)
///     | len(commitment_x_dec) || commitment_x_dec
///     | len(commitment_y_dec) || commitment_y_dec
/// )`
pub fn compute_commit_id_for_commitment(
    holder_key: &str,
    credential_type: &str,
    issued_at_unix: i64,
    commitment_x_dec: &str,
    commitment_y_dec: &str,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(olympus_crypto::SBT_COMMIT_BIND_PREFIX);
    h.update(&(holder_key.len() as u32).to_be_bytes());
    h.update(holder_key.as_bytes());
    h.update(&(credential_type.len() as u32).to_be_bytes());
    h.update(credential_type.as_bytes());
    h.update(&issued_at_unix.to_be_bytes());
    h.update(&(commitment_x_dec.len() as u32).to_be_bytes());
    h.update(commitment_x_dec.as_bytes());
    h.update(&(commitment_y_dec.len() as u32).to_be_bytes());
    h.update(commitment_y_dec.as_bytes());
    *h.finalize().as_bytes()
}

/// Derive the Pedersen message scalar `m` for a credential's `details`.
///
/// `m = (BLAKE3-XOF 64 bytes of SBT_OPEN_PREFIX | len | details) mod l` where
/// `l` is the Baby Jubjub prime-subgroup order. The 64-byte XOF output is
/// reduced via `BigUint % l` *before* `Fr::from_le_bytes_mod_order`, so the
/// resulting field element is already in `[0, l)`. The `< l` guard inside
/// [`pedersen::commit`] is therefore belt-and-suspenders, not the primary
/// in-range check. With ≥ 64 bytes of XOF entropy reduced mod l (≈ 2²⁵²)
/// the residual bias is < 2⁻²⁵⁶ — indistinguishable from uniform — so no
/// re-hash loop is needed.
///
/// `details` is encoded with RFC 8785 JCS canonicalisation (via
/// `canonical_details_bytes`), so a holder can reconstruct `m` from the
/// cleartext using any conformant JCS implementation, independent of the field
/// ordering they send.
pub(super) fn digest_jcs_to_subgroup_scalar(details: &serde_json::Value) -> ark_bn254::Fr {
    use ark_ff::PrimeField;
    let body = canonical_details_bytes(details);
    // 64-byte XOF output. Reducing 64 bytes (≈ 2⁵¹²) mod the ≈ 2²⁵² subgroup
    // order leaves bias < 2⁻²⁵⁶ — indistinguishable from uniform. A 32-byte
    // output would have bias ~2⁻⁴ because 2²⁵⁶ ≈ 34 · l; that's acceptable
    // for a *deterministic message digest* (no entropy concern) but we use
    // 64 bytes anyway to keep one consistent reduction recipe across the
    // codebase (matches `random_blinding`).
    let mut hasher = blake3::Hasher::new();
    hasher.update(olympus_crypto::SBT_OPEN_PREFIX);
    hasher.update(b"|");
    hasher.update(&(body.len() as u32).to_be_bytes());
    hasher.update(&body);
    let mut xof = hasher.finalize_xof();
    let mut wide = [0u8; 64];
    xof.fill(&mut wide);

    let l_dec = "2736030358979909402780800718157159386076813972158567259200215660948447373041";
    let l: num_bigint::BigUint = l_dec.parse().expect("static decimal");
    let reduced = num_bigint::BigUint::from_bytes_be(&wide) % l;
    let bytes = reduced.to_bytes_le();
    ark_bn254::Fr::from_le_bytes_mod_order(&bytes)
}

/// Compute the deterministic revocation digest. Separated from
/// `commit_id` so a stolen issued-signature can't be replayed as a
/// revocation.
pub(super) fn compute_revoke_digest(commit_id_hex: &str, revoked_at_unix: i64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"OLY:SBT:REVOKE:V1");
    h.update(&(commit_id_hex.len() as u32).to_be_bytes());
    h.update(commit_id_hex.as_bytes());
    h.update(&revoked_at_unix.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Reduce 32 bytes (BLAKE3 digest) into a BN254 scalar `Fr` exactly the
/// way the in-circuit verifier expects.
pub(super) fn digest_to_fr(digest: &[u8; 32]) -> ark_bn254::Fr {
    use ark_ff::PrimeField;
    ark_bn254::Fr::from_le_bytes_mod_order(digest)
}

pub(super) use crate::zk::proof::fr_to_decimal;

/// Parse a decimal string as a BN254 scalar `Fr`, **rejecting** any value
/// that is greater than or equal to the field modulus.
///
/// Audit: the previous implementation used `from_be_bytes_mod_order` which
/// silently reduces — a caller submitting `m + r` (where `r` is the field
/// modulus) would get back `m`, breaking the invariant that a parsed `Fr`
/// is byte-equal to the decimal a holder claims to be presenting.
///
/// This is the choke point for every Fr-shaped field on the credentials
/// surface: stored Pedersen-commitment coordinates, issuer pubkey
/// coordinates, BJJ signature `(R8.x, R8.y, S)` fields, and user-supplied
/// openings `(m, r)`. All of them must round-trip through their original
/// decimal form, so all of them must reject the non-canonical encoding.
pub(crate) fn parse_fr_decimal(s: &str) -> Option<ark_bn254::Fr> {
    use ark_ff::{BigInteger, PrimeField};
    // Reject non-canonical decimals: empty, leading '+'/'-', or leading zeros
    // (other than the literal "0"). Round-trip via `fr_to_decimal` would
    // otherwise quietly lose the leading zero and break the invariant the
    // caller relies on. Audit L-API-2.
    if s.is_empty() {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    let bu: num_bigint::BigUint = s.parse().ok()?;
    let modulus = num_bigint::BigUint::from_bytes_le(&ark_bn254::Fr::MODULUS.to_bytes_le());
    if bu >= modulus {
        return None;
    }
    let bytes = bu.to_bytes_be();
    Some(ark_bn254::Fr::from_be_bytes_mod_order(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::pedersen;
    use serde_json::json;

    #[test]
    fn commit_id_is_deterministic_and_length_safe() {
        let a = compute_commit_id("alice", "press", 1700000000, &json!({"role": "journalist"}));
        let b = compute_commit_id("alice", "press", 1700000000, &json!({"role": "journalist"}));
        assert_eq!(a, b);
        // Length-prefixing prevents holder/type boundary collisions:
        // "ali" + "cepress" cannot collide with "alice" + "press".
        let collision_try =
            compute_commit_id("ali", "cepress", 1700000000, &json!({"role": "journalist"}));
        assert_ne!(a, collision_try);
    }

    #[test]
    fn commit_id_changes_with_any_field() {
        let base = compute_commit_id("a", "p", 1, &json!({}));
        assert_ne!(base, compute_commit_id("b", "p", 1, &json!({})));
        assert_ne!(base, compute_commit_id("a", "q", 1, &json!({})));
        assert_ne!(base, compute_commit_id("a", "p", 2, &json!({})));
        assert_ne!(base, compute_commit_id("a", "p", 1, &json!({"x": 1})));
    }

    #[test]
    fn revoke_digest_is_distinct_from_commit_id() {
        let cid = hex::encode(compute_commit_id("a", "p", 1, &json!({})));
        let rd = compute_revoke_digest(&cid, 1);
        // The two digests are derived from distinct domain tags so they
        // can never collide — an issued signature is not a valid
        // revocation signature and vice versa.
        let bytes = hex::decode(&cid).expect("hex");
        assert_ne!(&rd[..], &bytes[..]);
    }

    // ── Pedersen commitment helpers (PD-3) ─────────────────────────────────

    #[test]
    fn digest_jcs_to_subgroup_scalar_is_deterministic() {
        // Same `details` → same `m`. Property the commitment scheme relies
        // on for holder-side verification.
        let d = json!({"role": "journalist", "tier": 2});
        assert_eq!(
            digest_jcs_to_subgroup_scalar(&d),
            digest_jcs_to_subgroup_scalar(&d)
        );
    }

    #[test]
    fn digest_jcs_to_subgroup_scalar_lands_in_subgroup() {
        // The digest MUST be in [0, l) so pedersen::commit accepts it
        // without the subgroup-scalar guard rejecting (which it would for
        // ~1-in-8 raw Fr values). Verify by trying to commit with r=0.
        let d = json!({"x": 1});
        let m = digest_jcs_to_subgroup_scalar(&d);
        // commit(m, 0) must NOT return ScalarOutOfRange for m.
        assert!(pedersen::commit(m, ark_bn254::Fr::from(0u64)).is_ok());
    }

    #[test]
    fn commit_ids_have_disjoint_domains() {
        // The plaintext-row commit_id (OLY:SBT:V1 tag) and the
        // committed-row commit_id (OLY:SBT:COMMIT:V1 tag) must NEVER
        // collide, even for inputs designed to confuse them. A plaintext
        // row whose `details` happens to contain the same bytes as a
        // commitment's `(x_dec, y_dec)` pair must produce a different
        // commit_id.
        let plain = compute_commit_id("alice", "press", 17, &json!({"x": "1", "y": "2"}));
        let committed = compute_commit_id_for_commitment("alice", "press", 17, "1", "2");
        assert_ne!(
            plain, committed,
            "domain tags must keep plaintext and committed commit_ids structurally disjoint"
        );
    }

    #[test]
    fn commit_id_for_commitment_changes_with_every_field() {
        // Each input field is hashed in — flipping any one must change the
        // output. Catches accidental input shadowing or length-prefix bugs.
        let base = compute_commit_id_for_commitment("alice", "press", 17, "1", "2");
        assert_ne!(
            base,
            compute_commit_id_for_commitment("alic", "epress", 17, "1", "2")
        );
        assert_ne!(
            base,
            compute_commit_id_for_commitment("alice", "presS", 17, "1", "2")
        );
        assert_ne!(
            base,
            compute_commit_id_for_commitment("alice", "press", 18, "1", "2")
        );
        assert_ne!(
            base,
            compute_commit_id_for_commitment("alice", "press", 17, "11", "2")
        );
        assert_ne!(
            base,
            compute_commit_id_for_commitment("alice", "press", 17, "1", "22")
        );
    }
    // ── parse_fr_decimal strict-decoding (audit M-3) ───────────────────────

    /// BN254 scalar field modulus as a decimal string.
    const FR_MODULUS_DEC: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    #[test]
    fn parse_fr_decimal_rejects_modulus() {
        // r itself must NOT silently reduce to 0. The fail-closed contract
        // is what stops a malicious holder from claiming m or r is e.g.
        // 0 while presenting `Fr::MODULUS` as the decimal form.
        assert!(parse_fr_decimal(FR_MODULUS_DEC).is_none());
    }

    #[test]
    fn parse_fr_decimal_rejects_modulus_plus_one() {
        let mut plus_one: num_bigint::BigUint = FR_MODULUS_DEC.parse().unwrap();
        plus_one += 1u32;
        assert!(parse_fr_decimal(&plus_one.to_str_radix(10)).is_none());
    }

    #[test]
    fn parse_fr_decimal_accepts_modulus_minus_one() {
        // Largest in-field value must parse and round-trip.
        let mut minus_one: num_bigint::BigUint = FR_MODULUS_DEC.parse().unwrap();
        minus_one -= 1u32;
        let s = minus_one.to_str_radix(10);
        let fr = parse_fr_decimal(&s).expect("r-1 is in-field");
        assert_eq!(fr_to_decimal(&fr), s);
    }

    #[test]
    fn parse_fr_decimal_rejects_huge_decimal() {
        let huge: num_bigint::BigUint = num_bigint::BigUint::from(1u8) << 300usize;
        assert!(parse_fr_decimal(&huge.to_str_radix(10)).is_none());
    }

    #[test]
    fn parse_fr_decimal_rejects_non_numeric() {
        assert!(parse_fr_decimal("not a number").is_none());
    }

    #[test]
    fn opening_round_trips_through_commit_verify() {
        // End-to-end without touching DB / HTTP: m comes from details,
        // r is a fresh random, commit(m, r) == C, verify with the same
        // opening recovers C, verify with a wrong opening does not.
        let details = json!({"role": "journalist", "verified": true});
        let m = digest_jcs_to_subgroup_scalar(&details);
        let r = pedersen::random_blinding(&mut rand::thread_rng());
        let c = pedersen::commit(m, r).expect("commit");
        // Correct opening verifies.
        assert!(pedersen::verify(&c, m, r).expect("verify"));
        // Modifying r breaks verify.
        assert!(!pedersen::verify(&c, m, r + ark_bn254::Fr::from(1u64)).expect("verify"));
    }
}

//! Field element bounds validation — edge case 4 (Protobuf-to-field truncation).
//!
//! The BN254 scalar field modulus r is a 254-bit prime:
//!   r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//!
//! Any byte sequence whose big-endian integer value ≥ r undergoes a **silent**
//! modular reduction when passed to `Fr::from_le_bytes_mod_order()`. Callers
//! accepting field elements from external sources (Protobuf `bytes` fields,
//! JSON RPC payloads, inter-service messages) MUST call these validators before
//! constructing an `Fr` — otherwise a balance of `r + 1` silently becomes `1`,
//! and a balance of `r` silently becomes `0`.
//!
//! **u64 values are always safe**: u64_max ≈ 1.8×10¹⁹ ≪ r ≈ 2.19×10⁷⁶, so
//! `Fr::from(some_u64)` never truncates and does not need this check.
//!
//! **32-byte payloads are not safe**: values in the range [r, 2²⁵⁶) are
//! syntactically valid 32-byte slices but semantically invalid field elements.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FieldValidationError {
    #[error(
        "field element exceeds BN254 scalar modulus: {bits}-bit value would be silently reduced"
    )]
    ExceedsModulus { bits: u64 },
    #[error("empty byte slice cannot represent a field element")]
    EmptyBytes,
}

/// Compute the BN254 scalar field modulus as a `BigUint`.
fn bn254_r() -> BigUint {
    // Derive from the canonical arkworks constant to stay in sync with the
    // crate rather than hardcoding a decimal literal that could drift.
    let mod_le = Fr::MODULUS.to_bytes_le();
    BigUint::from_bytes_le(&mod_le)
}

/// Validate that a **big-endian** byte slice represents a value strictly less
/// than the BN254 scalar field modulus `r`, then return the corresponding `Fr`.
///
/// Rejects values in `[r, 2^256)` that would otherwise be silently reduced by
/// `Fr::from_be_bytes_mod_order`. This is the primary guard for field elements
/// arriving from Protobuf `bytes` fields or any external wire format that packs
/// values into fixed-width 32-byte buffers.
pub fn validate_be_bytes_to_fr(bytes: &[u8]) -> Result<Fr, FieldValidationError> {
    if bytes.is_empty() {
        return Err(FieldValidationError::EmptyBytes);
    }
    let n = BigUint::from_bytes_be(bytes);
    validate_biguint_to_fr(n)
}

/// Validate that a **little-endian** byte slice represents a value < r.
pub fn validate_le_bytes_to_fr(bytes: &[u8]) -> Result<Fr, FieldValidationError> {
    if bytes.is_empty() {
        return Err(FieldValidationError::EmptyBytes);
    }
    let n = BigUint::from_bytes_le(bytes);
    validate_biguint_to_fr(n)
}

/// Validate that a `BigUint` is strictly less than `r`, then convert to `Fr`.
///
/// This is the shared internal path for both byte-based entry points. It can
/// also be called directly when the caller already holds a `BigUint` (e.g.,
/// after parsing a decimal string from a Protobuf field).
pub fn validate_biguint_to_fr(n: BigUint) -> Result<Fr, FieldValidationError> {
    let r = bn254_r();
    if n >= r {
        return Err(FieldValidationError::ExceedsModulus { bits: n.bits() });
    }
    // Safe: validated n < r, so from_le_bytes_mod_order reduces by zero.
    Ok(Fr::from_le_bytes_mod_order(&n.to_bytes_le()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_round_trips() {
        let fr = validate_be_bytes_to_fr(&[0u8; 32]).unwrap();
        assert_eq!(fr, Fr::from(0u64));
    }

    #[test]
    fn one_round_trips() {
        let mut bytes = [0u8; 32];
        bytes[31] = 1; // big-endian 1
        let fr = validate_be_bytes_to_fr(&bytes).unwrap();
        assert_eq!(fr, Fr::from(1u64));
    }

    #[test]
    fn u64_max_is_valid() {
        // u64::MAX ≈ 1.8×10¹⁹ ≪ r ≈ 2.19×10⁷⁶ — no truncation possible.
        let n = BigUint::from(u64::MAX);
        validate_biguint_to_fr(n).unwrap();
    }

    #[test]
    fn modulus_itself_is_rejected() {
        // r would silently reduce to 0, changing any amount to zero.
        let r = bn254_r();
        let err = validate_biguint_to_fr(r).unwrap_err();
        assert!(matches!(err, FieldValidationError::ExceedsModulus { .. }));
    }

    #[test]
    fn modulus_plus_one_is_rejected() {
        let r_plus_one = bn254_r() + 1u32;
        assert!(validate_biguint_to_fr(r_plus_one).is_err());
    }

    #[test]
    fn modulus_minus_one_is_valid() {
        // r - 1 is the largest representable field element.
        let r_minus_one = bn254_r() - 1u32;
        validate_biguint_to_fr(r_minus_one).unwrap();
    }

    #[test]
    fn empty_bytes_are_rejected() {
        assert!(validate_be_bytes_to_fr(&[]).is_err());
        assert!(validate_le_bytes_to_fr(&[]).is_err());
    }

    #[test]
    fn all_ones_32_bytes_is_rejected() {
        // 2^256 - 1 is far above r.
        let bytes = [0xFFu8; 32];
        assert!(validate_be_bytes_to_fr(&bytes).is_err());
    }

    #[test]
    fn le_and_be_round_trip_same_element() {
        let value = BigUint::from(123_456_789u64);
        let be = value.to_bytes_be();
        let le = value.to_bytes_le();
        let fr_be = validate_be_bytes_to_fr(&be).unwrap();
        let fr_le = validate_le_bytes_to_fr(&le).unwrap();
        assert_eq!(fr_be, fr_le);
    }
}

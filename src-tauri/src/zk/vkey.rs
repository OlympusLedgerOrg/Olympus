//! Parse snarkjs Groth16 verification-key JSON into `ark-groth16` types.
//!
//! snarkjs serialises BN254 G1 points as `["x","y","1"]` (decimal strings,
//! projective, z=1) and G2 points as `[["x_c0","x_c1"],["y_c0","y_c1"],["1","0"]]`.
//! Public input coefficients (`IC`) are G1 points.

use std::path::Path;
use std::str::FromStr;

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use num_bigint::BigUint;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VkeyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Field element parse error: {0}")]
    Field(String),
    #[error("Curve point not on curve")]
    PointNotOnCurve,
    /// Edge case 1 / 5 — subgroup membership failure.
    ///
    /// BN254 G1 and G2 each have a cofactor. A point that is on the curve but
    /// NOT in the correct prime-order subgroup would pass `is_on_curve()` yet
    /// lead to incorrect pairing results, potentially allowing a forged proof
    /// or a Phase-2 desync where a rogue node injects a manipulated vkey.
    #[error("Curve point is on the curve but not in the correct prime-order subgroup")]
    PointNotInSubgroup,
}

// ── Raw JSON shapes ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RawVkey {
    pub protocol: String,
    pub curve: String,
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
}

// ── Field / point parsing helpers ─────────────────────────────────────────────

fn parse_fq(s: &str) -> Result<Fq, VkeyError> {
    let n =
        BigUint::from_str(s).map_err(|e| VkeyError::Field(format!("BigUint parse '{s}': {e}")))?;
    // High finding: from_le_bytes_mod_order silently reduces — it is not a
    // validator.  Explicitly reject values >= Fq::MODULUS (BN254 base field).
    let modulus = BigUint::from_bytes_le(&Fq::MODULUS.to_bytes_le());
    if n >= modulus {
        return Err(VkeyError::Field(format!(
            "field element '{s}' exceeds BN254 base field modulus"
        )));
    }
    Ok(Fq::from_le_bytes_mod_order(&n.to_bytes_le()))
}

pub(super) fn parse_g1(coords: &[String]) -> Result<G1Affine, VkeyError> {
    if coords.len() < 2 {
        return Err(VkeyError::Field("G1 needs at least 2 coords".into()));
    }
    let x = parse_fq(&coords[0])?;
    let y = parse_fq(&coords[1])?;
    let pt = G1Affine::new_unchecked(x, y);
    if !pt.is_on_curve() {
        return Err(VkeyError::PointNotOnCurve);
    }
    // Edge case 1/5: being on the curve is necessary but not sufficient.
    // A point in a cofactor subgroup passes is_on_curve() but would break the
    // Groth16 pairing check or allow a rogue federation node to substitute a
    // maliciously crafted vkey component.
    if !pt.is_in_correct_subgroup_assuming_on_curve() {
        return Err(VkeyError::PointNotInSubgroup);
    }
    Ok(pt)
}

fn parse_fq2(pair: &[String]) -> Result<Fq2, VkeyError> {
    if pair.len() < 2 {
        return Err(VkeyError::Field("Fq2 needs 2 components".into()));
    }
    // snarkjs: c0 = pair[0], c1 = pair[1]
    Ok(Fq2::new(parse_fq(&pair[0])?, parse_fq(&pair[1])?))
}

pub(super) fn parse_g2(coords: &[Vec<String>]) -> Result<G2Affine, VkeyError> {
    if coords.len() < 2 {
        return Err(VkeyError::Field("G2 needs at least 2 coord pairs".into()));
    }
    let x = parse_fq2(&coords[0])?;
    let y = parse_fq2(&coords[1])?;
    let pt = G2Affine::new_unchecked(x, y);
    if !pt.is_on_curve() {
        return Err(VkeyError::PointNotOnCurve);
    }
    if !pt.is_in_correct_subgroup_assuming_on_curve() {
        return Err(VkeyError::PointNotInSubgroup);
    }
    Ok(pt)
}

// ── Fingerprinting ─────────────────────────────────────────────────────────────

/// Compute a BLAKE3 fingerprint of a raw vkey JSON string.
///
/// Edge case 5 — Phase 2 key desynchronization.
///
/// In a federated deployment every node must use **the same** verification key.
/// Because keys are embedded at compile time (`include_str!`) a mismatched vkey
/// causes one partition to accept proofs that the other rejects — silent
/// consensus failure.  Calling this function on startup and comparing the result
/// across nodes (via an out-of-band channel or a federation gossip protocol)
/// lets operators detect a partial deployment before it causes data loss.
///
/// The fingerprint is over the raw JSON bytes, not the parsed `VerifyingKey`,
/// so it catches whitespace / ordering differences that would otherwise survive
/// parsing.
pub fn vkey_blake3_fingerprint(json: &str) -> [u8; 32] {
    *blake3::hash(json.as_bytes()).as_bytes()
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Load and parse a snarkjs vkey JSON file.
pub fn load_vkey(path: impl AsRef<Path>) -> Result<VerifyingKey<Bn254>, VkeyError> {
    let json = std::fs::read_to_string(path)?;
    parse_vkey_json(&json)
}

/// Parse a snarkjs vkey JSON string (useful for embedding keys at compile time).
pub fn parse_vkey_json(json: &str) -> Result<VerifyingKey<Bn254>, VkeyError> {
    let raw: RawVkey = serde_json::from_str(json)?;
    from_raw(&raw)
}

pub fn from_raw(raw: &RawVkey) -> Result<VerifyingKey<Bn254>, VkeyError> {
    // Validate the otherwise-ignored header fields so a mislabelled / mismatched
    // vkey fails fast here rather than implicitly (and only later) inside
    // ark-groth16's verify. Cheap, and it hardens the file-loaded `load_vkey`
    // path which is not ceremony-checked at compile time.
    if !raw.protocol.eq_ignore_ascii_case("groth16") {
        return Err(VkeyError::Field(format!(
            "unsupported protocol '{}': expected groth16",
            raw.protocol
        )));
    }
    if !raw.curve.eq_ignore_ascii_case("bn128") {
        return Err(VkeyError::Field(format!(
            "unsupported curve '{}': expected bn128",
            raw.curve
        )));
    }
    // gamma_abc_g1 (IC) has nPublic + 1 entries (one extra for the constant term).
    if raw.ic.len() != raw.n_public + 1 {
        return Err(VkeyError::Field(format!(
            "nPublic ({}) inconsistent with IC length ({}): expected IC == nPublic + 1",
            raw.n_public,
            raw.ic.len()
        )));
    }

    let alpha_g1 = parse_g1(&raw.vk_alpha_1)?;
    let beta_g2 = parse_g2(&raw.vk_beta_2)?;
    let gamma_g2 = parse_g2(&raw.vk_gamma_2)?;
    let delta_g2 = parse_g2(&raw.vk_delta_2)?;

    let gamma_abc_g1 = raw
        .ic
        .iter()
        .map(|coords| parse_g1(coords))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── vkey_blake3_fingerprint ────────────────────────────────────────────────

    #[test]
    fn fingerprint_is_deterministic() {
        let json = r#"{"protocol":"groth16"}"#;
        assert_eq!(vkey_blake3_fingerprint(json), vkey_blake3_fingerprint(json));
    }

    #[test]
    fn different_json_gives_different_fingerprint() {
        let a = vkey_blake3_fingerprint(r#"{"a":1}"#);
        let b = vkey_blake3_fingerprint(r#"{"a":2}"#);
        assert_ne!(a, b);
    }

    #[test]
    fn whitespace_difference_changes_fingerprint() {
        // Raw-bytes fingerprint: compact vs pretty-printed must differ.
        let compact = vkey_blake3_fingerprint(r#"{"a":1}"#);
        let spaced = vkey_blake3_fingerprint(r#"{ "a": 1 }"#);
        assert_ne!(compact, spaced, "whitespace must change the fingerprint");
    }
}

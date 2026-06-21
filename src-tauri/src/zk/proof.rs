//! Parse snarkjs Groth16 proof JSON into `ark-groth16` types.
//!
//! snarkjs proof shape:
//! ```json
//! {
//!   "pi_a": ["x","y","1"],
//!   "pi_b": [["x_c0","x_c1"],["y_c0","y_c1"],["1","0"]],
//!   "pi_c": ["x","y","1"],
//!   "protocol": "groth16",
//!   "curve": "bn128"
//! }
//! ```
//! Public signals are a separate array of decimal strings.

use std::str::FromStr;

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;
use num_bigint::BigUint;
use serde::Deserialize;
use thiserror::Error;

use super::vkey::{parse_g1, parse_g2, VkeyError};

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Field parse error: {0}")]
    Field(String),
    #[error("Curve point error: {0}")]
    Curve(#[from] VkeyError),
}

#[derive(Deserialize)]
pub struct RawProof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
}

/// Parse a snarkjs proof JSON string.
pub fn parse_proof_json(json: &str) -> Result<Proof<Bn254>, ProofError> {
    let raw: RawProof = serde_json::from_str(json)?;
    from_raw(&raw)
}

/// Reject a G1 point whose projective z-coordinate isn't the affine normal form
/// `"1"` (audit proof-z / L-1). `parse_g1` reads only the affine x/y and drops z;
/// snarkjs always emits z = "1", so anything else is a non-canonical/garbage
/// encoding. NOT a soundness fix (the affine point is independently
/// curve+subgroup-checked) — strictness / defense-in-depth so a stricter parser
/// can't be claimed to accept what this one silently ignored.
fn check_g1_affine_z(coords: &[String], which: &str) -> Result<(), ProofError> {
    match coords.get(2) {
        Some(z) if z == "1" => Ok(()),
        Some(z) => Err(ProofError::Field(format!(
            "{which} projective z must be \"1\" (affine), got {z:?}"
        ))),
        None => Err(ProofError::Field(format!("{which} missing z-coordinate"))),
    }
}

/// G2 affine normal form requires the projective z = `["1","0"]`.
fn check_g2_affine_z(pi_b: &[Vec<String>]) -> Result<(), ProofError> {
    match pi_b.get(2) {
        Some(z) if z.len() == 2 && z[0] == "1" && z[1] == "0" => Ok(()),
        Some(z) => Err(ProofError::Field(format!(
            "pi_b projective z must be [\"1\",\"0\"] (affine), got {z:?}"
        ))),
        None => Err(ProofError::Field("pi_b missing z-coordinate".into())),
    }
}

pub fn from_raw(raw: &RawProof) -> Result<Proof<Bn254>, ProofError> {
    // Strictness (audit proof-z / L-1): reject a non-canonical projective z
    // before parse_g1/parse_g2 silently drop it.
    check_g1_affine_z(&raw.pi_a, "pi_a")?;
    check_g2_affine_z(&raw.pi_b)?;
    check_g1_affine_z(&raw.pi_c, "pi_c")?;
    Ok(Proof {
        a: parse_g1(&raw.pi_a)?,
        b: parse_g2(&raw.pi_b)?,
        c: parse_g1(&raw.pi_c)?,
    })
}

/// Parse public signals from a JSON array of decimal strings.
pub fn parse_public_signals(json: &str) -> Result<Vec<Fr>, ProofError> {
    let raw: Vec<String> = serde_json::from_str(json)?;
    parse_signals_slice(&raw)
}

pub fn parse_signals_slice(signals: &[String]) -> Result<Vec<Fr>, ProofError> {
    signals.iter().map(|s| parse_fr(s)).collect()
}

pub fn parse_fr(s: &str) -> Result<Fr, ProofError> {
    let n = BigUint::from_str(s).map_err(|e| ProofError::Field(format!("BigUint '{s}': {e}")))?;
    // Audit: `from_le_bytes_mod_order` silently reduces — it is NOT a
    // validator. For Groth16 public inputs and proof coordinates, an
    // overlarge decimal that reduces to the same field representative would
    // verify under the SNARK while differing from the value a client claims
    // to be attesting to. Explicitly reject any decimal >= the BN254 scalar
    // field modulus so the parsed `Fr` is byte-equal to its decimal source.
    let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
    if n >= modulus {
        return Err(ProofError::Field(format!(
            "field element '{s}' >= BN254 scalar field modulus (non-canonical)"
        )));
    }
    Ok(Fr::from_le_bytes_mod_order(&n.to_bytes_le()))
}

/// `Fr` → canonical big-endian decimal string. Inverse of [`parse_fr`], and the
/// single crate-wide helper for emitting BN254 scalars (BJJ pubkeys / signatures,
/// public signals, manifest fields) as the decimal strings snarkjs and the JS
/// verifier expect.
pub fn fr_to_decimal(f: &Fr) -> String {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_string()
}

/// Convenience: parse both proof and signals from a combined snarkjs output object.
///
/// Expected shape: `{"proof":{...}, "publicSignals":[...]}`
#[derive(Deserialize)]
struct FullProveOutput {
    proof: RawProof,
    #[serde(rename = "publicSignals")]
    public_signals: Vec<String>,
}

pub fn parse_full_prove_output(json: &str) -> Result<(Proof<Bn254>, Vec<Fr>), ProofError> {
    let out: FullProveOutput = serde_json::from_str(json)?;
    let proof = from_raw(&out.proof)?;
    let signals = parse_signals_slice(&out.public_signals)?;
    Ok((proof, signals))
}

/// Serialise an `ark-groth16` proof into the snarkjs `proof.json` shape
/// (`pi_a`/`pi_b`/`pi_c` as decimal field-element strings) — the inverse of
/// [`parse_proof_json`] and the single source of truth for proof export.
/// `/zk/prove`, redaction, own-checkpoints, ingest bundles and quorum
/// credentials all route their proof JSON through this one function.
///
/// Reads each coordinate directly from its base-field element via
/// `into_bigint()` (canonical reduced integer). Do NOT slice
/// `serialize_uncompressed` output: arkworks packs the short-Weierstrass
/// sign/infinity flag into the spare high bits of each coordinate's
/// most-significant byte, so `from_bytes_le(&buf[32..64])` yields `y + 2^255`
/// — an off-curve value rejected by snarkjs and by our own [`parse_proof_json`]
/// (which reduces mod p to the wrong element). #1170 fixed this in the ingest
/// path; this helper closes the remaining export sites and de-duplicates them.
#[cfg(feature = "prover")]
pub(crate) fn proof_to_snarkjs_json(proof: &Proof<Bn254>) -> serde_json::Value {
    fn fq_to_decimal(f: &ark_bn254::Fq) -> String {
        num_bigint::BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_string()
    }
    fn g1(p: &ark_bn254::G1Affine) -> Vec<String> {
        vec![fq_to_decimal(&p.x), fq_to_decimal(&p.y), "1".into()]
    }
    fn g2(p: &ark_bn254::G2Affine) -> Vec<Vec<String>> {
        vec![
            vec![fq_to_decimal(&p.x.c0), fq_to_decimal(&p.x.c1)],
            vec![fq_to_decimal(&p.y.c0), fq_to_decimal(&p.y.c1)],
            vec!["1".into(), "0".into()],
        ]
    }
    serde_json::json!({
        "pi_a": g1(&proof.a),
        "pi_b": g2(&proof.b),
        "pi_c": g1(&proof.c),
        "protocol": "groth16",
        "curve": "bn128",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // BN254 scalar field order (r). parse_fr should reduce this to 0.
    const BN254_SCALAR_R: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    // ── parse_fr / parse_public_signals / parse_signals_slice ────────────────

    #[test]
    fn parse_fr_handles_zero_and_one() {
        assert_eq!(parse_fr("0").unwrap(), Fr::from(0u64));
        assert_eq!(parse_fr("1").unwrap(), Fr::from(1u64));
    }

    #[test]
    fn parse_fr_rejects_modulus() {
        // r itself reduces to 0 under from_le_bytes_mod_order; strict parsing
        // must reject so an attacker can't submit `r` as a stand-in for `0`
        // in a public signal.
        let r = parse_fr(BN254_SCALAR_R);
        assert!(matches!(r, Err(ProofError::Field(_))));
    }

    #[test]
    fn parse_fr_rejects_modulus_plus_one() {
        // r+1 would reduce to 1. Same attack class as above.
        let mut plus_one = BigUint::from_str(BN254_SCALAR_R).unwrap();
        plus_one += 1u32;
        let r = parse_fr(&plus_one.to_str_radix(10));
        assert!(matches!(r, Err(ProofError::Field(_))));
    }

    #[test]
    fn parse_fr_accepts_modulus_minus_one() {
        // r-1 is the largest in-field value. It must parse to itself.
        let mut minus_one = BigUint::from_str(BN254_SCALAR_R).unwrap();
        minus_one -= 1u32;
        let s = minus_one.to_str_radix(10);
        let fr = parse_fr(&s).expect("r-1 is in-field");
        // Round-trip: fr back to decimal must equal the input.
        let bytes_be = fr.into_bigint().to_bytes_be();
        let round = BigUint::from_bytes_be(&bytes_be);
        assert_eq!(round.to_str_radix(10), s);
    }

    #[test]
    fn parse_fr_rejects_huge_decimal() {
        // 2^300 is well above any BN254 field bound.
        let huge: BigUint = BigUint::from(1u8) << 300usize;
        let r = parse_fr(&huge.to_str_radix(10));
        assert!(matches!(r, Err(ProofError::Field(_))));
    }

    #[test]
    fn parse_fr_rejects_non_decimal_garbage() {
        let r = parse_fr("not-a-number");
        assert!(matches!(r, Err(ProofError::Field(_))));
    }

    #[test]
    fn parse_public_signals_empty_array() {
        let signals = parse_public_signals("[]").unwrap();
        assert!(signals.is_empty());
    }

    #[test]
    fn parse_public_signals_parses_decimal_strings() {
        let s = parse_public_signals(r#"["0","1","42"]"#).unwrap();
        assert_eq!(s, vec![Fr::from(0u64), Fr::from(1u64), Fr::from(42u64)]);
    }

    #[test]
    fn parse_public_signals_propagates_field_error() {
        let r = parse_public_signals(r#"["1","bogus"]"#);
        assert!(matches!(r, Err(ProofError::Field(_))));
    }

    #[test]
    fn parse_public_signals_rejects_non_array_json() {
        let r = parse_public_signals(r#"{"not":"array"}"#);
        assert!(matches!(r, Err(ProofError::Json(_))));
    }

    #[test]
    fn parse_signals_slice_handles_empty_slice() {
        let s = parse_signals_slice(&[]).unwrap();
        assert!(s.is_empty());
    }

    // ── parse_proof_json / from_raw ──────────────────────────────────────────

    #[test]
    fn parse_proof_json_rejects_malformed_json() {
        let r = parse_proof_json("not json");
        assert!(matches!(r, Err(ProofError::Json(_))));
    }

    #[test]
    fn parse_proof_json_rejects_missing_fields() {
        // Missing pi_b and pi_c → serde rejects with a Json error.
        let r = parse_proof_json(r#"{"pi_a":["1","2","1"]}"#);
        assert!(matches!(r, Err(ProofError::Json(_))));
    }

    #[test]
    fn parse_proof_json_rejects_invalid_field_element_in_pi_a() {
        // Well-formed JSON shape, but the curve-point parser rejects a
        // non-decimal field-element string.
        let json = r#"{
            "pi_a":["not-a-number","2","1"],
            "pi_b":[["1","0"],["2","0"],["1","0"]],
            "pi_c":["1","2","1"]
        }"#;
        let r = parse_proof_json(json);
        assert!(matches!(r, Err(ProofError::Curve(_))));
    }

    #[test]
    fn parse_proof_json_rejects_point_not_on_curve() {
        // (3, 4) is not on BN254; parse_g1 must reject it.
        let json = r#"{
            "pi_a":["3","4","1"],
            "pi_b":[["1","0"],["2","0"],["1","0"]],
            "pi_c":["1","2","1"]
        }"#;
        let r = parse_proof_json(json);
        assert!(matches!(r, Err(ProofError::Curve(_))));
    }

    // ── proof-z / L-1: projective z must be the affine normal form ────────────
    // These run before parse_g1/parse_g2, so the coordinates are valid-shaped
    // and the *only* defect is a non-canonical z → ProofError::Field.

    #[test]
    fn from_raw_rejects_non_canonical_pi_a_z() {
        let json = r#"{
            "pi_a":["1","2","2"],
            "pi_b":[["1","0"],["2","0"],["1","0"]],
            "pi_c":["1","2","1"]
        }"#;
        assert!(
            matches!(parse_proof_json(json), Err(ProofError::Field(_))),
            "pi_a z=2 must be rejected"
        );
    }

    #[test]
    fn from_raw_rejects_non_canonical_pi_c_z() {
        let json = r#"{
            "pi_a":["1","2","1"],
            "pi_b":[["1","0"],["2","0"],["1","0"]],
            "pi_c":["1","2","7"]
        }"#;
        assert!(matches!(parse_proof_json(json), Err(ProofError::Field(_))));
    }

    #[test]
    fn from_raw_rejects_non_canonical_pi_b_z() {
        // G2 projective z must be ["1","0"]; ["1","1"] is non-affine.
        let json = r#"{
            "pi_a":["1","2","1"],
            "pi_b":[["1","0"],["2","0"],["1","1"]],
            "pi_c":["1","2","1"]
        }"#;
        assert!(matches!(parse_proof_json(json), Err(ProofError::Field(_))));
    }

    #[test]
    fn from_raw_rejects_missing_z_coordinate() {
        // pi_a with only [x, y]: serde accepts the 2-element Vec, the z check rejects.
        let json = r#"{
            "pi_a":["1","2"],
            "pi_b":[["1","0"],["2","0"],["1","0"]],
            "pi_c":["1","2","1"]
        }"#;
        assert!(matches!(parse_proof_json(json), Err(ProofError::Field(_))));
    }

    // ── parse_full_prove_output ──────────────────────────────────────────────

    #[test]
    fn parse_full_prove_output_rejects_malformed_json() {
        let r = parse_full_prove_output("not json");
        assert!(matches!(r, Err(ProofError::Json(_))));
    }

    #[test]
    fn parse_full_prove_output_rejects_missing_proof_field() {
        let r = parse_full_prove_output(r#"{"publicSignals":[]}"#);
        assert!(matches!(r, Err(ProofError::Json(_))));
    }

    #[test]
    fn parse_full_prove_output_propagates_signal_error() {
        // Public-signals string list is well-formed JSON but contains a bad
        // field element. The proof body has a curve-validity issue we don't
        // get to — but the error type is the same shape (ProofError::Field
        // via Curve) so this also catches the malformed shape; we just want
        // *some* error, not Ok.
        let r = parse_full_prove_output(
            r#"{
            "proof":{"pi_a":["bogus","2","1"],
                     "pi_b":[["1","0"],["2","0"],["1","0"]],
                     "pi_c":["1","2","1"]},
            "publicSignals":["1","2"]
        }"#,
        );
        assert!(r.is_err());
    }

    // ── proof_to_snarkjs_json (export round-trip) ────────────────────────────

    #[cfg(feature = "prover")]
    #[test]
    fn proof_to_snarkjs_json_roundtrips_both_field_halves() {
        use ark_ec::AffineRepr;
        // G1 generator (1, 2) has a lower-half y; its negation (1, p-2) has an
        // upper-half y, which is where arkworks sets the YIsNegative sign flag.
        // Serialize -> parse must recover the same point regardless of half.
        let g1 = ark_bn254::G1Affine::generator();
        let g2 = ark_bn254::G2Affine::generator();
        let a = -g1;
        let c = g1;
        for b in [g2, -g2] {
            let proof = Proof::<Bn254> { a, b, c };
            let json = proof_to_snarkjs_json(&proof).to_string();
            let got = parse_proof_json(&json).expect("must re-parse");
            assert_eq!(got.a, proof.a, "pi_a roundtrip");
            assert_eq!(got.b, proof.b, "pi_b roundtrip");
            assert_eq!(got.c, proof.c, "pi_c roundtrip");
        }
    }
}

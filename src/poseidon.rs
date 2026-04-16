//! Poseidon hash function for BN254/BN128 curve, exposed to Python via PyO3.
//!
//! This module implements the Poseidon hash function optimized for zk-SNARKs,
//! using the BN254 scalar field. The implementation follows the Poseidon paper
//! (https://eprint.iacr.org/2019/458) with parameters suitable for the BN254 curve.
//!
//! Domain separation constants match the Circom circuits in proofs/circuits/.
//!
//! **NOTE**: This is a STUB implementation for structural refactoring purposes.
//! The round constants are incomplete (only 10 of 195). For production use,
//! the full constants from circomlibjs must be integrated. The current
//! implementation produces deterministic but NOT circuit-compatible hashes.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use num_bigint::BigUint;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

// ---------------------------------------------------------------------------
// Poseidon constants for BN254
// ---------------------------------------------------------------------------

/// The BN254 scalar field prime (r).
/// This is the order of the BN254 curve's scalar field.
const BN254_SCALAR_FIELD_STR: &str = 
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Domain separation constants matching Circom circuits.
pub const POSEIDON_DOMAIN_LEAF: u64 = 0;
pub const POSEIDON_DOMAIN_NODE: u64 = 1;

/// Poseidon round constants for t=3 (2 inputs + 1 capacity).
/// 
/// **STUB**: Only 10 of 195 constants are included. This is sufficient for
/// testing the architecture but NOT for production/circuit-compatible hashes.
/// Full constants must be generated using the Poseidon grain LFSR.
const POSEIDON_C: &[&str] = &[
    "14397397413755236225575615486459253198602422701513067526754101844196324375522",
    "10405129301473404666785234951972711717481302463898292859783056520670200613128",
    "5179144822360023508491245509308555580251733042407187134628755730783052214509",
    "9132640374240188374542843306219594180154739721841249568925550236430986592615",
    "20360807315276763881209958738450444293273549928693737723235350358403012458514",
    "17933600965499023212689924809448543050840131883187652471064418452962948061619",
    "3636213416533737411392076250708419981662897009810345015164671602334517041153",
    "2008540005368330234524962342006691994500273283000229509835662097352946198608",
    "16018407964853379535338740313053768402596521780991140819786060571607994549498",
    "20653139667070586705378398435856186172195806027708437373130914721152832286242",
    // TODO: Add remaining 185 constants for production use
];

/// Poseidon MDS matrix for t=3.
/// This is a 3x3 circulant matrix optimized for the BN254 field.
const POSEIDON_M: &[[&str; 3]; 3] = &[
    [
        "1",
        "2",
        "1",
    ],
    [
        "1",
        "1",
        "2",
    ],
    [
        "2",
        "1",
        "1",
    ],
];

// ---------------------------------------------------------------------------
// Poseidon implementation
// ---------------------------------------------------------------------------

/// Compute x^5 in the BN254 scalar field (S-box).
#[inline]
fn sbox(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

/// Poseidon permutation for t=3 elements.
fn poseidon_permutation(state: &mut [Fr; 3]) {
    let num_full_rounds = 8;
    let num_partial_rounds = 57;
    let half_full = num_full_rounds / 2;
    
    // Parse MDS matrix
    let mds: [[Fr; 3]; 3] = POSEIDON_M.map(|row| {
        row.map(|s| Fr::from(s.parse::<u64>().unwrap()))
    });
    
    let mut round_idx = 0;
    
    // First half of full rounds
    for _ in 0..half_full {
        // Add round constants
        for i in 0..3 {
            if round_idx * 3 + i < POSEIDON_C.len() {
                let c = Fr::from(BigUint::parse_bytes(POSEIDON_C[round_idx * 3 + i].as_bytes(), 10).unwrap());
                state[i] += c;
            }
        }
        round_idx += 1;
        
        // S-box layer (full)
        for i in 0..3 {
            state[i] = sbox(state[i]);
        }
        
        // MDS layer
        let old = *state;
        for i in 0..3 {
            state[i] = Fr::from(0u64);
            for j in 0..3 {
                state[i] += mds[i][j] * old[j];
            }
        }
    }
    
    // Partial rounds
    for _ in 0..num_partial_rounds {
        // Add round constants
        for i in 0..3 {
            if round_idx * 3 + i < POSEIDON_C.len() {
                let c = Fr::from(BigUint::parse_bytes(POSEIDON_C[round_idx * 3 + i].as_bytes(), 10).unwrap());
                state[i] += c;
            }
        }
        round_idx += 1;
        
        // S-box layer (partial - only first element)
        state[0] = sbox(state[0]);
        
        // MDS layer
        let old = *state;
        for i in 0..3 {
            state[i] = Fr::from(0u64);
            for j in 0..3 {
                state[i] += mds[i][j] * old[j];
            }
        }
    }
    
    // Second half of full rounds
    for _ in 0..half_full {
        // Add round constants
        for i in 0..3 {
            if round_idx * 3 + i < POSEIDON_C.len() {
                let c = Fr::from(BigUint::parse_bytes(POSEIDON_C[round_idx * 3 + i].as_bytes(), 10).unwrap());
                state[i] += c;
            }
        }
        round_idx += 1;
        
        // S-box layer (full)
        for i in 0..3 {
            state[i] = sbox(state[i]);
        }
        
        // MDS layer
        let old = *state;
        for i in 0..3 {
            state[i] = Fr::from(0u64);
            for j in 0..3 {
                state[i] += mds[i][j] * old[j];
            }
        }
    }
}

/// Compute Poseidon hash of two field elements.
/// 
/// Uses the sponge construction with capacity 1:
/// - state[0] = capacity (initialized to 0)
/// - state[1] = first input
/// - state[2] = second input
/// 
/// Returns state[0] after permutation.
pub fn poseidon_hash(a: Fr, b: Fr) -> Fr {
    let mut state = [Fr::from(0u64), a, b];
    poseidon_permutation(&mut state);
    state[0]
}

/// Domain-separated Poseidon leaf hash.
/// Computes: Poseidon(Poseidon(DOMAIN_LEAF, key), value)
pub fn poseidon_leaf_hash(key: Fr, value: Fr) -> Fr {
    let domain = Fr::from(POSEIDON_DOMAIN_LEAF);
    let inner = poseidon_hash(domain, key);
    poseidon_hash(inner, value)
}

/// Domain-separated Poseidon node hash.
/// Computes: Poseidon(Poseidon(DOMAIN_NODE, left), right)
pub fn poseidon_node_hash(left: Fr, right: Fr) -> Fr {
    let domain = Fr::from(POSEIDON_DOMAIN_NODE);
    let inner = poseidon_hash(domain, left);
    poseidon_hash(inner, right)
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Convert a BigUint to Fr (BN254 scalar field element).
fn biguint_to_fr(n: &BigUint) -> Fr {
    Fr::from(n.clone())
}

/// Convert Fr to BigUint.
fn fr_to_biguint(f: Fr) -> BigUint {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be())
}

/// Convert 32 bytes to a field element (with modular reduction).
pub fn bytes_to_field(bytes: &[u8]) -> Fr {
    let n = BigUint::from_bytes_be(bytes);
    let modulus = BigUint::parse_bytes(BN254_SCALAR_FIELD_STR.as_bytes(), 10).unwrap();
    let reduced = n % modulus;
    biguint_to_fr(&reduced)
}

// ---------------------------------------------------------------------------
// PyO3 bindings
// ---------------------------------------------------------------------------

/// Compute Poseidon hash from big integers (as decimal strings for large values).
///
/// This is the preferred function for Python as it handles full 254-bit field elements.
///
/// # Python signature  
/// ``poseidon_hash_bn254_bigint(a: str, b: str) -> str``
#[pyfunction]
pub fn poseidon_hash_bn254_bigint(a: &str, b: &str) -> String {
    let a_int = BigUint::parse_bytes(a.as_bytes(), 10).unwrap_or_default();
    let b_int = BigUint::parse_bytes(b.as_bytes(), 10).unwrap_or_default();
    
    let fa = biguint_to_fr(&a_int);
    let fb = biguint_to_fr(&b_int);
    let result = poseidon_hash(fa, fb);
    
    fr_to_biguint(result).to_string()
}

/// Compute domain-separated Poseidon leaf hash.
///
/// # Python signature
/// ``poseidon_leaf_hash_bn254(key: str, value: str) -> str``
#[pyfunction]
pub fn poseidon_leaf_hash_bn254(key: &str, value: &str) -> String {
    let key_int = BigUint::parse_bytes(key.as_bytes(), 10).unwrap_or_default();
    let value_int = BigUint::parse_bytes(value.as_bytes(), 10).unwrap_or_default();
    
    let fk = biguint_to_fr(&key_int);
    let fv = biguint_to_fr(&value_int);
    let result = poseidon_leaf_hash(fk, fv);
    
    fr_to_biguint(result).to_string()
}

/// Compute domain-separated Poseidon node hash.
///
/// # Python signature
/// ``poseidon_node_hash_bn254(left: str, right: str) -> str``
#[pyfunction]
pub fn poseidon_node_hash_bn254(left: &str, right: &str) -> String {
    let left_int = BigUint::parse_bytes(left.as_bytes(), 10).unwrap_or_default();
    let right_int = BigUint::parse_bytes(right.as_bytes(), 10).unwrap_or_default();
    
    let fl = biguint_to_fr(&left_int);
    let fr_val = biguint_to_fr(&right_int);
    let result = poseidon_node_hash(fl, fr_val);
    
    fr_to_biguint(result).to_string()
}

/// Convert 32 bytes to a BN254 field element (with modular reduction).
///
/// # Python signature
/// ``bytes_to_field_element(data: bytes) -> str``
#[pyfunction]
pub fn bytes_to_field_element(_py: Python<'_>, data: &Bound<'_, PyBytes>) -> String {
    let bytes = data.as_bytes();
    let result = bytes_to_field(bytes);
    fr_to_biguint(result).to_string()
}

/// Get the BN254 scalar field modulus.
///
/// # Python signature
/// ``get_bn254_scalar_field() -> str``
#[pyfunction]
pub fn get_bn254_scalar_field() -> String {
    BN254_SCALAR_FIELD_STR.to_string()
}

// ---------------------------------------------------------------------------
// Submodule registration
// ---------------------------------------------------------------------------

/// Register all Poseidon functions into the given Python (sub)module.
pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(poseidon_hash_bn254, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_hash_bn254_bigint, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_leaf_hash_bn254, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_node_hash_bn254, m)?)?;
    m.add_function(wrap_pyfunction!(bytes_to_field_element, m)?)?;
    m.add_function(wrap_pyfunction!(get_bn254_scalar_field, m)?)?;

    // Make the submodule importable as `olympus_core.poseidon`
    py.import("sys")?
        .getattr("modules")?
        .set_item("olympus_core.poseidon", m)?;

    Ok(())
}

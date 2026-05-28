//! Baby Jubjub prime-order subgroup scalar field `Fr`.
//!
//! The Baby Jubjub *curve* has order `8·l` where `l` is a 252-bit prime;
//! the prime-order subgroup has order exactly `l`. EdDSA scalars (the
//! `s` component of a signature, the secret-key scalar after BLAKE-512
//! derivation + cofactor clearing) live in this field.
//!
//! Numeric value:
//!
//! ```text
//! l = 2736030358979909402780800718157159386076813972158567259200215660948447373041
//! ```
//!
//! Distinct from BN254's scalar field `ark_bn254::Fr` ≈ 8·l, which is
//! Baby Jubjub's *base* field (where point coordinates live).

// The `MontConfig` derive macro expands into `#[cfg(feature = "asm")]`
// blocks; rustc complains because *this* crate has not declared that
// feature (it's an `ark-ff` internal feature). Silence the warning at
// module scope so the derive lands clean.
#![allow(unexpected_cfgs)]

use ark_ff::{Fp256, MontBackend, MontConfig};

/// `MontConfig` for the Baby Jubjub prime-subgroup order `l`.
///
/// The `generator = "31"` annotation is a multiplicative generator of the
/// non-zero scalars; same value `ark-ed-on-bn254`'s `FrConfig` uses, since
/// both curves share this subgroup order.
#[derive(MontConfig)]
#[modulus = "2736030358979909402780800718157159386076813972158567259200215660948447373041"]
#[generator = "31"]
pub struct FrConfig;

/// Prime-order scalar field of the Baby Jubjub subgroup.
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

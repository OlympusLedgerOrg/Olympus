//! Circomlib-compatible Baby Jubjub curve + EdDSA-Poseidon (permissive
//! replacement for `babyjubjub-rs`).
//!
//! This crate is a drop-in replacement for the parts of `babyjubjub-rs`
//! Olympus uses, with the GPL-3.0 transitive `poseidon-rs` dependency
//! removed. See [`THIRD_PARTY_LICENSES.md`] at the workspace root for the
//! licensing motivation.
//!
//! # Curve parameterization
//!
//! Baby Jubjub is a twisted Edwards curve over the BN254 scalar field:
//!
//! ```text
//! 168700·x² + y² = 1 + 168696·x²·y²
//! ```
//!
//! This is the **circomlib parameterization** (a=168700, d=168696), not the
//! algebraically-equivalent untwisted form (a=1, d=168696/168700) that
//! arkworks ships in `ark-ed-on-bn254`. The two forms are isomorphic, but
//! point coordinates and compressed bytes are NOT compatible across the
//! isomorphism — so trusted-issuer pubkeys, ceremony coordinator signatures
//! on `proofs/keys/manifests/*.json`, SBT signatures, federation
//! co-signatures, and Pedersen commitments all require the circomlib form.
//!
//! # Public surface
//!
//! - [`PrivateKey`] / [`PublicKey`] / [`Signature`] / [`verify`] — EdDSA
//! - [`compress`] / [`decompress`] — iden3 32-byte point codec
//! - [`BabyJubjubAffine`] / [`BabyJubjubProjective`] — raw curve points
//! - [`Fr`] — prime-subgroup scalar field

#![forbid(unsafe_code)]

pub mod compress;
pub mod curve;
pub mod eddsa;
pub mod field;

pub use compress::{compress, decompress, identity, DecompressError};
pub use curve::{BabyJubjubAffine, BabyJubjubConfig, BabyJubjubProjective, B8, COFACTOR};
pub use eddsa::{verify, EdDsaError, PrivateKey, PublicKey, Signature};
pub use field::Fr;

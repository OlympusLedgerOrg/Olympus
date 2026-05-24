//! Binary + Poseidon Merkle trees.
//!
//! The implementation lives in `olympus-crypto` (feature `merkle`) so it can be
//! unit-tested without the desktop GUI toolchain and shared with the offline
//! verifiers. Re-exported here so existing `crate::merkle::*` call sites keep
//! working unchanged.
pub use olympus_crypto::merkle::*;

//! Baby Jubjub EdDSA-Poseidon types for the `unified` circuit.
//!
//! Baby Jubjub is the twisted-Edwards curve native to BN254 — its base
//! field equals BN254's scalar field, so curve points and circuit witness
//! values share the same `Fr` representation.  The `unified` circuit
//! verifies an EdDSA-Poseidon signature using `circomlib`'s
//! `EdDSAPoseidonVerifier` template.
//!
//! Scope of this module (Round 3):
//!   * Type definitions for pubkey + signature, both as bare `Fr` triples
//!     in the encoding ark-circom expects.
//!   * `pubkey_hash()` — the in-circuit `authorityPubKeyHash` is
//!     `Poseidon(Ax, Ay)`, computed here so callers can pre-image the
//!     public signal.
//!   * `sign()` — **stub**.  Producing a circomlib-compatible
//!     EdDSA-Poseidon signature is a substantial port (BLAKE-512 key
//!     expansion, bit pruning per RFC 8032, Baby Jubjub scalar
//!     arithmetic in the prime-order subgroup, Poseidon-based challenge)
//!     and there is currently no Rust crate that matches circomlib's
//!     scheme exactly: `babyjubjub-rs` uses iden3's `ff` types instead
//!     of arkworks, and `taceo-eddsa-babyjubjub` uses Poseidon**2**
//!     rather than the original Poseidon.  The follow-up either
//!     vendors the circomlib reference or adds a thin arkworks bridge
//!     over `babyjubjub-rs`.
//!
//! The Round 3 design accepts externally-produced signatures — the
//! realistic deployment model is that the checkpoint authority signs
//! offline (HSM / air-gapped signer) and the prover just packages the
//! signature components as witness inputs.  `sign()` is only needed for
//! tests and dev-mode dummy authorities.

use ark_bn254::Fr;

use crate::zk::poseidon::{hash2, PoseidonError};

/// Baby Jubjub public key in affine coordinates.
#[derive(Debug, Clone, Copy)]
pub struct BabyJubJubPubKey {
    pub x: Fr,
    pub y: Fr,
}

impl BabyJubJubPubKey {
    /// The in-circuit `authorityPubKeyHash` = `Poseidon(Ax, Ay)`.
    /// Callers use this as a public input — the circuit re-derives it
    /// from the private (Ax, Ay) inputs and constrains equality.
    pub fn authority_hash(&self) -> Result<Fr, PoseidonError> {
        hash2(self.x, self.y)
    }
}

/// EdDSA-Poseidon signature over Baby Jubjub.
///
/// Fields match circomlib's `EdDSAPoseidonVerifier` private-input names:
///   * `r8x`, `r8y` — the R8 point's affine coordinates (in the subgroup
///     of order ℓ = 2736030358979909402780800718157159386076813972158507871...).
///   * `s` — scalar response in the subgroup.
#[derive(Debug, Clone, Copy)]
pub struct BabyJubJubSignature {
    pub r8x: Fr,
    pub r8y: Fr,
    pub s: Fr,
}

/// Produce a Baby Jubjub EdDSA-Poseidon signature over `message`.
///
/// **Not yet implemented.** Producing a signature that the in-circuit
/// `EdDSAPoseidonVerifier` accepts requires a circomlib-compatible
/// signer (see module-level docs for why no existing Rust crate is a
/// drop-in fit).  Follow-up work tracked in the Round 3 commit message.
///
/// Production callers should obtain signatures from the checkpoint
/// authority's external signing service and construct a
/// `BabyJubJubSignature` directly from the returned components.
pub fn sign(_private_key: &[u8; 32], _message: Fr) -> BabyJubJubSignature {
    unimplemented!(
        "Round 3 stub: Baby Jubjub EdDSA-Poseidon signer not yet \
         implemented in arkworks-Fr terms — see \
         src-tauri/src/zk/witness/baby_jubjub.rs module docs.  The \
         unified prover accepts externally-produced signatures; this \
         function only matters for tests and dev fixtures."
    )
}

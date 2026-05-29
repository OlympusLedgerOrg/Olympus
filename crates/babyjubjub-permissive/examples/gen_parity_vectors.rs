//! Capture circomlib-format EdDSA parity vectors from the live
//! `babyjubjub-rs` crate so the new permissive impl can be regression-
//! tested against them byte-for-byte.
//!
//! # Why this is an example, not a test
//!
//! The vectors are *checked in* (`tests/parity_vectors.json`) — the
//! parity test reads JSON, never `babyjubjub-rs`. This file regenerates
//! the JSON on demand, e.g. if circomlib's wire format ever changes in a
//! way upstream `babyjubjub-rs` mirrors.
//!
//! Run with: `cargo run -p babyjubjub-permissive --example
//! gen_parity_vectors`. Output goes to
//! `crates/babyjubjub-permissive/tests/parity_vectors.json`.
//!
//! # Determinism
//!
//! Uses a fixed `StdRng` seed so the vectors are reproducible — running
//! this twice produces the same JSON. Changing the seed or the vector
//! count is a deliberate, reviewable diff.
//!
//! # Removal plan
//!
//! Once Phase 4 drops `babyjubjub-rs` from the workspace entirely, this
//! example becomes uncompilable and is deleted in the same commit.
//! The JSON it produced lives on as the parity-test fixture.

use std::fs;
use std::path::PathBuf;

use babyjubjub_rs::PrivateKey;
use ff_ce::PrimeField as _;
use num_bigint::{BigInt, BigUint, Sign};
use rand::{RngCore, SeedableRng};
use serde::Serialize;

const NUM_VECTORS: usize = 100;
// Deliberate "babe coffee" mnemonic for the deterministic-vector seed;
// the underscore grouping departs from the per-byte pattern clippy
// recommends but reads better here. clippy::unusual_byte_groupings
// silenced on this one literal.
#[allow(clippy::unusual_byte_groupings)]
const SEED: u64 = 0xBA_BE_C0FFEE_u64;

#[derive(Serialize)]
struct Vector {
    /// 32-byte raw private key, hex-encoded.
    sk_hex: String,
    /// Decimal message in BN254 `Fq` (the curve's base field). Sampled
    /// in `[0, q)`.
    msg_dec: String,
    /// Public key coordinates as decimal strings of `Fq` values.
    pk_x_dec: String,
    pk_y_dec: String,
    /// Signature components: R8 affine coords (decimal `Fq`) plus the
    /// response scalar `s` (decimal in `[0, l)`).
    r8x_dec: String,
    r8y_dec: String,
    s_dec: String,
}

fn fr_to_dec(f: &babyjubjub_rs::Fr) -> String {
    // `into_repr().0` is `[u64; 4]` little-endian limbs.
    let mut bytes_le = Vec::with_capacity(32);
    for limb in f.into_repr().0.iter() {
        bytes_le.extend_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes_le).to_string()
}

fn bigint_to_dec(n: &BigInt) -> String {
    n.to_str_radix(10)
}

/// BN254 scalar modulus q — the upper bound for our random messages.
/// Pulled from the same string `ark_bn254` uses internally.
fn q() -> BigUint {
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
        .parse()
        .expect("static decimal")
}

fn main() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(SEED);
    let q_big = q();

    let mut vectors = Vec::with_capacity(NUM_VECTORS);
    for _ in 0..NUM_VECTORS {
        // Random 32-byte private key seed.
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = PrivateKey::import(sk_bytes.to_vec()).expect("32-byte sk");

        // Random message in `[0, q)`. Reject-sample so the distribution is
        // uniform; the rejection rate is < 50% in practice (q ≈ 2^254 fits
        // comfortably inside 32 bytes).
        let msg_big = loop {
            let mut msg_bytes = [0u8; 32];
            rng.fill_bytes(&mut msg_bytes);
            let candidate = BigUint::from_bytes_le(&msg_bytes);
            if candidate < q_big {
                break candidate;
            }
        };
        let msg_bigint = BigInt::from_biguint(Sign::Plus, msg_big.clone());

        let pk = sk.public();
        let sig = sk.sign(msg_bigint).expect("sign");

        vectors.push(Vector {
            sk_hex: hex::encode(sk_bytes),
            msg_dec: msg_big.to_string(),
            pk_x_dec: fr_to_dec(&pk.x),
            pk_y_dec: fr_to_dec(&pk.y),
            r8x_dec: fr_to_dec(&sig.r_b8.x),
            r8y_dec: fr_to_dec(&sig.r_b8.y),
            s_dec: bigint_to_dec(&sig.s),
        });
    }

    let out_path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("parity_vectors.json");
    fs::create_dir_all(out_path.parent().expect("parent")).expect("mkdir");
    let json = serde_json::to_string_pretty(&vectors).expect("serialize");
    fs::write(&out_path, json).expect("write");

    eprintln!(
        "wrote {} vectors to {} (seed={:#x})",
        NUM_VECTORS,
        out_path.display(),
        SEED
    );
}

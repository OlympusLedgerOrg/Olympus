//! Emit `babyjubjub-permissive`'s OWN EdDSA outputs for the JS
//! cross-implementation parity test in `verifiers/javascript/`.
//!
//! Distinct from `gen_parity_vectors.rs`, which captures `babyjubjub-rs`
//! outputs (the Rust↔Rust regression fixture). This one signs with the
//! NEW impl so the JS test compares circomlibjs directly against
//! `babyjubjub-permissive` — not transitively through `babyjubjub-rs`.
//!
//! Output: `verifiers/javascript/rust_eddsa_vectors.json`.
//! Run: `cargo run -p babyjubjub-permissive --example gen_rust_eddsa_vectors`.
//!
//! Unlike `gen_parity_vectors`, this example survives Phase 4 (it has no
//! `babyjubjub-rs` dependency) — it's the permanent source of the JS
//! parity fixture.

use std::fs;
use std::path::PathBuf;

use ark_bn254::Fr as Fq;
use ark_ff::{BigInteger, PrimeField};
use babyjubjub_permissive::PrivateKey;
use num_bigint::BigUint;
use rand::{RngCore, SeedableRng};
use serde::Serialize;

const NUM_VECTORS: usize = 32;
// Distinct seed from gen_parity_vectors so the two fixtures don't share
// inputs by accident — independent coverage.
#[allow(clippy::unusual_byte_groupings)]
const SEED: u64 = 0x1DEA_B0A7_u64;

#[derive(Serialize)]
struct Vector {
    sk_hex: String,
    msg_dec: String,
    pk_x_dec: String,
    pk_y_dec: String,
    r8x_dec: String,
    r8y_dec: String,
    s_dec: String,
}

/// `Fq` (point coordinate / message) → decimal string.
fn fq_to_dec(f: &Fq) -> String {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_string()
}

/// `Fr` (signature scalar) → decimal string.
fn fr_to_dec(f: &babyjubjub_permissive::Fr) -> String {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_string()
}

/// BN254 scalar modulus q — message upper bound.
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
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let sk = PrivateKey::from_bytes(&sk_bytes).expect("32-byte sk");

        // Reject-sample a message in [0, q).
        let msg_big = loop {
            let mut mb = [0u8; 32];
            rng.fill_bytes(&mut mb);
            let cand = BigUint::from_bytes_le(&mb);
            if cand < q_big {
                break cand;
            }
        };
        let msg = Fq::from_le_bytes_mod_order(&msg_big.to_bytes_le());

        let (pk_x, pk_y) = sk.public().coords();
        let sig = sk.sign(msg).expect("sign");

        vectors.push(Vector {
            sk_hex: hex::encode(sk_bytes),
            msg_dec: msg_big.to_string(),
            pk_x_dec: fq_to_dec(&pk_x),
            pk_y_dec: fq_to_dec(&pk_y),
            r8x_dec: fq_to_dec(&sig.r8.x),
            r8y_dec: fq_to_dec(&sig.r8.y),
            s_dec: fr_to_dec(&sig.s),
        });
    }

    // Write into the JS verifier package so its test reads a sibling file
    // (no fragile reach into the Rust crate's tests/ dir).
    let out_path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("verifiers")
        .join("javascript")
        .join("rust_eddsa_vectors.json");
    let json = serde_json::to_string_pretty(&vectors).expect("serialize");
    fs::write(&out_path, json).expect("write");
    eprintln!(
        "wrote {} babyjubjub-permissive vectors to {} (seed={:#x})",
        NUM_VECTORS,
        out_path.display(),
        SEED
    );
}

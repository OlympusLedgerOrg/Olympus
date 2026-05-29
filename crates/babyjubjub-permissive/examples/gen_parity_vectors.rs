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
const NUM_POINT_VECTORS: usize = 50;
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

/// Point-arithmetic parity vectors: scalar-mul of an arbitrary (non-B8)
/// point and point addition — the ops Pedersen `commit` (`m·G + r·H`)
/// relies on but the EdDSA vectors (which only scalar-mul B8) don't cover.
#[derive(Serialize)]
struct PointVector {
    /// Scalars (decimal, in [0, l)) used to build the two operand points
    /// P = a·B8, Q = b·B8, and the multiplier k for k·P.
    a_dec: String,
    b_dec: String,
    k_dec: String,
    /// P = a·B8.
    px_dec: String,
    py_dec: String,
    /// Q = b·B8.
    qx_dec: String,
    qy_dec: String,
    /// k·P (arbitrary-point scalar-mul result).
    kp_x_dec: String,
    kp_y_dec: String,
    /// P + Q (point-addition result).
    sum_x_dec: String,
    sum_y_dec: String,
}

/// circomlib B8 base point — same decimal constants as pedersen.rs's
/// G_X_DEC / G_Y_DEC, since babyjubjub-rs doesn't expose B8 publicly.
const B8_X_DEC: &str =
    "5299619240641551281634865583518297030282874472190772894086521144482721001553";
const B8_Y_DEC: &str =
    "16950150798460657717958625567821834550301663161624707787222815936182638968203";

/// Baby Jubjub prime-subgroup order l.
fn l() -> BigUint {
    "2736030358979909402780800718157159386076813972158567259200215660948447373041"
        .parse()
        .expect("static decimal")
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
        "wrote {} EdDSA vectors to {} (seed={:#x})",
        NUM_VECTORS,
        out_path.display(),
        SEED
    );

    // ── Point-op vectors (add + arbitrary-point scalar-mul) ──────────────
    let b8 = babyjubjub_rs::Point {
        x: babyjubjub_rs::Fr::from_str(B8_X_DEC).expect("B8.x"),
        y: babyjubjub_rs::Fr::from_str(B8_Y_DEC).expect("B8.y"),
    };
    let l_big = l();
    // Random scalar in [1, l). Reject-sample from 32 bytes.
    let rand_scalar = |rng: &mut rand::rngs::StdRng| -> BigUint {
        loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            let c = BigUint::from_bytes_le(&b);
            if c < l_big && c > BigUint::from(0u8) {
                break c;
            }
        }
    };

    let mut point_vectors = Vec::with_capacity(NUM_POINT_VECTORS);
    for _ in 0..NUM_POINT_VECTORS {
        let a = rand_scalar(&mut rng);
        let b = rand_scalar(&mut rng);
        let k = rand_scalar(&mut rng);
        let to_bi = |u: &BigUint| BigInt::from_biguint(Sign::Plus, u.clone());

        let p = b8.mul_scalar(&to_bi(&a));
        let q = b8.mul_scalar(&to_bi(&b));
        let kp = p.mul_scalar(&to_bi(&k));
        let sum = p.projective().add(&q.projective()).affine();

        point_vectors.push(PointVector {
            a_dec: a.to_string(),
            b_dec: b.to_string(),
            k_dec: k.to_string(),
            px_dec: fr_to_dec(&p.x),
            py_dec: fr_to_dec(&p.y),
            qx_dec: fr_to_dec(&q.x),
            qy_dec: fr_to_dec(&q.y),
            kp_x_dec: fr_to_dec(&kp.x),
            kp_y_dec: fr_to_dec(&kp.y),
            sum_x_dec: fr_to_dec(&sum.x),
            sum_y_dec: fr_to_dec(&sum.y),
        });
    }

    let pt_path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("point_vectors.json");
    let pt_json = serde_json::to_string_pretty(&point_vectors).expect("serialize");
    fs::write(&pt_path, pt_json).expect("write");
    eprintln!(
        "wrote {} point-op vectors to {}",
        NUM_POINT_VECTORS,
        pt_path.display()
    );
}

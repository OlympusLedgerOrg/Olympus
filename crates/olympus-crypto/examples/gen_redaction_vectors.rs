//! Generate `verifiers/test_vectors/redaction_vectors.json` for the **hiding**
//! object-level redaction leaf (ADR-0026), from the canonical
//! `olympus_crypto::redaction` primitives — the single source of truth shared by
//! the in-process prover (`src-tauri/.../pdf_objects.rs`) and the cross-language
//! verifiers.
//!
//! Run: `cargo run -p olympus-crypto --example gen_redaction_vectors --features redaction`
//!
//! The vectors exercise the *crypto* (per-object hiding leaf → depth-10 fold →
//! redactedCommitment), independent of PDF parsing (which is Rust-only). `content_hash`
//! is an opaque 32-byte value the blinding derivation binds to — it need not be a
//! real PDF hash for a crypto conformance vector.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use num_bigint::BigUint;
use olympus_crypto::poseidon::{compute_redaction_commitments, poseidon_hash};
use olympus_crypto::redaction::{content_scalar, derive_blinding, redaction_leaf, REDACTION_BLIND_PREFIX};
use olympus_crypto::POSEIDON_DOMAIN_OBJ_LEAF;

const MAX_LEAVES: usize = 1024;
const TREE_DEPTH: usize = 10;
const NODE_DOMAIN: u64 = 1; // domain_node(1, l, r) fold (matches the circuit)

const BLIND_SECRET: [u8; 32] = [0x5a; 32];
const CONTENT_HASH: [u8; 32] = [0x11; 32];

/// Fixed 32-byte big-endian lowercase hex of a field element.
fn fr_hex(f: Fr) -> String {
    let be = f.into_bigint().to_bytes_be();
    let mut p = [0u8; 32];
    p[32 - be.len()..].copy_from_slice(&be);
    hex::encode(p)
}

fn fr_to_biguint(f: Fr) -> BigUint {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be())
}

fn main() {
    // Synthetic "objects" (obj_id, bytes). Object 4 will be redacted.
    let objects: [(u32, &[u8]); 5] = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>"),
        (4, b"<< /Length 44 >>\nstream\nBT /F1 24 Tf 72 720 Td (SECRET) Tj ET\nendstream"),
        (5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
    ];

    let mut leaves: Vec<Fr> = Vec::with_capacity(objects.len());
    let mut objs_json = Vec::new();
    for (id, bytes) in objects {
        let id_be = id.to_be_bytes();
        let content = content_scalar(&id_be, bytes);
        let blinding = derive_blinding(&BLIND_SECRET, &CONTENT_HASH, &id_be);
        let leaf = redaction_leaf(&content, &blinding).expect("leaf");
        leaves.push(leaf);
        objs_json.push(serde_json::json!({
            "obj_id": id,
            "bytes_hex": hex::encode(bytes),
            "blinding_decimal": blinding.to_string(),
            "leaf_hex": fr_hex(leaf),
        }));
    }

    // Pad to MAX_LEAVES and fold with domain_node(1, l, r) = Poseidon(Poseidon(1,l),r).
    let mut level: Vec<Fr> = leaves.clone();
    level.resize(MAX_LEAVES, Fr::zero());
    for _ in 0..TREE_DEPTH {
        level = level
            .chunks(2)
            .map(|p| poseidon_hash(poseidon_hash(Fr::from(NODE_DOMAIN), p[0]), p[1]))
            .collect();
    }
    let original_root = level[0];

    // Reveal mask over the real objects (redact object 4); padded leaves stay 0/unrevealed.
    let reveal_mask: Vec<u8> = objects.iter().map(|(id, _)| (*id != 4) as u8).collect();
    let mut padded_leaves: Vec<BigUint> = leaves.iter().map(|l| fr_to_biguint(*l)).collect();
    padded_leaves.resize(MAX_LEAVES, BigUint::from(0u64));
    let mut padded_mask = reveal_mask.clone();
    padded_mask.resize(MAX_LEAVES, 0u8);
    let revealed_count = reveal_mask.iter().filter(|&&b| b == 1).count() as u64;
    let (redacted_commitment, _mask_commitment) =
        compute_redaction_commitments(&padded_leaves, &padded_mask, revealed_count);

    let out = serde_json::json!({
        "scheme": "pdf-object-level-redaction-adr0026",
        "obj_domain": POSEIDON_DOMAIN_OBJ_LEAF,
        "blind_prefix": String::from_utf8_lossy(REDACTION_BLIND_PREFIX),
        "blind_secret_hex": hex::encode(BLIND_SECRET),
        "content_hash_hex": hex::encode(CONTENT_HASH),
        "tree_depth": TREE_DEPTH,
        "max_leaves": MAX_LEAVES,
        "objects": objs_json,
        "original_root_hex": fr_hex(original_root),
        "reveal_mask": reveal_mask,
        "revealed_count": revealed_count,
        "redacted_commitment_decimal": redacted_commitment.to_string(),
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../verifiers/test_vectors/redaction_vectors.json"
    );
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&out).unwrap()))
        .expect("write redaction_vectors.json");
    eprintln!("wrote {path}");
}

// SPDX-License-Identifier: Apache-2.0
//! Conformance gates for the root `test_vectors/` golden files.
//!
//! Both files under test were published with **no CI consumer**, so nothing
//! failed if they drifted from the implementations they claim to pin. These
//! tests close that gap:
//!
//! - `test_vectors/federation_event_v1.json` (ADR-0042 §4) — recomputed
//!   end-to-end from live primitives: BLAKE3, the ADR's length-prefixed
//!   preimage layout, `Fr::from_le_bytes_mod_order` reduction, circomlib
//!   Poseidon, and this crate's Baby Jubjub EdDSA verifier. ADR-0042's
//!   normative constructor (`olympus_crypto::federation::event_message_v1`)
//!   does not exist yet; when it lands, its output must match the preimage
//!   this test rebuilds byte-for-byte.
//! - `test_vectors/proofs/end_to_end.json` — a **legacy** pipeline vector.
//!   The Merkle-leaf → root → proof legs are recomputed against the live
//!   verifier here; the `input_record` → `canonicalized_bytes_hex` leg is
//!   recomputed against the live encoder in
//!   `crates/olympus-crypto/tests/vector_conformance.rs` (this standalone
//!   verifier deliberately carries no canonical-JSON encoder). The `record_hash` and `ledger.*` fields were
//!   produced by the retired Python pipeline (note the `canonical_v1` /
//!   `pikepdf` canonicalizer tags) and are reproducible by **no current
//!   implementation** — they are frozen by the whole-file pin below, not
//!   re-derived. Regenerating the file is a deliberate act: update the pin.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;

use olympus_verifier::eddsa::{self, EddsaError, Signature};
use olympus_verifier::pedersen::{parse_dec, Curve, Point};
use olympus_verifier::{compute_blake3, merkle_leaf_hash, verify_merkle_proof, MerkleProof};

const FEDERATION_EVENT_PATH: &str = "../../test_vectors/federation_event_v1.json";
const END_TO_END_PATH: &str = "../../test_vectors/proofs/end_to_end.json";

/// BLAKE3 of the committed `end_to_end.json` bytes. The `record_hash` and
/// `ledger` fields inside are retired-Python legacy values that cannot be
/// recomputed; this pin is what makes the file tamper-evident. If you
/// regenerate the vector intentionally, update this constant in the same
/// commit and say why in the commit message.
const END_TO_END_FILE_BLAKE3: &str =
    "142c6cb5b237b967194bdfdfe168ddc2daed2b391bd404d0345e5ea6306087cf";

fn fr_from_dec(s: &str) -> Fr {
    let b = parse_dec(s).expect("canonical decimal");
    Fr::from_le_bytes_mod_order(&b.to_bytes_le())
}

fn fr_to_dec(f: &Fr) -> String {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be()).to_str_radix(10)
}

/// 4-byte big-endian length prefix (ADR-0042 §4 `lp`).
fn lp(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

#[test]
fn federation_event_v1_vector_recomputes_and_verifies() {
    let raw = std::fs::read_to_string(FEDERATION_EVENT_PATH).expect("read fixture");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse fixture");
    let s = |k: &str| v[k].as_str().unwrap_or_else(|| panic!("field {k}"));

    // Canonical payload: the b64 wire field must encode exactly the canonical
    // UTF-8 bytes, and payload_hash is BLAKE3 over those exact bytes.
    let canonical = s("payload_canonical_utf8").as_bytes().to_vec();
    assert_eq!(
        BASE64.encode(&canonical),
        s("payload_canonical_b64"),
        "payload_canonical_b64 must encode payload_canonical_utf8"
    );
    let payload_hash = compute_blake3(&canonical);
    assert_eq!(
        hex::encode(payload_hash),
        s("payload_hash_blake3_hex"),
        "payload_hash must be BLAKE3(canonical payload bytes)"
    );

    // Issuer key hash: 32-byte big-endian Poseidon(authority_x, authority_y).
    let pk_x = fr_from_dec(s("pubkey_x_dec"));
    let pk_y = fr_from_dec(s("pubkey_y_dec"));
    let issuer_hash = Poseidon::<Fr>::new_circom(2)
        .expect("poseidon arity 2")
        .hash(&[pk_x, pk_y])
        .expect("poseidon hash");
    let issuer_hash_be = issuer_hash.into_bigint().to_bytes_be();
    assert_eq!(
        hex::encode(&issuer_hash_be),
        s("issuer_pubkey_hash_hex"),
        "issuer_pubkey_hash must be Poseidon(x, y) as 32-byte big-endian"
    );

    // Preimage: OLY:FEDERATION:EVENT:V1 || lp(shard) || lp(u64be(epoch)) ||
    // lp(u64be(seq)) || lp(issuer_hash) || lp(resource_key) || lp(payload_hash).
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"OLY:FEDERATION:EVENT:V1");
    lp(&mut preimage, s("shard_id_utf8").as_bytes());
    lp(
        &mut preimage,
        &v["authority_epoch"].as_u64().expect("epoch").to_be_bytes(),
    );
    lp(
        &mut preimage,
        &v["sequence"].as_u64().expect("sequence").to_be_bytes(),
    );
    lp(&mut preimage, &issuer_hash_be);
    lp(
        &mut preimage,
        &hex::decode(s("resource_key_hex")).expect("resource_key hex"),
    );
    lp(&mut preimage, &payload_hash);
    assert_eq!(
        hex::encode(&preimage),
        s("preimage_hex"),
        "preimage must follow the ADR-0042 §4 length-prefixed layout"
    );

    // Digest and BJJ message reduction.
    let digest = compute_blake3(&preimage);
    assert_eq!(
        hex::encode(digest),
        s("message_digest_blake3_hex"),
        "message digest must be BLAKE3(preimage)"
    );
    let msg_fr = Fr::from_le_bytes_mod_order(&digest);
    assert_eq!(
        fr_to_dec(&msg_fr),
        s("message_fr_le_reduced_dec"),
        "BJJ message must be Fr::from_le_bytes_mod_order(digest)"
    );

    // Signature must verify under the offline Baby Jubjub EdDSA verifier.
    let curve = Curve::baby_jubjub();
    let pubkey = Point {
        x: parse_dec(s("pubkey_x_dec")).expect("pubkey x"),
        y: parse_dec(s("pubkey_y_dec")).expect("pubkey y"),
    };
    let sig = Signature {
        r8: Point {
            x: parse_dec(v["signature"]["r8x_dec"].as_str().expect("r8x")).expect("r8x dec"),
            y: parse_dec(v["signature"]["r8y_dec"].as_str().expect("r8y")).expect("r8y dec"),
        },
        s: parse_dec(v["signature"]["s_dec"].as_str().expect("s")).expect("s dec"),
    };
    let msg = BigUint::from_bytes_be(&msg_fr.into_bigint().to_bytes_be());
    assert!(v["expected_valid"].as_bool().expect("expected_valid"));
    eddsa::verify(&curve, &pubkey, &sig, &msg).expect("fixture signature must verify");

    // Negative direction (ADR-0042: "changing one encoded byte must reject"):
    // flip one preimage byte, re-derive the message, and require the specific
    // equation failure — not a parse error.
    let mut tampered = preimage.clone();
    tampered[8] ^= 0x01;
    let tampered_digest = compute_blake3(&tampered);
    assert_ne!(tampered_digest, digest);
    let tampered_msg = Fr::from_le_bytes_mod_order(&tampered_digest);
    let tampered_msg = BigUint::from_bytes_be(&tampered_msg.into_bigint().to_bytes_be());
    assert_eq!(
        eddsa::verify(&curve, &pubkey, &sig, &tampered_msg),
        Err(EddsaError::Rejected),
        "a one-byte preimage change must fail the signature equation"
    );
}

#[test]
fn end_to_end_vector_live_legs_recompute() {
    let raw = std::fs::read(END_TO_END_PATH).expect("read fixture");

    // Whole-file freeze: the record_hash / ledger fields are legacy values the
    // retired Python pipeline produced; nothing current can recompute them, so
    // the file is pinned byte-for-byte instead.
    assert_eq!(
        hex::encode(compute_blake3(&raw)),
        END_TO_END_FILE_BLAKE3,
        "end_to_end.json changed — if intentional, update the pin and justify"
    );

    let v: serde_json::Value = serde_json::from_slice(&raw).expect("parse fixture");
    let canonical =
        hex::decode(v["canonicalized_bytes_hex"].as_str().expect("hex")).expect("canonical hex");

    // Live leg 1: Merkle leaf over the canonical bytes.
    let leaf = merkle_leaf_hash(&canonical);
    let leaf_hex = v["merkle"]["leaf_hash_hex"].as_str().expect("leaf hex");
    assert_eq!(hex::encode(leaf), leaf_hex, "merkle_leaf_hash drifted");

    // Live leg 2: single-leaf tree — root is the leaf hash.
    let root_hex = v["merkle"]["root_hex"].as_str().expect("root hex");
    assert_eq!(leaf_hex, root_hex, "single-leaf root must equal the leaf");

    // Live leg 3: the inclusion proof verifies, and a mutated canonical byte
    // breaks it (binding, not just agreement).
    let proof = MerkleProof {
        leaf_hash: leaf,
        siblings: vec![],
        root_hash: root_hex.to_owned(),
    };
    assert_eq!(verify_merkle_proof(&proof), Ok(true));

    let mut mutated = canonical.clone();
    mutated[0] ^= 0x01;
    let bad = MerkleProof {
        leaf_hash: merkle_leaf_hash(&mutated),
        siblings: vec![],
        root_hash: root_hex.to_owned(),
    };
    assert_eq!(
        verify_merkle_proof(&bad),
        Ok(false),
        "a mutated canonical byte must change the leaf and miss the pinned root"
    );
}

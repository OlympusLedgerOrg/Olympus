use std::{collections::HashSet, env, fs};

use serde::Deserialize;

#[derive(Deserialize)]
struct WitnessCosig {
    witness_id: String,
    public_key_hex: String,
    signature_hex: String,
}

#[derive(Deserialize)]
struct WitnessEnvelope {
    root_hash: String,
    witness_threshold: usize,
    witness_cosignatures: Vec<WitnessCosig>,
}

fn main() {
    let path = env::args().nth(1).expect("usage: verify_witness <vector_path>");
    let raw = fs::read_to_string(path).expect("read vector");
    let env: WitnessEnvelope = serde_json::from_str(&raw).expect("decode envelope");

    let root = hex::decode(env.root_hash).expect("root hex");
    assert_eq!(root.len(), 32, "root must be 32 bytes");

    let mut payload = b"OLY:WITNESS:V1|".to_vec();
    payload.extend_from_slice(&root);

    let mut valid = HashSet::new();
    for c in env.witness_cosignatures {
        let pk = match hex::decode(c.public_key_hex) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let sig = match hex::decode(c.signature_hex) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if pk.len() != 32 || sig.len() != 64 {
            continue;
        }
        let vk = match ed25519_dalek::VerifyingKey::from_bytes(
            pk.as_slice().try_into().expect("public key length checked"),
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let sig = match ed25519_dalek::Signature::from_slice(&sig) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if vk.verify_strict(&payload, &sig).is_ok() {
            valid.insert(c.witness_id);
        }
    }

    if valid.len() < env.witness_threshold {
        panic!("threshold not met");
    }
}

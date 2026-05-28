//! Regenerate the SSMF (Sparse Merkle Tree) conformance vectors after a
//! leaf-hash domain change (ADR-0003 parser binding / ADR-0004 model-hash
//! binding). Emits the `ssmf_existence_proof` and `ssmf_nonexistence_proof`
//! arrays as JSON on stdout; splice them into
//! `verifiers/test_vectors/vectors.json`.
//!
//! Run with:
//!   cargo run -p olympus-crypto --example gen_ssmf_vectors --features smt
//!
//! The canonical fixture tree holds exactly three leaves; the queried keys
//! cover both present keys (existence) and absent keys (non-existence),
//! including the all-zero and all-ones boundary keys.

use olympus_crypto::smt::{Proof, SparseMerkleTree};

const SHARD_ID: &str = "shard-fixture";
const PARSER_ID: &str = "docling@2.3.1";
const CPV: &str = "v1";
const MODEL_HASH: &str = "blake3:docling@2.3.1";

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

fn key(last: u8, fill: u8) -> [u8; 32] {
    let mut k = [fill; 32];
    k[31] = last;
    k
}

fn siblings_json(sibs: &[[u8; 32]]) -> String {
    let items: Vec<String> = sibs.iter().map(|s| format!("        \"{}\"", hex(s))).collect();
    format!("[\n{}\n      ]", items.join(",\n"))
}

fn main() {
    // Build the canonical fixture tree: 3 leaves, raw keys (no shard wrapping).
    let leaves: [([u8; 32], [u8; 32]); 3] = [
        (key(0x01, 0x00), [0x41u8; 32]),
        (key(0x02, 0x00), [0x42u8; 32]),
        ({
            let mut k = [0xffu8; 32];
            k[31] = 0xfe;
            k
        }, [0x43u8; 32]),
    ];

    let mut tree = SparseMerkleTree::new();
    for (k, v) in &leaves {
        tree.update(*k, *v, SHARD_ID, PARSER_ID, CPV, MODEL_HASH);
    }

    let existence_keys: Vec<[u8; 32]> = leaves.iter().map(|(k, _)| *k).collect();
    let nonexistence_keys: Vec<[u8; 32]> =
        vec![key(0x00, 0x00), [0xffu8; 32], key(0x03, 0x00)];

    let mut exist_entries = Vec::new();
    for k in &existence_keys {
        match tree.prove(k) {
            Proof::Existence(p) => {
                exist_entries.push(format!(
                    "    {{\n      \"description\": \"Existence proof for key {key}\",\n      \"key\": \"{key}\",\n      \"value_hash\": \"{val}\",\n      \"shard_id\": \"{shard}\",\n      \"parser_id\": \"{pid}\",\n      \"canonical_parser_version\": \"{cpv}\",\n      \"model_hash\": \"{mh}\",\n      \"root_hash\": \"{root}\",\n      \"siblings\": {sibs},\n      \"expected_valid\": true\n    }}",
                    key = hex(&p.key),
                    val = hex(&p.value_hash),
                    shard = p.shard_id,
                    pid = p.parser_id,
                    cpv = p.canonical_parser_version,
                    mh = p.model_hash,
                    root = hex(&p.root_hash),
                    sibs = siblings_json(&p.siblings),
                ));
            }
            Proof::NonExistence(_) => panic!("present key proved non-existence"),
        }
    }

    let mut nonexist_entries = Vec::new();
    for k in &nonexistence_keys {
        match tree.prove(k) {
            Proof::NonExistence(p) => {
                nonexist_entries.push(format!(
                    "    {{\n      \"description\": \"Non-existence proof for key {key}\",\n      \"key\": \"{key}\",\n      \"root_hash\": \"{root}\",\n      \"siblings\": {sibs},\n      \"expected_valid\": true\n    }}",
                    key = hex(&p.key),
                    root = hex(&p.root_hash),
                    sibs = siblings_json(&p.siblings),
                ));
            }
            Proof::Existence(_) => panic!("absent key proved existence"),
        }
    }

    println!(
        "{{\n  \"ssmf_existence_proof\": [\n{}\n  ],\n  \"ssmf_nonexistence_proof\": [\n{}\n  ]\n}}",
        exist_entries.join(",\n"),
        nonexist_entries.join(",\n"),
    );
}

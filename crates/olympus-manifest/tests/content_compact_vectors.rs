// SPDX-License-Identifier: Apache-2.0

//! Replays the committed compact exact-proof vectors
//! (`verifiers/test_vectors/dataset_compact_proof_vectors.json`, RFC-0000 §13)
//! through the Rust decoder and tree verifier. The bytes are pinned in the
//! file, so a codec change that alters the wire format fails here.

use olympus_manifest::content::{
    tree::{verify_membership, verify_non_membership, Terminal},
    verify_m1_open,
    version::ProfileEntry,
    wire::ExactProof,
};
use serde_json::Value;

const VECTORS: &str =
    include_str!("../../../verifiers/test_vectors/dataset_compact_proof_vectors.json");

fn bytes32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

#[test]
fn positive_compact_vectors_round_trip_and_verify() {
    let profiles = [ProfileEntry {
        id: "bytes/raw".into(),
        version: 1,
        implementation_id: "olympus=0.1.0".into(),
    }];
    let positives = vectors()["positive"].as_array().unwrap().clone();
    assert_eq!(positives.len(), 8);
    let mut depths = Vec::new();
    for v in &positives {
        let name = v["name"].as_str().unwrap();
        let p = u8::try_from(v["p"].as_u64().unwrap()).unwrap();
        let root = bytes32(&v["item_root"]);
        let query = bytes32(&v["query_key"]);
        let bytes = hex::decode(v["proof"].as_str().unwrap()).unwrap();
        let proof = ExactProof::decode(p, &bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(proof.encode(p).unwrap(), bytes, "{name}: re-encode");
        let (path, statement) = match &proof {
            ExactProof::Membership(item) => {
                assert_eq!(item.key, query, "{name}");
                let commitment = verify_membership(p, &root, &item.key, &item.path)
                    .unwrap_or_else(|e| panic!("{name}: {e:?}"));
                assert_eq!(commitment, item.preimage.commitment(), "{name}");
                if !v["content_key_profile"].is_null() {
                    verify_m1_open(p, &root, &profiles, item).unwrap();
                }
                (&item.path, "M1-open")
            }
            ExactProof::NonMembership { key, path } => {
                assert_eq!(*key, query, "{name}");
                verify_non_membership(p, &root, key, path)
                    .unwrap_or_else(|e| panic!("{name}: {e:?}"));
                (path, "N1")
            }
        };
        assert_eq!(v["statement"], statement, "{name}");
        let terminal = match (statement, path.terminal) {
            ("M1-open", _) => "leaf",
            (_, Terminal::Empty) => "empty",
            (_, Terminal::Leaf { .. }) => "neighbor",
        };
        assert_eq!(v["terminal"], terminal, "{name}");
        assert_eq!(v["depth"].as_u64().unwrap() as usize, path.siblings.len());
        assert_eq!(path.top_siblings.len(), usize::from(p));
        depths.push(path.siblings.len());
    }
    // The coverage the RFC requires: depth 0 and 256, a nonzero top path,
    // and both N1 terminals.
    assert!(depths.contains(&0) && depths.contains(&256));
    assert!(positives.iter().any(|v| v["p"].as_u64() > Some(0)));
    for terminal in ["empty", "neighbor"] {
        assert!(positives
            .iter()
            .any(|v| v["statement"] == "N1" && v["terminal"] == terminal));
    }
}

#[test]
fn negative_compact_vectors_reject_for_the_stated_reason() {
    let negatives = vectors()["negative"].as_array().unwrap().clone();
    assert!(negatives.len() >= 15);
    for v in &negatives {
        let name = v["name"].as_str().unwrap();
        assert!(!v["rule"].as_str().unwrap().is_empty(), "{name}: rule");
        let p = u8::try_from(v["p"].as_u64().unwrap()).unwrap();
        let root = bytes32(&v["item_root"]);
        let bytes = hex::decode(v["proof"].as_str().unwrap()).unwrap();
        let err = match v["stage"].as_str().unwrap() {
            "decode" => ExactProof::decode(p, &bytes).expect_err(name),
            "verify" => match ExactProof::decode(p, &bytes)
                .unwrap_or_else(|e| panic!("{name}: should decode, got {e:?}"))
            {
                ExactProof::Membership(item) => {
                    verify_membership(p, &root, &item.key, &item.path).expect_err(name)
                }
                ExactProof::NonMembership { key, path } => {
                    verify_non_membership(p, &root, &key, &path).expect_err(name)
                }
            },
            other => panic!("{name}: unknown stage {other}"),
        };
        assert_eq!(format!("{err:?}"), v["error"].as_str().unwrap(), "{name}");
    }
}

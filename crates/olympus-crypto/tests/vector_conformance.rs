// SPDX-License-Identifier: Apache-2.0
//! Canonicalization legs of the root `test_vectors/` conformance gates.
//!
//! Deliberately an **integration test**, not a `#[cfg(test)]` module inside
//! `src/canonical.rs`: that file is compiled into the pinned RISC Zero
//! canonicalization guest (ADR-0040), whose ELF/ImageID must stay
//! byte-identical — even a comment-induced line shift changes the panic
//! `Location` metadata baked into the ELF. Integration tests never enter a
//! dependency build, so this file can grow freely.
//!
//! The signature / preimage / Merkle legs of the same fixtures are gated in
//! `verifiers/rust/tests/vector_conformance.rs`.

#![cfg(feature = "canonical")]

use olympus_crypto::canonical::canonicalize_str;

fn read_fixture(rel: &str) -> serde_json::Value {
    let path = format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

/// ADR-0042 §4 interoperability fixture: the canonical payload committed in
/// `test_vectors/federation_event_v1.json` must be exactly what the live
/// encoder produces for the fixture's source payload.
#[test]
fn federation_event_fixture_payload_is_canonical() {
    let v = read_fixture("test_vectors/federation_event_v1.json");
    let source = v["payload_source_utf8"].as_str().expect("source");
    let canonical = v["payload_canonical_utf8"].as_str().expect("canonical");
    assert_eq!(
        canonicalize_str(source).expect("canonicalize"),
        canonical,
        "fixture canonical payload drifted from the live encoder"
    );
}

/// `test_vectors/proofs/end_to_end.json`: `canonicalized_bytes_hex` must be
/// what the live encoder produces for `input_record` — otherwise a fixture
/// update could pair unrelated input and canonical bytes while the Merkle
/// legs (gated in `verifiers/rust`) still pass. Canonicalization is
/// source-form independent, so re-serializing the parsed `input_record` and
/// canonicalizing it yields the same bytes the original source did.
#[test]
fn end_to_end_fixture_canonical_bytes_derive_from_input_record() {
    let v = read_fixture("test_vectors/proofs/end_to_end.json");
    let input_record = v.get("input_record").expect("fixture must carry input_record");
    let input = serde_json::to_string(input_record).expect("re-serialize input_record");
    let expected_hex = v["canonicalized_bytes_hex"].as_str().expect("hex field");
    let canonical = canonicalize_str(&input).expect("canonicalize input_record");
    assert_eq!(
        hex::encode(canonical.as_bytes()),
        expected_hex,
        "canonicalized_bytes_hex is not the live canonicalization of input_record"
    );
}

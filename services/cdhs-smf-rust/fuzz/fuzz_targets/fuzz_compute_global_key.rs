//! Fuzz target for `crypto::compute_global_key()`.
//!
//! Feeds arbitrary shard IDs and record-key fields to exercise version
//! parsing, metadata rejection, and the length-prefixed key derivation
//! pipeline.  Any panic in BLAKE3 or the input validation is a failure.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use cdhs_smf_service::crypto;
use cdhs_smf_service::proto::olympus::cdhs_smf::v1::RecordKey;
use std::collections::HashMap;

#[derive(Arbitrary, Debug)]
struct GlobalKeyInput {
    shard_id: String,
    record_type: String,
    record_id: String,
    version: String,
    /// Arbitrary metadata entries (should be rejected when non-empty).
    metadata: Vec<(String, String)>,
}

fuzz_target!(|input: GlobalKeyInput| {
    let metadata: HashMap<String, String> = input.metadata.into_iter().collect();

    let record_key = RecordKey {
        record_type: input.record_type,
        record_id: input.record_id,
        version: input.version,
        metadata,
    };

    // Errors are acceptable; panics are not.
    let _ = crypto::compute_global_key(&input.shard_id, &record_key);
});

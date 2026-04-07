//! Fuzz target for `canonicalization::canonicalize()`.
//!
//! Feeds arbitrary content-type strings and byte payloads into the
//! canonicalizer to catch panics in the JSON parser, text normalizer,
//! and content-type dispatch.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use cdhs_smf_service::canonicalization;

#[derive(Arbitrary, Debug)]
struct CanonicalizeInput {
    content_type: String,
    content: Vec<u8>,
}

fuzz_target!(|input: CanonicalizeInput| {
    // Errors are acceptable; panics are not.
    let _ = canonicalization::canonicalize(&input.content_type, &input.content);
});

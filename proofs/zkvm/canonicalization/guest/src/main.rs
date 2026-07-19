#![no_main]

// SPDX-License-Identifier: Apache-2.0

risc0_zkvm::guest::entry!(main);

fn main() {
    let source: Vec<u8> = risc0_zkvm::guest::env::read();
    let claim = olympus_crypto::canonical_proof::canonicalization_claim(&source)
        .expect("source must be valid bounded Olympus canonical JSON");
    risc0_zkvm::guest::env::commit_slice(&claim.encode());
}

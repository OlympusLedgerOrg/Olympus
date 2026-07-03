# Ledger Vectors

Legacy ledger chaining vectors remain in `verifiers/test_vectors/vectors.json`
under `ledger_entry_hash` and related sections. They pin the older
domain-separated ledger-entry hashing formula and previous-entry linkage for
consumers that still verify historic binary-Merkle bundles.

Current file ingest binds location and identity in
`src-tauri/src/api/ingest/files/route.rs` with the V2
`OLY:LEDGER_ENTRY:V2` layout, then anchors inclusion through the signed
Poseidon snapshot / parser-bound SMT path. New integrations should use the
SMT/snapshot vectors in `verifiers/test_vectors/vectors.json`.

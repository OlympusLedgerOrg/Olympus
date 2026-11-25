# Olympus Proof Bundle v1

The browser export is a JSON protocol artifact with schema
`olympus-proof-v1`. The protocol identity is authoritative under
`protocol.schema` and `protocol.network`; there are no duplicate top-level
copies. Its `bundle_hash` is the lowercase BLAKE3 digest of the
UTF-8 bytes of the compact JSON serialization of the bundle **without** the
`bundle_hash` member. Object keys are sorted lexicographically at every level;
arrays retain their order; no insignificant whitespace is emitted. This rule
is intentionally independent of pretty-printed download formatting.

The persisted `signature` is the BJJ EdDSA-Poseidon signature over the
ledger-snapshot signing digest
(`olympus_crypto::ledger_snapshot::signing_digest_v2`), which folds the snapshot
root (`merkle_root`), `tree.leaf_index`, `tree.tree_size`, `content_hash`,
`original_root`, and the authority's `signed_at` timestamp. It is **not** a
signature over the browser-generated `bundle_hash`. Everything else here —
`ledger_entry_hash`, `committed_at`, `record_id`, `shard_id`, `proof_id`,
`merkle_proof`, `issuer` and the remaining metadata — is displayed by the panel
and is not authenticated by `olympus verify`. The `signed_fields` member names
exactly the fields that digest consumes, so keep it to that set: listing a
field there asserts a check that does not exist.

A snapshot with no `signed_at` uses the legacy V1 digest: the same fold over a
disjoint Poseidon domain with no timestamp element, so stripping the field
cannot downgrade a V2 snapshot into verifying under V1. This bundle does not
carry the checkpoint `TransitionAttestation` or its `persist_message` BLAKE3
digest, which are a different signature over a different message.

A future schema that signs the complete exported artifact MUST change the
schema identifier and define the signing envelope before doing so.

Snapshot path entries use `position: "left"` when the record is the left
child at that level and `position: "right"` otherwise. `tree.leaf_index` is
the persisted snapshot index.

`original_root` is the Poseidon root of the record's original chunk tree,
before it is inserted as a leaf in the append-only ledger snapshot tree. It is
not a pre-canonicalization document root or a prior ledger root.

The current signature envelope authenticates the ledger snapshot payload. The
`signed_fields` list is the compatibility declaration for that payload;
future formats may replace it with an explicit `signed_payload` object, but
must publish a new schema identifier when changing the signing contract.

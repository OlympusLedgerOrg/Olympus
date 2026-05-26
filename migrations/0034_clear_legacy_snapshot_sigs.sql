-- Clear out any Ed25519-era snapshot signatures.
--
-- The snapshot signer migrated from Ed25519 (raw 128-char hex stored in
-- `snapshot_sig`) to BJJ EdDSA-Poseidon (JSON object with r8x/r8y/s). The
-- new verifier parses `snapshot_sig` as JSON; legacy 128-char hex rows would
-- be reported as "Invalid" instead of the intended "pending."
--
-- Nuking the snapshot_* tuple lets verify_proof_bundle treat legacy rows as
-- pending so they can be re-snapshotted on next file upload (or simply
-- accepted as historical records without inclusion witnesses). The leaf
-- (`original_root`) and chunk hashes are left in place — they're the binding
-- to the document and don't depend on the signature scheme.
UPDATE ingest_records
   SET snapshot_root  = NULL,
       snapshot_index = NULL,
       snapshot_size  = NULL,
       snapshot_path  = NULL,
       snapshot_sig   = NULL
 WHERE snapshot_sig IS NOT NULL
   AND snapshot_sig NOT LIKE '{%}';

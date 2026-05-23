-- ZK existence-proof snapshot columns.
--
-- Each commit freezes its own Poseidon Merkle inclusion snapshot at commit
-- time and stores it on the record. The snapshot is the canonical witness
-- for a `document_existence` Groth16 proof generated lazily on first
-- `/ingest/records/{hash}/zk_bundle` request and cached back into
-- `zk_bundle`.
--
-- Two parallel facts get frozen per record:
--   1. `original_root` + `chunk_hashes` — the 16-chunk Poseidon tree of the
--      document itself, required to build a `redaction_validity` witness
--      later. This is the leaf the ledger Merkle tree sees.
--   2. `snapshot_*` — the per-commit ledger snapshot (Poseidon root,
--      this record's leaf index, the tree size at commit time, the Merkle
--      path back to the root, and the Ed25519 signature over the tuple).
--      These are the inputs `prove_existence` needs to produce a proof
--      against the as-of-commit-time ledger root.
--
-- Snapshot fields are NULL on records committed before this migration; the
-- ZK-bundle endpoint returns 503 for such records until they are
-- back-filled (out of scope here — the DB is empty in dev environments).

ALTER TABLE ingest_records
    ADD COLUMN IF NOT EXISTS chunk_hashes    JSONB,
    ADD COLUMN IF NOT EXISTS original_root   TEXT,
    ADD COLUMN IF NOT EXISTS snapshot_root   TEXT,
    ADD COLUMN IF NOT EXISTS snapshot_index  BIGINT,
    ADD COLUMN IF NOT EXISTS snapshot_size   BIGINT,
    ADD COLUMN IF NOT EXISTS snapshot_path   JSONB,
    ADD COLUMN IF NOT EXISTS snapshot_sig    TEXT,
    ADD COLUMN IF NOT EXISTS zk_bundle       JSONB;

CREATE INDEX IF NOT EXISTS ingest_records_original_root_idx
    ON ingest_records (original_root)
    WHERE original_root IS NOT NULL;

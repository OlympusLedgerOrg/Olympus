-- Store serialized Merkle proof per record for offline verification.
ALTER TABLE ingest_records ADD COLUMN IF NOT EXISTS merkle_proof_json TEXT;

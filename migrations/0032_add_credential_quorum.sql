-- 0032_add_credential_quorum.sql
--
-- M-of-N federation multi-signature credential issuance.
--
-- Olympus credentials (migration 0027) are signed by a single BJJ authority
-- key.  This migration extends that to an optional federation quorum: a
-- credential can require M valid BJJ-EdDSA signatures from a pinned set of N
-- known federation signers (the issuing node's authority key + its trusted
-- peers' authority keys, as registered in `peer_nodes`).
--
-- Trust model
-- -----------
-- The signer set N and the threshold M are pinned on the credential row at
-- issue time.  Verification is reproducible offline against the pinned set,
-- even if the federation membership later changes — exactly like the
-- single-issuer `issuer_pubkey_{x,y}` columns are pinned for re-verification.
--
-- Every quorum signer signs the SAME domain-separated message:
--
--     quorum_msg = BLAKE3("OLY:SBT:QUORUM:V1" | len(commit_id_hex) || commit_id_hex)
--                  reduced into a BN254 Fr (le mod-order)
--
-- The `OLY:SBT:QUORUM:V1` tag keeps a quorum co-signature structurally
-- disjoint from a plain single-issuer signature (tagged via the bare
-- commit_id) and from a revocation signature (`OLY:SBT:REVOKE:V1`) — a
-- signature minted in one role can never be replayed in another.
--
-- New columns on key_credentials
-- ------------------------------
--   * quorum_threshold INTEGER   — M; NULL on single-sig (legacy / non-quorum)
--                                  rows.  When non-NULL the row is a quorum
--                                  credential and the verifier requires
--                                  >= M valid signatures from the pinned set.
--   * quorum_signers   JSONB     — pinned signer set N: a JSON array of
--                                  {"x": <dec>, "y": <dec>} BJJ pubkey
--                                  coordinates (decimal Fr strings).  Order
--                                  is the canonical signer order used by the
--                                  ZK quorum circuit's public inputs.
--   * quorum_proof          JSONB — optional Groth16 proof (snarkjs shape)
--                                   from the `federation_quorum` circuit,
--                                   attesting ">= M of these N signed" WITHOUT
--                                   revealing which subset signed.  NULL until
--                                   the circuit's trusted-setup ceremony has
--                                   run and a proof has been produced.
--   * quorum_proof_signals  JSONB — public signals for `quorum_proof`
--                                   (decimal Fr strings), NULL when absent.

ALTER TABLE key_credentials
    ADD COLUMN IF NOT EXISTS quorum_threshold     INTEGER,
    ADD COLUMN IF NOT EXISTS quorum_signers       JSONB,
    ADD COLUMN IF NOT EXISTS quorum_proof         JSONB,
    ADD COLUMN IF NOT EXISTS quorum_proof_signals JSONB;

-- Defence-in-depth: a quorum row must carry a positive threshold. NULL
-- threshold = non-quorum row (the common case), so the constraint only
-- bites when the column is populated.
ALTER TABLE key_credentials
    ADD CONSTRAINT ck_key_credentials_quorum_threshold_positive
    CHECK (quorum_threshold IS NULL OR quorum_threshold >= 1);

-- The collected signatures that satisfy a credential's quorum. One row per
-- (credential, signer); the UNIQUE constraint makes "the same signer signed
-- twice" a no-op rather than a way to inflate the satisfied-signature count.
CREATE TABLE IF NOT EXISTS credential_quorum_signatures (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id   VARCHAR(36) NOT NULL REFERENCES key_credentials(id) ON DELETE CASCADE,
    signer_pubkey_x TEXT NOT NULL,
    signer_pubkey_y TEXT NOT NULL,
    sig_r8x         TEXT NOT NULL,
    sig_r8y         TEXT NOT NULL,
    sig_s           TEXT NOT NULL,
    signed_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (credential_id, signer_pubkey_x, signer_pubkey_y)
);

CREATE INDEX IF NOT EXISTS ix_credential_quorum_signatures_credential
    ON credential_quorum_signatures (credential_id);

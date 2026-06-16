-- 0049_own_checkpoints_transition_attestation.sql
--
-- ADR-0031 §2: bind a signed `TransitionAttestation` to every own-checkpoint.
--
-- A checkpoint already asserts the latest ledger snapshot `(ledger_root =
-- snapshot_root, tree_size = snapshot_size)` and BJJ-signs that root. This
-- migration adds the *append-only transition* the checkpoint witnesses:
-- `original_root → snapshot_root over snapshot_size leaves`, signed under the
-- same BJJ authority key over the domain-separated digest
-- `BLAKE3(OLY:SNAPSHOT:PERSIST:V1 | lp(original_root) | lp(snapshot_root) |
-- lp(snapshot_size as u64 BE))` reduced mod l (see
-- `olympus_crypto::persist_message` / `TransitionAttestation`, ADR-0031 §1).
--
-- Only `original_root` and the transition signature are new — `snapshot_root`
-- and `snapshot_size` are already on the row as `ledger_root` / `tree_size`.
--
-- Forward-only and additive: all four columns are nullable, so existing rows and
-- no-BJJ-key builds (which leave them NULL) stay valid. No backfill, no
-- destructive change, no wire-format change.

ALTER TABLE own_checkpoints
    ADD COLUMN transition_original_root TEXT,
    ADD COLUMN transition_sig_r8x       TEXT,
    ADD COLUMN transition_sig_r8y       TEXT,
    ADD COLUMN transition_sig_s         TEXT;

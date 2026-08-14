-- SPDX-FileCopyrightText: 2026 Olympus Contributors
-- SPDX-License-Identifier: Apache-2.0

-- 0060_own_checkpoints_smt_root_attestation.sql
--
-- ADR-0044: bind a signed SmtRootAttestation to every own-checkpoint.
--
-- A checkpoint already BJJ-signs the Poseidon ledger-snapshot root
-- (`ledger_root`/`tree_size`) and, since migration 0049, the append-only
-- TransitionAttestation that produced it. Neither says anything about the
-- BLAKE3 CD-HS-ST parser-bound SMT that ADR-0003/0004/0005 describe as the
-- canonical per-leaf commitment (ADR-0021) — nothing has ever signed or
-- anchored that tree's root, so `PersistentSmt::prove` output had no signed
-- statement to verify against.
--
-- This migration adds a second, domain-separated attestation over the same
-- checkpoint row: "for this shard, at this (ledger_root, tree_size), the
-- shard's BLAKE3 SMT subtree root is X", signed under the same BJJ authority
-- key over `BLAKE3(OLY:SMT:ROOT:V1 | lp(shard_id) | lp(ledger_root) |
-- lp(tree_size as u64 BE) | lp(blake3_smt_root))` reduced mod l (see
-- `olympus_crypto::smt_root_attest_message` / `SmtRootAttestation`).
--
-- Forward-only and additive: all four columns are nullable, so existing rows
-- and no-BJJ-key builds (which leave them NULL) stay valid. No backfill, no
-- destructive change, no wire-format change to federation gossip.

ALTER TABLE own_checkpoints
    ADD COLUMN blake3_smt_root    TEXT,
    ADD COLUMN blake3_smt_sig_r8x TEXT,
    ADD COLUMN blake3_smt_sig_r8y TEXT,
    ADD COLUMN blake3_smt_sig_s   TEXT;

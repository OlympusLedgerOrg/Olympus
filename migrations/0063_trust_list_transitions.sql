-- SPDX-FileCopyrightText: 2026 Olympus Contributors
-- SPDX-License-Identifier: Apache-2.0

-- 0063_trust_list_transitions.sql
--
-- ADR-0041 §6: append-only trust-list transition records.
--
-- The role-separated trust-list state machine derives its authoritative
-- runtime state from a validated snapshot plus an append-only transition
-- history. Three tables carry that history; none of them is ever UPDATEd or
-- DELETEd by the runtime (the external-PG DML contract grants SELECT+INSERT
-- only — mirroring the ADR-0031 insert-only posture for ledger tables):
--
--   * trust_transition_candidates — one immutable row per staged transition
--     candidate. Staging is advisory and reserves NO protocol sequence slot
--     (ADR-0041 §3): many candidates may exist for one predecessor and
--     proposed next_sequence, each identified by candidate_id + digest.
--     Candidates are never discarded, overwritten, or mutated; every later
--     outcome is an appended lifecycle event referencing the original row.
--     The row pins everything §6 requires for reproducible re-validation:
--     the canonical snapshot JSON (storage form — the digest is always
--     recomputed from the decoded snapshot's canonical body, never from
--     these bytes), the submitted approval signatures, and the
--     authorization context (thresholds, profiles, signer sets) plus the
--     verification result observed at staging time.
--
--   * trust_candidate_events — the append-only lifecycle ledger
--     (rejected / superseded / accepted / activated). Rejection and
--     supersession events carry a stable reason and, where a competing
--     candidate won the successor slot, a reference to the winner. A
--     candidate may accumulate several rejected/superseded events (each
--     failed acceptance attempt appends its outcome — that is the audit
--     trail), but at most one accepted and one activated event: those are
--     state-bearing, so partial unique indexes make a double-append
--     impossible even if the serialised acceptance path were bypassed.
--
--   * trust_accepted_transitions — one insert-only row per acceptance; the
--     durable monotonic accepted-state marker (ADR-0041 §4: highest accepted
--     sequence + digest + enough metadata to reconstruct the accepted chain
--     without the replaceable trust-list file). Because a row exists here
--     only once a candidate reaches Accepted, plain UNIQUE constraints on
--     this table are exactly the "equivalent partial unique constraints"
--     §6 asks for over next_sequence, next_snapshot_digest, and
--     (previous_snapshot_digest, next_sequence): acceptance must atomically
--     acquire them, and a second candidate racing the same successor slot
--     fails the insert instead of silently forking the chain.
--
-- Digests are 64-char lowercase hex TEXT (the storage spelling the trust
-- wire format uses); activation_at is the signed snapshot timestamp in Unix
-- seconds, copied verbatim from the immutable signed snapshot — no unsigned
-- database or request field may override it (ADR-0041 §3), which is why the
-- column carries the value but the chain loader re-checks it against the
-- decoded snapshot on every load.
--
-- Forward-only and additive: no existing table changes, no backfill, no
-- ledger-hash / SMT / circuit impact. UUIDs are generated in Rust (no
-- sequences added to the closed catalog).

CREATE TABLE IF NOT EXISTS trust_transition_candidates (
    candidate_id             UUID PRIMARY KEY,
    kind                     TEXT NOT NULL
        CONSTRAINT ck_trust_candidates_kind
        CHECK (kind IN ('genesis', 'rotation', 'recovery')),
    previous_sequence        BIGINT
        CONSTRAINT ck_trust_candidates_previous_sequence_positive
        CHECK (previous_sequence IS NULL OR previous_sequence >= 1),
    next_sequence            BIGINT NOT NULL
        CONSTRAINT ck_trust_candidates_next_sequence_positive
        CHECK (next_sequence >= 1),
    previous_snapshot_digest TEXT
        CONSTRAINT ck_trust_candidates_previous_digest_hex
        CHECK (previous_snapshot_digest IS NULL OR previous_snapshot_digest ~ '^[0-9a-f]{64}$'),
    next_snapshot_digest     TEXT NOT NULL
        CONSTRAINT ck_trust_candidates_next_digest_hex
        CHECK (next_snapshot_digest ~ '^[0-9a-f]{64}$'),
    snapshot_json            JSONB NOT NULL,
    approvals_json           JSONB NOT NULL,
    authorization_json       JSONB NOT NULL,
    verification_json        JSONB NOT NULL,
    recovery_role            TEXT,
    recovery_reason          TEXT,
    activation_at            BIGINT NOT NULL,
    validated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Genesis is exactly the kind with no predecessor (ADR-0041 §1), and
    -- recovery is exactly the kind carrying a role + reason code (§7) —
    -- pinned as CHECKs so a malformed writer cannot persist an ambiguous
    -- candidate the re-validation path would then have to guess about.
    CONSTRAINT ck_trust_candidates_genesis_shape CHECK (
        (kind = 'genesis') = (previous_sequence IS NULL AND previous_snapshot_digest IS NULL)
    ),
    CONSTRAINT ck_trust_candidates_recovery_shape CHECK (
        (kind = 'recovery') = (recovery_role IS NOT NULL AND recovery_reason IS NOT NULL)
    ),
    -- ADR-0041 §1: every later snapshot increments sequence by exactly one.
    CONSTRAINT ck_trust_candidates_sequence_step CHECK (
        previous_sequence IS NULL OR next_sequence = previous_sequence + 1
    )
);

-- Acceptance scans the candidates proposed for one successor slot; the chain
-- loader scans by sequence.
CREATE INDEX IF NOT EXISTS ix_trust_candidates_next_sequence
    ON trust_transition_candidates (next_sequence);

CREATE TABLE IF NOT EXISTS trust_candidate_events (
    event_id             UUID PRIMARY KEY,
    candidate_id         UUID NOT NULL
        REFERENCES trust_transition_candidates (candidate_id),
    event_kind           TEXT NOT NULL
        CONSTRAINT ck_trust_candidate_events_kind
        CHECK (event_kind IN ('rejected', 'superseded', 'accepted', 'activated')),
    reason               TEXT,
    winning_candidate_id UUID
        REFERENCES trust_transition_candidates (candidate_id),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_trust_candidate_events_candidate
    ON trust_candidate_events (candidate_id, created_at);

-- Accepted/Activated are state transitions, not commentary: at most one of
-- each per candidate, enforced below the application's serialised write path
-- so even a bypassing writer cannot double-advance a candidate's lifecycle.
CREATE UNIQUE INDEX IF NOT EXISTS uq_trust_candidate_events_accepted_once
    ON trust_candidate_events (candidate_id)
    WHERE event_kind = 'accepted';
CREATE UNIQUE INDEX IF NOT EXISTS uq_trust_candidate_events_activated_once
    ON trust_candidate_events (candidate_id)
    WHERE event_kind = 'activated';

CREATE TABLE IF NOT EXISTS trust_accepted_transitions (
    accepted_id              UUID PRIMARY KEY,
    candidate_id             UUID NOT NULL
        REFERENCES trust_transition_candidates (candidate_id),
    next_sequence            BIGINT NOT NULL
        CONSTRAINT ck_trust_accepted_next_sequence_positive
        CHECK (next_sequence >= 1),
    next_snapshot_digest     TEXT NOT NULL
        CONSTRAINT ck_trust_accepted_next_digest_hex
        CHECK (next_snapshot_digest ~ '^[0-9a-f]{64}$'),
    previous_snapshot_digest TEXT
        CONSTRAINT ck_trust_accepted_previous_digest_hex
        CHECK (previous_snapshot_digest IS NULL OR previous_snapshot_digest ~ '^[0-9a-f]{64}$'),
    activation_at            BIGINT NOT NULL,
    accepted_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_trust_accepted_candidate     UNIQUE (candidate_id),
    CONSTRAINT uq_trust_accepted_next_sequence UNIQUE (next_sequence),
    CONSTRAINT uq_trust_accepted_next_digest   UNIQUE (next_snapshot_digest)
);

-- The (previous_snapshot_digest, next_sequence) successor-slot uniqueness
-- from ADR-0041 §6, as an expression index so the genesis row's NULL
-- predecessor participates too: PostgreSQL UNIQUE treats NULLs as distinct,
-- and while UNIQUE(next_sequence) already caps genesis at one row, encoding
-- the pair exactly keeps this constraint meaningful on its own rather than
-- only in combination. The empty string can never collide with a real
-- digest — the CHECK above pins non-NULL digests to 64 hex chars.
CREATE UNIQUE INDEX IF NOT EXISTS uq_trust_accepted_predecessor_slot
    ON trust_accepted_transitions (COALESCE(previous_snapshot_digest, ''), next_sequence);

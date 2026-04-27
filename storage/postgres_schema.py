"""PostgreSQL schema DDL for the Olympus storage layer."""

from __future__ import annotations


def schema_statements(node_rehash_gate: str) -> list[str]:
    """Return idempotent PostgreSQL schema statements for ``StorageLayer.init_schema``."""
    stmts = [
        # ------------------------------------------------------------------
        # SMT Leaves
        # ------------------------------------------------------------------
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'smt_leaves'
                  AND column_name = 'shard_id'
            ) AND to_regclass('public.smt_leaves_legacy_011') IS NULL THEN
                EXECUTE 'ALTER TABLE smt_leaves RENAME TO smt_leaves_legacy_011';
            END IF;
        END $$;
        """,
        """
        CREATE TABLE IF NOT EXISTS smt_leaves (
            key                       BYTEA       NOT NULL,
            version                   INT         NOT NULL,
            value_hash                BYTEA       NOT NULL,
            parser_id                 TEXT        NOT NULL,
            canonical_parser_version  TEXT        NOT NULL,
            ts                        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (key, version),
            CONSTRAINT smt_leaves_key_length
                CHECK (octet_length(key) = 32),
            CONSTRAINT smt_leaves_value_hash_length
                CHECK (octet_length(value_hash) = 32),
            CONSTRAINT smt_leaves_parser_id_nonempty
                CHECK (length(parser_id) > 0),
            CONSTRAINT smt_leaves_canonical_parser_version_nonempty
                CHECK (length(canonical_parser_version) > 0)
        )
        """,
        "CREATE INDEX IF NOT EXISTS smt_leaves_ts_idx ON smt_leaves(ts)",
        # ADR-0003 upgrade: add parser provenance columns to existing smt_leaves.
        # ADD COLUMN IF NOT EXISTS is idempotent; the DEFAULT uses the canonical
        # fallback values so that any previously-committed rows get a meaningful
        # parser identity, then the default is dropped so future INSERTs must
        # supply explicit values.
        "ALTER TABLE smt_leaves ADD COLUMN IF NOT EXISTS parser_id TEXT NOT NULL DEFAULT 'fallback@1.0.0'",
        "ALTER TABLE smt_leaves ADD COLUMN IF NOT EXISTS canonical_parser_version TEXT NOT NULL DEFAULT 'v1'",
        "ALTER TABLE smt_leaves ALTER COLUMN parser_id DROP DEFAULT",
        "ALTER TABLE smt_leaves ALTER COLUMN canonical_parser_version DROP DEFAULT",
        # ------------------------------------------------------------------
        # SMT Nodes
        # ------------------------------------------------------------------
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'smt_nodes'
                  AND column_name = 'shard_id'
            ) AND to_regclass('public.smt_nodes_legacy_011') IS NULL THEN
                EXECUTE 'ALTER TABLE smt_nodes RENAME TO smt_nodes_legacy_011';
            END IF;
        END $$;
        """,
        """
        CREATE TABLE IF NOT EXISTS smt_nodes (
            level    SMALLINT  NOT NULL,
            index    BYTEA     NOT NULL,
            hash     BYTEA     NOT NULL,
            ts       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (level, index),
            CONSTRAINT smt_nodes_level_range
                CHECK (level >= 0 AND level <= 256),
            CONSTRAINT smt_nodes_hash_length
                CHECK (octet_length(hash) = 32)
        )
        """,
        "CREATE INDEX IF NOT EXISTS smt_nodes_level_idx ON smt_nodes(level)",
        # ------------------------------------------------------------------
        # Shard Headers  (tree_size included from the start)
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS shard_headers (
            shard_id             TEXT        NOT NULL,
            seq                  BIGINT      NOT NULL,
            root                 BYTEA       NOT NULL,
            tree_size            BIGINT      NOT NULL DEFAULT 0,
            header_hash          BYTEA       NOT NULL,
            sig                  BYTEA       NOT NULL,
            pubkey               BYTEA       NOT NULL,
            previous_header_hash TEXT        NOT NULL,
            quorum_certificate   TEXT        DEFAULT NULL,
            ts                   TIMESTAMPTZ NOT NULL,
            created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (shard_id, seq),
            CONSTRAINT shard_headers_header_hash_unique
                UNIQUE (shard_id, header_hash),
            CONSTRAINT shard_headers_root_length
                CHECK (octet_length(root) = 32),
            CONSTRAINT shard_headers_header_hash_length
                CHECK (octet_length(header_hash) = 32),
            CONSTRAINT shard_headers_sig_length
                CHECK (octet_length(sig) = 64),
            CONSTRAINT shard_headers_pubkey_length
                CHECK (octet_length(pubkey) = 32),
            CONSTRAINT shard_headers_seq_positive
                CHECK (seq >= 0),
            CONSTRAINT shard_headers_tree_size_non_negative
                CHECK (tree_size >= 0)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS shard_headers_shard_seq_desc_idx
            ON shard_headers(shard_id, seq DESC)
        """,
        # ------------------------------------------------------------------
        # Ledger Entries  (poseidon_root included from the start)
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS ledger_entries (
            shard_id       TEXT        NOT NULL,
            seq            BIGINT      NOT NULL,
            entry_hash     BYTEA       NOT NULL,
            prev_entry_hash BYTEA      NOT NULL,
            payload        JSONB       NOT NULL,
            poseidon_root  TEXT        DEFAULT NULL,
            ts             TIMESTAMPTZ NOT NULL,
            created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (shard_id, seq),
            CONSTRAINT ledger_entries_entry_hash_unique
                UNIQUE (entry_hash),
            CONSTRAINT ledger_entries_entry_hash_length
                CHECK (octet_length(entry_hash) = 32),
            CONSTRAINT ledger_entries_seq_positive
                CHECK (seq >= 0),
            -- RT-H3: Defense-in-depth constraint to prevent chain forks.
            -- SERIALIZABLE isolation should already prevent two transactions
            -- from reading the same prev_entry_hash and committing, but this
            -- constraint provides a hard database-level guarantee.
            CONSTRAINT ledger_entries_no_chain_fork
                UNIQUE (shard_id, prev_entry_hash)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS ledger_entries_shard_seq_desc_idx
            ON ledger_entries(shard_id, seq DESC)
        """,
        "CREATE INDEX IF NOT EXISTS ledger_entries_ts_idx ON ledger_entries(ts)",
        """
        CREATE INDEX IF NOT EXISTS ledger_entries_poseidon_root_idx
            ON ledger_entries(poseidon_root)
            WHERE poseidon_root IS NOT NULL
        """,
        # ------------------------------------------------------------------
        # Ledger order-enforcement trigger function + trigger
        # Enforces append-only sequential ordering and chain linkage for
        # each shard: seq must increment by 1 and prev_entry_hash must
        # match the previous row's entry_hash.
        # ------------------------------------------------------------------
        """
        CREATE OR REPLACE FUNCTION enforce_ledger_entry_order()
        RETURNS TRIGGER AS $$
        DECLARE
            latest_seq  BIGINT;
            latest_hash BYTEA;
        BEGIN
            SELECT seq, entry_hash
            INTO latest_seq, latest_hash
            FROM ledger_entries
            WHERE shard_id = NEW.shard_id
            ORDER BY seq DESC
            LIMIT 1;

            IF latest_seq IS NULL THEN
                IF NEW.seq <> 0 THEN
                    RAISE EXCEPTION
                        'First ledger entry for shard % must have seq=0, got %',
                        NEW.shard_id, NEW.seq;
                END IF;
                IF octet_length(NEW.prev_entry_hash) <> 0 THEN
                    RAISE EXCEPTION
                        'First ledger entry for shard % must have empty prev_entry_hash',
                        NEW.shard_id;
                END IF;
            ELSE
                IF NEW.seq <> latest_seq + 1 THEN
                    RAISE EXCEPTION
                        'Out-of-order ledger entry for shard %: expected seq %, got %',
                        NEW.shard_id, latest_seq + 1, NEW.seq;
                END IF;
                IF NEW.prev_entry_hash <> latest_hash THEN
                    RAISE EXCEPTION
                        'Invalid prev_entry_hash for shard % at seq %',
                        NEW.shard_id, NEW.seq;
                END IF;
            END IF;

            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """,
        "DROP TRIGGER IF EXISTS ledger_entries_order_guard ON ledger_entries",
        """
        CREATE TRIGGER ledger_entries_order_guard
        BEFORE INSERT ON ledger_entries
        FOR EACH ROW
        EXECUTE FUNCTION enforce_ledger_entry_order()
        """,
        # ------------------------------------------------------------------
        # Shared append-only reject function
        # ------------------------------------------------------------------
        """
        CREATE OR REPLACE FUNCTION olympus_reject_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION '% is append-only: % is not allowed', TG_TABLE_NAME, TG_OP
                USING ERRCODE = '25006';
        END;
        $$ LANGUAGE plpgsql
        """,
        # ------------------------------------------------------------------
        # Append-only triggers for core tables
        # ------------------------------------------------------------------
        "DROP TRIGGER IF EXISTS ledger_entries_reject_update ON ledger_entries",
        """
        CREATE TRIGGER ledger_entries_reject_update
        BEFORE UPDATE ON ledger_entries
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        "DROP TRIGGER IF EXISTS ledger_entries_reject_delete ON ledger_entries",
        """
        CREATE TRIGGER ledger_entries_reject_delete
        BEFORE DELETE ON ledger_entries
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        "DROP TRIGGER IF EXISTS shard_headers_reject_update ON shard_headers",
        """
        CREATE TRIGGER shard_headers_reject_update
        BEFORE UPDATE ON shard_headers
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        "DROP TRIGGER IF EXISTS shard_headers_reject_delete ON shard_headers",
        """
        CREATE TRIGGER shard_headers_reject_delete
        BEFORE DELETE ON shard_headers
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        "DROP TRIGGER IF EXISTS smt_leaves_reject_update ON smt_leaves",
        """
        CREATE TRIGGER smt_leaves_reject_update
        BEFORE UPDATE ON smt_leaves
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        "DROP TRIGGER IF EXISTS smt_leaves_reject_delete ON smt_leaves",
        """
        CREATE TRIGGER smt_leaves_reject_delete
        BEFORE DELETE ON smt_leaves
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        "DROP TRIGGER IF EXISTS smt_leaves_reject_insert ON smt_leaves",
        f"""
        CREATE OR REPLACE FUNCTION olympus_reject_smt_leaf_direct_insert()
        RETURNS trigger AS $$
        BEGIN
            IF current_setting('olympus.allow_smt_insert', true)
                    = '{node_rehash_gate}' THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION
                'smt_leaves is append-only via append_record(): direct INSERT not allowed'
                USING ERRCODE = '25006';
        END;
        $$ LANGUAGE plpgsql
        """,
        """
        CREATE TRIGGER smt_leaves_reject_insert
        BEFORE INSERT ON smt_leaves
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_smt_leaf_direct_insert()
        """,
        # ------------------------------------------------------------------
        # smt_nodes: gated update trigger (ADR-0001)
        # ------------------------------------------------------------------
        # Internal SMT nodes are *derived state* — their hashes change
        # whenever a new leaf is inserted and the path from leaf to root
        # is rehashed.  The append_record write path sets the session variable
        # ``olympus.allow_node_rehash`` to a BLAKE3 domain-separated hash
        # (via SET LOCAL, scoped to the current transaction) before
        # running the upsert.  Ad-hoc UPDATE statements that do not set
        # this variable are still rejected, preserving the security
        # invariant.  The gate value follows the project's OLY:
        # domain-separation convention so that a naive ``SET LOCAL ... =
        # 'on'`` does not bypass the check.
        f"""
        CREATE OR REPLACE FUNCTION olympus_allow_node_rehash()
        RETURNS trigger AS $$
        BEGIN
            IF current_setting('olympus.allow_node_rehash', true)
                    = '{node_rehash_gate}' THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION '% is append-only: % is not allowed without rehash context',
                TG_TABLE_NAME, TG_OP
                USING ERRCODE = '25006';
        END;
        $$ LANGUAGE plpgsql
        """,
        "DROP TRIGGER IF EXISTS smt_nodes_reject_update ON smt_nodes",
        """
        CREATE TRIGGER smt_nodes_reject_update
        BEFORE UPDATE ON smt_nodes
        FOR EACH ROW EXECUTE FUNCTION olympus_allow_node_rehash()
        """,
        "DROP TRIGGER IF EXISTS smt_nodes_reject_delete ON smt_nodes",
        """
        CREATE TRIGGER smt_nodes_reject_delete
        BEFORE DELETE ON smt_nodes
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        # ------------------------------------------------------------------
        # Timestamp Tokens  (tsa_cert_fingerprint included from the start)
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS timestamp_tokens (
            shard_id            TEXT        NOT NULL,
            header_hash         BYTEA       NOT NULL,
            tsa_url             TEXT        NOT NULL,
            tst                 BYTEA       NOT NULL,
            imprint_hash        BYTEA       NOT NULL,
            gen_time            TIMESTAMPTZ NOT NULL,
            tsa_cert_fingerprint TEXT       DEFAULT NULL,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (shard_id, header_hash, tsa_url),
            CONSTRAINT timestamp_tokens_header_hash_length
                CHECK (octet_length(header_hash) = 32),
            CONSTRAINT timestamp_tokens_imprint_hash_length
                CHECK (octet_length(imprint_hash) = 32),
            CONSTRAINT timestamp_tokens_tst_nonempty
                CHECK (octet_length(tst) > 0)
        )
        """,
        # PostgreSQL does not support ADD CONSTRAINT IF NOT EXISTS for foreign
        # keys, so a DO block guarded by pg_constraint is the correct idiom.
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'timestamp_tokens_header_fk'
            ) THEN
                ALTER TABLE timestamp_tokens
                ADD CONSTRAINT timestamp_tokens_header_fk
                FOREIGN KEY (shard_id, header_hash)
                REFERENCES shard_headers (shard_id, header_hash);
            END IF;
        END;
        $$
        """,
        """
        CREATE INDEX IF NOT EXISTS timestamp_tokens_shard_created_desc_idx
            ON timestamp_tokens(shard_id, created_at DESC)
        """,
        """
        CREATE OR REPLACE FUNCTION olympus_reject_timestamp_token_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'timestamp_tokens is append-only: % is not allowed', TG_OP
                USING ERRCODE = '25006';
        END;
        $$ LANGUAGE plpgsql
        """,
        "DROP TRIGGER IF EXISTS timestamp_tokens_reject_update ON timestamp_tokens",
        """
        CREATE TRIGGER timestamp_tokens_reject_update
        BEFORE UPDATE ON timestamp_tokens
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_timestamp_token_mutation()
        """,
        "DROP TRIGGER IF EXISTS timestamp_tokens_reject_delete ON timestamp_tokens",
        """
        CREATE TRIGGER timestamp_tokens_reject_delete
        BEFORE DELETE ON timestamp_tokens
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_timestamp_token_mutation()
        """,
        # ------------------------------------------------------------------
        # Ingestion durability tables
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS ingestion_batches (
            batch_id   TEXT        PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS ingestion_proofs (
            proof_id          TEXT    PRIMARY KEY,
            batch_id          TEXT    REFERENCES ingestion_batches(batch_id) ON DELETE SET NULL,
            batch_index       INT,
            shard_id          TEXT        NOT NULL,
            record_type       TEXT        NOT NULL,
            record_id         TEXT        NOT NULL,
            version           INT         NOT NULL,
            content_hash      BYTEA       NOT NULL,
            merkle_root       BYTEA       NOT NULL,
            merkle_proof      JSONB       NOT NULL,
            ledger_entry_hash BYTEA       NOT NULL,
            ts                TIMESTAMPTZ NOT NULL,
            canonicalization  JSONB,
            persisted         BOOLEAN     NOT NULL DEFAULT TRUE,
            created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT ingestion_proofs_content_hash_length
                CHECK (octet_length(content_hash) = 32),
            CONSTRAINT ingestion_proofs_merkle_root_length
                CHECK (octet_length(merkle_root) = 32),
            CONSTRAINT ingestion_proofs_ledger_entry_hash_length
                CHECK (octet_length(ledger_entry_hash) = 32)
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ingestion_proofs_content_hash_idx
            ON ingestion_proofs(content_hash)
        """,
        """
        CREATE INDEX IF NOT EXISTS ingestion_proofs_batch_idx
            ON ingestion_proofs(batch_id, batch_index)
        """,
        "DROP TRIGGER IF EXISTS ingestion_batches_reject_update ON ingestion_batches",
        """
        CREATE TRIGGER ingestion_batches_reject_update
        BEFORE UPDATE ON ingestion_batches
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        "DROP TRIGGER IF EXISTS ingestion_batches_reject_delete ON ingestion_batches",
        """
        CREATE TRIGGER ingestion_batches_reject_delete
        BEFORE DELETE ON ingestion_batches
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        "DROP TRIGGER IF EXISTS ingestion_proofs_reject_update ON ingestion_proofs",
        """
        CREATE TRIGGER ingestion_proofs_reject_update
        BEFORE UPDATE ON ingestion_proofs
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        "DROP TRIGGER IF EXISTS ingestion_proofs_reject_delete ON ingestion_proofs",
        """
        CREATE TRIGGER ingestion_proofs_reject_delete
        BEFORE DELETE ON ingestion_proofs
        FOR EACH ROW EXECUTE FUNCTION olympus_reject_mutation()
        """,
        # ------------------------------------------------------------------
        # API rate limits
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS api_rate_limits (
            subject_type  TEXT              NOT NULL,
            subject       TEXT              NOT NULL,
            action        TEXT              NOT NULL,
            tokens        DOUBLE PRECISION  NOT NULL,
            last_refill_ts TIMESTAMPTZ      NOT NULL,
            PRIMARY KEY (subject_type, subject, action)
        )
        """,
        # ------------------------------------------------------------------
        # SMT change journal + checkpoints
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS smt_change_journal (
            id         BIGSERIAL   PRIMARY KEY,
            shard_id   TEXT        NOT NULL,
            key        BYTEA       NOT NULL,
            old_value  BYTEA,
            new_value  BYTEA       NOT NULL,
            header_seq INTEGER     NOT NULL,
            ts         TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_change_journal_shard_seq
            ON smt_change_journal(shard_id, header_seq)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_change_journal_shard_ts
            ON smt_change_journal(shard_id, ts)
        """,
        """
        CREATE TABLE IF NOT EXISTS smt_checkpoints (
            id         BIGSERIAL   PRIMARY KEY,
            shard_id   TEXT        NOT NULL,
            header_seq INTEGER     NOT NULL,
            root_hash  BYTEA       NOT NULL,
            leaf_count INTEGER     NOT NULL DEFAULT 0,
            ts         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (shard_id, header_seq)
        )
        """,
        # ------------------------------------------------------------------
        # Poseidon SMT Nodes — sparse internal nodes for incremental
        # O(log N) Poseidon root updates.  Structure mirrors smt_nodes
        # but stores Poseidon field elements as TEXT (decimal strings)
        # for circuit compatibility.
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS poseidon_smt_nodes (
            level    SMALLINT      NOT NULL,
            index    BYTEA         NOT NULL,
            hash     TEXT          NOT NULL,
            ts       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
            PRIMARY KEY (level, index),
            CONSTRAINT poseidon_smt_nodes_level_range
                CHECK (level >= 0 AND level <= 256)
        )
        """,
        "CREATE INDEX IF NOT EXISTS poseidon_smt_nodes_level_idx ON poseidon_smt_nodes(level)",
        # ------------------------------------------------------------------
        # Rekor Anchors — Sigstore Rekor transparency log anchoring
        # ------------------------------------------------------------------
        """
        CREATE TABLE IF NOT EXISTS rekor_anchors (
            id            BIGSERIAL   PRIMARY KEY,
            shard_id      TEXT        NOT NULL,
            shard_seq     BIGINT      NOT NULL,
            root_hash     BYTEA       NOT NULL,
            rekor_uuid    TEXT,
            rekor_index   BIGINT,
            anchored_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            status        TEXT        NOT NULL DEFAULT 'pending',
            CONSTRAINT rekor_anchors_root_hash_length
                CHECK (octet_length(root_hash) = 32)
        )
        """,
        "CREATE INDEX IF NOT EXISTS rekor_anchors_shard_seq_idx ON rekor_anchors(shard_id, shard_seq)",
        "CREATE INDEX IF NOT EXISTS rekor_anchors_status_idx ON rekor_anchors(status)",
    ]
    return stmts

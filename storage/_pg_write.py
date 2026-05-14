"""
Core record-append mixin (the primary write path).

Internal to the storage package (_pg_* convention).
Do NOT clean up logic while moving — behavior-preserving extraction only.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

import nacl.signing
import psycopg
import psycopg.errors
from psycopg import sql
from psycopg.rows import dict_row

from protocol.canonical_json import canonical_json_encode
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import global_key, record_key
from protocol.ledger import LedgerEntry
from protocol.shards import create_shard_header, sign_header, verify_header
from protocol.ssmf import ExistenceProof
from storage._pg_utils import (
    _NODE_REHASH_GATE,
    _poseidon_incremental_update,
    _require_rust_smt,
)


logger = logging.getLogger(__name__)


def _datetime_class() -> type[datetime]:
    """Return the facade datetime class so legacy monkeypatches still apply."""
    postgres_module = sys.modules.get("storage.postgres")
    facade_datetime = getattr(postgres_module, "datetime", None)
    return facade_datetime if facade_datetime is not None else datetime


class _WriteMixin:
    """Atomic record-append write path."""

    # Declared for type-checking; initialized by StorageLayer.__init__
    _retry_base_delay_seconds: float
    _retry_max_delay_seconds: float
    DEFAULT_FLUSH_BATCH_SIZE: int

    def append_record(
        self,
        shard_id: str,
        record_type: str,
        record_id: str,
        version: int,
        value_hash: bytes,
        signing_key: nacl.signing.SigningKey,
        canonicalization: dict[str, Any] | None = None,
        poseidon_root: bytes | None = None,
        *,
        parser_id: str = "fallback@1.0.0",
        canonical_parser_version: str = "v1",
        max_serialization_retries: int = 3,
    ) -> tuple[bytes, ExistenceProof, dict[str, Any], str, LedgerEntry]:
        """Append a record to the global sparse Merkle tree.

        Atomically updates the global SMT, shard header, and ledger.
        Retries on PostgreSQL serialization failures (SQLSTATE 40001) and
        deadlocks (SQLSTATE 40P01) up to *max_serialization_retries* times.

        Returns:
            Tuple of (root_hash, proof, header, signature, ledger_entry)
        """
        _require_rust_smt()

        if len(value_hash) != 32:
            raise ValueError(f"Value hash must be 32 bytes, got {len(value_hash)}")
        if not parser_id:
            raise ValueError("parser_id must be a non-empty string")
        if not canonical_parser_version:
            raise ValueError("canonical_parser_version must be a non-empty string")

        rec_key = record_key(record_type, record_id, version)
        key = global_key(shard_id, rec_key)

        max_attempts = 1 + max_serialization_retries
        _retryable = (
            psycopg.errors.SerializationFailure,
            psycopg.errors.DeadlockDetected,
        )
        for attempt in range(max_attempts):
            try:
                return self._append_record_inner(
                    shard_id=shard_id,
                    record_type=record_type,
                    record_id=record_id,
                    version=version,
                    key=key,
                    value_hash=value_hash,
                    parser_id=parser_id,
                    canonical_parser_version=canonical_parser_version,
                    signing_key=signing_key,
                    canonicalization=canonicalization,
                    poseidon_root=poseidon_root,
                )
            except _retryable as e:
                is_last_attempt = attempt == max_attempts - 1
                if not is_last_attempt:
                    delay = min(
                        self._retry_base_delay_seconds * (2**attempt),
                        self._retry_max_delay_seconds,
                    )
                    logger.warning(
                        "Serialization failure on append_record attempt %d/%d, "
                        "retrying in %.2fs: %s",
                        attempt + 1,
                        max_attempts,
                        delay,
                        e,
                    )
                    time.sleep(delay)
                else:
                    logger.error(
                        "Serialization failure after %d attempts, giving up: %s",
                        max_attempts,
                        e,
                    )
                    raise

        raise RuntimeError("Unexpected retry loop exit")

    def _append_record_inner(
        self,
        *,
        shard_id: str,
        record_type: str,
        record_id: str,
        version: int,
        key: bytes,
        value_hash: bytes,
        parser_id: str,
        canonical_parser_version: str,
        signing_key: nacl.signing.SigningKey,
        canonicalization: dict[str, Any] | None,
        poseidon_root: bytes | None,
    ) -> tuple[bytes, ExistenceProof, dict[str, Any], str, LedgerEntry]:
        """Inner implementation of append_record without retry logic."""
        from olympus_core import RustSparseMerkleTree  # required; _require_rust_smt guards

        with self._get_connection() as conn, conn.cursor(row_factory=dict_row) as cur:  # type: ignore[attr-defined]
            conn.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")

            cur.execute(
                "SELECT value_hash FROM smt_leaves WHERE key = %s AND version = %s",
                (key, version),
            )
            existing_row = cur.fetchone()
            if existing_row is not None:
                existing_value_hash = bytes(existing_row["value_hash"])
                if existing_value_hash == value_hash:
                    raise ValueError(f"Record already exists: {record_type}:{record_id}:{version}")
                raise ValueError(
                    f"Record already exists with different content: "
                    f"{record_type}:{record_id}:{version}"
                )

            siblings = self._get_proof_path(cur, key)  # type: ignore[attr-defined]

            root_hash, proof_siblings, node_deltas = RustSparseMerkleTree.incremental_update(
                key, value_hash, parser_id, canonical_parser_version, siblings
            )

            cur.execute("SELECT COUNT(*) AS cnt FROM smt_leaves")
            count_row = cur.fetchone()
            tree_size = (int(count_row["cnt"]) if count_row else 0) + 1

            proof = ExistenceProof(
                key=key,
                value_hash=value_hash,
                parser_id=parser_id,
                canonical_parser_version=canonical_parser_version,
                siblings=list(proof_siblings),
                root_hash=root_hash,
            )

            cur.execute(
                sql.SQL("SET LOCAL olympus.allow_smt_insert = {}").format(
                    sql.Literal(_NODE_REHASH_GATE)
                )
            )
            cur.execute(
                """
                    INSERT INTO smt_leaves
                        (key, version, value_hash, parser_id, canonical_parser_version, ts, shard_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING global_seq
                    """,
                (
                    key,
                    version,
                    value_hash,
                    parser_id,
                    canonical_parser_version,
                    _datetime_class().now(timezone.utc),
                    shard_id,
                ),
            )
            leaf_global_seq_row = cur.fetchone()
            if leaf_global_seq_row is None:
                raise RuntimeError("INSERT INTO smt_leaves did not return global_seq")
            leaf_global_seq: int = int(
                leaf_global_seq_row["global_seq"]
                if isinstance(leaf_global_seq_row, Mapping)
                else leaf_global_seq_row[0]
            )

            cur.execute(
                sql.SQL("SET LOCAL olympus.allow_node_rehash = {}").format(
                    sql.Literal(_NODE_REHASH_GATE)
                )
            )
            ts_now = _datetime_class().now(timezone.utc)
            cur.executemany(
                """
                INSERT INTO smt_nodes (level, index, hash, ts)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (level, index)
                DO UPDATE SET hash = EXCLUDED.hash, ts = EXCLUDED.ts
                """,
                [
                    (db_level, packed_index, hash_val, ts_now)
                    for db_level, packed_index, hash_val in node_deltas
                ],
            )
            for db_level, packed_index, hash_val in node_deltas:
                self._cache_put(shard_id, db_level, packed_index, hash_val)  # type: ignore[attr-defined]

            cur.execute(
                """
                    SELECT seq, header_hash FROM shard_headers
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT 1
                    FOR UPDATE
                    """,
                (shard_id,),
            )
            prev_row = cur.fetchone()
            prev_header_hash = "" if prev_row is None else bytes(prev_row["header_hash"]).hex()
            seq = 0 if prev_row is None else prev_row["seq"] + 1

            ts = _datetime_class().now(timezone.utc).isoformat().replace("+00:00", "Z")
            header = create_shard_header(
                shard_id=shard_id,
                root_hash=root_hash,
                timestamp=ts,
                tree_size=tree_size,
                previous_header_hash=prev_header_hash,
            )

            signature = sign_header(header, signing_key)
            pubkey = signing_key.verify_key.encode()

            if not verify_header(header, signature, signing_key.verify_key):
                raise RuntimeError("Shard header signature verification failed before persistence")

            cur.execute(
                """
                    INSERT INTO shard_headers
                        (shard_id, seq, root, tree_size, leaf_seq, header_hash,
                         sig, pubkey, previous_header_hash, ts)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                (
                    shard_id,
                    seq,
                    root_hash,
                    tree_size,
                    leaf_global_seq,
                    bytes.fromhex(header["header_hash"]),
                    bytes.fromhex(signature),
                    pubkey,
                    prev_header_hash,
                    ts,
                ),
            )

            cur.execute(
                """
                    INSERT INTO smt_change_journal
                        (shard_id, key, old_value, new_value, header_seq, ts)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                (shard_id, key, None, value_hash, seq, ts),
            )

            record_hash_hex = value_hash.hex()
            shard_root_hex = root_hash.hex()

            cur.execute(
                """
                    SELECT seq, entry_hash FROM ledger_entries
                    WHERE shard_id = %s
                    ORDER BY seq DESC
                    LIMIT 1
                    FOR UPDATE
                    """,
                (shard_id,),
            )
            prev_ledger_row = cur.fetchone()
            prev_entry_hash = (
                "" if prev_ledger_row is None else bytes(prev_ledger_row["entry_hash"]).hex()
            )
            ledger_seq = 0 if prev_ledger_row is None else prev_ledger_row["seq"] + 1

            canonicalization = canonicalization or canonicalization_provenance(
                "application/octet-stream",
                "byte_preserved",
            )

            ledger_payload: dict[str, Any] = {
                "ts": ts,
                "record_hash": record_hash_hex,
                "shard_id": shard_id,
                "shard_root": shard_root_hex,
                "canonicalization": canonicalization,
                "prev_entry_hash": prev_entry_hash,
            }

            poseidon_root_decimal: str | None = None
            if poseidon_root is not None:
                if len(poseidon_root) != 32:
                    raise ValueError(f"poseidon_root must be 32 bytes, got {len(poseidon_root)}")

            from protocol.hashes import (
                LEDGER_PREFIX,
                blake3_hash,
                create_dual_root_commitment,
                parse_dual_root_commitment,
            )

            if poseidon_root is not None:
                poseidon_siblings = self._get_poseidon_proof_path(cur, key)  # type: ignore[attr-defined]
                poseidon_root_int, poseidon_node_deltas = _poseidon_incremental_update(
                    key, value_hash, poseidon_siblings
                )
                authoritative_poseidon_root = poseidon_root_int.to_bytes(32, byteorder="big")
                poseidon_root_decimal = str(poseidon_root_int)
                ledger_payload["poseidon_root"] = poseidon_root_decimal

                ts_now_poseidon = _datetime_class().now(timezone.utc)
                cur.executemany(
                    """
                    INSERT INTO poseidon_smt_nodes (level, index, hash, ts)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (level, index)
                    DO UPDATE SET hash = EXCLUDED.hash, ts = EXCLUDED.ts
                    """,
                    [
                        (db_level, packed_index, hash_decimal, ts_now_poseidon)
                        for db_level, packed_index, hash_decimal in poseidon_node_deltas
                    ],
                )

                entry_hash = create_dual_root_commitment(root_hash, authoritative_poseidon_root)
                verified_b3_root, verified_poseidon_root = parse_dual_root_commitment(entry_hash)
                if (
                    verified_b3_root != root_hash
                    or verified_poseidon_root != authoritative_poseidon_root
                ):
                    raise RuntimeError("Ledger dual-root commitment verification failed")
            else:
                canonical_json = canonical_json_encode(ledger_payload)
                entry_hash = blake3_hash([LEDGER_PREFIX, canonical_json.encode("utf-8")])

            cur.execute(
                """
                    INSERT INTO ledger_entries
                        (shard_id, seq, entry_hash, prev_entry_hash, payload, ts)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                (
                    shard_id,
                    ledger_seq,
                    entry_hash,
                    bytes.fromhex(prev_entry_hash) if prev_entry_hash else b"",
                    json.dumps(ledger_payload),
                    ts,
                ),
            )

            # RT-M1: Re-verify persisted ledger entry hash from stored payload.
            cur.execute(
                """
                    SELECT entry_hash, payload
                    FROM ledger_entries
                    WHERE shard_id = %s AND seq = %s
                    LIMIT 1
                """,
                (shard_id, ledger_seq),
            )
            persisted_entry_row = cur.fetchone()
            if persisted_entry_row is None:
                raise RuntimeError("Failed to load persisted ledger entry for verification")

            persisted_entry_hash = bytes(persisted_entry_row["entry_hash"])
            persisted_payload = persisted_entry_row["payload"]
            if isinstance(persisted_payload, str):
                persisted_payload = json.loads(persisted_payload)

            if poseidon_root is not None:
                parsed_b3_root, parsed_poseidon_root = parse_dual_root_commitment(
                    persisted_entry_hash
                )
                if parsed_b3_root != root_hash:
                    raise RuntimeError("Persisted dual-root commitment BLAKE3 root mismatch")
                if poseidon_root_decimal is None:
                    raise RuntimeError("Persisted dual-root commitment missing poseidon root")
                if int.from_bytes(parsed_poseidon_root, byteorder="big") != int(
                    poseidon_root_decimal
                ):
                    raise RuntimeError("Persisted dual-root commitment Poseidon root mismatch")
            else:
                persisted_canonical = canonical_json_encode(persisted_payload)
                expected_persisted_hash = blake3_hash(
                    [LEDGER_PREFIX, persisted_canonical.encode("utf-8")]
                )
                if persisted_entry_hash != expected_persisted_hash:
                    raise RuntimeError("Persisted ledger entry hash verification failed")

            ledger_entry = LedgerEntry(
                ts=ts,
                record_hash=record_hash_hex,
                shard_id=shard_id,
                shard_root=shard_root_hex,
                canonicalization=canonicalization,
                prev_entry_hash=prev_entry_hash,
                entry_hash=entry_hash.hex(),
                poseidon_root=poseidon_root_decimal,
            )

            conn.commit()

            return root_hash, proof, header, signature, ledger_entry

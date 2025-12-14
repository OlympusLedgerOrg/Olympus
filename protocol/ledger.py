"""Append-only ledger and persistence helpers for Olympus Phase 0."""

from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .hashes import HASH_SEPARATOR, hash_string


@dataclass
class LedgerEntry:
    timestamp: str  # ISO 8601 format
    record_hash: str  # Hex-encoded record hash (e.g., leaf hash)
    shard_id: str
    merkle_root: str  # Hex-encoded shard root after commit
    previous_hash: str  # Hex-encoded, empty string for genesis
    entry_hash: str  # Hex-encoded hash of this entry

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Ledger:
    """In-memory append-only ledger chain."""

    def __init__(self):
        self.entries: List[LedgerEntry] = []

    def append(self, record_hash: str, shard_id: str, merkle_root: str) -> LedgerEntry:
        timestamp = datetime.utcnow().isoformat() + "Z"
        previous_hash = self.entries[-1].entry_hash if self.entries else ""
        entry_data = HASH_SEPARATOR.join([timestamp, record_hash, shard_id, merkle_root, previous_hash])
        entry_hash = hash_string(entry_data).hex()
        entry = LedgerEntry(
            timestamp=timestamp,
            record_hash=record_hash,
            shard_id=shard_id,
            merkle_root=merkle_root,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )
        self.entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        if not self.entries:
            return True

        if self.entries[0].previous_hash != "":
            return False

        for i, entry in enumerate(self.entries):
            entry_data = HASH_SEPARATOR.join(
                [entry.timestamp, entry.record_hash, entry.shard_id, entry.merkle_root, entry.previous_hash]
            )
            expected_hash = hash_string(entry_data).hex()
            if expected_hash != entry.entry_hash:
                return False
            if i > 0 and entry.previous_hash != self.entries[i - 1].entry_hash:
                return False
        return True


class LedgerDB:
    """Minimal SQLite-backed persistence for Phase 0 tables."""

    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path)
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS shard_headers(
                shard_id TEXT,
                seq INTEGER,
                ts TEXT,
                root TEXT,
                prev_header_hash TEXT,
                header_hash TEXT PRIMARY KEY,
                sig TEXT,
                signer_pubkey TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS smt_nodes(
                shard_id TEXT,
                level INTEGER,
                idx INTEGER,
                hash TEXT,
                PRIMARY KEY(shard_id, level, idx)
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS smt_leaves(
                shard_id TEXT,
                key TEXT,
                version TEXT,
                value_hash TEXT,
                leaf_hash TEXT,
                ts TEXT,
                PRIMARY KEY(shard_id, key, version)
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS policies(
                policy_id TEXT,
                version TEXT,
                policy_json TEXT,
                policy_hash TEXT,
                ts TEXT,
                header_hash_ref TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS waterfall_events(
                event_id TEXT,
                ts TEXT,
                revenue_cents INTEGER,
                ops_cents INTEGER,
                architect_cents INTEGER,
                fund_cents INTEGER,
                rnd_cents INTEGER,
                remainder_cents INTEGER,
                policy_hash TEXT,
                header_hash_ref TEXT
            );
            """
        )
        self.conn.commit()

    def insert_shard_header(
        self,
        shard_id: str,
        seq: int,
        ts: str,
        root: str,
        prev_header_hash: str,
        header_hash: str,
        sig: str,
        signer_pubkey: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO shard_headers(shard_id, seq, ts, root, prev_header_hash, header_hash, sig, signer_pubkey)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (shard_id, seq, ts, root, prev_header_hash, header_hash, sig, signer_pubkey),
        )
        self.conn.commit()

    def insert_leaf(
        self,
        shard_id: str,
        key: str,
        version: str,
        value_hash: str,
        leaf_hash: str,
        ts: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO smt_leaves(shard_id, key, version, value_hash, leaf_hash, ts)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (shard_id, key, version, value_hash, leaf_hash, ts),
        )
        self.conn.commit()

    def insert_policy(
        self, policy_id: str, version: str, policy_json: str, policy_hash: str, ts: str, header_hash_ref: str
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO policies(policy_id, version, policy_json, policy_hash, ts, header_hash_ref)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (policy_id, version, policy_json, policy_hash, ts, header_hash_ref),
        )
        self.conn.commit()

    def insert_waterfall_event(
        self,
        event_id: str,
        ts: str,
        revenue_cents: int,
        ops_cents: int,
        architect_cents: int,
        fund_cents: int,
        rnd_cents: int,
        remainder_cents: int,
        policy_hash: str,
        header_hash_ref: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO waterfall_events(event_id, ts, revenue_cents, ops_cents, architect_cents, fund_cents,
                rnd_cents, remainder_cents, policy_hash, header_hash_ref)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                ts,
                revenue_cents,
                ops_cents,
                architect_cents,
                fund_cents,
                rnd_cents,
                remainder_cents,
                policy_hash,
                header_hash_ref,
            ),
        )
        self.conn.commit()

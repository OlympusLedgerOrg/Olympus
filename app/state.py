"""State management for Olympus FastAPI service."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Dict, Optional

from nacl import signing

from protocol.canonical import canonicalize_json
from protocol.hashes import forest_root, hash_string, leaf_hash, record_key
from protocol.ledger import Ledger, LedgerDB
from protocol.policy import Policy, compute_waterfall
from protocol.shards import ShardHeader, create_header
from protocol.ssmf import ProofNode, SparseMerkleProof, SparseMerkleTree, verify_proof


class ShardState:
    def __init__(self, shard_id: str, signing_key: signing.SigningKey, db: LedgerDB):
        self.shard_id = shard_id
        self.tree = SparseMerkleTree()
        self.headers: list[ShardHeader] = []
        self.signing_key = signing_key
        self.db = db

    def latest_header(self) -> Optional[ShardHeader]:
        return self.headers[-1] if self.headers else None

    def append(self, key: bytes, version: str, value_hash: bytes, ts: Optional[str] = None) -> ShardHeader:
        root = self.tree.set(key, value_hash, version)
        prev = self.headers[-1].header_hash if self.headers else ""
        header = create_header(self.shard_id, root, len(self.headers) + 1, prev, self.signing_key, ts=ts)
        self.headers.append(header)
        ts = header.ts
        leaf = leaf_hash(key, value_hash).hex()
        self.db.insert_leaf(self.shard_id, key.hex(), version, value_hash.hex(), leaf, ts)
        self.db.insert_shard_header(
            self.shard_id, header.seq, ts, header.root, header.prev_header_hash, header.header_hash, header.signature, header.signer_pubkey
        )
        return header

    def existence_proof(self, key: bytes, version: Optional[str] = None) -> SparseMerkleProof:
        return self.tree.prove_existence(key, version)

    def nonexistence_proof(self, key: bytes, version: Optional[str] = None) -> SparseMerkleProof:
        return self.tree.prove_nonexistence(key, version)


class OlympusState:
    def __init__(self, db_path: str = ":memory:"):
        seed = os.getenv("OLY_SIGNING_SEED")
        self.signing_key = signing.SigningKey(bytes.fromhex(seed)) if seed else signing.SigningKey.generate()
        self.admin_key = os.getenv("OLY_ADMIN_KEY", "dev-admin-key")
        self.db = LedgerDB(db_path)
        self.shards: Dict[str, ShardState] = {}
        self.ledger = Ledger()

    def _shard(self, shard_id: str) -> ShardState:
        if shard_id not in self.shards:
            self.shards[shard_id] = ShardState(shard_id, self.signing_key, self.db)
        return self.shards[shard_id]

    def append_record(self, shard_id: str, record_type: str, record_id: str, version: str, value_json: dict, ts: Optional[str] = None) -> ShardHeader:
        key = record_key(record_type, record_id, version)
        canonical = canonicalize_json(value_json)
        value_hash = hash_string(canonical)
        shard = self._shard(shard_id)
        header = shard.append(key, version, value_hash, ts=ts)
        self.ledger.append(leaf_hash(key, value_hash).hex(), shard_id, shard.tree.root().hex())
        return header

    def create_policy(self, period: str, policy_payload: dict) -> Policy:
        payload = policy_payload.copy()
        if not payload.get("effective_ts"):
            payload["effective_ts"] = datetime.utcnow().isoformat() + "Z"
        policy = Policy(**payload)
        policy.compute_hash()
        shard_id = f"global:{period}:policy"
        self.append_record(shard_id, "policy", policy.policy_id, policy.version, payload)
        self.db.insert_policy(
            policy.policy_id,
            policy.version,
            canonicalize_json(payload),
            policy.policy_hash,
            policy.effective_ts,
            self.shards[shard_id].latest_header().header_hash,
        )
        return policy

    def record_waterfall(self, period: str, revenue_cents: int, policy_payload: dict) -> Dict[str, int]:
        payload = policy_payload.copy()
        if not payload.get("effective_ts"):
            payload["effective_ts"] = datetime.utcnow().isoformat() + "Z"
        policy = Policy(**payload)
        allocations = compute_waterfall(revenue_cents, policy)
        shard_id = f"global:{period}:finance"
        event_id = f"{period}:{policy.policy_id}:{policy.version}:{revenue_cents}"
        self.append_record(shard_id, "finance", event_id, policy.version, allocations)
        self.db.insert_waterfall_event(
            event_id,
            datetime.utcnow().isoformat() + "Z",
            revenue_cents,
            allocations["ops_cents"],
            allocations["architect_cents"],
            allocations["fund_cents"],
            allocations["rnd_cents"],
            allocations["remainder_cents"],
            allocations["policy_hash"],
            self.shards[shard_id].latest_header().header_hash,
        )
        return allocations

    def roots(self) -> Dict[str, str]:
        shard_roots = {sid: state.tree.root().hex() for sid, state in self.shards.items()}
        header_hashes = [bytes.fromhex(h.header_hash) for state in self.shards.values() if (h := state.latest_header())]
        global_root = forest_root(header_hashes).hex() if header_hashes else forest_root([]).hex()
        return {"global_root": global_root, "shards": shard_roots}

    def header_latest(self, shard_id: str) -> Optional[ShardHeader]:
        return self._shard(shard_id).latest_header()

    def proof_existence(self, shard_id: str, key: bytes, version: Optional[str] = None) -> SparseMerkleProof:
        return self._shard(shard_id).existence_proof(key, version)

    def proof_nonexistence(self, shard_id: str, key: bytes, version: Optional[str] = None) -> SparseMerkleProof:
        return self._shard(shard_id).nonexistence_proof(key, version)

    @staticmethod
    def verify_proof(root_hex: str, key_hex: str, proof_payload: dict, value_hash_hex: Optional[str] = None) -> bool:
        proof = SparseMerkleProof(
            key=bytes.fromhex(proof_payload["key"]),
            leaf_hash=bytes.fromhex(proof_payload["leaf_hash"]),
            siblings=[ProofNode(hash=bytes.fromhex(item["hash"]), is_right=item["is_right"]) for item in proof_payload["siblings"]],
            exists=proof_payload["exists"],
            value_hash=bytes.fromhex(proof_payload["value_hash"]) if proof_payload.get("value_hash") else None,
        )
        return verify_proof(bytes.fromhex(root_hex), bytes.fromhex(key_hex), proof, bytes.fromhex(value_hash_hex) if value_hash_hex else None)

    def validate_admin(self, api_key: str) -> bool:
        return api_key == self.admin_key

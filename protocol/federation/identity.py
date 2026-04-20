"""Federation identity, registry, and epoch helpers."""

from __future__ import annotations

import json
import math
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import nacl.signing

from protocol.hashes import hash_bytes


# Public domain-separation tag bound to every federation vote message.
# Prevents signatures created for other protocol contexts (ingest, admin,
# shard-merge, …) from being replayed as federation votes.
FEDERATION_DOMAIN_TAG = "OLY:FEDERATION-VOTE:V1"

# Minimum number of active Guardians required for the federation to operate.
# Byzantine fault tolerance with a 2/3 quorum requires at least N=3 nodes so
# that no single operator (or single failed node) can self-certify the ledger.
# A 1- or 2-node "federation" provides zero BFT guarantee and would silently
# turn the load-bearing distributed-trust claim into a single-operator trust
# claim; reject such configurations explicitly.
MIN_ACTIVE_GUARDIANS_FOR_BFT = 3

# Maximum window during which a rotated-away federation key remains valid for
# signature verification after the rotation timestamp. This bounds the overlap
# during a key handover and prevents an operator from setting an effectively
# permanent ``valid_until`` (e.g. ``"2099-12-31"``) which would keep a rotated
# key valid forever and defeat the purpose of rotation.
MAX_KEY_OVERLAP_WINDOW = timedelta(days=30)
_HEADER_EXCLUDED_FIELDS: frozenset[str] = frozenset(
    {"header_hash", "signature", "timestamp_token", "quorum_certificate_hash"}
)
_CERTIFICATE_SIGNATURE_SCHEME_ED25519 = "ed25519"
DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS = 120


def _to_int(value: Any) -> int | None:
    """Convert a value to int, returning None on type/format errors."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class FederationKeyHistoryEntry:
    """Historical federation key binding for rotation-aware signature verification."""

    pubkey: bytes
    valid_until: str

    def to_dict(self) -> dict[str, str]:
        """Serialize to JSON-friendly data."""
        return {"pubkey": self.pubkey.hex(), "valid_until": self.valid_until}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FederationKeyHistoryEntry:
        """Create a historical key binding from registry JSON data."""
        return cls(pubkey=bytes.fromhex(str(data["pubkey"])), valid_until=str(data["valid_until"]))

    def is_valid_for_timestamp(self, header_timestamp: str) -> bool:
        """Return whether this historical key is valid for a header timestamp."""
        return _parse_timestamp(header_timestamp) <= _parse_timestamp(self.valid_until)


@dataclass(frozen=True)
class FederationNode:
    """Persistent identity for a federation participant."""

    node_id: str
    pubkey: bytes
    endpoint: str
    operator: str
    jurisdiction: str
    status: str = "active"
    key_history: tuple[FederationKeyHistoryEntry, ...] = ()

    @property
    def active(self) -> bool:
        """Return whether the node participates in quorum calculations."""
        return self.status == "active"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the node to JSON-friendly values."""
        node_data: dict[str, Any] = {
            "node_id": self.node_id,
            "pubkey": self.pubkey.hex(),
            "endpoint": self.endpoint,
            "operator": self.operator,
            "jurisdiction": self.jurisdiction,
            "status": self.status,
        }
        if self.key_history:
            node_data["key_history"] = [entry.to_dict() for entry in self.key_history]
        return node_data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FederationNode:
        """Create a node from registry JSON data."""
        pubkey_hex = str(data["pubkey"])
        raw_key_history = data.get("key_history", [])
        key_history = tuple(
            FederationKeyHistoryEntry.from_dict(item)
            for item in raw_key_history
            if isinstance(item, dict) and "pubkey" in item and "valid_until" in item
        )
        return cls(
            node_id=str(data["node_id"]),
            pubkey=bytes.fromhex(pubkey_hex),
            endpoint=str(data["endpoint"]),
            operator=str(data["operator"]),
            jurisdiction=str(data["jurisdiction"]),
            status=str(data.get("status", "active")),
            key_history=key_history,
        )

    def verify_key(self) -> nacl.signing.VerifyKey:
        """Return the Ed25519 verification key for this node."""
        return nacl.signing.VerifyKey(self.pubkey)

    def verify_keys_for_timestamp(
        self, header_timestamp: str
    ) -> tuple[nacl.signing.VerifyKey, ...]:
        """Return current plus timestamp-valid historical verification keys."""
        verify_keys: list[nacl.signing.VerifyKey] = [self.verify_key()]
        for key_entry in self.key_history:
            try:
                if key_entry.is_valid_for_timestamp(header_timestamp):
                    verify_keys.append(nacl.signing.VerifyKey(key_entry.pubkey))
            except ValueError:
                continue
        return tuple(verify_keys)


@dataclass(frozen=True)
class FederationRegistry:
    """Static federation registry used by the prototype."""

    nodes: tuple[FederationNode, ...]
    epoch: int = 0
    snapshots: dict[int, FederationRegistry] | tuple[FederationRegistry, ...] | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        snapshot_cache = {self.epoch: self}
        extra_snapshots = self._normalize_snapshots(self.snapshots)
        snapshot_cache.update(extra_snapshots)
        object.__setattr__(self, "_snapshot_cache", snapshot_cache)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FederationRegistry:
        """Create a registry from parsed JSON data."""
        raw_nodes = data.get("nodes", [])
        if not isinstance(raw_nodes, list) or not raw_nodes:
            raise ValueError("Federation registry must include at least one node")

        nodes = tuple(FederationNode.from_dict(node) for node in raw_nodes)
        node_ids = {node.node_id for node in nodes}
        if len(node_ids) != len(nodes):
            raise ValueError("Federation registry node_id values must be unique")
        pubkeys: set[bytes] = set()
        for node in nodes:
            if node.pubkey in pubkeys:
                raise ValueError("Federation registry pubkey values must be unique")
            pubkeys.add(node.pubkey)
            for historical_key in node.key_history:
                if historical_key.pubkey in pubkeys:
                    raise ValueError("Federation registry pubkey values must be unique")
                pubkeys.add(historical_key.pubkey)

        epoch = int(data.get("epoch", 0))
        if epoch < 0:
            raise ValueError("Federation registry epoch must be non-negative")

        raw_snapshots = data.get("snapshots")

        return cls(nodes=nodes, epoch=epoch, snapshots=raw_snapshots)

    @classmethod
    def from_file(cls, path: str | Path) -> FederationRegistry:
        """Load a registry from disk."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the registry to JSON-friendly data."""
        return {"nodes": [node.to_dict() for node in self.nodes], "epoch": self.epoch}

    @staticmethod
    def _coerce_snapshot(snapshot: Any) -> FederationRegistry:
        """Normalize snapshot inputs into FederationRegistry instances."""
        if isinstance(snapshot, FederationRegistry):
            return snapshot
        if isinstance(snapshot, dict):
            return FederationRegistry.from_dict(snapshot)
        raise ValueError("Registry snapshots must be FederationRegistry instances or dicts")

    def _normalize_snapshots(
        self, snapshots: dict[int, FederationRegistry] | tuple[FederationRegistry, ...] | None
    ) -> dict[int, FederationRegistry]:
        """Return a normalized mapping of epoch -> registry snapshots."""
        if snapshots is None:
            return {}

        normalized: dict[int, FederationRegistry] = {}
        items: Iterator[tuple[int | None, FederationRegistry]]
        if isinstance(snapshots, dict):
            items = iter(snapshots.items())
        else:
            items = ((None, snapshot) for snapshot in snapshots)

        for key, snapshot in items:
            registry_snapshot = self._coerce_snapshot(snapshot)
            epoch = registry_snapshot.epoch if key is None else int(key)
            if epoch < 0:
                raise ValueError("Federation registry epoch must be non-negative")
            if epoch != registry_snapshot.epoch:
                raise ValueError("Snapshot epoch key does not match snapshot epoch value")
            normalized[epoch] = registry_snapshot

        return normalized

    def get_snapshot(self, epoch: int) -> FederationRegistry:
        """Return the registry snapshot for a specific epoch."""
        try:
            epoch_int = int(epoch)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid epoch value: {epoch}") from exc
        if epoch_int < 0:
            raise ValueError("Federation registry epoch must be non-negative")

        cache: dict[int, FederationRegistry] = getattr(self, "_snapshot_cache", {})
        if epoch_int in cache:
            return cache[epoch_int]

        raise ValueError(f"No registry snapshot available for epoch {epoch_int}")

    def get_node(self, node_id: str) -> FederationNode:
        """Return the registry entry for a node id."""
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        raise ValueError(f"Unknown federation node: {node_id}")

    def active_nodes(self) -> tuple[FederationNode, ...]:
        """Return only active nodes."""
        return tuple(node for node in self.nodes if node.active)

    def quorum_threshold(self) -> int:
        """Return the prototype >=2/3 quorum threshold.

        Requires at least ``MIN_ACTIVE_GUARDIANS_FOR_BFT`` (3) active Guardians.
        With fewer than three active nodes, a 2/3 quorum cannot tolerate a
        single Byzantine or unavailable node, so the federation provides no
        BFT guarantee and the "distributed trust" claim is unfounded.
        """
        active_count = len(self.active_nodes())
        if active_count == 0:
            raise ValueError("Federation registry has no active nodes")
        if active_count < MIN_ACTIVE_GUARDIANS_FOR_BFT:
            raise ValueError(
                "Federation requires at least 3 active Guardians for Byzantine fault tolerance"
            )
        # Require at least a two-thirds quorum of active federation members.
        return math.ceil((2 * active_count) / 3)

    def membership_hash(self) -> str:
        """Return the deterministic hash commitment for active federation membership.

        Uses length-prefixed encoding to prevent injection attacks when node_id
        or pubkey_hex contain literal pipe characters or colons.
        """
        active_members = sorted(
            ((node.node_id, node.pubkey.hex()) for node in self.active_nodes()),
            key=lambda item: (item[0], item[1]),
        )
        # Length-prefixed encoding: each field is encoded as
        # [4-byte big-endian length] || [UTF-8 bytes]
        domain = "olympus.federation.membership.v1"
        fields = [domain]
        for node_id, pubkey_hex in active_members:
            fields.append(node_id)
            fields.append(pubkey_hex)

        encoded_fields = []
        for value in fields:
            field_bytes = value.encode("utf-8")
            encoded_fields.append(len(field_bytes).to_bytes(4, byteorder="big"))
            encoded_fields.append(field_bytes)

        payload = b"".join(encoded_fields)
        return hash_bytes(payload).hex()

    def rotate_node_key(
        self,
        *,
        node_id: str,
        new_pubkey: bytes,
        rotated_at: str,
    ) -> FederationRegistry:
        """Return a new registry with one node key rotated while preserving history.

        ``rotated_at`` is recorded as the ``valid_until`` of the previous key in
        the node's key history. To prevent an operator from making a
        rotated-away key effectively permanent (e.g. ``valid_until =
        "2099-12-31"``), the timestamp must lie no further than
        :data:`MAX_KEY_OVERLAP_WINDOW` (30 days) in the future.
        """
        try:
            parsed_rotated_at = _parse_timestamp(rotated_at)
        except ValueError as exc:
            raise ValueError(f"Invalid rotation timestamp: {rotated_at}") from exc
        max_allowed = datetime.now(timezone.utc) + MAX_KEY_OVERLAP_WINDOW
        if parsed_rotated_at >= max_allowed:
            raise ValueError(
                "rotated_at must be within "
                f"{MAX_KEY_OVERLAP_WINDOW.days} days of the current time; "
                "a far-future valid_until would keep the previous key valid "
                "indefinitely and defeat key rotation"
            )
        updated_nodes: list[FederationNode] = []
        found = False
        for node in self.nodes:
            if node.node_id != node_id:
                updated_nodes.append(node)
                continue
            found = True
            if new_pubkey == node.pubkey:
                raise ValueError("new_pubkey must differ from current pubkey")
            updated_nodes.append(
                FederationNode(
                    node_id=node.node_id,
                    pubkey=new_pubkey,
                    endpoint=node.endpoint,
                    operator=node.operator,
                    jurisdiction=node.jurisdiction,
                    status=node.status,
                    key_history=(
                        *node.key_history,
                        FederationKeyHistoryEntry(pubkey=node.pubkey, valid_until=rotated_at),
                    ),
                )
            )
        if not found:
            raise ValueError(f"Unknown federation node: {node_id}")
        return FederationRegistry(nodes=tuple(updated_nodes))


def _parse_timestamp(timestamp: str) -> datetime:
    """Parse an ISO 8601 timestamp that may use a ``Z`` suffix as timezone-aware datetime."""
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def _median_numeric(values: list[int]) -> float:
    """Return the statistical median for integer values."""
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return float(ordered[midpoint])
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2


def _median_timestamp(values: list[datetime]) -> datetime:
    """Return the statistical median timestamp."""
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[midpoint]
    lower = ordered[midpoint - 1]
    upper = ordered[midpoint]
    return lower + (upper - lower) / 2


def is_replay_epoch(candidate_epoch: int, current_epoch: int) -> bool:
    """Return whether ``candidate_epoch`` is stale relative to ``current_epoch``.

    Federation replay protection rejects any quorum certificate/root candidate
    whose epoch is lower than the receiver's current epoch.
    """
    return candidate_epoch < current_epoch


def _extract_round_and_height(header: dict[str, Any]) -> tuple[int, int]:
    """Return validated round/height metadata required for federation vote binding."""
    try:
        height = int(header["height"])
        round_number = int(header["round"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Federation votes require integer height and round metadata") from exc
    if height < 0 or round_number < 0:
        raise ValueError("Federation vote round and height must be non-negative")
    return height, round_number

"""Federation identity, registry, and quorum-signing prototype."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import nacl.exceptions
import nacl.signing

from protocol.hashes import HASH_SEPARATOR, hash_bytes, shard_header_hash
from protocol.ledger import Ledger, LedgerEntry


_FEDERATION_VOTE_DOMAIN = "OLY:FEDERATION-VOTE:V1"
_HEADER_EXCLUDED_FIELDS: frozenset[str] = frozenset({"header_hash", "signature", "timestamp_token"})
_CERTIFICATE_SIGNATURE_SCHEME_ED25519 = "ed25519"


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

        return cls(nodes=nodes, epoch=epoch)

    @classmethod
    def from_file(cls, path: str | Path) -> FederationRegistry:
        """Load a registry from disk."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the registry to JSON-friendly data."""
        return {"nodes": [node.to_dict() for node in self.nodes], "epoch": self.epoch}

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
        """Return the prototype >=2/3 quorum threshold."""
        active_count = len(self.active_nodes())
        if active_count == 0:
            raise ValueError("Federation registry has no active nodes")
        # Require at least a two-thirds quorum of active federation members.
        return math.ceil((2 * active_count) / 3)

    def membership_hash(self) -> str:
        """Return the deterministic hash commitment for active federation membership."""
        active_members = sorted(
            ((node.node_id, node.pubkey.hex()) for node in self.active_nodes()),
            key=lambda item: (item[0], item[1]),
        )
        payload = HASH_SEPARATOR.join(
            [f"{node_id}:{pubkey_hex}" for node_id, pubkey_hex in active_members]
        ).encode("utf-8")
        return hash_bytes(payload).hex()

    def rotate_node_key(
        self,
        *,
        node_id: str,
        new_pubkey: bytes,
        rotated_at: str,
    ) -> FederationRegistry:
        """Return a new registry with one node key rotated while preserving history."""
        try:
            _parse_timestamp(rotated_at)
        except ValueError as exc:
            raise ValueError(f"Invalid rotation timestamp: {rotated_at}") from exc
        updated_nodes: list[FederationNode] = []
        found = False
        for node in self.nodes:
            if node.node_id != node_id:
                updated_nodes.append(node)
                continue
            found = True
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


@dataclass(frozen=True)
class NodeSignature:
    """Prototype federation signature attached to a shard header."""

    node_id: str
    signature: str

    def to_dict(self) -> dict[str, str]:
        """Serialize to JSON-friendly data."""
        return {"node_id": self.node_id, "signature": self.signature}


def sign_federated_header(
    header: dict[str, Any],
    node_id: str,
    signing_key: nacl.signing.SigningKey,
    registry: FederationRegistry,
) -> NodeSignature:
    """Sign a shard header on behalf of a federation node."""
    vote_hash = hash_bytes(_federation_vote_payload(header, node_id, registry))
    signature = signing_key.sign(vote_hash).signature.hex()
    return NodeSignature(node_id=node_id, signature=signature)


def _federation_vote_event_id(header: dict[str, Any], registry: FederationRegistry) -> str:
    """Return the deterministic federation vote event identifier for a shard header."""
    payload = HASH_SEPARATOR.join(
        [
            str(header["shard_id"]),
            str(header["header_hash"]),
            str(header["timestamp"]),
            str(registry.epoch),
            registry.membership_hash(),
        ]
    ).encode("utf-8")
    return hash_bytes(payload).hex()


def _federation_vote_payload(
    header: dict[str, Any], node_id: str, registry: FederationRegistry
) -> bytes:
    """Build domain-separated bytes for federation vote signing and verification."""
    event_id = _federation_vote_event_id(header, registry)
    payload = HASH_SEPARATOR.join(
        [
            _FEDERATION_VOTE_DOMAIN,
            str(node_id),
            str(header["shard_id"]),
            str(header["header_hash"]),
            str(header["timestamp"]),
            str(registry.epoch),
            registry.membership_hash(),
            event_id,
        ]
    )
    return payload.encode("utf-8")


def _header_hash_matches_commitment(header: dict[str, Any]) -> bool:
    """Return whether the provided header_hash matches committed shard header fields."""
    if "header_hash" not in header:
        return False
    header_without_hash = {k: v for k, v in header.items() if k not in _HEADER_EXCLUDED_FIELDS}
    expected_hash = shard_header_hash(header_without_hash).hex()
    return str(header.get("header_hash")) == expected_hash


def verify_federated_header_signatures(
    header: dict[str, Any],
    signatures: list[NodeSignature],
    registry: FederationRegistry,
) -> list[NodeSignature]:
    """Return the subset of unique, valid node signatures for a shard header."""
    if not _header_hash_matches_commitment(header):
        return []
    valid_signatures: list[NodeSignature] = []
    seen_nodes: set[str] = set()

    for signature in signatures:
        if signature.node_id in seen_nodes:
            continue
        try:
            node = registry.get_node(signature.node_id)
        except ValueError:
            continue
        if not node.active:
            continue
        try:
            vote_hash = hash_bytes(_federation_vote_payload(header, signature.node_id, registry))
            signature_bytes = bytes.fromhex(signature.signature)
            for verify_key in node.verify_keys_for_timestamp(str(header["timestamp"])):
                try:
                    verify_key.verify(vote_hash, signature_bytes)
                    valid_signatures.append(signature)
                    seen_nodes.add(signature.node_id)
                    break
                except nacl.exceptions.BadSignatureError:
                    continue
        except (ValueError, nacl.exceptions.BadSignatureError):
            continue

    return valid_signatures


def has_federation_quorum(
    header: dict[str, Any],
    signatures: list[NodeSignature],
    registry: FederationRegistry,
) -> bool:
    """Return whether a header has the prototype >=2/3 federation quorum."""
    valid_signatures = verify_federated_header_signatures(header, signatures, registry)
    return len(valid_signatures) >= registry.quorum_threshold()


def build_federation_header_record(
    header: dict[str, Any],
    signatures: list[NodeSignature],
) -> dict[str, Any]:
    """Build the reviewer-facing federation header structure."""
    return {
        "shard_id": str(header["shard_id"]),
        "state_root": str(header["root_hash"]),
        "timestamp": str(header["timestamp"]),
        "header_hash": str(header["header_hash"]),
        "node_signatures": [signature.to_dict() for signature in signatures],
    }


def build_quorum_certificate(
    header: dict[str, Any],
    signatures: list[NodeSignature],
    registry: FederationRegistry,
) -> dict[str, Any]:
    """Build a verifiable quorum certificate for a federation-finalized shard header."""
    valid_signatures = verify_federated_header_signatures(header, signatures, registry)
    if len(valid_signatures) < registry.quorum_threshold():
        raise ValueError("Insufficient valid federation signatures for quorum certificate")
    ordered_signatures = sorted(valid_signatures, key=lambda signature: signature.node_id)
    signed_node_ids = {signature.node_id for signature in ordered_signatures}
    active_node_ids = sorted(node.node_id for node in registry.active_nodes())
    signer_bitmap = "".join(
        "1" if node_id in signed_node_ids else "0" for node_id in active_node_ids
    )
    return {
        "shard_id": str(header["shard_id"]),
        "header_hash": str(header["header_hash"]),
        "timestamp": str(header["timestamp"]),
        "event_id": _federation_vote_event_id(header, registry),
        "federation_epoch": registry.epoch,
        "membership_hash": registry.membership_hash(),
        "quorum_threshold": registry.quorum_threshold(),
        "scheme": _CERTIFICATE_SIGNATURE_SCHEME_ED25519,
        "signer_bitmap": signer_bitmap,
        "signatures": [signature.to_dict() for signature in ordered_signatures],
    }


def verify_quorum_certificate(
    certificate: dict[str, Any],
    header: dict[str, Any],
    registry: FederationRegistry,
) -> bool:
    """Verify a quorum certificate against a header and registry membership."""
    required_fields = {
        "shard_id",
        "header_hash",
        "timestamp",
        "event_id",
        "federation_epoch",
        "membership_hash",
        "quorum_threshold",
        "scheme",
        "signer_bitmap",
        "signatures",
    }
    if not required_fields.issubset(certificate):
        return False
    if certificate["shard_id"] != header.get("shard_id"):
        return False
    if certificate["header_hash"] != header.get("header_hash"):
        return False
    if certificate["timestamp"] != header.get("timestamp"):
        return False
    if certificate["event_id"] != _federation_vote_event_id(header, registry):
        return False
    if int(certificate["federation_epoch"]) != registry.epoch:
        return False
    if str(certificate["membership_hash"]) != registry.membership_hash():
        return False
    if int(certificate["quorum_threshold"]) != registry.quorum_threshold():
        return False
    if certificate.get("scheme") != _CERTIFICATE_SIGNATURE_SCHEME_ED25519:
        return False

    serialized_signatures = certificate.get("signatures")
    if not isinstance(serialized_signatures, list):
        return False
    signatures = [
        NodeSignature(node_id=str(item["node_id"]), signature=str(item["signature"]))
        for item in serialized_signatures
        if isinstance(item, dict) and "node_id" in item and "signature" in item
    ]
    unique_signatures: list[NodeSignature] = []
    seen_signatures_by_node: dict[str, str] = {}
    for signature in signatures:
        previous_signature = seen_signatures_by_node.get(signature.node_id)
        if previous_signature is not None:
            if previous_signature != signature.signature:
                return False
            continue
        seen_signatures_by_node[signature.node_id] = signature.signature
        unique_signatures.append(signature)
    active_node_ids = sorted(node.node_id for node in registry.active_nodes())
    signer_bitmap = certificate.get("signer_bitmap")
    if not isinstance(signer_bitmap, str):
        return False
    if len(signer_bitmap) != len(active_node_ids) or set(signer_bitmap) - {"0", "1"}:
        return False
    expected_signer_ids = {
        node_id
        for node_id, bitmap_bit in zip(active_node_ids, signer_bitmap, strict=True)
        if bitmap_bit == "1"
    }
    if set(seen_signatures_by_node) != expected_signer_ids:
        return False
    valid_signatures = verify_federated_header_signatures(header, unique_signatures, registry)
    return len(valid_signatures) >= registry.quorum_threshold() and len(valid_signatures) == len(
        unique_signatures
    )


def append_quorum_certificate_to_ledger(
    *,
    ledger: Ledger,
    header: dict[str, Any],
    signatures: list[NodeSignature],
    registry: FederationRegistry,
    canonicalization: dict[str, Any],
) -> LedgerEntry:
    """Append a ledger entry that persistently commits a federation quorum certificate."""
    certificate = build_quorum_certificate(header, signatures, registry)
    return ledger.append(
        record_hash=str(header["header_hash"]),
        shard_id=str(header["shard_id"]),
        shard_root=str(header["root_hash"]),
        canonicalization=canonicalization,
        federation_quorum_certificate=certificate,
    )

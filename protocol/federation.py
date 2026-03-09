"""Federation identity, registry, and quorum-signing prototype."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import nacl.signing

from protocol.ledger import Ledger, LedgerEntry
from protocol.shards import sign_header, verify_header


@dataclass(frozen=True)
class FederationNode:
    """Persistent identity for a federation participant."""

    node_id: str
    pubkey: bytes
    endpoint: str
    operator: str
    jurisdiction: str
    status: str = "active"

    @property
    def active(self) -> bool:
        """Return whether the node participates in quorum calculations."""
        return self.status == "active"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the node to JSON-friendly values."""
        return {
            "node_id": self.node_id,
            "pubkey": self.pubkey.hex(),
            "endpoint": self.endpoint,
            "operator": self.operator,
            "jurisdiction": self.jurisdiction,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FederationNode:
        """Create a node from registry JSON data."""
        pubkey_hex = str(data["pubkey"])
        return cls(
            node_id=str(data["node_id"]),
            pubkey=bytes.fromhex(pubkey_hex),
            endpoint=str(data["endpoint"]),
            operator=str(data["operator"]),
            jurisdiction=str(data["jurisdiction"]),
            status=str(data.get("status", "active")),
        )

    def verify_key(self) -> nacl.signing.VerifyKey:
        """Return the Ed25519 verification key for this node."""
        return nacl.signing.VerifyKey(self.pubkey)


@dataclass(frozen=True)
class FederationRegistry:
    """Static federation registry used by the prototype."""

    nodes: tuple[FederationNode, ...]

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

        return cls(nodes=nodes)

    @classmethod
    def from_file(cls, path: str | Path) -> FederationRegistry:
        """Load a registry from disk."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        """Serialize the registry to JSON-friendly data."""
        return {"nodes": [node.to_dict() for node in self.nodes]}

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
) -> NodeSignature:
    """Sign a shard header on behalf of a federation node."""
    return NodeSignature(node_id=node_id, signature=sign_header(header, signing_key))


def verify_federated_header_signatures(
    header: dict[str, Any],
    signatures: list[NodeSignature],
    registry: FederationRegistry,
) -> list[NodeSignature]:
    """Return the subset of unique, valid node signatures for a shard header."""
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
        if verify_header(header, signature.signature, node.verify_key()):
            valid_signatures.append(signature)
            seen_nodes.add(signature.node_id)

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
    return {
        "shard_id": str(header["shard_id"]),
        "header_hash": str(header["header_hash"]),
        "timestamp": str(header["timestamp"]),
        "quorum_threshold": registry.quorum_threshold(),
        "acknowledgments": [signature.to_dict() for signature in valid_signatures],
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
        "quorum_threshold",
        "acknowledgments",
    }
    if not required_fields.issubset(certificate):
        return False
    if certificate["shard_id"] != header.get("shard_id"):
        return False
    if certificate["header_hash"] != header.get("header_hash"):
        return False
    if certificate["timestamp"] != header.get("timestamp"):
        return False
    if int(certificate["quorum_threshold"]) != registry.quorum_threshold():
        return False

    acknowledgments = certificate.get("acknowledgments")
    if not isinstance(acknowledgments, list):
        return False
    signatures = [
        NodeSignature(node_id=str(item["node_id"]), signature=str(item["signature"]))
        for item in acknowledgments
        if isinstance(item, dict) and "node_id" in item and "signature" in item
    ]
    valid_signatures = verify_federated_header_signatures(header, signatures, registry)
    return len(valid_signatures) >= registry.quorum_threshold() and len(valid_signatures) == len(
        signatures
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

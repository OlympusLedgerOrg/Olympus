"""Federation identity, registry, and quorum-signing prototype."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import nacl.signing

from protocol.hashes import event_id, federation_vote_hash
from protocol.ledger import Ledger, LedgerEntry


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
    """
    Sign a shard header on behalf of a federation node.

    Creates a federation vote signature that binds the signature to:
    - The federation protocol domain
    - The specific node making the vote (node_id)
    - The shard being voted on (shard_id)
    - The specific header commitment (header_hash)
    - The timestamp of the event
    - A unique event identifier derived from (shard_id, header_hash, timestamp)

    This provides cryptographic proof that a specific federation node
    acknowledged a specific shard header at a specific time.

    Args:
        header: Shard header dictionary with shard_id, header_hash, and timestamp
        node_id: Federation node identifier (registry binding)
        signing_key: Ed25519 signing key for the node

    Returns:
        NodeSignature containing the node_id and hex-encoded signature
    """
    shard_id = str(header["shard_id"])
    header_hash = str(header["header_hash"])
    timestamp = str(header["timestamp"])

    # Compute event ID to bind signature to this specific event
    event_id_hex = event_id(shard_id, header_hash, timestamp)

    # Compute the federation vote hash with domain separation
    vote_hash = federation_vote_hash(node_id, shard_id, header_hash, timestamp, event_id_hex)

    # Sign the vote hash
    signed = signing_key.sign(vote_hash)
    return NodeSignature(node_id=node_id, signature=signed.signature.hex())


def verify_federated_header_signatures(
    header: dict[str, Any],
    signatures: list[NodeSignature],
    registry: FederationRegistry,
) -> list[NodeSignature]:
    """
    Return the subset of unique, valid node signatures for a shard header.

    Verifies each signature by:
    1. Checking the node is in the registry and active
    2. Computing the same event_id and vote hash used during signing
    3. Verifying the Ed25519 signature over the vote hash

    Args:
        header: Shard header dictionary with shard_id, header_hash, and timestamp
        signatures: List of NodeSignature objects to verify
        registry: Federation registry for node lookup and key verification

    Returns:
        List of valid, unique NodeSignature objects
    """
    valid_signatures: list[NodeSignature] = []
    seen_nodes: set[str] = set()

    # Extract header fields needed for verification
    shard_id = str(header["shard_id"])
    header_hash = str(header["header_hash"])
    timestamp = str(header["timestamp"])

    # Compute event ID once for all signature verifications
    event_id_hex = event_id(shard_id, header_hash, timestamp)

    for signature in signatures:
        if signature.node_id in seen_nodes:
            continue
        try:
            node = registry.get_node(signature.node_id)
        except ValueError:
            continue
        if not node.active:
            continue

        # Compute the vote hash this node should have signed
        vote_hash = federation_vote_hash(
            signature.node_id, shard_id, header_hash, timestamp, event_id_hex
        )

        # Verify the signature
        try:
            signature_bytes = bytes.fromhex(signature.signature)
            node.verify_key().verify(vote_hash, signature_bytes)
            valid_signatures.append(signature)
            seen_nodes.add(signature.node_id)
        except Exception:  # nosec B112
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
    return {
        "shard_id": str(header["shard_id"]),
        "header_hash": str(header["header_hash"]),
        "timestamp": str(header["timestamp"]),
        "quorum_threshold": registry.quorum_threshold(),
        "acknowledgments": [
            signature.to_dict()
            for signature in sorted(valid_signatures, key=lambda signature: signature.node_id)
        ],
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
    unique_signatures: list[NodeSignature] = []
    seen_signature_tuples: set[tuple[str, str]] = set()
    for signature in signatures:
        signature_key = (signature.node_id, signature.signature)
        if signature_key in seen_signature_tuples:
            continue
        seen_signature_tuples.add(signature_key)
        unique_signatures.append(signature)
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

"""Federation identity, registry, and quorum-signing prototype."""

from __future__ import annotations

import json
import math
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import nacl.exceptions
import nacl.signing

from protocol.canonical_json import canonical_json_bytes
from protocol.hashes import (
    _VRF_COMMIT_REVEAL_PREFIX,
    HASH_SEPARATOR,
    VRF_SELECTION_PREFIX,
    blake3_hash,
    hash_bytes,
    shard_header_hash,
)
from protocol.ledger import Ledger, LedgerEntry


# Public domain-separation tag bound to every federation vote message.
# Prevents signatures created for other protocol contexts (ingest, admin,
# shard-merge, …) from being replayed as federation votes.
FEDERATION_DOMAIN_TAG = "OLY:FEDERATION-VOTE:V1"
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
        """Return the prototype >=2/3 quorum threshold."""
        active_count = len(self.active_nodes())
        if active_count == 0:
            raise ValueError("Federation registry has no active nodes")
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


@dataclass(frozen=True)
class NodeSignature:
    """Prototype federation signature attached to a shard header."""

    node_id: str
    signature: str

    def to_dict(self) -> dict[str, str]:
        """Serialize to JSON-friendly data."""
        return {"node_id": self.node_id, "signature": self.signature}


@dataclass(frozen=True)
class FederationBehaviorSample:
    """Observed federation-signing behavior used for compromise detection."""

    node_id: str
    round_number: int
    header_hash: str


@dataclass(frozen=True)
class FederationVoteMessage:
    """Canonical federation vote message — the only payload federation nodes ever sign.

    Using a single, typed message eliminates serialization drift, replay
    ambiguity, and cross-language mismatches.  Every field is included in the
    canonical JSON serialization so that signers and verifiers always hash
    identical bytes regardless of the implementation language.

    Fields
    ------
    domain:
        Protocol-level domain-separation tag.  Must always equal
        ``FEDERATION_DOMAIN_TAG`` so that a signature produced for any other
        Olympus context (ingest, admin, shard-merge …) cannot be replayed as a
        federation vote.
    node_id:
        Registry identity of the signing node.  The verifier looks up the
        public key from the registry using this ID, so an attacker cannot claim
        another node's identity.
    event_id:
        Deterministic event identifier that binds the vote to a unique
        (shard_id, header_hash, timestamp, epoch, membership_hash) tuple.
    shard_id:
        Identifier of the shard being voted on.
    entry_seq:
        Consensus height (block height) of the shard header.
    round_number:
        Consensus round number of the shard header.
    shard_root:
        Header hash — a cryptographic commitment over all shard header fields.
    timestamp:
        ISO 8601 timestamp of the shard header.
    epoch:
        Federation registry epoch at the time of the vote.
    validator_set_hash:
        Hash commitment of the active validator set (membership hash).
    """

    domain: str
    node_id: str
    event_id: str
    shard_id: str
    entry_seq: int
    round_number: int
    shard_root: str
    timestamp: str
    epoch: int
    validator_set_hash: str


def serialize_vote_message(msg: FederationVoteMessage) -> bytes:
    """Return the canonical JSON bytes that federation nodes sign.

    The payload is a deterministic canonical-JSON encoding of all
    ``FederationVoteMessage`` fields.  Using canonical JSON (sorted keys,
    compact separators, ASCII-escaped) guarantees that every implementation
    language produces identical bytes for the same logical message.

    Args:
        msg: The vote message to serialize.

    Returns:
        UTF-8 canonical JSON bytes ready to be hashed and signed.
    """
    payload: dict[str, Any] = {
        "domain": msg.domain,
        "entry_seq": msg.entry_seq,
        "epoch": msg.epoch,
        "event_id": msg.event_id,
        "node_id": msg.node_id,
        "round_number": msg.round_number,
        "shard_id": msg.shard_id,
        "shard_root": msg.shard_root,
        "timestamp": msg.timestamp,
        "validator_set_hash": msg.validator_set_hash,
    }
    return canonical_json_bytes(payload)


def _build_federation_vote_message(
    header: dict[str, Any], node_id: str, registry: FederationRegistry
) -> FederationVoteMessage:
    """Construct the canonical FederationVoteMessage for a shard header.

    Args:
        header: Shard header dictionary (must include shard_id, header_hash,
            timestamp, height, and round).
        node_id: Registry identity of the node that will sign or is being
            verified.
        registry: Current federation registry supplying epoch and membership.

    Returns:
        Fully-populated FederationVoteMessage with domain set to
        FEDERATION_DOMAIN_TAG.
    """
    event_id_hex = _federation_vote_event_id(header, registry)
    validator_set_hash = registry.membership_hash()
    height, round_number = _extract_round_and_height(header)
    return FederationVoteMessage(
        domain=FEDERATION_DOMAIN_TAG,
        node_id=node_id,
        event_id=event_id_hex,
        shard_id=str(header["shard_id"]),
        entry_seq=height,
        round_number=round_number,
        shard_root=str(header["header_hash"]),
        timestamp=str(header["timestamp"]),
        epoch=registry.epoch,
        validator_set_hash=validator_set_hash,
    )


def sign_federated_header(
    header: dict[str, Any],
    node_id: str,
    signing_key: nacl.signing.SigningKey,
    registry: FederationRegistry,
) -> NodeSignature:
    """Sign a shard header on behalf of a federation node."""
    msg = _build_federation_vote_message(header, node_id, registry)
    vote_hash = hash_bytes(serialize_vote_message(msg))
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
            # Enforce node identity binding: always derive the public key from
            # the registry rather than trusting any caller-supplied key.
            node = registry.get_node(signature.node_id)
        except ValueError:
            continue
        if not node.active:
            continue
        try:
            # Build the canonical vote message and assert domain separation.
            msg = _build_federation_vote_message(header, signature.node_id, registry)
            if msg.domain != FEDERATION_DOMAIN_TAG:
                # Reject messages whose domain tag does not match the federation
                # vote context (guards against cross-context signature replay).
                continue
            vote_hash = hash_bytes(serialize_vote_message(msg))
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
    height, round_number = _extract_round_and_height(header)
    validator_set_hash = registry.membership_hash()
    # Deduplicate in node-id canonical order aligned to the signer bitmap
    signature_by_node = {signature.node_id: signature for signature in valid_signatures}
    active_node_ids = sorted(node.node_id for node in registry.active_nodes())
    signer_bitmap_bits: list[str] = []
    ordered_signatures: list[NodeSignature] = []
    validator_count = len(active_node_ids)
    for node_id in active_node_ids:
        signature = signature_by_node.get(node_id)
        if signature is not None:
            ordered_signatures.append(signature)
            signer_bitmap_bits.append("1")
        else:
            signer_bitmap_bits.append("0")
    signer_bitmap = "".join(signer_bitmap_bits)
    if len(ordered_signatures) < registry.quorum_threshold():
        raise ValueError("Insufficient valid federation signatures for quorum certificate")
    certificate = {
        "shard_id": str(header["shard_id"]),
        "height": height,
        "round": round_number,
        "header_hash": str(header["header_hash"]),
        "timestamp": str(header["timestamp"]),
        "event_id": _federation_vote_event_id(header, registry),
        "federation_epoch": registry.epoch,
        "membership_hash": validator_set_hash,
        "validator_set_hash": validator_set_hash,
        "validator_count": validator_count,
        "quorum_threshold": registry.quorum_threshold(),
        "scheme": _CERTIFICATE_SIGNATURE_SCHEME_ED25519,
        "signer_bitmap": signer_bitmap,
        "signatures": [signature.to_dict() for signature in ordered_signatures],
    }
    certificate_hash = quorum_certificate_hash(certificate)
    header["quorum_certificate_hash"] = certificate_hash
    return certificate


def quorum_certificate_hash(certificate: dict[str, Any]) -> str:
    """Return the deterministic hash commitment for a quorum certificate."""
    canonical_certificate = {
        "event_id": str(certificate.get("event_id", "")),
        "federation_epoch": int(certificate.get("federation_epoch", 0)),
        "height": int(certificate.get("height", 0)),
        "header_hash": str(certificate.get("header_hash", "")),
        "membership_hash": str(certificate.get("membership_hash", "")),
        "validator_set_hash": str(certificate.get("validator_set_hash", "")),
        "validator_count": int(certificate.get("validator_count", 0)),
        "quorum_threshold": int(certificate.get("quorum_threshold", 0)),
        "round": int(certificate.get("round", 0)),
        "scheme": str(certificate.get("scheme", "")),
        "shard_id": str(certificate.get("shard_id", "")),
        "signer_bitmap": str(certificate.get("signer_bitmap", "")),
        "timestamp": str(certificate.get("timestamp", "")),
        "signatures": sorted(
            (
                {"node_id": str(item["node_id"]), "signature": str(item["signature"])}
                for item in certificate.get("signatures", [])
                if isinstance(item, dict) and "node_id" in item and "signature" in item
            ),
            key=lambda item: (item["node_id"], item["signature"]),
        ),
    }
    return hash_bytes(canonical_json_bytes(canonical_certificate)).hex()


def verify_quorum_certificate(
    certificate: dict[str, Any],
    header: dict[str, Any],
    registry: FederationRegistry,
) -> bool:
    """Verify a quorum certificate against a header and registry membership.

    Security properties enforced
    ----------------------------
    * **Structural completeness** – all required certificate fields must be present.
    * **Header binding** – shard_id, header_hash, timestamp, height, and round
      must match the provided header exactly.
    * **Event-ID binding** – event_id is recomputed from the header and registry
      and must match the certificate value (prevents replay across rounds).
    * **Epoch & membership binding** – federation_epoch and membership_hash must
      match the current registry state.
    * **Node identity binding** – for every signature the signing node's public
      key is looked up directly in the registry by node_id; no caller-supplied
      key is trusted.
    * **Domain separation** – the canonical vote message is constructed with
      ``FEDERATION_DOMAIN_TAG`` and the domain is checked before verification,
      preventing cross-context signature reuse.
    * **Uniqueness** – duplicate node_id values are tracked explicitly; only the
      count of *unique* verified signers is compared against the quorum threshold.
    * **Signer-bitmap consistency** – the signatures list must correspond exactly
      to the "1" bits in the signer bitmap.
    """
    required_fields = {
        "shard_id",
        "height",
        "round",
        "header_hash",
        "timestamp",
        "event_id",
        "federation_epoch",
        "membership_hash",
        "validator_set_hash",
        "validator_count",
        "quorum_threshold",
        "scheme",
        "signer_bitmap",
        "signatures",
    }
    if not required_fields.issubset(certificate):
        return False
    try:
        certificate_epoch = int(certificate["federation_epoch"])
    except (TypeError, ValueError):
        return False
    try:
        registry_snapshot = registry.get_snapshot(certificate_epoch)
    except ValueError:
        return False
    header_quorum_hash = header.get("quorum_certificate_hash")
    expected_certificate_hash = quorum_certificate_hash(certificate)
    if header_quorum_hash is None:
        return False
    if str(header_quorum_hash) != expected_certificate_hash:
        return False
    if certificate["shard_id"] != header.get("shard_id"):
        return False
    if certificate["header_hash"] != header.get("header_hash"):
        return False
    if certificate["timestamp"] != header.get("timestamp"):
        return False

    cert_height = _to_int(certificate.get("height"))
    header_height = _to_int(header.get("height"))
    cert_round = _to_int(certificate.get("round"))
    header_round = _to_int(header.get("round"))

    if None in (cert_height, header_height, cert_round, header_round):
        return False

    if cert_height != header_height:
        return False
    if cert_round != header_round:
        return False
    if certificate["event_id"] != _federation_vote_event_id(header, registry_snapshot):
        return False
    if int(certificate["federation_epoch"]) != registry_snapshot.epoch:
        return False
    validator_set_hash = registry_snapshot.membership_hash()
    if str(certificate["membership_hash"]) != validator_set_hash:
        return False
    if str(certificate["validator_set_hash"]) != validator_set_hash:
        return False
    try:
        validator_count = int(certificate["validator_count"])
        quorum_threshold = int(certificate["quorum_threshold"])
    except (TypeError, ValueError):
        return False
    if validator_count != len(registry_snapshot.active_nodes()):
        return False
    expected_threshold = math.ceil((2 * validator_count) / 3)
    if quorum_threshold != expected_threshold:
        return False
    if certificate.get("scheme") != _CERTIFICATE_SIGNATURE_SCHEME_ED25519:
        return False

    serialized_signatures = certificate.get("signatures")
    if not isinstance(serialized_signatures, list):
        return False
    active_node_ids = sorted(node.node_id for node in registry_snapshot.active_nodes())
    signer_bitmap = certificate.get("signer_bitmap")
    if not isinstance(signer_bitmap, str):
        return False
    if len(signer_bitmap) != len(active_node_ids) or set(signer_bitmap) - {"0", "1"}:
        return False
    expected_signer_ids = [
        node_id
        for node_id, bitmap_bit in zip(active_node_ids, signer_bitmap, strict=True)
        if bitmap_bit == "1"
    ]
    if len(serialized_signatures) != len(expected_signer_ids):
        return False

    # Verify each signature individually with explicit registry key lookup and
    # explicit uniqueness tracking, then check quorum against unique signers.
    unique_verified_nodes: set[str] = set()
    for expected_node_id, serialized_signature in zip(
        expected_signer_ids, serialized_signatures, strict=True
    ):
        if not (
            isinstance(serialized_signature, dict)
            and "node_id" in serialized_signature
            and "signature" in serialized_signature
        ):
            return False
        node_id = str(serialized_signature["node_id"])
        # The signer bitmap already establishes the expected order; reject any
        # mismatch to prevent node-id spoofing.
        if node_id != expected_node_id:
            return False
        # Enforce uniqueness: a node_id must appear at most once.
        if node_id in unique_verified_nodes:
            return False

        # Explicit registry key lookup — identity flows from the registry, not
        # from any field inside the certificate.
        try:
            node = registry_snapshot.get_node(node_id)
        except ValueError:
            return False
        if not node.active:
            return False

        # Build the canonical vote message and assert the domain tag.
        msg = _build_federation_vote_message(header, node_id, registry_snapshot)
        if msg.domain != FEDERATION_DOMAIN_TAG:
            return False
        vote_hash = hash_bytes(serialize_vote_message(msg))

        # Verify the signature against the registry-derived key(s).
        try:
            sig_bytes = bytes.fromhex(str(serialized_signature["signature"]))
            verified = False
            for verify_key in node.verify_keys_for_timestamp(str(header["timestamp"])):
                try:
                    verify_key.verify(vote_hash, sig_bytes)
                    verified = True
                    break
                except nacl.exceptions.BadSignatureError:
                    continue
            if not verified:
                return False
        except (ValueError, nacl.exceptions.BadSignatureError):
            return False

        unique_verified_nodes.add(node_id)

    # Quorum is counted against the number of *unique* verified signers.
    return len(unique_verified_nodes) >= registry_snapshot.quorum_threshold()


def resolve_canonical_fork(
    candidates: list[tuple[dict[str, Any], dict[str, Any]]],
    registry: FederationRegistry,
    *,
    current_epoch: int | None = None,
    max_clock_skew_seconds: int = DEFAULT_MAX_CERTIFICATE_CLOCK_SKEW_SECONDS,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Return the deterministic canonical root candidate among competing forks.

    The resolver applies these deterministic rules:
    1. Only candidates with valid quorum certificates are eligible.
    2. Replay protection rejects candidates whose federation epoch is lower than
       ``current_epoch`` (default: ``registry.epoch``).
    3. Prefer the candidate with the highest number of valid signer approvals.
    4. Apply NTP hardening by rejecting certificate timestamps that are outliers
       relative to the median candidate timestamp.
    5. If signer counts tie, choose the lexicographically lowest header hash.
    """
    if not candidates:
        return None
    effective_epoch = registry.epoch if current_epoch is None else int(current_epoch)
    if effective_epoch < 0:
        raise ValueError("Current federation epoch must be an integer >= 0")
    if max_clock_skew_seconds < 0:
        raise ValueError("max_clock_skew_seconds must be >= 0")

    eligible: list[tuple[int, datetime, str, dict[str, Any], dict[str, Any]]] = []
    slot: tuple[str, int, int] | None = None
    for header, certificate in candidates:
        cert_epoch = _to_int(certificate.get("federation_epoch"))
        if cert_epoch is None or is_replay_epoch(cert_epoch, effective_epoch):
            continue
        if not verify_quorum_certificate(certificate, header, registry):
            continue

        candidate_slot = (
            str(certificate["shard_id"]),
            int(certificate["height"]),
            int(certificate["round"]),
        )
        if slot is None:
            slot = candidate_slot
        elif candidate_slot != slot:
            raise ValueError("Fork candidates must reference the same shard_id, height, and round")

        signer_count = len(certificate["signatures"])
        try:
            certificate_timestamp = _parse_timestamp(str(certificate["timestamp"]))
        except ValueError:
            # Malformed timestamp: treat this candidate as ineligible for canonical fork resolution.
            continue
        header_hash = str(header["header_hash"])
        eligible.append((signer_count, certificate_timestamp, header_hash, header, certificate))

    if not eligible:
        return None

    median_timestamp = _median_timestamp([item[1] for item in eligible])
    skew_hardened = [
        item
        for item in eligible
        if abs((item[1] - median_timestamp).total_seconds()) <= max_clock_skew_seconds
    ]
    if not skew_hardened:
        skew_hardened = eligible

    selected_entry = min(skew_hardened, key=lambda item: (-item[0], item[2]))
    selected_header = selected_entry[3]
    selected_certificate = selected_entry[4]
    return selected_header, selected_certificate


def build_proactive_share_commitments(
    registry: FederationRegistry, *, epoch: int, refresh_nonce: str
) -> dict[str, str]:
    """Return deterministic proactive secret-share commitments for active nodes."""
    if epoch < 0:
        raise ValueError("Epoch must be non-negative")
    if not refresh_nonce:
        raise ValueError("refresh_nonce must be non-empty")
    commitments: dict[str, str] = {}
    for node in registry.active_nodes():
        payload = HASH_SEPARATOR.join(
            [
                node.node_id,
                node.pubkey.hex(),
                str(epoch),
                refresh_nonce,
            ]
        ).encode("utf-8")
        commitments[node.node_id] = hash_bytes(payload).hex()
    return commitments


def verify_proactive_share_commitments(
    registry: FederationRegistry,
    *,
    epoch: int,
    refresh_nonce: str,
    commitments: dict[str, str],
) -> bool:
    """Return whether proactive share commitments match deterministic expectations."""
    expected = build_proactive_share_commitments(
        registry,
        epoch=epoch,
        refresh_nonce=refresh_nonce,
    )
    return commitments == expected


def detect_compromise_signals(
    samples: list[FederationBehaviorSample],
    *,
    spike_multiplier: float = 2.0,
) -> dict[str, tuple[str, ...]]:
    """Return per-node behavioral compromise signals from observed vote samples."""
    if spike_multiplier < 1.0:
        raise ValueError("spike_multiplier must be >= 1.0")
    if not samples:
        return {}

    by_node: dict[str, list[FederationBehaviorSample]] = {}
    for sample in samples:
        by_node.setdefault(sample.node_id, []).append(sample)

    median_count = _median_numeric([len(node_samples) for node_samples in by_node.values()])
    results: dict[str, tuple[str, ...]] = {}
    for node_id, node_samples in by_node.items():
        signals: list[str] = []
        seen_round_hashes: dict[int, set[str]] = {}
        for sample in node_samples:
            seen_round_hashes.setdefault(sample.round_number, set()).add(sample.header_hash)
        if any(len(round_hashes) > 1 for round_hashes in seen_round_hashes.values()):
            signals.append("double_vote_detected")
        if median_count > 0 and len(node_samples) > median_count * spike_multiplier:
            signals.append("participation_spike_detected")
        if signals:
            results[node_id] = tuple(sorted(signals))
    return results


def vrf_selection_scores(
    *,
    shard_id: str,
    round_number: int,
    registry: FederationRegistry,
    epoch: int | None = None,
    round_entropy: str | None = None,
) -> list[tuple[str, int]]:
    """Return deterministic VRF-style selection scores for active federation nodes.

    Optional ``round_entropy`` lets callers bind commit-reveal randomness (and any
    associated non-interactive proof transcript hash) into the selection seed to
    mitigate VRF grinding by adaptive participants.
    """
    if round_number < 0:
        raise ValueError("Round number must be non-negative")
    effective_epoch = registry.epoch if epoch is None else int(epoch)
    if effective_epoch < 0:
        raise ValueError("Epoch must be non-negative")
    entropy_bytes = b""
    if round_entropy is not None:
        try:
            entropy_bytes = bytes.fromhex(round_entropy)
        except ValueError as exc:
            raise ValueError("Round entropy must be a valid hex string") from exc
    membership_hash = registry.membership_hash()
    selection_seed = blake3_hash(
        [
            VRF_SELECTION_PREFIX,
            HASH_SEPARATOR.encode("utf-8").join(
                [
                    str(shard_id).encode("utf-8"),
                    str(round_number).encode("utf-8"),
                    str(effective_epoch).encode("utf-8"),
                    membership_hash.encode("utf-8"),
                    entropy_bytes,
                ]
            ),
        ]
    )
    scores: list[tuple[str, int]] = []
    for node in registry.active_nodes():
        score_bytes = blake3_hash([selection_seed, node.node_id.encode("utf-8")])
        score = int.from_bytes(score_bytes[:8], byteorder="big", signed=False)
        scores.append((node.node_id, score))
    return sorted(scores, key=lambda item: (item[1], item[0]))


def select_vrf_committee(
    *,
    shard_id: str,
    round_number: int,
    registry: FederationRegistry,
    committee_size: int,
    epoch: int | None = None,
    round_entropy: str | None = None,
) -> list[str]:
    """Select a deterministic VRF-style committee from active federation nodes."""
    if committee_size <= 0:
        raise ValueError("Committee size must be positive")
    scores = vrf_selection_scores(
        shard_id=shard_id,
        round_number=round_number,
        registry=registry,
        epoch=epoch,
        round_entropy=round_entropy,
    )
    if committee_size > len(scores):
        raise ValueError("Committee size cannot exceed active federation members")
    return [node_id for node_id, _ in scores[:committee_size]]


def select_vrf_leader(
    *,
    shard_id: str,
    round_number: int,
    registry: FederationRegistry,
    epoch: int | None = None,
    round_entropy: str | None = None,
) -> str:
    """Select a deterministic VRF-style leader from active federation nodes."""
    committee = select_vrf_committee(
        shard_id=shard_id,
        round_number=round_number,
        registry=registry,
        committee_size=1,
        epoch=epoch,
        round_entropy=round_entropy,
    )
    return committee[0]


def build_vrf_reveal_commitment(*, node_id: str, reveal: str) -> str:
    """Build a deterministic commit-reveal binding for VRF anti-grinding rounds."""
    payload = HASH_SEPARATOR.encode("utf-8").join([node_id.encode("utf-8"), reveal.encode("utf-8")])
    return blake3_hash([_VRF_COMMIT_REVEAL_PREFIX, payload]).hex()


def derive_vrf_round_entropy(
    *,
    shard_id: str,
    round_number: int,
    epoch: int,
    commitments: dict[str, str],
    reveals: dict[str, str],
    proof_transcript_hashes: dict[str, str] | None = None,
) -> str:
    """Derive round entropy from commit-reveal data and optional ZK proof bindings.

    The optional ``proof_transcript_hashes`` map allows callers to bind each
    participant's non-interactive proof transcript hash into the final entropy.
    """
    if round_number < 0:
        raise ValueError("Round number must be non-negative")
    if epoch < 0:
        raise ValueError("Epoch must be non-negative")
    if not reveals:
        raise ValueError("At least one reveal is required")

    reveal_chunks: list[bytes] = []
    separator = HASH_SEPARATOR.encode("utf-8")
    for node_id, reveal in sorted(reveals.items()):
        commitment = commitments.get(node_id)
        if commitment is None:
            raise ValueError(f"Missing commitment for node_id: {node_id}")
        expected_commitment = build_vrf_reveal_commitment(node_id=node_id, reveal=reveal)
        normalized_commitment = commitment.lower()
        if normalized_commitment != expected_commitment.lower():
            raise ValueError(f"Reveal does not match commitment for node_id: {node_id}")

        proof_hash = ""
        if proof_transcript_hashes is not None:
            proof_hash = str(proof_transcript_hashes.get(node_id, ""))
            if not proof_hash:
                raise ValueError(f"Missing proof transcript hash for node_id: {node_id}")

        reveal_chunks.append(
            separator.join(
                [
                    node_id.encode("utf-8"),
                    reveal.encode("utf-8"),
                    proof_hash.encode("utf-8"),
                ]
            )
        )

    context = separator.join(
        [
            shard_id.encode("utf-8"),
            str(round_number).encode("utf-8"),
            str(epoch).encode("utf-8"),
        ]
    )
    return blake3_hash([_VRF_COMMIT_REVEAL_PREFIX, context, *reveal_chunks]).hex()


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


# =============================================================================
# T1: Steward-Guardian Equivocation Detection (Shadow Ledger Mitigation)
# =============================================================================


@dataclass(frozen=True)
class ShardHeaderForkEvidence:
    """
    Non-repudiable cryptographic proof of Steward-Guardian equivocation.

    When two distinct shard headers H_a and H_b share the same (shard_id, seq)
    but have different header_hash values, this constitutes a "shadow ledger"
    attack. Discovery of such conflicting headers is cryptographic proof of
    fraud that can be publicly verified.

    Attributes:
        shard_id: The shard where equivocation was detected.
        seq: The sequence number where conflicting headers were observed.
        conflicting_header_hashes: Tuple of distinct header hashes for the same seq.
        observer_ids: Tuple of observer identifiers who reported the conflict.
        signatures_a: Signatures collected for header H_a.
        signatures_b: Signatures collected for header H_b.
        detected_at: ISO 8601 timestamp when the fork was detected.
    """

    shard_id: str
    seq: int
    conflicting_header_hashes: tuple[str, ...]
    observer_ids: tuple[str, ...]
    signatures_a: tuple[NodeSignature, ...]
    signatures_b: tuple[NodeSignature, ...]
    detected_at: str

    def __post_init__(self) -> None:
        if not self.shard_id:
            raise ValueError("shard_id must be non-empty")
        if self.seq < 0:
            raise ValueError("seq must be non-negative")
        if len(self.conflicting_header_hashes) < 2:
            raise ValueError("conflicting_header_hashes must include at least two hashes")
        if len(set(self.conflicting_header_hashes)) != len(self.conflicting_header_hashes):
            raise ValueError("conflicting_header_hashes must be unique")
        if len(self.observer_ids) < 1:
            raise ValueError("observer_ids must include at least one observer")
        try:
            _parse_timestamp(self.detected_at)
        except ValueError as exc:
            raise ValueError("detected_at must be a valid ISO 8601 timestamp") from exc

    def to_dict(self) -> dict[str, Any]:
        """Serialize fork evidence to JSON-friendly data."""
        return {
            "shard_id": self.shard_id,
            "seq": self.seq,
            "conflicting_header_hashes": list(self.conflicting_header_hashes),
            "observer_ids": list(self.observer_ids),
            "signatures_a": [sig.to_dict() for sig in self.signatures_a],
            "signatures_b": [sig.to_dict() for sig in self.signatures_b],
            "detected_at": self.detected_at,
        }

    def colluding_guardians(self) -> tuple[str, ...]:
        """Return node_ids that signed both conflicting headers (provable collusion)."""
        signers_a = {sig.node_id for sig in self.signatures_a}
        signers_b = {sig.node_id for sig in self.signatures_b}
        return tuple(sorted(signers_a & signers_b))


@dataclass(frozen=True)
class GossipedShardHeader:
    """A shard header observation received via gossip from a peer."""

    peer_id: str
    shard_id: str
    seq: int
    header_hash: str
    root_hash: str
    timestamp: str
    signatures: tuple[NodeSignature, ...]

    def __post_init__(self) -> None:
        if not self.peer_id:
            raise ValueError("peer_id must be non-empty")
        if not self.shard_id:
            raise ValueError("shard_id must be non-empty")
        if self.seq < 0:
            raise ValueError("seq must be non-negative")
        if not self.header_hash:
            raise ValueError("header_hash must be non-empty")


def detect_shard_header_forks(
    observations: dict[str, GossipedShardHeader],
    *,
    registry: FederationRegistry | None = None,
) -> tuple[ShardHeaderForkEvidence, ...]:
    """
    Detect equivocation by comparing gossiped shard headers from multiple peers.

    This implements the gossip-based fork detection mitigation for the Shadow
    Ledger attack (T1). When monitors and third-party verifiers gossip signed
    headers, discovery of any H_a != H_b where seq(H_a) == seq(H_b) constitutes
    non-repudiable cryptographic proof of fraud.

    Args:
        observations: Mapping of peer_id -> GossipedShardHeader observed
        registry: Optional federation registry for signature validation

    Returns:
        Tuple of ShardHeaderForkEvidence objects describing detected forks.

    Raises:
        ValueError: If invalid observations are provided.
    """
    if not observations:
        return ()

    from protocol.timestamps import current_timestamp as _current_timestamp

    # Group observations by (shard_id, seq)
    grouped: dict[tuple[str, int], list[GossipedShardHeader]] = {}
    for peer_id, header in sorted(observations.items()):
        key = (header.shard_id, header.seq)
        grouped.setdefault(key, []).append(header)

    evidences: list[ShardHeaderForkEvidence] = []
    for (shard_id, seq), headers in sorted(grouped.items()):
        # Check for conflicting header hashes at the same seq
        hash_to_headers: dict[str, list[GossipedShardHeader]] = {}
        for header in headers:
            hash_to_headers.setdefault(header.header_hash, []).append(header)

        if len(hash_to_headers) <= 1:
            # No conflict at this seq
            continue

        # Fork detected: multiple distinct header hashes for the same seq
        sorted_hashes = sorted(hash_to_headers.keys())
        observer_ids: set[str] = set()
        signatures_by_hash: dict[str, list[NodeSignature]] = {}

        for header_hash, hash_headers in hash_to_headers.items():
            signatures_by_hash[header_hash] = []
            for header in hash_headers:
                observer_ids.add(header.peer_id)
                signatures_by_hash[header_hash].extend(header.signatures)

        # Use the first two conflicting hashes for the evidence
        hash_a, hash_b = sorted_hashes[0], sorted_hashes[1]

        evidence = ShardHeaderForkEvidence(
            shard_id=shard_id,
            seq=seq,
            conflicting_header_hashes=tuple(sorted_hashes),
            observer_ids=tuple(sorted(observer_ids)),
            signatures_a=tuple(signatures_by_hash[hash_a]),
            signatures_b=tuple(signatures_by_hash[hash_b]),
            detected_at=_current_timestamp(),
        )
        evidences.append(evidence)

    return tuple(evidences)


def registry_forest_commitment(registry: FederationRegistry) -> str:
    """
    Compute a deterministic commitment of the Guardian registry to the Forest root.

    This implements the Public Guardian Registry mitigation: the set of active
    Guardian keys is committed to the immutable Forest root, ensuring that a
    "Shadow Ledger" would require a quorum from specifically registered keys.

    Args:
        registry: The federation registry to commit

    Returns:
        Hex-encoded BLAKE3 hash commitment of the registry state.
    """
    active_nodes = sorted(registry.active_nodes(), key=lambda n: n.node_id)
    commitment_parts: list[bytes] = [
        f"epoch:{registry.epoch}".encode(),
        f"membership:{registry.membership_hash()}".encode(),
    ]
    for node in active_nodes:
        node_commitment = HASH_SEPARATOR.join(
            [
                node.node_id,
                node.pubkey.hex(),
                node.endpoint,
                node.operator,
                node.jurisdiction,
                node.status,
            ]
        ).encode("utf-8")
        commitment_parts.append(node_commitment)

    return hash_bytes(b"\n".join(commitment_parts)).hex()


# =============================================================================
# T2: State Suppression Mitigation (Missing Shard Attack)
# =============================================================================


@dataclass(frozen=True)
class DataAvailabilityChallenge:
    """
    A challenge requiring proof that shard data is available for replication.

    Guardians must refuse to countersign a Forest header unless they have
    successfully replicated the underlying shard data or a verifiable
    data-availability commitment.

    Attributes:
        shard_id: The shard being challenged for availability.
        header_hash: The header hash whose underlying data must be available.
        challenger_id: Node ID of the Guardian issuing the challenge.
        challenge_nonce: Random nonce to prevent replay of stale proofs.
        issued_at: ISO 8601 timestamp when the challenge was issued.
        response_deadline: ISO 8601 timestamp by which proof must be provided.
    """

    shard_id: str
    header_hash: str
    challenger_id: str
    challenge_nonce: str
    issued_at: str
    response_deadline: str

    def __post_init__(self) -> None:
        if not self.shard_id:
            raise ValueError("shard_id must be non-empty")
        if not self.header_hash:
            raise ValueError("header_hash must be non-empty")
        if not self.challenger_id:
            raise ValueError("challenger_id must be non-empty")
        if not self.challenge_nonce:
            raise ValueError("challenge_nonce must be non-empty")
        try:
            _parse_timestamp(self.issued_at)
            _parse_timestamp(self.response_deadline)
        except ValueError as exc:
            raise ValueError("timestamps must be valid ISO 8601") from exc

    def to_dict(self) -> dict[str, str]:
        """Serialize to JSON-friendly data."""
        return {
            "shard_id": self.shard_id,
            "header_hash": self.header_hash,
            "challenger_id": self.challenger_id,
            "challenge_nonce": self.challenge_nonce,
            "issued_at": self.issued_at,
            "response_deadline": self.response_deadline,
        }

    def challenge_hash(self) -> str:
        """Return deterministic hash of the challenge for binding responses."""
        payload = HASH_SEPARATOR.join(
            [
                self.shard_id,
                self.header_hash,
                self.challenger_id,
                self.challenge_nonce,
                self.issued_at,
            ]
        ).encode("utf-8")
        return hash_bytes(payload).hex()


@dataclass(frozen=True)
class ReplicationProof:
    """
    Proof that a Guardian has replicated and verified shard data.

    This implements the Signed Tail Consistency mitigation: Guardians must
    provide evidence that they have the underlying Merkle inclusion proofs
    and raw data before a header can be promoted to "Federation Final" status.

    Attributes:
        challenge_hash: Hash of the DataAvailabilityChallenge being answered.
        guardian_id: Node ID of the Guardian providing the proof.
        ledger_tail_hash: BLAKE3 hash of the replicated ledger tail entries.
        merkle_root_verified: Whether the Merkle root was independently verified.
        proof_sample_indices: Random indices that were spot-checked for availability.
        proof_sample_hashes: Hashes of the spot-checked data at sample indices.
        replicated_at: ISO 8601 timestamp when replication completed.
        guardian_signature: Ed25519 signature over the proof payload.
    """

    challenge_hash: str
    guardian_id: str
    ledger_tail_hash: str
    merkle_root_verified: bool
    proof_sample_indices: tuple[int, ...]
    proof_sample_hashes: tuple[str, ...]
    replicated_at: str
    guardian_signature: str

    def __post_init__(self) -> None:
        if not self.challenge_hash:
            raise ValueError("challenge_hash must be non-empty")
        if not self.guardian_id:
            raise ValueError("guardian_id must be non-empty")
        if not self.ledger_tail_hash:
            raise ValueError("ledger_tail_hash must be non-empty")
        if len(self.proof_sample_indices) != len(self.proof_sample_hashes):
            raise ValueError("proof_sample_indices and proof_sample_hashes must have same length")
        try:
            _parse_timestamp(self.replicated_at)
        except ValueError as exc:
            raise ValueError("replicated_at must be valid ISO 8601") from exc

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-friendly data."""
        return {
            "challenge_hash": self.challenge_hash,
            "guardian_id": self.guardian_id,
            "ledger_tail_hash": self.ledger_tail_hash,
            "merkle_root_verified": self.merkle_root_verified,
            "proof_sample_indices": list(self.proof_sample_indices),
            "proof_sample_hashes": list(self.proof_sample_hashes),
            "replicated_at": self.replicated_at,
            "guardian_signature": self.guardian_signature,
        }

    def proof_payload_hash(self) -> str:
        """Return the hash of the proof payload (excluding signature)."""
        payload = HASH_SEPARATOR.join(
            [
                self.challenge_hash,
                self.guardian_id,
                self.ledger_tail_hash,
                str(self.merkle_root_verified),
                ",".join(str(i) for i in self.proof_sample_indices),
                ",".join(self.proof_sample_hashes),
                self.replicated_at,
            ]
        ).encode("utf-8")
        return hash_bytes(payload).hex()


@dataclass(frozen=True)
class FederationFinalityStatus:
    """
    Tracks the finality status of a shard header with availability gates.

    A header progresses through these states:
    1. PROPOSED: Header announced by Steward
    2. AVAILABILITY_PENDING: Awaiting replication proofs from Guardians
    3. AVAILABILITY_VERIFIED: Sufficient replication proofs received
    4. QUORUM_PENDING: Awaiting quorum signatures
    5. FEDERATION_FINAL: Full quorum + availability = immutable

    Attributes:
        shard_id: The shard being finalized.
        seq: Sequence number of the header.
        header_hash: Hash of the header being finalized.
        status: Current finality status string.
        availability_proofs: Replication proofs received from Guardians.
        quorum_signatures: Federation signatures received.
        finalized_at: ISO 8601 timestamp when finality was achieved (if final).
    """

    shard_id: str
    seq: int
    header_hash: str
    status: str
    availability_proofs: tuple[ReplicationProof, ...]
    quorum_signatures: tuple[NodeSignature, ...]
    finalized_at: str | None

    # Finality status constants
    STATUS_PROPOSED = "PROPOSED"
    STATUS_AVAILABILITY_PENDING = "AVAILABILITY_PENDING"
    STATUS_AVAILABILITY_VERIFIED = "AVAILABILITY_VERIFIED"
    STATUS_QUORUM_PENDING = "QUORUM_PENDING"
    STATUS_FEDERATION_FINAL = "FEDERATION_FINAL"

    def __post_init__(self) -> None:
        valid_statuses = {
            self.STATUS_PROPOSED,
            self.STATUS_AVAILABILITY_PENDING,
            self.STATUS_AVAILABILITY_VERIFIED,
            self.STATUS_QUORUM_PENDING,
            self.STATUS_FEDERATION_FINAL,
        }
        if self.status not in valid_statuses:
            raise ValueError(f"status must be one of {valid_statuses}")
        if self.seq < 0:
            raise ValueError("seq must be non-negative")
        if self.finalized_at is not None:
            try:
                _parse_timestamp(self.finalized_at)
            except ValueError as exc:
                raise ValueError("finalized_at must be valid ISO 8601") from exc

    def is_final(self) -> bool:
        """Return whether the header has achieved federation finality."""
        return self.status == self.STATUS_FEDERATION_FINAL

    def availability_threshold_met(self, registry: FederationRegistry) -> bool:
        """Return whether sufficient availability proofs have been received."""
        # Require at least 2/3 of Guardians to have verified availability
        verified_guardians = {proof.guardian_id for proof in self.availability_proofs}
        return len(verified_guardians) >= registry.quorum_threshold()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-friendly data."""
        return {
            "shard_id": self.shard_id,
            "seq": self.seq,
            "header_hash": self.header_hash,
            "status": self.status,
            "availability_proofs": [p.to_dict() for p in self.availability_proofs],
            "quorum_signatures": [s.to_dict() for s in self.quorum_signatures],
            "finalized_at": self.finalized_at,
        }


def verify_data_availability(
    challenge: DataAvailabilityChallenge,
    proof: ReplicationProof,
    registry: FederationRegistry,
) -> bool:
    """
    Verify a replication proof against a data availability challenge.

    This verifies that:
    1. The proof answers the correct challenge
    2. The Guardian is registered in the federation
    3. The signature is valid for the proof payload
    4. The Merkle root was verified

    Args:
        challenge: The availability challenge being answered
        proof: The replication proof to verify
        registry: Federation registry for key lookup

    Returns:
        True if the proof is valid, False otherwise
    """
    # Verify challenge binding
    if proof.challenge_hash != challenge.challenge_hash():
        return False

    # Verify Guardian is registered
    try:
        node = registry.get_node(proof.guardian_id)
    except ValueError:
        return False
    if not node.active:
        return False

    # Verify Merkle root was checked
    if not proof.merkle_root_verified:
        return False

    # Verify signature over proof payload
    try:
        payload_hash = bytes.fromhex(proof.proof_payload_hash())
        signature_bytes = bytes.fromhex(proof.guardian_signature)
        verify_key = node.verify_key()
        verify_key.verify(payload_hash, signature_bytes)
    except (ValueError, nacl.exceptions.BadSignatureError):
        return False

    return True


def create_replication_proof(
    challenge: DataAvailabilityChallenge,
    guardian_id: str,
    signing_key: nacl.signing.SigningKey,
    ledger_tail_hash: str,
    proof_sample_indices: tuple[int, ...],
    proof_sample_hashes: tuple[str, ...],
    replicated_at: str,
) -> ReplicationProof:
    """
    Create a signed replication proof for a data availability challenge.

    Args:
        challenge: The availability challenge being answered
        guardian_id: Node ID of the Guardian creating the proof
        signing_key: Ed25519 signing key for the Guardian
        ledger_tail_hash: Hash of the replicated ledger tail
        proof_sample_indices: Indices of spot-checked data
        proof_sample_hashes: Hashes of spot-checked data
        replicated_at: Timestamp when replication completed

    Returns:
        Signed ReplicationProof
    """
    # Create unsigned proof to compute payload hash
    unsigned_proof = ReplicationProof(
        challenge_hash=challenge.challenge_hash(),
        guardian_id=guardian_id,
        ledger_tail_hash=ledger_tail_hash,
        merkle_root_verified=True,
        proof_sample_indices=proof_sample_indices,
        proof_sample_hashes=proof_sample_hashes,
        replicated_at=replicated_at,
        guardian_signature="",  # Placeholder
    )

    # Sign the proof payload
    payload_hash = bytes.fromhex(unsigned_proof.proof_payload_hash())
    signed = signing_key.sign(payload_hash)
    signature_hex = signed.signature.hex()

    return ReplicationProof(
        challenge_hash=challenge.challenge_hash(),
        guardian_id=guardian_id,
        ledger_tail_hash=ledger_tail_hash,
        merkle_root_verified=True,
        proof_sample_indices=proof_sample_indices,
        proof_sample_hashes=proof_sample_hashes,
        replicated_at=replicated_at,
        guardian_signature=signature_hex,
    )


# =============================================================================
# T3: Long-Range Key Compromise Mitigation (Recursive SNARK Chain Proofs)
# =============================================================================


@dataclass(frozen=True)
class RecursiveChainProof:
    """
    Recursive SNARK proof of correct hash chain transition.

    Using the existing Circom/snarkjs stack, this wraps the hash chain in a
    ZK-proof of correct transition. Even with leaked keys, an adversary cannot
    easily forge the computational history of the ledger without breaking the
    underlying circuit logic.

    The proof attests that:
    1. The chain from previous_root to current_root follows valid transitions
    2. All intermediate hashes are correctly computed
    3. The epoch transitions respect key rotation schedules

    Attributes:
        proof_type: The ZK proof system used (e.g., "groth16", "plonk")
        previous_root: The starting state root being proved from
        current_root: The ending state root being proved to
        epoch_start: Starting epoch of the proven transition
        epoch_end: Ending epoch of the proven transition
        transition_count: Number of state transitions covered by the proof
        proof_data: The serialized SNARK proof (hex-encoded)
        public_inputs: Public inputs to the circuit verification
        verification_key_hash: Hash of the verification key for this proof type
        created_at: ISO 8601 timestamp when the proof was generated
    """

    proof_type: str
    previous_root: str
    current_root: str
    epoch_start: int
    epoch_end: int
    transition_count: int
    proof_data: str
    public_inputs: tuple[str, ...]
    verification_key_hash: str
    created_at: str

    # Supported proof types
    PROOF_TYPE_GROTH16 = "groth16"
    PROOF_TYPE_PLONK = "plonk"

    def __post_init__(self) -> None:
        valid_proof_types = {self.PROOF_TYPE_GROTH16, self.PROOF_TYPE_PLONK}
        if self.proof_type not in valid_proof_types:
            raise ValueError(f"proof_type must be one of {valid_proof_types}")
        if not self.previous_root:
            raise ValueError("previous_root must be non-empty")
        if not self.current_root:
            raise ValueError("current_root must be non-empty")
        if self.epoch_start < 0:
            raise ValueError("epoch_start must be non-negative")
        if self.epoch_end < self.epoch_start:
            raise ValueError("epoch_end must be >= epoch_start")
        if self.transition_count < 0:
            raise ValueError("transition_count must be non-negative")
        if not self.proof_data:
            raise ValueError("proof_data must be non-empty")
        if not self.verification_key_hash:
            raise ValueError("verification_key_hash must be non-empty")
        try:
            _parse_timestamp(self.created_at)
        except ValueError as exc:
            raise ValueError("created_at must be valid ISO 8601") from exc

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-friendly data."""
        return {
            "proof_type": self.proof_type,
            "previous_root": self.previous_root,
            "current_root": self.current_root,
            "epoch_start": self.epoch_start,
            "epoch_end": self.epoch_end,
            "transition_count": self.transition_count,
            "proof_data": self.proof_data,
            "public_inputs": list(self.public_inputs),
            "verification_key_hash": self.verification_key_hash,
            "created_at": self.created_at,
        }

    def proof_commitment_hash(self) -> str:
        """Return a deterministic hash commitment for this proof."""
        payload = HASH_SEPARATOR.join(
            [
                self.proof_type,
                self.previous_root,
                self.current_root,
                str(self.epoch_start),
                str(self.epoch_end),
                str(self.transition_count),
                self.verification_key_hash,
            ]
        ).encode("utf-8")
        return hash_bytes(payload).hex()


@dataclass(frozen=True)
class EpochKeyRotationRecord:
    """
    Record of a key rotation event for epoch-based key compromise mitigation.

    Guardian keys are rotated based on time-bound epochs. This record captures
    the rotation event for audit and verification purposes.

    Attributes:
        node_id: The Guardian node whose key was rotated
        epoch: The epoch in which the rotation occurred
        old_pubkey_hash: Hash of the previous public key
        new_pubkey_hash: Hash of the new public key
        rotated_at: ISO 8601 timestamp of the rotation
        rotation_signature: Signature over the rotation by the old key
        witness_signatures: Signatures from witnesses who observed the rotation
    """

    node_id: str
    epoch: int
    old_pubkey_hash: str
    new_pubkey_hash: str
    rotated_at: str
    rotation_signature: str
    witness_signatures: tuple[NodeSignature, ...]

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id must be non-empty")
        if self.epoch < 0:
            raise ValueError("epoch must be non-negative")
        if not self.old_pubkey_hash:
            raise ValueError("old_pubkey_hash must be non-empty")
        if not self.new_pubkey_hash:
            raise ValueError("new_pubkey_hash must be non-empty")
        if self.old_pubkey_hash == self.new_pubkey_hash:
            raise ValueError("new_pubkey_hash must differ from old_pubkey_hash")
        try:
            _parse_timestamp(self.rotated_at)
        except ValueError as exc:
            raise ValueError("rotated_at must be valid ISO 8601") from exc

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-friendly data."""
        return {
            "node_id": self.node_id,
            "epoch": self.epoch,
            "old_pubkey_hash": self.old_pubkey_hash,
            "new_pubkey_hash": self.new_pubkey_hash,
            "rotated_at": self.rotated_at,
            "rotation_signature": self.rotation_signature,
            "witness_signatures": [s.to_dict() for s in self.witness_signatures],
        }


def verify_recursive_chain_proof(
    proof: RecursiveChainProof,
    verification_key: dict[str, Any],
    expected_vk_hash: str,
) -> bool:
    """
    Verify a recursive SNARK chain proof.

    This is a placeholder for integration with the existing Circom/snarkjs
    verification infrastructure. Full implementation requires binding to the
    proof_interface module.

    Args:
        proof: The recursive chain proof to verify
        verification_key: The SNARK verification key
        expected_vk_hash: Expected hash of the verification key

    Returns:
        True if the proof is valid, False otherwise
    """
    # Verify the verification key hash matches
    vk_bytes = canonical_json_bytes(verification_key)
    actual_vk_hash = hash_bytes(vk_bytes).hex()
    if actual_vk_hash != expected_vk_hash:
        return False

    if proof.verification_key_hash != expected_vk_hash:
        return False

    # Verify public inputs match the proof claims
    expected_inputs = [
        proof.previous_root,
        proof.current_root,
        str(proof.epoch_start),
        str(proof.epoch_end),
    ]
    if list(proof.public_inputs[:4]) != expected_inputs:
        return False

    # NOTE: Actual SNARK verification would be performed here via
    # protocol.proof_interface or protocol.groth16_backend
    # For now, this validates structural integrity only
    return True


def verify_epoch_key_rotation(
    record: EpochKeyRotationRecord,
    old_verify_key: nacl.signing.VerifyKey,
    registry: FederationRegistry,
    *,
    min_witnesses: int = 1,
) -> bool:
    """
    Verify an epoch key rotation record.

    This verifies that:
    1. The rotation was signed by the old key
    2. Sufficient witnesses observed the rotation
    3. The new key hash is different from the old

    Args:
        record: The key rotation record to verify
        old_verify_key: The previous verification key
        registry: Federation registry for witness verification
        min_witnesses: Minimum number of witness signatures required

    Returns:
        True if the rotation is valid, False otherwise
    """
    # Verify the rotation signature by the old key
    rotation_payload = HASH_SEPARATOR.join(
        [
            record.node_id,
            str(record.epoch),
            record.old_pubkey_hash,
            record.new_pubkey_hash,
            record.rotated_at,
        ]
    ).encode("utf-8")
    rotation_hash = hash_bytes(rotation_payload)

    try:
        signature_bytes = bytes.fromhex(record.rotation_signature)
        old_verify_key.verify(rotation_hash, signature_bytes)
    except (ValueError, nacl.exceptions.BadSignatureError):
        return False

    # Verify witness signatures meet threshold
    if len(record.witness_signatures) < min_witnesses:
        return False

    verified_witnesses: set[str] = set()
    for witness_sig in record.witness_signatures:
        try:
            witness_node = registry.get_node(witness_sig.node_id)
        except ValueError:
            continue
        if not witness_node.active:
            continue
        try:
            witness_sig_bytes = bytes.fromhex(witness_sig.signature)
            witness_node.verify_key().verify(rotation_hash, witness_sig_bytes)
            verified_witnesses.add(witness_sig.node_id)
        except (ValueError, nacl.exceptions.BadSignatureError):
            continue

    return len(verified_witnesses) >= min_witnesses

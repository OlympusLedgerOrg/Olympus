"""Federation quorum signing, verification, and certificate construction."""

from __future__ import annotations

import asyncio
import logging
import math
from dataclasses import dataclass
from typing import Any

import httpx
import nacl.exceptions
import nacl.signing

from protocol.canonical_json import canonical_json_bytes
from protocol.hashes import HASH_SEPARATOR, hash_bytes, shard_header_hash

from .identity import (
    _CERTIFICATE_SIGNATURE_SCHEME_ED25519,
    _HEADER_EXCLUDED_FIELDS,
    FEDERATION_DOMAIN_TAG,
    FederationRegistry,
    _extract_round_and_height,
    _to_int,
)


logger = logging.getLogger(__name__)


class QuorumNotReached(Exception):
    """Raised when the required quorum threshold is not reached."""

    def __init__(self, message: str, collected_signatures: int, required_threshold: int):
        super().__init__(message)
        self.collected_signatures = collected_signatures
        self.required_threshold = required_threshold


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


async def collect_quorum_signatures(
    *,
    header: dict[str, Any],
    local_signature: str,
    local_node_id: str,
    registry: FederationRegistry,
    threshold: int,
    timeout_seconds: float = 5.0,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Collect quorum signatures from Guardian nodes for a shard header.

    This function broadcasts the header to all active Guardian nodes in the
    registry, collects their signatures, and returns a quorum certificate
    once the threshold is reached.

    Args:
        header: The shard header to sign (must include header_hash).
        local_signature: Hex-encoded signature from the local node.
        local_node_id: Node ID of the local node.
        registry: Federation registry with active Guardian nodes.
        threshold: Minimum number of valid signatures required.
        timeout_seconds: Maximum time to wait for all nodes to respond.
        http_client: Optional async HTTP client (creates one if not provided).

    Returns:
        A quorum certificate dictionary containing all collected signatures.

    Raises:
        QuorumNotReached: If insufficient signatures are collected before timeout.
        ValueError: If the header is missing required fields.
    """
    if "header_hash" not in header:
        raise ValueError("Header must include header_hash for quorum signing")

    # Build the vote message for broadcasting
    vote_msg = _build_federation_vote_message(header, local_node_id, registry)

    # Serialize the vote message for transmission
    vote_payload = {
        "domain": vote_msg.domain,
        "node_id": vote_msg.node_id,
        "event_id": vote_msg.event_id,
        "shard_id": vote_msg.shard_id,
        "entry_seq": vote_msg.entry_seq,
        "round_number": vote_msg.round_number,
        "shard_root": vote_msg.shard_root,
        "timestamp": vote_msg.timestamp,
        "epoch": vote_msg.epoch,
        "validator_set_hash": vote_msg.validator_set_hash,
        "header": header,  # Include full header for fork detection
    }

    # Start with the local signature
    collected_signatures: list[NodeSignature] = [
        NodeSignature(node_id=local_node_id, signature=local_signature)
    ]

    # Get all active nodes except the local node
    remote_nodes = [
        node for node in registry.active_nodes() if node.node_id != local_node_id
    ]

    if len(remote_nodes) == 0:
        # Single-node deployment - check if local signature is sufficient
        if len(collected_signatures) >= threshold:
            return build_quorum_certificate(header, collected_signatures, registry)
        raise QuorumNotReached(
            "No remote Guardian nodes available and local signature alone is insufficient",
            collected_signatures=len(collected_signatures),
            required_threshold=threshold,
        )

    # Create HTTP client if not provided
    should_close_client = http_client is None
    if http_client is None:
        http_client = httpx.AsyncClient(timeout=timeout_seconds)

    try:
        # Request signatures from all remote nodes concurrently
        async def request_signature(node) -> NodeSignature | None:
            """Request a signature from a single Guardian node."""
            try:
                endpoint = f"{node.endpoint.rstrip('/')}/v1/federation/sign-header"
                response = await http_client.post(
                    endpoint,
                    json=vote_payload,
                    timeout=timeout_seconds,
                )

                if response.status_code == 200:
                    data = response.json()
                    node_sig = NodeSignature(
                        node_id=data.get("node_id", node.node_id),
                        signature=data.get("signature", ""),
                    )

                    # Verify the signature against the registry
                    valid_sigs = verify_federated_header_signatures(
                        header, [node_sig], registry
                    )
                    if valid_sigs:
                        return valid_sigs[0]

                    logger.warning(
                        "Invalid signature from Guardian node %s",
                        node.node_id,
                    )
                    return None

                elif response.status_code == 409:
                    # Fork detected - log but don't fail the overall collection
                    logger.error(
                        "Fork detected by Guardian node %s: %s",
                        node.node_id,
                        response.json().get("detail", "Unknown fork"),
                    )
                    return None

                else:
                    logger.warning(
                        "Guardian node %s returned HTTP %d",
                        node.node_id,
                        response.status_code,
                    )
                    return None

            except httpx.TimeoutException:
                logger.warning(
                    "Guardian node %s timed out after %.1fs",
                    node.node_id,
                    timeout_seconds,
                )
                return None
            except httpx.RequestError as exc:
                logger.warning(
                    "Guardian node %s request failed: %s",
                    node.node_id,
                    exc,
                )
                return None
            except Exception:
                # Catch-all for unexpected errors (JSON decoding, response parsing, etc.)
                # We log the full exception and return None to allow other nodes to
                # continue - a single node's failure should not prevent quorum if
                # enough other nodes respond successfully.
                logger.exception(
                    "Unexpected error requesting signature from Guardian node %s",
                    node.node_id,
                )
                return None

        # Gather all signature requests with a global timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    *[request_signature(node) for node in remote_nodes],
                    return_exceptions=True,
                ),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            results = []

        # Collect valid signatures
        for result in results:
            if isinstance(result, NodeSignature):
                collected_signatures.append(result)

        # Check if we have enough signatures
        if len(collected_signatures) >= threshold:
            return build_quorum_certificate(header, collected_signatures, registry)

        raise QuorumNotReached(
            f"Only collected {len(collected_signatures)} signatures, "
            f"need {threshold} for quorum",
            collected_signatures=len(collected_signatures),
            required_threshold=threshold,
        )

    finally:
        if should_close_client:
            await http_client.aclose()


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

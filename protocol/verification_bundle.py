"""
Verification bundle generator for Olympus.

Assembles a self-contained JSON bundle that allows offline verification of
a record's inclusion in the Olympus ledger.  The bundle contains:

  - canonicalization provenance
  - shard header
  - Ed25519 signature
  - RFC 3161 timestamp token (when available)
  - SMT inclusion proof

Usage::

    bundle = create_verification_bundle(
        storage, shard_id="us-gov-foia",
        record_type="document", record_id="doc-1", version=1,
    )

See ``schemas/verification_bundle.json`` for the normative schema.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .consistency import ConsistencyProof
from .epochs import SignedTreeHead


if TYPE_CHECKING:
    from storage.postgres import StorageLayer

BUNDLE_VERSION = "1.0.0"


def create_verification_bundle(
    storage: StorageLayer,
    *,
    shard_id: str,
    record_type: str,
    record_id: str,
    version: int,
    signed_tree_head: SignedTreeHead | dict[str, Any] | None = None,
    previous_sth: SignedTreeHead | dict[str, Any] | None = None,
    consistency_proof: ConsistencyProof | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Assemble a complete verification bundle for a record.

    The bundle is a self-contained JSON-serializable dict that a third party
    can use to verify the record's inclusion offline, without access to the
    Olympus database.

    Args:
        storage: Initialised :class:`StorageLayer` instance.
        shard_id: Shard identifier containing the record.
        record_type: Record type (e.g. ``"document"``).
        record_id: Unique record identifier.
        version: Record version (≥ 1).
        signed_tree_head: Optional Signed Tree Head for the shard root. When
            supplied, verifiers can bind the inclusion proof to an operator-
            signed epoch commitment.
        previous_sth: Optional previous Signed Tree Head. When supplied with
            ``consistency_proof``, allows verifiers to check append-only growth.
        consistency_proof: Optional Merkle consistency proof linking
            ``previous_sth`` to ``signed_tree_head``. Must be supplied with
            ``previous_sth``.

    Returns:
        Dictionary conforming to ``schemas/verification_bundle.json``.

    Raises:
        ValueError: If the record does not exist or the shard has no header.
    """
    # 1. Inclusion proof
    proof = storage.get_proof(shard_id, record_type, record_id, version)
    if proof is None:
        raise ValueError(
            f"Record not found: {record_type}:{record_id}:{version} in shard '{shard_id}'"
        )

    # 2. Latest shard header (includes signature verification)
    header_info = storage.get_latest_header(shard_id)
    if header_info is None:
        raise ValueError(f"No shard header found for shard '{shard_id}'")

    header = header_info["header"]
    signature = header_info["signature"]
    pubkey = header_info["pubkey"]

    # 3. Canonicalization provenance from the latest ledger entry
    tail = storage.get_ledger_tail(shard_id, n=1)
    canonicalization: dict[str, Any] = {}
    if tail:
        canonicalization = tail[0].canonicalization

    # 4. Timestamp token (optional)
    timestamp_token: dict[str, Any] | None = None
    header_hash_hex = header["header_hash"]
    token = storage.get_timestamp_token(shard_id, header_hash_hex)
    if token is not None:
        timestamp_token = token

    # 5. Assemble bundle
    bundle: dict[str, Any] = {
        "bundle_version": BUNDLE_VERSION,
        "canonicalization": canonicalization,
        "shard_header": header,
        "signature": signature,
        "pubkey": pubkey,
    }

    if timestamp_token is not None:
        bundle["timestamp_token"] = timestamp_token

    if signed_tree_head is not None:
        bundle["signed_tree_head"] = (
            signed_tree_head.to_dict()
            if isinstance(signed_tree_head, SignedTreeHead)
            else dict(signed_tree_head)
        )

    if previous_sth is not None:
        bundle["previous_sth"] = (
            previous_sth.to_dict() if isinstance(previous_sth, SignedTreeHead) else dict(previous_sth)
        )

    if consistency_proof is not None:
        bundle["consistency_proof"] = (
            consistency_proof.to_dict()
            if isinstance(consistency_proof, ConsistencyProof)
            else dict(consistency_proof)
        )

    # Include SMT proof as smt_proof (key/value based)
    bundle["smt_proof"] = proof.to_dict()

    return bundle

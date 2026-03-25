#!/usr/bin/env python3
"""One-command offline verifier for Olympus verification bundles.

Usage::

    python tools/verify_bundle_cli.py bundle.json

The bundle is a self-contained JSON file that includes a shard header,
Ed25519 signature, optional RFC 3161 timestamp token, and optional
Merkle inclusion proofs.  The verifier checks every component without
network access.

Exit codes:
    0  All checks passed.
    1  One or more checks failed or the bundle is malformed.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any


# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import nacl.signing

from protocol.consistency import ConsistencyProof
from protocol.epochs import EpochRecord, SignedTreeHead, compute_epoch_head, verify_sth_consistency
from protocol.events import CanonicalEvent
from protocol.hashes import shard_header_hash
from protocol.merkle import MerkleProof, MerkleTree, merkle_leaf_hash, verify_proof
from protocol.rfc3161 import TRUST_MODE_DEV, TRUST_MODE_PROD, verify_timestamp_token
from protocol.shards import verify_header


BUNDLE_SCHEMA_VERSION = "1.0.0"
BUNDLE_CLI_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Core verification logic
# ---------------------------------------------------------------------------


def _check_header_hash(header: dict[str, Any]) -> tuple[bool, str]:
    """Recompute the header hash and compare to the claimed value.

    Returns:
        ``(passed, message)``
    """
    required_fields = {
        "shard_id",
        "root_hash",
        "timestamp",
        "height",
        "round",
        "previous_header_hash",
    }
    if not required_fields.issubset(header):
        missing = required_fields - set(header)
        return False, f"Header validation failed: missing required fields {sorted(missing)}"

    # Use the full header (minus header_hash) to mirror protocol.shards.create_shard_header
    # canonicalization; sorting keys keeps the hash reproducible across Python versions and runtimes.
    fields = {k: header[k] for k in sorted(header) if k != "header_hash"}
    expected = shard_header_hash(fields).hex()
    claimed = header["header_hash"]
    if expected == claimed:
        return True, f"Header hash matches: {claimed}"
    return False, f"Header hash MISMATCH: expected {expected}, got {claimed}"


def _check_signature(
    header: dict[str, Any], signature_hex: str, pubkey_hex: str
) -> tuple[bool, str]:
    """Verify the Ed25519 signature over the header hash.

    Returns:
        ``(passed, message)``
    """
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(pubkey_hex))
    except Exception as exc:
        return False, f"Invalid public key: {exc}"

    if not verify_header(header, signature_hex, verify_key):
        return False, "Ed25519 signature INVALID"
    return True, "Ed25519 signature valid"


def _check_timestamp_token(
    header_hash_hex: str,
    token: dict[str, str],
    *,
    trust_mode: str,
    trusted_fingerprints: set[str] | None,
    trust_store_path: str | None,
) -> tuple[bool, str]:
    """Verify the RFC 3161 timestamp token imprint matches the header hash.

    The Olympus imprint scheme is::

        imprint = SHA-256(bytes.fromhex(blake3_header_hash_hex))

    This function checks that the token's ``hash_hex`` matches the header
    hash (i.e. the token was issued for the correct header) and optionally
    verifies the TST if ``rfc3161ng`` is available.

    Returns:
        ``(passed, message)``
    """
    if "tsa_cert_fingerprint" not in token:
        return False, "Timestamp token missing tsa_cert_fingerprint"

    # 1. Verify that the token was issued for the correct header hash
    if token["hash_hex"] != header_hash_hex:
        return False, (
            f"Timestamp token hash_hex mismatch: "
            f"expected {header_hash_hex}, got {token['hash_hex']}"
        )

    # 2. Validate that header_hash_hex is well-formed hex before proceeding.
    try:
        bytes.fromhex(header_hash_hex)
    except ValueError as exc:
        return False, f"Invalid header hash hex: {exc}"

    try:
        tst_bytes = bytes.fromhex(token["tst_hex"])
        result = verify_timestamp_token(
            tst_bytes,
            header_hash_hex,
            trust_mode=trust_mode,
            trusted_fingerprints=trusted_fingerprints,
            trust_store_path=trust_store_path,
        )
        if result:
            return True, "RFC 3161 timestamp token valid (imprint verified)"
        return False, "RFC 3161 timestamp token INVALID"
    except Exception as exc:
        return False, f"RFC 3161 verification error: {exc}"


def _check_merkle_proofs(
    root_hash_hex: str, proofs: list[dict[str, Any]]
) -> list[tuple[bool, str]]:
    """Verify each Merkle inclusion proof against the shard root.

    Returns:
        List of ``(passed, message)`` for each proof.
    """
    results: list[tuple[bool, str]] = []
    for i, pdata in enumerate(proofs):
        try:
            sibling_entries = []
            for h, position in pdata["siblings"]:
                if position not in ("left", "right"):
                    raise ValueError("Sibling position must be 'left' or 'right'")
                sibling_entries.append((bytes.fromhex(h), position))

            proof = MerkleProof(
                leaf_hash=bytes.fromhex(pdata["leaf_hash"]),
                leaf_index=pdata["leaf_index"],
                siblings=sibling_entries,
                root_hash=bytes.fromhex(pdata["root_hash"]),
            )
        except (KeyError, ValueError) as exc:
            results.append((False, f"Merkle proof [{i}]: malformed – {exc}"))
            continue

        # Proof root must match shard header root
        if pdata["root_hash"] != root_hash_hex:
            results.append(
                (
                    False,
                    f"Merkle proof [{i}]: root mismatch – "
                    f"proof root {pdata['root_hash']} != header root {root_hash_hex}",
                )
            )
            continue
        try:
            if verify_proof(proof):
                results.append((True, f"Merkle proof [{i}]: valid (leaf {pdata['leaf_index']})"))
            else:
                results.append((False, f"Merkle proof [{i}]: INVALID"))
        except ValueError as exc:
            results.append((False, f"Merkle proof [{i}]: INVALID ({exc})"))

    return results


def _check_bundle_version(bundle_version: str) -> tuple[bool, str]:
    """Ensure the bundle schema version is supported."""
    if bundle_version == BUNDLE_SCHEMA_VERSION:
        return True, f"Bundle schema version supported: {bundle_version}"
    return False, f"Bundle schema version unsupported: {bundle_version}"


def _check_canonicalization_provenance(
    canonicalization: dict[str, Any],
) -> tuple[bool, str]:
    """Verify canonicalization provenance fields are present."""
    required = {"format", "normalization_mode", "canonicalizer_versions", "fallback_reason"}
    missing = required - set(canonicalization.keys())
    if missing:
        return False, f"Canonicalization provenance missing fields: {sorted(missing)}"
    if not isinstance(canonicalization.get("canonicalizer_versions"), dict):
        return False, "Canonicalization provenance canonicalizer_versions must be a dict"
    return True, (
        "Canonicalization provenance present "
        f"(format={canonicalization.get('format')}, "
        f"mode={canonicalization.get('normalization_mode')})"
    )


def _check_schema_version(schema_version: str) -> tuple[bool, str]:
    """Ensure the bundle schema version is present and matches expectations."""
    if not schema_version:
        return False, "Schema version missing"
    if schema_version == BUNDLE_SCHEMA_VERSION:
        return True, f"Schema version supported: {schema_version}"
    return False, f"Schema version unsupported: {schema_version}"


def _check_root_consistency(header_root_hex: str, bundle_root_hex: str) -> tuple[bool, str]:
    """Ensure Merkle root in bundle matches the shard header root."""
    if header_root_hex.lower() == bundle_root_hex.lower():
        return True, f"Merkle root matches shard header: {header_root_hex}"
    return False, (
        f"Merkle root mismatch: header root {header_root_hex} != bundle root {bundle_root_hex}"
    )


def _canonical_event_bytes(schema_version: str, event_data: Any) -> CanonicalEvent:
    """Canonicalize event payload to bytes and hash."""
    if not isinstance(event_data, dict):
        raise ValueError("canonical_events entries must be objects")
    return CanonicalEvent.from_raw(event_data, schema_version)


def _check_canonical_events(
    schema_version: str,
    canonical_events: list[dict[str, Any]],
    leaf_hashes: list[str],
    claimed_root_hex: str,
) -> list[tuple[bool, str]]:
    """Validate canonical events, leaf hashes, and Merkle root determinism."""
    results: list[tuple[bool, str]] = []
    if not isinstance(claimed_root_hex, str):
        return [(False, "Merkle root must be a hex string")]
    claimed_root_hex = claimed_root_hex.lower()
    if len(claimed_root_hex) != 64:
        return [(False, f"Merkle root must be 64 hex chars, got {len(claimed_root_hex)}")]
    try:
        events = [_canonical_event_bytes(schema_version, evt) for evt in canonical_events]
    except Exception as exc:
        return [(False, f"Canonical events invalid: {exc}")]

    if len(events) != len(leaf_hashes):
        return [
            (
                False,
                f"Leaf hash count mismatch: {len(leaf_hashes)} provided "
                f"for {len(events)} canonical events",
            )
        ]

    computed_leaf_hashes = [merkle_leaf_hash(evt.canonical_bytes).hex() for evt in events]
    try:
        provided_hashes = [h.lower() for h in leaf_hashes]
    except Exception as exc:
        return [(False, f"Leaf hashes invalid: {exc}")]
    leaves_match = computed_leaf_hashes == provided_hashes
    results.append(
        (
            leaves_match,
            "Leaf hashes match canonical events"
            if leaves_match
            else "Leaf hashes do not match canonical events",
        )
    )

    tree_root = MerkleTree([evt.canonical_bytes for evt in events]).get_root().hex()
    root_match = tree_root == claimed_root_hex.lower()
    results.append(
        (
            root_match,
            f"Merkle root deterministic: {tree_root}"
            if root_match
            else f"Merkle root mismatch: computed {tree_root}, claimed {claimed_root_hex}",
        )
    )
    return results


def _check_epoch_record(epoch_record: dict[str, Any], root_hash_hex: str) -> tuple[bool, str]:
    """Validate epoch record linkage."""
    try:
        record = EpochRecord.from_dict(epoch_record)
    except Exception as exc:
        return False, f"Epoch record malformed: {exc}"

    if record.merkle_root.lower() != root_hash_hex.lower():
        return False, (
            f"Epoch record Merkle root mismatch: {record.merkle_root} != shard root {root_hash_hex}"
        )

    try:
        computed_head = compute_epoch_head(
            record.previous_epoch_head, record.merkle_root, record.metadata_hash
        ).hex()
    except ValueError as exc:
        return False, f"Epoch head computation failed: {exc}"

    if computed_head != record.epoch_head:
        return False, (
            f"Epoch head mismatch: computed {computed_head} != claimed {record.epoch_head}"
        )

    return True, f"Epoch record valid (head={record.epoch_head})"


def _check_signed_tree_head(
    signed_tree_head: dict[str, Any],
    *,
    root_hash_hex: str,
    leaf_count: int,
    epoch_record: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Validate the Signed Tree Head binding and signature."""
    try:
        sth = SignedTreeHead.from_dict(signed_tree_head)
    except Exception as exc:
        return False, f"Signed Tree Head malformed: {exc}"

    if sth.merkle_root.lower() != root_hash_hex.lower():
        return False, (
            f"Signed Tree Head Merkle root mismatch: {sth.merkle_root} != shard root {root_hash_hex}"
        )
    if sth.tree_size != leaf_count:
        return False, (
            f"Signed Tree Head tree size mismatch: {sth.tree_size} != bundle leaf count {leaf_count}"
        )
    if epoch_record is not None:
        try:
            record = EpochRecord.from_dict(epoch_record)
        except Exception as exc:
            return False, f"Signed Tree Head epoch linkage invalid: {exc}"
        if sth.epoch_id != record.epoch_index:
            return False, (
                f"Signed Tree Head epoch mismatch: {sth.epoch_id} != epoch record {record.epoch_index}"
            )
    if not sth.verify():
        return False, "Signed Tree Head signature INVALID"
    return True, f"Signed Tree Head valid (epoch={sth.epoch_id}, tree_size={sth.tree_size})"


def _check_sth_consistency(
    previous_sth: dict[str, Any],
    signed_tree_head: dict[str, Any],
    consistency_proof: dict[str, Any],
) -> tuple[bool, str]:
    """Verify consistency between two Signed Tree Heads using a consistency proof."""
    try:
        old_sth = SignedTreeHead.from_dict(previous_sth)
        new_sth = SignedTreeHead.from_dict(signed_tree_head)
        proof = ConsistencyProof.from_dict(consistency_proof)
    except Exception as exc:
        return False, f"STH consistency check failed: malformed data - {exc}"

    if not verify_sth_consistency(old_sth, new_sth, proof):
        return False, (
            f"STH consistency INVALID: append-only violation detected between "
            f"epoch {old_sth.epoch_id} (size {old_sth.tree_size}) and "
            f"epoch {new_sth.epoch_id} (size {new_sth.tree_size})"
        )

    return True, (
        f"STH consistency valid: append-only growth from "
        f"epoch {old_sth.epoch_id} (size {old_sth.tree_size}) to "
        f"epoch {new_sth.epoch_id} (size {new_sth.tree_size})"
    )


def verify_bundle(
    bundle: dict[str, Any],
    *,
    trust_mode: str = TRUST_MODE_DEV,
    trusted_fingerprints: set[str] | None = None,
    trust_store_path: str | None = None,
) -> tuple[bool, list[tuple[bool, str]]]:
    """Verify all components of a verification bundle.

    Args:
        bundle: Parsed JSON bundle (dict).

    Returns:
        ``(all_passed, results)`` where *results* is a list of
        ``(passed, message)`` tuples.
    """
    results: list[tuple[bool, str]] = []

    # --- Required fields ---
    try:
        bundle_version = bundle["bundle_version"]
        schema_version = bundle.get("schema_version", bundle_version)
        canonicalization = bundle["canonicalization"]
        canonical_events = bundle["canonical_events"]
        leaf_hashes = bundle["leaf_hashes"]
        merkle_root_hex = bundle["merkle_root"]
        header = bundle["shard_header"]
        signature_hex = bundle["signature"]
        pubkey_hex = bundle["pubkey"]
        epoch_record = bundle.get("epoch_record")
        signed_tree_head = bundle.get("signed_tree_head")
    except KeyError as exc:
        return False, [(False, f"Missing required field: {exc}")]

    # 0. Bundle schema version
    results.append(_check_bundle_version(bundle_version))
    results.append(_check_schema_version(schema_version))

    # 0.5 Canonicalization provenance
    results.append(_check_canonicalization_provenance(canonicalization))

    # 0.7 Canonical events and Merkle root determinism
    results.extend(
        _check_canonical_events(
            schema_version,
            canonical_events,
            leaf_hashes,
            merkle_root_hex,
        )
    )

    # 1. Header hash
    results.append(_check_header_hash(header))
    results.append(_check_root_consistency(header["root_hash"], merkle_root_hex))

    # 2. Ed25519 signature
    results.append(_check_signature(header, signature_hex, pubkey_hex))

    # 2.5 Epoch chaining (required for tamper-evident replication)
    if epoch_record is None:
        results.append((False, "Epoch record missing"))
    else:
        results.append(_check_epoch_record(epoch_record, header["root_hash"]))

    # 2.7 Signed Tree Head accountability for the committed root
    if signed_tree_head is None:
        results.append((False, "Signed Tree Head missing"))
    else:
        results.append(
            _check_signed_tree_head(
                signed_tree_head,
                root_hash_hex=header["root_hash"],
                leaf_count=len(leaf_hashes),
                epoch_record=epoch_record,
            )
        )

    # 3. Timestamp token (optional)
    if "timestamp_token" in bundle and bundle["timestamp_token"] is not None:
        results.append(
            _check_timestamp_token(
                header["header_hash"],
                bundle["timestamp_token"],
                trust_mode=trust_mode,
                trusted_fingerprints=trusted_fingerprints,
                trust_store_path=trust_store_path,
            )
        )

    # 4. Merkle proofs (optional)
    proof_entries = bundle.get("inclusion_proofs") or bundle.get("merkle_proofs")
    if proof_entries:
        results.extend(_check_merkle_proofs(header["root_hash"], proof_entries))

    # 5. STH consistency proof (optional)
    previous_sth = bundle.get("previous_sth")
    consistency_proof = bundle.get("consistency_proof")
    if previous_sth is not None and consistency_proof is not None and signed_tree_head is not None:
        results.append(_check_sth_consistency(previous_sth, signed_tree_head, consistency_proof))
    elif previous_sth is not None or consistency_proof is not None:
        # Warn if only one is present
        if previous_sth is not None:
            results.append((False, "Consistency proof missing (previous_sth present but no proof)"))
        if consistency_proof is not None:
            results.append((False, "Previous STH missing (consistency_proof present but no previous_sth)"))

    all_passed = all(passed for passed, _ in results)
    return all_passed, results


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline verifier for Olympus verification bundles",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Olympus bundle verifier {BUNDLE_CLI_VERSION}",
    )
    parser.add_argument(
        "bundle_file",
        help="Path to the verification bundle JSON file",
    )
    parser.add_argument(
        "--tsa-trust-mode",
        choices=[TRUST_MODE_DEV, TRUST_MODE_PROD],
        default=TRUST_MODE_DEV,
        help="TSA trust policy (dev accepts embedded certs; prod requires pinning)",
    )
    parser.add_argument(
        "--tsa-fingerprint",
        action="append",
        default=[],
        help="Trusted TSA certificate fingerprint (hex). Repeatable.",
    )
    parser.add_argument(
        "--tsa-trust-store",
        help="Path to a TSA certificate PEM/DER for production verification.",
    )
    args = parser.parse_args()

    try:
        with open(args.bundle_file) as f:
            bundle = json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {args.bundle_file}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON: {exc}", file=sys.stderr)
        return 1

    trusted_fingerprints = (
        {fp.lower() for fp in args.tsa_fingerprint} if args.tsa_fingerprint else None
    )
    all_passed, results = verify_bundle(
        bundle,
        trust_mode=args.tsa_trust_mode,
        trusted_fingerprints=trusted_fingerprints,
        trust_store_path=args.tsa_trust_store,
    )

    for passed, message in results:
        symbol = "✓" if passed else "✗"
        stream = sys.stdout if passed else sys.stderr
        print(f"  {symbol} {message}", file=stream)

    if all_passed:
        print(f"\n✓ Bundle verification PASSED ({len(results)} checks)")
        return 0
    else:
        failed = sum(1 for p, _ in results if not p)
        print(
            f"\n✗ Bundle verification FAILED ({failed}/{len(results)} checks failed)",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())

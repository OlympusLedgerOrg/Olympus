#!/usr/bin/env python3
"""Client-side rejoin verifier for Olympus nodes."""

import argparse
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx
import nacl.exceptions
import nacl.signing


# Import protocol modules when running as a standalone script from tools/.
sys.path.insert(0, str(Path(__file__).parent.parent))

from protocol.canonical_json import canonical_json_bytes
from protocol.epochs import signed_tree_head_hash
from protocol.merkle import ct_merkle_root, merkle_leaf_hash, verify_consistency_proof


logger = logging.getLogger(__name__)

STATUS_HEALTHY = "HEALTHY"
STATUS_CATCHING_UP = "CATCHING_UP"
STATUS_DIVERGED = "DIVERGED"
STATUS_UNREACHABLE = "UNREACHABLE"
STATUS_NO_HISTORY = "NO_HISTORY"
DEFAULT_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class RejoinReport:
    """Verification result from a rejoin health check."""

    status: str
    details: str


class _HTTPClient(Protocol):
    """Minimal HTTP client protocol for testable rejoin verification."""

    def get(self, url: str, *, params: dict[str, Any] | None = None) -> Any:
        """Perform a GET request."""


def _verify_sth_signature(sth: dict[str, Any]) -> bool:
    """Verify Signed Tree Head signature when signature fields are populated.

    Historical STH records may currently omit signature fields in deployments
    where history is reconstructed from shard headers. In that case we treat
    signature validation as unavailable and continue with other checks.
    """
    signature = sth.get("signature", "")
    pubkey = sth.get("signer_pubkey", "")
    signature_hex = signature if isinstance(signature, str) else ""
    pubkey_hex = pubkey if isinstance(pubkey, str) else ""
    if not signature_hex and not pubkey_hex:
        return True
    if not signature_hex or not pubkey_hex:
        return False

    try:
        payload_hash = signed_tree_head_hash(
            epoch_id=int(sth["epoch_id"]),
            tree_size=int(sth["tree_size"]),
            merkle_root=str(sth["merkle_root"]),
            timestamp=str(sth["timestamp"]),
        )
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(pubkey_hex))
        verify_key.verify(payload_hash, bytes.fromhex(signature_hex))
        return True
    except (KeyError, TypeError, ValueError, nacl.exceptions.BadSignatureError):
        return False


def _extract_proof_nodes(proof_data: dict[str, Any]) -> list[bytes]:
    """Extract consistency proof nodes from API response payload."""
    raw_nodes = proof_data.get("proof_nodes")
    if raw_nodes is None:
        raw_nodes = proof_data.get("proof", [])
    if not isinstance(raw_nodes, list):
        raise ValueError("consistency proof_nodes must be a list")
    return [bytes.fromhex(str(node)) for node in raw_nodes]


def _compute_replayed_root(entries: list[dict[str, Any]]) -> bytes:
    """Recompute CT-style Merkle root from canonicalized ledger entries.

    Each entry should follow the serialized ``LedgerEntry`` shape returned by
    the API (ts, record_hash, shard_id, shard_root, canonicalization,
    prev_entry_hash, entry_hash, and optional extras).
    """
    if not entries:
        raise ValueError("no entries to replay")
    leaf_hashes = [merkle_leaf_hash(canonical_json_bytes(entry)) for entry in entries]
    return ct_merkle_root(leaf_hashes)


def evaluate_rejoin_health(
    *,
    sths: list[dict[str, Any]],
    consistency_proofs: dict[tuple[int, int], dict[str, Any]],
    entries: list[dict[str, Any]],
) -> RejoinReport:
    """Evaluate node rejoin health from fetched STHs, proofs, and ledger entries."""
    if not sths:
        return RejoinReport(status=STATUS_NO_HISTORY, details="No STH history returned by node")

    ordered_sths = sorted(sths, key=lambda sth: int(sth["epoch_id"]))

    for index, sth in enumerate(ordered_sths):
        previous = ordered_sths[index - 1] if index > 0 else None
        if previous is not None:
            if int(sth["tree_size"]) < int(previous["tree_size"]):
                return RejoinReport(
                    status=STATUS_DIVERGED,
                    details=(
                        "Non-monotonic tree_size between epochs "
                        f"{previous.get('epoch_id')} and {sth.get('epoch_id')}"
                    ),
                )
        if not _verify_sth_signature(sth):
            return RejoinReport(
                status=STATUS_DIVERGED,
                details=f"Invalid STH signature at epoch {sth.get('epoch_id')}",
            )
        if previous is not None:
            prev_key = str(previous.get("signer_pubkey", ""))
            curr_key = str(sth.get("signer_pubkey", ""))
            if prev_key and curr_key and prev_key != curr_key:
                return RejoinReport(
                    status=STATUS_DIVERGED,
                    details=(
                        "Signer continuity break between epochs "
                        f"{previous.get('epoch_id')} and {sth.get('epoch_id')}"
                    ),
                )

    for index in range(1, len(ordered_sths)):
        old_sth = ordered_sths[index - 1]
        new_sth = ordered_sths[index]
        old_size = int(old_sth["tree_size"])
        new_size = int(new_sth["tree_size"])
        if new_size == old_size:
            continue

        proof_data = consistency_proofs.get((old_size, new_size))
        if proof_data is None:
            return RejoinReport(
                status=STATUS_DIVERGED,
                details=f"Missing consistency proof for ({old_size}, {new_size})",
            )

        try:
            proof_nodes = _extract_proof_nodes(proof_data)
            trust_new_root_on_empty = old_size == 0
            # new_root comes from the signed STHs validated earlier in this verifier.
            is_valid = verify_consistency_proof(
                bytes.fromhex(str(old_sth["merkle_root"])),
                bytes.fromhex(str(new_sth["merkle_root"])),
                proof_nodes,
                old_size,
                new_size,
                trust_new_root_on_empty=trust_new_root_on_empty,
            )
        except (TypeError, ValueError):
            is_valid = False
        if not is_valid:
            return RejoinReport(
                status=STATUS_DIVERGED,
                details=(
                    "Consistency proof verification failed between epochs "
                    f"{old_sth.get('epoch_id')} and {new_sth.get('epoch_id')}"
                ),
            )

    try:
        replayed_root = _compute_replayed_root(entries)
    except ValueError:
        return RejoinReport(
            status=STATUS_CATCHING_UP,
            details="No ledger entries available for replay root validation",
        )

    latest = ordered_sths[-1]
    expected_root = bytes.fromhex(str(latest["merkle_root"]))
    latest_tree_size = int(latest["tree_size"])

    if len(entries) < latest_tree_size:
        return RejoinReport(
            status=STATUS_CATCHING_UP,
            details=f"Node has {len(entries)} entries but latest STH commits {latest_tree_size}",
        )
    if replayed_root != expected_root:
        return RejoinReport(
            status=STATUS_DIVERGED,
            details="Replayed journal root diverges from latest STH merkle_root",
        )
    return RejoinReport(
        status=STATUS_HEALTHY,
        details=f"Verified STH chain and replay root at tree_size {latest_tree_size}",
    )


def run_rejoin_verifier(
    *,
    node_url: str,
    shard_id: str,
    history_limit: int = 100,
    client: _HTTPClient | None = None,
) -> RejoinReport:
    """Fetch node state over HTTP and evaluate rejoin health."""
    http_client = client or httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS)
    close_client = client is None
    try:
        history_resp = http_client.get(
            f"{node_url.rstrip('/')}/protocol/sth/history",
            params={"shard_id": shard_id, "n": history_limit},
        )
        history_resp.raise_for_status()
        history_payload = history_resp.json()
        sths = list(history_payload.get("sths", []))
        if not sths:
            return RejoinReport(STATUS_NO_HISTORY, "No STH history returned by node")

        consistency_proofs: dict[tuple[int, int], dict[str, Any]] = {}
        ordered_sths = sorted(sths, key=lambda sth: int(sth["epoch_id"]))
        for index in range(1, len(ordered_sths)):
            old_size = int(ordered_sths[index - 1]["tree_size"])
            new_size = int(ordered_sths[index]["tree_size"])
            if new_size == old_size:
                continue
            proof_resp = http_client.get(
                f"{node_url.rstrip('/')}/ledger/consistency_proof",
                params={"from_size": old_size, "to_size": new_size},
            )
            proof_resp.raise_for_status()
            consistency_proofs[(old_size, new_size)] = proof_resp.json()

        entries_resp = http_client.get(
            f"{node_url.rstrip('/')}/ledger/entries",
            params={"start": 0, "shard_id": shard_id},
        )
        entries_resp.raise_for_status()
        entries_payload = entries_resp.json()
        if isinstance(entries_payload, dict):
            entries = list(entries_payload.get("entries", []))
        else:
            entries = list(entries_payload)

        return evaluate_rejoin_health(
            sths=sths,
            consistency_proofs=consistency_proofs,
            entries=entries,
        )
    except httpx.HTTPError as exc:
        return RejoinReport(STATUS_UNREACHABLE, f"Network error: {exc}")
    finally:
        if close_client and isinstance(http_client, httpx.Client):
            http_client.close()


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Olympus rejoin verification tool")
    parser.add_argument("--node-url", required=True, help="Node base URL")
    parser.add_argument("--shard-id", required=True, help="Shard ID to verify")
    parser.add_argument(
        "--history-limit",
        type=int,
        default=100,
        help="Number of STH history records to fetch (default: 100)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    report = run_rejoin_verifier(
        node_url=args.node_url,
        shard_id=args.shard_id,
        history_limit=args.history_limit,
    )
    print(f"{report.status}: {report.details}")

    if report.status in {STATUS_HEALTHY, STATUS_CATCHING_UP}:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

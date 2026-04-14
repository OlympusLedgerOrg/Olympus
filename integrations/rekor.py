"""Sigstore Rekor transparency log integration for external root anchoring.

This module provides asynchronous anchoring of Olympus shard headers to the
Sigstore Rekor transparency log, providing external tamper-evidence without
requiring live Guardian nodes.

Rekor anchoring is a soft dependency: failures are logged but do not block
ingest operations. This ensures that temporary Rekor unavailability does not
impact ledger availability.

Usage:
    anchor = RekorAnchor(http_client)
    await anchor.anchor_shard_header(storage, shard_id, seq, header_hash, root_hash)

Environment Variables:
    OLYMPUS_REKOR_ENABLED: Set to "true" to enable Rekor anchoring (default: false)
    OLYMPUS_REKOR_URL: Rekor API base URL (default: https://rekor.sigstore.dev)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import httpx


if TYPE_CHECKING:
    from storage.postgres import StorageLayer


logger = logging.getLogger(__name__)


# Default Rekor API endpoint
DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"


def _env_flag_enabled(name: str) -> bool:
    """Return True when an environment flag is enabled with common truthy values.

    This is a shared utility to ensure consistent boolean parsing across the codebase.
    """
    return os.environ.get(name, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _rekor_enabled() -> bool:
    """Return True when Rekor anchoring is enabled via environment variable."""
    return _env_flag_enabled("OLYMPUS_REKOR_ENABLED")


def _rekor_base_url() -> str:
    """Return the configured Rekor API base URL."""
    return os.environ.get("OLYMPUS_REKOR_URL", DEFAULT_REKOR_URL).rstrip("/")


@dataclass(frozen=True)
class RekorAnchorResult:
    """Result of a Rekor anchoring operation.

    Attributes:
        success: Whether the anchoring operation succeeded.
        rekor_uuid: The UUID of the Rekor log entry (if successful).
        rekor_index: The log index of the Rekor entry (if successful).
        verification_url: URL to verify the Rekor entry (if successful).
        error_message: Error message if the operation failed.
    """

    success: bool
    rekor_uuid: str | None = None
    rekor_index: int | None = None
    verification_url: str | None = None
    error_message: str | None = None


class RekorAnchor:
    """Asynchronous Rekor transparency log anchor for Olympus shard headers.

    This class provides methods to anchor shard header commitments to the
    Sigstore Rekor transparency log. All operations are non-blocking and
    failures do not impact ingest operations.

    Attributes:
        http_client: The async HTTP client to use for Rekor API requests.
        base_url: The Rekor API base URL.
        timeout_seconds: Timeout for Rekor API requests in seconds.
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        base_url: str | None = None,
        timeout_seconds: float = 10.0,
    ):
        """Initialize the Rekor anchor.

        Args:
            http_client: Async HTTP client for Rekor API requests.
            base_url: Rekor API base URL (defaults to sigstore.dev).
            timeout_seconds: Timeout for Rekor API requests.
        """
        self.http_client = http_client
        self.base_url = base_url or _rekor_base_url()
        self.timeout_seconds = timeout_seconds

    def _build_hashedrekord_payload(
        self,
        shard_id: str,
        seq: int,
        header_hash: bytes,
        root_hash: bytes,
    ) -> dict[str, Any]:
        """Build the hashedrekord entry payload for Rekor.

        The hashedrekord type allows submitting a hash directly without
        requiring an artifact upload or signature.

        Args:
            shard_id: The shard identifier.
            seq: The shard header sequence number.
            header_hash: The 32-byte header hash.
            root_hash: The 32-byte SMT root hash.

        Returns:
            Rekor API payload for creating a hashedrekord entry.
        """
        # Combine header_hash and root_hash into a single commitment
        # Use SHA-256 as Rekor requires SHA-256 or SHA-512 for hashedrekord
        commitment = hashlib.sha256(header_hash + root_hash).digest()

        # Include shard metadata in the data field for provenance
        data_payload = {
            "olympus_version": "1.0",
            "shard_id": shard_id,
            "seq": seq,
            "header_hash": header_hash.hex(),
            "root_hash": root_hash.hex(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        data_b64 = base64.standard_b64encode(
            json.dumps(data_payload, sort_keys=True).encode("utf-8")
        ).decode("ascii")

        return {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": commitment.hex(),
                    },
                },
                "signature": {
                    # hashedrekord requires a signature field, but we're using
                    # the "intoto" style where the hash itself is the commitment
                    # For pure hash anchoring, we use an empty signature
                    "content": data_b64,
                    "publicKey": {
                        "content": data_b64,  # Self-describing payload
                    },
                },
            },
        }

    async def anchor_commitment(
        self,
        shard_id: str,
        seq: int,
        header_hash: bytes,
        root_hash: bytes,
    ) -> RekorAnchorResult:
        """Submit a shard header commitment to Rekor.

        This method is non-blocking and catches all exceptions to ensure
        Rekor failures never impact ingest operations.

        Args:
            shard_id: The shard identifier.
            seq: The shard header sequence number.
            header_hash: The 32-byte header hash.
            root_hash: The 32-byte SMT root hash.

        Returns:
            RekorAnchorResult with success status and entry details.
        """
        if not _rekor_enabled():
            return RekorAnchorResult(
                success=False,
                error_message="Rekor anchoring is disabled",
            )

        try:
            payload = self._build_hashedrekord_payload(
                shard_id, seq, header_hash, root_hash
            )

            response = await self.http_client.post(
                f"{self.base_url}/api/v1/log/entries",
                json=payload,
                timeout=self.timeout_seconds,
            )

            if response.status_code == 201:
                # Success - parse the response
                result = response.json()
                # Rekor returns a dict with UUID as key
                if isinstance(result, dict) and len(result) == 1:
                    rekor_uuid = next(iter(result.keys()))
                    entry = result[rekor_uuid]
                    log_index = entry.get("logIndex")

                    verification_url = (
                        f"{self.base_url}/api/v1/log/entries?logIndex={log_index}"
                        if log_index is not None
                        else None
                    )

                    return RekorAnchorResult(
                        success=True,
                        rekor_uuid=rekor_uuid,
                        rekor_index=log_index,
                        verification_url=verification_url,
                    )

                # Unexpected response format - treat as failure
                return RekorAnchorResult(
                    success=False,
                    error_message="Unexpected response format from Rekor: expected dict with UUID key",
                )

            # HTTP error
            return RekorAnchorResult(
                success=False,
                error_message=f"Rekor API error: HTTP {response.status_code}",
            )

        except httpx.TimeoutException:
            logger.warning(
                "Rekor anchoring timed out for shard=%s seq=%d",
                shard_id,
                seq,
            )
            return RekorAnchorResult(
                success=False,
                error_message="Rekor request timed out",
            )
        except httpx.RequestError as exc:
            logger.warning(
                "Rekor anchoring request failed for shard=%s seq=%d: %s",
                shard_id,
                seq,
                exc,
            )
            return RekorAnchorResult(
                success=False,
                error_message=f"Rekor request failed: {exc}",
            )
        except Exception as exc:
            logger.exception(
                "Unexpected error during Rekor anchoring for shard=%s seq=%d",
                shard_id,
                seq,
            )
            return RekorAnchorResult(
                success=False,
                error_message=f"Unexpected error: {exc}",
            )

    async def anchor_shard_header(
        self,
        storage: StorageLayer,
        shard_id: str,
        seq: int,
        header_hash: bytes,
        root_hash: bytes,
    ) -> RekorAnchorResult:
        """Anchor a shard header to Rekor and persist the result.

        This method:
        1. Creates a pending rekor_anchors record
        2. Submits the commitment to Rekor
        3. Updates the record with the result (anchored or failed)

        Args:
            storage: The storage layer for persisting anchor records.
            shard_id: The shard identifier.
            seq: The shard header sequence number.
            header_hash: The 32-byte header hash.
            root_hash: The 32-byte SMT root hash.

        Returns:
            RekorAnchorResult with success status and entry details.
        """
        # Create pending record
        anchor_id = storage.create_rekor_anchor(
            shard_id=shard_id,
            shard_seq=seq,
            root_hash=root_hash,
        )

        # Submit to Rekor
        result = await self.anchor_commitment(
            shard_id=shard_id,
            seq=seq,
            header_hash=header_hash,
            root_hash=root_hash,
        )

        # Update record with result
        if result.success:
            storage.update_rekor_anchor(
                anchor_id=anchor_id,
                status="anchored",
                rekor_uuid=result.rekor_uuid,
                rekor_index=result.rekor_index,
            )
        else:
            storage.update_rekor_anchor(
                anchor_id=anchor_id,
                status="failed",
            )

        return result


def fire_and_forget_anchor(
    http_client: httpx.AsyncClient,
    storage: StorageLayer,
    shard_id: str,
    seq: int,
    header_hash: bytes,
    root_hash: bytes,
) -> None:
    """Schedule a Rekor anchor operation without blocking.

    This function creates an asyncio task to perform Rekor anchoring
    asynchronously. The task is fire-and-forget: any errors are logged
    but do not propagate to the caller.

    Args:
        http_client: Async HTTP client for Rekor API requests.
        storage: The storage layer for persisting anchor records.
        shard_id: The shard identifier.
        seq: The shard header sequence number.
        header_hash: The 32-byte header hash.
        root_hash: The 32-byte SMT root hash.
    """
    if not _rekor_enabled():
        return

    async def _do_anchor() -> None:
        try:
            anchor = RekorAnchor(http_client)
            result = await anchor.anchor_shard_header(
                storage=storage,
                shard_id=shard_id,
                seq=seq,
                header_hash=header_hash,
                root_hash=root_hash,
            )
            if result.success:
                logger.info(
                    "Rekor anchor successful: shard=%s seq=%d uuid=%s index=%s",
                    shard_id,
                    seq,
                    result.rekor_uuid,
                    result.rekor_index,
                )
            else:
                logger.warning(
                    "Rekor anchor failed: shard=%s seq=%d error=%s",
                    shard_id,
                    seq,
                    result.error_message,
                )
        except Exception:
            logger.exception(
                "Fire-and-forget Rekor anchor failed: shard=%s seq=%d",
                shard_id,
                seq,
            )

    asyncio.create_task(_do_anchor())

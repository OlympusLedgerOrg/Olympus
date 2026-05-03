"""
Go sequencer HTTP client for the Olympus write path.

This module provides an async HTTP client for the Go sequencer service,
implementing the Trillian-shaped API for record ingestion and proof retrieval.

The client is gated behind the OLYMPUS_USE_GO_SEQUENCER environment variable.
When enabled, Python routes all write operations through the Go sequencer
instead of directly to storage/postgres.py.

Environment Variables:
    OLYMPUS_USE_GO_SEQUENCER: Enable Go sequencer routing (default: false)
    OLYMPUS_SEQUENCER_URL: Sequencer base URL (default: http://localhost:8081)
    OLYMPUS_SEQUENCER_TOKEN: Authentication token for X-Sequencer-Token header
    OLYMPUS_SEQUENCER_TIMEOUT_SECONDS: Request timeout (default: 30)
"""

from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx


if TYPE_CHECKING:
    pass


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------


class SequencerError(Exception):
    """Base exception for sequencer-related errors."""


class SequencerUnavailableError(SequencerError):
    """Raised when the Go sequencer service is unreachable.

    This exception indicates a transient failure (connection refused,
    timeout, network error). Callers may fall back to direct storage
    or return HTTP 503 to clients.
    """

    def __init__(self, message: str, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.cause = cause


class SequencerResponseError(SequencerError):
    """Raised when the Go sequencer returns a non-2xx response.

    Attributes:
        status_code: HTTP status code from the sequencer.
        detail: Error detail from the response body, if available.
    """

    def __init__(self, message: str, status_code: int, detail: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


# ---------------------------------------------------------------------------
# Response dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SequencerAppendResult:
    """Result from appending a record via the Go sequencer.

    Attributes:
        new_root: Hex-encoded 32-byte SMT root after the update.
        global_key: Hex-encoded 32-byte composite key (H(shard_id || record_key)).
        leaf_value_hash: Hex-encoded 32-byte leaf value hash.
        tree_size: Number of non-empty leaves in the tree.
    """

    new_root: str
    global_key: str
    leaf_value_hash: str
    tree_size: int


@dataclass(frozen=True, slots=True)
class SequencerInclusionProof:
    """Inclusion proof returned by the Go sequencer.

    Attributes:
        global_key: Hex-encoded 32-byte composite key.
        value_hash: Hex-encoded 32-byte leaf value hash.
        siblings: List of hex-encoded sibling hashes (256 for full SMT).
        root: Hex-encoded 32-byte root hash the proof was generated against.
    """

    global_key: str
    value_hash: str
    siblings: list[str]
    root: str


@dataclass(frozen=True, slots=True)
class SequencerLatestRoot:
    """Latest root information from the Go sequencer.

    Attributes:
        root: Hex-encoded 32-byte current root hash.
        tree_size: Number of non-empty leaves in the tree.
    """

    root: str
    tree_size: int


@dataclass(frozen=True, slots=True)
class SequencerSignedRootPair:
    """A pair of signed roots returned by `/v1/get-signed-root-pair`.

    This is **not** an RFC-6962 / Trillian consistency proof. It returns the
    two signed roots so that a caller can verify both signatures and compare
    the hashes offline. A real consistency proof for the CD-HS-ST sparse
    Merkle tree is tracked as a follow-up; see the changelog entry that
    renamed the original `/v1/get-consistency-proof` endpoint.

    Attributes:
        old_tree_size: Smaller tree size requested by the caller.
        new_tree_size: Larger tree size requested by the caller.
        old_root: Hex-encoded 32-byte root at `old_tree_size`.
        old_signature: Hex-encoded Ed25519 signature over the old root.
        new_root: Hex-encoded 32-byte root at `new_tree_size`.
        new_signature: Hex-encoded Ed25519 signature over the new root.
    """

    old_tree_size: int
    new_tree_size: int
    old_root: str
    old_signature: str
    new_root: str
    new_signature: str


# ---------------------------------------------------------------------------
# Client implementation
# ---------------------------------------------------------------------------


def _env_flag_enabled(name: str) -> bool:
    """Return True when an environment flag is enabled with common truthy values."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def use_go_sequencer() -> bool:
    """Return True when the Go sequencer write path is enabled."""
    return _env_flag_enabled("OLYMPUS_USE_GO_SEQUENCER")


class GoSequencerClient:
    """Async HTTP client for the Go sequencer service.

    Wraps the Trillian-shaped API with a clean interface for Python callers.
    When OLYMPUS_USE_GO_SEQUENCER is enabled, this client is used instead of
    direct storage/postgres.py writes.

    The client uses X-Sequencer-Token header authentication and handles
    connection failures gracefully by raising SequencerUnavailableError.

    Example:
        >>> client = GoSequencerClient()
        >>> result = await client.append_record(
        ...     shard_id="test.shard",
        ...     record_type="doc",
        ...     record_id="doc-001",
        ...     content=b'{"key": "value"}',
        ... )
        >>> print(result.new_root)
    """

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        """Initialize the Go sequencer client.

        Args:
            base_url: Sequencer base URL. Defaults to OLYMPUS_SEQUENCER_URL
                environment variable or http://localhost:8081.
            token: Authentication token. Defaults to OLYMPUS_SEQUENCER_TOKEN
                environment variable.
            timeout_seconds: Request timeout in seconds. Defaults to
                OLYMPUS_SEQUENCER_TIMEOUT_SECONDS or 30.
        """
        self._base_url = (
            base_url
            or os.environ.get("OLYMPUS_SEQUENCER_URL", "").strip()
            or "http://localhost:8081"
        )
        # Remove trailing slash for consistent URL construction
        self._base_url = self._base_url.rstrip("/")

        self._token = token or os.environ.get("OLYMPUS_SEQUENCER_TOKEN", "")

        default_timeout = 30.0
        if timeout_seconds is not None:
            self._timeout = timeout_seconds
        else:
            timeout_env = os.environ.get("OLYMPUS_SEQUENCER_TIMEOUT_SECONDS", "")
            try:
                self._timeout = float(timeout_env) if timeout_env else default_timeout
            except ValueError:
                logger.warning(
                    "Invalid OLYMPUS_SEQUENCER_TIMEOUT_SECONDS=%r, using default %s",
                    timeout_env,
                    default_timeout,
                )
                self._timeout = default_timeout

        # Lazily initialized HTTP client
        self._client: httpx.AsyncClient | None = None

        # Warn loudly when token is missing - requests will be rejected
        # by the sequencer's requireToken middleware. The token value itself
        # is intentionally never logged to avoid credential exposure.
        if not self._token:
            # Use error-level logging in production-like environments to
            # ensure this misconfiguration is noticed early.
            logger.error(
                "GoSequencerClient: OLYMPUS_SEQUENCER_TOKEN not set -- "
                "sequencer requests will be unauthorized and fail"
            )

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create the underlying HTTP client."""
        if self._client is None:
            limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
            self._client = httpx.AsyncClient(timeout=self._timeout, limits=limits)
        return self._client

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _headers(self) -> dict[str, str]:
        """Return headers for sequencer requests."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._token:
            headers["X-Sequencer-Token"] = self._token
        return headers

    async def append_record(
        self,
        shard_id: str,
        record_type: str,
        record_id: str,
        content: bytes,
        content_type: str = "application/octet-stream",
        version: str = "",
        metadata: dict[str, str] | None = None,
        parser_id: str = "",
        canonical_parser_version: str = "",
    ) -> SequencerAppendResult:
        """Append a record to the ledger via the Go sequencer.

        POST /v1/queue-leaf → Rust service canonicalizes the content, then
        inserts the leaf into the global SMT.  Use this method when you have
        raw (not yet hashed) content.  For pre-computed value hashes, use
        ``append_record_hash`` which calls /v1/queue-leaf-hash and bypasses
        the Rust canonicalization step.

        Args:
            shard_id: Shard identifier (e.g., "test.shard" or "watauga:2025:budget").
            record_type: Record type (e.g., "doc", "dataset", "artifact").
            record_id: Unique record identifier.
            content: Raw content bytes to canonicalize and commit.
            content_type: MIME type understood by the Rust canonicalizer
                ("json", "text", or "plaintext"). Do NOT pass
                "application/octet-stream" here — that will be rejected by
                the Rust service. Use ``append_record_hash`` instead.
            version: Optional version string (empty string if not versioned).
            metadata: Optional key-value metadata pairs.
            parser_id: ADR-0003 parser identity (e.g. "docling@2.3.1").
                Required; empty string is rejected by the Go sequencer.
            canonical_parser_version: ADR-0003 canonical parser version
                (e.g. "v1"). Required; empty string is rejected.

        Returns:
            SequencerAppendResult with new_root, global_key, leaf_value_hash, tree_size.

        Raises:
            SequencerUnavailableError: If the sequencer is unreachable.
            SequencerResponseError: If the sequencer returns a non-2xx status.
        """
        url = f"{self._base_url}/v1/queue-leaf"
        payload: dict[str, Any] = {
            "shard_id": shard_id,
            "record_type": record_type,
            "record_id": record_id,
            "version": version,
            "content": base64.b64encode(content).decode("ascii"),
            "content_type": content_type,
            "parser_id": parser_id,
            "canonical_parser_version": canonical_parser_version,
        }
        if metadata:
            payload["metadata"] = metadata

        try:
            client = self._get_client()
            resp = await client.post(url, json=payload, headers=self._headers())
        except httpx.RequestError as exc:
            logger.error("sequencer_unreachable url=%s error=%s", url, exc)
            raise SequencerUnavailableError(
                f"Sequencer unavailable at {self._base_url}", cause=exc
            ) from exc

        if resp.status_code != 200:
            detail = resp.text[:500] if resp.text else None
            logger.error(
                "sequencer_error url=%s status=%d body=%.200s",
                url,
                resp.status_code,
                detail,
            )
            raise SequencerResponseError(
                f"Sequencer returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                detail=detail,
            )

        data = resp.json()
        return SequencerAppendResult(
            new_root=data["new_root"],
            global_key=data["global_key"],
            leaf_value_hash=data["leaf_value_hash"],
            tree_size=int(data["tree_size"]),
        )

    async def append_record_hash(
        self,
        shard_id: str,
        record_type: str,
        record_id: str,
        value_hash: bytes,
        parser_id: str,
        canonical_parser_version: str,
        version: str = "",
        metadata: dict[str, str] | None = None,
    ) -> SequencerAppendResult:
        """Append a pre-computed 32-byte leaf hash to the ledger.

        POST /v1/queue-leaf-hash → passes ``value_hash`` directly to the Rust
        SMT service as canonical_content, bypassing the Rust canonicalization
        step.  Use this method when the caller already holds a canonical content
        hash (e.g. Python ``storage_layer.py`` sending a pre-hashed value).

        Passing raw binary with content_type="application/octet-stream" to
        ``append_record`` would be rejected by the Rust canonicalization step
        (H-3); this endpoint is the correct alternative.

        Args:
            shard_id: Shard identifier.
            record_type: Record type.
            record_id: Unique record identifier.
            value_hash: Exactly 32-byte pre-computed canonical content hash.
            parser_id: ADR-0003 parser identity. Required; empty string is
                rejected by the Go sequencer.
            canonical_parser_version: ADR-0003 canonical parser version.
                Required; empty string is rejected.
            version: Optional version string.
            metadata: Optional key-value metadata pairs.

        Returns:
            SequencerAppendResult with new_root, global_key, leaf_value_hash, tree_size.

        Raises:
            ValueError: If ``value_hash`` is not exactly 32 bytes.
            SequencerUnavailableError: If the sequencer is unreachable.
            SequencerResponseError: If the sequencer returns a non-2xx status.
        """
        if len(value_hash) != 32:
            raise ValueError(f"value_hash must be exactly 32 bytes, got {len(value_hash)}")
        url = f"{self._base_url}/v1/queue-leaf-hash"
        payload: dict[str, Any] = {
            "shard_id": shard_id,
            "record_type": record_type,
            "record_id": record_id,
            "version": version,
            "value_hash": base64.b64encode(value_hash).decode("ascii"),
            "parser_id": parser_id,
            "canonical_parser_version": canonical_parser_version,
        }
        if metadata:
            payload["metadata"] = metadata

        try:
            client = self._get_client()
            resp = await client.post(url, json=payload, headers=self._headers())
        except httpx.RequestError as exc:
            logger.error("sequencer_unreachable url=%s error=%s", url, exc)
            raise SequencerUnavailableError(
                f"Sequencer unavailable at {self._base_url}", cause=exc
            ) from exc

        if resp.status_code != 200:
            detail = resp.text[:500] if resp.text else None
            logger.error(
                "sequencer_hash_error url=%s status=%d body=%.200s",
                url,
                resp.status_code,
                detail,
            )
            raise SequencerResponseError(
                f"Sequencer returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                detail=detail,
            )

        data = resp.json()
        return SequencerAppendResult(
            new_root=data["new_root"],
            global_key=data["global_key"],
            leaf_value_hash=data["leaf_value_hash"],
            tree_size=int(data["tree_size"]),
        )

    async def append_records_batch(
        self,
        records: list[dict[str, Any]],
    ) -> list[SequencerAppendResult]:
        """Append multiple records atomically via the Go sequencer batch endpoint.

        POST /v1/queue-leaves → returns per-record results plus final root.

        Args:
            records: List of record dicts, each containing:
                - shard_id: Shard identifier
                - record_type: Record type
                - record_id: Record identifier
                - content: Canonical content bytes
                - content_type: MIME type (optional, default: "json")
                - version: Version string (optional, default: "")
                - metadata: Optional metadata dict
                - parser_id: ADR-0003 parser identity (required)
                - canonical_parser_version: ADR-0003 canonical parser version (required)

        Returns:
            List of SequencerAppendResult in the same order as input records.

        Raises:
            SequencerUnavailableError: If the sequencer is unreachable.
            SequencerResponseError: If the sequencer returns a non-2xx status.
        """
        url = f"{self._base_url}/v1/queue-leaves"
        payload = {
            "records": [
                {
                    "shard_id": r["shard_id"],
                    "record_type": r["record_type"],
                    "record_id": r["record_id"],
                    "version": r.get("version", ""),
                    "content": base64.b64encode(r["content"]).decode("ascii"),
                    "content_type": r.get("content_type", "json"),
                    "parser_id": r.get("parser_id", ""),
                    "canonical_parser_version": r.get("canonical_parser_version", ""),
                    **({"metadata": r["metadata"]} if r.get("metadata") else {}),
                }
                for r in records
            ]
        }

        try:
            client = self._get_client()
            resp = await client.post(url, json=payload, headers=self._headers())
        except httpx.RequestError as exc:
            logger.error("sequencer_batch_unreachable url=%s error=%s", url, exc)
            raise SequencerUnavailableError(
                f"Sequencer unavailable at {self._base_url}", cause=exc
            ) from exc

        if resp.status_code != 200:
            detail = resp.text[:500] if resp.text else None
            logger.error(
                "sequencer_batch_error url=%s status=%d body=%.200s",
                url,
                resp.status_code,
                detail,
            )
            raise SequencerResponseError(
                f"Sequencer returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                detail=detail,
            )

        data = resp.json()
        return [
            SequencerAppendResult(
                new_root=r["new_root"],
                global_key=r["global_key"],
                leaf_value_hash=r["leaf_value_hash"],
                tree_size=int(r["tree_size"]),
            )
            for r in data["results"]
        ]

    async def get_inclusion_proof(
        self,
        shard_id: str,
        record_type: str,
        record_id: str,
        root: bytes | None = None,
        version: str = "",
    ) -> SequencerInclusionProof:
        """Get an inclusion proof for a record.

        GET /v1/get-inclusion-proof → returns siblings, global_key, value_hash, root.

        Args:
            shard_id: Shard identifier.
            record_type: Record type.
            record_id: Record identifier.
            root: Optional root hash to prove against (uses latest if not specified).
            version: Optional version string.

        Returns:
            SequencerInclusionProof with global_key, value_hash, siblings, root.

        Raises:
            SequencerUnavailableError: If the sequencer is unreachable.
            SequencerResponseError: If the sequencer returns a non-2xx status.
        """
        params: dict[str, str] = {
            "shard_id": shard_id,
            "record_type": record_type,
            "record_id": record_id,
        }
        if version:
            params["version"] = version
        if root is not None:
            params["root"] = root.hex()

        url = f"{self._base_url}/v1/get-inclusion-proof"

        try:
            client = self._get_client()
            resp = await client.get(url, params=params, headers=self._headers())
        except httpx.RequestError as exc:
            logger.error("sequencer_proof_unreachable url=%s error=%s", url, exc)
            raise SequencerUnavailableError(
                f"Sequencer unavailable at {self._base_url}", cause=exc
            ) from exc

        if resp.status_code != 200:
            detail = resp.text[:500] if resp.text else None
            logger.error(
                "sequencer_proof_error url=%s status=%d body=%.200s",
                url,
                resp.status_code,
                detail,
            )
            raise SequencerResponseError(
                f"Sequencer returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                detail=detail,
            )

        data = resp.json()
        return SequencerInclusionProof(
            global_key=data["global_key"],
            value_hash=data["value_hash"],
            siblings=data["siblings"],
            root=data["root"],
        )

    async def get_latest_root(self, shard_id: str | None = None) -> SequencerLatestRoot:
        """Get the current global SMT root.

        GET /v1/get-latest-root → returns current root hash and tree size.

        Args:
            shard_id: Optional shard identifier (currently ignored; global root returned).

        Returns:
            SequencerLatestRoot with root hash and tree_size.

        Raises:
            SequencerUnavailableError: If the sequencer is unreachable.
            SequencerResponseError: If the sequencer returns a non-2xx status.
        """
        url = f"{self._base_url}/v1/get-latest-root"
        params: dict[str, str] = {}
        if shard_id:
            params["shard_id"] = shard_id

        try:
            client = self._get_client()
            resp = await client.get(url, params=params, headers=self._headers())
        except httpx.RequestError as exc:
            logger.error("sequencer_root_unreachable url=%s error=%s", url, exc)
            raise SequencerUnavailableError(
                f"Sequencer unavailable at {self._base_url}", cause=exc
            ) from exc

        if resp.status_code != 200:
            detail = resp.text[:500] if resp.text else None
            logger.error(
                "sequencer_root_error url=%s status=%d body=%.200s",
                url,
                resp.status_code,
                detail,
            )
            raise SequencerResponseError(
                f"Sequencer returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                detail=detail,
            )

        data = resp.json()
        return SequencerLatestRoot(
            root=data["root"],
            tree_size=int(data["tree_size"]),
        )

    async def health_check(self) -> bool:
        """Check if the sequencer is reachable and responding.

        Returns:
            True if the sequencer responds to get-latest-root, False otherwise.
        """
        try:
            await self.get_latest_root()
            return True
        except (SequencerUnavailableError, SequencerResponseError):
            return False

    async def get_signed_root_pair(
        self,
        old_tree_size: int,
        new_tree_size: int,
    ) -> SequencerSignedRootPair:
        """Fetch a pair of signed roots for offline comparison.

        GET /v1/get-signed-root-pair → returns (old_root, old_signature,
        new_root, new_signature) plus the requested tree sizes.

        This is **not** an RFC-6962 consistency proof; it only returns the
        two signed roots and lets the caller verify the signatures and
        compare the hashes. The endpoint was renamed from the misleading
        `/v1/get-consistency-proof` (which now returns 410 Gone on the Go
        side); see the changelog entry under the rename.

        Args:
            old_tree_size: Smaller tree size (must be ≥ 0).
            new_tree_size: Larger tree size (must be ≥ `old_tree_size`).

        Returns:
            A `SequencerSignedRootPair` with both signed roots.

        Raises:
            ValueError: If `new_tree_size < old_tree_size`.
            SequencerUnavailableError: If the sequencer is unreachable.
            SequencerResponseError: If the sequencer returns a non-2xx status.
        """
        if old_tree_size < 0 or new_tree_size < 0:
            raise ValueError(
                f"tree sizes must be non-negative (got old={old_tree_size}, new={new_tree_size})"
            )
        if new_tree_size < old_tree_size:
            raise ValueError(
                f"new_tree_size ({new_tree_size}) must be >= old_tree_size ({old_tree_size})"
            )

        url = f"{self._base_url}/v1/get-signed-root-pair"
        params = {
            "old_tree_size": str(old_tree_size),
            "new_tree_size": str(new_tree_size),
        }

        try:
            client = self._get_client()
            resp = await client.get(url, params=params, headers=self._headers())
        except httpx.RequestError as exc:
            logger.error("sequencer_signed_root_pair_unreachable url=%s error=%s", url, exc)
            raise SequencerUnavailableError(
                f"Sequencer unavailable at {self._base_url}", cause=exc
            ) from exc

        if resp.status_code != 200:
            detail = resp.text[:500] if resp.text else None
            logger.error(
                "sequencer_signed_root_pair_error url=%s status=%d body=%.200s",
                url,
                resp.status_code,
                detail,
            )
            raise SequencerResponseError(
                f"Sequencer returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                detail=detail,
            )

        data = resp.json()
        return SequencerSignedRootPair(
            old_tree_size=int(data["old_tree_size"]),
            new_tree_size=int(data["new_tree_size"]),
            old_root=data["old_root"],
            old_signature=data["old_signature"],
            new_root=data["new_root"],
            new_signature=data["new_signature"],
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_sequencer_client: GoSequencerClient | None = None


def get_sequencer_client() -> GoSequencerClient:
    """Get or create the module-level GoSequencerClient singleton.

    The client is lazily initialized on first call to avoid touching
    the event loop at import time.

    Returns:
        The singleton GoSequencerClient instance.
    """
    global _sequencer_client
    if _sequencer_client is None:
        _sequencer_client = GoSequencerClient()
    return _sequencer_client


async def close_sequencer_client() -> None:
    """Close the module-level sequencer client.

    Should be called from the application lifespan shutdown hook.
    """
    global _sequencer_client
    if _sequencer_client is not None:
        await _sequencer_client.close()
        _sequencer_client = None


async def get_sequencer_health_status() -> tuple[str, bool]:
    """Return (status_string, is_healthy) for the sequencer.

    Returns:
        Tuple of (status, healthy) where status is one of:
        - "ok": Sequencer is reachable and responding
        - "degraded": Sequencer returned an error
        - "unavailable": Sequencer is unreachable
        - "disabled": Go sequencer routing is disabled
    """
    if not use_go_sequencer():
        return ("disabled", True)

    client = get_sequencer_client()
    try:
        await client.get_latest_root()
        return ("ok", True)
    except SequencerUnavailableError:
        return ("unavailable", False)
    except SequencerResponseError:
        return ("degraded", False)

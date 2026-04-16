"""
In-memory record store and cache for the Olympus ingest path.

This module provides LRU-bounded caching for ingestion metadata to enable
fast lookups by proof_id and content_hash. The cache is used for:

1. Fast deduplication checks during ingestion
2. Proof retrieval without hitting the database
3. Content hash verification

When PostgreSQL storage is configured, the cache acts as a read-through
cache backed by durable storage. In test/dev mode without DATABASE_URL,
the cache IS the authoritative store.

Thread Safety:
    The OrderedDict operations are atomic at the Python level, but the
    LRU eviction window between get() and move_to_end() is intentionally
    not locked — a concurrent eviction between these calls simply falls
    back to the persistent store lookup.
"""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from storage.postgres import StorageLayer


logger = logging.getLogger(__name__)


# LRU cache capacity limits to prevent unbounded memory growth under sustained
# ingestion load. When the cache exceeds these limits, the oldest entries are
# evicted.
INGESTION_CACHE_LRU_CAP = 100_000
CONTENT_INDEX_LRU_CAP = 100_000


class IngestRecordStore:
    """In-memory LRU-bounded cache for ingestion records.

    This class manages two related caches:
    - _ingestion_store: Maps proof_id → ingestion metadata dict
    - _content_index: Maps content_hash → proof_id (dedup index)

    Both caches are bounded to prevent OOM under sustained load.
    """

    def __init__(
        self,
        ingestion_cap: int = INGESTION_CACHE_LRU_CAP,
        content_cap: int = CONTENT_INDEX_LRU_CAP,
    ) -> None:
        """Initialize the record store with given capacity limits.

        Args:
            ingestion_cap: Maximum entries in the proof_id → metadata cache.
            content_cap: Maximum entries in the content_hash → proof_id index.
        """
        self._ingestion_store: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._content_index: OrderedDict[str, str] = OrderedDict()
        self._ingestion_cap = ingestion_cap
        self._content_cap = content_cap

    def cache_ingestion_record(self, entry: dict[str, Any]) -> None:
        """Cache ingestion metadata for fast lookups with LRU eviction.

        Implements LRU eviction to prevent unbounded memory growth under sustained
        ingestion load. When the cache exceeds the capacity limit, the oldest
        entries are evicted.

        Args:
            entry: Ingestion metadata dict. Must contain 'proof_id' and 'content_hash'.
                   Should also contain 'poseidon_root' for full functionality.
        """
        poseidon_root = entry.get("poseidon_root")
        if poseidon_root is None:
            # Extract from canonicalization if not at top level
            poseidon_root = entry.get("canonicalization", {}).get("poseidon_root")
            if poseidon_root is not None:
                entry = {**entry, "poseidon_root": poseidon_root}

        proof_id = entry["proof_id"]
        content_hash = entry["content_hash"]

        # Update ingestion store
        self._ingestion_store[proof_id] = entry

        # Evict oldest entries if over capacity
        while len(self._ingestion_store) > self._ingestion_cap:
            evicted_id, evicted_entry = self._ingestion_store.popitem(last=False)
            # Also remove from content index to maintain consistency
            evicted_hash = evicted_entry.get("content_hash")
            if evicted_hash and self._content_index.get(evicted_hash) == evicted_id:
                self._content_index.pop(evicted_hash, None)

        # Update content index
        self._content_index[content_hash] = proof_id
        while len(self._content_index) > self._content_cap:
            self._content_index.popitem(last=False)

    def get_by_proof_id(self, proof_id: str) -> dict[str, Any] | None:
        """Get ingestion metadata by proof_id from cache.

        Args:
            proof_id: The proof identifier to look up.

        Returns:
            The ingestion metadata dict, or None if not in cache.
        """
        return self._ingestion_store.get(proof_id)

    def promote_to_mru(self, proof_id: str) -> bool:
        """Promote a proof_id to most-recently-used position in the cache.

        Args:
            proof_id: The proof identifier to promote.

        Returns:
            True if the entry was promoted, False if it wasn't in the cache.
        """
        try:
            self._ingestion_store.move_to_end(proof_id)
            return True
        except KeyError:
            return False

    def get_proof_id_by_content_hash(self, content_hash: str) -> str | None:
        """Get proof_id for a content hash from the dedup index.

        Args:
            content_hash: The hex-encoded content hash to look up.

        Returns:
            The proof_id if found, None otherwise.
        """
        return self._content_index.get(content_hash)

    def set_content_index(self, content_hash: str, proof_id: str) -> None:
        """Set a content_hash → proof_id mapping in the dedup index.

        Args:
            content_hash: The hex-encoded content hash.
            proof_id: The proof identifier to map to.
        """
        self._content_index[content_hash] = proof_id
        while len(self._content_index) > self._content_cap:
            self._content_index.popitem(last=False)

    def clear(self) -> None:
        """Clear all cached records (for testing)."""
        self._ingestion_store.clear()
        self._content_index.clear()

    @property
    def ingestion_store(self) -> OrderedDict[str, dict[str, Any]]:
        """Direct access to ingestion store (for backward compatibility)."""
        return self._ingestion_store

    @property
    def content_index(self) -> OrderedDict[str, str]:
        """Direct access to content index (for backward compatibility)."""
        return self._content_index


# Module-level singleton for backward compatibility with existing ingest.py code
_record_store = IngestRecordStore()


def get_record_store() -> IngestRecordStore:
    """Get the module-level record store singleton."""
    return _record_store


def reset_record_store_for_tests() -> None:
    """Reset the record store state for tests."""
    _record_store.clear()


# ---------------------------------------------------------------------------
# Persistent storage lookups
# ---------------------------------------------------------------------------


def fetch_persisted_proof_sync(
    proof_id: str, storage: StorageLayer | None = None
) -> dict[str, Any] | None:
    """Synchronously fetch an ingestion record from persistent storage.

    Args:
        proof_id: The proof identifier to look up.
        storage: Optional storage layer. If None, returns None.

    Returns:
        The ingestion metadata dict from storage, or None if not found.
    """
    if storage is None:
        return None

    try:
        return storage.fetch_ingestion_by_proof_id(proof_id)
    except Exception:
        logger.warning("Failed to fetch persisted proof %s", proof_id, exc_info=True)
        return None


async def fetch_persisted_proof(
    proof_id: str, storage: StorageLayer | None = None
) -> dict[str, Any] | None:
    """Asynchronously fetch an ingestion record from persistent storage.

    Runs the synchronous storage lookup in a thread pool executor to avoid
    blocking the async event loop.

    Args:
        proof_id: The proof identifier to look up.
        storage: Optional storage layer. If None, returns None.

    Returns:
        The ingestion metadata dict from storage, or None if not found.
    """
    if storage is None:
        return None

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, fetch_persisted_proof_sync, proof_id, storage
    )


def fetch_by_content_hash_sync(
    content_hash_hex: str,
    record_store: IngestRecordStore | None = None,
    storage: StorageLayer | None = None,
) -> dict[str, Any] | None:
    """Synchronously fetch an ingestion record by content hash.

    Checks the in-memory cache first, then falls back to persistent storage.

    Args:
        content_hash_hex: The hex-encoded BLAKE3 content hash.
        record_store: The in-memory record store to check first.
        storage: Optional storage layer for persistent lookup.

    Returns:
        The ingestion metadata dict, or None if not found.
    """
    if record_store is None:
        record_store = _record_store

    # Check cache first
    proof_id = record_store.get_proof_id_by_content_hash(content_hash_hex)
    if proof_id is not None:
        cached = record_store.get_by_proof_id(proof_id)
        if cached is not None:
            return cached

    # Fall back to storage if configured
    if storage is not None:
        try:
            return storage.fetch_ingestion_by_content_hash(content_hash_hex)
        except Exception:
            logger.warning(
                "Failed to fetch by content hash %s", content_hash_hex, exc_info=True
            )

    return None


async def fetch_by_content_hash(
    content_hash_hex: str,
    record_store: IngestRecordStore | None = None,
    storage: StorageLayer | None = None,
) -> dict[str, Any] | None:
    """Asynchronously fetch an ingestion record by content hash.

    Checks the in-memory cache first, then falls back to persistent storage.

    Args:
        content_hash_hex: The hex-encoded BLAKE3 content hash.
        record_store: The in-memory record store to check first.
        storage: Optional storage layer for persistent lookup.

    Returns:
        The ingestion metadata dict, or None if not found.
    """
    if record_store is None:
        record_store = _record_store

    # Check cache first (synchronous, fast)
    proof_id = record_store.get_proof_id_by_content_hash(content_hash_hex)
    if proof_id is not None:
        cached = record_store.get_by_proof_id(proof_id)
        if cached is not None:
            return cached

    # Fall back to storage if configured
    if storage is None:
        return None

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, fetch_by_content_hash_sync, content_hash_hex, record_store, storage
    )

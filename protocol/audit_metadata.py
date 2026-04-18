"""
Automated audit metadata tracking for Olympus canonicalization.

Every canonicalization operation can be recorded in an append-only audit log
that captures:

- **Input hash** — BLAKE3 of the raw input.
- **Output hash** — BLAKE3 of the canonical output.
- **Canonicalizer version** — exact version string of the pipeline used.
- **Timestamp** — ISO 8601 UTC timestamp.
- **Operator** — identity of the user or service that triggered the operation.
- **Format** — MIME type / format identifier.
- **Metadata** — arbitrary key-value pairs for catalog integration.

The audit log is itself an append-only JSONL file whose entries are
individually hashable and chain-linked (each entry includes the hash of
the previous entry, forming a mini-ledger).

Integration points for external data catalogs (Alation, AWS Glue, Unity
Catalog) can consume the JSONL log or use :func:`create_catalog_entry`
to produce catalog-native metadata records.
"""

from __future__ import annotations

import getpass
import json
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import blake3 as _blake3

from .canonical_json import canonical_json_encode
from .canonicalization_versions import (
    _CANONICAL_MODULE_VERSIONS,
    create_version_manifest,
)
from .canonicalizer import CANONICALIZER_VERSIONS
from .timestamps import current_timestamp


# ---------------------------------------------------------------------------
# Audit entry data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEntry:
    """A single canonicalization audit record.

    Attributes:
        timestamp: ISO 8601 UTC timestamp of the operation.
        operator: Identity of the operator (user/service).
        format_name: MIME type or format identifier.
        input_hash: BLAKE3 hex digest of the raw input.
        output_hash: BLAKE3 hex digest of the canonical output.
        canonicalizer_version: Version string of the canonicalization pipeline.
        previous_hash: BLAKE3 hex digest of the previous audit entry
            (empty string for the first entry).
        entry_hash: BLAKE3 hex digest of this entry's canonical JSON.
        metadata: Arbitrary key-value metadata for catalog integration.
    """

    timestamp: str
    operator: str
    format_name: str
    input_hash: str
    output_hash: str
    canonicalizer_version: str
    previous_hash: str = ""
    entry_hash: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (suitable for JSON)."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Deserialize from a dict."""
        return cls(**data)


def _compute_entry_hash(entry_dict: dict[str, Any]) -> str:
    """Compute the BLAKE3 hash of an audit entry's canonical JSON.

    The ``entry_hash`` field is excluded from the hash computation to avoid
    circular dependency.

    Args:
        entry_dict: Serialized audit entry.

    Returns:
        Hex-encoded BLAKE3 digest.
    """
    hashable = {k: v for k, v in sorted(entry_dict.items()) if k != "entry_hash"}
    canonical = canonical_json_encode(hashable)
    return _blake3.blake3(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Audit log writer
# ---------------------------------------------------------------------------


class AuditLog:
    """Thread-safe append-only audit log for canonicalization operations.

    Each entry is chain-linked to the previous one via ``previous_hash``,
    forming a tamper-evident mini-ledger.

    Usage::

        log = AuditLog("/var/log/olympus/canonicalization_audit.jsonl")
        entry = log.record(
            format_name="application/json",
            input_hash="abc123...",
            output_hash="def456...",
        )
    """

    def __init__(
        self,
        log_path: str | Path,
        *,
        operator: str | None = None,
    ) -> None:
        """Initialize the audit log.

        Args:
            log_path: Path to the JSONL audit log file (created if missing).
            operator: Default operator name.  Falls back to
                ``OLYMPUS_OPERATOR`` env var, then ``getpass.getuser()``.
        """
        self._path = Path(log_path)
        self._lock = threading.Lock()
        self._operator = operator or os.environ.get("OLYMPUS_OPERATOR", "") or _safe_getuser()
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        """Read the last entry's hash to continue the chain.

        Returns:
            Hash of the last entry, or empty string if log is empty/missing.
        """
        if not self._path.exists():
            return ""
        try:
            last_line = ""
            with self._path.open(encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
            if not last_line:
                return ""
            entry = json.loads(last_line)
            return entry.get("entry_hash", "")
        except (json.JSONDecodeError, OSError):
            return ""

    def record(
        self,
        *,
        format_name: str,
        input_hash: str,
        output_hash: str,
        operator: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> AuditEntry:
        """Record a canonicalization event.

        Thread-safe: multiple threads may call ``record()`` concurrently.

        Args:
            format_name: MIME type or format identifier.
            input_hash: BLAKE3 hex of the raw input.
            output_hash: BLAKE3 hex of the canonical output.
            operator: Override operator for this entry.
            metadata: Extra key-value metadata.

        Returns:
            The persisted :class:`AuditEntry`.
        """
        version = _resolve_version(format_name)
        ts = current_timestamp()

        with self._lock:
            entry_dict: dict[str, Any] = {
                "timestamp": ts,
                "operator": operator or self._operator,
                "format_name": format_name,
                "input_hash": input_hash,
                "output_hash": output_hash,
                "canonicalizer_version": version,
                "previous_hash": self._last_hash,
                "metadata": metadata or {},
            }
            entry_hash = _compute_entry_hash(entry_dict)
            entry_dict["entry_hash"] = entry_hash

            entry = AuditEntry(**entry_dict)

            # Append to log
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(canonical_json_encode(entry_dict))
                fh.write("\n")

            self._last_hash = entry_hash

        return entry

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify the integrity of the audit log chain.

        Returns:
            Tuple of ``(is_valid, entry_count, message)``.
        """
        if not self._path.exists():
            return True, 0, "Audit log does not exist (empty chain)"

        previous_hash = ""
        count = 0

        with self._path.open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                try:
                    entry_dict = json.loads(stripped)
                except json.JSONDecodeError:
                    return False, count, f"Line {lineno}: invalid JSON"

                # Verify chain linkage
                if entry_dict.get("previous_hash", "") != previous_hash:
                    return (
                        False,
                        count,
                        f"Line {lineno}: chain break — expected previous_hash "
                        f"'{previous_hash}', got '{entry_dict.get('previous_hash')}'",
                    )

                # Verify entry hash
                expected_hash = _compute_entry_hash(entry_dict)
                if entry_dict.get("entry_hash", "") != expected_hash:
                    return (
                        False,
                        count,
                        f"Line {lineno}: entry_hash mismatch — "
                        f"expected '{expected_hash}', got '{entry_dict.get('entry_hash')}'",
                    )

                previous_hash = entry_dict["entry_hash"]
                count += 1

        return True, count, f"Chain valid: {count} entries"

    @property
    def path(self) -> Path:
        """Return the log file path."""
        return self._path


# ---------------------------------------------------------------------------
# Data catalog integration helpers
# ---------------------------------------------------------------------------


def create_catalog_entry(
    *,
    dataset_name: str,
    format_name: str,
    input_hash: str,
    output_hash: str,
    operator: str | None = None,
    tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create a metadata record suitable for data catalog ingestion.

    The returned dictionary conforms to a common catalog schema that can
    be adapted to Alation, AWS Glue, Unity Catalog, or any JSON-based
    catalog API.

    Args:
        dataset_name: Human-readable name of the dataset.
        format_name: MIME type or format identifier.
        input_hash: BLAKE3 hex of the raw input.
        output_hash: BLAKE3 hex of the canonical output.
        operator: Identity of the operator.
        tags: Extra key-value tags for catalog indexing.

    Returns:
        Catalog metadata dictionary.
    """
    version = _resolve_version(format_name)
    return {
        "dataset_name": dataset_name,
        "format": format_name,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "canonicalizer_version": version,
        "version_manifest": create_version_manifest(),
        "timestamp": current_timestamp(),
        "operator": operator or os.environ.get("OLYMPUS_OPERATOR", "") or _safe_getuser(),
        "tags": tags or {},
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_version(format_name: str) -> str:
    """Resolve the canonicalizer version for a format name.

    Checks both ``CANONICALIZER_VERSIONS`` (canonicalizer.py formats)
    and ``_CANONICAL_MODULE_VERSIONS`` (canonical.py formats).

    Args:
        format_name: Format name or MIME type.

    Returns:
        Version string, or ``"unknown"`` if format is not recognized.
    """
    # Normalize MIME types to short format names
    _mime_map: dict[str, str] = {
        "application/json": "jcs",
        "text/html": "html",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        "application/pdf": "pdf",
        "text/plain": "plaintext",
        "text/xml": "xml",
        "application/xml": "xml",
        "text/csv": "csv",
        "text/tab-separated-values": "csv",
    }
    short_name = _mime_map.get(format_name, format_name)

    if short_name in CANONICALIZER_VERSIONS:
        return CANONICALIZER_VERSIONS[short_name]
    if short_name in _CANONICAL_MODULE_VERSIONS:
        return _CANONICAL_MODULE_VERSIONS[short_name]
    return "unknown"


def _safe_getuser() -> str:
    """Return the current username, or ``'unknown'`` on failure."""
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"

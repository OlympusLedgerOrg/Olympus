"""
Cryptographic utilities for the ingest-parser service.

Provides BLAKE3 and SHA256 hashing with deterministic, verifiable outputs.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO

import blake3


def compute_blake3(data: bytes) -> str:
    """Compute BLAKE3 hash of raw bytes.

    Args:
        data: Raw bytes to hash.

    Returns:
        BLAKE3 hash prefixed with 'blake3_' (e.g., 'blake3_abc123...').
    """
    digest = blake3.blake3(data).hexdigest()
    return f"blake3_{digest}"


def compute_blake3_file(file_path: Path | str) -> str:
    """Compute BLAKE3 hash of a file.

    Reads the file in chunks to handle large files efficiently.

    Args:
        file_path: Path to the file to hash.

    Returns:
        BLAKE3 hash prefixed with 'blake3_' (e.g., 'blake3_abc123...').
    """
    hasher = blake3.blake3()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return f"blake3_{hasher.hexdigest()}"


def compute_blake3_stream(stream: BinaryIO) -> str:
    """Compute BLAKE3 hash of a binary stream.

    Reads the stream in chunks to handle large files efficiently.
    The stream position is reset to the beginning after hashing.

    Args:
        stream: Binary file-like object to hash.

    Returns:
        BLAKE3 hash prefixed with 'blake3_' (e.g., 'blake3_abc123...').
    """
    hasher = blake3.blake3()
    initial_pos = stream.tell()

    for chunk in iter(lambda: stream.read(65536), b""):
        hasher.update(chunk)

    stream.seek(initial_pos)
    return f"blake3_{hasher.hexdigest()}"


def compute_sha256(data: bytes) -> str:
    """Compute SHA256 hash of raw bytes.

    Args:
        data: Raw bytes to hash.

    Returns:
        SHA256 hash prefixed with 'sha256_' (e.g., 'sha256_abc123...').
    """
    digest = hashlib.sha256(data).hexdigest()
    return f"sha256_{digest}"


def compute_sha256_file(file_path: Path | str) -> str:
    """Compute SHA256 hash of a file.

    Reads the file in chunks to handle large files efficiently.

    Args:
        file_path: Path to the file to hash.

    Returns:
        SHA256 hash prefixed with 'sha256_' (e.g., 'sha256_abc123...').
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return f"sha256_{hasher.hexdigest()}"


def compute_sha256_directory(dir_path: Path | str) -> str:
    """Compute SHA256 hash of a directory's contents.

    Recursively hashes all files in the directory in sorted order,
    producing a deterministic hash of the entire directory tree.

    Args:
        dir_path: Path to the directory to hash.

    Returns:
        SHA256 hash prefixed with 'sha256_' (e.g., 'sha256_abc123...').
    """
    dir_path = Path(dir_path)
    hasher = hashlib.sha256()

    # Get all files in sorted order for determinism
    files = sorted(dir_path.rglob("*"))

    for file_path in files:
        if file_path.is_file():
            # Include relative path in hash for structure-sensitivity
            rel_path = file_path.relative_to(dir_path)
            hasher.update(str(rel_path).encode("utf-8"))
            hasher.update(b"\x00")  # Null separator

            # Hash file contents
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)

    return f"sha256_{hasher.hexdigest()}"


def verify_hash(expected: str, actual: str) -> bool:
    """Verify that two hashes match.

    Performs constant-time comparison to prevent timing attacks.

    Args:
        expected: The expected hash value.
        actual: The actual computed hash value.

    Returns:
        True if hashes match, False otherwise.
    """
    import hmac

    return hmac.compare_digest(expected, actual)

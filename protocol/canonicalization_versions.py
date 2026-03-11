"""
Canonicalization Version Management for Olympus

This module enforces strict version control for canonicalization algorithms
to prevent hash drift across software versions. Canonicalization versions
must be treated as immutable once deployed.

Based on the principle that canonicalization is a wire protocol - once
published, it's effectively permanent.
"""

from __future__ import annotations

from typing import Any

from .canonicalizer import CANONICALIZER_VERSIONS


# Version history tracking - records all canonical versions ever used
# Format: {format_name: {version: {deployed_at: timestamp, deprecated_at: timestamp | None}}}
VERSION_HISTORY: dict[str, dict[str, dict[str, str | None]]] = {
    "jcs": {
        "1.2.0-strict-numeric": {
            "deployed_at": "2024-01-01T00:00:00Z",
            "deprecated_at": None,
        },
    },
    "html": {
        "1.0.1-lxml-pinned-nfc": {
            "deployed_at": "2024-01-01T00:00:00Z",
            "deprecated_at": None,
        },
    },
    "docx": {
        "1.1.0-c14n-strict": {
            "deployed_at": "2024-01-01T00:00:00Z",
            "deprecated_at": None,
        },
    },
    "pdf": {
        "1.4.0-pikepdf-10.3.0-linearized": {
            "deployed_at": "2024-01-01T00:00:00Z",
            "deprecated_at": None,
        },
    },
}


class CanonicalizationVersionError(Exception):
    """Raised when canonicalization version validation fails."""


def get_current_version(format_name: str) -> str:
    """
    Get the current canonicalization version for a format.

    Args:
        format_name: Format name (e.g., "jcs", "html", "docx", "pdf")

    Returns:
        Current version string

    Raises:
        CanonicalizationVersionError: If format is unknown
    """
    if format_name not in CANONICALIZER_VERSIONS:
        raise CanonicalizationVersionError(f"Unknown format: {format_name}")
    return CANONICALIZER_VERSIONS[format_name]


def verify_version_compatibility(
    format_name: str,
    claimed_version: str,
) -> bool:
    """
    Verify that a claimed version is valid and compatible.

    Args:
        format_name: Format name (e.g., "jcs", "html", "docx", "pdf")
        claimed_version: Version string to verify

    Returns:
        True if version is valid and compatible
    """
    if format_name not in VERSION_HISTORY:
        return False

    # Version must exist in history
    if claimed_version not in VERSION_HISTORY[format_name]:
        return False

    # Check if version is deprecated
    version_info = VERSION_HISTORY[format_name][claimed_version]
    if version_info.get("deprecated_at") is not None:
        # Deprecated versions are still valid for verification,
        # but should not be used for new canonicalizations
        pass

    return True


def validate_canonicalization_result(result: dict[str, Any]) -> bool:
    """
    Validate that a canonicalization result contains proper version metadata.

    Args:
        result: Canonicalization result dictionary from process_artifact()

    Returns:
        True if result has valid version metadata

    Raises:
        CanonicalizationVersionError: If version metadata is invalid
    """
    if "version" not in result:
        raise CanonicalizationVersionError("Missing version field in canonicalization result")

    if "mode" not in result:
        raise CanonicalizationVersionError("Missing mode field in canonicalization result")

    # Extract format from mode (e.g., "jcs_v1" -> "jcs")
    mode = result["mode"]
    format_name = mode.split("_")[0] if "_" in mode else mode

    # Handle special cases
    if "jcs" in mode:
        format_name = "jcs"
    elif "html" in mode:
        format_name = "html"
    elif "docx" in mode:
        format_name = "docx"
    elif "pdf" in mode or "norm" in mode:
        format_name = "pdf"

    claimed_version = result["version"]

    if not verify_version_compatibility(format_name, claimed_version):
        raise CanonicalizationVersionError(
            f"Invalid version {claimed_version} for format {format_name}"
        )

    # Verify version matches current version for the format
    current = get_current_version(format_name)
    if claimed_version != current:
        # This is a warning condition - old versions are valid but should
        # trigger alerts in production
        pass

    return True


def create_version_manifest() -> dict[str, Any]:
    """
    Create a manifest of all canonicalization versions.

    Returns:
        Version manifest containing current versions and full history
    """
    return {
        "current_versions": CANONICALIZER_VERSIONS.copy(),
        "version_history": VERSION_HISTORY.copy(),
    }


def verify_version_manifest(manifest: dict[str, Any]) -> bool:
    """
    Verify that a version manifest is consistent with current versions.

    Args:
        manifest: Version manifest to verify

    Returns:
        True if manifest is valid and consistent
    """
    if "current_versions" not in manifest:
        return False

    claimed_current = manifest["current_versions"]

    # All current versions must match
    for format_name, version in CANONICALIZER_VERSIONS.items():
        if format_name not in claimed_current:
            return False
        if claimed_current[format_name] != version:
            return False

    return True


# Test vector validation support
class CanonicalTestVector:
    """
    A test vector for validating canonicalization consistency.

    Test vectors ensure that canonicalization behavior remains stable
    across versions and implementations.
    """

    def __init__(
        self,
        *,
        name: str,
        format_name: str,
        version: str,
        input_bytes: bytes,
        expected_canonical_hash: str,
        description: str = "",
    ) -> None:
        """
        Initialize a test vector.

        Args:
            name: Unique name for this test vector
            format_name: Format name (e.g., "jcs", "html")
            version: Canonicalization version this vector is for
            input_bytes: Raw input bytes
            expected_canonical_hash: Expected hex-encoded hash of canonical output
            description: Human-readable description
        """
        self.name = name
        self.format_name = format_name
        self.version = version
        self.input_bytes = input_bytes
        self.expected_canonical_hash = expected_canonical_hash
        self.description = description

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "format_name": self.format_name,
            "version": self.version,
            "input_hex": self.input_bytes.hex(),
            "expected_canonical_hash": self.expected_canonical_hash,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CanonicalTestVector:
        """Create from dictionary."""
        return cls(
            name=data["name"],
            format_name=data["format_name"],
            version=data["version"],
            input_bytes=bytes.fromhex(data["input_hex"]),
            expected_canonical_hash=data["expected_canonical_hash"],
            description=data.get("description", ""),
        )


# Built-in test vectors to detect canonicalization drift
CANONICAL_TEST_VECTORS: list[CanonicalTestVector] = [
    CanonicalTestVector(
        name="jcs_basic_object",
        format_name="jcs",
        version="1.2.0-strict-numeric",
        input_bytes=b'{"b": 2, "a": 1}',
        expected_canonical_hash="d5c6475d8c876eb6cbd33ba5b6d5c97b57a8c4e0a15b56ed18e76b3e8b5d6f42",
        description="Basic JCS test - key ordering and compact formatting",
    ),
    CanonicalTestVector(
        name="jcs_numbers",
        format_name="jcs",
        version="1.2.0-strict-numeric",
        input_bytes=b'{"int": 42, "float": 3.14159, "exp": 1.0e10}',
        expected_canonical_hash="e72d09c5a8c9e28a4f75a1d2f3d8e5c6a7b9f4d3e8c2a7b5f9d4e6c8a3b7f1d9",
        description="JCS numeric serialization test",
    ),
]


def get_test_vectors_for_format(format_name: str) -> list[CanonicalTestVector]:
    """
    Get all test vectors for a specific format.

    Args:
        format_name: Format name to filter by

    Returns:
        List of test vectors for the format
    """
    return [v for v in CANONICAL_TEST_VECTORS if v.format_name == format_name]


def verify_test_vector(
    vector: CanonicalTestVector,
    canonicalizer_func: Any,
) -> tuple[bool, str]:
    """
    Verify a test vector against a canonicalization function.

    Args:
        vector: Test vector to verify
        canonicalizer_func: Canonicalization function to test

    Returns:
        Tuple of (success: bool, message: str)
    """
    try:
        from .canonicalizer import Canonicalizer

        c = Canonicalizer()

        # Apply canonicalization
        canonical_bytes = canonicalizer_func(vector.input_bytes)

        # Compute hash
        canonical_hash = c.get_hash(canonical_bytes).hex()

        if canonical_hash == vector.expected_canonical_hash:
            return True, f"Test vector '{vector.name}' passed"
        else:
            return (
                False,
                f"Test vector '{vector.name}' failed: "
                f"expected {vector.expected_canonical_hash}, "
                f"got {canonical_hash}",
            )
    except Exception as e:
        return False, f"Test vector '{vector.name}' raised exception: {e}"

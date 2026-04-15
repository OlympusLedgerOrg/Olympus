"""Shared helpers for storage-layer session gate derivation."""

from __future__ import annotations

import logging
import os

import blake3


logger = logging.getLogger(__name__)


def derive_node_rehash_gate() -> str:
    """Derive the session gate value for SMT trigger-protected writes.

    The gate mixes a domain prefix with an optional deployment-specific
    secret from the ``OLYMPUS_NODE_REHASH_GATE_SECRET`` environment variable.

    In **production** (``OLYMPUS_ENV`` is ``"production"`` or unset), the
    secret is **required** — a ``RuntimeError`` is raised if it is missing
    or empty. This prevents the gate value from being derivable from source
    code alone.

    In **development** or **test** mode, the secret is recommended but not
    required. A warning is logged when operating without the secret.

    Returns:
        Hex-encoded BLAKE3 digest used as the session gate value.

    Raises:
        RuntimeError: If running in production without a gate secret.
    """
    olympus_env = os.getenv("OLYMPUS_ENV", "production").lower()
    gate_secret = os.getenv("OLYMPUS_NODE_REHASH_GATE_SECRET", "")

    if not gate_secret:
        if olympus_env in ("development", "test"):
            logger.warning(
                "OLYMPUS_NODE_REHASH_GATE_SECRET is not set. "
                "Using deterministic gate value. This is acceptable for "
                "development/test but MUST NOT be used in production."
            )
        else:
            raise RuntimeError(
                "OLYMPUS_NODE_REHASH_GATE_SECRET must be set in production. "
                'Generate with: python -c "import secrets; print(secrets.token_hex(32))"'
            )

    hasher = blake3.blake3()
    hasher.update(b"OLY:NODE-REHASH-GATE:V1")
    if gate_secret:
        hasher.update(b"|")
        hasher.update(gate_secret.encode("utf-8"))
    return hasher.hexdigest()

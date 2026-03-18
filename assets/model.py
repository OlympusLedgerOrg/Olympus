"""Data model stubs for Olympus assets.

This module intentionally defines only immutable data shapes. Business logic
(minting, transfer, valuation, ownership, reputation) is out of scope for now.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AssetID:
    """Versioned, algorithm-scoped asset identifier."""

    version: str
    algorithm: str
    digest: str


@dataclass(frozen=True)
class ProofAsset:
    """Schema-aligned proof asset shape with required non-null ZK public inputs."""

    version: str
    asset_id: AssetID
    canonical_claim: dict[str, Any]
    merkle_root: str
    zk_public_inputs: dict[str, Any]
    verification_bundle: dict[str, Any]
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class DatasetAsset:
    """Schema-aligned dataset asset shape."""

    version: str
    asset_id: AssetID
    dataset_descriptor: dict[str, Any]
    canonical_claim: dict[str, Any]
    merkle_root: str
    zk_public_inputs: dict[str, Any] | None
    verification_bundle: dict[str, Any]
    metadata: dict[str, Any] | None = None

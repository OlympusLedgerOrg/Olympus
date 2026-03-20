"""
HTTP transport layer for witness protocol.

This module provides HTTP client utilities for witnesses to fetch Signed Tree
Heads (STHs) and consistency proofs from remote Olympus nodes. Witnesses use
these to monitor multiple nodes and detect split-view attacks.

This is a Phase 1+ feature implementing the witness protocol described in
docs/17_signed_checkpoints.md.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

from .consistency import ConsistencyProof
from .epochs import SignedTreeHead


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NodeEndpoint:
    """Configuration for a monitored Olympus node endpoint."""

    node_id: str
    base_url: str
    timeout_seconds: float = 30.0


class WitnessTransportError(Exception):
    """Base exception for witness transport errors."""

    pass


class WitnessHTTPTransport:
    """
    HTTP transport for fetching STHs and consistency proofs from Olympus nodes.

    This class provides the network layer for witness monitoring, allowing
    witnesses to collect and compare STHs from multiple nodes.
    """

    def __init__(
        self,
        endpoints: list[NodeEndpoint],
        *,
        http_client: Any | None = None,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialize witness transport with node endpoints.

        Args:
            endpoints: List of node endpoints to monitor
            http_client: Optional httpx client (for testing). If None, creates one.
            verify_ssl: Whether to verify SSL certificates (default True)

        Raises:
            ImportError: If httpx is not installed
        """
        if httpx is None:
            raise ImportError(
                "httpx is required for witness transport. Install with: pip install httpx"
            )

        self.endpoints = {ep.node_id: ep for ep in endpoints}
        self.verify_ssl = verify_ssl

        if http_client is None:
            self._client = httpx.Client(verify=verify_ssl)
            self._owns_client = True
        else:
            self._client = http_client
            self._owns_client = False

    def __enter__(self) -> WitnessHTTPTransport:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit - close client if we own it."""
        if self._owns_client and self._client is not None:
            self._client.close()

    def close(self) -> None:
        """Close the HTTP client if we own it."""
        if self._owns_client and self._client is not None:
            self._client.close()

    def fetch_sth(self, node_id: str, shard_id: str) -> SignedTreeHead:
        """
        Fetch the latest Signed Tree Head from a node.

        Args:
            node_id: Identifier of the node to query
            shard_id: Shard identifier

        Returns:
            Latest SignedTreeHead for the shard

        Raises:
            WitnessTransportError: If the fetch fails or response is invalid
            ValueError: If node_id is not in configured endpoints
        """
        endpoint = self.endpoints.get(node_id)
        if endpoint is None:
            raise ValueError(f"Unknown node_id: {node_id}")

        url = f"{endpoint.base_url}/protocol/sth/latest"
        params = {"shard_id": shard_id}

        try:
            response = self._client.get(
                url,
                params=params,
                timeout=endpoint.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()

            # Convert response to SignedTreeHead
            # Note: The actual STH response format from api/sth.py uses a different
            # structure than protocol/epochs.py SignedTreeHead. This is a simplified
            # adapter that would need proper mapping in production.
            return SignedTreeHead(
                epoch_id=data["epoch_id"],
                tree_size=data["tree_size"],
                merkle_root=data["merkle_root"],
                timestamp=data["timestamp"],
                signature=data["signature"],
                signer_pubkey=data["signer_pubkey"],
            )

        except httpx.HTTPError as e:
            raise WitnessTransportError(
                f"Failed to fetch STH from {node_id} for shard {shard_id}: {e}"
            ) from e
        except (KeyError, ValueError) as e:
            raise WitnessTransportError(
                f"Invalid STH response from {node_id} for shard {shard_id}: {e}"
            ) from e

    def fetch_sth_history(
        self,
        node_id: str,
        shard_id: str,
        count: int = 10,
    ) -> list[SignedTreeHead]:
        """
        Fetch recent STH history from a node.

        Args:
            node_id: Identifier of the node to query
            shard_id: Shard identifier
            count: Number of historical STHs to retrieve (default 10)

        Returns:
            List of SignedTreeHeads in reverse chronological order

        Raises:
            WitnessTransportError: If the fetch fails or response is invalid
            ValueError: If node_id is not in configured endpoints
        """
        endpoint = self.endpoints.get(node_id)
        if endpoint is None:
            raise ValueError(f"Unknown node_id: {node_id}")

        url = f"{endpoint.base_url}/protocol/sth/history"
        params = {"shard_id": shard_id, "n": count}

        try:
            response = self._client.get(
                url,
                params=params,
                timeout=endpoint.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()

            sths = []
            for sth_data in data.get("sths", []):
                sths.append(
                    SignedTreeHead(
                        epoch_id=sth_data["epoch_id"],
                        tree_size=sth_data["tree_size"],
                        merkle_root=sth_data["merkle_root"],
                        timestamp=sth_data["timestamp"],
                        signature=sth_data["signature"],
                        signer_pubkey=sth_data["signer_pubkey"],
                    )
                )
            return sths

        except httpx.HTTPError as e:
            raise WitnessTransportError(
                f"Failed to fetch STH history from {node_id} for shard {shard_id}: {e}"
            ) from e
        except (KeyError, ValueError) as e:
            raise WitnessTransportError(
                f"Invalid STH history response from {node_id} for shard {shard_id}: {e}"
            ) from e

    def fetch_consistency_proof(
        self,
        node_id: str,
        shard_id: str,
        old_size: int,
        new_size: int,
    ) -> ConsistencyProof:
        """
        Fetch a Merkle consistency proof from a node.

        Args:
            node_id: Identifier of the node to query
            shard_id: Shard identifier
            old_size: Tree size of the older STH
            new_size: Tree size of the newer STH

        Returns:
            ConsistencyProof demonstrating append-only growth

        Raises:
            WitnessTransportError: If the fetch fails or response is invalid
            ValueError: If node_id is not in configured endpoints
        """
        endpoint = self.endpoints.get(node_id)
        if endpoint is None:
            raise ValueError(f"Unknown node_id: {node_id}")

        # Note: This endpoint doesn't exist in the current API but would be needed
        # for full witness protocol implementation
        url = f"{endpoint.base_url}/protocol/consistency-proof"
        params = {
            "shard_id": shard_id,
            "old_size": old_size,
            "new_size": new_size,
        }

        try:
            response = self._client.get(
                url,
                params=params,
                timeout=endpoint.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()

            # Convert hex-encoded proof elements to bytes
            proof_hashes = [bytes.fromhex(h) for h in data["proof"]]

            return ConsistencyProof(
                old_size=data["old_size"],
                new_size=data["new_size"],
                proof=proof_hashes,
            )

        except httpx.HTTPError as e:
            raise WitnessTransportError(
                f"Failed to fetch consistency proof from {node_id}: {e}"
            ) from e
        except (KeyError, ValueError) as e:
            raise WitnessTransportError(
                f"Invalid consistency proof response from {node_id}: {e}"
            ) from e

    def create_sth_fetcher(self) -> Callable[[str, str], SignedTreeHead]:
        """
        Create an STH fetcher callback for use with LogMonitor.

        Returns:
            Callable that fetches STH for (node_id, shard_id) pairs
        """
        return self.fetch_sth

    def create_consistency_fetcher(
        self,
    ) -> Callable[[str, str, int, int], ConsistencyProof]:
        """
        Create a consistency proof fetcher callback for use with LogMonitor.

        Returns:
            Callable that fetches consistency proofs
        """
        return self.fetch_consistency_proof


def create_witness_transport(
    endpoints: list[dict[str, Any]],
    **kwargs: Any,
) -> WitnessHTTPTransport:
    """
    Factory function to create a WitnessHTTPTransport from configuration.

    Args:
        endpoints: List of endpoint configurations with keys:
            - node_id: Node identifier
            - base_url: Base URL of the node API
            - timeout_seconds: Optional timeout (default 30.0)
        **kwargs: Additional arguments passed to WitnessHTTPTransport

    Returns:
        Configured WitnessHTTPTransport instance

    Example:
        >>> endpoints = [
        ...     {"node_id": "node-1", "base_url": "https://olympus1.example.com"},
        ...     {"node_id": "node-2", "base_url": "https://olympus2.example.com"},
        ... ]
        >>> transport = create_witness_transport(endpoints)
        >>> with transport:
        ...     sth = transport.fetch_sth("node-1", "shard-0")
    """
    node_endpoints = [
        NodeEndpoint(
            node_id=ep["node_id"],
            base_url=ep["base_url"],
            timeout_seconds=ep.get("timeout_seconds", 30.0),
        )
        for ep in endpoints
    ]
    return WitnessHTTPTransport(node_endpoints, **kwargs)

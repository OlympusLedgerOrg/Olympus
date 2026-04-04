"""
HTTP transport layer for witness protocol.

This module provides HTTP client utilities for witnesses to fetch Signed Tree
Heads (STHs) and consistency proofs from remote Olympus nodes. Witnesses use
these to monitor multiple nodes and detect split-view attacks.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar
from urllib.parse import urlparse

import httpx

from protocol.consistency import ConsistencyProof
from protocol.epochs import SignedTreeHead


T = TypeVar("T")


@dataclass(frozen=True)
class NodeEndpoint:
    """Configuration for a monitored Olympus node endpoint (default timeout 10s)."""

    node_id: str
    base_url: str
    timeout_seconds: float = 10.0  # Default timeout in seconds.

    def __post_init__(self) -> None:
        _env = os.environ.get("OLYMPUS_ENV", "production")
        _validate_endpoint_url(
            self.base_url,
            allow_http=(_env == "development"),
        )


def _validate_endpoint_url(url: str, *, allow_http: bool = False) -> None:
    """Validate a witness endpoint URL against SSRF risks.

    Args:
        url: The base URL to validate.
        allow_http: If True, permit http:// in addition to https://.
                    Only set True in development/test contexts.

    Raises:
        ValueError: If the URL scheme is not permitted or the host
                    resolves to a private/loopback address.
    """
    parsed = urlparse(url)

    permitted_schemes = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme not in permitted_schemes:
        raise ValueError(
            f"Witness endpoint URL scheme {parsed.scheme!r} is not permitted. "
            f"Only {sorted(permitted_schemes)} are allowed."
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Witness endpoint URL must include a hostname.")

    # Block private and loopback ranges to prevent SSRF.
    # ip_address() raises ValueError for DNS names (not an IP literal) — ignore those.
    # Only raise when the hostname IS a valid IP that falls in a restricted range.
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return  # DNS hostname — not an IP literal, no range check needed

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        _env = os.environ.get("OLYMPUS_ENV", "production")
        if _env != "development":
            raise ValueError(
                f"Witness endpoint hostname {hostname!r} resolves to a "
                f"private/loopback address. This is not permitted in "
                f"production to prevent SSRF attacks."
            )


class WitnessHTTPTransport:
    """
    HTTP transport for fetching STHs and consistency proofs from Olympus nodes.

    This class provides the network layer for witness monitoring, allowing
    witnesses to collect and compare STHs from multiple nodes.
    """

    def __init__(
        self, endpoints: list[NodeEndpoint], http_client: httpx.AsyncClient | None = None
    ) -> None:
        """
        Initialize witness transport with node endpoints.

        Args:
            endpoints: List of node endpoints to monitor.
            http_client: Optional async HTTP client for testing or reuse.
        """
        self.endpoints = {endpoint.node_id: endpoint for endpoint in endpoints}
        self._client = http_client or httpx.AsyncClient()
        self._owns_client = http_client is None

    async def close(self) -> None:
        """Close the HTTP client if owned by this transport."""
        if self._owns_client:
            await self._client.aclose()

    def _require_endpoint(self, node_id: str) -> NodeEndpoint:
        endpoint = self.endpoints.get(node_id)
        if endpoint is None:
            raise ValueError(f"Unknown node_id: {node_id}")
        return endpoint

    async def fetch_sth(self, node_id: str, shard_id: str) -> SignedTreeHead:
        """
        Fetch the latest Signed Tree Head from a node.

        Args:
            node_id: Identifier of the node to query.
            shard_id: Shard identifier.

        Returns:
            Latest SignedTreeHead for the shard.
        """
        endpoint = self._require_endpoint(node_id)
        url = f"{endpoint.base_url}/witness/sth/{shard_id}"
        response = await self._client.get(url, timeout=endpoint.timeout_seconds)
        response.raise_for_status()
        return SignedTreeHead.from_dict(response.json())

    async def fetch_consistency_proof(
        self,
        node_id: str,
        shard_id: str,
        old_size: int,
        new_size: int,
    ) -> ConsistencyProof:
        """
        Fetch a Merkle consistency proof from a node.

        Args:
            node_id: Identifier of the node to query.
            shard_id: Shard identifier.
            old_size: Tree size of the older STH.
            new_size: Tree size of the newer STH.

        Returns:
            ConsistencyProof demonstrating append-only growth.
        """
        endpoint = self._require_endpoint(node_id)
        url = f"{endpoint.base_url}/witness/consistency/{shard_id}"
        params = {"from": old_size, "to": new_size}
        response = await self._client.get(
            url,
            params=params,
            timeout=endpoint.timeout_seconds,
        )
        response.raise_for_status()
        return ConsistencyProof.from_dict(response.json())

    def _run_sync(self, coro: Awaitable[T]) -> T:
        loop, owns_loop = self._select_loop()
        if loop.is_running():
            raise RuntimeError("Cannot use sync wrapper while an event loop is running")
        try:
            return loop.run_until_complete(coro)
        finally:
            if owns_loop:
                loop.close()
                asyncio.set_event_loop(None)

    def _select_loop(self) -> tuple[asyncio.AbstractEventLoop, bool]:
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop, True
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop, True
        return loop, False

    def create_sth_fetcher(self) -> Callable[[str, str], SignedTreeHead]:
        """
        Create an STH fetcher callback for use with LogMonitor.

        Returns:
            Callable that fetches STH for (node_id, shard_id) pairs.
        """

        def _fetch(node_id: str, shard_id: str) -> SignedTreeHead:
            return self._run_sync(self.fetch_sth(node_id, shard_id))

        return _fetch

    def create_consistency_fetcher(
        self,
    ) -> Callable[[str, str, int, int], ConsistencyProof]:
        """
        Create a consistency proof fetcher callback for use with LogMonitor.

        Returns:
            Callable that fetches consistency proofs.
        """

        def _fetch(node_id: str, shard_id: str, old_size: int, new_size: int) -> ConsistencyProof:
            return self._run_sync(
                self.fetch_consistency_proof(node_id, shard_id, old_size, new_size)
            )

        return _fetch


def create_witness_transport(endpoints: list[dict[str, Any]]) -> WitnessHTTPTransport:
    """
    Factory function to create a WitnessHTTPTransport from configuration.

    Args:
        endpoints: List of endpoint configurations with keys:
            - node_id: Node identifier.
            - base_url: Base URL of the node API.
            - timeout_seconds: Optional timeout (default 10.0).

    Returns:
        Configured WitnessHTTPTransport instance.
    """
    node_endpoints = [
        NodeEndpoint(
            node_id=endpoint["node_id"],
            base_url=endpoint["base_url"],
            timeout_seconds=endpoint.get("timeout_seconds", 10.0),
        )
        for endpoint in endpoints
    ]
    return WitnessHTTPTransport(node_endpoints)

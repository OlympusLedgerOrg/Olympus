import asyncio

import httpx
import nacl.signing
import pytest

from protocol.consistency import ConsistencyProof, generate_consistency_proof
from protocol.epochs import SignedTreeHead
from protocol.hashes import hash_bytes
from protocol.merkle import MerkleTree
from protocol.monitoring import LogMonitor
from protocol.witness_transport import NodeEndpoint, WitnessHTTPTransport


@pytest.mark.asyncio
async def test_fetch_sth_parses_response():
    signing_key = nacl.signing.SigningKey.generate()
    sth = SignedTreeHead.create(
        epoch_id=1,
        tree_size=3,
        merkle_root=hash_bytes(b"root-1"),
        signing_key=signing_key,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/witness/sth/shard-1"
        return httpx.Response(200, json=sth.to_dict())

    mock_transport = httpx.MockTransport(handler)
    transport = WitnessHTTPTransport([NodeEndpoint(node_id="node-1", base_url="https://node")])
    await transport._client.aclose()
    transport._client = httpx.AsyncClient(transport=mock_transport)

    try:
        fetched = await transport.fetch_sth("node-1", "shard-1")
        assert fetched == sth
    finally:
        await transport._client.aclose()


@pytest.mark.asyncio
async def test_fetch_consistency_proof_parses_response():
    proof = ConsistencyProof(
        old_tree_size=2,
        new_tree_size=4,
        proof_nodes=[hash_bytes(b"proof-1"), hash_bytes(b"proof-2")],
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/witness/consistency/shard-2"
        assert dict(request.url.params) == {"from": "2", "to": "4"}
        return httpx.Response(200, json=proof.to_dict())

    mock_transport = httpx.MockTransport(handler)
    transport = WitnessHTTPTransport([NodeEndpoint(node_id="node-1", base_url="https://node")])
    await transport._client.aclose()
    transport._client = httpx.AsyncClient(transport=mock_transport)

    try:
        fetched = await transport.fetch_consistency_proof("node-1", "shard-2", 2, 4)
        assert fetched == proof
    finally:
        await transport._client.aclose()


def test_fetcher_factories_work_with_log_monitor():
    signing_key = nacl.signing.SigningKey.generate()
    leaves = [hash_bytes(f"leaf-{i}".encode()) for i in range(5)]
    tree_3 = MerkleTree(leaves[:3])
    tree_5 = MerkleTree(leaves)
    sth_3 = SignedTreeHead.create(
        epoch_id=1, tree_size=3, merkle_root=tree_3.get_root(), signing_key=signing_key
    )
    sth_5 = SignedTreeHead.create(
        epoch_id=2, tree_size=5, merkle_root=tree_5.get_root(), signing_key=signing_key
    )
    proof = generate_consistency_proof(3, 5, tree_5)
    sth_sequence = [sth_3, sth_5]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/witness/sth/"):
            response = sth_sequence.pop(0)
            return httpx.Response(200, json=response.to_dict())
        if request.url.path.startswith("/witness/consistency/"):
            return httpx.Response(200, json=proof.to_dict())
        return httpx.Response(404)

    mock_transport = httpx.MockTransport(handler)
    transport = WitnessHTTPTransport([NodeEndpoint(node_id="node-1", base_url="https://node")])
    asyncio.run(transport._client.aclose())
    transport._client = httpx.AsyncClient(transport=mock_transport)

    try:
        monitor = LogMonitor(
            sth_fetcher=transport.create_sth_fetcher(),
            consistency_fetcher=transport.create_consistency_fetcher(),
        )
        monitor.poll_node(node_id="node-1", shard_id="shard-9")
        monitor.poll_node(node_id="node-1", shard_id="shard-9")
        observations = list(monitor.observed())
        assert observations[0].sth.tree_size == 5
    finally:
        asyncio.run(transport._client.aclose())

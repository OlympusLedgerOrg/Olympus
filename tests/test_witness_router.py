"""API tests for witness transport endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routers import witness as witness_router
from protocol.checkpoints import create_checkpoint
from protocol.federation import FederationRegistry
from protocol.hashes import hash_bytes
from protocol.shards import get_signing_key_from_seed


REGISTRY_PATH = Path(__file__).resolve().parent.parent / "examples" / "federation_registry.json"


def _registry() -> FederationRegistry:
    return FederationRegistry.from_file(REGISTRY_PATH)


def _signing_keys() -> dict[str, object]:
    return {
        "olympus-node-1": get_signing_key_from_seed(b"\x01" * 32),
        "olympus-node-2": get_signing_key_from_seed(b"\x02" * 32),
    }


def _checkpoint_payload() -> tuple[dict, dict]:
    registry = _registry()
    checkpoint = create_checkpoint(
        sequence=0,
        ledger_head_hash=hash_bytes(b"router-root").hex(),
        ledger_height=1,
        registry=registry,
        signing_keys=_signing_keys(),
    )
    return checkpoint.to_dict(), registry.to_dict()


def _test_client() -> TestClient:
    app = FastAPI()
    app.include_router(witness_router.router)
    return TestClient(app)


def test_witness_announce_and_verify_round_trip():
    checkpoint_dict, registry_dict = _checkpoint_payload()
    client = _test_client()

    announce = client.post(
        "/witness/announce",
        json={
            "origin": "node-a",
            "checkpoint": checkpoint_dict,
        },
    )
    assert announce.status_code == 201
    packet = announce.json()
    assert packet["packet_hash"]

    verify = client.post(
        "/witness/verify",
        json={
            "packet": packet,
            "validate_checkpoint": True,
            "registry": registry_dict,
        },
    )
    assert verify.status_code == 200
    assert verify.json()["valid"] is True


def test_witness_verify_rejects_tampered_packet():
    checkpoint_dict, registry_dict = _checkpoint_payload()
    client = _test_client()

    announce = client.post(
        "/witness/announce",
        json={"origin": "node-b", "checkpoint": checkpoint_dict},
    )
    packet = announce.json()
    packet["packet_hash"] = "00" * 32  # tamper hash

    verify = client.post(
        "/witness/verify",
        json={
            "packet": packet,
            "validate_checkpoint": True,
            "registry": registry_dict,
        },
    )
    assert verify.status_code == 200
    assert verify.json()["valid"] is False

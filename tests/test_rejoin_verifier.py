"""Tests for tools/rejoin_verifier.py."""

import sys
from pathlib import Path

import nacl.signing
import pytest

from protocol.canonical_json import canonical_json_bytes
from protocol.epochs import SignedTreeHead
from protocol.merkle import ct_merkle_root, generate_consistency_proof, merkle_leaf_hash


sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
import rejoin_verifier  # noqa: E402


def _entry(index: int) -> dict[str, object]:
    return {
        "ts": f"2026-03-17T00:00:0{index}Z",
        "record_hash": f"{index:064x}",
        "shard_id": "4F3A",
        "shard_root": f"{index + 10:064x}",
        "canonicalization": {"format": "json", "version": "1.0"},
        "prev_entry_hash": "",
        "entry_hash": f"{index + 20:064x}",
    }


def _build_sth_chain(
    entries: list[dict[str, object]],
) -> tuple[list[dict[str, object]], dict[tuple[int, int], dict[str, object]]]:
    signing_key = nacl.signing.SigningKey.generate()
    leaf_hashes = [merkle_leaf_hash(canonical_json_bytes(entry)) for entry in entries]

    old_size = max(1, len(entries) // 2)
    new_size = len(entries)
    old_root = ct_merkle_root(leaf_hashes[:old_size])
    new_root = ct_merkle_root(leaf_hashes[:new_size])
    proof_nodes = generate_consistency_proof(leaf_hashes, old_size, new_size)

    old_sth = SignedTreeHead.create(
        epoch_id=1,
        tree_size=old_size,
        merkle_root=old_root,
        signing_key=signing_key,
    )
    new_sth = SignedTreeHead.create(
        epoch_id=2,
        tree_size=new_size,
        merkle_root=new_root,
        signing_key=signing_key,
    )
    sths = [
        {
            "epoch_id": old_sth.epoch_id,
            "tree_size": old_sth.tree_size,
            "merkle_root": old_sth.merkle_root,
            "timestamp": old_sth.timestamp,
            "signature": old_sth.signature,
            "signer_pubkey": old_sth.signer_pubkey,
        },
        {
            "epoch_id": new_sth.epoch_id,
            "tree_size": new_sth.tree_size,
            "merkle_root": new_sth.merkle_root,
            "timestamp": new_sth.timestamp,
            "signature": new_sth.signature,
            "signer_pubkey": new_sth.signer_pubkey,
        },
    ]
    proofs = {(old_size, new_size): {"proof_nodes": [node.hex() for node in proof_nodes]}}
    return sths, proofs


def test_valid_sth_chain_passes() -> None:
    entries = [_entry(i) for i in range(1, 5)]
    sths, proofs = _build_sth_chain(entries)

    report = rejoin_verifier.evaluate_rejoin_health(
        sths=sths,
        consistency_proofs=proofs,
        entries=entries,
    )
    assert report.status == rejoin_verifier.STATUS_HEALTHY


def test_non_monotonic_tree_size_detected() -> None:
    entries = [_entry(i) for i in range(1, 5)]
    sths, proofs = _build_sth_chain(entries)
    sths[1]["tree_size"] = 1

    report = rejoin_verifier.evaluate_rejoin_health(
        sths=sths,
        consistency_proofs=proofs,
        entries=entries,
    )
    assert report.status == rejoin_verifier.STATUS_DIVERGED
    assert "Non-monotonic tree_size" in report.details


def test_invalid_consistency_proof_detected() -> None:
    entries = [_entry(i) for i in range(1, 5)]
    sths, proofs = _build_sth_chain(entries)
    key = next(iter(proofs.keys()))
    proofs[key]["proof_nodes"][0] = "00" * 32

    report = rejoin_verifier.evaluate_rejoin_health(
        sths=sths,
        consistency_proofs=proofs,
        entries=entries,
    )
    assert report.status == rejoin_verifier.STATUS_DIVERGED
    assert "Consistency proof verification failed" in report.details


def test_diverged_root_detected() -> None:
    entries = [_entry(i) for i in range(1, 5)]
    sths, proofs = _build_sth_chain(entries)
    entries[0]["record_hash"] = "ff" * 32

    report = rejoin_verifier.evaluate_rejoin_health(
        sths=sths,
        consistency_proofs=proofs,
        entries=entries,
    )
    assert report.status == rejoin_verifier.STATUS_DIVERGED
    assert "Replayed journal root diverges" in report.details


# ---------------------------------------------------------------------------
# Extended tests (Step 2l)
# ---------------------------------------------------------------------------


def test_no_sth_history_returns_no_history() -> None:
    report = rejoin_verifier.evaluate_rejoin_health(
        sths=[],
        consistency_proofs={},
        entries=[],
    )
    assert report.status == rejoin_verifier.STATUS_NO_HISTORY


def test_missing_consistency_proof_detected() -> None:
    entries = [_entry(i) for i in range(1, 5)]
    sths, _ = _build_sth_chain(entries)
    # Provide no proofs at all
    report = rejoin_verifier.evaluate_rejoin_health(
        sths=sths,
        consistency_proofs={},
        entries=entries,
    )
    assert report.status == rejoin_verifier.STATUS_DIVERGED
    assert "Missing consistency proof" in report.details


def test_catching_up_with_fewer_entries() -> None:
    entries = [_entry(i) for i in range(1, 5)]
    sths, proofs = _build_sth_chain(entries)
    # Give fewer entries than the latest STH tree_size
    report = rejoin_verifier.evaluate_rejoin_health(
        sths=sths,
        consistency_proofs=proofs,
        entries=entries[:1],  # Only 1 entry but STH commits 4
    )
    assert report.status == rejoin_verifier.STATUS_CATCHING_UP


def test_signer_continuity_break_detected() -> None:
    """Different signing keys across STHs are detected as a continuity break."""
    entries = [_entry(i) for i in range(1, 5)]
    signing_key1 = nacl.signing.SigningKey.generate()
    signing_key2 = nacl.signing.SigningKey.generate()
    leaf_hashes = [merkle_leaf_hash(canonical_json_bytes(entry)) for entry in entries]

    old_size = max(1, len(entries) // 2)
    new_size = len(entries)
    old_root = ct_merkle_root(leaf_hashes[:old_size])
    new_root = ct_merkle_root(leaf_hashes[:new_size])
    proof_nodes = generate_consistency_proof(leaf_hashes, old_size, new_size)

    # Sign each STH with a different key
    old_sth = SignedTreeHead.create(
        epoch_id=1, tree_size=old_size, merkle_root=old_root, signing_key=signing_key1
    )
    new_sth = SignedTreeHead.create(
        epoch_id=2, tree_size=new_size, merkle_root=new_root, signing_key=signing_key2
    )

    sths = [
        {
            "epoch_id": old_sth.epoch_id,
            "tree_size": old_sth.tree_size,
            "merkle_root": old_sth.merkle_root,
            "timestamp": old_sth.timestamp,
            "signature": old_sth.signature,
            "signer_pubkey": old_sth.signer_pubkey,
        },
        {
            "epoch_id": new_sth.epoch_id,
            "tree_size": new_sth.tree_size,
            "merkle_root": new_sth.merkle_root,
            "timestamp": new_sth.timestamp,
            "signature": new_sth.signature,
            "signer_pubkey": new_sth.signer_pubkey,
        },
    ]
    proofs = {(old_size, new_size): {"proof_nodes": [node.hex() for node in proof_nodes]}}

    report = rejoin_verifier.evaluate_rejoin_health(
        sths=sths,
        consistency_proofs=proofs,
        entries=entries,
    )
    assert report.status == rejoin_verifier.STATUS_DIVERGED
    assert "Signer continuity break" in report.details


def test_invalid_sth_signature_detected() -> None:
    entries = [_entry(i) for i in range(1, 5)]
    sths, proofs = _build_sth_chain(entries)
    # Tamper with the signature but keep pubkey
    sths[0]["signature"] = "00" * 64

    report = rejoin_verifier.evaluate_rejoin_health(
        sths=sths,
        consistency_proofs=proofs,
        entries=entries,
    )
    assert report.status == rejoin_verifier.STATUS_DIVERGED
    assert "Invalid STH signature" in report.details


def test_verify_sth_signature_no_fields() -> None:
    """STH with no signature/pubkey fields is treated as valid."""
    sth = {
        "epoch_id": 1,
        "tree_size": 1,
        "merkle_root": "aa" * 32,
        "timestamp": "2026-03-17T00:00:00Z",
    }
    assert rejoin_verifier._verify_sth_signature(sth) is True


def test_verify_sth_signature_partial_fields() -> None:
    """STH with only signature but no pubkey returns False."""
    sth = {
        "epoch_id": 1,
        "tree_size": 1,
        "merkle_root": "aa" * 32,
        "timestamp": "2026-03-17T00:00:00Z",
        "signature": "bb" * 64,
        "signer_pubkey": "",
    }
    assert rejoin_verifier._verify_sth_signature(sth) is False


def test_extract_proof_nodes_with_proof_key() -> None:
    """_extract_proof_nodes uses 'proof' key as fallback."""
    proof_data = {"proof": ["aa" * 32, "bb" * 32]}
    nodes = rejoin_verifier._extract_proof_nodes(proof_data)
    assert len(nodes) == 2
    assert nodes[0] == bytes.fromhex("aa" * 32)


def test_extract_proof_nodes_invalid_type() -> None:
    """_extract_proof_nodes raises on non-list."""
    with pytest.raises(ValueError, match="must be a list"):
        rejoin_verifier._extract_proof_nodes({"proof_nodes": "not-a-list"})


def test_compute_replayed_root_empty() -> None:
    """_compute_replayed_root raises on empty entries."""
    with pytest.raises(ValueError, match="no entries"):
        rejoin_verifier._compute_replayed_root([])


def test_run_rejoin_verifier_unreachable() -> None:
    """run_rejoin_verifier returns UNREACHABLE on network errors."""
    import httpx

    class FakeClient:
        def get(self, url, *, params=None):
            raise httpx.HTTPError("connection refused")

    report = rejoin_verifier.run_rejoin_verifier(
        node_url="http://localhost:9999",
        shard_id="test-shard",
        client=FakeClient(),
    )
    assert report.status == rejoin_verifier.STATUS_UNREACHABLE


def test_run_rejoin_verifier_no_history() -> None:
    """run_rejoin_verifier returns NO_HISTORY when node has no STHs."""
    from unittest.mock import MagicMock

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"sths": []}
    mock_resp.raise_for_status = MagicMock()

    client = MagicMock()
    client.get.return_value = mock_resp

    report = rejoin_verifier.run_rejoin_verifier(
        node_url="http://localhost:9999",
        shard_id="test",
        client=client,
    )
    assert report.status == rejoin_verifier.STATUS_NO_HISTORY


def test_same_tree_size_sths_skip_consistency_proof() -> None:
    """STHs with equal tree_size skip consistency proof checking."""
    signing_key = nacl.signing.SigningKey.generate()
    entries = [_entry(i) for i in range(1, 3)]
    leaf_hashes = [merkle_leaf_hash(canonical_json_bytes(entry)) for entry in entries]
    root = ct_merkle_root(leaf_hashes)

    sth1 = SignedTreeHead.create(epoch_id=1, tree_size=2, merkle_root=root, signing_key=signing_key)
    sth2 = SignedTreeHead.create(epoch_id=2, tree_size=2, merkle_root=root, signing_key=signing_key)

    sths = [
        {
            "epoch_id": sth1.epoch_id,
            "tree_size": sth1.tree_size,
            "merkle_root": sth1.merkle_root,
            "timestamp": sth1.timestamp,
            "signature": sth1.signature,
            "signer_pubkey": sth1.signer_pubkey,
        },
        {
            "epoch_id": sth2.epoch_id,
            "tree_size": sth2.tree_size,
            "merkle_root": sth2.merkle_root,
            "timestamp": sth2.timestamp,
            "signature": sth2.signature,
            "signer_pubkey": sth2.signer_pubkey,
        },
    ]

    report = rejoin_verifier.evaluate_rejoin_health(
        sths=sths,
        consistency_proofs={},
        entries=entries,
    )
    assert report.status == rejoin_verifier.STATUS_HEALTHY

"""Tests for tools/rejoin_verifier.py."""

import sys
from pathlib import Path

import nacl.signing

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


def _build_sth_chain(entries: list[dict[str, object]]) -> tuple[list[dict[str, object]], dict[tuple[int, int], dict[str, object]]]:
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

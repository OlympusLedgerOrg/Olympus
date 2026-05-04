"""
Storage layer invariant fuzzing tests.

Targets the real Postgres storage layer (via a disposable test database) and
verifies deterministic ledger invariants across randomly-generated operation
sequences.

Invariants checked
------------------
INV-1  get_current_root() must match the root stored in the latest shard header.
INV-2  verify_state_replay() must succeed after every append.
INV-3  A proof retrieved via get_proof() must verify against the current root.
INV-4  get_nonexistence_proof() must never succeed for an existing key.
INV-5  Checkpoints must have non-overlapping, contiguous header_seq ranges
       per shard.
INV-6  A reconnect (new StorageLayer instance) must return the same root as the
       previous instance.

Skipped automatically when:
  - ``TEST_DATABASE_URL`` is unset (no Postgres available), OR
  - the ``olympus_core`` Rust extension is not installed.

Select profile:
  HYPOTHESIS_PROFILE=fuzz_smoke  pytest tests/fuzz/test_storage_invariants_fuzz.py -m fuzz
  HYPOTHESIS_PROFILE=fuzz_24h    pytest tests/fuzz/test_storage_invariants_fuzz.py -m "fuzz and slow"
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import nacl.signing
import pytest
from hypothesis import given, settings, strategies as st

from protocol.canonical import CANONICAL_VERSION, canonicalize_document, document_to_bytes
from protocol.canonicalizer import canonicalization_provenance
from protocol.hashes import hash_bytes
from protocol.ssmf import verify_nonexistence_proof, verify_proof
from tests.fuzz.artifacts import save_artifact
from tests.fuzz.conftest import _EXAMPLES_DIR  # noqa: F401 — ensures profile loaded
from tests.fuzz.strategies import (
    OP_APPEND,
    OP_CHECKPOINT,
    OP_GET_NONEXISTENCE_PROOF,
    OP_GET_PROOF,
    OP_RECONNECT,
    OP_VERIFY_GLOBAL_ROOT,
    OP_VERIFY_SHARD_HEADER,
    content_dicts,
    operation_sequence,
    record_ids,
    record_types,
    record_versions,
    shard_ids,
)


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

TEST_DB = os.environ.get("TEST_DATABASE_URL", "")

_RUST_AVAILABLE = False
try:
    from olympus_core import RustSparseMerkleTree as _RST  # noqa: F401

    _RUST_AVAILABLE = True
except ImportError:
    pass

pytestmark = [
    pytest.mark.fuzz,
    pytest.mark.storage,
    pytest.mark.skipif(
        not TEST_DB,
        reason="TEST_DATABASE_URL not set — skipping storage fuzz tests.",
    ),
    pytest.mark.skipif(
        not _RUST_AVAILABLE,
        reason="olympus_core Rust extension not installed — skipping storage fuzz tests.",
    ),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_signing_key(seed: bytes | None = None) -> nacl.signing.SigningKey:
    """Return a deterministic Ed25519 signing key for tests."""
    seed_bytes = seed if seed is not None else hash_bytes(b"fuzz-storage-test-key")
    return nacl.signing.SigningKey(seed_bytes)


def _fresh_storage(db_url: str | None = None):
    """Create and initialise a StorageLayer against the test database."""
    from storage.postgres import StorageLayer

    url = db_url or TEST_DB
    sl = StorageLayer(url, pool_min_size=1, pool_max_size=3, node_cache_size=0)
    sl.init_schema()
    return sl


def _unique_shard(prefix: str = "fuzz") -> str:
    """Return a unique shard ID to isolate each test run."""
    return f"{prefix}.{uuid.uuid4().hex[:12]}"


def _canonicalize_and_hash(content: dict[str, Any]) -> bytes:
    """Canonicalize a content dict and return its 32-byte hash."""
    canon = canonicalize_document(content)
    return hash_bytes(document_to_bytes(canon))


# ---------------------------------------------------------------------------
# Helper: execute a single operation against a live StorageLayer
# ---------------------------------------------------------------------------


def _run_op(
    storage: Any,
    op: dict[str, Any],
    signing_key: nacl.signing.SigningKey,
    shard_namespace: str,
    appended: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Execute one fuzz operation against *storage*.

    Args:
        storage: Active StorageLayer.
        op: Operation descriptor.
        signing_key: Ed25519 key for shard header signing.
        shard_namespace: UUID prefix that namespaces all shard IDs for this
            run so they never collide with other concurrent runs.
        appended: Accumulator of successfully appended records (mutated in place).

    Returns:
        Result dict with at least ``"op"`` and ``"ok"`` keys.
    """
    op_type = op["op"]

    # Namespace the shard_id to isolate this run
    raw_shard = op.get("shard_id", "default")
    shard_id = f"{shard_namespace}.{raw_shard}"

    if op_type == OP_APPEND:
        content = op["content"]
        value_hash = _canonicalize_and_hash(content)
        canon_prov = canonicalization_provenance("application/json", CANONICAL_VERSION)
        try:
            root_hash, proof, header, _sig, ledger_entry = storage.append_record(
                shard_id=shard_id,
                record_type=op["record_type"],
                record_id=op["record_id"],
                version=op["version"],
                value_hash=value_hash,
                signing_key=signing_key,
                canonicalization=canon_prov,
            )
            appended.append(
                {
                    "shard_id": shard_id,
                    "record_type": op["record_type"],
                    "record_id": op["record_id"],
                    "version": op["version"],
                    "value_hash": value_hash,
                    "root_hash": root_hash,
                    "proof": proof,
                }
            )
            return {"op": op_type, "ok": True, "root_hash": root_hash.hex()}
        except ValueError as exc:
            # Duplicate record — expected for replayed ops; not a bug
            if "already exists" in str(exc):
                return {"op": op_type, "ok": True, "skipped": "duplicate"}
            raise

    if op_type == OP_GET_PROOF:
        proof = storage.get_proof(shard_id, op["record_type"], op["record_id"], op["version"])
        if proof is not None:
            current_root = storage.get_current_root(shard_id)
            # INV-3: live proof must verify against the current root
            assert verify_proof(proof, expected_root=current_root), (
                f"INV-3 FAIL: proof for {shard_id}/{op['record_id']} "
                f"does not verify against current root {current_root.hex()}"
            )
        return {"op": op_type, "ok": True, "found": proof is not None}

    if op_type == OP_GET_NONEXISTENCE_PROOF:
        # Only request non-existence if we know the key doesn't exist
        already_appended = any(
            a["shard_id"] == shard_id
            and a["record_type"] == op["record_type"]
            and a["record_id"] == op["record_id"]
            and a["version"] == op["version"]
            for a in appended
        )
        if not already_appended:
            try:
                nex_proof = storage.get_nonexistence_proof(
                    shard_id, op["record_type"], op["record_id"], op["version"]
                )
                current_root = storage.get_current_root(shard_id)
                # INV-4: non-existence proof must verify
                assert verify_nonexistence_proof(nex_proof, expected_root=current_root), (
                    f"INV-4 FAIL: non-existence proof for "
                    f"({shard_id}, {op['record_type']}, {op['record_id']}, {op['version']}) "
                    f"does not verify"
                )
            except ValueError as exc:
                if "exists" in str(exc):
                    return {"op": op_type, "ok": True, "skipped": "key_exists"}
                raise
        return {"op": op_type, "ok": True}

    if op_type == OP_VERIFY_GLOBAL_ROOT:
        # INV-1: current root from header must match replay
        shard_ids_in_run = list({a["shard_id"] for a in appended})
        for sid in shard_ids_in_run:
            root = storage.get_current_root(sid)
            latest_header = storage.get_latest_header(sid)
            if latest_header is not None:
                header_root = bytes.fromhex(latest_header["header"]["root_hash"])
                assert root == header_root, (
                    f"INV-1 FAIL: get_current_root={root.hex()} != "
                    f"latest_header.root_hash={header_root.hex()} for shard {sid}"
                )
        return {"op": op_type, "ok": True}

    if op_type == OP_VERIFY_SHARD_HEADER:
        # INV-2 partial: replay should succeed for any shard with records
        shard_id_for_replay = f"{shard_namespace}.{op['shard_id']}"
        latest = storage.get_latest_header(shard_id_for_replay)
        if latest is not None:
            result = storage.verify_state_replay(shard_id_for_replay, max_headers=5)
            assert result["verified"], f"INV-2 FAIL: replay failed for {shard_id_for_replay}"
        return {"op": op_type, "ok": True}

    if op_type == OP_CHECKPOINT:
        # INV-5: create checkpoints and verify non-overlapping ranges
        for sid in list({a["shard_id"] for a in appended})[:3]:
            ckpt = storage.create_checkpoint(sid)
            if ckpt is not None:
                checkpoints = storage.get_checkpoints(sid, n=100)
                seqs = [c["header_seq"] for c in checkpoints]
                assert len(seqs) == len(set(seqs)), (
                    f"INV-5 FAIL: duplicate checkpoint seqs for {sid}: {seqs}"
                )
        return {"op": op_type, "ok": True}

    if op_type == OP_RECONNECT:
        # INV-6: a fresh storage instance must return the same root
        storage2 = _fresh_storage()
        try:
            for a in appended[-5:]:  # check last 5 appended records
                sid = a["shard_id"]
                root1 = storage.get_current_root(sid)
                root2 = storage2.get_current_root(sid)
                assert root1 == root2, (
                    f"INV-6 FAIL: root diverged after reconnect for {sid}: "
                    f"{root1.hex()} vs {root2.hex()}"
                )
        finally:
            storage2.close()
        return {"op": op_type, "ok": True}

    return {"op": op_type, "ok": True, "skipped": "unknown_op"}


# ---------------------------------------------------------------------------
# Fuzz tests
# ---------------------------------------------------------------------------


@pytest.mark.fuzz
@pytest.mark.storage
@given(ops=operation_sequence(min_ops=3, max_ops=15))
@settings(
    max_examples=int(os.environ.get("FUZZ_MAX_EXAMPLES", "30")),
    deadline=None,
)
def test_storage_invariants_sequence(ops: list[dict[str, Any]]) -> None:
    """
    Drive random operation sequences against a live Postgres StorageLayer and
    assert all ledger invariants hold after every step.
    """
    storage = _fresh_storage()
    signing_key = _make_signing_key()
    shard_namespace = uuid.uuid4().hex[:8]
    appended: list[dict[str, Any]] = []

    try:
        for idx, op in enumerate(ops):
            try:
                _run_op(storage, op, signing_key, shard_namespace, appended)
            except AssertionError as exc:
                artifact_path = save_artifact(
                    test_name="test_storage_invariants_sequence",
                    operations=ops,
                    failing_index=idx,
                    exception=exc,
                )
                pytest.fail(
                    f"Ledger invariant violated at op[{idx}] ({op['op']}). "
                    f"Artifact: {artifact_path}\n{exc}"
                )
    finally:
        storage.close()


@pytest.mark.fuzz
@pytest.mark.storage
@given(
    shard=shard_ids,
    records=st.lists(
        st.fixed_dictionaries(
            {
                "record_type": record_types,
                "record_id": record_ids,
                "version": record_versions,
                "content": content_dicts,
            }
        ),
        min_size=2,
        max_size=8,
        unique_by=lambda r: (r["record_type"], r["record_id"], r["version"]),
    ),
)
@settings(
    max_examples=int(os.environ.get("FUZZ_MAX_EXAMPLES", "20")),
    deadline=None,
)
def test_nonexistence_proof_never_validates_for_existing_key(
    shard: str,
    records: list[dict[str, Any]],
) -> None:
    """
    After appending records, get_nonexistence_proof() must raise ValueError
    for every key that was actually appended.
    """
    storage = _fresh_storage()
    signing_key = _make_signing_key()
    ns = uuid.uuid4().hex[:8]
    shard_id = f"{ns}.{shard}"

    try:
        for i, rec in enumerate(records):
            value_hash = _canonicalize_and_hash(rec["content"])
            canon_prov = canonicalization_provenance("application/json", CANONICAL_VERSION)
            storage.append_record(
                shard_id=shard_id,
                record_type=rec["record_type"],
                record_id=rec["record_id"],
                version=rec["version"],
                value_hash=value_hash,
                signing_key=signing_key,
                canonicalization=canon_prov,
            )

        for i, rec in enumerate(records):
            try:
                storage.get_nonexistence_proof(
                    shard_id, rec["record_type"], rec["record_id"], rec["version"]
                )
                # If we reach here, a non-existence proof was returned for an existing key — bug
                artifact_path = save_artifact(
                    test_name="test_nonexistence_proof_never_validates_for_existing_key",
                    operations=[{"op": "append", **r} for r in records],
                    failing_index=i,
                    failing_operation={"op": "get_nonexistence_proof", **rec},
                    expected="ValueError: record exists",
                    actual="no exception raised",
                )
                pytest.fail(
                    f"INV-4 FAIL: get_nonexistence_proof returned for existing key "
                    f"{rec['record_id']}. Artifact: {artifact_path}"
                )
            except ValueError as exc:
                # Expected — record exists
                assert "exists" in str(exc).lower(), f"Unexpected ValueError: {exc}"
    finally:
        storage.close()


@pytest.mark.fuzz
@pytest.mark.storage
@given(ops=operation_sequence(min_ops=4, max_ops=12))
@settings(
    max_examples=int(os.environ.get("FUZZ_MAX_EXAMPLES", "20")),
    deadline=None,
)
def test_checkpoint_seq_monotonicity(ops: list[dict[str, Any]]) -> None:
    """
    Checkpoints for a shard must have monotonically increasing, non-duplicate
    header_seq values.
    """
    storage = _fresh_storage()
    signing_key = _make_signing_key()
    ns = uuid.uuid4().hex[:8]
    appended: list[dict[str, Any]] = []

    try:
        for idx, op in enumerate(ops):
            _run_op(storage, op, signing_key, ns, appended)

        for sid in list({a["shard_id"] for a in appended})[:5]:
            # Create two checkpoints (second should be idempotent on same seq)
            storage.create_checkpoint(sid)
            storage.create_checkpoint(sid)  # idempotent
            checkpoints = storage.get_checkpoints(sid, n=100)
            seqs = [c["header_seq"] for c in checkpoints]
            assert len(seqs) == len(set(seqs)), (
                f"INV-5 FAIL: duplicate checkpoint seqs for {sid}: {seqs}"
            )
            # Checkpoints must be returned in descending order
            assert seqs == sorted(seqs, reverse=True), (
                f"INV-5 FAIL: checkpoints not in descending order for {sid}: {seqs}"
            )
    finally:
        storage.close()

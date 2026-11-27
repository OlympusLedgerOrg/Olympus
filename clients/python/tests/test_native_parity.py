# SPDX-FileCopyrightText: 2026 Olympus Contributors
# SPDX-License-Identifier: Apache-2.0

"""Cross-backend parity: the optional native (PyO3) module vs the pure-Python port.

``olympus_manifest_native`` wraps the Rust source of truth, so agreeing with
``vectors.json`` proves only that the binding is wired correctly. The point of
this file is the *cross* check: the native backend and the independent
pure-Python re-implementation must return the same answer on the same inputs,
including tampered ones, so a regression in either is caught by the other.

Skipped when the native module is not built (``maturin develop`` in
``clients/python/native``).
"""

import json
import pathlib

import pytest

from olympus_manifest import hashing, verify
from olympus_manifest.proof import Verdict

native = pytest.importorskip("olympus_manifest_native")

VECTORS = json.loads((pathlib.Path(__file__).parent / "vectors.json").read_text())
ROOT = bytes.fromhex(VECTORS["manifest_root"])


def _copy(obj):
    return json.loads(json.dumps(obj))


def test_native_primitives_match_vectors():
    p = VECTORS["primitives"]
    assert native.empty_leaf().hex() == p["empty_leaf"]
    assert native.empty_subtree_hash(192).hex() == p["empty_subtree_192"]
    assert native.empty_subtree_hash(256).hex() == p["empty_subtree_256"]
    rk = p["record_key"]
    assert native.record_key(rk["record_type"], rk["record_id"], rk["version"]).hex() == rk["out"]
    srk = p["shard_record_key"]
    assert (
        native.shard_record_key(srk["shard_id"], bytes.fromhex(srk["record_key"])).hex()
        == srk["out"]
    )
    nh = p["node_hash"]
    assert (
        native.node_hash(bytes.fromhex(nh["left"]), bytes.fromhex(nh["right"])).hex()
        == nh["out"]
    )


LEAF_ARGS = (
    b"alpha",
    bytes(range(32)),
    bytes([0x11]) * 32,
    b"olympus.manifest@v1",
    b"v1",
    b"none",
)


def test_leaf_hash_backends_agree():
    assert native.leaf_hash(*LEAF_ARGS) == hashing.leaf_hash(*LEAF_ARGS)


@pytest.mark.parametrize("field", range(6))
def test_leaf_hash_binds_every_field_in_both_backends(field):
    # Mutating any one input must change the digest in BOTH backends, and the
    # two must still agree on the mutated digest (binding, not just agreement).
    args = list(LEAF_ARGS)
    b = bytearray(args[field])
    b[0] ^= 0x01
    args[field] = bytes(b)
    mutated_native = native.leaf_hash(*args)
    assert mutated_native != native.leaf_hash(*LEAF_ARGS)
    assert mutated_native == hashing.leaf_hash(*args)


def test_native_rejects_short_inputs_with_value_error():
    # The Rust core release-asserts on these; the binding must raise, not abort.
    with pytest.raises(ValueError):
        native.leaf_hash(b"a", b"\x00" * 31, b"\x00" * 32, b"p", b"v", b"m")
    with pytest.raises(ValueError):
        native.node_hash(b"\x00" * 32, b"\x00" * 33)
    with pytest.raises(ValueError):
        native.empty_subtree_hash(257)


def _mutations():
    inc = VECTORS["inclusion_bundle"]
    yield "inclusion", inc, ROOT
    yield "exclusion", VECTORS["exclusion_bundle"], ROOT
    yield "wrong_root", inc, b"\x00" * 32
    b = _copy(inc)
    b["record_id"] = "a-2"
    yield "relabeled", b, ROOT
    b = _copy(inc)
    b["content_hash"] = "99" * 32
    yield "content", b, ROOT
    b = _copy(inc)
    b["kind"] = "exclusion"
    yield "kind", b, ROOT
    b = _copy(inc)
    b["smt_proof"]["siblings"][0][0] ^= 0xFF
    yield "sibling", b, ROOT
    b = _copy(VECTORS["exclusion_bundle"])
    b["smt_proof"]["siblings"][5][3] ^= 0x01
    yield "exclusion_sibling", b, ROOT


@pytest.mark.parametrize("name,bundle,root", list(_mutations()), ids=lambda x: x if isinstance(x, str) else "")
def test_verify_backends_agree(name, bundle, root):
    pure = verify(bundle, root)
    assert native.verify_bundle(json.dumps(bundle), root) == pure.value
    # Only the untampered bundles may verify.
    assert pure.is_valid == (name in ("inclusion", "exclusion"))


@pytest.mark.parametrize("bad", ["", "{}", "not json", "[]", '{"kind": "inclusion"}'])
def test_native_malformed_never_raises(bad):
    assert native.verify_bundle(bad, ROOT) == Verdict.MALFORMED.value

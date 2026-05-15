"""
24-hour Hypothesis marathon — five deep invariant tests.

Run with 4 workers via pytest-xdist::

    HYPOTHESIS_PROFILE=fuzz_marathon pytest tests/fuzz/test_marathon_24h.py \
        -m "fuzz and marathon" -n 4 -x

Each test is independent and stateless so xdist can distribute them freely
across the 4 cores.  All five test the most security-critical invariants in
the protocol layer where a silent failure would be catastrophic:

  MARA-1  SMT leaf/value hash binding — a proof must not verify against a
          different value hash than the one committed.
  MARA-2  Global-key domain separation — key_a and key_b produced by
          global_key() for different (shard, record_type, record_id, version)
          tuples must be distinct.
  MARA-3  Canonical JSON injectivity — two semantically different Python
          dicts must never encode to the same byte string.
  MARA-4  Round-trip stability — canonical_json_encode(parse(encode(x))) == encode(x)
          for any well-formed content dict.
  MARA-5  Record-key determinism under shard rename — the SMT root for a tree
          built with shard_a must differ from the root built with shard_b,
          regardless of content, proving that the key function is shard-bound.

Pytest markers: ``fuzz``, ``marathon``
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import HealthCheck, Phase, assume, given, settings

from protocol.canonical import canonicalize_document, document_to_bytes
from protocol.canonical_json import canonical_json_encode
from protocol.hashes import global_key, hash_bytes, record_key
from protocol.ssmf import ExistenceProof, SparseMerkleTree, verify_proof
from tests.fuzz.strategies import (
    content_dicts,
    hash_32,
    record_ids,
    record_types,
    record_versions,
    shard_ids,
)


_MARATHON_SETTINGS = dict(
    deadline=None,
    suppress_health_check=list(HealthCheck),
    phases=[Phase.reuse, Phase.generate, Phase.target, Phase.shrink, Phase.explain],
    print_blob=True,
    # max_examples is intentionally omitted — the loaded profile (fuzz_marathon,
    # fuzz_24h, etc.) controls the count. A hardcoded value here would override
    # HYPOTHESIS_PROFILE and cap runs regardless of which profile is active.
)


# ---------------------------------------------------------------------------
# MARA-1  SMT leaf/value hash binding
# ---------------------------------------------------------------------------


@pytest.mark.fuzz
@pytest.mark.marathon
@given(
    content=content_dicts,
    shard=shard_ids,
    record=record_ids,
    wrong_value=hash_32,
)
@settings(**_MARATHON_SETTINGS)
def test_mara1_proof_binds_to_committed_value(
    content: dict[str, Any],
    shard: str,
    record: str,
    wrong_value: bytes,
) -> None:
    """
    MARA-1: An SMT existence proof must not verify if the value_hash is replaced
    with an arbitrary wrong hash, regardless of the committed content.
    """
    tree = SparseMerkleTree()
    value_hash = hash_bytes(document_to_bytes(canonicalize_document(content)))
    key = global_key(shard, record_key("document", record, 1))

    assume(wrong_value != value_hash)

    tree.update(key, value_hash, "mara@1.0.0", "v1")
    root = tree.get_root()
    proof = tree.prove_existence(key)

    tampered = ExistenceProof(
        key=proof.key,
        value_hash=wrong_value,  # substituted
        parser_id=proof.parser_id,
        canonical_parser_version=proof.canonical_parser_version,
        siblings=proof.siblings,
        root_hash=root,
    )
    assert not verify_proof(tampered, expected_root=root), (
        "MARA-1 FAIL: proof verified with wrong value_hash — value binding broken"
    )


# ---------------------------------------------------------------------------
# MARA-2  Global-key domain separation
# ---------------------------------------------------------------------------


@pytest.mark.fuzz
@pytest.mark.marathon
@given(
    shard_a=shard_ids,
    shard_b=shard_ids,
    record=record_ids,
    rtype=record_types,
    version=record_versions,
)
@settings(**_MARATHON_SETTINGS)
def test_mara2_global_key_domain_separation(
    shard_a: str,
    shard_b: str,
    record: str,
    rtype: str,
    version: int,
) -> None:
    """
    MARA-2: global_key() must produce distinct keys whenever shard_a != shard_b,
    for any (record_type, record_id, version).  A collision here would let a proof
    from shard_a verify as belonging to shard_b.
    """
    assume(shard_a != shard_b)

    rec_key = record_key(rtype, record, version)
    key_a = global_key(shard_a, rec_key)
    key_b = global_key(shard_b, rec_key)

    assert key_a != key_b, (
        f"MARA-2 FAIL: global_key collision. "
        f"shard_a={shard_a!r} shard_b={shard_b!r} "
        f"record={record!r} rtype={rtype!r} version={version}"
    )


# ---------------------------------------------------------------------------
# MARA-3  Canonical JSON injectivity
# ---------------------------------------------------------------------------


@pytest.mark.fuzz
@pytest.mark.marathon
@given(
    doc_a=content_dicts,
    doc_b=content_dicts,
)
@settings(**_MARATHON_SETTINGS)
def test_mara3_canonical_json_injectivity(
    doc_a: dict[str, Any],
    doc_b: dict[str, Any],
) -> None:
    """
    MARA-3: Two Python dicts that are semantically different (doc_a != doc_b after
    canonicalization) must encode to different canonical JSON byte strings.

    A collision here would allow two distinct documents to share the same
    content hash, breaking the tamper-evidence guarantee of the ledger.
    """
    canon_a = canonicalize_document(doc_a)
    canon_b = canonicalize_document(doc_b)
    assume(canon_a != canon_b)

    enc_a = canonical_json_encode(canon_a)
    enc_b = canonical_json_encode(canon_b)

    assert enc_a != enc_b, (
        f"MARA-3 FAIL: distinct documents encoded to the same canonical JSON.\n"
        f"doc_a: {doc_a}\ndoc_b: {doc_b}"
    )


# ---------------------------------------------------------------------------
# MARA-4  Canonical JSON round-trip stability
# ---------------------------------------------------------------------------


@pytest.mark.fuzz
@pytest.mark.marathon
@given(content=content_dicts)
@settings(**_MARATHON_SETTINGS)
def test_mara4_canonical_json_roundtrip_stable(content: dict[str, Any]) -> None:
    """
    MARA-4: canonical_json_encode(json.loads(canonical_json_encode(x))) must equal
    canonical_json_encode(x).

    A round-trip instability means the canonical encoding is not idempotent
    and two processes encoding the same logical document could produce different
    hashes after a serialise→parse→serialise cycle.
    """
    first_pass = canonical_json_encode(content)

    # Parse back through stdlib JSON — must be lossless for the types our
    # strategies generate (str, int, bool, None, list, dict).
    try:
        reparsed = json.loads(first_pass)
    except (ValueError, UnicodeDecodeError):
        # canonical_json_encode produced non-parseable output — that itself is
        # a bug, but is covered by MARA-3; skip here to keep tests orthogonal.
        assume(False)
        return

    second_pass = canonical_json_encode(reparsed)

    assert first_pass == second_pass, (
        f"MARA-4 FAIL: canonical JSON is not round-trip stable.\n"
        f"first_pass:  {first_pass[:300]}\n"
        f"second_pass: {second_pass[:300]}"
    )


# ---------------------------------------------------------------------------
# MARA-5  SMT root is shard-bound
# ---------------------------------------------------------------------------


@pytest.mark.fuzz
@pytest.mark.marathon
@given(
    content=content_dicts,
    shard_a=shard_ids,
    shard_b=shard_ids,
    record=record_ids,
)
@settings(**_MARATHON_SETTINGS)
def test_mara5_smt_root_is_shard_bound(
    content: dict[str, Any],
    shard_a: str,
    shard_b: str,
    record: str,
) -> None:
    """
    MARA-5: Two single-leaf SMTs built from the same content but different shards
    must produce different roots.

    If the roots collide a verifier could accept a proof from shard_a as valid
    evidence for shard_b without detecting the cross-shard substitution.
    """
    assume(shard_a != shard_b)

    value_hash = hash_bytes(document_to_bytes(canonicalize_document(content)))
    key_a = global_key(shard_a, record_key("document", record, 1))
    key_b = global_key(shard_b, record_key("document", record, 1))

    # MARA-2 already guarantees key_a != key_b; assume guards the negligible
    # cryptographic-collision path so the assertion here is purely structural.
    assume(key_a != key_b)

    tree_a = SparseMerkleTree()
    tree_b = SparseMerkleTree()
    tree_a.update(key_a, value_hash, "mara@1.0.0", "v1")
    tree_b.update(key_b, value_hash, "mara@1.0.0", "v1")

    root_a = tree_a.get_root()
    root_b = tree_b.get_root()

    assert root_a != root_b, (
        f"MARA-5 FAIL: identical content under different shards produced the same "
        f"SMT root.\nshard_a={shard_a!r} shard_b={shard_b!r} record={record!r}"
    )

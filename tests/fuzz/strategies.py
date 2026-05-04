"""
Hypothesis strategies for Olympus fuzzing.

All strategies are deterministic given a seed and are designed to generate
sequences of operations against the Olympus storage layer and API.

Strategy categories
-------------------
* Primitive strategies — identifiers, hashes, content blobs
* Operation strategies — individual ledger/proof operations
* Sequence strategies — ordered multi-step operation lists for stateful tests
* Security strategies — adversarial inputs for auth, validation, injection

All strategies avoid third-party network calls and are strictly local.
"""

from __future__ import annotations

import string
from typing import Any

from hypothesis import strategies as st


# ---------------------------------------------------------------------------
# Primitive strategies
# ---------------------------------------------------------------------------

# Valid shard identifiers (match SHARD_ID_PATTERN in api/schemas/ingest.py)
_SHARD_ALPHABET = string.ascii_letters + string.digits + "_.:- "
_SHARD_ALPHABET = _SHARD_ALPHABET.replace(" ", "")  # no spaces

shard_ids = st.text(
    alphabet=string.ascii_letters + string.digits + "_.-",
    min_size=1,
    max_size=64,
).filter(lambda s: s and not s.startswith(".") and not s.endswith("."))

# Record identifiers matching IDENTIFIER_PATTERN
record_ids = st.text(
    alphabet=string.ascii_letters + string.digits + "_./:-@+",
    min_size=1,
    max_size=64,
)

# Record versions
record_versions = st.integers(min_value=1, max_value=10)

# Record types
record_types = st.sampled_from(["document", "artifact", "report", "policy", "index"])

# Arbitrary content dicts (bounded depth/size to stay under MAX_CONTENT_DEPTH=64)
_content_leaf = st.one_of(
    st.text(max_size=128),
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.booleans(),
    st.none(),
)

_content_values: st.SearchStrategy[Any] = st.deferred(
    lambda: st.one_of(
        _content_leaf,
        st.lists(_content_leaf, max_size=8),
        st.dictionaries(
            st.text(alphabet=string.ascii_letters + string.digits + "_", min_size=1, max_size=32),
            _content_leaf,
            max_size=8,
        ),
    )
)

content_dicts = st.dictionaries(
    st.text(alphabet=string.ascii_letters + string.digits + "_", min_size=1, max_size=32),
    _content_values,
    min_size=1,
    max_size=16,
)

# 32-byte hashes (arbitrary)
hash_32 = st.binary(min_size=32, max_size=32)

# API keys
valid_api_keys = st.text(
    alphabet=string.ascii_letters + string.digits + "-_",
    min_size=16,
    max_size=64,
)

# ---------------------------------------------------------------------------
# Operation type enums (plain strings for JSON-serializability of artifacts)
# ---------------------------------------------------------------------------

OP_APPEND = "append"
OP_GET_PROOF = "get_proof"
OP_GET_NONEXISTENCE_PROOF = "get_nonexistence_proof"
OP_VERIFY_GLOBAL_ROOT = "verify_global_root"
OP_VERIFY_SHARD_HEADER = "verify_shard_header_at_seq"
OP_CHECKPOINT = "checkpoint"
OP_RECONNECT = "reconnect"

ALL_OP_TYPES = [
    OP_APPEND,
    OP_GET_PROOF,
    OP_GET_NONEXISTENCE_PROOF,
    OP_VERIFY_GLOBAL_ROOT,
    OP_VERIFY_SHARD_HEADER,
    OP_CHECKPOINT,
    OP_RECONNECT,
]


# ---------------------------------------------------------------------------
# Individual operation strategies
# ---------------------------------------------------------------------------


def append_op(draw: Any) -> dict[str, Any]:
    """Draw a single append operation descriptor."""
    return {
        "op": OP_APPEND,
        "shard_id": draw(shard_ids),
        "record_type": draw(record_types),
        "record_id": draw(record_ids),
        "version": draw(record_versions),
        "content": draw(content_dicts),
    }


def proof_op(draw: Any) -> dict[str, Any]:
    """Draw a get-proof operation descriptor (key may or may not exist)."""
    return {
        "op": OP_GET_PROOF,
        "shard_id": draw(shard_ids),
        "record_type": draw(record_types),
        "record_id": draw(record_ids),
        "version": draw(record_versions),
    }


def nonexistence_proof_op(draw: Any) -> dict[str, Any]:
    """Draw a non-existence proof operation descriptor."""
    return {
        "op": OP_GET_NONEXISTENCE_PROOF,
        "shard_id": draw(shard_ids),
        "record_type": draw(record_types),
        "record_id": draw(record_ids),
        "version": draw(record_versions),
    }


def verify_global_root_op(_draw: Any) -> dict[str, Any]:
    """Draw a verify-global-root operation descriptor."""
    return {"op": OP_VERIFY_GLOBAL_ROOT}


def verify_shard_header_op(draw: Any) -> dict[str, Any]:
    """Draw a verify-shard-header-at-seq operation descriptor."""
    return {
        "op": OP_VERIFY_SHARD_HEADER,
        "shard_id": draw(shard_ids),
        "seq": draw(st.integers(min_value=0, max_value=100)),
    }


def checkpoint_op(_draw: Any) -> dict[str, Any]:
    """Draw a checkpoint creation operation descriptor."""
    return {"op": OP_CHECKPOINT}


def reconnect_op(_draw: Any) -> dict[str, Any]:
    """Draw a reconnect/restart operation descriptor."""
    return {"op": OP_RECONNECT}


# ---------------------------------------------------------------------------
# Sequence strategies — builds a mixed list of operations
# ---------------------------------------------------------------------------


@st.composite
def operation_sequence(
    draw: Any,
    min_ops: int = 2,
    max_ops: int = 20,
    append_weight: int = 5,
    proof_weight: int = 3,
    nonexistence_weight: int = 2,
    global_root_weight: int = 3,
    shard_header_weight: int = 2,
    checkpoint_weight: int = 1,
    reconnect_weight: int = 1,
) -> list[dict[str, Any]]:
    """
    Generate a mixed sequence of storage operations.

    The sequence always starts with at least one append so that subsequent
    proof/root operations have something to verify against.

    Args:
        draw: Hypothesis draw callable.
        min_ops: Minimum total operations in the sequence.
        max_ops: Maximum total operations.
        *_weight: Relative weights controlling how frequently each operation
            type appears.

    Returns:
        List of operation descriptor dicts, JSON-serializable.
    """
    n = draw(st.integers(min_value=min_ops, max_value=max_ops))

    # Always start with an append to seed the tree
    ops: list[dict[str, Any]] = [draw(st.builds(append_op, draw=st.just(draw)))]

    _op_builders = [
        (append_weight, lambda: draw(st.builds(append_op, draw=st.just(draw)))),
        (proof_weight, lambda: draw(st.builds(proof_op, draw=st.just(draw)))),
        (nonexistence_weight, lambda: draw(st.builds(nonexistence_proof_op, draw=st.just(draw)))),
        (global_root_weight, lambda: verify_global_root_op(draw)),
        (shard_header_weight, lambda: draw(st.builds(verify_shard_header_op, draw=st.just(draw)))),
        (checkpoint_weight, lambda: checkpoint_op(draw)),
        (reconnect_weight, lambda: reconnect_op(draw)),
    ]
    weights = [w for w, _ in _op_builders]
    builders = [b for _, b in _op_builders]

    for _ in range(n - 1):
        idx = draw(st.integers(min_value=0, max_value=sum(weights) - 1))
        cumulative = 0
        for i, w in enumerate(weights):
            cumulative += w
            if idx < cumulative:
                ops.append(builders[i]())
                break

    return ops


# ---------------------------------------------------------------------------
# Security / adversarial strategies
# ---------------------------------------------------------------------------

# Strings that look like SQL injection attempts
sql_injection_strings = st.sampled_from(
    [
        "'; DROP TABLE smt_leaves; --",
        "1 OR 1=1",
        "1; SELECT * FROM pg_tables",
        "admin'--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND '1'='1",
        "\\x00\\x1a",
        "/* comment */ SELECT 1",
    ]
)

# Strings that look like filesystem paths
path_like_strings = st.sampled_from(
    [
        "../../../etc/passwd",
        "/etc/shadow",
        "C:\\Windows\\System32\\config\\SAM",
        "../../secret",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd",
    ]
)

# Strings containing null bytes and control characters
control_char_strings = st.sampled_from(
    [
        "\x00",
        "\x00test\x00",
        "test\x1atest",
        "test\r\ntest",
        "test\x0btest",
        "\xff\xfe",
    ]
)


# Deeply nested JSON-like structures (up to depth 70, above MAX_CONTENT_DEPTH=64)
def deeply_nested_dict(depth: int = 70) -> dict[str, Any]:
    """Build a dict nested to the given depth."""
    result: dict[str, Any] = {"leaf": "value"}
    for _ in range(depth):
        result = {"child": result}
    return result


oversized_field_strings = st.one_of(
    st.just("x" * (16 * 1024 * 1024 + 1)),  # > 16 MiB
    st.just("a" * 100_000),
    st.text(min_size=10_000, max_size=20_000),
)

# Unicode edge cases.
# Note: lone surrogates (\ud800, \udc00) are excluded because Python's standard
# json.dumps rejects them, making them impossible to send in an HTTP JSON body.
# The API therefore never sees them — they would produce a test-client encoding
# error before reaching the server.
unicode_edge_strings = st.sampled_from(
    [
        "\u0000",  # null byte
        "\ufffe",  # BOM
        "\u202e",  # right-to-left override
        "\u00e9",  # NFC e-acute
        "\u0065\u0301",  # NFD e + combining accent (semantically equal to \u00e9)
        "\uff41",  # fullwidth Latin small a
        "\u0041\u0301",  # A + combining accent
        "テスト",  # Japanese
        "测试",  # Chinese
        "🔐",  # Emoji
    ]
)

# Malformed auth header values
malformed_auth_headers = st.sampled_from(
    [
        "",
        "Bearer ",
        "Bearer " + "x" * 512,
        "Basic dXNlcjpwYXNz",  # Basic auth (wrong scheme)
        "NotBearer abc123",
        "\x00\x01\x02",
        "Bearer\t",
        "Bearer" + " " * 200 + "key",
    ]
)

# Invalid shard ID patterns
invalid_shard_ids = st.sampled_from(
    [
        "",
        " ",
        "\x00",
        "../shard",
        "shard; DROP TABLE",
        "shard\ninjection",
        "a" * 300,  # exceeds IDENTIFIER_MAX_LEN=256
        "shard/../../etc",
        "shard\x00null",
    ]
)


# Semantically equivalent content pairs for canonicalization testing
@st.composite
def semantically_equivalent_content_pair(draw: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Draw a (doc_a, doc_b) pair that are semantically identical but may differ
    in key ordering (canonical JSON should produce the same hash).
    """
    keys = draw(
        st.lists(
            st.text(alphabet=string.ascii_letters, min_size=1, max_size=16),
            min_size=2,
            max_size=8,
            unique=True,
        )
    )
    values = {k: draw(st.one_of(st.text(max_size=32), st.integers())) for k in keys}
    # Produce two dicts with the same content but different creation order
    doc_a = dict(values)
    doc_b = dict(reversed(list(values.items())))
    return doc_a, doc_b


@st.composite
def semantically_different_content_pair(draw: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Draw a (doc_a, doc_b) pair that are semantically different — they must
    produce different canonical hashes.
    """
    doc_a = draw(content_dicts)
    # Mutate one value to ensure difference
    key = draw(st.sampled_from(list(doc_a.keys())))
    old_val = doc_a[key]
    new_val = draw(st.one_of(st.text(max_size=32), st.integers()))
    # Ensure actual difference
    while new_val == old_val:
        new_val = draw(st.one_of(st.text(max_size=32), st.integers()))
    doc_b = {**doc_a, key: new_val}
    return doc_a, doc_b

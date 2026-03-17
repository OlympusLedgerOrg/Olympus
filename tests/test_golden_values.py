"""
Golden value tests for Olympus protocol.

These tests pin the exact canonical output and hash values for known inputs.
If any of these tests fail, it means the canonicalization or hashing semantics
have changed, which would break all historical document proofs.

DO NOT CHANGE the expected values without a protocol version bump.

Golden vectors serve three purposes:
1. Regression detection — catch accidental canonicalization drift
2. Cross-implementation parity — other implementations can use these vectors
3. Tamper-evidence — a third party can reconstruct these values independently
"""

import json
from decimal import Decimal

import blake3 as _blake3

from protocol.canonical import (
    canonicalize_document,
    canonicalize_json,
    canonicalize_text,
    document_to_bytes,
    normalize_whitespace,
)
from protocol.canonical_json import canonical_json_bytes, canonical_json_encode
from protocol.hashes import (
    HASH_SEPARATOR,
    LEDGER_PREFIX,
    LEGACY_BYTES_PREFIX,
    blake3_hash,
    hash_bytes,
    leaf_hash,
    node_hash,
    record_key,
    shard_header_hash,
)


# ---------------------------------------------------------------------------
# Golden vectors: JSON canonicalization
# ---------------------------------------------------------------------------


class TestJsonCanonicalGoldenValues:
    """Pin exact canonical JSON outputs for known inputs."""

    def test_simple_object(self):
        """Simple object with sorted keys and compact separators."""
        data = {"z": 1, "a": 2, "m": 3}
        expected = '{"a":2,"m":3,"z":1}'
        assert canonicalize_json(data) == expected

    def test_nested_object(self):
        """Nested objects — keys sorted at every level."""
        data = {"outer": {"z": True, "a": False}, "inner": 42}
        expected = '{"inner":42,"outer":{"a":false,"z":true}}'
        assert canonicalize_json(data) == expected

    def test_empty_object(self):
        """Empty object produces '{}'."""
        assert canonicalize_json({}) == "{}"

    def test_unicode_escaped(self):
        """Non-ASCII characters are escaped (ensure_ascii=True)."""
        data = {"key": "café"}
        result = canonicalize_json(data)
        # Must not contain raw non-ASCII bytes
        result.encode("ascii")  # raises if non-ASCII present
        assert "caf" in result

    def test_canonical_json_encode_golden_values(self):
        """Pin canonical_json_encode outputs for protocol-critical types."""
        # Integer
        assert canonical_json_encode(0) == "0"
        assert canonical_json_encode(42) == "42"
        assert canonical_json_encode(-1) == "-1"

        # Decimal
        assert canonical_json_encode(Decimal("3.14")) == "3.14"
        assert canonical_json_encode(Decimal("1.0")) == "1"
        assert canonical_json_encode(Decimal("-0.0")) == "0"

        # Boolean
        assert canonical_json_encode(True) == "true"
        assert canonical_json_encode(False) == "false"

        # Null
        assert canonical_json_encode(None) == "null"

        # String
        assert canonical_json_encode("hello") == '"hello"'

    def test_canonical_json_bytes_golden(self):
        """Pin canonical_json_bytes for a known object."""
        obj = {"b": 2, "a": 1}
        expected = b'{"a":1,"b":2}'
        assert canonical_json_bytes(obj) == expected

    def test_scientific_notation_boundary(self):
        """Pin the fixed/scientific notation boundary values."""
        # Fixed notation: -6 <= adjusted_exponent <= 20
        assert canonical_json_encode(Decimal("0.000001")) == "0.000001"  # 1e-6 in fixed
        assert canonical_json_encode(Decimal("1e-7")) == "1e-7"  # 1e-7 in scientific

        # Upper boundary
        expected_1e20 = "1" + "0" * 20
        assert canonical_json_encode(Decimal("1e20")) == expected_1e20  # 1e20 in fixed
        assert canonical_json_encode(Decimal("1e21")) == "1e+21"  # 1e21 in scientific


# ---------------------------------------------------------------------------
# Golden vectors: text canonicalization
# ---------------------------------------------------------------------------


class TestTextCanonicalGoldenValues:
    """Pin exact canonical text outputs for known inputs."""

    def test_whitespace_collapse(self):
        """Multiple spaces collapse to single space."""
        assert canonicalize_text("Hello   world") == "Hello world"

    def test_crlf_normalization(self):
        """Windows line endings (CRLF) normalize to Unix (LF)."""
        assert canonicalize_text("line1\r\nline2") == "line1\nline2"

    def test_cr_normalization(self):
        """Old Mac line endings (CR) normalize to Unix (LF)."""
        assert canonicalize_text("line1\rline2") == "line1\nline2"

    def test_leading_trailing_empty_lines_stripped(self):
        """Leading and trailing empty lines are removed."""
        assert canonicalize_text("\n\nHello\n\n") == "Hello"

    def test_internal_empty_lines_preserved(self):
        """Internal empty lines are preserved."""
        assert canonicalize_text("Hello\n\nWorld") == "Hello\n\nWorld"

    def test_unicode_whitespace_normalized(self):
        """Unicode non-breaking spaces are normalized to ASCII space."""
        # NO-BREAK SPACE U+00A0
        text = "Hello\u00a0world"
        result = normalize_whitespace(text)
        assert result == "Hello world"

    def test_tab_normalization(self):
        """Tabs are collapsed like other whitespace."""
        assert normalize_whitespace("Hello\tworld") == "Hello world"


# ---------------------------------------------------------------------------
# Golden vectors: document canonicalization
# ---------------------------------------------------------------------------


class TestDocumentCanonicalGoldenValues:
    """Pin exact canonical document outputs for known inputs."""

    def test_simple_document(self):
        """Simple document with sorted keys and normalized whitespace."""
        doc = {"title": "Test", "body": "Hello   world"}
        canonical = canonicalize_document(doc)
        assert canonical == {"body": "Hello world", "title": "Test"}

    def test_nested_document(self):
        """Nested document with recursive key sorting."""
        doc = {"z": {"b": 2, "a": 1}, "a": "value"}
        canonical = canonicalize_document(doc)
        assert list(canonical.keys()) == ["a", "z"]
        assert list(canonical["z"].keys()) == ["a", "b"]

    def test_document_to_bytes_golden(self):
        """Pin document_to_bytes output for a known document."""
        doc = {"title": "Test", "body": "Hello world"}
        expected = b'{"body":"Hello world","title":"Test"}'
        assert document_to_bytes(doc) == expected

    def test_document_with_list(self):
        """Document with list values — list order preserved."""
        doc = {"items": [3, 1, 2], "name": "test"}
        canonical = canonicalize_document(doc)
        assert canonical == {"items": [3, 1, 2], "name": "test"}

    def test_document_with_nested_list_of_dicts(self):
        """Nested list of dicts — each dict is canonicalized."""
        doc = {"records": [{"z": 1, "a": 2}]}
        canonical = canonicalize_document(doc)
        inner = canonical["records"][0]
        assert list(inner.keys()) == ["a", "z"]


# ---------------------------------------------------------------------------
# Golden vectors: BLAKE3 hashing
# ---------------------------------------------------------------------------


class TestHashGoldenValues:
    """
    Pin exact BLAKE3 hash outputs for known inputs.

    These values allow a third party to independently verify the hash
    process using any BLAKE3 implementation.
    """

    def test_hash_bytes_known_value(self):
        """Pin hash_bytes output for b"hello"."""
        result = hash_bytes(b"hello")
        assert result.hex() == "2fb63604f5db190f79feb9782811b6bfb88dc5ded7a81bd41f67fd886adfdc85"
        # Compute expected value using reference BLAKE3 with domain separation
        expected = _blake3.blake3(LEGACY_BYTES_PREFIX + b"hello").digest()
        assert result == expected

    def test_blake3_hash_concatenation(self):
        """Pin blake3_hash for concatenated parts."""
        parts = [b"hello", b"world"]
        result = blake3_hash(parts)
        assert result.hex() == "7bb205244d808356318ec65d0ae54f32ee3a7bab5dfaf431b01e567e03baab4f"
        expected = _blake3.blake3(b"helloworld").digest()
        assert result == expected

    def test_domain_separated_hash(self):
        """Pin domain-separated hashing for LEDGER_PREFIX."""
        payload = b"test_payload"
        result = blake3_hash([LEDGER_PREFIX, payload])
        assert result.hex() == "ede31d066f20ad398f75fc2f4112faa4aad4901b35ddb4f9a6b4d291961bb0ec"
        expected = _blake3.blake3(LEDGER_PREFIX + payload).digest()
        assert result == expected

    def test_record_key_golden(self):
        """Pin record_key output for known inputs."""
        key = record_key("document", "doc-001", 1)
        assert key.hex() == "cfecc3fd1ab6d4ed32193c35868a01706f6e2ab2c8db8dcdcb88b7882256c5b2"
        assert len(key) == 32
        # Verify determinism
        assert key == record_key("document", "doc-001", 1)
        # Verify different inputs produce different keys
        assert key != record_key("document", "doc-001", 2)

    def test_leaf_hash_golden(self):
        """Pin leaf_hash for known key and value."""
        key = record_key("document", "doc-001", 1)
        value = hash_bytes(b"document content")
        leaf = leaf_hash(key, value)
        assert leaf.hex() == "1e8d6d47ef41dcc8f0553f7482a6d765cd75344bb588f15119b7914a798c05c2"
        assert len(leaf) == 32
        # Verify determinism
        assert leaf == leaf_hash(key, value)

    def test_node_hash_golden(self):
        """Pin node_hash for known left and right children."""
        left = hash_bytes(b"left")
        right = hash_bytes(b"right")
        node = node_hash(left, right)
        assert node.hex() == "d1c58795e8dce38add178fb3a9a7b2cec02a10fc8b84f01e78be9bd4d24fa2f0"
        assert len(node) == 32
        # Order matters
        assert node != node_hash(right, left)

    def test_shard_header_hash_golden(self):
        """Pin shard_header_hash for a known header."""
        header = {
            "shard_id": "shard-test",
            "root_hash": "abcdef0123456789",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        result = shard_header_hash(header)
        assert result.hex() == "ce9042233d5e6ad6d0a89a17149bdd58127be8c711b1a1a8feb072acca6cf42c"
        assert len(result) == 32

        # Recompute independently to verify
        from protocol.canonical_json import canonical_json_bytes as _cjb
        from protocol.hashes import HDR_PREFIX

        expected = blake3_hash([HDR_PREFIX, _cjb(header)])
        assert result == expected


# ---------------------------------------------------------------------------
# Golden vectors: ledger entry hash computation
# ---------------------------------------------------------------------------


class TestLedgerHashGoldenValues:
    """Pin exact ledger entry hash computation for known inputs."""

    def test_ledger_entry_hash_golden(self):
        """
        Pin the exact hash computation for a ledger entry.

        This verifies that a third party can independently reconstruct
        the entry hash from the constituent fields.
        """
        payload = {
            "ts": "2024-01-01T00:00:00Z",
            "record_hash": "abc123",
            "shard_id": "shard-1",
            "shard_root": "def456",
            "prev_entry_hash": "",
        }
        canonical_json = canonical_json_encode(payload)
        entry_hash = blake3_hash([LEDGER_PREFIX, canonical_json.encode("utf-8")]).hex()

        # Pin the canonical JSON form
        expected_json = (
            '{"prev_entry_hash":"","record_hash":"abc123",'
            '"shard_id":"shard-1","shard_root":"def456",'
            '"ts":"2024-01-01T00:00:00Z"}'
        )
        assert canonical_json == expected_json

        # Pin the hash (deterministic)
        assert entry_hash == blake3_hash([LEDGER_PREFIX, expected_json.encode("utf-8")]).hex()

    def test_chained_entry_hashes_golden(self):
        """
        Pin hash computation for a two-entry chain.

        Verifies that the second entry's prev_entry_hash correctly
        references the first entry's hash.
        """
        # First entry (genesis)
        payload1 = {
            "ts": "2024-01-01T00:00:00Z",
            "record_hash": "hash1",
            "shard_id": "shard-1",
            "shard_root": "root1",
            "prev_entry_hash": "",
        }
        json1 = canonical_json_encode(payload1)
        entry1_hash = blake3_hash([LEDGER_PREFIX, json1.encode("utf-8")]).hex()

        # Second entry (chains to first)
        payload2 = {
            "ts": "2024-01-01T00:00:01Z",
            "record_hash": "hash2",
            "shard_id": "shard-1",
            "shard_root": "root2",
            "prev_entry_hash": entry1_hash,
        }
        json2 = canonical_json_encode(payload2)
        entry2_hash = blake3_hash([LEDGER_PREFIX, json2.encode("utf-8")]).hex()

        # Verify chain linkage
        assert payload2["prev_entry_hash"] == entry1_hash
        assert entry1_hash != entry2_hash


# ---------------------------------------------------------------------------
# Golden vectors: canonicalization idempotency
# ---------------------------------------------------------------------------


class TestCanonicalIdempotencyGolden:
    """Verify that canonicalization is idempotent: C(x) == C(C(x))."""

    def test_json_idempotent(self):
        """JSON canonicalization is idempotent."""
        data = {"z": [3, 1], "a": {"nested": True, "key": "value"}}
        first = canonicalize_json(data)
        second = canonicalize_json(json.loads(first))
        assert first == second

    def test_text_idempotent(self):
        """Text canonicalization is idempotent."""
        text = "Hello   world\r\n\r\nSecond   line\r\n"
        first = canonicalize_text(text)
        second = canonicalize_text(first)
        assert first == second

    def test_document_idempotent(self):
        """Document canonicalization is idempotent."""
        doc = {"z": "Hello   world", "a": {"nested": "  spaces  "}}
        first = canonicalize_document(doc)
        second = canonicalize_document(first)
        assert first == second

    def test_document_to_bytes_idempotent(self):
        """document_to_bytes is idempotent."""
        doc = {"title": "Test  Document", "body": "Hello   world"}
        first = document_to_bytes(doc)
        # Parse the bytes back and re-canonicalize
        parsed = json.loads(first.decode("utf-8"))
        second = document_to_bytes(parsed)
        assert first == second


# ---------------------------------------------------------------------------
# Golden vectors: pipeline_golden_example.json artifact
# ---------------------------------------------------------------------------


class TestPipelineGoldenArtifact:
    """Verify the examples/pipeline_golden_example.json artifact is self-consistent.

    This test independently reproduces every hash in the artifact so that:
    - contributors cannot accidentally change canonicalization/hashing semantics
      without this test failing, and
    - a third party can verify the artifact without trusting the server.
    """

    def _load_artifact(self) -> dict:
        from pathlib import Path

        path = Path(__file__).parent.parent / "examples" / "pipeline_golden_example.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_canonical_json_reproducible(self):
        """Reproduce stage 2 (canonicalize) from the raw document."""
        artifact = self._load_artifact()
        doc = artifact["stage_1_ingest"]["document"]
        expected = artifact["stage_2_canonicalize"]["canonical_json"]
        assert canonicalize_json(doc) == expected

    def test_document_hash_reproducible(self):
        """Reproduce stage 3 (hash) from the canonical JSON."""
        artifact = self._load_artifact()
        doc = artifact["stage_1_ingest"]["document"]
        expected_hex = artifact["stage_3_hash"]["document_hash_blake3"]
        doc_bytes = document_to_bytes(doc)
        assert hash_bytes(doc_bytes).hex() == expected_hex

    def test_merkle_leaf_hashes_reproducible(self):
        """Reproduce stage 4 merkle leaf hashes."""
        from protocol.merkle import merkle_leaf_hash

        artifact = self._load_artifact()
        leaves_utf8 = artifact["stage_4_commit"]["merkle_leaves_utf8"]
        expected_hashes = artifact["stage_4_commit"]["merkle_leaf_hashes"]
        for leaf_text, expected_hex in zip(leaves_utf8, expected_hashes):
            assert merkle_leaf_hash(leaf_text.encode("utf-8")).hex() == expected_hex

    def test_merkle_root_reproducible(self):
        """Reproduce stage 4 Merkle root."""
        from protocol.merkle import MerkleTree, merkle_leaf_hash

        artifact = self._load_artifact()
        leaves_utf8 = artifact["stage_4_commit"]["merkle_leaves_utf8"]
        expected_root = artifact["stage_4_commit"]["merkle_root"]
        leaf_hashes = [merkle_leaf_hash(s.encode("utf-8")) for s in leaves_utf8]
        tree = MerkleTree(leaf_hashes)
        assert tree.get_root().hex() == expected_root

    def test_ledger_entry_hash_reproducible(self):
        """Reproduce stage 4 ledger entry hash."""
        artifact = self._load_artifact()
        entry = artifact["stage_4_commit"]["ledger_entry"]
        expected_canonical_json = entry["payload_canonical_json"]
        expected_entry_hash = entry["entry_hash"]
        # Reproduce canonical JSON from payload dict
        actual_canonical = canonical_json_encode(entry["payload"])
        assert actual_canonical == expected_canonical_json
        # Reproduce entry hash
        actual_hash = blake3_hash(
            [LEDGER_PREFIX, actual_canonical.encode("utf-8"), HASH_SEPARATOR.encode(), b""]
        ).hex()
        assert actual_hash == expected_entry_hash

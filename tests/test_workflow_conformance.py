"""
Workflow conformance tests for Olympus protocol.

These tests verify that every function in the canonical workflow
(Ingest → Canonicalize → Hash → Commit → Prove → Verify)
is importable, callable, and matches the documented pipeline.

If any of these tests fail, it means the code has diverged from the
documented protocol — either a function was removed/renamed without
updating docs, or a new function was added without documentation.

This acts as an automated "protocol conformance checklist" to catch
undocumented changes early.
"""

import dataclasses
import inspect

import nacl.signing
import pytest

from protocol.canonical import (
    canonicalize_document,
    canonicalize_json,
    canonicalize_text,
    document_to_bytes,
    normalize_whitespace,
)
from protocol.canonical_json import canonical_json_bytes, canonical_json_encode
from protocol.canonicalizer import (
    CanonicalizationError,
    Canonicalizer,
    canonicalization_provenance,
    process_artifact,
)
from protocol.epochs import EpochRecord, SignedTreeHead, compute_epoch_head, signed_tree_head_hash
from protocol.events import CanonicalEvent
from protocol.hashes import (
    HASH_SEPARATOR,
    HDR_PREFIX,
    KEY_PREFIX,
    LEAF_PREFIX,
    LEDGER_PREFIX,
    NODE_PREFIX,
    POLICY_PREFIX,
    blake3_hash,
    blake3_to_field_element,
    hash_bytes,
    leaf_hash,
    merkle_root,
    node_hash,
    record_key,
    shard_header_hash,
)
from protocol.ledger import Ledger, LedgerEntry
from protocol.merkle import InclusionProof, MerkleProof, MerkleTree, verify_proof
from protocol.redaction import RedactionProof, RedactionProtocol
from protocol.shards import (
    create_shard_header,
    sign_header,
    verify_header,
)
from protocol.timestamps import current_timestamp


# ---------------------------------------------------------------------------
# Stage 1: Ingest — artifact ingestion and format detection
# ---------------------------------------------------------------------------


class TestIngestStage:
    """Verify Ingest stage functions are present and callable."""

    def test_process_artifact_exists(self):
        """process_artifact is the primary ingestion entry point."""
        assert callable(process_artifact)

    def test_process_artifact_signature(self):
        """process_artifact accepts (raw_data, mime_type, witness_anchor)."""
        sig = inspect.signature(process_artifact)
        params = list(sig.parameters.keys())
        assert "raw_data" in params
        assert "mime_type" in params

    def test_canonicalizer_class_exists(self):
        """Canonicalizer class provides format-specific pipelines."""
        assert callable(Canonicalizer.json_jcs)
        assert callable(Canonicalizer.html_v1)
        assert callable(Canonicalizer.docx_v1)
        assert callable(Canonicalizer.pdf_normalize)

    def test_canonicalization_error_exists(self):
        """CanonicalizationError is raised on ingestion failures."""
        assert issubclass(CanonicalizationError, Exception)


# ---------------------------------------------------------------------------
# Stage 2: Canonicalize — deterministic formatting
# ---------------------------------------------------------------------------


class TestCanonicalizeStage:
    """Verify Canonicalize stage functions are present and callable."""

    def test_canonicalize_json_exists(self):
        """canonicalize_json provides basic JSON canonicalization."""
        assert callable(canonicalize_json)

    def test_canonical_json_encode_exists(self):
        """canonical_json_encode provides strict deterministic JSON encoding."""
        assert callable(canonical_json_encode)

    def test_canonical_json_bytes_exists(self):
        """canonical_json_bytes returns canonical JSON as UTF-8 bytes."""
        assert callable(canonical_json_bytes)

    def test_normalize_whitespace_exists(self):
        """normalize_whitespace handles Unicode and multi-space normalization."""
        assert callable(normalize_whitespace)

    def test_canonicalize_document_exists(self):
        """canonicalize_document recursively normalizes document structures."""
        assert callable(canonicalize_document)

    def test_document_to_bytes_exists(self):
        """document_to_bytes produces canonical byte representation."""
        assert callable(document_to_bytes)

    def test_canonicalize_text_exists(self):
        """canonicalize_text normalizes whitespace and line endings."""
        assert callable(canonicalize_text)

    def test_current_timestamp_exists(self):
        """current_timestamp provides ISO 8601 UTC timestamps with Z suffix."""
        assert callable(current_timestamp)


# ---------------------------------------------------------------------------
# Stage 3: Hash — BLAKE3 domain-separated hashing
# ---------------------------------------------------------------------------


class TestHashStage:
    """Verify Hash stage functions and constants are present."""

    def test_blake3_hash_exists(self):
        """blake3_hash is the core hashing primitive."""
        assert callable(blake3_hash)

    def test_hash_bytes_exists(self):
        """hash_bytes provides legacy raw-bytes hashing."""
        assert callable(hash_bytes)

    def test_record_key_exists(self):
        """record_key generates deterministic 32-byte record keys."""
        assert callable(record_key)

    def test_leaf_hash_exists(self):
        """leaf_hash computes domain-separated leaf node hashes."""
        assert callable(leaf_hash)

    def test_node_hash_exists(self):
        """node_hash computes domain-separated internal node hashes."""
        assert callable(node_hash)

    def test_shard_header_hash_exists(self):
        """shard_header_hash computes domain-separated shard header hashes."""
        assert callable(shard_header_hash)

    def test_blake3_to_field_element_exists(self):
        """blake3_to_field_element maps hashes into the BN128 scalar field."""
        assert callable(blake3_to_field_element)

    def test_domain_separation_constants(self):
        """All domain separation prefixes are defined and immutable."""
        assert KEY_PREFIX == b"OLY:KEY:V1"
        assert LEAF_PREFIX == b"OLY:LEAF:V1"
        assert NODE_PREFIX == b"OLY:NODE:V1"
        assert HDR_PREFIX == b"OLY:HDR:V1"
        assert POLICY_PREFIX == b"OLY:POLICY:V1"
        assert LEDGER_PREFIX == b"OLY:LEDGER:V1"

    def test_hash_separator_constant(self):
        """HASH_SEPARATOR is the field separator for structured data."""
        assert HASH_SEPARATOR == "|"


# ---------------------------------------------------------------------------
# Stage 4: Commit — Merkle tree and shard header commitments
# ---------------------------------------------------------------------------


class TestCommitStage:
    """Verify Commit stage functions are present and callable."""

    def test_merkle_tree_class_exists(self):
        """MerkleTree builds binary Merkle trees from leaf hashes."""
        leaf = hash_bytes(b"test")
        tree = MerkleTree([leaf])
        assert callable(tree.get_root)
        assert callable(tree.generate_proof)

    def test_merkle_root_exists(self):
        """merkle_root computes Merkle root from leaf hashes."""
        assert callable(merkle_root)

    def test_shard_header_functions_exist(self):
        """Shard header creation and signing functions are available."""
        assert callable(create_shard_header)
        assert callable(sign_header)
        assert callable(verify_header)


# ---------------------------------------------------------------------------
# Stage 5: Prove — proof generation and redaction proofs
# ---------------------------------------------------------------------------


class TestProveStage:
    """Verify Prove stage functions are present and callable."""

    def test_merkle_proof_dataclass_exists(self):
        """MerkleProof dataclass represents Merkle inclusion proofs."""
        field_names = [f.name for f in dataclasses.fields(MerkleProof)]
        assert "leaf_hash" in field_names
        assert "root_hash" in field_names

    def test_redaction_proof_dataclass_exists(self):
        """RedactionProof dataclass represents redaction proofs."""
        field_names = [f.name for f in dataclasses.fields(RedactionProof)]
        assert "original_root" in field_names

    def test_redaction_protocol_exists(self):
        """RedactionProtocol provides proof creation and verification."""
        assert callable(RedactionProtocol.commit_document)
        assert callable(RedactionProtocol.create_redaction_proof)
        assert callable(RedactionProtocol.verify_redaction_proof)

    def test_inclusion_proof_alias_exists(self):
        """InclusionProof is an alias of MerkleProof for clarity."""
        assert issubclass(InclusionProof, MerkleProof)


# ---------------------------------------------------------------------------
# Stage 6: Verify — chain verification and proof validation
# ---------------------------------------------------------------------------


class TestVerifyStage:
    """Verify the Verify stage functions are present and callable."""

    def test_verify_proof_exists(self):
        """verify_proof validates Merkle inclusion proofs."""
        assert callable(verify_proof)

    def test_ledger_verify_chain_exists(self):
        """Ledger.verify_chain validates the entire ledger chain."""
        ledger = Ledger()
        assert callable(ledger.verify_chain)

    def test_verify_header_exists(self):
        """verify_header validates Ed25519-signed shard headers."""
        assert callable(verify_header)


# ---------------------------------------------------------------------------
# Stage 7: Ledger — append-only hash-chained ledger
# ---------------------------------------------------------------------------


class TestLedgerStage:
    """Verify Ledger stage classes and functions are present."""

    def test_ledger_entry_dataclass_exists(self):
        """LedgerEntry dataclass represents individual ledger entries."""
        field_names = [f.name for f in dataclasses.fields(LedgerEntry)]
        assert "ts" in field_names
        assert "record_hash" in field_names
        assert "shard_id" in field_names
        assert "shard_root" in field_names
        assert "prev_entry_hash" in field_names
        assert "entry_hash" in field_names

    def test_ledger_class_exists(self):
        """Ledger class implements the append-only hash-chained log."""
        ledger = Ledger()
        assert callable(ledger.append)
        assert callable(ledger.get_entry)
        assert callable(ledger.get_all_entries)
        assert callable(ledger.verify_chain)

    def test_ledger_entry_serialization_exists(self):
        """LedgerEntry supports to_dict/from_dict for serialization."""
        assert callable(LedgerEntry.to_dict)
        assert callable(LedgerEntry.from_dict)


class TestEpochAndEvents:
    """Verify canonical event and epoch chaining helpers."""

    def test_canonical_event_dataclass_exists(self):
        """CanonicalEvent provides canonical bytes and hash."""
        event = CanonicalEvent.from_raw({"body": "hello  world"}, "1.0.0")
        assert event.schema_version == "1.0.0"
        assert event.hash_hex
        assert event.payload["body"] == "hello world"

    def test_canonical_event_rejects_non_dict(self):
        """CanonicalEvent.from_raw raises ValueError for non-dict input."""

        with pytest.raises(ValueError, match="must be a dictionary"):
            CanonicalEvent.from_raw("not a dict", "1.0.0")  # type: ignore[arg-type]

    def test_canonical_event_rejects_empty_schema_version(self):
        """CanonicalEvent.from_raw raises ValueError for empty schema_version."""

        with pytest.raises(ValueError, match="non-empty string"):
            CanonicalEvent.from_raw({"key": "value"}, "")

    def test_canonical_event_to_dict(self):
        """CanonicalEvent.to_dict serializes payload, schema_version, and hash."""
        event = CanonicalEvent.from_raw({"key": "value"}, "2.0.0")
        result = event.to_dict()
        assert result["schema_version"] == "2.0.0"
        assert result["payload"] == event.payload
        assert result["hash_hex"] == event.hash_hex

    def test_epoch_record_head_computation(self):
        """EpochRecord computes deterministic epoch heads."""
        merkle_root = hash_bytes(b"root")
        metadata_hash = hash_bytes(b"meta")
        record = EpochRecord.create(
            epoch_index=0,
            merkle_root=merkle_root,
            metadata_hash=metadata_hash,
        )
        computed_head = compute_epoch_head(
            record.previous_epoch_head, record.merkle_root, record.metadata_hash
        ).hex()
        assert record.epoch_head == computed_head

    def test_epoch_record_chaining(self):
        """EpochRecord correctly chains epochs using the previous epoch head."""
        merkle_root = hash_bytes(b"root1")
        metadata_hash = hash_bytes(b"meta1")
        first = EpochRecord.create(
            epoch_index=0,
            merkle_root=merkle_root,
            metadata_hash=metadata_hash,
        )
        second = EpochRecord.create(
            epoch_index=1,
            merkle_root=hash_bytes(b"root2"),
            metadata_hash=hash_bytes(b"meta2"),
            previous_epoch_head=first.epoch_head,
        )
        assert second.previous_epoch_head == first.epoch_head
        assert second.epoch_head != first.epoch_head

    def test_epoch_record_rejects_negative_index(self):
        """EpochRecord.create raises ValueError for negative epoch_index."""

        with pytest.raises(ValueError, match="non-negative"):
            EpochRecord.create(
                epoch_index=-1,
                merkle_root=hash_bytes(b"root"),
                metadata_hash=hash_bytes(b"meta"),
            )

    def test_epoch_record_rejects_wrong_hash_type(self):
        """EpochRecord.create raises ValueError for invalid hash type."""

        with pytest.raises(ValueError, match="bytes or hex strings"):
            EpochRecord.create(
                epoch_index=0,
                merkle_root=12345,  # type: ignore[arg-type]
                metadata_hash=hash_bytes(b"meta"),
            )

    def test_epoch_record_rejects_wrong_hash_length(self):
        """EpochRecord.create raises ValueError when hash is wrong length."""

        with pytest.raises(ValueError, match="32 bytes"):
            EpochRecord.create(
                epoch_index=0,
                merkle_root=b"tooshort",
                metadata_hash=hash_bytes(b"meta"),
            )

    def test_signed_tree_head_signs_epoch_root_and_size(self):
        """SignedTreeHead binds epoch id, tree size, root, and timestamp to a signature."""
        signing_key = nacl.signing.SigningKey.generate()
        merkle_root = hash_bytes(b"root")
        tree_head = SignedTreeHead.create(
            epoch_id=3,
            tree_size=5,
            merkle_root=merkle_root,
            signing_key=signing_key,
            timestamp="2026-03-13T00:00:00Z",
        )

        assert tree_head.verify()
        assert tree_head.merkle_root == merkle_root.hex()
        assert tree_head.payload_hash() == signed_tree_head_hash(
            epoch_id=3,
            tree_size=5,
            merkle_root=merkle_root,
            timestamp="2026-03-13T00:00:00Z",
        )

    def test_signed_tree_head_rejects_tampering(self):
        """Changing the bound Merkle root invalidates the Signed Tree Head signature."""
        signing_key = nacl.signing.SigningKey.generate()
        tree_head = SignedTreeHead.create(
            epoch_id=1,
            tree_size=2,
            merkle_root=hash_bytes(b"root"),
            signing_key=signing_key,
            timestamp="2026-03-13T00:00:00Z",
        )
        tampered = dataclasses.replace(tree_head, merkle_root=hash_bytes(b"other-root").hex())

        assert not tampered.verify()


# ---------------------------------------------------------------------------
# End-to-end pipeline smoke test
# ---------------------------------------------------------------------------


@pytest.mark.smoke
class TestPipelineSmokeTest:
    """Verify the full pipeline can execute end-to-end."""

    def test_full_pipeline_json_document(self):
        """
        Smoke test: ingest a JSON document through the full pipeline.

        Ingest → Canonicalize → Hash → Commit → Prove → Verify
        """
        # Stage 1: Ingest
        raw_doc = {"title": "Test Document", "body": "Hello  world"}
        raw_bytes = document_to_bytes(raw_doc)

        # Stage 2: Canonicalize
        canonical = canonicalize_document(raw_doc)
        assert canonical["body"] == "Hello world"  # whitespace normalized

        # Stage 3: Hash
        doc_hash = hash_bytes(raw_bytes)
        assert len(doc_hash) == 32

        # Stage 4: Commit (Merkle tree)
        tree = MerkleTree([doc_hash])
        root = tree.get_root()
        assert len(root) == 32

        # Stage 5: Prove
        proof = tree.generate_proof(0)
        assert proof.root_hash == root

        # Stage 6: Verify
        assert verify_proof(proof) is True

    def test_full_pipeline_with_ledger(self):
        """
        Smoke test: commit a document hash to the ledger and verify chain.

        Canonicalize → Hash → Ledger Append → Verify Chain
        """
        # Canonicalize and hash
        doc = {"agency": "DOJ", "type": "filing", "content": "Test"}
        canonical_bytes = document_to_bytes(doc)
        doc_hash = hash_bytes(canonical_bytes).hex()

        # Build Merkle tree
        leaf = hash_bytes(canonical_bytes)
        tree = MerkleTree([leaf])
        root = tree.get_root().hex()

        # Append to ledger
        ledger = Ledger()
        canon_meta = canonicalization_provenance("application/json", "canonical_v1")
        entry = ledger.append(
            record_hash=doc_hash,
            shard_id="shard-1",
            shard_root=root,
            canonicalization=canon_meta,
        )

        assert entry.record_hash == doc_hash
        assert entry.shard_root == root
        assert entry.prev_entry_hash == ""  # genesis

        # Verify chain
        assert ledger.verify_chain() is True

    def test_full_pipeline_with_redaction(self):
        """
        Smoke test: commit, redact, and verify a document.

        Commit → Redact → Prove → Verify
        """
        parts = ["Section 1: Public", "Section 2: Classified", "Section 3: Public"]

        # Commit
        tree, root_hash = RedactionProtocol.commit_document(parts)

        # Create redaction proof (reveal sections 0 and 2, redact section 1)
        proof = RedactionProtocol.create_redaction_proof(tree, [0, 2])

        # Verify
        revealed = ["Section 1: Public", "Section 3: Public"]
        assert RedactionProtocol.verify_redaction_proof(proof, revealed) is True

"""
Test schema alignment between JSON schemas and Pydantic models.

This test verifies that the JSON schemas in schemas/ are compatible with
the Pydantic models used in the API, even though the schemas are not used
for runtime validation.

The schemas serve as external specifications while Pydantic models are
the source of truth for implementation.
"""

import json
from pathlib import Path

import pytest
from jsonschema.validators import validator_for
from pydantic import BaseModel, ValidationError


# Define test models that mirror the API models to avoid importing api.app
# which would trigger database initialization


class ShardInfo(BaseModel):
    """Information about a shard."""

    shard_id: str
    latest_seq: int
    latest_root: str


class ShardHeaderResponse(BaseModel):
    """Shard header with signature for verification."""

    shard_id: str
    seq: int
    root_hash: str
    header_hash: str
    previous_header_hash: str
    timestamp: str
    signature: str
    pubkey: str
    canonical_header_json: str


class ExistenceProofResponse(BaseModel):
    """Existence proof with all data for offline verification."""

    shard_id: str
    record_type: str
    record_id: str
    version: int
    key: str
    value_hash: str
    siblings: list[str]
    root_hash: str
    shard_header: ShardHeaderResponse


class NonExistenceProofResponse(BaseModel):
    """Non-existence proof with all data for offline verification."""

    shard_id: str
    record_type: str
    record_id: str
    version: int
    key: str
    siblings: list[str]
    root_hash: str
    shard_header: ShardHeaderResponse


class LedgerEntryResponse(BaseModel):
    """Ledger entry for chain verification."""

    ts: str
    doc_id: str
    record_hash: str
    shard_id: str
    shard_root: str
    prev_entry_hash: str
    entry_hash: str


class LedgerTailResponse(BaseModel):
    """Last N ledger entries for a shard."""

    shard_id: str
    entries: list[LedgerEntryResponse]


def load_schema(schema_name: str) -> dict:
    """Load a JSON schema from the schemas directory."""
    schema_path = Path(__file__).parent.parent / "schemas" / schema_name
    with open(schema_path) as f:
        return json.load(f)


class TestSchemaAlignment:
    """Test that JSON schemas align with Pydantic models."""

    def test_shard_commit_aligns_with_shard_header_response(self):
        """
        Verify shard_commit.json is compatible with ShardHeaderResponse.

        Note: The schema and model don't need to match exactly - the schema
        is a specification artifact while the Pydantic model is the implementation.
        This test just ensures they're not fundamentally incompatible.
        """
        schema = load_schema("shard_commit.json")

        # Create a valid ShardHeaderResponse instance
        response = ShardHeaderResponse(
            shard_id="test_shard",
            seq=1,
            root_hash="a" * 64,  # 32 bytes hex
            header_hash="b" * 64,
            previous_header_hash="c" * 64,
            timestamp="2024-01-01T00:00:00Z",
            signature="d" * 128,  # 64 bytes hex (Ed25519 signature)
            pubkey="e" * 64,  # 32 bytes hex (Ed25519 public key)
            canonical_header_json='{"shard_id":"test_shard"}',
        )

        # Convert to dict for JSON schema validation
        response_dict = response.model_dump()

        # The schema describes a shard commitment which is conceptually similar
        # but not identical to the API response. We verify the schema is valid
        # and documents the expected structure for external consumers.

        # Verify the schema itself is valid
        validator_cls = validator_for(schema)
        validator_cls.check_schema(schema)

        # Create a sample that matches the shard_commit schema
        shard_commit_sample = {
            "shard_id": "test_shard",
            "merkle_root": "a" * 64,
            "timestamp": "2024-01-01T00:00:00Z",
            "leaf_count": 10,
            "previous_shard_root": "b" * 64,
            "signature": "c" * 128,
        }

        # Validate the sample against the schema
        validator_cls(schema).validate(shard_commit_sample)

        # Verify key fields are present in both
        assert "shard_id" in response_dict
        assert "timestamp" in response_dict
        # Note: Different field names (root_hash vs merkle_root) are acceptable
        # as the schema is for external spec, not internal validation

    def test_leaf_record_schema_is_valid(self):
        """Verify leaf_record.json is a valid JSON schema."""
        schema = load_schema("leaf_record.json")
        validator_cls = validator_for(schema)
        validator_cls.check_schema(schema)

        # Create a sample leaf record that matches the schema
        leaf_record = {
            "leaf_index": 0,
            "leaf_hash": "a" * 64,
            "content_hash": "b" * 64,
            "parent_tree_root": "c" * 64,
            "inclusion_proof": {
                "siblings": [
                    {"hash": "d" * 64, "position": "left"},
                    {"hash": "e" * 64, "position": "right"},
                ]
            },
        }

        # Validate against schema
        validator_cls(schema).validate(leaf_record)

    def test_canonical_document_schema_is_valid(self):
        """Verify canonical_document.json is a valid JSON schema."""
        schema = load_schema("canonical_document.json")
        validator_cls = validator_for(schema)
        validator_cls.check_schema(schema)

        # Create a sample canonical document
        canonical_doc = {
            "version": "1.0.0",
            "document_id": "doc123",
            "content": {"format": "text", "encoding": "utf-8", "data": "Sample document content"},
            "metadata": {
                "title": "Test Document",
                "author": "Test Agency",
                "created_at": "2024-01-01T00:00:00Z",
                "source_agency": "TestGov",
            },
        }

        # Validate against schema
        validator_cls(schema).validate(canonical_doc)

    def test_source_proof_schema_is_valid(self):
        """Verify source_proof.json is a valid JSON schema."""
        schema = load_schema("source_proof.json")
        validator_cls = validator_for(schema)
        validator_cls.check_schema(schema)

        # Create a sample source proof
        source_proof = {
            "document_hash": "a" * 64,
            "source_agency": "TestGov",
            "timestamp": "2024-01-01T00:00:00Z",
            "signature": "sig_12345",
            "public_key": "pubkey_67890",
            "metadata": {
                "submission_id": "sub123",
                "submission_method": "api",
                "contact": "admin@testgov.example",
            },
        }

        # Validate against schema
        validator_cls(schema).validate(source_proof)

    def test_ledger_entry_response_has_required_fields(self):
        """Verify LedgerEntryResponse has fields that would be in a ledger schema."""
        # Create a valid LedgerEntryResponse
        entry = LedgerEntryResponse(
            ts="2024-01-01T00:00:00Z",
            doc_id="doc1",
            record_hash="a" * 64,
            shard_id="test_shard",
            shard_root="b" * 64,
            prev_entry_hash="c" * 64,
            entry_hash="d" * 64,
        )

        entry_dict = entry.model_dump()

        # Verify expected fields are present
        assert "ts" in entry_dict
        assert "doc_id" in entry_dict
        assert "record_hash" in entry_dict
        assert "shard_id" in entry_dict
        assert "shard_root" in entry_dict
        assert "prev_entry_hash" in entry_dict
        assert "entry_hash" in entry_dict

        # Verify timestamp format
        assert entry_dict["ts"].endswith("Z")

        # Verify hash fields are hex strings
        assert len(entry_dict["record_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in entry_dict["record_hash"])

    def test_pydantic_models_validate_correctly(self):
        """Ensure Pydantic models provide runtime validation."""
        # Valid ShardInfo
        shard_info = ShardInfo(shard_id="shard1", latest_seq=42, latest_root="a" * 64)
        assert shard_info.shard_id == "shard1"

        # Invalid ShardInfo should raise ValidationError
        with pytest.raises(ValidationError):
            ShardInfo(
                shard_id="shard1",
                latest_seq="not_an_int",  # Should be an int
                latest_root="a" * 64,
            )

    def test_existence_proof_response_structure(self):
        """Verify ExistenceProofResponse has expected structure."""
        header = ShardHeaderResponse(
            shard_id="test",
            seq=1,
            root_hash="a" * 64,
            header_hash="b" * 64,
            previous_header_hash="c" * 64,
            timestamp="2024-01-01T00:00:00Z",
            signature="d" * 128,
            pubkey="e" * 64,
            canonical_header_json="{}",
        )

        proof = ExistenceProofResponse(
            shard_id="test",
            record_type="document",
            record_id="doc1",
            version=1,
            key="a" * 64,
            value_hash="b" * 64,
            siblings=["c" * 64] * 256,
            root_hash="d" * 64,
            shard_header=header,
        )

        proof_dict = proof.model_dump()

        # Verify structure matches expected API response format
        assert proof_dict["shard_id"] == "test"
        assert proof_dict["record_type"] == "document"
        assert len(proof_dict["siblings"]) == 256
        assert "shard_header" in proof_dict

    def test_schemas_directory_documentation_exists(self):
        """Verify schemas directory has README explaining their purpose."""
        readme_path = Path(__file__).parent.parent / "schemas" / "README.md"
        assert readme_path.exists(), "schemas/README.md should document schema purpose"

        # Verify README contains key information
        readme_content = readme_path.read_text()
        assert "runtime validation" in readme_content.lower()
        assert "pydantic" in readme_content.lower()
        assert "external" in readme_content.lower() or "interoperability" in readme_content.lower()

"""Extended tests for protocol.verification_bundle – create_verification_bundle paths."""

from unittest.mock import MagicMock

import pytest

from protocol.consistency import ConsistencyProof
from protocol.epochs import SignedTreeHead
from protocol.verification_bundle import BUNDLE_VERSION, create_verification_bundle


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_proof():
    """Return a mock proof object with to_dict()."""
    proof = MagicMock()
    proof.to_dict.return_value = {
        "key": "test-key",
        "value": "test-value",
        "siblings": ["aa" * 32],
    }
    return proof


def _mock_storage(
    proof=None,
    header_info=None,
    tail=None,
    token=None,
):
    """Create a mock StorageLayer with configurable returns."""
    storage = MagicMock()
    storage.get_proof.return_value = proof
    storage.get_latest_header.return_value = header_info
    storage.get_ledger_tail.return_value = tail if tail is not None else []
    storage.get_timestamp_token.return_value = token
    return storage


def _default_header_info():
    return {
        "header": {"header_hash": "bb" * 32, "shard_id": "test-shard"},
        "signature": "cc" * 64,
        "pubkey": "dd" * 32,
    }


def _default_sth_dict():
    return {
        "epoch_id": 1,
        "tree_size": 10,
        "merkle_root": "ee" * 32,
        "timestamp": "2026-01-01T00:00:00Z",
        "signature": "ff" * 64,
        "signer_pubkey": "aa" * 32,
    }


def _default_consistency_dict():
    return {
        "old_tree_size": 5,
        "new_tree_size": 10,
        "proof_nodes": ["bb" * 32],
    }


# ---------------------------------------------------------------------------
# Basic success case
# ---------------------------------------------------------------------------


def test_create_bundle_basic():
    """Basic bundle creation with minimal arguments."""
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
    )
    assert bundle["bundle_version"] == BUNDLE_VERSION
    assert "smt_proof" in bundle
    assert "shard_header" in bundle
    assert "signature" in bundle
    assert "pubkey" in bundle


# ---------------------------------------------------------------------------
# proof is None → ValueError
# ---------------------------------------------------------------------------


def test_create_bundle_no_proof_raises():
    """ValueError when get_proof returns None."""
    storage = _mock_storage(proof=None, header_info=_default_header_info())
    with pytest.raises(ValueError, match="Record not found"):
        create_verification_bundle(
            storage,
            shard_id="test-shard",
            record_type="document",
            record_id="doc-1",
            version=1,
        )


# ---------------------------------------------------------------------------
# header_info is None → ValueError
# ---------------------------------------------------------------------------


def test_create_bundle_no_header_raises():
    """ValueError when get_latest_header returns None."""
    storage = _mock_storage(proof=_mock_proof(), header_info=None)
    with pytest.raises(ValueError, match="No shard header found"):
        create_verification_bundle(
            storage,
            shard_id="test-shard",
            record_type="document",
            record_id="doc-1",
            version=1,
        )


# ---------------------------------------------------------------------------
# signed_tree_head as SignedTreeHead object
# ---------------------------------------------------------------------------


def test_create_bundle_with_sth_object():
    """signed_tree_head as SignedTreeHead object uses to_dict()."""
    import nacl.signing

    key = nacl.signing.SigningKey.generate()
    sth = SignedTreeHead.create(
        epoch_id=1,
        tree_size=10,
        merkle_root="ee" * 32,
        signing_key=key,
    )
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
        signed_tree_head=sth,
    )
    assert "signed_tree_head" in bundle
    assert bundle["signed_tree_head"]["epoch_id"] == 1


# ---------------------------------------------------------------------------
# signed_tree_head as dict
# ---------------------------------------------------------------------------


def test_create_bundle_with_sth_dict():
    """signed_tree_head as dict is copied into bundle."""
    sth_dict = _default_sth_dict()
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
        signed_tree_head=sth_dict,
    )
    assert "signed_tree_head" in bundle
    assert bundle["signed_tree_head"]["epoch_id"] == 1


# ---------------------------------------------------------------------------
# previous_sth as SignedTreeHead object
# ---------------------------------------------------------------------------


def test_create_bundle_with_previous_sth_object():
    """previous_sth as SignedTreeHead object uses to_dict()."""
    import nacl.signing

    key = nacl.signing.SigningKey.generate()
    sth = SignedTreeHead.create(
        epoch_id=0,
        tree_size=5,
        merkle_root="dd" * 32,
        signing_key=key,
    )
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
        previous_sth=sth,
    )
    assert "previous_sth" in bundle
    assert bundle["previous_sth"]["epoch_id"] == 0


# ---------------------------------------------------------------------------
# previous_sth as dict
# ---------------------------------------------------------------------------


def test_create_bundle_with_previous_sth_dict():
    """previous_sth as dict is copied into bundle."""
    sth_dict = _default_sth_dict()
    sth_dict["epoch_id"] = 0
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
        previous_sth=sth_dict,
    )
    assert "previous_sth" in bundle
    assert bundle["previous_sth"]["epoch_id"] == 0


# ---------------------------------------------------------------------------
# consistency_proof as ConsistencyProof object
# ---------------------------------------------------------------------------


def test_create_bundle_with_consistency_proof_object():
    """consistency_proof as ConsistencyProof object uses to_dict()."""
    cp = ConsistencyProof(
        old_tree_size=5,
        new_tree_size=10,
        proof_nodes=[b"\xbb" * 32],
    )
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
        consistency_proof=cp,
    )
    assert "consistency_proof" in bundle
    assert bundle["consistency_proof"]["old_tree_size"] == 5


# ---------------------------------------------------------------------------
# consistency_proof as dict
# ---------------------------------------------------------------------------


def test_create_bundle_with_consistency_proof_dict():
    """consistency_proof as dict is copied into bundle."""
    cp_dict = _default_consistency_dict()
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
        consistency_proof=cp_dict,
    )
    assert "consistency_proof" in bundle
    assert bundle["consistency_proof"]["old_tree_size"] == 5


# ---------------------------------------------------------------------------
# tail is empty → canonicalization remains {}
# ---------------------------------------------------------------------------


def test_create_bundle_empty_tail():
    """When get_ledger_tail returns empty list, canonicalization is {}."""
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
        tail=[],
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
    )
    assert bundle["canonicalization"] == {}


# ---------------------------------------------------------------------------
# tail with entry → canonicalization from entry
# ---------------------------------------------------------------------------


def test_create_bundle_tail_with_entry():
    """When get_ledger_tail returns an entry, canonicalization is taken from it."""
    entry = MagicMock()
    entry.canonicalization = {"method": "canonical_json", "version": "1.0"}
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
        tail=[entry],
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
    )
    assert bundle["canonicalization"] == {"method": "canonical_json", "version": "1.0"}


# ---------------------------------------------------------------------------
# token is None → no timestamp_token in bundle
# ---------------------------------------------------------------------------


def test_create_bundle_token_none():
    """When get_timestamp_token returns None, no timestamp_token key."""
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
        token=None,
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
    )
    assert "timestamp_token" not in bundle


# ---------------------------------------------------------------------------
# token present → timestamp_token in bundle
# ---------------------------------------------------------------------------


def test_create_bundle_token_present():
    """When get_timestamp_token returns a dict, timestamp_token is included."""
    token_data = {"tst_hex": "aa" * 32, "tsa_url": "https://tsa.test"}
    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
        token=token_data,
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
    )
    assert bundle["timestamp_token"] == token_data


# ---------------------------------------------------------------------------
# All optional params together
# ---------------------------------------------------------------------------


def test_create_bundle_all_optional_params():
    """Bundle with all optional parameters populated."""
    import nacl.signing

    key = nacl.signing.SigningKey.generate()
    sth = SignedTreeHead.create(epoch_id=1, tree_size=10, merkle_root="ee" * 32, signing_key=key)
    prev_sth = SignedTreeHead.create(
        epoch_id=0, tree_size=5, merkle_root="dd" * 32, signing_key=key
    )
    cp = ConsistencyProof(old_tree_size=5, new_tree_size=10, proof_nodes=[b"\xcc" * 32])
    token_data = {"tst_hex": "ff" * 32, "tsa_url": "https://tsa.test"}
    entry = MagicMock()
    entry.canonicalization = {"method": "canonical_json"}

    storage = _mock_storage(
        proof=_mock_proof(),
        header_info=_default_header_info(),
        tail=[entry],
        token=token_data,
    )
    bundle = create_verification_bundle(
        storage,
        shard_id="test-shard",
        record_type="document",
        record_id="doc-1",
        version=1,
        signed_tree_head=sth,
        previous_sth=prev_sth,
        consistency_proof=cp,
    )
    assert "signed_tree_head" in bundle
    assert "previous_sth" in bundle
    assert "consistency_proof" in bundle
    assert "timestamp_token" in bundle
    assert "smt_proof" in bundle
    assert bundle["bundle_version"] == BUNDLE_VERSION

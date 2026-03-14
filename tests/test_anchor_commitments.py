from datetime import datetime, timezone

import pytest

from protocol.anchors import AnchorCommitment


def test_anchor_commitment_round_trip_and_verify():
    anchor = AnchorCommitment.create(
        anchor_chain="bitcoin",
        merkle_root="00" * 32,
        anchor_reference="txid123",
        anchored_at="2025-01-01T00:00:00Z",
        metadata={"block_height": 100},
    )

    assert anchor.verify(expected_root="00" * 32)

    restored = AnchorCommitment.from_dict(anchor.to_dict())
    assert restored.verify(expected_root="00" * 32)


def test_anchor_commitment_detects_root_mismatch():
    anchor = AnchorCommitment.create(
        anchor_chain="ethereum",
        merkle_root="11" * 32,
        anchor_reference="0xdeadbeef",
    )
    assert not anchor.verify(expected_root="22" * 32)


def test_anchor_commitment_invalid_hash_rejected():
    with pytest.raises(ValueError, match="Hash must be 32 bytes"):
        AnchorCommitment.create(
            anchor_chain="bitcoin",
            merkle_root="1234",
            anchor_reference="txid",
        )

    bad = AnchorCommitment(
        anchor_chain="bitcoin",
        merkle_root="00" * 32,
        anchor_reference="txid",
        anchored_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        commitment_hash="deadbeef",
        metadata={},
    )
    assert not bad.verify(expected_root="00" * 32)


def test_anchor_commitment_normalizes_anchored_at_equivalents():
    ts_with_offset = "2025-01-01T00:00:00+00:00"
    ts_with_z = "2025-01-01T00:00:00Z"

    anchor_offset = AnchorCommitment.create(
        anchor_chain="bitcoin",
        merkle_root="00" * 32,
        anchor_reference="txid123",
        anchored_at=ts_with_offset,
        metadata={"block_height": 100},
    )
    anchor_z = AnchorCommitment.create(
        anchor_chain="bitcoin",
        merkle_root="00" * 32,
        anchor_reference="txid123",
        anchored_at=ts_with_z,
        metadata={"block_height": 100},
    )

    assert anchor_offset.anchored_at == "2025-01-01T00:00:00Z"
    assert anchor_z.anchored_at == "2025-01-01T00:00:00Z"
    assert anchor_offset.commitment_hash == anchor_z.commitment_hash
    assert anchor_offset.verify(expected_root="00" * 32)
    assert anchor_z.verify(expected_root="00" * 32)


def test_anchor_commitment_metadata_ordering_is_canonical():
    metadata_alpha_first = {"alpha": 1, "beta": 2, "gamma": "x"}
    metadata_gamma_first = {"gamma": "x", "beta": 2, "alpha": 1}

    anchor_alpha = AnchorCommitment.create(
        anchor_chain="ethereum",
        merkle_root="11" * 32,
        anchor_reference="0xabc",
        anchored_at="2025-02-02T12:00:00Z",
        metadata=metadata_alpha_first,
    )
    anchor_gamma = AnchorCommitment.create(
        anchor_chain="ethereum",
        merkle_root="11" * 32,
        anchor_reference="0xabc",
        anchored_at="2025-02-02T12:00:00Z",
        metadata=metadata_gamma_first,
    )

    assert anchor_alpha.commitment_hash == anchor_gamma.commitment_hash
    assert anchor_alpha.verify(expected_root="11" * 32)
    assert anchor_gamma.verify(expected_root="11" * 32)


def test_anchor_commitment_handles_large_metadata():
    metadata = {f"key_{i}": i for i in range(200)}

    anchor = AnchorCommitment.create(
        anchor_chain="bitcoin",
        merkle_root="22" * 32,
        anchor_reference="txid-large",
        anchored_at="2026-03-14T00:00:00Z",
        metadata=metadata,
    )

    assert anchor.verify(expected_root="22" * 32)

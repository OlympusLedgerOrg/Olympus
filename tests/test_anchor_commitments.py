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

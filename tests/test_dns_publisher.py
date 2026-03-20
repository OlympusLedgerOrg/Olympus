"""
Tests for DNS checkpoint publishing helpers.
"""

from protocol.checkpoints import SignedCheckpoint
from protocol.dns_publisher import DNSCheckpointRecord, DNSPublisher, DryRunBackend


def _checkpoint(sequence: int) -> SignedCheckpoint:
    return SignedCheckpoint(
        sequence=sequence,
        timestamp="2026-03-20T00:00:00Z",
        ledger_head_hash="head",
        previous_checkpoint_hash="",
        ledger_height=100,
        shard_roots={},
        consistency_proof=[],
        checkpoint_hash=f"hash-{sequence}",
        federation_quorum_certificate={},
    )


def test_dns_checkpoint_record_format() -> None:
    record = DNSCheckpointRecord(sequence=1, checkpoint_hash="abc123")

    assert record.to_txt_record() == "oly-v1 seq=1 hash=abc123"

    parsed = DNSCheckpointRecord.from_txt_record("oly-v1 seq=1 hash=abc123")
    assert parsed.sequence == 1
    assert parsed.checkpoint_hash == "abc123"
    assert parsed.timestamp is None


def test_dns_checkpoint_record_legacy_format() -> None:
    parsed = DNSCheckpointRecord.from_txt_record("oly-chk seq=2;hash=def456;height=9;root=xyz")

    assert parsed.sequence == 2
    assert parsed.checkpoint_hash == "def456"


def test_dns_checkpoint_record_normalizes_separators() -> None:
    parsed = DNSCheckpointRecord.from_txt_record("oly-chk  seq=4;;hash=abc123;;;")

    assert parsed.sequence == 4
    assert parsed.checkpoint_hash == "abc123"


def test_dns_checkpoint_record_from_checkpoint_keeps_timestamp() -> None:
    checkpoint = _checkpoint(5)
    record = DNSCheckpointRecord.from_checkpoint(checkpoint)

    assert record.timestamp == checkpoint.timestamp
    assert record.to_txt_record() == "oly-v1 seq=5 hash=hash-5"


def test_dns_publisher_publish_and_delete() -> None:
    backend = DryRunBackend()
    publisher = DNSPublisher("checkpoints.example.com", backend)
    checkpoint = _checkpoint(7)

    fqdn = publisher.publish_checkpoint(checkpoint)

    assert fqdn == "seq-7.checkpoints.example.com"
    assert backend.records[fqdn] == "oly-v1 seq=7 hash=hash-7"
    assert backend.records["latest.checkpoints.example.com"] == backend.records[fqdn]

    publisher.delete_checkpoint(7)

    assert "seq-7.checkpoints.example.com" not in backend.records


def test_dns_publisher_custom_label() -> None:
    backend = DryRunBackend()
    publisher = DNSPublisher("checkpoints.example.com", backend)
    checkpoint = _checkpoint(3)

    fqdn = publisher.publish_checkpoint(checkpoint, label="custom")

    assert fqdn == "custom.checkpoints.example.com"
    assert backend.records[fqdn] == "oly-v1 seq=3 hash=hash-3"
    assert "latest.checkpoints.example.com" not in backend.records

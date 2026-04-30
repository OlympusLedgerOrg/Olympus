"""Extended tests for protocol.dns_publisher covering uncovered code paths."""

import pytest

from protocol.checkpoints import SignedCheckpoint
from protocol.dns_publisher import (
    DNSBackend,
    DNSCheckpointRecord,
    DNSPublisher,
    DNSPublisherError,
    DryRunBackend,
    create_dns_publisher,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DOMAIN = "checkpoints.olympus.test"


def _make_publisher() -> tuple[DNSPublisher, DryRunBackend]:
    """Create a DNSPublisher with a DryRunBackend."""
    backend = DryRunBackend()
    publisher = DNSPublisher(DOMAIN, backend)
    return publisher, backend


def _make_checkpoint(sequence: int = 1) -> SignedCheckpoint:
    """Create a minimal SignedCheckpoint for testing."""
    return SignedCheckpoint(
        sequence=sequence,
        timestamp="2026-01-01T00:00:00Z",
        ledger_head_hash="aa" * 32,
        previous_checkpoint_hash="",
        ledger_height=10,
        shard_roots={},
        consistency_proof=[],
        checkpoint_hash="bb" * 32,
        federation_quorum_certificate={},
    )


# ---------------------------------------------------------------------------
# DNSPublisher.query_checkpoint – empty, valid, and invalid record
# ---------------------------------------------------------------------------


def test_query_checkpoint_empty():
    """query_checkpoint returns None when no record exists."""
    publisher, _backend = _make_publisher()
    assert publisher.query_checkpoint(42) is None


def test_query_checkpoint_valid():
    """query_checkpoint returns a DNSCheckpointRecord for a published record."""
    publisher, backend = _make_publisher()
    cp = _make_checkpoint(sequence=5)
    publisher.publish_checkpoint(cp)

    result = publisher.query_checkpoint(5)
    assert result is not None
    assert isinstance(result, DNSCheckpointRecord)
    assert result.sequence == 5
    assert result.checkpoint_hash == cp.checkpoint_hash


def test_query_checkpoint_invalid_record():
    """query_checkpoint returns None when the stored TXT record is invalid."""
    publisher, backend = _make_publisher()
    # Manually inject an invalid record
    fqdn = publisher.checkpoint_subdomain(99)
    backend.records[fqdn] = "garbage-data-not-a-checkpoint"

    result = publisher.query_checkpoint(99)
    assert result is None


# ---------------------------------------------------------------------------
# DNSPublisher.query_latest_checkpoint – empty, valid, and invalid record
# ---------------------------------------------------------------------------


def test_query_latest_checkpoint_empty():
    """query_latest_checkpoint returns None when no record exists."""
    publisher, _backend = _make_publisher()
    assert publisher.query_latest_checkpoint() is None


def test_query_latest_checkpoint_valid():
    """query_latest_checkpoint returns the latest published record."""
    publisher, backend = _make_publisher()
    cp = _make_checkpoint(sequence=7)
    publisher.publish_checkpoint(cp)

    result = publisher.query_latest_checkpoint()
    assert result is not None
    assert isinstance(result, DNSCheckpointRecord)
    assert result.sequence == 7


def test_query_latest_checkpoint_invalid_record():
    """query_latest_checkpoint returns None when the latest TXT record is invalid."""
    publisher, backend = _make_publisher()
    fqdn = publisher.latest_subdomain()
    backend.records[fqdn] = "not-valid-format"

    result = publisher.query_latest_checkpoint()
    assert result is None


# ---------------------------------------------------------------------------
# DNSBackend.create_or_update_txt_record wrapper
# ---------------------------------------------------------------------------


def test_create_or_update_txt_record():
    """create_or_update_txt_record delegates to publish()."""
    backend = DryRunBackend()
    backend.create_or_update_txt_record("test.example.com", "oly-v1 seq=1 hash=abc")
    assert backend.records.get("test.example.com") == "oly-v1 seq=1 hash=abc"


# ---------------------------------------------------------------------------
# DNSBackend.query_txt_record raises NotImplementedError
# ---------------------------------------------------------------------------


def test_dns_backend_query_txt_record_not_implemented():
    """DNSBackend subclasses that omit query_txt_record cannot be instantiated."""

    class MinimalBackend(DNSBackend):
        def publish(self, name: str, txt: str) -> None:
            pass

        def delete(self, name: str) -> None:
            pass

    with pytest.raises(TypeError):
        MinimalBackend()


# ---------------------------------------------------------------------------
# create_dns_publisher – various providers
# ---------------------------------------------------------------------------


def test_create_dns_publisher_route53():
    """route53 provider raises ValueError when hosted_zone_id is not configured."""
    with pytest.raises(ValueError, match="hosted_zone_id"):
        create_dns_publisher(DOMAIN, provider="route53")


def test_create_dns_publisher_cloudflare():
    """cloudflare provider raises NotImplementedError."""
    with pytest.raises(NotImplementedError, match="Cloudflare"):
        create_dns_publisher(DOMAIN, provider="cloudflare")


def test_create_dns_publisher_unknown():
    """Unknown provider raises ValueError."""
    with pytest.raises(ValueError, match="Unknown DNS provider"):
        create_dns_publisher(DOMAIN, provider="unknown_provider")


def test_create_dns_publisher_none_returns_dry_run():
    """None provider returns a publisher with DryRunBackend."""
    publisher = create_dns_publisher(DOMAIN)
    assert isinstance(publisher, DNSPublisher)
    assert isinstance(publisher.backend, DryRunBackend)


# ---------------------------------------------------------------------------
# DNSPublisherError
# ---------------------------------------------------------------------------


def test_dns_publisher_error_is_exception():
    """DNSPublisherError is a valid exception class."""
    error = DNSPublisherError("test error")
    assert isinstance(error, Exception)
    assert str(error) == "test error"


def test_dns_publisher_error_can_be_raised():
    """DNSPublisherError can be raised and caught."""
    with pytest.raises(DNSPublisherError, match="something went wrong"):
        raise DNSPublisherError("something went wrong")


# ---------------------------------------------------------------------------
# DryRunBackend.delete
# ---------------------------------------------------------------------------


def test_dry_run_backend_delete_existing():
    """DryRunBackend.delete removes a previously published record."""
    backend = DryRunBackend()
    backend.publish("rec.example.com", "value")
    assert backend.records.get("rec.example.com") == "value"

    backend.delete("rec.example.com")
    assert backend.records.get("rec.example.com") is None


def test_dry_run_backend_delete_nonexistent():
    """DryRunBackend.delete on a non-existent record does not raise."""
    backend = DryRunBackend()
    backend.delete("missing.example.com")  # should not raise

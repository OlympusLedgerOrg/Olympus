"""
DNS TXT record publishing for Olympus checkpoints.

This module provides utilities for publishing checkpoint hashes to DNS TXT
records, allowing out-of-band verification of checkpoint integrity through
DNS lookups. This is a Phase 1+ feature for witness protocol.

DNS publication provides:
1. Public verifiability - anyone can query DNS to verify checkpoints
2. Split-view detection - witnesses can compare DNS vs direct API results
3. Tamper evidence - DNS records provide an independent anchor

Based on RFC 6962 (Certificate Transparency) DNS publication patterns.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .checkpoints import SignedCheckpoint


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DNSCheckpointRecord:
    """
    DNS TXT record content for checkpoint publication.

    Format follows CT log DNS publication: checkpoint hash + sequence number
    encoded in a machine-readable format.
    """

    sequence: int
    checkpoint_hash: str
    timestamp: str | None = None

    def to_txt_record(self) -> str:
        """
        Convert to DNS TXT record value.

        Returns:
            DNS TXT record string in format: "oly-v1 seq=N hash=..."

        Example:
            >>> record = DNSCheckpointRecord(sequence=42, checkpoint_hash="abc123")
            >>> record.to_txt_record()
            'oly-v1 seq=42 hash=abc123'
        """
        return f"oly-v1 seq={self.sequence} hash={self.checkpoint_hash}"

    @classmethod
    def from_txt_record(cls, txt_value: str) -> DNSCheckpointRecord:
        """
        Parse a DNS TXT record value into a DNSCheckpointRecord.

        Args:
            txt_value: DNS TXT record string

        Returns:
            Parsed DNSCheckpointRecord

        Accepts both the current "oly-v1" space-delimited format and the
        legacy "oly-chk" semicolon-delimited format by normalizing ";" to
        whitespace before parsing. Records that omit timestamps set timestamp
        to None.

        Raises:
            ValueError: If the TXT record format is invalid
        """
        normalized = txt_value.replace(";", " ")
        parts = [part for part in normalized.split() if part]
        if len(parts) < 3 or parts[0] not in {"oly-v1", "oly-chk"}:
            raise ValueError(f"Invalid DNS checkpoint record format: {txt_value}")

        parsed: dict[str, str] = {}
        for part in parts[1:]:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            parsed[key] = value

        if "seq" not in parsed or "hash" not in parsed:
            raise ValueError(f"Missing required fields in DNS checkpoint record: {txt_value}")

        try:
            sequence = int(parsed["seq"])
        except ValueError as e:
            raise ValueError(f"Invalid sequence number in DNS checkpoint record: {parsed['seq']}") from e

        return cls(
            sequence=sequence,
            checkpoint_hash=parsed["hash"],
            timestamp=parsed.get("ts"),
        )

    @classmethod
    def from_checkpoint(cls, checkpoint: SignedCheckpoint) -> DNSCheckpointRecord:
        """
        Create a DNS record from a SignedCheckpoint.

        Args:
            checkpoint: Signed checkpoint to publish

        Returns:
            DNSCheckpointRecord ready for DNS publication
        """
        return cls(
            sequence=checkpoint.sequence,
            checkpoint_hash=checkpoint.checkpoint_hash,
            timestamp=checkpoint.timestamp,
        )


def checkpoint_record_set(
    checkpoint: SignedCheckpoint, domain: str, label: str | None = None
) -> tuple[str, str]:
    """
    Build the DNS record set for a signed checkpoint.

    Args:
        checkpoint: Signed checkpoint to publish
        domain: Base domain for checkpoint records
        label: Optional label override (defaults to "seq-N")

    Returns:
        Tuple of (fqdn, txt_value) for DNS publication
    """
    record = DNSCheckpointRecord.from_checkpoint(checkpoint)
    txt_value = record.to_txt_record()
    record_label = label or f"seq-{checkpoint.sequence}"
    fqdn = f"{record_label}.{domain}"
    return fqdn, txt_value


class DNSPublisher:
    """
    Publisher for checkpoint DNS TXT records.

    This class provides an interface for publishing checkpoints to DNS, with
    pluggable backend support for different DNS providers (AWS Route53,
    Cloudflare, etc.).
    """

    def __init__(self, domain: str, backend: DNSBackend | None = None) -> None:
        """
        Initialize DNS publisher.

        Args:
            domain: Base domain for checkpoint records (e.g., "checkpoints.olympus.example.com")
            backend: DNS backend implementation (if None, uses DryRunBackend)
        """
        self.domain = domain
        self.backend = backend or DryRunBackend()

    def checkpoint_subdomain(self, sequence: int) -> str:
        """
        Generate subdomain for a checkpoint sequence.

        Args:
            sequence: Checkpoint sequence number

        Returns:
            Full subdomain for the checkpoint record

        Example:
            >>> publisher = DNSPublisher("checkpoints.olympus.example.com")
            >>> publisher.checkpoint_subdomain(42)
            'seq-42.checkpoints.olympus.example.com'
        """
        return f"seq-{sequence}.{self.domain}"

    def latest_subdomain(self) -> str:
        """
        Get the subdomain for the latest checkpoint pointer.

        Returns:
            Subdomain for the latest checkpoint record

        Example:
            >>> publisher = DNSPublisher("checkpoints.olympus.example.com")
            >>> publisher.latest_subdomain()
            'latest.checkpoints.olympus.example.com'
        """
        return f"latest.{self.domain}"

    def publish_checkpoint(self, checkpoint: SignedCheckpoint, label: str | None = None) -> str:
        """
        Publish a checkpoint to DNS.

        Args:
            checkpoint: Signed checkpoint to publish
            label: Optional label override (defaults to "seq-N")

        Raises:
            DNSPublisherError: If DNS update fails

        Returns:
            Fully qualified domain name for the published record
        """
        fqdn, txt_value = checkpoint_record_set(checkpoint, self.domain, label)
        self.backend.publish(fqdn, txt_value)
        logger.info(f"Published checkpoint {checkpoint.sequence} to DNS: {fqdn}")

        if label is None:
            latest_fqdn, latest_txt_value = checkpoint_record_set(
                checkpoint, self.domain, label="latest"
            )
            self.backend.publish(latest_fqdn, latest_txt_value)
            logger.info(f"Updated latest checkpoint pointer to sequence {checkpoint.sequence}")

        return fqdn

    def delete_checkpoint(self, sequence: int) -> None:
        """
        Delete a checkpoint DNS record for a sequence.

        Args:
            sequence: Checkpoint sequence number to delete

        Raises:
            DNSPublisherError: If DNS deletion fails
        """
        subdomain = self.checkpoint_subdomain(sequence)
        self.backend.delete(subdomain)
        logger.info(f"Deleted checkpoint {sequence} DNS record: {subdomain}")

    def query_checkpoint(self, sequence: int) -> DNSCheckpointRecord | None:
        """
        Query DNS for a specific checkpoint sequence.

        Args:
            sequence: Checkpoint sequence number to query

        Returns:
            DNSCheckpointRecord if found, None otherwise

        Raises:
            ValueError: If the DNS record format is invalid
        """
        subdomain = self.checkpoint_subdomain(sequence)
        txt_values = self.backend.query_txt_record(subdomain)

        if not txt_values:
            return None

        # Return first valid record (should only be one)
        for txt_value in txt_values:
            try:
                return DNSCheckpointRecord.from_txt_record(txt_value)
            except ValueError:
                logger.warning(f"Invalid DNS checkpoint record at {subdomain}: {txt_value}")
                continue

        return None

    def query_latest_checkpoint(self) -> DNSCheckpointRecord | None:
        """
        Query DNS for the latest checkpoint.

        Returns:
            DNSCheckpointRecord for the latest checkpoint, or None if not found

        Raises:
            ValueError: If the DNS record format is invalid
        """
        subdomain = self.latest_subdomain()
        txt_values = self.backend.query_txt_record(subdomain)

        if not txt_values:
            return None

        for txt_value in txt_values:
            try:
                return DNSCheckpointRecord.from_txt_record(txt_value)
            except ValueError:
                logger.warning(f"Invalid DNS checkpoint record at {subdomain}: {txt_value}")
                continue

        return None


class DNSPublisherError(Exception):
    """Base exception for DNS publisher errors."""

    pass


class DNSBackend(ABC):
    """
    Abstract base class for DNS backend implementations.

    Concrete implementations should provide methods for creating/updating
    TXT records and querying existing records.
    """

    @abstractmethod
    def publish(self, name: str, txt: str) -> None:
        """
        Publish a DNS TXT record.

        Args:
            name: Fully qualified domain name
            txt: TXT record value

        Raises:
            DNSPublisherError: If the operation fails
        """
        raise NotImplementedError

    @abstractmethod
    def delete(self, name: str) -> None:
        """
        Delete a DNS TXT record.

        Args:
            name: Fully qualified domain name

        Raises:
            DNSPublisherError: If the operation fails
        """
        raise NotImplementedError

    def create_or_update_txt_record(self, fqdn: str, value: str) -> None:
        """
        Create or update a DNS TXT record.

        This is a compatibility wrapper around publish() for legacy callers.

        Args:
            fqdn: Fully qualified domain name
            value: TXT record value

        Raises:
            DNSPublisherError: If the operation fails
        """
        self.publish(fqdn, value)

    def query_txt_record(self, fqdn: str) -> list[str]:
        """
        Query DNS TXT records for a domain.

        Args:
            fqdn: Fully qualified domain name

        Returns:
            List of TXT record values

        Raises:
            DNSPublisherError: If the query fails
        """
        raise NotImplementedError


class DryRunBackend(DNSBackend):
    """
    DNS backend that logs operations without making actual DNS changes.

    Useful for testing and development.
    """

    def __init__(self) -> None:
        """Initialize dry-run backend with in-memory storage."""
        self.records: dict[str, str] = {}

    def publish(self, name: str, txt: str) -> None:
        """
        Log TXT record creation without making DNS changes.

        Args:
            name: Fully qualified domain name
            txt: TXT record value
        """
        logger.info(f"[DRY RUN] Would publish TXT record: {name} -> {txt}")
        self.records[name] = txt

    def delete(self, name: str) -> None:
        """
        Log TXT record deletion without making DNS changes.

        Args:
            name: Fully qualified domain name
        """
        logger.info(f"[DRY RUN] Would delete TXT record: {name}")
        self.records.pop(name, None)

    def query_txt_record(self, fqdn: str) -> list[str]:
        """
        Query in-memory TXT records.

        Args:
            fqdn: Fully qualified domain name

        Returns:
            List of TXT record values from in-memory storage
        """
        record = self.records.get(fqdn)
        records = [record] if record is not None else []
        logger.info(f"[DRY RUN] Query TXT record: {fqdn} -> {records}")
        return records


def create_dns_publisher(
    domain: str,
    provider: str | None = None,
    credentials: dict[str, Any] | None = None,
) -> DNSPublisher:
    """
    Factory function to create a DNS publisher with the appropriate backend.

    Args:
        domain: Base domain for checkpoint records
        provider: DNS provider name ('route53', 'cloudflare', etc.)
            If None, uses DryRunBackend
        credentials: Provider-specific credentials

    Returns:
        Configured DNSPublisher instance

    Example:
        >>> # Development/testing
        >>> publisher = create_dns_publisher("checkpoints.olympus.example.com")
        >>>
        >>> # Production with AWS Route53 (requires boto3)
        >>> publisher = create_dns_publisher(
        ...     "checkpoints.olympus.example.com",
        ...     provider="route53",
        ...     credentials={"aws_access_key_id": "...", "aws_secret_access_key": "..."}
        ... )
    """
    if provider is None:
        backend: DNSBackend = DryRunBackend()
    elif provider == "route53":
        # Placeholder - would require boto3 integration
        raise NotImplementedError("AWS Route53 backend not yet implemented")
    elif provider == "cloudflare":
        # Placeholder - would require cloudflare API integration
        raise NotImplementedError("Cloudflare backend not yet implemented")
    else:
        raise ValueError(f"Unknown DNS provider: {provider}")

    return DNSPublisher(domain, backend)

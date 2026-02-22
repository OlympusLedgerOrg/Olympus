# storage/blob.py
"""
Olympus Object Storage Interface.

This module provides the blob storage layer for immutable artifacts using
Content-Addressable Storage (CAS). Object keys are strictly the BLAKE3
hash of the raw bytes, guaranteeing deduplication and integrity.

Supports AWS S3 and S3-compatible stores (e.g., MinIO) via environment
variables.
"""

import os

import boto3
from botocore.exceptions import ClientError


class BlobStore:
    """
    Olympus Object Storage Interface.

    Enforces Content-Addressable Storage (CAS) for immutable artifacts.
    All objects are keyed by their BLAKE3 hash, ensuring:
    - Deduplication: identical content shares the same key
    - Integrity: key serves as checksum for verification
    - Immutability: overwriting an existing key is idempotent
    """

    def __init__(self) -> None:
        """
        Initialize BlobStore with S3/MinIO configuration from environment.

        Environment variables:
            S3_BUCKET_NAME: Bucket name (default: olympus-artifacts)
            S3_ENDPOINT_URL: Custom endpoint for MinIO (e.g., http://localhost:9000)
            AWS_ACCESS_KEY_ID: AWS/MinIO access key
            AWS_SECRET_ACCESS_KEY: AWS/MinIO secret key
            AWS_REGION: AWS region (default: us-east-1)
        """
        self.bucket = os.getenv("S3_BUCKET_NAME", "olympus-artifacts")
        self.s3 = boto3.client(
            "s3",
            endpoint_url=os.getenv("S3_ENDPOINT_URL"),  # e.g., http://localhost:9000
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("AWS_REGION", "us-east-1"),
        )

    def put_artifact(self, raw_hash: str, raw_data: bytes, mime_type: str) -> str:
        """
        Upload raw bytes to S3 using the BLAKE3 hash as the object key.

        Silently succeeds if the artifact already exists (idempotent ingest).
        This enforces the CAS rule: the object key is strictly the raw_hash.

        Args:
            raw_hash: The 64-char hex string of the BLAKE3 digest.
            raw_data: The exact bytes of the file.
            mime_type: The MIME type (e.g., application/pdf).

        Returns:
            The S3 object key (which is the raw_hash).

        Raises:
            ValueError: If raw_hash is not a valid 64-character hex string.
            ClientError: If S3 operation fails (except 404 on existence check).
        """
        # Validate raw_hash format
        if len(raw_hash) != 64:
            raise ValueError(f"raw_hash must be 64 characters, got {len(raw_hash)}")
        try:
            bytes.fromhex(raw_hash)
        except ValueError as e:
            raise ValueError(f"raw_hash must be a valid hex string: {e}") from e

        try:
            # Check if it already exists to save bandwidth and enforce immutability
            self.s3.head_object(Bucket=self.bucket, Key=raw_hash)
            return raw_hash  # Already safely stored
        except ClientError as e:
            if e.response["Error"]["Code"] != "404":
                raise

        # Does not exist, upload it
        self.s3.put_object(
            Bucket=self.bucket,
            Key=raw_hash,
            Body=raw_data,
            ContentType=mime_type,
        )
        return raw_hash

    def get_artifact(self, raw_hash: str) -> bytes | None:
        """
        Retrieve raw bytes for cryptographic verification.

        Args:
            raw_hash: The 64-char hex string of the BLAKE3 digest.

        Returns:
            The raw bytes if the artifact exists, None otherwise.

        Raises:
            ValueError: If raw_hash is not a valid 64-character hex string.
            ClientError: If S3 operation fails (except NoSuchKey).
        """
        # Validate raw_hash format
        if len(raw_hash) != 64:
            raise ValueError(f"raw_hash must be 64 characters, got {len(raw_hash)}")
        try:
            bytes.fromhex(raw_hash)
        except ValueError as e:
            raise ValueError(f"raw_hash must be a valid hex string: {e}") from e

        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=raw_hash)
            return response["Body"].read()
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                return None
            raise

    def exists(self, raw_hash: str) -> bool:
        """
        Check if an artifact exists in the store.

        Args:
            raw_hash: The 64-char hex string of the BLAKE3 digest.

        Returns:
            True if the artifact exists, False otherwise.

        Raises:
            ValueError: If raw_hash is not a valid 64-character hex string.
            ClientError: If S3 operation fails (except 404).
        """
        # Validate raw_hash format
        if len(raw_hash) != 64:
            raise ValueError(f"raw_hash must be 64 characters, got {len(raw_hash)}")
        try:
            bytes.fromhex(raw_hash)
        except ValueError as e:
            raise ValueError(f"raw_hash must be a valid hex string: {e}") from e

        try:
            self.s3.head_object(Bucket=self.bucket, Key=raw_hash)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            raise

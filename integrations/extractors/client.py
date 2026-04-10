"""
HTTP client for the ingest-parser-service.

This client provides a clean interface for the Olympus API to communicate
with the deterministic document parsing microservice.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import httpx

from integrations.extractors.schemas import (
    ExtractionResult,
    ParserHealthStatus,
)


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


class IngestParserError(Exception):
    """Base exception for parser client errors."""

    pass


class ParserConnectionError(IngestParserError):
    """Raised when connection to parser service fails."""

    pass


class ParserValidationError(IngestParserError):
    """Raised when parser returns a validation error."""

    pass


class HashMismatchError(IngestParserError):
    """Raised when file hash doesn't match expected value."""

    pass


class IngestParserClient:
    """HTTP client for the ingest-parser-service.

    This client handles communication with the document parsing microservice,
    including file upload, hash verification, and result parsing.

    Example:
        ```python
        async with IngestParserClient() as client:
            # Check service health
            health = await client.health()
            print(f"Parser: {health.parser_name} v{health.parser_version}")

            # Parse a document
            with open("document.pdf", "rb") as f:
                result = await client.parse(f.read(), "document.pdf")

            print(f"File hash: {result.provenance.raw_file_blake3}")
            print(f"Pages: {result.document.total_pages}")
        ```
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 300.0,
        max_retries: int = 3,
    ) -> None:
        """Initialize the parser client.

        Args:
            base_url: Base URL of the parser service. Defaults to
                      INGEST_PARSER_URL env var or http://localhost:8090.
            timeout: Request timeout in seconds (default 300s for large files).
            max_retries: Maximum number of retry attempts on transient failures.
        """
        self._base_url = base_url or os.getenv(
            "INGEST_PARSER_URL", "http://localhost:8090"
        )
        self._timeout = timeout
        self._max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> IngestParserClient:
        """Enter async context manager."""
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(self._timeout),
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit async context manager."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get the HTTP client, raising if not initialized."""
        if self._client is None:
            raise RuntimeError(
                "Client not initialized. Use 'async with IngestParserClient()' context."
            )
        return self._client

    async def health(self) -> ParserHealthStatus:
        """Check parser service health.

        Returns:
            ParserHealthStatus with service information.

        Raises:
            ParserConnectionError: If connection fails.
        """
        try:
            response = await self.client.get("/health")
            response.raise_for_status()
            return ParserHealthStatus.model_validate(response.json())
        except httpx.ConnectError as e:
            raise ParserConnectionError(
                f"Failed to connect to parser service at {self._base_url}: {e}"
            ) from e
        except httpx.HTTPStatusError as e:
            raise ParserConnectionError(
                f"Parser service unhealthy: {e.response.status_code}"
            ) from e

    async def parse(
        self,
        content: bytes,
        filename: str,
        *,
        expected_blake3: str | None = None,
        content_type: str | None = None,
    ) -> ExtractionResult:
        """Parse a document and return structured extraction with provenance.

        Args:
            content: Raw file bytes.
            filename: Original filename (used for content type detection).
            expected_blake3: Optional expected BLAKE3 hash for verification.
                            Format: 'blake3_' + 64 hex chars.
            content_type: Optional MIME type override.

        Returns:
            ExtractionResult with provenance and extracted document.

        Raises:
            ParserConnectionError: If connection fails.
            ParserValidationError: If parser returns validation error.
            HashMismatchError: If hash verification fails.
        """
        # Determine content type from filename if not provided
        if content_type is None:
            content_type = self._guess_content_type(filename)

        # Build multipart form data
        files = {"file": (filename, content, content_type)}
        data = {}
        if expected_blake3:
            data["expected_blake3"] = expected_blake3

        try:
            response = await self.client.post("/parse", files=files, data=data)

            if response.status_code == 422:
                # Hash mismatch
                detail = response.json().get("detail", "")
                raise HashMismatchError(detail)

            if response.status_code == 415:
                # Unsupported content type
                detail = response.json().get("detail", "")
                raise ParserValidationError(f"Unsupported content type: {detail}")

            if response.status_code == 413:
                # File too large
                detail = response.json().get("detail", "")
                raise ParserValidationError(f"File too large: {detail}")

            response.raise_for_status()
            return ExtractionResult.model_validate(response.json())

        except httpx.ConnectError as e:
            raise ParserConnectionError(
                f"Failed to connect to parser service: {e}"
            ) from e
        except httpx.HTTPStatusError as e:
            raise ParserConnectionError(
                f"Parser request failed: {e.response.status_code}"
            ) from e

    async def parse_file(
        self,
        file_path: Path,
        *,
        expected_blake3: str | None = None,
    ) -> ExtractionResult:
        """Parse a document from a file path.

        Args:
            file_path: Path to the document file.
            expected_blake3: Optional expected hash for verification.

        Returns:
            ExtractionResult with provenance and extracted document.
        """
        with open(file_path, "rb") as f:
            content = f.read()
        return await self.parse(
            content,
            file_path.name,
            expected_blake3=expected_blake3,
        )

    def _guess_content_type(self, filename: str) -> str:
        """Guess content type from filename extension."""
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        return {
            "pdf": "application/pdf",
            "txt": "text/plain",
            "html": "text/html",
            "htm": "text/html",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "doc": "application/msword",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xls": "application/vnd.ms-excel",
            "csv": "text/csv",
            "json": "application/json",
            "xml": "application/xml",
            "png": "image/png",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "tiff": "image/tiff",
            "tif": "image/tiff",
        }.get(ext, "application/octet-stream")


# Thread-safe singleton client management for the API
_client: IngestParserClient | None = None
_client_lock = threading.Lock()


def get_parser_client() -> IngestParserClient:
    """Get the global parser client instance (thread-safe).

    Note: This returns a client that must be used within an async context.
    For FastAPI integration, prefer using the lifespan context manager instead.

    Warning: This singleton pattern is provided for convenience but the
    recommended approach is to use parser_client_lifespan() in your
    FastAPI application's lifespan handler.
    """
    global _client
    if _client is None:
        with _client_lock:
            # Double-check locking pattern
            if _client is None:
                _client = IngestParserClient()
    return _client


@asynccontextmanager
async def parser_client_lifespan() -> AsyncGenerator[IngestParserClient, None]:
    """Lifespan context manager for FastAPI integration.

    Example:
        ```python
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            async with parser_client_lifespan() as client:
                app.state.parser_client = client
                yield

        app = FastAPI(lifespan=lifespan)
        ```
    """
    client = IngestParserClient()
    async with client:
        yield client

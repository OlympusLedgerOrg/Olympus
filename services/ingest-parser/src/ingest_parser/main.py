"""
Ingest Parser Service - FastAPI Application.

A standalone, deterministic microservice for extracting structured data
from documents (PDFs, images, office files) for the Olympus ledger system.

IMPORTANT: This module enforces CPU-only execution BEFORE importing any
ML libraries to ensure floating-point determinism.
"""
# ruff: noqa: E402
# The E402 violations are intentional - enforce_cpu_only() MUST run before
# any other imports to disable GPU before ML libraries are loaded.

from __future__ import annotations

# CRITICAL: Enforce CPU-only execution BEFORE any other imports
# This prevents GPU floating-point non-determinism
from ingest_parser.config import configure_deterministic_execution, enforce_cpu_only

enforce_cpu_only()

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Annotated

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ingest_parser import __version__
from ingest_parser.config import Config
from ingest_parser.crypto import compute_blake3, verify_hash
from ingest_parser.parser import BaseParser, create_parser
from ingest_parser.schemas import (
    ErrorResponse,
    HealthResponse,
    ParseResponse,
    Provenance,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


# Module-level state
_config: Config | None = None
_parser: BaseParser | None = None
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager.

    Initializes the parser and configuration on startup,
    and cleans up resources on shutdown.
    """
    global _config, _parser

    # Load configuration
    _config = Config.from_env()

    # Configure deterministic execution
    configure_deterministic_execution(_config.parser.num_threads)

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, _config.server.log_level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    logger.info(
        f"Starting ingest-parser-service v{__version__} "
        f"(parser={_config.parser.parser_name}, cpu_only={_config.parser.cpu_only})"
    )

    # Initialize parser
    try:
        _parser = create_parser(_config.parser)
        logger.info(
            f"Parser initialized: name={_parser.name}, "
            f"version={_parser.version}, model_hash={_parser.model_hash}"
        )
    except Exception as e:
        logger.error(f"Failed to initialize parser: {e}")
        raise

    yield

    # Cleanup
    logger.info("Shutting down ingest-parser-service")
    _parser = None
    _config = None


# Create FastAPI application
app = FastAPI(
    title="Olympus Ingest Parser Service",
    description=(
        "A standalone, deterministic microservice for extracting structured data "
        "from documents for the Olympus ledger system."
    ),
    version=__version__,
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Content type mapping
SUPPORTED_CONTENT_TYPES = {
    "application/pdf": "application/pdf",
    "pdf": "application/pdf",
    "text/plain": "text/plain",
    "txt": "text/plain",
    "text/html": "text/html",
    "html": "text/html",
}


def get_content_type(filename: str | None, content_type: str | None) -> str:
    """Determine the content type from filename or provided content type."""
    if content_type and content_type in SUPPORTED_CONTENT_TYPES:
        return SUPPORTED_CONTENT_TYPES[content_type]

    if filename:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext in SUPPORTED_CONTENT_TYPES:
            return SUPPORTED_CONTENT_TYPES[ext]

    return content_type or "application/octet-stream"


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint.

    Returns service status, parser information, and configuration.
    """
    if _parser is None or _config is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    return HealthResponse(
        status="healthy",
        parser_name=_parser.name,
        parser_version=_parser.version,
        model_hash=_parser.model_hash,
        cpu_only=_config.parser.cpu_only,
        environment_digest=_config.server.environment_digest,
    )


@app.post(
    "/parse",
    response_model=ParseResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid request"},
        413: {"model": ErrorResponse, "description": "File too large"},
        415: {"model": ErrorResponse, "description": "Unsupported media type"},
        422: {"model": ErrorResponse, "description": "Hash mismatch"},
        500: {"model": ErrorResponse, "description": "Internal error"},
    },
)
async def parse_document(
    file: Annotated[UploadFile, File(description="Document file to parse")],
    expected_blake3: str | None = None,
) -> ParseResponse:
    """Parse a document and return structured extraction with provenance.

    This endpoint accepts a raw file binary and returns a strictly formatted
    JSON with full provenance metadata for cryptographic verification.

    **Determinism Guarantees:**
    - CPU-only execution (no GPU floating-point non-determinism)
    - All bounding box coordinates rounded to 4 decimal places
    - Model weights verified against expected hash

    Args:
        file: The document file to parse.
        expected_blake3: Optional expected BLAKE3 hash for verification.
                         Format: 'blake3_' followed by 64 hex characters.

    Returns:
        ParseResponse with provenance metadata and extracted document.

    Raises:
        HTTPException 400: Invalid request parameters.
        HTTPException 413: File exceeds maximum size.
        HTTPException 415: Unsupported content type.
        HTTPException 422: Hash verification failed.
        HTTPException 500: Internal parsing error.
    """
    if _parser is None or _config is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not initialized",
        )

    # Read file content with size limit
    try:
        content = await file.read()
    except Exception as e:
        logger.error(f"Failed to read file: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read file: {e}",
        ) from e

    # Check file size
    if len(content) > _config.server.max_file_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size {len(content)} exceeds maximum {_config.server.max_file_size_bytes}",
        )

    # Compute BLAKE3 hash of raw file
    raw_file_blake3 = compute_blake3(content)

    # Verify hash if expected
    if expected_blake3:
        if not verify_hash(expected_blake3, raw_file_blake3):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Hash mismatch. Expected {expected_blake3}, got {raw_file_blake3}",
            )

    # Determine content type
    content_type = get_content_type(file.filename, file.content_type)
    if content_type not in SUPPORTED_CONTENT_TYPES.values():
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported content type: {content_type}",
        )

    # Parse document
    try:
        document = _parser.parse(content, content_type)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.exception(f"Failed to parse document: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse document: {e}",
        ) from e

    # Build provenance
    provenance = Provenance(
        raw_file_blake3=raw_file_blake3,
        parser_name=_parser.name,
        parser_version=_parser.version,
        canonical_parser_version=_config.parser.canonical_parser_version,
        model_hash=_parser.model_hash,
        environment_digest=_config.server.environment_digest,
    )

    return ParseResponse(
        provenance=provenance,
        document=document,
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global exception handler for unhandled errors."""
    logger.exception(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="internal_error",
            message="An unexpected error occurred",
            details={"type": type(exc).__name__},
        ).model_dump(),
    )


def main() -> None:
    """Run the service using uvicorn."""
    import uvicorn

    config = Config.from_env()

    uvicorn.run(
        "ingest_parser.main:app",
        host=config.server.host,
        port=config.server.port,
        log_level=config.server.log_level.lower(),
        reload=False,  # Never reload in production (non-deterministic)
    )


if __name__ == "__main__":
    main()

"""
Olympus Unified API — single FastAPI entry point.

Combines FOIA/public-records management with protocol-layer audit,
ingest, and cryptographic verification endpoints.

Start with:
    uvicorn api.main:app --reload

Environment variables (see api/config.py for full list):
    DATABASE_URL  — async SQLAlchemy URL (default: sqlite+aiosqlite:///./olympus_foia.db)
    CORS_ORIGINS  — comma-separated allowed origins (default: empty; must be configured)
"""

from __future__ import annotations

import api._patches as _patches  # apply CVE patches before any third-party imports


_patches.apply_all()

import json as _json_mod
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from api.auth import _assert_xff_default_deny
from api.config import get_settings
from api.db import engine
from api.ingest import _close_sequencer_client, router as ingest_router
from api.models import Base  # noqa: F401 — ensures all models are registered
from api.routers import agencies, appeals, documents, keys, ledger, requests as requests_router
from api.routers.admin import router as admin_router
from api.routers.datasets import router as datasets_router
from api.routers.federation import router as federation_router
from api.routers.shards import router as shards_router
from api.routers.witness import router as witness_router
from api.rust_smoke import assert_rust_hot_path
from api.sth import router as sth_router


class _JSONLogFormatter(logging.Formatter):
    """Structured JSON log formatter for production environments.

    Emits one JSON object per line with standard fields: ``timestamp``,
    ``level``, ``logger``, ``message``, plus any ``extra`` fields attached
    to the LogRecord.
    """

    # Pre-compute standard LogRecord attributes once to avoid repeated allocation.
    _STANDARD_ATTRS: frozenset[str] = frozenset(
        logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
    )

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        # Forward structured 'extra' fields (skip standard LogRecord attrs)
        for key, val in record.__dict__.items():
            if key not in self._STANDARD_ATTRS and key not in log_entry:
                log_entry[key] = val
        return _json_mod.dumps(log_entry, default=str)


_log_format = os.environ.get("OLYMPUS_LOG_FORMAT", "text").strip().lower()
if _log_format == "json":
    _handler = logging.StreamHandler()
    _handler.setFormatter(_JSONLogFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[_handler])
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
logger = logging.getLogger(__name__)


def _env_flag_enabled(name: str) -> bool:
    """Return True when an environment flag is enabled with common truthy values."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _assert_no_dev_zk_stub_artifacts(repo_root: Path | None = None) -> None:
    """Block production startup when known development ceremony stubs are present."""
    if os.environ.get("OLYMPUS_ENV", "production") == "development":
        return
    if os.environ.get("OLYMPUS_ALLOW_DEV_ZK_ARTIFACTS", "").lower() == "true":
        logger.warning("OLYMPUS_ALLOW_DEV_ZK_ARTIFACTS=true: allowing dev ZK artifacts")
        return

    root = repo_root or Path(__file__).resolve().parent.parent
    stub_paths = (
        root / "ceremony" / "transcript" / "dev_powers_of_tau.ptau",
        root / "ceremony" / "transcript" / "dev_redaction_validity_final.zkey",
    )
    for stub_path in stub_paths:
        if not stub_path.exists():
            continue
        header = stub_path.read_bytes()[:256].lower()
        if b"dev placeholder" in header or b"development" in header:
            raise RuntimeError(
                "Refusing startup in non-development environment with dev ceremony stub "
                f"artifact present: {stub_path}. Set OLYMPUS_ALLOW_DEV_ZK_ARTIFACTS=true "
                "only for non-production test scenarios."
            )


def _assert_no_dev_signing_key_in_non_development() -> None:
    """Block non-development startup when OLYMPUS_DEV_SIGNING_KEY is enabled."""
    if os.environ.get("OLYMPUS_ENV", "production") == "development":
        return
    if _env_flag_enabled("OLYMPUS_DEV_SIGNING_KEY"):
        raise RuntimeError(
            "Refusing startup in non-development environment with "
            "OLYMPUS_DEV_SIGNING_KEY=true. Configure a persistent "
            "OLYMPUS_INGEST_SIGNING_KEY for production use."
        )


def _assert_dev_auth_flag_restricted_to_development() -> None:
    """Disallow dev auth bypass flag outside development."""
    env = os.environ.get("OLYMPUS_ENV", "production")
    if env == "development":
        return
    if os.environ.get("OLYMPUS_ALLOW_DEV_AUTH") == "1":
        raise RuntimeError(
            "OLYMPUS_ALLOW_DEV_AUTH=1 is not permitted when OLYMPUS_ENV != 'development'."
        )


def _assert_no_multiworker_with_memory_rate_limit() -> None:
    """Block production startup when the memory rate limiter is used with multiple workers.

    The in-process ``MemoryRateLimitBackend`` is per-worker: with *N* workers
    each process tracks its own buckets, so the effective rate limit would be
    *N×* the configured value — making rate limiting essentially non-functional.
    Fail hard at startup rather than silently under-enforcing limits.

    Raises:
        RuntimeError: In production when ``WEB_CONCURRENCY > 1`` and
            ``RATE_LIMIT_BACKEND`` is ``'memory'`` (i.e. Redis is not configured).
    """
    env = os.environ.get("OLYMPUS_ENV", "production")
    if env != "production":
        return
    workers_str = os.environ.get("WEB_CONCURRENCY", "")
    try:
        workers = int(workers_str) if workers_str else 1
    except ValueError:
        workers = 1
    settings = get_settings()
    if workers > 1 and settings.rate_limit_backend.lower() == "memory":
        raise RuntimeError(
            f"RATE_LIMIT_BACKEND=memory is not effective with WEB_CONCURRENCY={workers}. "
            "Each worker maintains independent rate limit buckets, so the effective limit "
            f"would be {workers}× the configured value. "
            "Options: (1) Set WEB_CONCURRENCY=1, (2) configure RATE_LIMIT_BACKEND=redis "
            "once implemented, or (3) set OLYMPUS_ENV=development to skip this check locally. "
            "Note: this check only runs when OLYMPUS_ENV=production — "
            "staging environments with OLYMPUS_ENV != 'production' will not trigger it."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup and dispose the engine on shutdown."""
    settings = get_settings()
    logger.info("Starting Olympus API v%s", settings.app_version)
    _assert_no_dev_zk_stub_artifacts()
    _assert_no_dev_signing_key_in_non_development()
    _assert_dev_auth_flag_restricted_to_development()
    _assert_no_multiworker_with_memory_rate_limit()
    _assert_xff_default_deny()
    assert_rust_hot_path()

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database schema ready.")
    except Exception as exc:
        logger.warning(
            "Database unavailable at startup; schema init deferred — app starting in degraded mode: %s",
            exc,
        )

    yield

    await _close_sequencer_client()
    await engine.dispose()
    logger.info("Engine disposed; shutdown complete.")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard security response headers to every API response."""

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        # HSTS — always set to protect against SSL stripping attacks.
        # Safe even over HTTP (browsers ignore the header on non-HTTPS).
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        # CSP — restrictive default; operators should customize for their frontend origin
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response


class RequestBodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose declared Content-Length exceeds the configured maximum.

    This guard fires before any route handler reads the body, providing an
    early-exit 413 for oversized requests without buffering the full payload.
    Requests without a Content-Length header are not blocked here; chunked or
    streaming uploads are bounded by the per-endpoint read helpers in ingest.py.
    """

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )
            settings = get_settings()
            if length > settings.max_upload_bytes:
                max_mb = settings.max_upload_bytes // (1024 * 1024)
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body too large (limit {max_mb} MB)."},
                )
        return await call_next(request)


def _json_safe_validation_detail(value: Any) -> Any:
    """Recursively sanitize validation payloads so JSON rendering cannot fail."""
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, list):
        return [_json_safe_validation_detail(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe_validation_detail(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_safe_validation_detail(item) for key, item in value.items()}
    return value


def create_app() -> FastAPI:
    """Build and configure the unified FastAPI application.

    Returns:
        Configured FastAPI instance.
    """
    settings = get_settings()

    app = FastAPI(
        title=settings.app_title,
        version=settings.app_version,
        description=(
            "Unified Olympus API — append-only cryptographic ledger for "
            "NC Public Records (G.S. § 132) and Federal FOIA (5 U.S.C. § 552) "
            "requests, plus protocol-layer audit and verification."
        ),
        lifespan=lifespan,
    )

    # CORS — restrict origins; no wildcard default (H4)
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]

    _env = os.environ.get("OLYMPUS_ENV", "production")
    if not origins:
        if _env == "development":
            origins = ["http://localhost:3000", "http://localhost:8000"]
            logger.warning("CORS_ORIGINS not set — using localhost defaults for development.")
        else:
            origins = []  # No CORS in production unless explicitly configured
            logger.warning("CORS_ORIGINS not set — cross-origin requests will be rejected.")

    # Only enable CORS credentials when origins are explicitly configured and non-empty.
    # Explicit wildcard origins with credentials are rejected as insecure.
    explicit_cors_origins = bool(os.environ.get("CORS_ORIGINS", "").strip())
    wildcard_origin_present = any("*" in origin for origin in origins)
    if explicit_cors_origins and wildcard_origin_present:
        raise RuntimeError(
            "CORS_ORIGINS contains wildcard values, which is not allowed with "
            "credentialed requests. Configure explicit origins instead."
        )
    allow_credentials = bool(origins) and explicit_cors_origins

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestBodySizeLimitMiddleware)

    @app.exception_handler(RequestValidationError)
    async def request_validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Return validation errors without re-serializing invalid Unicode input."""
        return JSONResponse(
            status_code=422,
            content={"detail": _json_safe_validation_detail(exc.errors())},
        )

    # FOIA routers
    app.include_router(documents.router)
    app.include_router(ledger.router)
    app.include_router(requests_router.router)
    app.include_router(agencies.router)
    app.include_router(appeals.router)
    app.include_router(keys.router)

    # Protocol-layer routers
    app.include_router(shards_router)
    app.include_router(ingest_router)
    app.include_router(sth_router)
    app.include_router(witness_router)
    app.include_router(datasets_router)
    app.include_router(federation_router)

    # Admin RBAC router
    app.include_router(admin_router)

    # ── API Versioning ──
    # Mount all routers under /v1 prefix for versioned access.
    # Unversioned routes above are kept for backward compatibility.
    v1 = APIRouter(prefix="/v1")
    v1.include_router(documents.router)
    v1.include_router(ledger.router)
    v1.include_router(requests_router.router)
    v1.include_router(agencies.router)
    v1.include_router(appeals.router)
    v1.include_router(keys.router)
    v1.include_router(shards_router)
    v1.include_router(ingest_router)
    v1.include_router(sth_router)
    v1.include_router(witness_router)
    v1.include_router(datasets_router)
    v1.include_router(federation_router)
    v1.include_router(admin_router)
    app.include_router(v1)

    @app.get("/", tags=["health"])
    async def root() -> dict[str, Any]:
        """API root with version info."""
        return {
            "service": settings.app_title,
            "version": settings.app_version,
            "status": "ok",
        }

    @app.get("/health", tags=["health"])
    async def health() -> Any:
        """Health check with database and sequencer status.

        Returns:
            JSON response with service health indicators:
            - status: "ok" | "degraded" (overall health)
            - version: API version string
            - database: "connected" | "degraded" | "error" | "not_initialized"
            - db_check: True if database SELECT 1 succeeds
            - sequencer: "ok" | "degraded" | "unavailable" | "disabled"
              (only present when storage_layer is importable)

        Status codes:
            200: Service is healthy (status == "ok")
            503: Service is degraded (database or sequencer unavailable)
        """
        from starlette.responses import JSONResponse

        result: dict[str, Any] = {
            "status": "ok",
            "version": settings.app_version,
        }

        # Check database status
        try:
            from api.services.storage_layer import get_storage_status

            db_status, db_check = get_storage_status()
            result["database"] = db_status
            result["db_check"] = db_check
            if db_status in ("error", "degraded"):
                result["status"] = "degraded"
        except ImportError:
            # storage_layer not available (e.g. test environment) — skip db check
            pass

        # Check sequencer status when Go sequencer routing is enabled
        try:
            from api.services.storage_layer import get_sequencer_status

            seq_status, seq_healthy = await get_sequencer_status()
            result["sequencer"] = seq_status
            if not seq_healthy and seq_status != "disabled":
                result["status"] = "degraded"
        except ImportError:
            # storage_layer not available — skip sequencer check
            pass

        # Return 503 when degraded
        if result["status"] == "degraded":
            return JSONResponse(content=result, status_code=503)
        return result

    return app


app = create_app()

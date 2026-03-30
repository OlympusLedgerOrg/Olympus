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

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from api.config import get_settings
from api.db import engine
from api.ingest import router as ingest_router
from api.models import Base  # noqa: F401 — ensures all models are registered
from api.routers import agencies, appeals, documents, keys, ledger, requests as requests_router
from api.routers.datasets import router as datasets_router
from api.routers.shards import router as shards_router
from api.routers.witness import router as witness_router
from api.sth import router as sth_router


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup and dispose the engine on shutdown."""
    settings = get_settings()
    logger.info("Starting Olympus API v%s", settings.app_version)

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
            "style-src 'self' 'unsafe-inline'; "  # TODO: Replace unsafe-inline with nonces after frontend refactor
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response


def _json_safe_validation_detail(value: Any) -> Any:
    """Recursively sanitize validation payloads so JSON rendering cannot fail."""
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if isinstance(value, list):
        return [_json_safe_validation_detail(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe_validation_detail(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _json_safe_validation_detail(item)
            for key, item in value.items()
            # FastAPI attaches a documentation URL for each validation error.
            # It is not needed in API responses here and may contain unsanitized
            # path data, so we omit it while making the payload JSON-safe.
            if key != "url"
        }
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
    # allow_credentials=True with broad/unset origins is a credential-stealing vector.
    allow_credentials = bool(origins) and bool(os.environ.get("CORS_ORIGINS", "").strip())

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.add_middleware(SecurityHeadersMiddleware)

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

    @app.get("/", tags=["health"])
    async def root() -> dict[str, Any]:
        """API root with version info."""
        return {
            "service": settings.app_title,
            "version": settings.app_version,
            "status": "ok",
        }

    @app.get("/health", tags=["health"])
    async def health() -> dict[str, Any]:
        """Health check with optional database status."""
        result: dict[str, Any] = {
            "status": "ok",
            "version": settings.app_version,
        }
        try:
            from api.services.storage_layer import get_storage_status

            db_status, db_check = get_storage_status()
            result["database"] = db_status
            result["db_check"] = db_check
            if db_status == "error":
                result["status"] = "degraded"
        except ImportError:
            pass
        return result

    return app


app = create_app()

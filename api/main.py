"""
Olympus FOIA Ledger — FastAPI application entry point.

Start with:
    uvicorn api.main:app --reload

Environment variables (see api/config.py for full list):
    DATABASE_URL — async SQLAlchemy URL (default: sqlite+aiosqlite:///./olympus_foia.db)
    CORS_ORIGINS  — comma-separated allowed origins (default: *)
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.config import get_settings
from api.db import engine
from api.models import Base  # noqa: F401 — ensures all models are registered
from api.routers import agencies, appeals, documents, keys, ledger, requests as requests_router


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create database tables on startup and dispose the engine on shutdown."""
    settings = get_settings()
    logger.info("Starting Olympus FOIA Ledger v%s", settings.app_version)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    logger.info("Database schema ready.")
    yield

    await engine.dispose()
    logger.info("Engine disposed; shutdown complete.")


def create_app() -> FastAPI:
    """Build and configure the FastAPI application.

    Returns:
        Configured FastAPI instance.
    """
    settings = get_settings()

    app = FastAPI(
        title=settings.app_title,
        version=settings.app_version,
        description=(
            "Append-only cryptographic ledger for NC Public Records (G.S. § 132) "
            "and Federal FOIA (5 U.S.C. § 552) requests."
        ),
        lifespan=lifespan,
    )

    # CORS
    origins = [o.strip() for o in settings.cors_origins.split(",")]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    app.include_router(documents.router)
    app.include_router(ledger.router)
    app.include_router(requests_router.router)
    app.include_router(agencies.router)
    app.include_router(appeals.router)
    app.include_router(keys.router)

    @app.get("/", tags=["health"])
    async def root():
        """Health check / version endpoint."""
        return {
            "service": settings.app_title,
            "version": settings.app_version,
            "status": "ok",
        }

    @app.get("/health", tags=["health"])
    async def health():
        """Liveness probe."""
        return {"status": "ok"}

    return app


app = create_app()

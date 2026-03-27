"""
Settings management for the Olympus FOIA backend.

Configuration is loaded from environment variables with sensible defaults
for development. Use a .env file or environment to override in production.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_logger = logging.getLogger(__name__)


def _load_db_password() -> str:
    """Load database password from Docker secret file or environment variable.

    Prefers ``DATABASE_PASSWORD_FILE`` (Docker secrets).  Falls back to
    ``DATABASE_PASSWORD`` env var and logs a warning about credential
    visibility.

    Returns:
        The database password as a string (may be empty).
    """
    password_file = os.getenv("DATABASE_PASSWORD_FILE")
    if password_file:
        path = Path(password_file)
        if path.exists():
            return path.read_text().strip()
        _logger.warning(
            "DATABASE_PASSWORD_FILE=%s does not exist — falling back to env var", password_file
        )
    password = os.getenv("DATABASE_PASSWORD", "")
    if password:
        _logger.warning(
            "DATABASE_PASSWORD_FILE not configured — credentials visible in environment. "
            "Use Docker secrets in production."
        )
    return password


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Args:
        database_url: Async SQLAlchemy connection string.
        app_title: Human-readable API title.
        app_version: Semver version string.
        cors_origins: Comma-separated list of allowed CORS origins.
        default_shard_id: Hex shard identifier used for all commits in Phase 0.
        statutory_window_nc_days: Business-day window for NC Public Records (G.S. § 132).
        statutory_window_foia_days: Business-day window for Federal FOIA (5 U.S.C. § 552).

    See also:
        OLYMPUS_FOIA_API_KEYS — JSON array of hashed API key records (see api/auth.py).
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "sqlite+aiosqlite:///./olympus_foia.db"
    app_title: str = "Olympus FOIA Ledger"
    app_version: str = "0.1.0"
    cors_origins: str = ""  # No default — must be explicitly configured
    default_shard_id: str = "0x4F3A"

    # Trusted proxy IPs/CIDRs for X-Forwarded-For parsing
    trusted_proxy_ips: list[str] = []  # e.g. ["10.0.0.1", "172.16.0.0/12"]

    # Rate limit backend configuration
    rate_limit_backend: str = "memory"  # Options: "memory", "redis"
    rate_limit_redis_url: str = ""

    # Maximum upload file size in bytes (default 256 MB)
    max_upload_bytes: int = 256 * 1024 * 1024

    # TLS configuration — set to true when terminating TLS at the app layer
    tls_enabled: bool = False

    # Maximum allowed timestamp skew for shard headers (milliseconds)
    shard_timestamp_skew_ms: int = 30_000

    # Statutory deadlines (business days)
    # NC Public Records: no explicit limit; flag overdue after these thresholds
    statutory_window_nc_ack_days: int = 14  # G.S. § 132 — acknowledgment
    statutory_window_nc_fulfill_days: int = 30  # G.S. § 132 — fulfillment
    # Federal FOIA: 20 business days per 5 U.S.C. § 552(a)(6)(A)
    statutory_window_foia_days: int = 20

    @field_validator("cors_origins")
    @classmethod
    def parse_cors_origins(cls, v: str) -> str:
        """Accept the raw string; splitting is done by the app startup handler."""
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached singleton Settings instance."""
    return Settings()

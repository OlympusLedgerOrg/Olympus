"""
Settings management for the Olympus FOIA backend.

Configuration is loaded from environment variables with sensible defaults
for development. Use a .env file or environment to override in production.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "sqlite+aiosqlite:///./olympus_foia.db"
    app_title: str = "Olympus FOIA Ledger"
    app_version: str = "0.1.0"
    cors_origins: str = "*"
    default_shard_id: str = "0x4F3A"

    # Statutory deadlines (business days)
    # NC Public Records: no explicit limit; flag overdue after these thresholds
    statutory_window_nc_ack_days: int = 14   # G.S. § 132 — acknowledgment
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

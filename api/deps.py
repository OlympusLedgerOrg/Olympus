"""
Dependency injection helpers for the Olympus FOIA backend.

Provides reusable FastAPI dependencies for database sessions and
API key authentication.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db


# Re-export for convenience
DBSession = Annotated[AsyncSession, Depends(get_db)]

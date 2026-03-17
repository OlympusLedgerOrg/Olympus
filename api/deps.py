"""
Dependency injection helpers for the Olympus FOIA backend.

Provides reusable FastAPI dependencies for database sessions and—when
authentication is added—the current authenticated user.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.db import get_db


# Re-export for convenience
DBSession = Annotated[AsyncSession, Depends(get_db)]


# Placeholder for future auth. Inject `CurrentUser` into route handlers when
# authentication is enabled. For now, all endpoints are open.
async def get_current_user():
    """Return the authenticated user (stub — no auth yet).

    Returns:
        None: Authentication is not yet implemented.
    """
    return None


CurrentUser = Annotated[None, Depends(get_current_user)]

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - API Dependencies
==============================

Common dependencies for API endpoints.
Re-exports the canonical RBAC helpers from ``app.core.dependencies``.
"""

from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, status

from app.core.dependencies import (
    CurrentUser,
    get_current_active_user,
    get_current_user,
    require_any_permission,
    require_min_role,
    require_permissions,
    require_role,
    require_site_permissions,
)
from app.db import get_session
from app.models import UserRole

# Alias for compatibility
get_db = get_session


def require_roles(allowed_roles: list[UserRole]) -> Callable[..., Any]:
    """
    Dependency factory to require specific roles.

    Args:
        allowed_roles: List of allowed user roles

    Returns:
        A dependency function that checks the user's role
    """

    async def role_checker(
        user: CurrentUser = Depends(get_current_active_user),
    ) -> CurrentUser:
        # Scope ceiling: a scoped API key must not satisfy a role-only gate via its
        # owner's raw role (see core.dependencies.require_min_role). No-op for normal
        # users / unscoped keys.
        if getattr(user, "is_scoped", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Scoped API keys cannot satisfy role-based gates",
            )
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return role_checker


# Re-export for convenience
__all__ = [
    "CurrentUser",
    "get_current_user",
    "get_current_active_user",
    "require_any_permission",
    "require_min_role",
    "require_permissions",
    "require_role",
    "require_roles",
    "require_site_permissions",
    "get_db",
    "get_session",
]

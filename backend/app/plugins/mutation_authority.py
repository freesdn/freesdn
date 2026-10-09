# SPDX-License-Identifier: AGPL-3.0-only
"""Request-bound plugin authority at the lifecycle mutation boundary."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from copy import deepcopy
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import DEFAULT_ROLE_PERMISSIONS, CurrentUser, _permission_granted_by
from app.models.api_keys import APIKey, verify_api_key
from app.models.core import User


def capture_plugin_mutation_authority(
    request: Request,
    current_user: CurrentUser,
    session: AsyncSession,
) -> Callable[[], Awaitable[None]]:
    """Capture before any queue/download and check fresh scalar state after it.

    Lifecycle callers invoke this inside the actual lifecycle mutex; catalog
    synchronization invokes it after fetch, catalog lock and final flush; settings
    saves invoke it after their upserts before committing. Re-running API-key
    authentication would commit last_used and release database locks.
    No actor/key row locks are added, avoiding reversed lock order. This is a
    boundary check, not serialization of revocations during every later await.
    """
    user_id = current_user.id
    original = (
        current_user.user.token_version,
        current_user.role,
        current_user.organization_id,
        current_user.user.hashed_password,
    )
    original_permissions = frozenset(current_user.permissions)
    original_scoped = current_user.is_scoped
    claims = deepcopy(current_user.token_claims)
    supplied_key = request.headers.get("x-api-key", "")

    async def check() -> None:
        actor = (
            await session.execute(
                select(
                    User.token_version,
                    User.role,
                    User.organization_id,
                    User.hashed_password,
                    User.is_active,
                    User.deleted_at,
                ).where(User.id == user_id)
            )
        ).one_or_none()
        if (
            actor is None
            or not actor.is_active
            or actor.deleted_at is not None
            or original
            != (actor.token_version, actor.role, actor.organization_id, actor.hashed_password)
        ):
            raise HTTPException(401, "Authentication changed; retry with current credentials")
        if claims.get("auth_method") == "api_key":
            try:
                key_id = UUID(claims["key_id"])
            except (ValueError, TypeError, KeyError):
                raise HTTPException(401, "Invalid API key authentication") from None
            key = (
                await session.execute(
                    select(
                        APIKey.is_active,
                        APIKey.expires_at,
                        APIKey.key_hash,
                        APIKey.scopes,
                    ).where(APIKey.id == key_id, APIKey.user_id == user_id)
                )
            ).one_or_none()
            if (
                key is None
                or not key.is_active
                or (key.expires_at is not None and key.expires_at <= datetime.now(UTC))
                or not verify_api_key(supplied_key, key.key_hash)
            ):
                raise HTTPException(401, "API key was revoked or expired")
            # Match the current dependency's role policy without a cached ORM actor.
            role_permissions = DEFAULT_ROLE_PERMISSIONS.get(
                actor.role or "viewer",
                DEFAULT_ROLE_PERMISSIONS["viewer"],
            )
            permissions = (
                {scope for scope in key.scopes if _permission_granted_by(scope, role_permissions)}
                if key.scopes
                else set(role_permissions)
            )
            if bool(key.scopes) != original_scoped or permissions != original_permissions:
                raise HTTPException(
                    401, "API key authority changed; retry with current credentials"
                )
        else:
            from app.core.session_revocation import is_session_revoked_for_access_jti
            from app.core.token_blacklist import is_token_blacklisted

            if claims.get("tv", 0) != actor.token_version:
                raise HTTPException(401, "Session was revoked")
            jti = claims.get("jti")
            if jti and (
                await is_token_blacklisted(str(jti))
                or await is_session_revoked_for_access_jti(session, str(jti))
            ):
                raise HTTPException(401, "Session was revoked")
            # Check time after the asynchronous revocation reads too.
            expiry = claims.get("exp")
            if (
                type(expiry) not in (int, float)
                or cast(float, expiry) <= datetime.now(UTC).timestamp()
            ):
                raise HTTPException(401, "Session expired")

    return check

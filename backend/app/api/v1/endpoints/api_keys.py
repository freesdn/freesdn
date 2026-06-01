# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - API Key Authentication
====================================

Provides API key-based authentication for service accounts,
integrations, and automated scripts.
"""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.api_keys import APIKey, generate_api_key

router = APIRouter()


# ===========================================
# Schemas
# ===========================================


class APIKeyCreate(BaseModel):
    """Create API key request.

    Caps on JSONB columns (``description``, ``scopes``) prevent a logged-in
    user from inflating ``core.api_keys`` rows with multi-MB blobs. Hard
    per-user active-key ceiling is enforced in the endpoint, not the
    schema (requires a DB count).
    """

    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(None, max_length=2000)
    scopes: list[str] = Field(default_factory=list, max_length=32)
    expires_in_days: int | None = Field(None, ge=1, le=365)


# Hard ceiling on number of active API keys per user. The list endpoint
# already caps display at 100; allowing unbounded creation lets a user
# (or a compromised session) flood ``core.api_keys`` with rows that
# can't even be enumerated through the UI. 50 is generous for service-
# account use cases and well under the list cap.
MAX_KEYS_PER_USER = 50


class APIKeyResponse(BaseModel):
    """API key response (without the actual key)."""

    id: UUID
    name: str
    key_prefix: str
    description: str | None
    scopes: list[str]
    last_used: datetime | None
    expires_at: datetime | None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class APIKeyCreated(APIKeyResponse):
    """Response when creating a new API key - includes the actual key."""

    key: str  # Only returned once at creation


# ===========================================
# Endpoints
# ===========================================


@router.get("/", response_model=list[APIKeyResponse])
async def list_api_keys(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """List all API keys for the current user."""
    result = await session.execute(
        select(APIKey)
        .where(APIKey.user_id == current_user.id)
        .order_by(APIKey.created_at.desc())
        .limit(100)
    )
    return result.scalars().all()


@router.post("/", response_model=APIKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    key_data: APIKeyCreate,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Create a new API key.

    **Important:** The full API key is only returned once. Store it securely.
    """
    from datetime import timedelta

    from app.models import User as _UserModel

    # Per-user active key ceiling. Two concurrent POSTs at limit-1
    # used to both see ``active_count == 49``, both pass, and end up
    # with 51 keys for the user. Serialize on the user row via
    # SELECT FOR UPDATE so the second request waits for the first
    # to commit, then re-counts. This is the same pattern used by
    # the password-reset path (auth.py) and the tier-quota check
    # (controllers.py).
    await session.execute(
        select(_UserModel.id).where(_UserModel.id == current_user.id).with_for_update()
    )
    active_count_row = await session.execute(
        select(func.count(APIKey.id)).where(
            APIKey.user_id == current_user.id,
            APIKey.is_active.is_(True),
        )
    )
    active_count = int(active_count_row.scalar_one() or 0)
    if active_count >= MAX_KEYS_PER_USER:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"API key limit reached ({MAX_KEYS_PER_USER}). Revoke an "
                "unused key before creating a new one."
            ),
        )

    requested_scopes = list(dict.fromkeys(key_data.scopes))
    # Cap individual scope string length — a single 10 KB scope is
    # almost certainly garbage and would inflate the JSONB column.
    if any(len(scope) > 100 for scope in requested_scopes):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Each scope must be 100 characters or fewer",
        )
    # SECURITY (scope-ceiling): an empty scope list means "inherit the owner's
    # FULL role" at auth time (is_scoped=False ⇒ the super_admin/'*' short-circuits
    # re-enable). A *scoped* caller minting an empty-scope child would therefore
    # self-escalate its deliberately-narrowed credential back to full power. Forbid
    # it: a scoped key may only create keys with an explicit (non-empty) scope set.
    if current_user.is_scoped and not requested_scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "A scoped API key cannot create an unscoped (empty-scope) key; "
                "specify an explicit subset of scopes"
            ),
        )
    if requested_scopes and not current_user.has_permission("*"):
        unauthorized_scopes = [
            scope
            for scope in requested_scopes
            if scope == "*" or not current_user.has_permission(scope)
        ]
        if unauthorized_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot grant API key scopes beyond your own permissions",
            )

    # Generate key
    full_key, prefix, key_hash = generate_api_key()

    # Calculate expiration
    expires_at = None
    if key_data.expires_in_days:
        expires_at = datetime.now(UTC) + timedelta(days=key_data.expires_in_days)

    # Create record
    api_key = APIKey(
        user_id=current_user.id,
        name=key_data.name,
        key_prefix=prefix,
        key_hash=key_hash,
        description=key_data.description,
        scopes=requested_scopes,
        expires_at=expires_at,
    )

    session.add(api_key)
    await session.commit()
    await session.refresh(api_key)

    return APIKeyCreated(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        key=full_key,  # Only time the key is returned!
        description=api_key.description,
        scopes=api_key.scopes,
        last_used=api_key.last_used,
        expires_at=api_key.expires_at,
        is_active=api_key.is_active,
        created_at=api_key.created_at,
    )


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Revoke (delete) an API key."""
    result = await session.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == current_user.id)
    )
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    await session.delete(api_key)
    await session.commit()

    return None

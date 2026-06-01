# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - API Key Model
============================

SQLAlchemy model and utility functions for API key management.
Kept separate from the endpoint file to avoid circular imports with
app.core.dependencies which needs to look up keys during authentication.
"""

import hashlib
import secrets
from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin


class APIKey(Base, UUIDMixin, AuditMixin):
    """
    API Key for programmatic access.

    The actual key is never stored — only its SHA-256 hash.
    Key format: fsd_<64 hex chars>
    Prefix (first 12 chars) is stored for efficient lookup.
    """

    __tablename__ = "api_keys"
    __table_args__ = (
        Index("ix_api_keys_prefix", "key_prefix"),
        Index("ix_api_keys_user_id", "user_id"),
        {"schema": "core"},
    )

    # Owner
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Key identification
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)  # fsd_ + first 8 chars
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256 hex

    # Permissions
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)

    # Metadata
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


# =============================================================================
# Utility Functions
# =============================================================================


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.

    Returns:
        Tuple of (full_key, prefix, sha256_hash)
        full_key  — e.g. "fsd_a1b2c3..." (68 chars total)
        prefix    — first 12 chars, e.g. "fsd_a1b2c3d4" (stored in DB for lookup)
        hash      — SHA-256 hex of full_key (stored in DB, never the key itself)
    """
    raw = secrets.token_hex(32)  # 64 hex chars
    key = f"fsd_{raw}"  # 68 chars total
    prefix = key[:12]  # "fsd_" + first 8 hex chars
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, prefix, key_hash


def verify_api_key(provided_key: str, stored_hash: str) -> bool:
    """Constant-time comparison of a provided key against its stored hash."""
    provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()
    return secrets.compare_digest(provided_hash, stored_hash)


def extract_prefix(key: str) -> str:
    """Extract the lookup prefix (first 12 chars) from an API key."""
    return key[:12] if len(key) >= 12 else ""


async def revoke_user_api_keys(session: AsyncSession, user_id: UUID) -> int:
    """Deactivate every API key belonging to ``user_id``.

    Called from code paths that bump ``User.token_version`` (logout-all,
    password change, password reset) so that long-lived API keys cannot be
    used to re-authenticate as the user after a session revocation event.

    Returns the number of rows affected. Does NOT commit — the caller is
    expected to commit as part of the surrounding transaction so the key
    revocation is atomic with the ``token_version`` bump.
    """
    result = await session.execute(
        update(APIKey)
        .where(APIKey.user_id == user_id)
        .where(APIKey.is_active == True)  # noqa: E712
        .values(is_active=False)
    )
    # rowcount is present on DML Result objects but mypy only sees the
    # generic Result[Any] protocol which lacks it.
    return int(getattr(result, "rowcount", 0) or 0)

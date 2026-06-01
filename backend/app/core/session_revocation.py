# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Shared per-device session-revocation check (AUTH-001).

Lives in ``app.core`` rather than the auth endpoint module so that BOTH the
auth router's local dependency AND the shared ``get_current_user_optional``
dependency can enforce per-device session revocation without creating an
``app.api -> app.core`` import cycle.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def is_session_revoked_for_access_jti(session: AsyncSession, access_jti: str) -> bool:
    """Return True if the ``UserSession`` bound to this access-jti is revoked.

    Missing rows are treated as NOT-revoked (legacy compat — only sessions
    created after the ``access_jti`` migration are tracked). A targeted
    ``DELETE /auth/sessions/{id}`` flips ``revoked_at``/``is_revoked`` WITHOUT
    bumping ``token_version`` or blacklisting the JTI, so this row check is the
    only thing that makes a single-device revocation take effect on the shared
    REST path before the access token naturally expires (default 60 min).
    """
    from app.models import UserSession

    res = await session.execute(
        select(UserSession.revoked_at, UserSession.is_revoked).where(
            UserSession.access_jti == access_jti
        )
    )
    row = res.first()
    if row is None:
        return False
    revoked_at, is_revoked = row
    return revoked_at is not None or bool(is_revoked)

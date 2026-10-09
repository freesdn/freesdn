# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Serialize first-install and HTTP administrator lifecycle decisions."""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# Preserve the existing first-install key ("SETU") for setup/restore compatibility.
_USER_LIFECYCLE_LOCK_KEY = 0x53455455


async def lock_user_lifecycle(session: AsyncSession) -> None:
    """Acquire before user row locks; retain until commit or rollback.

    This coordinates bootstrap and user PATCH/DELETE count-plus-write paths.
    It does not by itself serialize every service or full-vault account writer.
    Do not run authentication that commits API-key usage while holding this lock.
    """
    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _USER_LIFECYCLE_LOCK_KEY})


async def try_lock_user_lifecycle(session: AsyncSession) -> bool:
    """Join the lifecycle transaction without waiting behind another owner.

    Vault callers may already hold resource rows. A blocking advisory wait
    there could invert the normal advisory-before-row order. The caller must
    refuse and roll back its restore if another transaction owns this lock.
    The same transaction can reuse its existing bootstrap/lifecycle lock.
    """
    return bool(
        await session.scalar(
            text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": _USER_LIFECYCLE_LOCK_KEY}
        )
    )


async def try_share_user_lifecycle(session: AsyncSession) -> bool:
    """Allow concurrent established sign-ins while excluding lifecycle writers.

    A callback already owns its one-use SSO state row. Do not create an inverse
    wait on an exclusive lifecycle writer; the caller must roll back and ask
    for a new sign-in when this nonblocking acquisition fails. Account/provider
    resource locks and fresh validation are still required before issuance.
    """
    return bool(
        await session.scalar(
            text("SELECT pg_try_advisory_xact_lock_shared(:k)"), {"k": _USER_LIFECYCLE_LOCK_KEY}
        )
    )

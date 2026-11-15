# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Whether a user's organization still lets the user in.

Every authentication path checked the USER row (``deleted_at``, ``is_active``,
``token_version``) and never the organization the user belongs to. Deleting an
organization only stamped ``organizations.deleted_at`` and deactivating one only
cleared ``organizations.is_active``, so the organization's users kept signing in
and kept using their sessions, refresh tokens and API keys.

The rule applied at every place a principal is established (users, and the
edge agents an organization registered):

* a user with an organization is admitted only while that organization exists,
  is not soft-deleted and is active;
* a user with no organization is unaffected (there is nothing to retire);
* a ``super_admin`` is always admitted. It is the platform role that manages
  every organization, including reactivating the one it belongs to, and the
  only role that can. Its authority does not come from its home organization,
  so retiring that organization must not lock the appliance's administrators
  out.

Callers turn a refusal into the same generic 401 they use for a disabled
account, so a response never says whether the organization exists.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.core import Organization, User, UserRole, UserSession

logger = logging.getLogger(__name__)

# token_version is a 32-bit column; the auth paths refuse to advance a counter
# that is already at the top of the range, so the bulk bump does the same.
_TOKEN_VERSION_CEILING = 2**31 - 1


def is_super_admin(user: Any) -> bool:
    """True for the platform ``super_admin`` role (str or enum, User or row)."""
    return getattr(user, "role", None) == UserRole.SUPER_ADMIN


def organization_state_admits(user: Any, organization: Any) -> bool:
    """Decide from an organization row that is already loaded.

    ``organization`` is the user's organization as loaded by the caller, or
    ``None`` when it could not be loaded. A user who names an organization that
    cannot be loaded is refused: with the global soft-delete filter switched on,
    a deleted organization loads as ``None``, and that must fail closed.
    """
    if is_super_admin(user):
        return True
    if getattr(user, "organization_id", None) is None:
        return True
    if organization is None:
        return False
    return organization.deleted_at is None and organization.is_active is True


async def organization_admits(session: AsyncSession, principal: Any) -> bool:
    """Decide with a fresh read of the principal's organization.

    ``principal`` is anything carrying ``organization_id`` (and ``role`` for a
    user): a ``User``, a selected row, or a ``RemoteAgent``, whose key belongs
    to its organization in the same way a user's password does.
    """
    if is_super_admin(principal):
        return True
    org_id = getattr(principal, "organization_id", None)
    if org_id is None:
        return True
    # include_deleted: a deleted organization must load and be refused, not be
    # hidden by the optional global soft-delete filter (which would also refuse,
    # but by accident).
    organization = (
        await session.execute(
            select(Organization)
            .where(Organization.id == org_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()
    return organization_state_admits(principal, organization)


async def sign_out_organization_members(session: AsyncSession, org_id: UUID) -> int:
    """Revoke every session of the organization's users, effective at once.

    Bumps ``token_version`` (which every access and refresh token, the auth
    router, the REST chokepoint and the realtime socket's revalidation compare
    against) and marks the users' session rows revoked, the same pair of writes
    ``/auth/logout-all`` makes. Super admins are left signed in, matching the
    admission rule above. API keys are not deleted: they stop working while the
    organization is retired, and work again if it is reactivated.

    Returns the number of users signed out.
    """
    # Members of the organization being retired: a lookup by the target org,
    # not a tenant scope of the caller's data (tenant_filter scopes to the
    # caller). include_deleted keeps the optional global soft-delete filter from
    # hiding the members of an organization already stamped deleted.
    member_ids = list(
        (
            await session.execute(
                select(User.id)
                .join(User.organization)
                .where(
                    Organization.id == org_id,
                    User.role != UserRole.SUPER_ADMIN,
                    User.deleted_at.is_(None),
                )
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    if not member_ids:
        return 0
    # The default ("auto") session synchronisation carries the new counter onto
    # any of these users already loaded in this session, so a later flush
    # cannot write the old value back.
    await session.execute(
        update(User)
        .where(User.id.in_(member_ids), User.token_version < _TOKEN_VERSION_CEILING)
        .values(token_version=User.token_version + 1)
    )
    await session.execute(
        update(UserSession)
        .where(UserSession.user_id.in_(member_ids), UserSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC), is_revoked=True)
    )
    return len(member_ids)


async def close_retired_organization_sockets(org_id: UUID) -> None:
    """Close the members' live realtime sockets on every API process, at once.

    Call it after the retirement is committed, so a socket that reconnects is
    refused. Without it a member's open socket lasted until its next
    revalidation, up to five minutes, on whichever process held it.
    """
    try:
        from app.api.v1.endpoints.websocket import manager

        await manager.close_organization(str(org_id))
    except Exception:
        logger.warning("Could not close the realtime sockets of retired org %s", org_id)


async def organization_holds_last_super_admin(session: AsyncSession, org_id: UUID) -> bool:
    """True when every active super admin of the appliance belongs to ``org_id``.

    Deleting that organization would strand the only accounts that can manage
    the appliance inside an organization that no longer exists. Super admins
    with no organization, or in another organization, count as remaining.
    """
    active = select(func.count(User.id)).where(
        User.role == UserRole.SUPER_ADMIN,
        User.deleted_at.is_(None),
        User.is_active.is_(True),
    )
    everywhere = (await session.execute(active)).scalar() or 0
    outside = (
        await session.execute(
            active.where(or_(User.organization_id.is_(None), User.organization_id != org_id))
        )
    ).scalar() or 0
    # None remain outside, and at least one is inside.
    return outside == 0 and everywhere > 0

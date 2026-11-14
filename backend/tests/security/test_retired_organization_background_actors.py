# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Stored actors of a retired organization stop acting.

Some work runs later on behalf of the user who set it up: a Fabric Connection
re-checks its author's permissions on every run, an SLA report schedule re-checks
the approving user and every recipient before it renders or mails anything, and
a queued bulk operation re-loads the user who triggered it. Each re-check read
the user row (deleted, active, same organization id) and never asked whether
that organization had since been deleted or deactivated, so a retired
organization's automation kept running with its members' authority.

Real PostgreSQL through the ``db_session`` savepoint fixture.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.models.core import Organization, User

RETIREMENTS = pytest.mark.parametrize("how", ["deleted", "deactivated"])


async def _member(db: AsyncSession, *, role: str = "org_admin") -> tuple[Organization, User]:
    org = Organization(id=uuid4(), name="Retired actor probe", slug="actor-" + uuid4().hex[:12])
    db.add(org)
    await db.flush()
    tag = uuid4().hex[:12]
    user = User(
        id=uuid4(),
        email=f"actor-{tag}@example.com",
        username=f"actor-{tag}",
        hashed_password=get_password_hash("Retired-Actor-Passw0rd!"),
        role=role,
        is_active=True,
        is_verified=True,
        organization_id=org.id,
    )
    db.add(user)
    await db.flush()
    return org, user


async def _retire(db: AsyncSession, org: Organization, how: str) -> None:
    if how == "deleted":
        org.deleted_at = datetime.now(UTC)
    else:
        org.is_active = False
    await db.flush()


@RETIREMENTS
async def test_a_fabric_connection_author_loses_authority(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    from app.core.fabric.runtime import fabric_permission_checker

    @contextlib.asynccontextmanager
    async def _factory() -> AsyncIterator[AsyncSession]:
        yield db_session

    monkeypatch.setattr("app.db.session.async_session_factory", _factory)
    org, author = await _member(db_session)
    assert await fabric_permission_checker(author.id, "site:read", org.id) is True
    await _retire(db_session, org, how)

    assert await fabric_permission_checker(author.id, "site:read", org.id) is False


@RETIREMENTS
async def test_an_sla_schedule_approver_loses_authority(db_session: AsyncSession, how: str) -> None:
    from app.services.sla_schedule_authorization import (
        ScheduleAuthorizationError,
        authorize_schedule,
    )

    org, approver = await _member(db_session)
    schedule = SimpleNamespace(
        organization_id=org.id,
        sla_policy_ids=[],
        execution_scope={
            "version": 1,
            "actor_id": str(approver.id),
            "permissions": ["config:read", "config:write"],
            "site_ids": None,
        },
    )
    assert (await authorize_schedule(db_session, schedule)).id == approver.id  # type: ignore[arg-type]
    await _retire(db_session, org, how)

    with pytest.raises(ScheduleAuthorizationError):
        await authorize_schedule(db_session, schedule)  # type: ignore[arg-type]


@RETIREMENTS
async def test_an_sla_report_recipient_is_no_longer_mailed(
    db_session: AsyncSession, how: str
) -> None:
    from app.services.sla_report_delivery import ReportDeliveryError, recipient_principal

    org, recipient = await _member(db_session, role="viewer")
    assert (await recipient_principal(db_session, org.id, recipient.id)).id == recipient.id
    await _retire(db_session, org, how)

    with pytest.raises(ReportDeliveryError):
        await recipient_principal(db_session, org.id, recipient.id)


@RETIREMENTS
async def test_a_queued_bulk_operation_drops_its_trigger(
    db_session: AsyncSession, how: str
) -> None:
    from app.tasks.bulk_operations import _load_user_for_authz

    org, trigger = await _member(db_session)
    assert await _load_user_for_authz(db_session, trigger.id) is not None
    await _retire(db_session, org, how)

    assert await _load_user_for_authz(db_session, trigger.id) is None

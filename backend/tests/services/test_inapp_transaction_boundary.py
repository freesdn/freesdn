# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Notification staging cannot commit another owner's work or publish early."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.core import events
from app.models.notification import InAppNotification
from app.services import notification_helpers
from app.services.notification import NotificationError, NotificationService

CANARY = "synthetic-private-transaction-detail"


def database(user, org):
    db = MagicMock()
    rows = SimpleNamespace(
        scalar_one_or_none=lambda: user, one_or_none=lambda: (user, org) if user else None
    )
    db.execute = AsyncMock(return_value=rows)
    added = []
    db.add.side_effect = added.append

    async def flush():
        for record in added:
            if isinstance(record, InAppNotification) and record.id is None:
                record.id = uuid4()

    db.flush = AsyncMock(side_effect=flush)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db, added


@pytest.mark.asyncio
@pytest.mark.parametrize("commit", [False, True])
@pytest.mark.parametrize("scope", ["explicit", "resolved", "platform"])
async def test_bell_and_pending_event_are_staged_together_without_publication(
    monkeypatch, commit, scope
):
    user, org = uuid4(), None if scope == "platform" else uuid4()
    db, added = database(user, org)
    bus = SimpleNamespace(publish=AsyncMock())
    monkeypatch.setattr(events, "get_event_bus", lambda: bus)
    notification = await NotificationService(db).create_in_app(
        user,
        "owned",
        "private",
        organization_id=org if scope == "explicit" else None,
        commit=commit,
    )
    assert len(added) == 2
    bell, pending = added
    assert pending.notification_id == bell.id and notification["id"] == str(bell.id)
    assert bell.organization_id == pending.organization_id == org
    assert pending.user_id == bell.user_id == user
    assert db.commit.await_count == int(commit)
    db.rollback.assert_not_awaited()
    bus.publish.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("recipients", [1, 3])
async def test_shared_dispatch_leaves_commit_to_the_business_owner(monkeypatch, recipients):
    service = SimpleNamespace(create_in_app=AsyncMock())
    monkeypatch.setattr(notification_helpers, "NotificationService", lambda _db: service)
    db = MagicMock()
    result = await notification_helpers.dispatch_notifications(
        db,
        {"in_app": {"user_ids": [str(uuid4()) for _ in range(recipients)]}},
        "owned",
        "private",
        uuid4(),
    )
    assert len(result) == recipients and all(row.success for row in result)
    assert all(call.kwargs["commit"] is False for call in service.create_in_app.call_args_list)
    db.commit.assert_not_called()
    db.rollback.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("commit", [False, True])
async def test_outbox_flush_failure_is_not_reported_as_success(monkeypatch, caplog, commit):
    user, org = uuid4(), uuid4()
    db, _ = database(user, org)
    db.flush.side_effect = [None, RuntimeError(CANARY)]
    bus = SimpleNamespace(publish=AsyncMock())
    monkeypatch.setattr(events, "get_event_bus", lambda: bus)
    with pytest.raises(NotificationError) as error:
        await NotificationService(db).create_in_app(
            user, "owned", "private", organization_id=org, commit=commit
        )
    assert CANARY not in str(error.value) and CANARY not in caplog.text
    assert all(row.exc_info is None for row in caplog.records)
    db.commit.assert_not_awaited()
    assert db.rollback.await_count == int(commit)
    bus.publish.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("scoped", [False, True])
async def test_missing_recipient_never_creates_a_platform_or_tenant_event(monkeypatch, scoped):
    db, added = database(None, None)
    bus = SimpleNamespace(publish=AsyncMock())
    monkeypatch.setattr(events, "get_event_bus", lambda: bus)
    with pytest.raises(NotificationError):
        await NotificationService(db).create_in_app(
            uuid4(), "owned", "private", organization_id=uuid4() if scoped else None
        )
    assert not added
    db.commit.assert_not_awaited()
    bus.publish.assert_not_awaited()

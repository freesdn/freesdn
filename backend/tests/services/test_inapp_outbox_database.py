# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Independent PostgreSQL transactions qualify the personal event outbox.

Only the publication transport is synthetic here. Real Redis/Valkey and process
termination checks are additional release-qualification fixtures.
"""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select, update

from app.db.session import CelerySessionLocal
from app.models.core import Organization, User
from app.models.notification import InAppNotification
from app.models.notification_outbox import InAppNotificationEvent
from app.services import notification_helpers
from app.services import notification_outbox as outbox
from app.services.notification import NotificationService


@pytest_asyncio.fixture
async def committed_users(monkeypatch):
    org, foreign, user, peer = [uuid4() for _ in range(4)]
    async with CelerySessionLocal() as db:
        db.add_all(
            [
                Organization(
                    id=identity, name="Owned outbox fixture", slug="outbox-" + identity.hex
                )
                for identity in [org, foreign]
            ]
        )
        await db.flush()
        db.add_all(
            [
                User(
                    id=identity,
                    organization_id=org,
                    email=identity.hex + "@example.invalid",
                    username=identity.hex,
                    hashed_password="synthetic-not-a-login-password",
                )
                for identity in [user, peer]
            ]
        )
        await db.commit()
    client = SimpleNamespace(publish=AsyncMock(return_value=1), aclose=AsyncMock())
    monkeypatch.setattr(outbox, "get_async_redis", lambda **_kwargs: client)
    try:
        yield SimpleNamespace(org=org, foreign=foreign, user=user, peer=peer, client=client)
    finally:
        async with CelerySessionLocal() as db:
            await db.execute(delete(User).where(User.id.in_([user, peer])))
            await db.execute(delete(Organization).where(Organization.id.in_([org, foreign])))
            await db.commit()


async def create(fixture):
    async with CelerySessionLocal() as db:
        result = await NotificationService(db).create_in_app(
            fixture.user, "owned", "private", organization_id=fixture.org
        )
    from uuid import UUID

    return UUID(result["id"])


async def read(identity):
    async with CelerySessionLocal() as db:
        return await db.get(InAppNotificationEvent, identity)


@pytest.mark.asyncio
@pytest.mark.parametrize("finish", ["commit", "rollback"])
async def test_pending_bell_and_event_are_invisible_until_business_owner_commits(
    committed_users, finish
):
    f = committed_users
    async with CelerySessionLocal() as db:
        original = (await db.get(Organization, f.org)).name
        (await db.get(Organization, f.org)).name = "Uncommitted business edit"
        results = await notification_helpers.dispatch_notifications(
            db, {"in_app": {"user_ids": [str(f.user)]}}, "owned", "private", f.org
        )
        assert results[0].success
        assert await outbox.publish_pending_notifications(1) == {
            "published": 0,
            "deferred": 0,
            "suppressed": 0,
        }
        async with CelerySessionLocal() as observer:
            assert (await observer.get(Organization, f.org)).name == original
            assert (
                await observer.scalar(
                    select(func.count())
                    .select_from(InAppNotification)
                    .where(InAppNotification.user_id == f.user)
                )
                == 0
            )
        await getattr(db, finish)()
    expected = int(finish == "commit")
    assert (await outbox.publish_pending_notifications(1))["published"] == expected
    async with CelerySessionLocal() as observer:
        assert (
            await observer.scalar(
                select(func.count())
                .select_from(InAppNotification)
                .where(InAppNotification.user_id == f.user)
            )
            == expected
        )
        assert (
            await observer.scalar(
                select(func.count())
                .select_from(InAppNotificationEvent)
                .where(InAppNotificationEvent.user_id == f.user)
            )
            == expected
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "user_disabled",
        "user_deleted",
        "org_disabled",
        "org_deleted",
        "user_moved",
        "notification_moved",
        "notification_retargeted",
        "read",
        "dismissed",
    ],
)
async def test_worker_checks_committed_current_recipient_and_notification_state(
    committed_users, change
):
    f = committed_users
    identity = await create(f)
    now = datetime.now(UTC)
    if change.startswith("user_"):
        model, key = User, f.user
        values = (
            {"is_active": False}
            if change == "user_disabled"
            else {"deleted_at": now}
            if change == "user_deleted"
            else {"organization_id": f.foreign}
        )
    elif change.startswith("org_"):
        model, key = Organization, f.org
        values = {"is_active": False} if change == "org_disabled" else {"deleted_at": now}
    else:
        model, key = InAppNotification, identity
        values = (
            {"organization_id": f.foreign}
            if change == "notification_moved"
            else {"user_id": f.peer}
            if change == "notification_retargeted"
            else {change: True}
        )
    async with CelerySessionLocal() as db:
        await db.execute(update(model).where(model.id == key).values(**values))
        await db.commit()
    assert await outbox.publish_pending_notifications(1) == {
        "published": 0,
        "deferred": 0,
        "suppressed": 1,
    }
    row = await read(identity)
    assert row.status == "suppressed" and row.published_at is None
    f.client.publish.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["organization", "user", "notification"])
async def test_hard_delete_cascades_pending_event_instead_of_promoting_scope(
    committed_users, target
):
    f = committed_users
    identity = await create(f)
    model, key = (
        (Organization, f.org)
        if target == "organization"
        else (User, f.user)
        if target == "user"
        else (InAppNotification, identity)
    )
    async with CelerySessionLocal() as db:
        await db.execute(delete(model).where(model.id == key))
        await db.commit()
    assert await read(identity) is None
    assert await outbox.publish_pending_notifications(1) == {
        "published": 0,
        "deferred": 0,
        "suppressed": 0,
    }
    f.client.publish.assert_not_awaited()


@pytest.mark.asyncio
async def test_locked_row_is_skipped_then_recovered_after_lock_owner_rolls_back(committed_users):
    f = committed_users
    identity = await create(f)
    async with CelerySessionLocal() as owner:
        await owner.execute(
            select(InAppNotificationEvent)
            .where(InAppNotificationEvent.notification_id == identity)
            .with_for_update()
        )
        assert await asyncio.wait_for(outbox.publish_pending_notifications(1), 2) == {
            "published": 0,
            "deferred": 0,
            "suppressed": 0,
        }
        f.client.publish.assert_not_awaited()
        await owner.rollback()
    assert (await outbox.publish_pending_notifications(1))["published"] == 1
    assert (await read(identity)).status == "published"


@pytest.mark.asyncio
async def test_concurrent_workers_do_not_publish_the_same_committed_row_twice(committed_users):
    f = committed_users
    await create(f)

    async def accept(*_args):
        await asyncio.sleep(0.05)
        return 1

    f.client.publish.side_effect = accept
    rows = await asyncio.gather(
        outbox.publish_pending_notifications(1), outbox.publish_pending_notifications(1)
    )
    assert sum(row["published"] for row in rows) == 1
    f.client.publish.assert_awaited_once()


@pytest.mark.asyncio
async def test_refused_publication_is_due_later_and_recoverable(committed_users):
    f = committed_users
    identity = await create(f)
    f.client.publish.return_value = 0
    assert (await outbox.publish_pending_notifications(1))["deferred"] == 1
    row = await read(identity)
    assert row.status == "pending" and row.attempts == 1 and row.last_failure == "no_subscribers"
    assert (await outbox.publish_pending_notifications(1)) == {
        "published": 0,
        "deferred": 0,
        "suppressed": 0,
    }
    async with CelerySessionLocal() as db:
        await db.execute(
            update(InAppNotificationEvent)
            .where(InAppNotificationEvent.notification_id == identity)
            .values(next_attempt_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await db.commit()
    f.client.publish.return_value = 1
    assert (await outbox.publish_pending_notifications(1))["published"] == 1
    assert (await read(identity)).attempts == 2
    assert (await outbox.publish_pending_notifications(1)) == {
        "published": 0,
        "deferred": 0,
        "suppressed": 0,
    }


@pytest.mark.asyncio
async def test_publication_followed_by_transaction_abort_is_retried_with_same_event_identity(
    committed_users, monkeypatch
):
    f = committed_users
    identity = await create(f)
    factory = CelerySessionLocal

    class AbortCommit:
        def __init__(self, db):
            self.db = db

        async def __aenter__(self):
            return await self.db.begin().__aenter__()

        async def __aexit__(self, *_args):
            await self.db.rollback()
            raise RuntimeError("synthetic transaction abort after broker acknowledgment")

    class OwnedSession:
        def __init__(self):
            self.db = factory()

        async def __aenter__(self):
            await self.db.__aenter__()
            return self

        async def __aexit__(self, *args):
            return await self.db.__aexit__(*args)

        def begin(self):
            return AbortCommit(self.db)

        async def execute(self, *args, **kwargs):
            return await self.db.execute(*args, **kwargs)

    monkeypatch.setattr(outbox, "CelerySessionLocal", OwnedSession)
    with pytest.raises(RuntimeError, match="synthetic transaction abort"):
        await outbox.publish_pending_notifications(1)
    assert (await read(identity)).status == "pending"
    first = json.loads(f.client.publish.call_args.args[1])
    monkeypatch.setattr(outbox, "CelerySessionLocal", factory)
    assert (await outbox.publish_pending_notifications(1))["published"] == 1
    second = json.loads(f.client.publish.call_args.args[1])
    assert first == second and f.client.publish.await_count == 2

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Pending publication survives refusal, uncertainty, cancellation and commit errors."""

import asyncio
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.models.notification import InAppNotification
from app.services import notification_outbox as service

CANARY = "synthetic-private-publication-error"


def fixture(monkeypatch, *, eligible=True, acknowledgment=1, commit_error=None):
    now = datetime.now(UTC)
    user, org, identity = uuid4(), uuid4(), uuid4()
    pending = SimpleNamespace(
        notification_id=identity,
        user_id=user,
        organization_id=org,
        attempts=0,
        status="pending",
        next_attempt_at=now,
        published_at=None,
        suppressed_at=None,
        last_failure=None,
    )
    notification = InAppNotification(
        id=identity,
        user_id=user,
        organization_id=org,
        created_at=now,
        read=False,
        dismissed=False,
        title="owned",
        body="private",
        category="system",
        severity="info",
        data={},
    )
    db = MagicMock()
    db.__aenter__ = AsyncMock(return_value=db)
    tx = MagicMock()
    tx.__aexit__ = AsyncMock(side_effect=commit_error, return_value=False)
    db.begin.return_value = tx
    db.execute = AsyncMock(
        side_effect=[
            SimpleNamespace(scalar_one_or_none=lambda: pending),
            SimpleNamespace(scalar_one_or_none=lambda: notification if eligible else None),
        ]
    )
    monkeypatch.setattr(service, "CelerySessionLocal", lambda: db)
    client = SimpleNamespace(publish=AsyncMock(return_value=acknowledgment), aclose=AsyncMock())
    monkeypatch.setattr(service, "get_async_redis", lambda **_kwargs: client)
    return pending, notification, db, tx, client


@pytest.mark.asyncio
@pytest.mark.parametrize("acknowledgment", [1, 2, 0, -1, None, "1", True])
async def test_only_a_positive_integer_broker_ack_marks_publication(monkeypatch, acknowledgment):
    pending, notification, _db, _tx, client = fixture(monkeypatch, acknowledgment=acknowledgment)
    accepted = type(acknowledgment) is int and acknowledgment > 0
    result = await service.publish_pending_notifications(1)
    assert result == {"published": int(accepted), "deferred": int(not accepted), "suppressed": 0}
    assert pending.status == ("published" if accepted else "pending")
    assert pending.attempts == 1
    assert (pending.published_at is not None) is accepted
    channel, raw = client.publish.call_args.args
    event = json.loads(raw)
    assert channel == "freesdn:events:user:" + str(notification.organization_id)
    assert event["id"] == str(notification.id)
    assert (
        event["payload"]["user_id"]
        == event["payload"]["notification"]["user_id"]
        == str(notification.user_id)
    )
    if not accepted:
        assert pending.last_failure == "no_subscribers"
        assert (pending.next_attempt_at - notification.created_at).total_seconds() >= 2
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("attempts", [0, 5, 30, 2_147_483_647])
async def test_uncertain_publication_keeps_pending_and_bounds_retry_delay(
    monkeypatch, caplog, attempts
):
    pending, _notification, _db, _tx, client = fixture(monkeypatch)
    pending.attempts = attempts
    client.publish.side_effect = RuntimeError(CANARY)
    start = datetime.now(UTC)
    result = await service.publish_pending_notifications(1)
    assert result == {"published": 0, "deferred": 1, "suppressed": 0}
    assert pending.status == "pending" and pending.published_at is None
    assert 2 <= (pending.next_attempt_at - start).total_seconds() < 61
    assert pending.attempts == min(attempts + 1, 2_147_483_647)
    assert pending.last_failure == "publication_unavailable"
    assert CANARY not in caplog.text and all(row.exc_info is None for row in caplog.records)
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_ineligible_recipient_or_seen_notification_is_suppressed_without_publication(
    monkeypatch,
):
    pending, _notification, _db, _tx, client = fixture(monkeypatch, eligible=False)
    assert await service.publish_pending_notifications(1) == {
        "published": 0,
        "deferred": 0,
        "suppressed": 1,
    }
    assert (
        pending.status == "suppressed"
        and pending.suppressed_at is not None
        and pending.published_at is None
    )
    client.publish.assert_not_awaited()
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_cancellation_propagates_and_releases_owned_resources(monkeypatch):
    _pending, _notification, _db, tx, client = fixture(monkeypatch)
    client.publish.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await service.publish_pending_notifications(1)
    assert tx.__aexit__.call_args.args[0] is asyncio.CancelledError
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_commit_failure_is_not_counted_as_a_success(monkeypatch):
    _pending, _notification, _db, _tx, client = fixture(
        monkeypatch, commit_error=RuntimeError(CANARY)
    )
    with pytest.raises(RuntimeError, match=CANARY):
        await service.publish_pending_notifications(1)
    client.publish.assert_awaited_once()
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_empty_queue_closes_client_without_publishing(monkeypatch):
    _pending, _notification, db, _tx, client = fixture(monkeypatch)
    db.execute.side_effect = [SimpleNamespace(scalar_one_or_none=lambda: None)]
    assert await service.publish_pending_notifications(1) == {
        "published": 0,
        "deferred": 0,
        "suppressed": 0,
    }
    client.publish.assert_not_awaited()
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", [0, -1, 101, True, "1", None])
async def test_invalid_batch_limit_creates_no_resources(monkeypatch, limit):
    factory = MagicMock()
    monkeypatch.setattr(service, "get_async_redis", factory)
    with pytest.raises(ValueError):
        await service.publish_pending_notifications(limit)
    factory.assert_not_called()


def test_event_identity_is_stable_across_retries(monkeypatch):
    _pending, notification, _db, _tx, _client = fixture(monkeypatch)
    assert (
        service.notification_event(notification).to_dict()
        == service.notification_event(notification).to_dict()
    )


def test_worker_and_default_queue_beat_are_registered():
    from app.core.celery_app import celery_app
    from app.tasks.notification_outbox import publish_in_app_events

    assert "app.tasks.notification_outbox" in celery_app.conf.include
    schedule = celery_app.conf.beat_schedule["publish-in-app-events"]
    assert schedule == {
        "task": publish_in_app_events.name,
        "schedule": 5.0,
        "options": {"queue": "default"},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["configured", "empty", "dispatch_failed", "commit_failed"])
async def test_plugin_alert_owner_persists_its_post_commit_notification_transaction(
    monkeypatch, caplog, mode
):
    from app.plugins.sdk import AlertSDK
    from app.services import notification_helpers

    db = MagicMock()
    db.commit = AsyncMock(side_effect=RuntimeError(CANARY) if mode == "commit_failed" else None)
    db.rollback = AsyncMock()
    sender = AsyncMock(side_effect=RuntimeError(CANARY) if mode == "dispatch_failed" else None)
    monkeypatch.setattr(notification_helpers, "dispatch_notifications", sender)
    owner = SimpleNamespace(_db=db, _org_id=uuid4(), _plugin_id="owned-fixture")
    alert = SimpleNamespace(title="owned", message="private")
    rule = SimpleNamespace(notification_channels={} if mode == "empty" else {"in_app": {}})
    await AlertSDK._notify(owner, alert, rule)
    assert sender.await_count == int(mode != "empty")
    assert db.commit.await_count == int(mode in {"configured", "commit_failed"})
    assert db.rollback.await_count == int(mode == "commit_failed")
    assert CANARY not in caplog.text and all(row.exc_info is None for row in caplog.records)

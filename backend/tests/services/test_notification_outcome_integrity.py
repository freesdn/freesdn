# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Delivery outcomes and retry identities must describe the attempt that occurred."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.core.fabric.builtin_ops import _notify_handler
from app.core.fabric.execution import OperationContext
from app.services import notification_helpers as helpers
from app.services.notification import (
    DeliveryResult,
    DeliveryStatus,
    NotificationChannel,
    NotificationPayload,
    NotificationService,
)

CANARY = "qualification-only-notification-private-detail"


def result(success=True, status=DeliveryStatus.SENT):
    return DeliveryResult(
        success, NotificationChannel.EMAIL, status, error=CANARY if not success else None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcomes", "success", "output"),
    [
        ([result(False, DeliveryStatus.FAILED)], False, {"dispatched": 0, "failed": 1}),
        ([result(), result(False, DeliveryStatus.FAILED)], False, {"dispatched": 1, "failed": 1}),
        ([result(), result(True, DeliveryStatus.SKIPPED)], True, {"dispatched": 1, "skipped": 1}),
        ([result(True, DeliveryStatus.SKIPPED)], True, {"dispatched": 0, "skipped": 1}),
        ([result()], True, {"dispatched": 1}),
        ([], True, {"dispatched": 0}),
    ],
)
async def test_fabric_reports_actual_delivery_outcomes(monkeypatch, outcomes, success, output):
    send = AsyncMock(return_value=outcomes)
    monkeypatch.setattr(helpers, "dispatch_notifications", send)
    response = await _notify_handler(OperationContext(uuid4(), {"channels": {}}, db=MagicMock()))
    assert response.success is success
    assert response.output == output
    assert response.error_code == (None if success else "NOTIFY_ERROR")
    assert CANARY not in json.dumps(response.to_dict())
    send.assert_awaited_once()


def service_fixture(monkeypatch):
    from app.tasks import notification_retry

    service = MagicMock()
    service.load_providers_from_db = AsyncMock()
    service.send = AsyncMock()
    service.create_in_app = AsyncMock()
    monkeypatch.setattr(helpers, "NotificationService", lambda _db: service)
    retry = MagicMock()
    monkeypatch.setattr(notification_retry, "schedule_retry", retry)
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.execute.return_value.scalar_one_or_none.return_value = uuid4()
    return service, db, retry


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", ["email", "in_app"])
async def test_raised_attempt_remains_failed_without_private_details(monkeypatch, caplog, channel):
    service, db, retry = service_fixture(monkeypatch)
    targets = (
        [str(uuid4()), str(uuid4())]
        if channel == "in_app"
        else ["first@example.invalid", "second@example.invalid"]
    )
    if channel == "in_app":
        service.create_in_app.side_effect = [RuntimeError(CANARY), None]
        config = {channel: {"user_ids": targets}}
    else:
        service.send.side_effect = [RuntimeError(CANARY), result()]
        config = {channel: {"to": targets}}
    outcomes = await helpers.dispatch_notifications(
        db, config, "same subject", "owned body", uuid4()
    )
    assert len(outcomes) == 2 and [r.success for r in outcomes] == [False, True]
    assert outcomes[0].status == DeliveryStatus.FAILED
    assert CANARY not in str(outcomes) and CANARY not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    retry.assert_not_called()
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancelled_provider_is_not_an_empty_success(monkeypatch):
    service, db, retry = service_fixture(monkeypatch)
    service.send.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await helpers.dispatch_notifications(
            db, {"email": {"to": "owned@example.invalid"}}, "title", "body", uuid4()
        )
    retry.assert_not_called()


@pytest.mark.asyncio
async def test_retries_use_exact_attempt_id_even_with_identical_subjects(monkeypatch):
    service, db, retry = service_fixture(monkeypatch)
    outcomes = [result(False, DeliveryStatus.FAILED), result(False, DeliveryStatus.FAILED)]
    ids = [str(uuid4()), str(uuid4())]
    for outcome, identity in zip(outcomes, ids, strict=True):
        outcome.delivery_id = identity
    service.send.side_effect = outcomes
    recipients = ["first@example.invalid", "second@example.invalid"]
    returned = await helpers.dispatch_notifications(
        db, {"email": {"to": recipients}}, "identical subject", "body", uuid4()
    )
    assert returned == outcomes
    assert [
        (call.kwargs["delivery_id"], call.kwargs["recipient"]) for call in retry.call_args_list
    ] == list(zip(ids, recipients, strict=True))
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_tracking_identity_never_borrows_an_unrelated_row(monkeypatch):
    service, db, retry = service_fixture(monkeypatch)
    service.send.return_value = result(False, DeliveryStatus.FAILED)
    returned = await helpers.dispatch_notifications(
        db, {"email": {"to": "owned@example.invalid"}}, "identical subject", "body", None
    )
    assert len(returned) == 1 and not returned[0].success
    retry.assert_not_called()
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("flush_fails", [False, True])
async def test_tracking_identity_is_set_only_after_the_owned_row_flushes(caplog, flush_fails):
    db = MagicMock()
    identity = uuid4()

    async def flush():
        if flush_fails:
            raise RuntimeError(CANARY)
        db.add.call_args.args[0].id = identity

    db.flush = AsyncMock(side_effect=flush)
    service = NotificationService(db)
    outcome = result(False, DeliveryStatus.FAILED)
    outcome.delivery_id = str(uuid4())  # Untrusted/stale provider-supplied identity.
    await service._track_delivery(
        None, None, NotificationChannel.EMAIL, outcome, NotificationPayload("owned", "body")
    )
    assert outcome.delivery_id == (None if flush_fails else str(identity))
    assert CANARY not in caplog.text
    db.add.assert_called_once()
    db.flush.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "commit", "rollback_fails"),
    [
        ("flush", True, False),
        ("flush", False, False),
        ("commit", True, False),
        ("commit", True, True),
    ],
)
async def test_inapp_persistence_failure_never_publishes_phantom_notification(
    monkeypatch, caplog, failure, commit, rollback_fails
):
    from app.core import events
    from app.services.notification import NotificationError

    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.execute.return_value.one_or_none.return_value = (uuid4(), None)
    db.flush = AsyncMock(side_effect=RuntimeError(CANARY) if failure == "flush" else None)
    db.commit = AsyncMock(side_effect=RuntimeError(CANARY) if failure == "commit" else None)
    db.rollback = AsyncMock(side_effect=RuntimeError(CANARY) if rollback_fails else None)
    bus = MagicMock()
    bus.publish = AsyncMock()
    monkeypatch.setattr(events, "get_event_bus", lambda: bus)
    with pytest.raises(NotificationError) as caught:
        await NotificationService(db).create_in_app(uuid4(), "owned", "body", commit=commit)
    assert CANARY not in str(caught.value) and CANARY not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    bus.publish.assert_not_awaited()
    assert db.rollback.await_count == int(commit)


@pytest.mark.asyncio
@pytest.mark.parametrize("commit", [False, True])
async def test_inapp_success_keeps_owned_tracking_identity_and_commit_choice(monkeypatch, commit):
    from app.core import events

    identity = uuid4()
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.execute.return_value.one_or_none.return_value = (uuid4(), None)

    async def flush():
        db.add.call_args.args[0].id = identity

    db.flush = AsyncMock(side_effect=flush)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    bus = MagicMock()
    bus.publish = AsyncMock()
    monkeypatch.setattr(events, "get_event_bus", lambda: bus)
    notification = await NotificationService(db).create_in_app(
        uuid4(), "owned", "body", commit=commit
    )
    assert notification["id"] == str(identity)
    assert db.commit.await_count == int(commit)
    db.rollback.assert_not_awaited()
    bus.publish.assert_not_awaited()
    assert db.add.call_count == db.flush.await_count == 2
    assert db.add.call_args.args[0].notification_id == identity


@pytest.mark.asyncio
async def test_inapp_persistence_cancellation_propagates_without_event(monkeypatch):
    from app.core import events

    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.execute.return_value.one_or_none.return_value = (uuid4(), None)
    db.flush = AsyncMock(side_effect=asyncio.CancelledError())
    bus = MagicMock()
    bus.publish = AsyncMock()
    monkeypatch.setattr(events, "get_event_bus", lambda: bus)
    with pytest.raises(asyncio.CancelledError):
        await NotificationService(db).create_in_app(uuid4(), "owned", "body")
    bus.publish.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("lookup", ["absent", "error", "cancelled", "owned"])
async def test_scoped_inapp_recipient_requires_owned_active_user(monkeypatch, caplog, lookup):
    from app.core import events
    from app.services.notification import NotificationError

    user_id, org_id, notification_id = uuid4(), uuid4(), uuid4()
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.execute.return_value.one_or_none.return_value = (
        (user_id, org_id) if lookup == "owned" else None
    )
    if lookup == "error":
        db.execute.side_effect = RuntimeError(CANARY)
    if lookup == "cancelled":
        db.execute.side_effect = asyncio.CancelledError()

    async def flush():
        db.add.call_args.args[0].id = notification_id

    db.flush = AsyncMock(side_effect=flush)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    bus = MagicMock()
    bus.publish = AsyncMock()
    monkeypatch.setattr(events, "get_event_bus", lambda: bus)
    service = NotificationService(db)
    if lookup == "owned":
        response = await service.create_in_app(user_id, "owned", "body", organization_id=org_id)
        assert response["id"] == str(notification_id)
        assert db.add.call_args.args[0].organization_id == org_id
        bus.publish.assert_not_awaited()
        assert db.add.call_args.args[0].notification_id == notification_id
        db.commit.assert_awaited_once()
    else:
        expected = asyncio.CancelledError if lookup == "cancelled" else NotificationError
        with pytest.raises(expected):
            await service.create_in_app(user_id, "owned", "body", organization_id=org_id)
        db.add.assert_not_called()
        db.flush.assert_not_awaited()
        db.commit.assert_not_awaited()
        bus.publish.assert_not_awaited()
        assert CANARY not in caplog.text

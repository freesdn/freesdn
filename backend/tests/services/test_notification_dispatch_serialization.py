# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Dispatch must respect the caller's single-session transaction contract."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.exc import InvalidRequestError

from app.services import notification_helpers as helpers
from app.services.notification import (
    DeliveryResult,
    DeliveryStatus,
    NotificationChannel,
    NotificationService,
)


@pytest.fixture
def dispatch_session(monkeypatch):
    from app.tasks import notification_retry

    db = MagicMock()
    records = []
    sends = []
    state = SimpleNamespace(active=0, peak=0, failed=False, interrupt=None, ordinary_error=None)
    db.add.side_effect = records.append

    async def flush():
        # Model SQLAlchemy's documented single-transaction exclusivity. The
        # real driver/mapper reproduction lives in the database qualification.
        state.active += 1
        state.peak = max(state.peak, state.active)
        try:
            if state.active > 1:
                raise InvalidRequestError("Session is already flushing")
            record = records[-1]
            await asyncio.sleep(0)
            record.id = uuid4()
        finally:
            state.active -= 1

    db.flush = AsyncMock(side_effect=flush)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()

    async def load(service, organization_id=None):
        for channel in [NotificationChannel.EMAIL, NotificationChannel.SLACK]:

            async def send(recipient, _payload, selected=channel):
                sends.append((selected, recipient))
                if recipient == state.interrupt:
                    raise asyncio.CancelledError()
                if recipient == state.ordinary_error:
                    raise RuntimeError("owned transport refusal")
                return DeliveryResult(
                    not state.failed,
                    selected,
                    DeliveryStatus.FAILED if state.failed else DeliveryStatus.SENT,
                    error="429 temporary refusal" if state.failed else None,
                    message_id=recipient,
                )

            service.register_provider(
                channel, SimpleNamespace(provider_type=channel.value, send=send)
            )

    monkeypatch.setattr(NotificationService, "load_providers_from_db", load)
    retry = MagicMock(return_value=True)
    monkeypatch.setattr(notification_retry, "schedule_retry", retry)
    return SimpleNamespace(db=db, records=records, sends=sends, state=state, retry=retry)


@pytest.mark.asyncio
@pytest.mark.parametrize("layout", ["single", "two", "four", "mixed"])
@pytest.mark.parametrize("failed", [False, True])
async def test_batch_keeps_each_recipient_identity_without_overlapping_session_use(
    dispatch_session, layout, failed
):
    f = dispatch_session
    f.state.failed = failed
    recipients = [f"owned-{index}@example.invalid" for index in range(4)]
    count = {"single": 1, "two": 2, "four": 4, "mixed": 2}[layout]
    config = {"email": {"to": recipients[:count]}}
    targets = [(NotificationChannel.EMAIL, recipient) for recipient in recipients[:count]]
    if layout == "mixed":
        config["slack"] = {"channel": "#owned"}
        targets.append((NotificationChannel.SLACK, "#owned"))
    results = await helpers.dispatch_notifications(f.db, config, "Owned", "Synthetic", uuid4())
    assert f.sends == targets
    assert len(results) == len(targets)
    assert f.state.peak == 1, "Concurrent attempts used the same mutable database session"
    identities = [result.delivery_id for result in results]
    assert all(identities) and len(set(identities)) == len(targets)
    assert identities == [str(record.id) for record in f.records]
    assert all(result.success is (not failed) for result in results)
    assert f.retry.call_count == (len(targets) if failed else 0)
    if failed:
        assert [
            (call.kwargs["delivery_id"], call.kwargs["recipient"])
            for call in f.retry.call_args_list
        ] == list(zip(identities, [recipient for _channel, recipient in targets], strict=True))
    f.db.commit.assert_not_awaited()
    f.db.rollback.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_index", [0, 1])
async def test_cancellation_does_not_start_later_recipients_or_publish_retries(
    dispatch_session, cancel_index
):
    f = dispatch_session
    recipients = [f"owned-{index}@example.invalid" for index in range(3)]
    f.state.interrupt = recipients[cancel_index]
    f.state.failed = True
    with pytest.raises(asyncio.CancelledError):
        await helpers.dispatch_notifications(
            f.db, {"email": {"to": recipients}}, "Owned", "Synthetic", uuid4()
        )
    assert [recipient for _channel, recipient in f.sends] == recipients[: cancel_index + 1]
    f.retry.assert_not_called()
    f.db.commit.assert_not_awaited()
    f.db.rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_ordinary_provider_failure_still_allows_the_next_recipient(dispatch_session):
    f = dispatch_session
    f.state.ordinary_error = "owned-error@example.invalid"
    recipients = [f.state.ordinary_error, "owned-next@example.invalid"]
    results = await helpers.dispatch_notifications(
        f.db, {"email": {"to": recipients}}, "Owned", "Synthetic", uuid4()
    )
    assert [recipient for _channel, recipient in f.sends] == recipients
    assert [result.success for result in results] == [False, True]
    assert results[0].delivery_id is None and results[1].delivery_id is not None
    f.retry.assert_not_called()

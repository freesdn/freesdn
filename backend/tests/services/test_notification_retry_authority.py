# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Delayed retries must recheck persisted authority before external delivery.

The SQL fixture executes production queries using SQLite. PostgreSQL row locks,
commit races and external provider acceptance require separate qualification.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

from app.models.core import Organization
from app.models.notification import NotificationDelivery, NotificationProviderRecord
from app.services.notification import DeliveryResult, DeliveryStatus, NotificationChannel
from app.tasks import notification_retry as retry

CANARY = "qualification-only-private-retry-detail"


@pytest.fixture
def owned_retry(monkeypatch):
    engine = create_engine("sqlite://")
    connection = engine.connect()
    connection.exec_driver_sql("ATTACH DATABASE ':memory:' AS core")
    for model in [Organization, NotificationDelivery, NotificationProviderRecord]:
        columns = ", ".join('"' + c.name + '"' for c in model.__table__.columns)
        connection.exec_driver_sql(f"CREATE TABLE core.{model.__tablename__} ({columns})")
    org, foreign, delivery, provider = [uuid4() for _ in range(4)]
    for oid in [org, foreign]:
        connection.execute(
            Organization.__table__.insert().values(
                id=oid, name="Owned fixture", slug=str(oid), is_active=True
            )
        )
    connection.execute(
        NotificationDelivery.__table__.insert().values(
            id=delivery,
            organization_id=org,
            channel="email",
            subject="Owned subject",
            success=False,
            status="failed",
            provider="smtp",
            attempt=1,
            retry_dead_letter=False,
            sent_at=datetime.now(UTC),
        )
    )
    connection.execute(
        NotificationProviderRecord.__table__.insert().values(
            id=provider,
            organization_id=org,
            name="Owned synthetic provider",
            channel="email",
            provider_type="smtp",
            is_enabled=True,
            is_default=True,
            config={},
            created_at=datetime.now(UTC),
        )
    )
    connection.commit()
    runtime = SimpleNamespace(
        provider_type="smtp",
        send=AsyncMock(
            return_value=DeliveryResult(True, NotificationChannel.EMAIL, DeliveryStatus.SENT)
        ),
    )
    build = MagicMock(return_value=runtime)
    monkeypatch.setattr(retry.NotificationService, "_build_runtime_provider", build)
    faults = {}

    @asynccontextmanager
    async def factory():
        with Session(bind=connection, expire_on_commit=False) as session:

            class Database:
                async def execute(self, statement):
                    return session.execute(statement)

                async def commit(self):
                    if faults.get("commit"):
                        raise RuntimeError(CANARY)
                    session.commit()

                async def rollback(self):
                    session.rollback()

                async def flush(self):
                    session.flush()

            yield Database()

    monkeypatch.setattr(retry, "AsyncSessionLocal", factory)
    enqueue = MagicMock()
    monkeypatch.setattr(retry.retry_notification_delivery, "apply_async", enqueue)

    def change(model, identity, **values):
        connection.execute(update(model).where(model.id == identity).values(**values))
        connection.commit()

    def row():
        with Session(bind=connection) as session:
            item = session.scalar(
                select(NotificationDelivery).where(NotificationDelivery.id == delivery)
            )
            if item is None:
                return None
            return {c.name: getattr(item, c.name) for c in NotificationDelivery.__table__.columns}

    values = {
        "delivery_id": str(delivery),
        "provider_id": str(provider),
        "channel": "email",
        "recipient": "owned@example.invalid",
        "title": "Owned subject",
        "body": "Synthetic retry fixture only",
        "body_html": None,
        "organization_id": str(org),
        "attempt": 2,
        "max_retries": 5,
    }
    try:
        yield SimpleNamespace(
            values=values,
            org=org,
            foreign=foreign,
            delivery=delivery,
            provider=provider,
            change=change,
            row=row,
            runtime=runtime,
            build=build,
            enqueue=enqueue,
            connection=connection,
            faults=faults,
        )
    finally:
        connection.close()
        engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state",
    [
        "missing",
        "foreign",
        "wrong_channel",
        "wrong_subject",
        "sent",
        "skipped",
        "success",
        "dead_letter",
        "stale_attempt",
        "future_attempt",
        "org_inactive",
        "org_deleted",
        "org_missing",
    ],
)
async def test_ineligible_delivery_never_sends_or_changes_its_row(owned_retry, state):
    f = owned_retry
    changes = {
        "foreign": {"organization_id": f.foreign},
        "wrong_channel": {"channel": "sms"},
        "wrong_subject": {"subject": "Unrelated subject"},
        "sent": {"status": "sent"},
        "skipped": {"status": "skipped"},
        "success": {"success": True},
        "dead_letter": {"retry_dead_letter": True},
        "stale_attempt": {"attempt": 2},
        "future_attempt": {"attempt": 0},
    }
    if state == "missing":
        f.connection.execute(NotificationDelivery.__table__.delete())
        f.connection.commit()
    elif state.startswith("org_"):
        if state == "org_missing":
            f.connection.execute(Organization.__table__.delete().where(Organization.id == f.org))
            f.connection.commit()
        else:
            f.change(
                Organization,
                f.org,
                **(
                    {"is_active": False}
                    if state == "org_inactive"
                    else {"deleted_at": datetime.now(UTC)}
                ),
            )
    else:
        f.change(NotificationDelivery, f.delivery, **changes[state])
    before = f.row()
    outcome = await retry._do_retry(**f.values)
    f.runtime.send.assert_not_awaited()
    f.enqueue.assert_not_called()
    assert outcome["success"] is False
    assert f.row() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["foreign", "disabled", "wrong_channel", "missing"])
async def test_explicit_provider_must_be_owned_enabled_and_channel_matched(owned_retry, state):
    f = owned_retry
    if state == "missing":
        # Keep an eligible default available: an explicit stale ID cannot fall back.
        f.values["provider_id"] = str(uuid4())
    else:
        f.change(
            NotificationProviderRecord,
            f.provider,
            **{
                "foreign": {"organization_id": f.foreign},
                "disabled": {"is_enabled": False},
                "wrong_channel": {"channel": "sms"},
            }[state],
        )
    outcome = await retry._do_retry(**f.values)
    f.runtime.send.assert_not_awaited()
    f.enqueue.assert_not_called()
    assert outcome["success"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_id", ["explicit", "default"])
async def test_owned_retry_sends_once_then_duplicate_is_refused(owned_retry, provider_id):
    f = owned_retry
    if provider_id == "default":
        f.values["provider_id"] = None
    first = await retry._do_retry(**f.values)
    assert first["success"] is True
    assert f.row()["status"] == "sent" and f.row()["attempt"] == 2
    second = await retry._do_retry(**f.values)
    assert second["success"] is False
    f.runtime.send.assert_awaited_once()
    assert f.runtime.send.await_args.args[0] == f.values["recipient"]
    assert f.runtime.send.await_args.args[1].title == f.values["title"]
    assert f.runtime.send.await_args.args[1].body == f.values["body"]


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_scope", ["platform", "foreign"])
async def test_platform_delivery_never_loads_a_tenant_provider(owned_retry, provider_scope):
    f = owned_retry
    f.change(NotificationDelivery, f.delivery, organization_id=None)
    f.values.update(organization_id=None, provider_id=None)
    if provider_scope == "platform":
        f.change(NotificationProviderRecord, f.provider, organization_id=None)
    outcome = await retry._do_retry(**f.values)
    assert outcome["success"] is (provider_scope == "platform")
    assert f.runtime.send.await_count == (1 if provider_scope == "platform" else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "values",
    [
        {"delivery_id": "invalid"},
        {"organization_id": "invalid"},
        {"provider_id": "invalid"},
        {"attempt": 1},
        {"attempt": 6},
        {"attempt": True},
        {"max_retries": 0},
    ],
)
async def test_invalid_retry_arguments_have_no_external_effect(owned_retry, values):
    f = owned_retry
    before = f.row()
    outcome = await retry._do_retry(**(f.values | values))
    f.runtime.send.assert_not_awaited()
    f.enqueue.assert_not_called()
    assert outcome["success"] is False and f.row() == before


@pytest.mark.asyncio
async def test_owned_transient_failure_commits_before_next_attempt_is_queued(owned_retry):
    f = owned_retry
    f.runtime.send.return_value = DeliveryResult(
        False, NotificationChannel.EMAIL, DeliveryStatus.FAILED, error="timeout"
    )
    observations = []
    f.enqueue.side_effect = lambda **_kwargs: observations.append(f.row()["attempt"])
    outcome = await retry._do_retry(**f.values)
    assert outcome["success"] is False and outcome["rescheduled"] is True
    assert observations == [2]
    assert f.enqueue.call_args.kwargs["kwargs"]["attempt"] == 3


def scheduling_values():
    return {
        "delivery_id": str(uuid4()),
        "provider_id": None,
        "channel": "email",
        "recipient": "owned@example.invalid",
        "title": "Owned title",
        "body": "Owned body",
        "body_html": None,
        "organization_id": str(uuid4()),
        "error": "timeout",
        "attempt": 1,
    }


def test_exhausted_attempt_does_not_schedule_an_extra_delivery(monkeypatch):
    enqueue = MagicMock()
    monkeypatch.setattr(retry.retry_notification_delivery, "apply_async", enqueue)
    retry.schedule_retry(**(scheduling_values() | {"attempt": 5, "max_retries": 5}))
    enqueue.assert_not_called()


def test_broker_failure_is_not_logged_as_a_scheduled_retry(monkeypatch, caplog):
    enqueue = MagicMock(side_effect=RuntimeError(CANARY))
    monkeypatch.setattr(retry.retry_notification_delivery, "apply_async", enqueue)
    caplog.set_level("INFO", logger="freesdn.tasks.notification_retry")
    retry.schedule_retry(**(scheduling_values() | {"error": CANARY}))
    assert "notification.delivery.retry_scheduled" not in caplog.text
    assert CANARY not in repr([r.__dict__ for r in caplog.records])


def test_successful_enqueue_keeps_the_next_attempt_and_delay(monkeypatch, caplog):
    enqueue = MagicMock()
    monkeypatch.setattr(retry.retry_notification_delivery, "apply_async", enqueue)
    caplog.set_level("INFO", logger="freesdn.tasks.notification_retry")
    retry.schedule_retry(**scheduling_values())
    assert enqueue.call_args.kwargs["kwargs"]["attempt"] == 2
    assert enqueue.call_args.kwargs["countdown"] == 120
    assert "notification.delivery.retry_scheduled" in caplog.text


@pytest.mark.asyncio
async def test_worker_reports_broker_rejection_without_claiming_reschedule(owned_retry, caplog):
    f = owned_retry
    f.runtime.send.return_value = DeliveryResult(
        False, NotificationChannel.EMAIL, DeliveryStatus.FAILED, error="timeout"
    )
    f.enqueue.side_effect = RuntimeError(CANARY)
    outcome = await retry._do_retry(**f.values)
    assert outcome["success"] is False and outcome["rescheduled"] is False
    assert f.row()["attempt"] == 2 and f.row()["status"] == "failed"
    assert CANARY not in repr([r.__dict__ for r in caplog.records])


@pytest.mark.asyncio
async def test_commit_failure_after_send_is_not_a_persisted_success(owned_retry, caplog):
    f = owned_retry
    before = f.row()
    f.faults["commit"] = True
    outcome = await retry._do_retry(**f.values)
    assert outcome["success"] is False
    f.runtime.send.assert_awaited_once()
    f.enqueue.assert_not_called()
    assert f.row() == before
    assert CANARY not in str(outcome) + repr([r.__dict__ for r in caplog.records])


@pytest.mark.asyncio
async def test_provider_exception_does_not_disclose_private_details(owned_retry, caplog):
    f = owned_retry
    f.runtime.send.side_effect = RuntimeError(CANARY)
    outcome = await retry._do_retry(**f.values)
    assert outcome["success"] is False
    assert CANARY not in str(outcome) + str(f.row()) + repr([r.__dict__ for r in caplog.records])


@pytest.mark.asyncio
async def test_provider_cancellation_propagates_without_advancing_attempt(owned_retry):
    f = owned_retry
    before = f.row()
    f.runtime.send.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await retry._do_retry(**f.values)
    assert f.row() == before
    f.enqueue.assert_not_called()


@pytest.mark.asyncio
async def test_provider_skip_remains_skipped_in_delivery_history(owned_retry):
    f = owned_retry
    f.runtime.send.return_value = DeliveryResult(
        True, NotificationChannel.EMAIL, DeliveryStatus.SKIPPED
    )
    outcome = await retry._do_retry(**f.values)
    assert outcome["success"] is True and f.row()["status"] == "skipped"
    f.enqueue.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["missing_provider", "permanent", "exhausted"])
async def test_final_failure_is_committed_without_an_extra_attempt(owned_retry, failure):
    f = owned_retry
    if failure == "missing_provider":
        f.connection.execute(NotificationProviderRecord.__table__.delete())
        f.connection.commit()
    else:
        f.runtime.send.return_value = DeliveryResult(
            False,
            NotificationChannel.EMAIL,
            DeliveryStatus.FAILED,
            error="forbidden" if failure == "permanent" else "timeout",
        )
    if failure == "exhausted":
        f.change(NotificationDelivery, f.delivery, attempt=4)
        f.values["attempt"] = 5
    outcome = await retry._do_retry(**f.values)
    assert outcome["success"] is False and f.row()["retry_dead_letter"] is True
    assert f.row()["attempt"] == f.values["attempt"]
    f.enqueue.assert_not_called()


@pytest.mark.asyncio
async def test_explicit_platform_retry_cannot_use_a_tenant_provider(owned_retry):
    f = owned_retry
    f.change(NotificationDelivery, f.delivery, organization_id=None)
    f.values["organization_id"] = None
    outcome = await retry._do_retry(**f.values)
    assert outcome["success"] is False
    f.runtime.send.assert_not_awaited()

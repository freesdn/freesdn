# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Delayed offline messages must describe a current tenant-owned transition."""

import asyncio
import inspect
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql

from app.services import notification_helpers
from app.services.notification import DeliveryResult, DeliveryStatus, NotificationChannel
from app.tasks import agents

CANARY = "owned-offline-private-transport-detail"


def outcome(success=True, status=DeliveryStatus.SENT):
    return DeliveryResult(success, NotificationChannel.EMAIL, status)


@pytest.fixture
def worker(monkeypatch):
    now = datetime.now(UTC)
    agent = SimpleNamespace(
        id=uuid4(),
        site_id=uuid4(),
        organization_id=uuid4(),
        name="Current agent name",
        notification_channels={"email": {"to": "current@example.invalid"}},
        last_heartbeat=now - timedelta(minutes=10),
        disconnected_at=now - timedelta(minutes=1),
    )
    lookup = MagicMock()
    lookup.one_or_none.return_value = (agent, agent.organization_id)
    update = SimpleNamespace(rowcount=1)
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    session.execute = AsyncMock(side_effect=[lookup, update])
    session.commit = AsyncMock()
    factory = MagicMock(return_value=session)
    send = AsyncMock(return_value=[outcome()])
    monkeypatch.setattr(agents, "AsyncSessionLocal", factory)
    monkeypatch.setattr(notification_helpers, "dispatch_notifications", send)
    args = {
        "agent_id": str(agent.id),
        "agent_name": "Obsolete queued name",
        "site_id": str(agent.site_id),
        "last_heartbeat_iso": agent.last_heartbeat.isoformat(),
        "stale_seconds": 999999999,
        "channels": {"webhook": {"url": "https://obsolete.example.invalid/private"}},
        "disconnected_at_iso": agent.disconnected_at.isoformat(),
    }

    def call(**changes):
        values = {**args, **changes}
        # The previous implementation had no epoch parameter. Execute its real
        # six-argument body for the before/after regression comparison.
        if (
            "disconnected_at_iso"
            not in inspect.signature(agents.notify_offline_agent.run).parameters
        ):
            values.pop("disconnected_at_iso")
        return agents.notify_offline_agent.run(**values)

    return SimpleNamespace(
        agent=agent,
        session=session,
        factory=factory,
        lookup=lookup,
        update=update,
        send=send,
        args=args,
        call=call,
    )


def test_worker_uses_current_scope_settings_and_content(worker):
    f = worker
    result = f.call()
    assert result == {"success": True, "delivered": 1}
    kwargs = f.send.await_args.kwargs
    assert kwargs["organization_id"] == f.agent.organization_id
    assert kwargs["channels_config"] == f.agent.notification_channels
    assert kwargs["title"] == "[FreeSDN] Agent OFFLINE: Current agent name"
    assert "Obsolete" not in kwargs["body"] and "999999999" not in kwargs["body"]
    assert str(f.agent.site_id) in kwargs["body"]
    f.session.commit.assert_awaited_once()


@pytest.mark.parametrize(
    "results",
    [
        [],
        [outcome(False, DeliveryStatus.FAILED)],
        [outcome(False, DeliveryStatus.BOUNCED)],
        [outcome(), outcome(False, DeliveryStatus.FAILED)],
        [outcome(True, DeliveryStatus.PENDING)],
        [outcome(True, DeliveryStatus.FAILED)],
        [outcome(False, DeliveryStatus.SENT)],
        [outcome(True, DeliveryStatus.SKIPPED)],
    ],
)
def test_non_delivery_never_marks_offline_alert_notified(worker, results):
    f = worker
    f.send.return_value = results
    response = f.call()
    assert response == {"success": False, "error": "offline_notification_not_delivered"}
    # Only the current-state read occurs: no success-marker UPDATE.
    assert f.session.execute.await_count == 1
    f.session.commit.assert_awaited_once()


@pytest.mark.parametrize(
    "results,delivered",
    [
        ([outcome(True, DeliveryStatus.DELIVERED)], 1),
        ([outcome(), outcome(True, DeliveryStatus.SKIPPED)], 1),
        ([outcome(), outcome()], 2),
    ],
)
def test_success_counts_only_sent_or_delivered_results(worker, results, delivered):
    worker.send.return_value = results
    assert worker.call() == {"success": True, "delivered": delivered}
    assert worker.session.execute.await_count == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("agent_id", "not-uuid"),
        ("site_id", "not-uuid"),
        ("last_heartbeat_iso", "bad"),
        ("last_heartbeat_iso", "2026-09-24T01:00:00"),
        ("disconnected_at_iso", "bad"),
        ("disconnected_at_iso", None),
        ("disconnected_at_iso", "2026-09-24T01:00:00"),
        ("last_heartbeat_iso", None),
    ],
)
def test_invalid_or_legacy_transition_is_refused_before_database_or_send(worker, field, value):
    assert worker.call(**{field: value}) == {
        "success": False,
        "error": "invalid_offline_transition",
    }
    worker.factory.assert_not_called()
    worker.send.assert_not_awaited()


def test_missing_or_no_longer_authorized_transition_does_not_send(worker):
    worker.lookup.one_or_none.return_value = None
    assert worker.call() == {"success": False, "error": "offline_transition_unavailable"}
    worker.send.assert_not_awaited()
    worker.session.commit.assert_not_awaited()


def test_disabled_current_channels_never_fall_back_to_queued_targets(worker):
    worker.agent.notification_channels = {}
    assert worker.call() == {"success": False, "error": "offline_channels_disabled"}
    worker.send.assert_not_awaited()
    worker.session.commit.assert_not_awaited()


def test_transition_changed_during_send_does_not_report_committed_success(worker):
    worker.update.rowcount = 0
    assert worker.call() == {"success": False, "error": "offline_transition_changed"}
    worker.send.assert_awaited_once()
    worker.session.commit.assert_awaited_once()


@pytest.mark.parametrize("stage", ["query", "send", "commit"])
def test_failures_have_safe_outcomes_and_no_private_traceback(worker, caplog, stage):
    target = {
        "query": worker.session.execute,
        "send": worker.send,
        "commit": worker.session.commit,
    }[stage]
    target.side_effect = RuntimeError(CANARY)
    result = worker.call()
    assert result == {"success": False, "error": "offline_notification_unavailable"}
    assert CANARY not in str(result) and CANARY not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


def test_cancellation_propagates_without_marking_notification(worker):
    worker.send.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        worker.call()
    worker.session.commit.assert_not_awaited()
    assert worker.session.execute.await_count == 1


def test_database_predicates_bind_epoch_and_tenant_lifecycle_on_read_and_mark(worker):
    assert worker.call()["success"]
    statements = [call.args[0] for call in worker.session.execute.await_args_list]
    assert len(statements) == 2
    for statement in statements:
        compiled = statement.compile(dialect=postgresql.dialect())
        sql = str(compiled)
        values = list(compiled.params.values())
        for text in [
            "remote_agents.deleted_at IS NULL",
            "remote_agents.offline_notified_at IS NULL",
            "remote_agents.is_enabled IS true",
            "sites.deleted_at IS NULL",
            "sites.is_active IS true",
            "organizations.deleted_at IS NULL",
            "organizations.is_active IS true",
        ]:
            assert text in sql
        for value in [
            worker.agent.id,
            worker.agent.site_id,
            "offline",
            worker.agent.last_heartbeat,
            worker.agent.disconnected_at,
        ]:
            assert value in values
    mark = str(statements[1].compile(dialect=postgresql.dialect()))
    assert "notification_channels =" in mark
    assert statements[1].get_execution_options()["synchronize_session"] is False


@pytest.mark.parametrize("broker_fails", [False, True])
def test_detector_queues_exact_committed_epoch_without_private_broker_errors(
    worker, monkeypatch, caplog, broker_fails
):
    f = worker
    f.agent.offline_threshold_seconds = 180
    f.agent.offline_notified_at = None
    f.agent.status = "online"
    response = MagicMock()
    response.scalars.return_value.all.return_value = [f.agent]
    f.session.execute.side_effect = None
    f.session.execute.return_value = response
    enqueued = []

    def enqueue(*, args):
        f.session.commit.assert_awaited_once()
        enqueued.append(args)
        if broker_fails:
            raise RuntimeError(CANARY)

    monkeypatch.setattr(agents.notify_offline_agent, "apply_async", enqueue)
    result = agents.cleanup_stale_agents.run()
    assert result["marked_offline"] == 1
    assert result["notifications_dispatched"] == (0 if broker_fails else 1)
    assert enqueued[0][-1] == f.agent.disconnected_at.isoformat()
    f.send.assert_not_awaited()
    assert CANARY not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)

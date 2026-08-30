# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
``agents.cleanup_stale`` must hand the offline alert to ``agents.notify_offline``.

``notify_offline_agent`` was written to fix "Audit MEDIUM #9" and says so in its
own docstring: cleanup_stale_agents "previously did all dispatches inline,
holding the periodic-task slot for as long as the slowest SMTP / Slack RTT. Push
the dispatch ... out to this task". The task was written, registered under
``agents.notify_offline``, and then nothing ever sent it -- ``grep -rn
notify_offline app/`` returned only its own decorator line. The inline
``await dispatch_notifications(...)`` it was extracted from was still what ran,
so the audit finding was open behind a green suite and a registered task.

The consequence was concrete: ``agents.cleanup_stale`` runs on beat every 2
minutes with ``soft_time_limit=120``, and it dispatched serially for every agent
that had just gone offline. One unreachable SMTP host or a hung Slack webhook
could consume the whole budget, and the offline detector stalled for the rest of
the fleet -- exactly when a site outage makes many agents go offline at once.

These tests execute the task body against a fake session rather than reading its
source, because a source assertion would pass on a version that imports the task
and never sends it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from app.tasks import agents as agents_tasks


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> Any:
        return SimpleNamespace(all=lambda: list(self._rows))


class _Session:
    """Just enough AsyncSession for cleanup_stale_agents, with an ordered log."""

    def __init__(self, rows: list[Any], log: list[str]) -> None:
        self._rows = rows
        self._log = log

    async def execute(self, *_a: Any, **_k: Any) -> _Result:
        return _Result(self._rows)

    async def commit(self) -> None:
        self._log.append("commit")

    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False


def _agent(
    *,
    stale_seconds: int = 600,
    channels: dict[str, Any] | None = None,
    notified_at: datetime | None = None,
    threshold: int = 180,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        name="edge-01",
        site_id=uuid4(),
        status="online",
        last_heartbeat=datetime.now(UTC) - timedelta(seconds=stale_seconds),
        offline_threshold_seconds=threshold,
        offline_notified_at=notified_at,
        notification_channels=channels if channels is not None else {"email": ["ops@x.test"]},
        disconnected_at=None,
    )


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch):
    """Patch the session factory, the enqueue, and the inline dispatch symbol.

    ``dispatch_notifications`` is patched on its home module: the pre-fix code
    did ``from app.services.notification_helpers import dispatch_notifications``
    INSIDE the task body, so the lookup happens at call time and this catches
    it. If it is ever called during cleanup_stale_agents, the extraction has
    been undone.
    """
    log: list[str] = []
    enqueued: list[list[Any]] = []
    inline_calls: list[Any] = []

    import app.services.notification_helpers as helpers

    async def _inline(*a: Any, **k: Any) -> None:
        inline_calls.append((a, k))

    monkeypatch.setattr(helpers, "dispatch_notifications", _inline)

    def _apply_async(*, args: list[Any], **_k: Any) -> Any:
        log.append("enqueue")
        enqueued.append(args)
        return SimpleNamespace(id="fake-task-id")

    monkeypatch.setattr(agents_tasks.notify_offline_agent, "apply_async", _apply_async)

    def _install(rows: list[Any]) -> None:
        monkeypatch.setattr(agents_tasks, "AsyncSessionLocal", lambda: _Session(rows, log))

    return SimpleNamespace(install=_install, log=log, enqueued=enqueued, inline_calls=inline_calls)


def test_offline_alert_is_enqueued_not_sent_inline(wired: Any) -> None:
    """The whole point of the extraction: no SMTP/Slack call from the beat slot.

    Mutation this catches: restore the inline
    ``await dispatch_notifications(...)`` in cleanup_stale_agents (i.e. the
    shipped behaviour before this fix) and ``inline_calls`` becomes non-empty
    while ``enqueued`` stays empty. Both halves fail.
    """
    agent = _agent()
    wired.install([agent])

    result = agents_tasks.cleanup_stale_agents.run()

    assert result["marked_offline"] == 1
    assert agent.status == "offline"
    assert wired.inline_calls == [], (
        "cleanup_stale_agents called dispatch_notifications itself. That is the "
        "inline behaviour agents.notify_offline was extracted to replace; it "
        "puts an SMTP/Slack round trip inside a soft_time_limit=120 beat task."
    )
    assert len(wired.enqueued) == 1, "the offline alert was neither sent nor queued"
    assert result["notifications_dispatched"] == 1


def test_enqueued_args_match_the_task_signature(wired: Any) -> None:
    """A positional-args mismatch would only surface as a worker-side TypeError.

    Mutation this catches: drop or reorder any argument in the apply_async
    args list -- the zip against notify_offline_agent's own parameter names
    fails, instead of the task blowing up in a worker where nothing looks at
    the result.
    """
    import inspect

    agent = _agent(stale_seconds=600, threshold=180)
    wired.install([agent])
    agents_tasks.cleanup_stale_agents.run()

    (args,) = wired.enqueued
    params = list(inspect.signature(agents_tasks.notify_offline_agent.run).parameters)
    assert len(args) == len(params), f"expected args for {params}, got {args}"

    sent = dict(zip(params, args, strict=True))
    assert sent["agent_id"] == str(agent.id)
    assert sent["agent_name"] == agent.name
    assert sent["site_id"] == str(agent.site_id)
    assert sent["last_heartbeat_iso"] == agent.last_heartbeat.isoformat()
    assert sent["stale_seconds"] >= 600
    assert sent["channels"] == agent.notification_channels
    # Everything must survive JSON serialization -- Celery's task_serializer is
    # "json", so a raw UUID here would raise at publish time in production and
    # never in a test that only inspected the call.
    import json

    json.dumps(args)


def test_enqueue_happens_after_the_commit(wired: Any) -> None:
    """notify_offline_agent UPDATEs offline_notified_at on the row we just wrote.

    Mutation this catches: move the apply_async loop back inside the scan (i.e.
    before ``await session.commit()``), and the worker can read/UPDATE the row
    while this transaction still holds the uncommitted status flip.
    """
    wired.install([_agent()])
    agents_tasks.cleanup_stale_agents.run()

    assert wired.log == ["commit", "enqueue"], f"order was {wired.log}"


def test_already_notified_agent_is_not_alerted_again(wired: Any) -> None:
    """Dedup on offline_notified_at survives the move to a queued dispatch."""
    wired.install([_agent(notified_at=datetime.now(UTC) - timedelta(hours=1))])

    result = agents_tasks.cleanup_stale_agents.run()

    assert result["marked_offline"] == 1
    assert wired.enqueued == []
    assert result["notifications_dispatched"] == 0


def test_agent_inside_its_threshold_is_untouched(wired: Any) -> None:
    """A live agent must not be flipped offline or alerted on."""
    agent = _agent(stale_seconds=30, threshold=180)
    wired.install([agent])

    result = agents_tasks.cleanup_stale_agents.run()

    assert result["marked_offline"] == 0
    assert agent.status == "online"
    assert wired.enqueued == []


def test_broker_failure_does_not_lose_the_offline_transition(
    wired: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreachable broker must not take the offline detector down with it.

    Mutation this catches: drop the try/except around apply_async. The status
    flip is already committed at that point, so an escaping exception would
    turn a broker blip into a task failure that reports nothing about the
    agents it did mark offline.
    """

    def _boom(**_k: Any) -> Any:
        raise OSError("broker unreachable")

    monkeypatch.setattr(agents_tasks.notify_offline_agent, "apply_async", _boom)
    agent = _agent()
    wired.install([agent])

    result = agents_tasks.cleanup_stale_agents.run()

    assert result["success"] is True
    assert result["marked_offline"] == 1
    assert result["notifications_dispatched"] == 0
    assert agent.status == "offline"

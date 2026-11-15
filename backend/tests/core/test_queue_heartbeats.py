# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Every Celery queue has its own heartbeat, on real Valkey.

Evidence (architecture review 2026-11, topic 8): one ``worker.heartbeat``
routed to ``default`` stood in for two worker tiers. In pro/max the I/O worker
owns discovery, sync and metrics (every device poller); if it wedged, all
polling stopped and health stayed green.
"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace

import pytest

from app.core import queue_heartbeat as qh

_SCRATCH_DB = 11


@pytest.fixture
def valkey(monkeypatch):
    from app.core.redis_client import get_sync_redis

    client = get_sync_redis(db=_SCRATCH_DB, decode_responses=True)

    def wipe():
        for pattern in (qh.HEARTBEAT_PREFIX + "*", qh.CONSUMER_PREFIX + "*"):
            for key in client.scan_iter(match=pattern):
                client.delete(key)

    wipe()
    monkeypatch.setattr(qh, "_redis", lambda: client)
    monkeypatch.setattr(
        qh, "_worker", {"hostname": None, "queues": [], "since": None, "written": 0.0}
    )
    try:
        yield client
    finally:
        wipe()
        client.close()


NO_DEPTH = {"default": 0, "priority": 0, "discovery": 0, "sync": 0, "metrics": 0}


def _running_since(client, hostname: str, queues: list[str], *, minutes: float = 60) -> None:
    """A worker that started ``minutes`` ago and is still refreshing its registration."""
    now = time.time()
    record = {"hostname": hostname, "queues": queues, "since": now - minutes * 60, "seen": now}
    client.set(qh.CONSUMER_PREFIX + hostname, json.dumps(record), ex=qh.REGISTRATION_TTL)


def _pro_tier(client, *, io_heartbeat_age: float, now: float) -> None:
    """worker: default+priority; worker-io: discovery+sync+metrics."""
    _running_since(client, "worker@h", ["default", "priority"])
    _running_since(client, "worker-io@h", ["discovery", "metrics", "sync"])
    for q in ("default", "priority"):
        client.set(qh.HEARTBEAT_PREFIX + q, repr(now - 5))
    for q in ("discovery", "sync", "metrics"):
        client.set(qh.HEARTBEAT_PREFIX + q, repr(now - io_heartbeat_age))


def test_a_wedged_io_worker_shows_as_stalled_queues(valkey) -> None:
    """Fails on the old health check: it only read the default queue's heartbeat."""
    now = time.time()
    _pro_tier(valkey, io_heartbeat_age=900, now=now)
    status = qh.queue_status(client=valkey, depths=NO_DEPTH, now=now)
    assert {q: s["state"] for q, s in status.items()} == {
        "default": "ok",
        "priority": "ok",
        "discovery": "stalled",
        "sync": "stalled",
        "metrics": "stalled",
    }
    assert status["sync"]["last_heartbeat_age_seconds"] == pytest.approx(900, abs=1)


def test_a_healthy_tier_is_all_ok(valkey) -> None:
    now = time.time()
    _pro_tier(valkey, io_heartbeat_age=10, now=now)
    status = qh.queue_status(client=valkey, depths=NO_DEPTH, now=now)
    assert {s["state"] for s in status.values()} == {"ok"}
    assert status["sync"]["consumers"] == 1


def test_a_queue_this_tier_does_not_run_is_not_reported_stalled(valkey) -> None:
    now = time.time()
    _running_since(valkey, "worker@h", ["default", "discovery", "sync", "metrics"])
    for q in ("default", "discovery", "sync", "metrics"):
        valkey.set(qh.HEARTBEAT_PREFIX + q, repr(now - 5))
    status = qh.queue_status(client=valkey, depths=NO_DEPTH, now=now)
    assert status["priority"]["state"] == "not_consumed"
    assert "stalled" not in {s["state"] for s in status.values()}


def test_tasks_waiting_in_a_queue_nobody_consumes_are_a_stall(valkey) -> None:
    now = time.time()
    _running_since(valkey, "worker@h", ["default", "priority"])
    valkey.set(qh.HEARTBEAT_PREFIX + "default", repr(now - 5))
    valkey.set(qh.HEARTBEAT_PREFIX + "priority", repr(now - 5))
    # The io-worker profile is not running, but beat keeps queueing sync work.
    status = qh.queue_status(client=valkey, depths={**NO_DEPTH, "sync": 42}, now=now)
    assert status["sync"]["state"] == "stalled" and status["sync"]["depth"] == 42
    assert status["discovery"]["state"] == "not_consumed"


def test_a_worker_that_just_started_is_starting_not_stalled(valkey) -> None:
    qh.register_consumer("worker@h", ["default"], client=valkey)
    status = qh.queue_status(client=valkey, depths=NO_DEPTH, now=time.time())
    assert status["default"]["state"] == "starting"


def test_the_dispatcher_sends_heartbeats_only_to_consumed_queues(valkey, monkeypatch) -> None:
    from app.core import celery_app as celery_module

    sent: list[tuple] = []
    monkeypatch.setattr(
        celery_module.queue_heartbeat,
        "apply_async",
        lambda args, queue, expires: sent.append((args[0], queue, expires)),
    )
    qh.register_consumer("worker@h", ["default", "priority"], client=valkey)
    assert celery_module.dispatch_queue_heartbeats() == 2
    assert sorted((a, q) for a, q, _ in sent) == [("default", "default"), ("priority", "priority")]
    assert all(e < 30 * 3 for *_, e in sent)


def test_the_heartbeat_task_records_when_it_ran(valkey) -> None:
    from app.core import celery_app as celery_module

    before = time.time()
    celery_module.queue_heartbeat("sync")
    assert float(valkey.get(qh.HEARTBEAT_PREFIX + "sync")) >= before


def test_a_worker_registers_its_queues_when_ready_and_leaves_on_shutdown(valkey) -> None:
    from celery.signals import heartbeat_sent, worker_ready, worker_shutdown

    from app.core import celery_app as celery_module

    # The receivers are connected to Celery's signals (called directly here so
    # the module-loading worker_ready receiver does not run in the test).
    assert worker_ready.has_listeners() and heartbeat_sent.has_listeners()
    assert celery_module.register_queue_consumer in [r() for _, r in worker_ready.receivers]
    assert celery_module.on_worker_shutdown in [r() for _, r in worker_shutdown.receivers]
    consumer = SimpleNamespace(
        hostname="worker-io@test",
        task_consumer=SimpleNamespace(
            queues=[SimpleNamespace(name="discovery"), SimpleNamespace(name="sync")]
        ),
    )
    celery_module.register_queue_consumer(sender=consumer)
    assert qh.consumed_queues(client=valkey) == {"discovery", "sync"}
    celery_module.on_worker_shutdown(consumer)
    assert qh.consumed_queues(client=valkey) == set()


async def test_health_detail_reports_the_stalled_queues(valkey, monkeypatch) -> None:
    from app.api.v1.endpoints import health

    now = time.time()
    _pro_tier(valkey, io_heartbeat_age=900, now=now)
    import app.core.metrics as metrics

    monkeypatch.setattr(metrics, "celery_queue_lengths", lambda: NO_DEPTH)
    component = await health._celery_queues_component()
    assert component.status == health.HealthStatus.DEGRADED
    assert component.details["stalled"] == ["discovery", "metrics", "sync"]


def test_prometheus_exposes_the_stall(valkey, monkeypatch) -> None:
    import app.core.metrics as metrics

    now = time.time()
    _pro_tier(valkey, io_heartbeat_age=900, now=now)
    monkeypatch.setattr(metrics, "celery_queue_lengths", lambda: NO_DEPTH)
    metrics.refresh_celery_queue_heartbeats()
    assert metrics.celery_queue_stalled.labels(queue="sync")._value.get() == 1
    assert metrics.celery_queue_stalled.labels(queue="default")._value.get() == 0
    assert metrics.celery_queue_consumers.labels(queue="sync")._value.get() == 1


def test_alerts_yml_alerts_on_a_stalled_queue() -> None:
    from pathlib import Path

    rules = Path(__file__).resolve().parents[3] / "observability" / "prometheus" / "alerts.yml"
    if not rules.exists():
        pytest.skip("observability/ not reachable (backend-only mount)")
    assert "freesdn_celery_queue_stalled == 1" in rules.read_text(encoding="utf-8")


def test_registration_is_refreshed_from_the_event_heartbeat_at_most_every_30s(valkey) -> None:
    qh.register_consumer("worker@h", ["default"], client=valkey)
    first = valkey.get(qh.CONSUMER_PREFIX + "worker@h")
    qh.refresh_registration()  # within 30 s: no write
    assert valkey.get(qh.CONSUMER_PREFIX + "worker@h") == first
    qh._worker["written"] -= 31
    qh.refresh_registration()
    assert valkey.get(qh.CONSUMER_PREFIX + "worker@h") != first


def test_status_runs_against_a_real_broker_read(valkey) -> None:
    """No depth override: the real broker LLEN path must not break the status."""
    status = asyncio.run(asyncio.to_thread(qh.queue_status, client=valkey))
    assert set(status) == {"default", "priority", "discovery", "sync", "metrics"}

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Webhooks are at-least-once: a lost task or a crash produces a duplicate, never a loss.

Every delivery path carries one stable event id (``X-Webhook-Event-Id`` equals
the body's ``id``) across the first POST, its retries, a sweeper requeue and a
replay. What these tests pin, on real PostgreSQL with the HTTP client and the
broker hop replaced:

* an event delivery's row is committed before its POST, so a worker that dies
  between the POST and recording its outcome leaves a pending row, and the
  sweeper sends that event again with the same id. Before, the row and the
  outcome rode on one commit at the end of the task and vanished with it;
* a database error inside ``deliver_event`` is retried instead of acknowledged,
  and the retry skips the webhooks already recorded;
* a duplicate retry message does not post an event that was already delivered;
* a requeued delivery keeps its attempt budget instead of starting over;
* "Replay all" commits before it queues, so its first replay cannot run before
  its row exists;
* a claimed event the broker refuses is reported and its claim released,
  instead of vanishing silently with the claim held for an hour.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, select, update

from app.core.config import settings
from app.db.session import CelerySessionLocal
from app.models.core import Organization
from app.models.webhooks import DeliveryStatus, Webhook, WebhookDeadLetter, WebhookDelivery
from app.services import webhooks as webhook_service
from app.services.webhooks import PersistentWebhookService
from app.tasks import webhooks as webhook_tasks

HOST = "198.51.100.7"


class _WorkerDied(BaseException):
    """Stands in for SIGKILL: not an Exception, so nothing in the path catches it."""


class _Receiver:
    def __init__(self) -> None:
        self.posts: list[dict] = []
        self.status = 200
        self.die_after_send = False

    async def __call__(self, method, url, *, content, headers, **_kw):
        self.posts.append({"headers": dict(headers), "body": content})
        if self.die_after_send:
            self.die_after_send = False
            raise _WorkerDied()
        return SimpleNamespace(status_code=self.status)


@pytest.fixture
def receiver(monkeypatch):
    rx = _Receiver()
    monkeypatch.setattr("app.core.security_utils.safe_http_request", rx)
    return rx


@pytest.fixture
def queued(monkeypatch):
    """Retry messages, recorded instead of sent."""
    sent: list[str] = []
    monkeypatch.setattr(
        webhook_tasks.retry_webhook_delivery,
        "apply_async",
        lambda args, **_kw: sent.append(args[0]),
    )
    return sent


def _in_thread(coro_fn):
    """Run a coroutine on its own loop in a worker thread, from sync code."""
    with ThreadPoolExecutor(1) as pool:
        return pool.submit(lambda: asyncio.run(coro_fn())).result()


async def _make_webhook(org):
    async with CelerySessionLocal() as db:
        wh = await PersistentWebhookService.create_webhook(
            db,
            {
                "name": "n8n",
                "url": f"https://{HOST}/hook",
                "event_types": [],
                "organization_id": org,
            },
        )
        await db.commit()
        return wh.id


@pytest_asyncio.fixture
async def webhook(monkeypatch):
    monkeypatch.setattr(settings, "WEBHOOK_ALLOWED_HOSTS", HOST)
    org = uuid4()
    async with CelerySessionLocal() as db:
        db.add(Organization(id=org, name="At-least-once", slug="alo-" + org.hex))
        await db.commit()
    webhook_id = await _make_webhook(org)
    try:
        yield SimpleNamespace(id=webhook_id, org=org)
    finally:
        async with CelerySessionLocal() as db:
            await db.execute(delete(Webhook).where(Webhook.organization_id == org))
            await db.execute(delete(Organization).where(Organization.id == org))
            await db.commit()


def _envelope(org) -> dict:
    return {
        "id": str(uuid4()),
        "event": "device.status.changed",
        "organization_id": str(org),
        "data": {},
    }


async def _rows(webhook_id) -> list[WebhookDelivery]:
    async with CelerySessionLocal() as db:
        return list(
            (
                await db.execute(
                    select(WebhookDelivery)
                    .where(WebhookDelivery.webhook_id == webhook_id)
                    .order_by(WebhookDelivery.created_at)
                )
            )
            .scalars()
            .all()
        )


async def _dispatch(envelope, org) -> int:
    async with CelerySessionLocal() as db:
        n = await PersistentWebhookService.dispatch_event(
            db, envelope["event"], envelope, event_id=envelope["id"], organization_id=org
        )
        await db.commit()
        return n


async def _age(delivery_id) -> None:
    async with CelerySessionLocal() as db:
        await db.execute(
            update(WebhookDelivery)
            .where(WebhookDelivery.id == delivery_id)
            .values(
                updated_at=datetime.now(UTC)
                - timedelta(seconds=webhook_service.STALLED_DELIVERY_SECONDS + 60)
            )
        )
        await db.commit()


def _run(task, *args):
    """Run a Celery task body the way a worker does (its own event loop, in a thread)."""
    return asyncio.to_thread(lambda: task.apply(args=list(args)))


async def test_a_worker_that_dies_after_the_post_leaves_a_row_the_sweeper_resends(
    webhook, receiver, queued
):
    envelope = _envelope(webhook.org)
    receiver.die_after_send = True
    with pytest.raises(_WorkerDied):
        await _dispatch(envelope, webhook.org)

    (row,) = await _rows(webhook.id)
    assert row.status == DeliveryStatus.PENDING
    assert row.event_id == envelope["id"]

    # Not yet stalled: the sweeper leaves a delivery that may still be in flight.
    (await _run(webhook_tasks.requeue_stalled_deliveries)).get()
    assert str(row.id) not in queued
    await _age(row.id)
    (await _run(webhook_tasks.requeue_stalled_deliveries)).get()
    assert queued.count(str(row.id)) == 1

    await _run(webhook_tasks.retry_webhook_delivery, str(row.id))
    (row,) = await _rows(webhook.id)
    assert row.status == DeliveryStatus.DELIVERED

    # Sent twice (the receiver may have processed the first), always the same id.
    assert len(receiver.posts) == 2
    assert {p["headers"]["X-Webhook-Event-Id"] for p in receiver.posts} == {envelope["id"]}


async def test_a_database_error_in_deliver_event_is_retried_not_dropped(
    webhook, receiver, queued, monkeypatch
):
    """Two webhooks; recording the second one fails once, mid-task."""
    second = await _make_webhook(webhook.org)
    real_circuit_open = PersistentWebhookService._circuit_open
    blips = {"left": 1}

    async def _circuit_open(session, webhook_id):
        if webhook_id == second and blips["left"]:
            blips["left"] -= 1
            raise ConnectionResetError("database connection lost")
        return await real_circuit_open(session, webhook_id)

    monkeypatch.setattr(PersistentWebhookService, "_circuit_open", staticmethod(_circuit_open))
    envelope = _envelope(webhook.org)

    # Eager apply: an autoretry re-runs the task in place.
    await _run(webhook_tasks.deliver_event, envelope)

    assert blips["left"] == 0, "the injected failure never happened"
    for webhook_id in (webhook.id, second):
        rows = await _rows(webhook_id)
        assert [(r.status, r.event_id) for r in rows] == [
            (DeliveryStatus.DELIVERED, envelope["id"])
        ], webhook_id
    # Each webhook got the event exactly once: the retry skipped the one
    # already recorded instead of posting it again.
    assert len(receiver.posts) == 2


async def test_a_duplicate_retry_message_does_not_post_a_delivered_event(webhook, receiver, queued):
    envelope = _envelope(webhook.org)
    receiver.status = 503
    await _dispatch(envelope, webhook.org)
    (row,) = await _rows(webhook.id)
    assert row.status == DeliveryStatus.RETRYING and queued == [str(row.id)]

    receiver.status = 200
    await _run(webhook_tasks.retry_webhook_delivery, str(row.id))
    await _run(webhook_tasks.retry_webhook_delivery, str(row.id))  # the duplicate

    assert len(receiver.posts) == 2  # the first 503, then one delivered retry
    (row,) = await _rows(webhook.id)
    assert row.status == DeliveryStatus.DELIVERED and row.attempt_number == 2


async def test_a_requeued_delivery_keeps_its_attempt_budget(webhook, receiver, queued):
    envelope = _envelope(webhook.org)
    receiver.status = 503
    await _dispatch(envelope, webhook.org)
    (row,) = await _rows(webhook.id)
    async with CelerySessionLocal() as db:
        await db.execute(
            update(WebhookDelivery)
            .where(WebhookDelivery.id == row.id)
            .values(attempt_number=webhook_tasks.MAX_ATTEMPTS - 1)
        )
        await db.commit()

    # A fresh message (request.retries == 0), as the sweeper sends.
    await _run(webhook_tasks.retry_webhook_delivery, str(row.id))

    (row,) = await _rows(webhook.id)
    assert row.attempt_number == webhook_tasks.MAX_ATTEMPTS
    assert row.status == DeliveryStatus.FAILED
    async with CelerySessionLocal() as db:
        dead = (
            await db.execute(
                select(WebhookDeadLetter).where(WebhookDeadLetter.delivery_id == row.id)
            )
        ).scalar_one()
    assert dead.attempt_count == webhook_tasks.MAX_ATTEMPTS


async def test_replay_all_commits_before_it_queues(webhook, receiver, monkeypatch):
    from app.api.v1.endpoints import webhooks as endpoint

    async with CelerySessionLocal() as db:
        wh = await db.get(Webhook, webhook.id)
        payload = {"id": "evt-replayed", "event": "alert.fired", "data": {}}
        await PersistentWebhookService._dead_letter_unsent(
            db, wh, "alert.fired", payload, "evt-replayed"
        )
        await db.commit()

    seen_committed: list[bool] = []

    def _apply_async(args, **_kw):
        # What a worker that picked the task up immediately would find.
        async def _look():
            async with CelerySessionLocal() as db:
                return await db.get(WebhookDelivery, args[0]) is not None

        seen_committed.append(_in_thread(_look))

    monkeypatch.setattr(webhook_tasks.retry_webhook_delivery, "apply_async", _apply_async)
    user = SimpleNamespace(id=None, organization_id=webhook.org, role="admin", is_superuser=True)
    monkeypatch.setattr(endpoint, "require_admin", lambda _u: None)
    monkeypatch.setattr(endpoint, "_org_id", lambda _u: webhook.org)

    async with CelerySessionLocal() as db:
        result = await endpoint.replay_all_dead_letters(webhook.id, session=db, user=user)

    assert result == {"status": "queued", "count": 1}
    assert seen_committed == [True]
    replays = [
        r for r in await _rows(webhook.id) if r.attempt_number == 0 and r.status == "pending"
    ]
    assert [r.event_id for r in replays] == ["evt-replayed"]


def test_a_claimed_event_the_broker_refuses_is_reported_and_released(monkeypatch, caplog):
    from app.services import webhook_events

    class _Redis:
        def __init__(self) -> None:
            self.keys: dict[str, str] = {}

        def set(self, key, value, nx, ex):
            if key in self.keys:
                return None
            self.keys[key] = value
            return True

        def delete(self, key):
            self.keys.pop(key, None)

    redis = _Redis()
    forwarder = webhook_events.WebhookEventForwarder(bus=object())
    forwarder._redis = redis
    calls: list[dict] = []

    def _refuse(args, **_kw):
        calls.append(args[0])
        raise ConnectionError("broker down")

    monkeypatch.setattr("app.tasks.webhooks.deliver_event.apply_async", _refuse)
    monkeypatch.setattr(webhook_events, "_ENQUEUE_BACKOFF_SECONDS", 0)
    envelope = {"id": "evt-1", "event": "alert.fired"}

    with caplog.at_level("ERROR", logger="app.services.webhook_events"):
        forwarder._claim_and_enqueue(envelope)

    assert len(calls) == webhook_events._ENQUEUE_ATTEMPTS
    assert redis.keys == {}, "the claim must be released"
    assert forwarder.enqueue_failed == 1 and forwarder.enqueued == 0
    assert "NOT queued" in caplog.text and "evt-1" in caplog.text

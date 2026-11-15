# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A real bus event reaches a configured webhook as a signed HTTP request.

``PersistentWebhookService.dispatch_event`` had no caller. Every webhook, every
n8n trigger and every generic integration received only the deliveries an
operator triggered with "Test"; a device going offline or an alert firing never
left the building.

The end-to-end test here runs the whole path with nothing faked but the Celery
broker hop (eager mode): publish on an EventBus -> forwarder subscription map
from the real database -> Redis claim on real Valkey -> ``deliver_event`` task ->
org-scoped lookup -> SSRF guard with the deploy owner's allow-list -> signed
POST to an HTTP server listening on this host's LAN address -> delivery row.

The receiver deliberately listens on a private, non-loopback address: that is
where a self-hosted operator's n8n lives, and it is unreachable unless the host
is on ``WEBHOOK_ALLOWED_HOSTS``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.core.celery_app import celery_app
from app.core.config import settings
from app.core.events import Event, EventBus, EventCategory
from app.core.security_utils import sign_webhook_payload
from app.db.session import CelerySessionLocal
from app.models.core import Organization
from app.models.webhooks import (
    DeliveryStatus,
    Webhook,
    WebhookDeadLetter,
    WebhookDelivery,
)
from app.services.webhook_events import WebhookEventForwarder, webhook_wants
from app.services.webhooks import CIRCUIT_FAILURE_THRESHOLD, PersistentWebhookService

SECRET = "receiver-shared-secret"


# --------------------------------------------------------------------------
# Subscription matching (pure)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("patterns", "event_type", "wanted"),
    [
        ([], "device.status.changed", True),
        ([], "pbx.sync.progress", False),  # "all" skips progress ticks
        (["*"], "pbx.sync.progress", True),
        (["device.status.changed"], "device.status.changed", True),
        (["device.status.changed"], "device.discovered", False),
        # The n8n node offers device.* as "Any Device Event".
        (["device.*"], "device.status.changed", True),
        (["device.#"], "device.discovered", True),
        (["device.*"], "devices.other", False),
        (["alert.fired"], "alert.resolved", False),
        ([], "webhook.test", False),  # never loop deliveries into deliveries
    ],
)
def test_subscription_matching(patterns, event_type, wanted):
    assert webhook_wants(patterns, event_type) is wanted


# --------------------------------------------------------------------------
# A receiver on this host's LAN address
# --------------------------------------------------------------------------


def _lan_ip() -> str | None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect sends nothing; it only selects the outbound interface.
        probe.connect(("192.0.2.1", 9))
        ip = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        return None
    return ip


class _Receiver:
    def __init__(self, host: str) -> None:
        self.requests: list[SimpleNamespace] = []
        self.status = 200
        received = self.requests
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length") or 0)
                received.append(
                    SimpleNamespace(
                        path=self.path,
                        headers={k.lower(): v for k, v in self.headers.items()},
                        body=self.rfile.read(length),
                    )
                )
                self.send_response(outer.status)
                self.end_headers()

            def log_message(self, *_args):
                return

        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.url = f"http://{host}:{self.server.server_address[1]}/hook"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def lan_receiver():
    ip = _lan_ip()
    if ip is None:
        pytest.skip("no non-loopback IPv4 interface to host the receiver on")
    receiver = _Receiver(ip)
    receiver.ip = ip
    try:
        yield receiver
    finally:
        receiver.close()


@pytest.fixture
def eager_celery():
    previous = {k: celery_app.conf.get(k) for k in ("task_always_eager", "task_eager_propagates")}
    celery_app.conf.update(task_always_eager=True, task_eager_propagates=True)
    yield
    celery_app.conf.update(**previous)


@pytest_asyncio.fixture
async def orgs():
    ids = [uuid4(), uuid4()]
    async with CelerySessionLocal() as db:
        db.add_all([Organization(id=i, name="Webhook fixture", slug="wh-" + i.hex) for i in ids])
        await db.commit()
    try:
        yield ids
    finally:
        async with CelerySessionLocal() as db:
            await db.execute(delete(Webhook).where(Webhook.organization_id.in_(ids)))
            await db.execute(delete(Organization).where(Organization.id.in_(ids)))
            await db.commit()
        from app.db.session import engine

        await engine.dispose()


async def _create_webhook(org, url, event_types, **extra):
    async with CelerySessionLocal() as db:
        wh = await PersistentWebhookService.create_webhook(
            db,
            {
                "name": "n8n",
                "url": url,
                "event_types": event_types,
                "secret": SECRET,
                "organization_id": org,
                **extra,
            },
        )
        await db.commit()
        return wh.id


async def _deliveries(webhook_id):
    async with CelerySessionLocal() as db:
        return list(
            (
                await db.execute(
                    select(WebhookDelivery).where(WebhookDelivery.webhook_id == webhook_id)
                )
            )
            .scalars()
            .all()
        )


async def _wait_for(predicate, timeout=10.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return predicate()


def _event(org, event_type="device.status.changed", **payload) -> Event:
    return Event(
        event_type=event_type,
        category=EventCategory.DEVICE,
        organization_id=str(org),
        payload={"device_id": str(uuid4()), "status": "offline", **payload},
    )


# --------------------------------------------------------------------------
# End to end
# --------------------------------------------------------------------------


async def test_a_published_event_is_posted_signed_to_the_webhook(
    orgs, lan_receiver, eager_celery, monkeypatch
):
    org, other_org = orgs
    monkeypatch.setattr(settings, "WEBHOOK_ALLOWED_HOSTS", lan_receiver.ip)
    webhook_id = await _create_webhook(org, lan_receiver.url, ["device.status.changed"])

    bus = EventBus()
    forwarder = WebhookEventForwarder(bus)
    await forwarder.start()
    try:
        event = _event(org)
        await bus.publish(event)
        assert await _wait_for(lambda: len(lan_receiver.requests) == 1), "no delivery arrived"

        # A second API worker sees the same event over pub/sub: claimed, so no repeat.
        await bus.publish(event)
        # Another tenant's event and an unsubscribed event type go nowhere.
        await bus.publish(_event(other_org))
        await bus.publish(_event(org, event_type="device.discovered"))
        await asyncio.sleep(0.5)
    finally:
        await forwarder.stop()

    assert len(lan_receiver.requests) == 1
    request = lan_receiver.requests[0]
    assert request.path == "/hook"
    assert request.headers["x-webhook-event"] == "device.status.changed"
    assert request.headers["x-webhook-event-id"] == event.id
    timestamp = int(request.headers["x-webhook-timestamp"])
    assert request.headers["x-webhook-signature"] == sign_webhook_payload(
        SECRET, request.body, timestamp
    )
    body = json.loads(request.body)
    assert body["event"] == "device.status.changed"
    assert body["id"] == event.id
    assert body["organization_id"] == str(org)
    assert body["data"]["status"] == "offline"

    rows = await _deliveries(webhook_id)
    assert [(r.status, r.response_code, r.event_id) for r in rows] == [
        (DeliveryStatus.DELIVERED, 200, event.id)
    ]


async def test_a_lan_receiver_is_refused_unless_the_owner_allowed_it(orgs, lan_receiver):
    org, _ = orgs
    if not ipaddress.ip_address(lan_receiver.ip).is_private:
        pytest.skip("this host's address is public; nothing private to refuse")
    with pytest.raises(ValueError, match="SSRF"):
        await _create_webhook(org, lan_receiver.url, [])


async def test_a_failing_endpoint_is_paused_and_events_land_in_the_dead_letter_queue(
    orgs, monkeypatch
):
    org, _ = orgs
    monkeypatch.setattr(settings, "WEBHOOK_ALLOWED_HOSTS", "198.51.100.7")
    webhook_id = await _create_webhook(org, "https://198.51.100.7/hook", [])

    now = datetime.now(UTC)
    async with CelerySessionLocal() as db:
        for i in range(CIRCUIT_FAILURE_THRESHOLD):
            db.add(
                WebhookDelivery(
                    webhook_id=webhook_id,
                    event_id=str(uuid4()),
                    event_type="device.status.changed",
                    status=DeliveryStatus.FAILED,
                    sent_at=now - timedelta(seconds=10 + i),
                    error_message="HTTP 503",
                )
            )
        await db.commit()

    async def _must_not_send(*_a, **_kw):
        raise AssertionError("a paused endpoint must not be contacted")

    monkeypatch.setattr("app.core.security_utils.safe_http_request", _must_not_send)

    event_id = str(uuid4())
    async with CelerySessionLocal() as db:
        count = await PersistentWebhookService.dispatch_event(
            db,
            "device.status.changed",
            {"event": "device.status.changed", "data": {}},
            event_id=event_id,
            organization_id=org,
        )
        await db.commit()
    assert count == 1

    async with CelerySessionLocal() as db:
        dead = (
            await db.execute(
                select(WebhookDeadLetter).where(WebhookDeadLetter.webhook_id == webhook_id)
            )
        ).scalar_one()
        delivery = await db.get(WebhookDelivery, dead.delivery_id)
    assert delivery.event_id == event_id
    assert delivery.status == DeliveryStatus.FAILED
    assert delivery.sent_at is None
    assert "paused" in (dead.failure_reason or "")


async def test_an_event_without_an_organization_reaches_no_webhook(orgs, monkeypatch):
    org, _ = orgs
    monkeypatch.setattr(settings, "WEBHOOK_ALLOWED_HOSTS", "198.51.100.7")
    await _create_webhook(org, "https://198.51.100.7/hook", [], enabled=True)
    async with CelerySessionLocal() as db:
        count = await PersistentWebhookService.dispatch_event(
            db, "device.status.changed", {}, event_id=str(uuid4()), organization_id=None
        )
    assert count == 0


# --------------------------------------------------------------------------
# At-least-once: one stable event id in header and body, across replays
# --------------------------------------------------------------------------


async def test_a_test_delivery_carries_the_same_event_id_in_header_and_body(
    orgs, lan_receiver, monkeypatch
):
    org, _ = orgs
    monkeypatch.setattr(settings, "WEBHOOK_ALLOWED_HOSTS", lan_receiver.ip)
    webhook_id = await _create_webhook(org, lan_receiver.url, [])
    async with CelerySessionLocal() as db:
        result = await PersistentWebhookService.test_webhook(db, webhook_id)
        await db.commit()

    assert result["status"] == DeliveryStatus.DELIVERED, result
    request = lan_receiver.requests[0]
    assert json.loads(request.body)["id"] == request.headers["x-webhook-event-id"]


async def test_a_dead_letter_replay_keeps_the_original_event_id(orgs, monkeypatch):
    from app.api.v1.endpoints.webhooks import _replay_event_id

    org, _ = orgs
    monkeypatch.setattr(settings, "WEBHOOK_ALLOWED_HOSTS", "198.51.100.7")
    webhook_id = await _create_webhook(org, "https://198.51.100.7/hook", [])
    async with CelerySessionLocal() as db:
        wh = await db.get(Webhook, webhook_id)
        with_id = {"id": "evt-from-the-body", "event": "alert.fired", "data": {}}
        await PersistentWebhookService._dead_letter_unsent(
            db, wh, "alert.fired", with_id, "evt-from-the-body"
        )
        await PersistentWebhookService._dead_letter_unsent(
            db, wh, "alert.fired", {"event": "alert.fired"}, "evt-only-on-the-delivery"
        )
        await db.commit()
        dead = (
            (
                await db.execute(
                    select(WebhookDeadLetter).where(WebhookDeadLetter.webhook_id == webhook_id)
                )
            )
            .scalars()
            .all()
        )
        replayed = {await _replay_event_id(db, entry) for entry in dead}

    assert replayed == {"evt-from-the-body", "evt-only-on-the-delivery"}


async def test_a_database_blip_at_startup_does_not_leave_webhooks_unsubscribed(monkeypatch):
    from app.services.webhook_events import WebhookEventForwarder

    class _Bus:
        def __init__(self):
            self.handlers = []

        def subscribe(self, pattern, handler):
            self.handlers.append((pattern, handler))
            return "sub-1"

    bus = _Bus()
    forwarder = WebhookEventForwarder(bus=bus)
    calls = {"n": 0}

    async def _refresh():
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionRefusedError("postgres restarting")
        forwarder._subscriptions = {}
        forwarder._loaded_at = 1e12

    monkeypatch.setattr(forwarder, "refresh", _refresh)

    await forwarder.start()

    assert [p for p, _ in bus.handlers] == ["*"]  # subscribed despite the failure
    # The first event retries the load instead of waiting for a restart.
    await forwarder._ensure_fresh()
    assert calls["n"] == 2

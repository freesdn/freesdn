# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A page's live read of any device waits its turn, then answers "as of".

``take_device_turn`` (called by the shared helpers that build a device's
client) plus ``DeviceReadTurnMiddleware``, over ASGI and real Valkey. The
endpoints here stand in for any live read: they take the device's turn and
then count a "device request".
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.core.device_slot import device_slots
from app.core.site_access import current_user_var
from app.services import device_live_read
from app.services.device_live_read import (
    DeviceReadTurnMiddleware,
    take_device_turn,
    uncacheable_read,
)

BOX = "host:192.0.2.50"
OTHER = "host:192.0.2.51"


@pytest.fixture
def quick_waits(monkeypatch):
    monkeypatch.setattr(settings, "DEVICE_UI_READ_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(settings, "DEVICE_UI_READ_MAX_WAIT_SECONDS", 0.6)


@pytest.fixture
def box():
    """The fake device and an app whose GET routes read it live."""
    state = SimpleNamespace(calls=0, user=None, body={"hostname": "fw1", "psk": "s3cret-psk"})
    app = FastAPI()
    app.add_middleware(DeviceReadTurnMiddleware)

    async def read(slot: str = BOX) -> None:
        if state.user is not None:
            current_user_var.set(state.user)
        await take_device_turn(slot)
        state.calls += 1

    @app.get("/live")
    async def live() -> dict[str, Any]:
        await read()
        return dict(state.body)

    @app.get("/live-list")
    async def live_list() -> list[dict[str, Any]]:
        await read()
        return [{"name": "eth0"}]

    @app.get("/has-own-cached")
    async def has_own_cached() -> dict[str, Any]:
        await read()
        return {"cached": "the vendor's own meaning", "value": 1}

    @app.get("/ticket")
    async def ticket() -> dict[str, Any]:
        uncacheable_read()
        await read()
        return {"ticket": state.calls}

    @app.get("/two-boxes")
    async def two_boxes() -> dict[str, Any]:
        await read(BOX)
        await read(OTHER)
        return {"both": True}

    @app.get("/database-only")
    async def database_only() -> dict[str, Any]:
        return {"from": "database"}

    @app.post("/action")
    async def action() -> dict[str, Any]:
        await read()
        return {"done": True}

    @app.get("/slow")
    async def slow() -> dict[str, Any]:
        await read()
        state.in_flight = getattr(state, "in_flight", 0) + 1
        state.max_in_flight = max(getattr(state, "max_in_flight", 0), state.in_flight)
        await asyncio.sleep(0.3)
        state.in_flight -= 1
        return {"ok": True}

    state.app = app
    return state


async def _get(state, path: str, method: str = "GET"):
    async with AsyncClient(
        transport=ASGITransport(app=state.app), base_url="http://ui.test"
    ) as client:
        return await client.request(method, path)


def _hold(slot: str = BOX, holder: str = "NVR alert ingest"):
    lease = device_slots.try_acquire(slot, holder, ttl=60)
    assert lease is not None and lease.guarded, "the test needs real Valkey"
    return lease


async def test_a_live_answer_says_when_it_was_read(box, quick_waits):
    response = await _get(box, "/live")
    assert response.status_code == 200
    body = response.json()
    assert body["cached"] is False and body["cache_reason"] is None
    assert datetime.fromisoformat(body["as_of"]).tzinfo is not None
    # Every field the endpoint returned is still there, unchanged.
    assert body["hostname"] == "fw1" and body["psk"] == "s3cret-psk"
    assert response.headers["x-freesdn-as-of"] == body["as_of"]
    assert response.headers["x-freesdn-cached"] == "false"
    assert "x-freesdn-cache-reason" not in response.headers
    assert int(response.headers["content-length"]) == len(response.content)


async def test_a_busy_device_is_answered_from_the_last_read_without_contacting_it(box, quick_waits):
    first = (await _get(box, "/live")).json()
    box.body["hostname"] = "changed since"
    held = _hold()
    try:
        response = await _get(box, "/live")
    finally:
        device_slots.release(held)
    assert response.status_code == 200
    assert box.calls == 1, "nothing may be sent to a device a poller holds"
    body = response.json()
    assert body["cached"] is True and body["cache_reason"] == "device_busy"
    assert body["as_of"] == first["as_of"] and body["hostname"] == "fw1"
    assert response.headers["x-freesdn-cached"] == "true"
    assert response.headers["x-freesdn-cache-reason"] == "device_busy"
    assert response.headers["x-freesdn-as-of"] == first["as_of"]


async def test_with_nothing_remembered_a_busy_device_answers_503_with_retry_after(box, quick_waits):
    held = _hold()
    try:
        response = await _get(box, "/live")
    finally:
        device_slots.release(held)
    assert response.status_code == 503
    assert response.headers["retry-after"] == "5"
    error = response.json()["error"]
    assert error["code"] == 503 and error["type"] == "device_busy"
    assert "NVR alert ingest" in error["message"]
    assert box.calls == 0


async def test_a_reader_with_nothing_remembered_waits_for_the_poll_to_finish(box, quick_waits):
    held = _hold()

    async def finish_poll():
        await asyncio.sleep(0.35)
        await device_slots.arelease(held)

    releaser = asyncio.create_task(finish_poll())
    response = await _get(box, "/live")
    await releaser
    assert response.status_code == 200 and response.json()["cached"] is False
    assert box.calls == 1


async def test_a_list_answer_keeps_its_shape_and_says_its_age_in_headers(box, quick_waits):
    first = await _get(box, "/live-list")
    assert first.json() == [{"name": "eth0"}]
    assert first.headers["x-freesdn-cached"] == "false"
    held = _hold()
    try:
        again = await _get(box, "/live-list")
    finally:
        device_slots.release(held)
    assert again.status_code == 200 and again.json() == [{"name": "eth0"}]
    assert again.headers["x-freesdn-cached"] == "true"
    assert again.headers["x-freesdn-as-of"] == first.headers["x-freesdn-as-of"]
    assert box.calls == 1


async def test_a_body_that_already_uses_the_names_is_left_as_it_is(box, quick_waits):
    response = await _get(box, "/has-own-cached")
    assert response.json() == {"cached": "the vendor's own meaning", "value": 1}
    assert response.headers["x-freesdn-cached"] == "false"


async def test_the_remembered_copy_holds_no_secret(box, quick_waits):
    await _get(box, "/live")
    key = next(iter(device_live_read._redis().scan_iter(f"{device_live_read._CACHE_PREFIX}http:*")))
    stored = json.loads(device_live_read._redis().get(key))
    assert "s3cret-psk" not in json.dumps(stored)
    assert stored["body"]["hostname"] == "fw1"


async def test_a_remembered_answer_is_only_served_to_a_caller_with_the_same_scope(box, quick_waits):
    """An operator limited to one site never gets an answer an admin's read
    left behind, even for the same URL."""
    box.user = SimpleNamespace(
        organization_id="org-1", role="org_admin", is_site_limited=False, _scoped=False
    )
    await _get(box, "/live")
    box.user = SimpleNamespace(
        organization_id="org-1",
        role="operator",
        is_site_limited=True,
        accessible_site_ids={"site-a"},
        _scoped=False,
    )
    held = _hold()
    try:
        response = await _get(box, "/live")
    finally:
        device_slots.release(held)
    assert response.status_code == 503
    assert box.calls == 1


async def test_a_one_time_answer_is_never_served_again(box, quick_waits):
    assert (await _get(box, "/ticket")).json()["ticket"] == 1
    held = _hold()
    try:
        response = await _get(box, "/ticket")
    finally:
        device_slots.release(held)
    assert response.status_code == 503


async def test_a_read_of_two_devices_takes_a_turn_at_each(box, quick_waits):
    held = _hold(OTHER, "Proxmox monitor")
    try:
        response = await _get(box, "/two-boxes")
    finally:
        device_slots.release(held)
    assert response.status_code == 503
    assert "Proxmox monitor" in response.json()["error"]["message"]
    assert box.calls == 1  # the first device answered; the busy one was not contacted


async def test_the_turn_is_given_back_as_soon_as_the_answer_is_ready(box, quick_waits):
    response = await _get(box, "/live")
    assert response.status_code == 200
    poller = device_slots.try_acquire(BOX, "health poll", ttl=30)
    assert poller is not None, "a background poller must get the device after the read"
    device_slots.release(poller)


async def test_ui_reads_of_one_device_never_exceed_the_shared_cap(box, monkeypatch):
    monkeypatch.setattr(settings, "DEVICE_UI_READ_CONCURRENCY", 2)
    monkeypatch.setattr(settings, "DEVICE_UI_READ_WAIT_SECONDS", 5.0)
    responses = await asyncio.gather(*(_get(box, "/slow") for _ in range(5)))
    assert all(r.status_code == 200 for r in responses)
    assert box.max_in_flight <= 2


async def test_database_only_reads_and_writes_are_untouched(box, quick_waits):
    held = _hold()
    try:
        plain = await _get(box, "/database-only")
        write = await _get(box, "/action", method="POST")
    finally:
        device_slots.release(held)
    assert plain.json() == {"from": "database"} and "x-freesdn-as-of" not in plain.headers
    # A POST is not a page read: it neither waits nor answers from memory.
    assert write.status_code == 200 and write.json() == {"done": True}
    assert "x-freesdn-as-of" not in write.headers


async def test_outside_a_page_request_the_turn_is_not_taken():
    """Background pollers hold the device exclusively and must not wait on
    themselves: outside a GET request the helper does nothing."""
    held = _hold()
    try:
        await asyncio.wait_for(take_device_turn(BOX), timeout=0.5)
    finally:
        device_slots.release(held)


async def test_a_gateway_read_that_stays_busy_answers_the_same_envelope():
    """The gateway reads raise DeviceBusyError inside the endpoint; the
    app's handler renders it with ``type: "device_busy"`` like the middleware
    does, instead of the generic envelope the UI could only match by sentence."""
    from app.core.middleware import setup_exception_handlers
    from app.services.device_live_read import DeviceBusyError

    app = FastAPI()
    setup_exception_handlers(app)

    @app.get("/gateway-read")
    async def gateway_read() -> dict[str, Any]:
        raise DeviceBusyError("Device busy: gateway full sync since 12:03:04 UTC (12s)")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://ui.test") as client:
        response = await client.get("/gateway-read")
    assert response.status_code == 503 and response.headers["retry-after"] == "5"
    error = response.json()["error"]
    assert error["type"] == "device_busy" and error["code"] == 503
    assert error["message"].startswith("Device busy: gateway full sync")

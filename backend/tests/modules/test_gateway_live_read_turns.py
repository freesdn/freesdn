# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A live gateway read waits briefly for the device, then serves "as of" data.

Real PostgreSQL and ASGI (the aggregate-read fixture), real Valkey for the
device slot and the remembered answers; the gateway itself is a double.
"""

from __future__ import annotations

import asyncio
from datetime import datetime

import pytest

from app.adapters.base import AdapterResult
from app.core.config import settings
from app.core.device_slot import device_slots, gateway_slot_key
from app.services import device_live_read
from tests.modules.test_gateway_aggregate_availability import (
    aggregate_inventory as aggregate_inventory,  # noqa: F401
)
from tests.modules.test_gateway_aggregate_availability import inventory, request
from tests.modules.test_gateway_aggregate_availability import trigger as trigger  # noqa: F401
from tests.services.test_device_config_render import ENCODED_NAME_URLS


@pytest.fixture
def quick_waits(monkeypatch):
    monkeypatch.setattr(settings, "DEVICE_UI_READ_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(settings, "DEVICE_UI_READ_MAX_WAIT_SECONDS", 0.6)


def _hold(gw, holder="gateway full sync"):
    lease = device_slots.try_acquire(gateway_slot_key(gw), holder, ttl=60)
    assert lease is not None and lease.guarded, "the test needs real Valkey"
    return lease


async def test_a_live_answer_says_when_it_was_read(aggregate_inventory, quick_waits):
    f = aggregate_inventory
    f.inventory_result = AdapterResult.ok(inventory("device-summary", True))
    response = await request(f, "device-summary")
    assert response.status_code == 200
    body = response.json()
    assert body["cached"] is False and body["cache_reason"] is None
    assert datetime.fromisoformat(body["as_of"]).tzinfo is not None
    # Nothing the endpoint returned before is renamed or removed.
    assert body["summary"]["hostname"] == "owned" and body["gateway_id"] == str(f.gateway.id)


async def test_a_busy_gateway_is_answered_from_the_last_read_without_contacting_it(
    aggregate_inventory, quick_waits
):
    """Fails on the old endpoint: it opened another session on the busy box."""
    f = aggregate_inventory
    f.inventory_result = AdapterResult.ok(inventory("device-summary", True))
    first = (await request(f, "device-summary")).json()
    f.calls.clear()
    held = _hold(f.gateway)
    try:
        response = await request(f, "device-summary")
    finally:
        device_slots.release(held)
    assert response.status_code == 200
    body = response.json()
    assert f.calls == [], "nothing may be sent to a device a poller holds"
    assert body["cached"] is True and body["cache_reason"] == "device_busy"
    assert body["as_of"] == first["as_of"]
    assert body["summary"] == first["summary"]


async def test_with_nothing_remembered_a_busy_gateway_answers_503_with_retry_after(
    aggregate_inventory, quick_waits
):
    f = aggregate_inventory
    f.inventory_result = AdapterResult.ok(inventory("device-summary", True))
    held = _hold(f.gateway)
    try:
        response = await request(f, "device-summary")
    finally:
        device_slots.release(held)
    assert response.status_code == 503
    assert response.headers.get("retry-after") == "5"
    assert "gateway full sync" in response.json()["detail"]
    assert f.calls == []


async def test_a_reader_with_nothing_remembered_waits_for_the_poll_to_finish(
    aggregate_inventory, quick_waits
):
    f = aggregate_inventory
    f.inventory_result = AdapterResult.ok(inventory("device-summary", True))
    held = _hold(f.gateway)

    async def finish_poll():
        await asyncio.sleep(0.35)
        await device_slots.arelease(held)

    releaser = asyncio.create_task(finish_poll())
    response = await request(f, "device-summary")
    await releaser
    assert response.status_code == 200 and response.json()["cached"] is False


async def test_ui_reads_of_one_gateway_never_exceed_the_shared_cap(
    aggregate_inventory, monkeypatch
):
    """A page opening many panels does not open that many sessions at once."""
    f = aggregate_inventory
    monkeypatch.setattr(settings, "DEVICE_UI_READ_CONCURRENCY", 2)
    monkeypatch.setattr(settings, "DEVICE_UI_READ_WAIT_SECONDS", 5.0)
    in_flight = {"now": 0, "max": 0}

    async def slow():
        in_flight["now"] += 1
        in_flight["max"] = max(in_flight["max"], in_flight["now"])
        await asyncio.sleep(0.3)
        in_flight["now"] -= 1
        return AdapterResult.ok(inventory("device-summary", True))

    from app.modules.firewall.gateway_service import adapter_registry

    original = adapter_registry.create_adapter

    def create(**kwargs):
        adapter = original(**kwargs)
        adapter.get_device_summary = slow
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    responses = await asyncio.gather(*(request(f, "device-summary") for _ in range(5)))
    assert all(r.status_code == 200 for r in responses)
    assert in_flight["max"] <= 2


async def test_the_remembered_copy_holds_no_secret(monkeypatch):
    key = device_live_read.cache_key("gateway", "g1", "get_live_wireguard")

    async def fetch():
        return {"servers": [{"name": "wg0", "private_key": "owned-wg-private-key"}]}

    out = await device_live_read.live_or_cached(
        slot_key="host:192.0.2.90", cache_key=key, fetch=fetch, holder="UI read"
    )
    assert out["servers"][0]["private_key"] == "owned-wg-private-key"  # the live answer
    stored = device_live_read._load_sync(key)
    assert "owned-wg-private-key" not in str(stored)


async def test_a_read_inside_a_read_of_the_same_device_does_not_wait_for_itself(monkeypatch):
    monkeypatch.setattr(settings, "DEVICE_UI_READ_CONCURRENCY", 1)
    monkeypatch.setattr(settings, "DEVICE_UI_READ_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(settings, "DEVICE_UI_READ_MAX_WAIT_SECONDS", 0.4)

    async def inner():
        return {"inner": True}

    async def outer():
        nested = await device_live_read.live_or_cached(
            slot_key="host:192.0.2.91",
            cache_key=device_live_read.cache_key("gateway", "g2", "inner"),
            fetch=inner,
            holder="UI read",
        )
        return {"nested": nested["inner"]}

    out = await device_live_read.live_or_cached(
        slot_key="host:192.0.2.91",
        cache_key=device_live_read.cache_key("gateway", "g2", "outer"),
        fetch=outer,
        holder="UI read",
    )
    assert out["nested"] is True


async def test_the_remembered_copy_masks_credentials_inside_urls():
    """Fails on the old cache: a key-based redactor passed string values through."""
    key = device_live_read.cache_key("gateway", "g1", "get_live_syslog_destinations")

    async def fetch():
        return {
            "destinations": [
                {
                    "name": "central",
                    "description": "push to https://admin:owned-pass@logs.example.test/in",
                },
                {
                    "name": "backup",
                    "url": "https://logs.example.test/u%3Fx=1?password=owned-query&a=1",
                },
            ]
        }

    out = await device_live_read.live_or_cached(
        slot_key="host:192.0.2.91", cache_key=key, fetch=fetch, holder="UI read"
    )
    assert "owned-pass" in str(out)  # the live answer is unchanged
    stored = str(device_live_read._load_sync(key))
    assert "owned-pass" not in stored and "owned-query" not in stored
    # Only the strings that may hold a credential are hidden, whole.
    assert "'central'" in stored and "'backup'" in stored


@pytest.fixture
async def log_gateway(trigger, monkeypatch):
    from app.modules.firewall.gateway_service import adapter_registry

    f = trigger
    f.permissions.append("firewall.view")
    original = adapter_registry.create_adapter

    def create(**kwargs):
        adapter = original(**kwargs)

        async def get_system_log(limit):
            f.calls.append("get_system_log")
            return AdapterResult.ok([{"message": "login https://root:owned-log@192.0.2.1/"}])

        adapter.get_system_log = get_system_log
        return adapter

    monkeypatch.setattr(adapter_registry, "create_adapter", create)
    yield f


async def test_a_raw_device_log_is_never_remembered(log_gateway, quick_waits):
    """Fails on the old cache: the log answer was stored and served while busy."""
    f = log_gateway
    first = await request(f, "logs/system")
    assert first.status_code == 200 and "owned-log" in first.text
    held = _hold(f.gateway)
    try:
        busy = await request(f, "logs/system")
    finally:
        device_slots.release(held)
    assert busy.status_code == 503
    assert "owned-log" not in busy.text


@pytest.mark.parametrize("url", ENCODED_NAME_URLS)
def test_remembered_answers_mask_encoded_credential_parameters(url):
    """The cache uses the same URL parser as the config renderer."""
    stored = str(device_live_read._for_cache({"rows": [{"note": f"callback {url} set"}]}))
    assert "SECRET" not in stored and "callback" not in stored

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""discovery.started / completed / failed come from the one discovery pipeline.

They were published only by the Discovery page's private copy of the pipeline.
When that copy was replaced by app.tasks.discovery they went silent, while the
n8n trigger and the webhook event list still offered them. "started" goes out
once the run holds the controller's slot; a run that never started (busy device,
disabled or unknown controller) announces nothing.
"""

from __future__ import annotations

import pytest

from app.tasks import discovery


@pytest.fixture
def run(monkeypatch):
    events: list = []

    class _Bus:
        async def publish(self, event):
            events.append(event)

    import app.core.celery_app as celery_app

    monkeypatch.setattr(celery_app, "acquire_solo_lock", lambda *_a, **_k: "token")
    monkeypatch.setattr(celery_app, "release_solo_lock", lambda *_a, **_k: None)
    monkeypatch.setattr(discovery, "get_event_bus", lambda: _Bus())

    def install(impl):
        monkeypatch.setattr(discovery, "_discover_devices_for_controller_impl", impl)
        return events

    return install


async def _started(cid):
    await discovery._announce_started("org-1", cid, "Office controller")


async def test_a_successful_discovery_announces_start_and_completion(run):
    async def impl(cid):
        await _started(cid)
        return {"success": True, "devices_discovered": 3, "devices_created": 1, "note": "x"}

    events = run(impl)
    await discovery._discover_devices_for_controller("c-1")

    assert [e.event_type for e in events] == ["discovery.started", "discovery.completed"]
    assert {e.organization_id for e in events} == {"org-1"}
    assert events[1].payload["stats"] == {"devices_discovered": 3, "devices_created": 1}
    assert events[1].payload["controller_name"] == "Office controller"


async def test_a_raising_discovery_announces_failure_with_the_class_only(run):
    async def impl(cid):
        await _started(cid)
        raise ConnectionError("timeout talking to https://controller.example.test/api")

    events = run(impl)
    with pytest.raises(ConnectionError):
        await discovery._discover_devices_for_controller("c-1")

    assert [e.event_type for e in events] == ["discovery.started", "discovery.failed"]
    assert events[1].payload["error"] == "ConnectionError"
    assert "example.test" not in str(events[1].payload)


async def test_an_unsuccessful_run_is_announced_without_its_text(run):
    async def impl(cid):
        await _started(cid)
        return {"success": False, "error": "vendor said something long"}

    events = run(impl)
    await discovery._discover_devices_for_controller("c-1")

    assert [e.event_type for e in events] == ["discovery.started", "discovery.failed"]
    assert events[1].payload["error"] == "DiscoveryFailed"


async def test_a_run_skipped_because_the_device_is_busy_announces_nothing(run):
    async def impl(cid):
        return {"success": True, "skipped": True, "reason": "device_busy", "controller_id": cid}

    events = run(impl)
    result = await discovery._discover_devices_for_controller("c-1")
    assert result["skipped"] is True
    assert events == []


async def test_a_run_refused_before_it_started_announces_nothing(run):
    async def impl(cid):
        return {"success": False, "error": f"Controller {cid} is disabled"}

    events = run(impl)
    await discovery._discover_devices_for_controller("c-1")
    assert events == []

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Regression test for the WebSocket cross-tenant event leak (readiness
audit P0).

Threat model
------------
``ConnectionManager._should_receive`` decides whether a given subscribed
WS connection should be sent a given ``Event``. The audit found that the
prior implementation was fail-OPEN: an event whose ``organization_id``
was ``None`` would bypass the org check entirely and reach every
subscribed client across tenants. Several event factories
(``device_event``, ``alert_event``, ``discovery_event``, ``task_event``,
the three ``publish_*`` helpers, and the ``_network_event`` factory in
the network module) shipped without ever setting ``organization_id`` on
the produced ``Event``. Combined, this meant `device.discovered` /
`discovery.scan.*` / `alert.fired` envelopes — sanitized of creds, but
still carrying ``device_id`` / ``name`` / ``site_id`` / ``controller_id``
/ ``alert_id`` / ``severity`` / ``title`` — were broadcast cross-tenant.

The fix has three parts:

1. ``_should_receive`` now fails CLOSED on missing ``event.organization_id``.
2. Every event factory + ``publish_*`` helper accepts an explicit
   ``organization_id`` kwarg and threads it into ``Event(...)``.
3. Every internal call site that produced these events now resolves the
   producing org (via ``device.site.organization_id``, ``rule.organization_id``,
   etc.) and passes it.

These tests assert (1) directly — the helper and call-site changes are
exercised by the higher-level integration tests in ``test_websocket.py``.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.api.v1.endpoints.websocket import ConnectionInfo, ConnectionManager
from app.core.events import Event, EventCategory


def _info(*, org_id: str | None, subs: list[str] | None = None, site_ids: list[str] | None = None) -> ConnectionInfo:
    """Build a minimal ConnectionInfo for the routing decision. ``websocket``
    is set to None — ``_should_receive`` doesn't touch it."""
    return ConnectionInfo(
        user_id="user-stub",
        organization_id=org_id,
        websocket=None,
        subscriptions=set(subs or ["*"]),
        site_ids=site_ids or [],
    )


def _event(*, org_id: str | None, event_type: str = "device.discovered", site_id: str | None = None) -> Event:
    """Build a minimal Event. Payload carries site_id if provided so the
    routing code's payload.get('site_id') path is exercised."""
    return Event(
        event_type=event_type,
        category=EventCategory.DEVICE,
        organization_id=org_id,
        payload={"site_id": site_id} if site_id else {},
    )


class TestShouldReceiveOrgRouting:
    """Pure-function tests for the org-routing branch of ``_should_receive``.

    ConnectionManager is constructed without arguments — the broadcast
    path that ``_should_receive`` is part of doesn't touch the Redis /
    cross-instance pub-sub side of the manager.
    """

    @pytest.fixture
    def manager(self) -> ConnectionManager:
        return ConnectionManager()

    def test_matching_org_delivers(self, manager: ConnectionManager) -> None:
        org_a = str(uuid4())
        assert manager._should_receive(
            _info(org_id=org_a),
            _event(org_id=org_a),
        ) is True

    def test_cross_tenant_event_blocked(self, manager: ConnectionManager) -> None:
        """The headline regression: an event for Org A must NOT reach a
        connection scoped to Org B."""
        org_a, org_b = str(uuid4()), str(uuid4())
        assert manager._should_receive(
            _info(org_id=org_b),
            _event(org_id=org_a),
        ) is False

    def test_event_without_org_id_dropped(self, manager: ConnectionManager) -> None:
        """Fail-closed: an event whose ``organization_id`` is None must
        not reach any client (this was the leak)."""
        assert manager._should_receive(
            _info(org_id=str(uuid4())),
            _event(org_id=None),
        ) is False

    def test_connection_without_org_id_dropped(self, manager: ConnectionManager) -> None:
        """A connection with no resolved org_id receives nothing."""
        assert manager._should_receive(
            _info(org_id=None),
            _event(org_id=str(uuid4())),
        ) is False

    def test_uuid_vs_string_org_id_compares_equal(self, manager: ConnectionManager) -> None:
        """Event.organization_id may be a UUID (from internal call sites)
        while ConnectionInfo.organization_id is always a string — the
        routing must compare as strings, not by Python identity."""
        org_a_uuid = uuid4()
        assert manager._should_receive(
            _info(org_id=str(org_a_uuid)),
            _event(org_id=org_a_uuid),  # type: ignore[arg-type]
        ) is True

    def test_unsubscribed_event_type_dropped(self, manager: ConnectionManager) -> None:
        """Subscription filter takes precedence — even a same-org event
        is dropped if the client didn't subscribe to its pattern."""
        org_a = str(uuid4())
        info = _info(org_id=org_a, subs=["alert.*"])  # subscribed only to alerts
        evt = _event(org_id=org_a, event_type="device.discovered")
        assert manager._should_receive(info, evt) is False

    def test_site_filter_blocks_cross_site(self, manager: ConnectionManager) -> None:
        """Within the same org, a connection's site_ids filter still applies."""
        org_a = str(uuid4())
        site_a, site_b = str(uuid4()), str(uuid4())
        info = _info(org_id=org_a, site_ids=[site_a])
        evt = _event(org_id=org_a, site_id=site_b)
        assert manager._should_receive(info, evt) is False

    def test_site_filter_empty_allows_all_sites(self, manager: ConnectionManager) -> None:
        """A connection with no site_ids filter receives any same-org event."""
        org_a = str(uuid4())
        info = _info(org_id=org_a, site_ids=[])
        evt = _event(org_id=org_a, site_id=str(uuid4()))
        assert manager._should_receive(info, evt) is True

    def test_wildcard_subscription_still_org_scoped(self, manager: ConnectionManager) -> None:
        """``*`` subscription does not bypass the org filter (this was
        the trap — broad subscription + missing event org_id = leak)."""
        org_a, org_b = str(uuid4()), str(uuid4())
        info = _info(org_id=org_b, subs=["*"])
        evt = _event(org_id=org_a)
        assert manager._should_receive(info, evt) is False


class TestEventFactoriesThreadOrgId:
    """The helper-level half of the fix: the documented event factories
    must accept an ``organization_id`` kwarg and put it on the Event."""

    def test_device_event_threads_org_id(self) -> None:
        from app.core.events import device_event

        org = str(uuid4())
        evt = device_event("discovered", device_id="dev1", organization_id=org)
        assert evt.organization_id == org

    def test_alert_event_threads_org_id(self) -> None:
        from app.core.events import alert_event

        org = str(uuid4())
        evt = alert_event("critical", "boom", "service:test", organization_id=org)
        assert evt.organization_id == org

    def test_discovery_event_threads_org_id(self) -> None:
        from app.core.events import discovery_event

        org = str(uuid4())
        evt = discovery_event("started", organization_id=org, controller_id="c1")
        assert evt.organization_id == org

    def test_task_event_threads_org_id(self) -> None:
        from app.core.events import task_event

        org = str(uuid4())
        evt = task_event("started", task_id="t1", organization_id=org)
        assert evt.organization_id == org

    def test_device_event_without_org_id_is_none(self) -> None:
        """Backwards-compat: callers that haven't been updated yet still
        construct an Event, just with organization_id=None (and the
        fail-closed router will drop it — which is the desired behavior
        until the call site is updated)."""
        from app.core.events import device_event

        evt = device_event("discovered", device_id="dev1")
        assert evt.organization_id is None

    def test_network_event_lifts_payload_org_id_onto_event(self) -> None:
        """``_network_event`` in the network module keeps the payload key
        for backwards compat (gateway handler reads it from payload) but
        ALSO lifts it onto the Event field so WS routing works."""
        from app.modules.network.service import _network_event

        org = str(uuid4())
        evt = _network_event(
            "network.vlan.created",
            site_id="site-1",
            vlan_id=10,
            organization_id=org,
        )
        assert evt.organization_id == org
        # Payload retains the key for the gateway handler:
        assert evt.payload.get("organization_id") == org


class TestEventBusDispatchConcurrent:
    """The other half of the WS P0 cluster (P0-D): ``_dispatch_local``
    must run priority buckets concurrently with per-handler timeout
    so a slow subscriber can't pin the publisher."""

    @pytest.mark.asyncio
    async def test_slow_subscriber_does_not_block_publisher(self) -> None:
        """A 1-second sleep in one subscriber must not delay the publish
        path indefinitely; the dispatch runs handlers concurrently."""
        import asyncio
        import time

        from app.core.events import EventBus, EventPriority

        bus = EventBus(redis_url=None)  # no Redis, local-only dispatch
        fast_calls: list[float] = []
        slow_calls: list[float] = []

        async def fast(_event: Event) -> None:
            fast_calls.append(time.monotonic())

        async def slow(_event: Event) -> None:
            await asyncio.sleep(0.2)
            slow_calls.append(time.monotonic())

        bus.subscribe("test.evt", fast, priority=EventPriority.NORMAL)
        bus.subscribe("test.evt", slow, priority=EventPriority.NORMAL)

        start = time.monotonic()
        await bus.publish(Event(
            event_type="test.evt",
            category=EventCategory.SYSTEM,
            organization_id=str(uuid4()),
            payload={},
        ))
        elapsed = time.monotonic() - start

        # Both handlers ran:
        assert len(fast_calls) == 1
        assert len(slow_calls) == 1
        # If dispatch were sequential the slow handler's sleep would be
        # added to whatever the fast handler took. Concurrent gather
        # means publish returns in ~0.2s (slow's duration), NOT
        # fast_duration + 0.2s. Generous bound to avoid flake:
        assert elapsed < 0.4, f"dispatch was sequential, took {elapsed:.3f}s"

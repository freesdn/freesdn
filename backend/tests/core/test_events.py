# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for app.core.events — EventBus, Event, and helpers.

All tests run in-memory (no Redis connection).
"""

from datetime import datetime

import pytest

from app.core.events import (
    Event,
    EventBus,
    EventCategory,
    EventPriority,
    EventSubscription,
    InMemoryEventStore,
    alert_event,
    device_event,
    discovery_event,
    task_event,
)

# ── Event dataclass ─────────────────────────────────────────────────────────


class TestEvent:
    def test_create_with_defaults(self):
        e = Event(event_type="test.ping")
        assert e.event_type == "test.ping"
        assert e.category == EventCategory.SYSTEM
        assert e.priority == EventPriority.NORMAL
        assert e.source == "freesdn"
        assert e.payload == {}
        assert e.metadata == {}
        assert e.causation_id is None
        assert isinstance(e.id, str)
        assert isinstance(e.timestamp, datetime)

    def test_create_with_all_fields(self):
        e = Event(
            event_type="device.status.changed",
            payload={"device_id": "abc"},
            category=EventCategory.DEVICE,
            priority=EventPriority.HIGH,
            source="adapter",
            correlation_id="corr-1",
            causation_id="cause-1",
            metadata={"extra": True},
        )
        assert e.category == EventCategory.DEVICE
        assert e.priority == EventPriority.HIGH
        assert e.correlation_id == "corr-1"
        assert e.causation_id == "cause-1"
        assert e.payload["device_id"] == "abc"

    def test_to_dict_roundtrip(self):
        e = Event(
            event_type="test.roundtrip",
            payload={"key": "value"},
            category=EventCategory.NETWORK,
            priority=EventPriority.CRITICAL,
        )
        d = e.to_dict()
        assert d["event_type"] == "test.roundtrip"
        assert d["category"] == "network"
        assert d["priority"] == "critical"
        assert d["payload"] == {"key": "value"}
        assert "timestamp" in d

        restored = Event.from_dict(d)
        assert restored.event_type == e.event_type
        assert restored.category == e.category
        assert restored.priority == e.priority
        assert restored.id == e.id

    def test_caused_by_links_parent(self):
        parent = Event(event_type="discovery.started")
        child = Event(event_type="device.discovered", payload={"mac": "aa:bb"})
        linked = child.caused_by(parent)
        assert linked.correlation_id == parent.correlation_id
        assert linked.causation_id == parent.id
        assert linked.event_type == "device.discovered"


# ── EventSubscription pattern matching ──────────────────────────────────────


class TestEventSubscription:
    def _sub(self, pattern: str):
        async def noop(e):
            pass
        return EventSubscription(pattern=pattern, handler=noop)

    def test_exact_match(self):
        s = self._sub("device.status.changed")
        assert s.matches("device.status.changed")
        assert not s.matches("device.status.created")

    def test_star_wildcard(self):
        s = self._sub("device.*.changed")
        assert s.matches("device.status.changed")
        assert s.matches("device.config.changed")
        assert not s.matches("device.status.created")
        assert not s.matches("device.changed")

    def test_hash_wildcard(self):
        s = self._sub("device.#")
        assert s.matches("device.status.changed")
        assert s.matches("device.discovered")
        assert s.matches("device.a.b.c")
        assert not s.matches("alert.created")

    def test_star_single_segment_only(self):
        s = self._sub("device.*")
        assert s.matches("device.discovered")
        assert not s.matches("device.status.changed")


# ── EventBus subscribe / publish ────────────────────────────────────────────


class TestEventBus:
    @pytest.fixture
    def bus(self):
        """Create a bus with no Redis (pure in-memory)."""
        return EventBus(redis_url=None)

    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self, bus):
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("test.ping", handler)
        await bus.publish(Event(event_type="test.ping", payload={"n": 1}))

        assert len(received) == 1
        assert received[0].payload["n"] == 1

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self, bus):
        results_a = []
        results_b = []

        async def handler_a(event: Event):
            results_a.append(event)

        async def handler_b(event: Event):
            results_b.append(event)

        bus.subscribe("multi.test", handler_a)
        bus.subscribe("multi.test", handler_b)

        await bus.publish(Event(event_type="multi.test"))
        assert len(results_a) == 1
        assert len(results_b) == 1

    @pytest.mark.asyncio
    async def test_wildcard_subscriber(self, bus):
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("device.*", handler)
        await bus.publish(Event(event_type="device.discovered"))
        await bus.publish(Event(event_type="device.updated"))
        await bus.publish(Event(event_type="alert.created"))

        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_hash_wildcard_subscriber(self, bus):
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("device.#", handler)
        await bus.publish(Event(event_type="device.status.changed"))
        await bus.publish(Event(event_type="device.discovered"))
        await bus.publish(Event(event_type="system.startup"))

        assert len(received) == 2

    @pytest.mark.asyncio
    async def test_unsubscribe(self, bus):
        received = []

        async def handler(event: Event):
            received.append(event)

        sub_id = bus.subscribe("unsub.test", handler)
        await bus.publish(Event(event_type="unsub.test"))
        assert len(received) == 1

        result = bus.unsubscribe(sub_id)
        assert result is True

        await bus.publish(Event(event_type="unsub.test"))
        assert len(received) == 1  # no new events

    @pytest.mark.asyncio
    async def test_unsubscribe_nonexistent(self, bus):
        assert bus.unsubscribe("does-not-exist") is False

    @pytest.mark.asyncio
    async def test_no_match_no_delivery(self, bus):
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("alert.*", handler)
        await bus.publish(Event(event_type="device.discovered"))

        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_priority_ordering(self, bus):
        """CRITICAL handlers should run before LOW handlers."""
        order = []

        async def low_handler(event: Event):
            order.append("low")

        async def critical_handler(event: Event):
            order.append("critical")

        bus.subscribe("order.test", low_handler, priority=EventPriority.LOW)
        bus.subscribe("order.test", critical_handler, priority=EventPriority.CRITICAL)

        await bus.publish(Event(event_type="order.test"))
        assert order == ["critical", "low"]

    @pytest.mark.asyncio
    async def test_handler_error_does_not_break_others(self, bus):
        received = []

        async def bad_handler(event: Event):
            raise RuntimeError("boom")

        async def good_handler(event: Event):
            received.append(event)

        bus.subscribe("error.test", bad_handler)
        bus.subscribe("error.test", good_handler)

        await bus.publish(Event(event_type="error.test"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_decorator_subscribe(self, bus):
        received = []

        @bus.subscribe("deco.test")
        async def handler(event: Event):
            received.append(event)

        await bus.publish(Event(event_type="deco.test"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_event_history(self, bus):
        await bus.publish(Event(event_type="hist.a"))
        await bus.publish(Event(event_type="hist.b"))

        history = await bus.get_history(limit=10)
        assert len(history) == 2
        types = [e.event_type for e in history]
        assert "hist.a" in types
        assert "hist.b" in types

    @pytest.mark.asyncio
    async def test_correlation_tracking(self, bus):
        corr = "corr-xyz"
        await bus.publish(Event(event_type="corr.a", correlation_id=corr))
        await bus.publish(Event(event_type="corr.b", correlation_id=corr))
        await bus.publish(Event(event_type="corr.c", correlation_id="other"))

        related = await bus.get_by_correlation(corr)
        assert len(related) == 2


# ── InMemoryEventStore ──────────────────────────────────────────────────────


class TestInMemoryEventStore:
    @pytest.mark.asyncio
    async def test_append_and_recent(self):
        store = InMemoryEventStore(max_events=5)
        for i in range(7):
            await store.append(Event(event_type=f"e.{i}"))

        recent = await store.get_recent(limit=10)
        # max_events=5, so only last 5 survive
        assert len(recent) == 5
        assert recent[0].event_type == "e.2"

    @pytest.mark.asyncio
    async def test_get_by_type(self):
        store = InMemoryEventStore()
        await store.append(Event(event_type="device.up"))
        await store.append(Event(event_type="device.down"))
        await store.append(Event(event_type="device.up"))

        matches = await store.get_by_type("device.up")
        assert len(matches) == 2


# ── Factory functions ───────────────────────────────────────────────────────


class TestEventFactories:
    def test_device_event(self):
        e = device_event("discovered", device_id="d1", site_id="s1", name="sw1")
        assert e.event_type == "device.discovered"
        assert e.category == EventCategory.DEVICE
        assert e.payload["device_id"] == "d1"
        assert e.payload["site_id"] == "s1"
        assert e.payload["name"] == "sw1"

    def test_alert_event_critical(self):
        e = alert_event("critical", message="Port down", source="monitor")
        assert e.event_type == "alert.critical"
        assert e.priority == EventPriority.CRITICAL
        assert e.category == EventCategory.SECURITY

    def test_alert_event_warning(self):
        e = alert_event("warning", message="High CPU", source="monitor")
        assert e.priority == EventPriority.HIGH

    def test_discovery_event(self):
        e = discovery_event("started", controller_id="c1")
        assert e.event_type == "discovery.started"
        assert e.category == EventCategory.SYSTEM
        assert e.payload["controller_id"] == "c1"

    def test_task_event(self):
        e = task_event("completed", task_id="t1", result="ok")
        assert e.event_type == "task.completed"
        assert e.category == EventCategory.TASK
        assert e.payload["task_id"] == "t1"
        assert e.payload["result"] == "ok"

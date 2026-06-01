# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Event Bus System
==============================

Comprehensive event system with Redis pub/sub support for distributed events.
"""

import asyncio
import contextlib
import json
import logging
import re
import uuid
from collections import defaultdict, deque
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class EventPriority(StrEnum):
    """Event processing priority."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(StrEnum):
    """High-level event categories."""

    SYSTEM = "system"
    DEVICE = "device"
    SITE = "site"
    CONTROLLER = "controller"
    NETWORK = "network"
    SECURITY = "security"
    USER = "user"
    TASK = "task"


@dataclass
class Event:
    """
    Domain event with full tracing support.

    Attributes:
        event_type: Dot-notation event type (e.g., 'device.status.changed')
        payload: Event data
        category: High-level category
        priority: Processing priority
        source: Originating service/component
        correlation_id: Links related events together
        causation_id: ID of event that caused this one
        metadata: Additional context
        organization_id: Owning tenant. Events without an org are published
            on the 'system' channel and are visible to any subscriber listening
            for system events.
        sequence: Per-process monotonic counter stamped by
            :meth:`EventBus.publish`. Subscribers can detect drops or reorder
            events delivered out of order via Redis pub/sub. Default ``0``
            means "unstamped" (e.g., constructed by ``from_dict`` for an
            event that never went through ``publish``). NOTE: this counter
            is **per-process**, not cluster-wide — two workers publishing
            concurrently may emit identical sequence numbers. For
            cluster-wide ordering use a Redis ``INCR`` or a Lamport clock.
    """

    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    category: EventCategory = EventCategory.SYSTEM
    priority: EventPriority = EventPriority.NORMAL
    source: str = "freesdn"
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    causation_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    organization_id: str | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    sequence: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "payload": self.payload,
            "category": self.category.value,
            "priority": self.priority.value,
            "source": self.source,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "metadata": self.metadata,
            "organization_id": self.organization_id,
            "timestamp": self.timestamp.isoformat(),
            "sequence": self.sequence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            event_type=data["event_type"],
            payload=data.get("payload", {}),
            category=EventCategory(data.get("category", "system")),
            priority=EventPriority(data.get("priority", "normal")),
            source=data.get("source", "freesdn"),
            correlation_id=data.get("correlation_id", str(uuid.uuid4())),
            causation_id=data.get("causation_id"),
            metadata=data.get("metadata", {}),
            organization_id=data.get("organization_id"),
            timestamp=datetime.fromisoformat(data["timestamp"])
            if "timestamp" in data
            else datetime.now(UTC),
            sequence=int(data.get("sequence", 0)),
        )

    def caused_by(self, parent: "Event") -> "Event":
        """Create a new event with causation tracking."""
        return Event(
            event_type=self.event_type,
            payload=self.payload,
            category=self.category,
            priority=self.priority,
            source=self.source,
            correlation_id=parent.correlation_id,
            causation_id=parent.id,
            metadata=self.metadata,
        )


@dataclass
class EventSubscription:
    """Subscription to event patterns."""

    pattern: str
    handler: Callable[[Event], Coroutine[Any, Any, None]]
    priority: EventPriority = EventPriority.NORMAL
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def matches(self, event_type: str) -> bool:
        """Check if event type matches subscription pattern (supports wildcards).

        - Bare ``*`` matches EVERY event_type (full firehose). The
          WebSocket forwarder, automation engine, and audit subscribers
          all use this — without this special case the regex below
          would only match single-segment names like ``"device"`` and
          silently drop compound names like ``"pbx.sync.progress"`` or
          ``"device.status_changed"``. That dropped every event the UI
          actually cares about.
        - ``device.*`` (with a literal dot) still means "single segment
          after the prefix" — matches ``device.created`` but not
          ``device.lifecycle.created``.
        - ``device.#`` matches any number of trailing segments.
        """
        if self.pattern == "*":
            return True
        regex = self.pattern.replace(".", r"\.").replace("*", r"[^.]+").replace("#", r".*")
        return bool(re.match(f"^{regex}$", event_type))


class InMemoryEventStore:
    """In-memory event store with O(1) append/eviction via deque."""

    def __init__(self, max_events: int = 10000):
        from collections import deque

        self.events: deque[Event] = deque(maxlen=max_events)

    async def append(self, event: Event) -> None:
        self.events.append(event)

    async def get_by_correlation(self, correlation_id: str) -> list[Event]:
        return [e for e in self.events if e.correlation_id == correlation_id]

    async def get_by_type(self, event_type: str, limit: int = 100) -> list[Event]:
        matching = [e for e in self.events if e.event_type == event_type]
        return matching[-limit:]

    async def get_recent(self, limit: int = 100) -> list[Event]:
        return list(self.events)[-limit:]


class EventBus:
    """
    Event bus with Redis pub/sub support.

    Features:
    - Pattern-based subscriptions with wildcards (* and #)
    - Priority-based handler execution
    - Redis pub/sub for distributed events
    - In-memory store for event history
    """

    def __init__(self, redis_url: str | None = None):
        self._subscriptions: dict[str, list[EventSubscription]] = defaultdict(list)
        self._redis_url = redis_url
        self._redis: redis.Redis | None = None
        self._pubsub: redis.client.PubSub | None = None
        self._store = InMemoryEventStore()
        self._running = False
        self._listener_task: asyncio.Task[None] | None = None
        # IDs of events this process has already dispatched locally. The
        # Redis listener consults this set so that events produced *in
        # this process* (already dispatched at publish() time) are not
        # dispatched a second time when they come back over pub/sub.
        # Bounded to avoid unbounded memory growth on long-running buses.
        self._locally_dispatched_ids: deque[str] = deque(maxlen=10000)
        self._locally_dispatched_set: set[str] = set()
        # Per-process monotonic counter stamped onto each event in
        # :meth:`publish`. Wrapped in an asyncio.Lock so concurrent
        # publishers see strictly increasing values *within this process*.
        # NOT cluster-wide — see Event.sequence docstring.
        self._seq_counter: int = 0
        self._seq_lock: asyncio.Lock = asyncio.Lock()

    async def connect(self) -> None:
        """Connect to Redis if URL provided."""
        if self._redis_url:
            # Cast to ``str`` defensively — when ``self._redis_url`` is
            # sourced from a Pydantic settings field it may arrive as a
            # ``RedisDsn`` (URL value type) rather than a plain string.
            # ``redis.from_url`` calls ``urllib.parse.urlparse`` which
            # only accepts ``str`` / ``bytes``; passing a Pydantic Url
            # blows up with ``'RedisDsn' object has no attribute
            # 'decode'``. Exposed by the redis 6.4 + pydantic 2.13.4
            # upgrade (the older redis client coerced more eagerly).
            # socket_connect_timeout bounds the CONNECT so a black-holed/restarting
            # Redis fails fast instead of blocking on the OS TCP timeout (which can
            # stall lifespan startup). NOT socket_timeout — that would break the
            # long-lived pub/sub listen reads.
            # Sentinel-aware (HA): master_for re-resolves the promoted master on
            # reconnect, so the EventBus follows a Redis/Valkey failover.
            from app.core.redis_client import get_async_redis

            # socket_timeout=None: pub/sub listen() is a long-lived blocking read.
            self._redis = get_async_redis(socket_connect_timeout=5, socket_timeout=None)
            self._pubsub = self._redis.pubsub()
            # Pattern matches both legacy 'freesdn:events:{category}' and
            # org-scoped 'freesdn:events:{category}:{org_id}' channels since
            # Redis glob '*' spans ':' separators.
            await self._pubsub.psubscribe("freesdn:events:*")
            self._running = True
            self._listener_task = asyncio.create_task(self._listen_redis())
            logger.info("EventBus connected to Redis")

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        self._running = False
        if self._listener_task:
            self._listener_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._listener_task
        if self._pubsub:
            await self._pubsub.unsubscribe()
            await self._pubsub.close()
        if self._redis:
            await self._redis.close()
        logger.info("EventBus disconnected from Redis")

    async def _listen_redis(self) -> None:
        """
        Listen for Redis pub/sub messages with automatic reconnection.

        On any connection error we wait 5 s, then tear down and rebuild the
        Redis connection + pubsub subscription before resuming. This ensures
        the automation engine and other subscribers keep receiving events even
        after a Redis restart or network blip.
        """
        while self._running:
            try:
                message = await self._pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )  # type: ignore[union-attr]
                if message and message["type"] == "pmessage":
                    data = json.loads(message["data"])
                    event = Event.from_dict(data)
                    # NOTE: avoid double-dispatch — publish() already
                    # dispatched this event locally before sending to
                    # Redis. Only dispatch events that originated in
                    # another process.
                    if event.id in self._locally_dispatched_set:
                        continue
                    await self._dispatch_local(event)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("EventBus Redis listener error: %s. Reconnecting in 5 s…", e)
                await asyncio.sleep(5)
                if not self._running:
                    break
                # Tear down broken connection
                try:
                    if self._pubsub:
                        await self._pubsub.close()
                except Exception:
                    pass
                try:
                    if self._redis:
                        await self._redis.aclose()
                except Exception:
                    pass
                # Rebuild connection + re-subscribe
                # NOTE: redis-py 6.4 + pydantic 2.13 won't coerce a
                # ``RedisDsn`` directly — must stringify here just like
                # the initial ``connect()`` path, or the reconnect
                # loop spins forever logging
                # "'RedisDsn' object has no attribute 'decode'" and
                # the bus stays dead until a process restart.
                try:
                    # Sentinel-aware reconnect: re-resolves the CURRENT master, so
                    # after a failover the bus reconnects to the promoted node.
                    from app.core.redis_client import get_async_redis

                    # socket_timeout=None: pub/sub listen() is a long-lived blocking read.
                    self._redis = get_async_redis(socket_connect_timeout=5, socket_timeout=None)
                    self._pubsub = self._redis.pubsub()
                    await self._pubsub.psubscribe("freesdn:events:*")
                    logger.info("EventBus reconnected to Redis")
                except Exception as reconnect_err:
                    logger.error("EventBus reconnect failed: %s", reconnect_err)

    async def start_listening(self) -> None:
        """Start listening for events (alias for connect for backward compat)."""
        if not self._running and self._redis_url:
            await self.connect()

    def subscribe(
        self,
        pattern: str,
        handler: Callable[[Event], Coroutine[Any, Any, None]] | None = None,
        priority: EventPriority = EventPriority.NORMAL,
    ) -> str | Callable[..., Any]:
        """
        Subscribe to events matching pattern.

        Can be used as a decorator or directly:

        # As decorator
        @event_bus.subscribe("device.*")
        async def handle_device(event: Event):
            ...

        # Direct call
        event_bus.subscribe("device.*", handle_device)

        Patterns support wildcards:
        - * matches single segment (device.*.created)
        - # matches any segments (device.#)
        """

        def _register(fn: Callable[[Event], Coroutine[Any, Any, None]]) -> Callable[..., Any]:
            sub = EventSubscription(pattern=pattern, handler=fn, priority=priority)
            self._subscriptions[pattern].append(sub)
            logger.debug("Subscribed to %s with priority %s", pattern, priority)
            return fn

        if handler is not None:
            # Direct call: subscribe(pattern, handler)
            sub = EventSubscription(pattern=pattern, handler=handler, priority=priority)
            self._subscriptions[pattern].append(sub)
            logger.debug("Subscribed to %s with priority %s", pattern, priority)
            return sub.id
        else:
            # Decorator usage: @subscribe(pattern)
            return _register

    def unsubscribe(self, subscription_id: str) -> bool:
        """Remove subscription by ID."""
        for _pattern, subs in self._subscriptions.items():
            for sub in subs:
                if sub.id == subscription_id:
                    subs.remove(sub)
                    return True
        return False

    async def publish(self, event: Event) -> None:
        """Publish event to all subscribers and Redis.

        The Redis channel is scoped by organization_id so that a subscriber
        interested only in a specific tenant can PSUBSCRIBE to
        ``freesdn:events:{category}:{org_id}``. Events without an
        organization_id (truly system-wide events) are published on the
        'system' scope.

        NOTE: Local in-process subscribers (e.g. the WebSocket forwarder,
        automation engine) must ALWAYS be dispatched, regardless of whether
        Redis pub/sub is configured. Previously the local dispatch was put
        in an ``else`` branch — when Redis was configured the producing
        process would only get the event back via the Redis listener task,
        which (a) adds latency and (b) breaks entirely if the listener has
        died. Redis is for *cross-process* fanout, not a substitute for
        in-process delivery.

        Sequence numbering: every event is stamped with a per-process
        monotonic ``sequence`` before dispatch. Subscribers can use this
        to detect drops (gap in sequence) or reorder events that the
        Redis pubsub layer may have delivered out of order. The counter
        is held under ``self._seq_lock`` so concurrent calls produce
        strictly increasing values **within this process** — it is not
        cluster-wide. See :attr:`Event.sequence`.
        """
        # Stamp sequence under lock so concurrent publishers see strictly
        # increasing values. Only stamp if not already set (caller may have
        # forwarded an event with an existing sequence, e.g. replay tooling).
        if event.sequence == 0:
            async with self._seq_lock:
                self._seq_counter += 1
                event.sequence = self._seq_counter

        await self._store.append(event)

        # Record before local dispatch so the Redis listener (which may
        # receive our own publish back) knows to skip this event.
        if len(self._locally_dispatched_ids) == self._locally_dispatched_ids.maxlen:
            # Evict the oldest tracked id from the set when the deque is full.
            old_id = self._locally_dispatched_ids[0]
            self._locally_dispatched_set.discard(old_id)
        self._locally_dispatched_ids.append(event.id)
        self._locally_dispatched_set.add(event.id)

        # Always dispatch to local subscribers in the producing process.
        await self._dispatch_local(event)

        if self._redis:
            org_scope = event.organization_id or "system"
            channel = f"freesdn:events:{event.category.value}:{org_scope}"
            await self._redis.publish(channel, json.dumps(event.to_dict()))
            logger.debug("Published %s to Redis channel %s", event.event_type, channel)

    async def subscribe_redis_for_org(self, organization_id: str) -> None:
        """Narrow the active Redis pattern subscription to a single org.

        This is an optional helper for worker processes that only need to
        see events for a specific tenant. Callers that need cross-tenant
        visibility (e.g. super-admin dashboards) should keep the default
        wildcard subscription created in :meth:`connect`.
        """
        if not self._pubsub:
            return
        # Add a more specific pattern alongside (or instead of) the wildcard.
        await self._pubsub.psubscribe(f"freesdn:events:*:{organization_id}")

    # Per-handler budget for local dispatch. A subscriber must not be
    # allowed to wedge the publisher. Tuned generously (10s) because
    # the WS forwarder fans out to up to ``broadcast_event``'s own
    # 5s per-send timeout multiplied by O(N) clients — but each
    # handler is now invoked concurrently within its priority bucket
    # so a slow one only loses its own slot, not the bus.
    _HANDLER_TIMEOUT_SECONDS = 10.0

    async def _dispatch_local(self, event: Event) -> None:
        """Dispatch event to local subscribers.

        Concurrency model: previously this loop
        was strictly sequential — every ``await handler(event)`` blocked
        the publisher until the prior handler returned. With the WS
        forwarder as one such handler (fanning out to every connected
        client), an adapter sync that publishes 100s of
        ``device.status.changed`` events would serialize behind the
        full WS fan-out for every event. That was the single largest
        scalability ceiling in the bus.

        We now group handlers by priority bucket and run each bucket
        concurrently with ``asyncio.gather``. Buckets are awaited in
        priority order so a CRITICAL handler still completes before a
        NORMAL handler starts; within a bucket order is unspecified
        (acceptable: same-priority handlers are peers by definition).
        Each handler is wrapped in ``asyncio.wait_for`` with a 10s
        budget — a single misbehaving subscriber can no longer pin
        the publisher indefinitely.
        """
        handlers = []
        for _pattern, subs in self._subscriptions.items():
            for sub in subs:
                if sub.matches(event.event_type):
                    handlers.append((sub.priority, sub.handler))

        if not handlers:
            return

        # Group by priority preserving the documented CRITICAL→HIGH→NORMAL→LOW ordering.
        priority_order = [
            EventPriority.CRITICAL,
            EventPriority.HIGH,
            EventPriority.NORMAL,
            EventPriority.LOW,
        ]
        by_priority: dict[EventPriority, list[Callable[[Event], Coroutine[Any, Any, None]]]] = {
            p: [] for p in priority_order
        }
        for prio, handler in handlers:
            by_priority.setdefault(prio, []).append(handler)

        async def _safe_invoke(handler: Callable[[Event], Coroutine[Any, Any, None]]) -> None:
            try:
                await asyncio.wait_for(handler(event), timeout=self._HANDLER_TIMEOUT_SECONDS)
            except TimeoutError:
                logger.warning(
                    "Event handler timed out after %.1fs for event_type=%s",
                    self._HANDLER_TIMEOUT_SECONDS,
                    event.event_type,
                )
            except Exception as e:
                logger.error("Error in event handler for %s: %s", event.event_type, e)

        for prio in priority_order:
            bucket = by_priority.get(prio) or []
            if not bucket:
                continue
            # ``return_exceptions=True`` is belt-and-braces: ``_safe_invoke``
            # already swallows, but if a future refactor lets an exception
            # escape, gather still completes the sibling handlers.
            await asyncio.gather(
                *(_safe_invoke(h) for h in bucket),
                return_exceptions=True,
            )

    async def get_history(self, limit: int = 100) -> list[Event]:
        return await self._store.get_recent(limit)

    async def get_by_correlation(self, correlation_id: str) -> list[Event]:
        return await self._store.get_by_correlation(correlation_id)


# Global event bus instance
_event_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Get or create global event bus."""
    global _event_bus
    if _event_bus is None:
        from app.core.config import settings

        _event_bus = EventBus(redis_url=getattr(settings, "REDIS_URL", None))
    return _event_bus


# SECURITY: every factory and publisher in this
# module takes an explicit ``organization_id`` keyword and threads it
# into ``Event(...)``. The WS broadcast router
# (``endpoints/websocket.py::_should_receive``) fails closed when
# ``event.organization_id`` is None, so any call site that omits the
# kwarg will silently drop the event from cross-tenant routing.
#
# Most internal call sites have the producing org's id at construction
# time (controller.site.organization_id / alert.organization_id, etc.).
# For surfaces that only carry a Device, ``Device`` itself has no
# ``organization_id`` column (only ``site_id``) — use the helper below
# to resolve org id from a ``site_id`` in one query.
async def org_id_for_site(session: Any, site_id: Any) -> str | None:
    """Resolve ``Site.organization_id`` for the given ``site_id``.

    Returns the stringified org UUID or ``None`` if the site does not
    exist, ``site_id`` is None, or the lookup raises. Costs one indexed
    lookup; safe to call from event-publish call sites where
    ``device.site`` is not eagerly loaded.

    Failure is swallowed because the caller treats this as a routing
    hint, not a correctness invariant — if the resolver fails the
    Event will simply lack an ``organization_id`` and the fail-closed
    WS router will drop it (no leak, just a missed delivery). That's
    strictly better than letting a transient DB issue cascade into
    a publish-time exception that takes out the producer's flow.

    Imports ``Site`` locally to avoid a model-import cycle when this
    module is imported from ``app.core.config``.
    """
    if site_id is None:
        return None
    try:
        from sqlalchemy import select as _sa_select

        from app.models.core import Site

        result = await session.execute(_sa_select(Site.organization_id).where(Site.id == site_id))
        row = result.scalar_one_or_none()
        return str(row) if row else None
    except Exception:
        logger.debug(
            "org_id_for_site lookup failed for site_id=%s",
            site_id,
            exc_info=True,
        )
        return None


# Event factory functions.
#
# Every factory takes an explicit ``organization_id`` keyword.
# See the module-level SECURITY note above for the threat model.
def device_event(
    event_type: str,
    device_id: str,
    site_id: str | None = None,
    *,
    organization_id: str | None = None,
    **payload: Any,
) -> Event:
    """Create a device-related event. ``organization_id`` is required for
    cross-tenant WS routing; passing None makes the event invisible to all
    WS clients (fail-closed)."""
    return Event(
        event_type=f"device.{event_type}",
        category=EventCategory.DEVICE,
        organization_id=organization_id,
        payload={"device_id": device_id, "site_id": site_id, **payload},
    )


def alert_event(
    severity: str,
    message: str,
    source: str,
    *,
    organization_id: str | None = None,
    **payload: Any,
) -> Event:
    """Create an alert event. ``organization_id`` is required for
    cross-tenant WS routing (see :func:`device_event`)."""
    priority = EventPriority.CRITICAL if severity == "critical" else EventPriority.HIGH
    return Event(
        event_type=f"alert.{severity}",
        category=EventCategory.SECURITY,
        priority=priority,
        organization_id=organization_id,
        payload={"message": message, "source": source, **payload},
    )


def discovery_event(
    event_type: str,
    *,
    organization_id: str | None = None,
    **payload: Any,
) -> Event:
    """Create a discovery-related event. ``organization_id`` is required
    for cross-tenant WS routing (see :func:`device_event`)."""
    return Event(
        event_type=f"discovery.{event_type}",
        category=EventCategory.SYSTEM,
        organization_id=organization_id,
        payload=payload,
    )


def task_event(
    event_type: str,
    task_id: str,
    *,
    organization_id: str | None = None,
    **payload: Any,
) -> Event:
    """Create a background task event. ``organization_id`` is required
    for cross-tenant WS routing (see :func:`device_event`)."""
    return Event(
        event_type=f"task.{event_type}",
        category=EventCategory.TASK,
        organization_id=organization_id,
        payload={"task_id": task_id, **payload},
    )


# ===========================================
# EventType enum for backwards compatibility
# ===========================================


class EventType(StrEnum):
    """Event type enum for backwards compatibility."""

    # Device events
    DEVICE_DISCOVERED = "device.discovered"
    DEVICE_UPDATED = "device.updated"
    DEVICE_DELETED = "device.deleted"
    DEVICE_STATUS_CHANGED = "device.status.changed"

    # Controller events
    CONTROLLER_CONNECTED = "controller.connected"
    CONTROLLER_DISCONNECTED = "controller.disconnected"
    CONTROLLER_SYNC_STARTED = "controller.sync.started"
    CONTROLLER_SYNC_COMPLETED = "controller.sync.completed"
    CONTROLLER_SYNC_FAILED = "controller.sync.failed"

    # Discovery events
    DISCOVERY_STARTED = "discovery.started"
    DISCOVERY_PROGRESS = "discovery.progress"
    DISCOVERY_COMPLETED = "discovery.completed"
    DISCOVERY_FAILED = "discovery.failed"

    # Alert events
    ALERT_CREATED = "alert.created"
    ALERT_RESOLVED = "alert.resolved"

    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"


# ===========================================
# Helper publish functions
# ===========================================


async def publish_device_event(
    event_type: str,
    device_id: str,
    site_id: str | None = None,
    *,
    organization_id: str | None = None,
    **payload: Any,
) -> None:
    """Publish a device event. ``organization_id`` is required for
    cross-tenant WS routing (see :func:`device_event`)."""
    bus = get_event_bus()
    event = Event(
        event_type=event_type,
        category=EventCategory.DEVICE,
        organization_id=organization_id,
        payload={"device_id": device_id, "site_id": site_id, **payload},
    )
    await bus.publish(event)


async def publish_controller_event(
    event_type: str,
    controller_id: str,
    *,
    organization_id: str | None = None,
    **payload: Any,
) -> None:
    """Publish a controller event. ``organization_id`` is required for
    cross-tenant WS routing (see :func:`device_event`)."""
    bus = get_event_bus()
    event = Event(
        event_type=event_type,
        category=EventCategory.CONTROLLER,
        organization_id=organization_id,
        payload={"controller_id": controller_id, **payload},
    )
    await bus.publish(event)


async def publish_discovery_event(
    event_type: str,
    *,
    organization_id: str | None = None,
    **payload: Any,
) -> None:
    """Publish a discovery event. ``organization_id`` is required for
    cross-tenant WS routing (see :func:`device_event`)."""
    bus = get_event_bus()
    event = Event(
        event_type=event_type,
        category=EventCategory.SYSTEM,
        organization_id=organization_id,
        payload=payload,
    )
    await bus.publish(event)


async def publish_adapter_event(
    event_type: str,
    *,
    adapter_id: str,
    organization_id: str | None = None,
    priority: EventPriority = EventPriority.NORMAL,
    category: EventCategory = EventCategory.DEVICE,
    **payload: Any,
) -> None:
    """Publish an adapter-write event (non-staging adapters).

    Twin of :func:`publish_controller_event` for adapters that don't go
    through :class:`AdapterStagingService` (cameras, voice, future
    device-direct adapters). The AdapterStagingService publishes
    ``controller.change.*`` events for every staged write; this helper
    is for adapters whose writes go straight to the device (snapshot
    capture, PTZ command, call originate, extension provision, etc.)
    where the staging table doesn't apply because the operation is
    transient.

    Several device adapters (Hikvision / ONVIF / FreePBX / Grandstream)
    historically wrote directly to devices without ever emitting events,
    making them invisible to
    the automation engine, WebSocket forwarder, plugins, and any
    notification rule that wants to react to a camera snapshot
    failure or a PTZ command. This helper closes the gap with one
    call site per write method.

    Best-effort: failures are logged but never raised. The actual
    device action already happened; losing observability is
    preferable to losing operator confidence in the write.

    Args:
        event_type: Dot-notation type like ``"camera.snapshot.captured"``
            or ``"voip.call.originated"``. Caller chooses the taxonomy.
        adapter_id: Vendor adapter id, e.g. ``"hikvision"``,
            ``"unifi_protect"``, ``"freepbx"``. Used by metric labels
            and automation rule conditions.
        organization_id: Tenant id (stringified UUID). Required for
            multi-tenant routing through the Redis pub/sub channel.
        priority: Event priority. Default NORMAL; lift to HIGH for
            device-altering operations (PTZ goto-preset, recording
            schedule change).
        category: Default DEVICE. Use NETWORK / SECURITY when
            appropriate.
        **payload: Arbitrary additional fields (camera_id, action,
            channel, etc.).
    """
    import logging

    try:
        full_payload = dict(payload)
        full_payload["adapter_id"] = adapter_id
        await get_event_bus().publish(
            Event(
                event_type=event_type,
                category=category,
                priority=priority,
                payload=full_payload,
                organization_id=organization_id,
                source=f"adapter:{adapter_id}",
            )
        )
    except Exception:
        logging.getLogger(__name__).warning(
            "publish_adapter_event failed for %s (adapter=%s)",
            event_type,
            adapter_id,
            exc_info=True,
        )


# Create a lazy-loaded global event bus instance
class _LazyEventBus:
    """Lazy-loaded event bus that initializes on first access.

    NOTE: This shim now defers to :func:`get_event_bus` so that
    ``app.core.events.event_bus`` and ``get_event_bus()`` always resolve
    to the *same* singleton. Previously they tracked separate instances,
    which meant code that called ``event_bus.subscribe(...)`` registered
    on a different bus than code that called
    ``get_event_bus().publish(...)`` — so neither saw each other's
    events. This was the root cause of the "WebSocket forwarder never
    fires" bug.
    """

    def __getattr__(self, name: str) -> Any:
        return getattr(get_event_bus(), name)


# Global event bus instance (lazy-loaded)
event_bus = _LazyEventBus()

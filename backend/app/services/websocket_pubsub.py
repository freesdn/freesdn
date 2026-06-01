# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Cross-instance WebSocket fan-out for targeted messages.

The broadcast path (``manager.broadcast_event``) is already
cross-instance correct because it's driven by the EventBus, which
publishes to Redis pub/sub and replays remote events on every pod
(``app/core/events.py``). Direct targeted sends —
``send_to_user``, ``send_personal`` — are NOT routed through the bus
and so are stuck on the pod that called them. If a user has tabs
open on pod A and pod B, a ``send_to_user`` triggered on pod B may
never reach the pod-A tabs.

This module adds a thin Redis pub/sub layer that fans those targeted
sends across all pods. Self-published messages are dropped via a
per-process ``pod_id`` so we don't double-deliver on the originating
pod.

Wire-up (lifecycle):
    bus = WSCrossInstanceBus(redis_url=...)
    await bus.connect(on_targeted=manager._deliver_remote_to_user)
    # ... app runs ...
    await bus.disconnect()

Sender:
    await bus.publish_to_user(user_id, payload)

Channel layout:
    freesdn:ws:user:{user_id}   — targeted single-user fan-out
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import redis.asyncio as redis

logger = logging.getLogger(__name__)

# Channel namespace. Kept distinct from the event bus' ``freesdn:events:*``
# pattern so a buggy event-bus subscriber can never receive raw WS
# targeted-message envelopes (they're not Event dataclasses).
_CHANNEL_PREFIX = "freesdn:ws:user:"
_PATTERN = "freesdn:ws:user:*"

# Bounded reconnect backoff — same shape as EventBus._listen_redis.
_RECONNECT_DELAY_SEC = 5.0

# Type alias for the delivery callback the ConnectionManager registers.
TargetedHandler = Callable[[str, dict[str, Any]], Awaitable[None]]


class WSCrossInstanceBus:
    """Redis pub/sub fan-out for targeted WebSocket sends.

    One instance per process. Each process generates its own
    ``pod_id`` at construction time so it can dedupe its own
    publishes (Redis pub/sub echoes the message back to subscribers
    on the same client connection — without the pod-id tag we'd
    double-deliver on the originating pod).
    """

    def __init__(self, redis_url: str | None) -> None:
        self._redis_url = str(redis_url) if redis_url else None
        self.pod_id: str = uuid.uuid4().hex  # per-process; public for tests
        self._redis: redis.Redis | None = None
        self._pubsub: redis.client.PubSub | None = None
        self._listener_task: asyncio.Task[None] | None = None
        self._running: bool = False
        self._on_targeted: TargetedHandler | None = None

    @property
    def connected(self) -> bool:
        return self._running and self._redis is not None

    async def connect(self, *, on_targeted: TargetedHandler) -> None:
        """Connect to Redis and start the listener task.

        ``on_targeted`` is invoked with ``(user_id, payload)`` for every
        remote message (i.e. messages NOT originating from this pod).
        If ``redis_url`` was not provided at construction time, this
        is a no-op — the manager falls back to single-pod behaviour
        with a debug log.
        """
        if not self._redis_url:
            logger.info(
                "WSCrossInstanceBus: REDIS_URL not configured — running "
                "single-pod (targeted sends won't fan out)",
            )
            return

        self._on_targeted = on_targeted
        # socket_connect_timeout bounds the connect so a black-holed Redis fails
        # fast at boot instead of blocking startup; no socket_timeout (would break
        # the long-lived pub/sub listen).
        # Sentinel-aware (HA): master_for re-resolves the promoted master on
        # reconnect, so cross-instance WS fan-out follows a Redis/Valkey failover.
        from app.core.redis_client import get_async_redis

        # socket_timeout=None: pub/sub listen() is a long-lived blocking read.
        self._redis = get_async_redis(socket_connect_timeout=5, socket_timeout=None)
        self._pubsub = self._redis.pubsub()
        await self._pubsub.psubscribe(_PATTERN)
        self._running = True
        self._listener_task = asyncio.create_task(self._listen())

        # If the listener dies on a Redis hiccup, targeted cross-pod
        # sends silently break until the next connect(). Surface the
        # failure in logs so ops can spot it instead of debugging
        # "user X isn't receiving WS events on pod B".
        def _on_listener_done(t: asyncio.Task[Any]) -> None:
            if t.cancelled():
                return
            e = t.exception()
            if e is not None:
                logger.error(
                    "WSCrossInstanceBus listener task crashed (pod=%s): %s",
                    self.pod_id[:8],
                    e,
                    exc_info=e,
                )

        self._listener_task.add_done_callback(_on_listener_done)
        logger.info(
            "WSCrossInstanceBus connected (pod_id=%s, pattern=%s)",
            self.pod_id[:8],
            _PATTERN,
        )

    async def disconnect(self) -> None:
        """Stop listening and close the Redis connection."""
        self._running = False
        if self._listener_task:
            self._listener_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._listener_task
            self._listener_task = None
        if self._pubsub:
            with contextlib.suppress(Exception):
                await self._pubsub.unsubscribe()
                await self._pubsub.close()
            self._pubsub = None
        if self._redis:
            with contextlib.suppress(Exception):
                await self._redis.aclose()
            self._redis = None
        logger.info("WSCrossInstanceBus disconnected")

    async def publish_to_user(
        self,
        user_id: str,
        payload: dict[str, Any],
    ) -> None:
        """Publish a targeted user message to every pod.

        No-op if Redis isn't connected — the local send_to_user has
        already fanned out to this pod's connections, and there's no
        remote pod we could reach. This matches the single-node
        deployment story.
        """
        if not self.connected or self._redis is None:
            return

        envelope = {
            "source_pod_id": self.pod_id,
            "user_id": user_id,
            "payload": payload,
        }
        try:
            await self._redis.publish(
                f"{_CHANNEL_PREFIX}{user_id}",
                json.dumps(envelope, default=str),
            )
        except Exception:
            logger.exception(
                "WSCrossInstanceBus: publish_to_user failed for %s",
                user_id,
            )

    async def _listen(self) -> None:
        """Listener loop with automatic reconnection.

        Reconnect cadence mirrors EventBus._listen_redis so an
        operator who sees a Redis blip in one log sees the same
        recovery story in the other.
        """
        while self._running:
            try:
                if self._pubsub is None:
                    raise RuntimeError("pubsub closed")
                message = await self._pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                )
                if message and message["type"] == "pmessage":
                    await self._handle_message(message)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning(
                    "WSCrossInstanceBus listener error: %s — reconnecting in %ds",
                    exc,
                    int(_RECONNECT_DELAY_SEC),
                )
                await asyncio.sleep(_RECONNECT_DELAY_SEC)
                if not self._running:
                    break
                await self._reconnect()

    async def _handle_message(self, message: dict[str, Any]) -> None:
        try:
            envelope = json.loads(message["data"])
        except (json.JSONDecodeError, TypeError):
            logger.debug("WSCrossInstanceBus: dropping non-JSON message")
            return

        # Drop self-published messages — we already delivered locally.
        if envelope.get("source_pod_id") == self.pod_id:
            return

        user_id = envelope.get("user_id")
        payload = envelope.get("payload")
        if not user_id or not isinstance(payload, dict):
            logger.debug("WSCrossInstanceBus: malformed envelope, ignoring")
            return

        if self._on_targeted is None:
            return
        try:
            await self._on_targeted(user_id, payload)
        except Exception:
            logger.exception(
                "WSCrossInstanceBus: handler failed for user %s",
                user_id,
            )

    async def _reconnect(self) -> None:
        """Rebuild Redis + pubsub after a connection blip."""
        with contextlib.suppress(Exception):
            if self._pubsub:
                await self._pubsub.close()
        with contextlib.suppress(Exception):
            if self._redis:
                await self._redis.aclose()
        try:
            # Sentinel-aware reconnect: re-resolves the CURRENT master after a failover.
            from app.core.redis_client import get_async_redis

            # socket_timeout=None: pub/sub listen() is a long-lived blocking read.
            self._redis = get_async_redis(socket_connect_timeout=5, socket_timeout=None)
            self._pubsub = self._redis.pubsub()
            await self._pubsub.psubscribe(_PATTERN)
            logger.info("WSCrossInstanceBus reconnected to Redis")
        except Exception as exc:
            logger.error("WSCrossInstanceBus reconnect failed: %s", exc)


# Module-global singleton — created lazily by ``get_ws_pubsub`` so that
# importing this module does not connect to Redis. Lifecycle managed by
# app.main:lifespan via ``connect_ws_pubsub`` / ``disconnect_ws_pubsub``.
_singleton: WSCrossInstanceBus | None = None


def get_ws_pubsub() -> WSCrossInstanceBus:
    """Return the process-wide cross-instance WS bus."""
    global _singleton
    if _singleton is None:
        from app.core.config import settings

        _singleton = WSCrossInstanceBus(
            redis_url=str(settings.REDIS_URL) if settings.REDIS_URL else None,
        )
    return _singleton


def reset_ws_pubsub_for_tests() -> None:
    """Drop the singleton between tests — call from fixture teardown."""
    global _singleton
    _singleton = None

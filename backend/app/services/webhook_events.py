# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Event bus to webhook delivery
=======================================

``PersistentWebhookService.dispatch_event`` was written, documented as "called
by other services", and never called by anything. Every configured webhook --
and every n8n trigger, generic integration and template built on one -- only
ever received the deliveries an operator triggered by pressing "Test". A
device going offline, an alert firing, a sync failing: none of it left the
building.

This module is the missing wire:

* :class:`WebhookEventForwarder` subscribes to the event bus in each API
  process. Every API worker sees every event (locally or over Redis pub/sub),
  so the forwarder keeps an in-memory map of which organisations have enabled
  webhooks for which events, ignores the rest without touching Redis or the
  database, and claims each matching event id in Redis so exactly ONE worker
  enqueues it.
* The ``app.tasks.webhooks.deliver_event`` Celery task does the delivery off
  the request path: org-scoped lookup, signed POST through the SSRF guard,
  delivery log, retries with backoff, dead-letter after the last one.

Tenancy is fail-closed: an event without an ``organization_id`` reaches no
webhook, because there is no tenant it could be delivered on behalf of.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Iterable
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# How long the per-process subscription map is trusted before it is re-read.
# A webhook created, edited or disabled starts or stops receiving within this.
SUBSCRIPTION_CACHE_SECONDS = 30.0

# The Redis claim outlives any plausible pub/sub skew between API workers.
_CLAIM_TTL_SECONDS = 3600
_CLAIM_PREFIX = "webhooks:event-claim:"

# Enqueue attempts for a claimed event before it is reported as dropped. The
# whole loop runs in a worker thread (handle -> asyncio.to_thread).
_ENQUEUE_ATTEMPTS = 3
_ENQUEUE_BACKOFF_SECONDS = 0.5

# Event types that never go to a webhook. ``webhook.*`` would let a delivery
# event trigger another delivery.
_NEVER_FORWARDED_PREFIXES = ("webhook.",)


def is_progress_event(event_type: str) -> bool:
    """Progress ticks (``pbx.sync.progress``, ``discovery.scan_progress``...).

    A single sync publishes dozens of them. They are deliverable when a webhook
    names them explicitly, but an "all events" webhook does not receive them:
    they would turn one sync into dozens of HTTP posts.
    """
    return event_type.endswith("progress")


def webhook_wants(event_types: Iterable[str] | None, event_type: str) -> bool:
    """Does a webhook subscribed to ``event_types`` want ``event_type``?

    * empty / None -> every event except progress ticks (the UI promises
      "leave empty to receive all events");
    * ``"*"`` or ``"#"`` -> every event, progress included;
    * ``"device.*"`` or ``"device.#"`` -> every event under ``device.``, at any
      depth. This deliberately differs from the bus's single-segment ``*``:
      the n8n node offers ``device.*`` as "Any Device Event", and the event a
      person most wants from that, ``device.status.changed``, is two segments
      deep;
    * anything else -> exact match.
    """
    if any(event_type.startswith(p) for p in _NEVER_FORWARDED_PREFIXES):
        return False
    patterns = [p.strip() for p in (event_types or []) if p and p.strip()]
    if not patterns:
        return not is_progress_event(event_type)
    for pattern in patterns:
        if pattern in ("*", "#"):
            return True
        if pattern.endswith((".*", ".#")):
            if event_type.startswith(pattern[:-1]):
                return True
            continue
        if pattern == event_type:
            return True
    return False


def build_envelope(event: Any) -> dict[str, Any]:
    """The JSON body a webhook receives for a bus event.

    Same top-level ``event`` / ``timestamp`` / ``data`` keys as the "Test"
    delivery, so a receiver written against the test payload parses real ones.
    """
    timestamp: Any = getattr(event, "timestamp", None)
    category = getattr(event, "category", None)
    return {
        "id": str(event.id),
        "event": event.event_type,
        "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp,
        "organization_id": str(event.organization_id) if event.organization_id else None,
        "category": getattr(category, "value", category),
        "source": getattr(event, "source", None),
        "correlation_id": getattr(event, "correlation_id", None),
        "data": dict(event.payload or {}),
    }


class WebhookEventForwarder:
    """Hands bus events that some enabled webhook wants to the delivery task."""

    def __init__(self, bus: Any | None = None) -> None:
        self._bus = bus
        self._subscription_id: str | None = None
        self._subscriptions: dict[str, list[list[str]]] = {}
        self._loaded_at = 0.0
        self._refresh_lock: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None
        self._redis: Any = None
        self.claimed = 0
        self.enqueued = 0
        self.enqueue_failed = 0

    # -- lifecycle ---------------------------------------------------------

    def _get_bus(self) -> Any:
        if self._bus is None:
            from app.core.events import get_event_bus

            self._bus = get_event_bus()
        return self._bus

    async def start(self) -> None:
        if self._subscription_id is not None:
            return
        # Subscribe first. Loading the subscription map needs the database; if
        # that failed at startup (a restarting Postgres, a slow PgBouncer) and
        # aborted start(), the forwarder never subscribed and no webhook got an
        # event until the API was restarted. Now a failed first load only leaves
        # the map empty and stale, so the first event retries it.
        self._subscription_id = self._get_bus().subscribe("*", self.handle)
        logger.info("Webhook event forwarder subscribed to the event bus")
        try:
            await self.refresh()
        except Exception:
            self._loaded_at = 0.0
            logger.warning(
                "Webhook subscriptions not loaded at startup; retrying on the first event",
                exc_info=True,
            )

    async def stop(self) -> None:
        if self._subscription_id is not None:
            with contextlib.suppress(Exception):
                self._get_bus().unsubscribe(self._subscription_id)
            self._subscription_id = None
        if self._redis is not None:
            with contextlib.suppress(Exception):
                self._redis.close()
            self._redis = None

    # -- subscription map --------------------------------------------------

    async def refresh(self) -> None:
        """Re-read which organisations have enabled webhooks for what."""
        from sqlalchemy import select

        from app.db.session import async_session_factory
        from app.models.webhooks import Webhook

        async with async_session_factory() as session:
            rows = (
                await session.execute(
                    select(Webhook.organization_id, Webhook.event_types).where(
                        Webhook.enabled.is_(True),
                        Webhook.organization_id.isnot(None),
                    )
                )
            ).all()
        subscriptions: dict[str, list[list[str]]] = {}
        for org_id, event_types in rows:
            subscriptions.setdefault(str(org_id), []).append(list(event_types or []))
        self._subscriptions = subscriptions
        self._loaded_at = time.monotonic()

    def invalidate(self) -> None:
        """Forget the map so the next event re-reads it (after a webhook edit)."""
        self._loaded_at = 0.0

    def _lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._refresh_lock is None or self._lock_loop is not loop:
            self._refresh_lock = asyncio.Lock()
            self._lock_loop = loop
        return self._refresh_lock

    async def _ensure_fresh(self) -> None:
        if time.monotonic() - self._loaded_at < SUBSCRIPTION_CACHE_SECONDS:
            return
        async with self._lock():
            if time.monotonic() - self._loaded_at < SUBSCRIPTION_CACHE_SECONDS:
                return
            try:
                await self.refresh()
            except Exception:
                # Keep serving the last good map; try again next TTL.
                self._loaded_at = time.monotonic()
                logger.warning("Could not refresh webhook subscriptions", exc_info=True)

    def wants(self, event: Any) -> bool:
        org_id = getattr(event, "organization_id", None)
        if not org_id:
            return False
        return any(
            webhook_wants(event_types, event.event_type)
            for event_types in self._subscriptions.get(str(org_id), [])
        )

    # -- handling ----------------------------------------------------------

    async def handle(self, event: Any) -> None:
        await self._ensure_fresh()
        if not self.wants(event):
            return
        envelope = build_envelope(event)
        await asyncio.to_thread(self._claim_and_enqueue, envelope)

    def _redis_client(self) -> Any:
        if self._redis is None:
            from app.core.redis_client import get_sync_redis

            self._redis = get_sync_redis()
        return self._redis

    def _claim_and_enqueue(self, envelope: dict[str, Any]) -> None:
        """Exactly one API worker wins the claim and enqueues the delivery.

        Without a positively acknowledged claim nothing is enqueued: the broker
        is the same Valkey, so if the claim cannot be written the enqueue would
        not have reached a worker either.
        """
        event_id = envelope["id"]
        try:
            won = self._redis_client().set(
                _CLAIM_PREFIX + event_id, "1", nx=True, ex=_CLAIM_TTL_SECONDS
            )
        except Exception:
            self._redis = None
            logger.warning(
                "Webhook delivery for event %s (%s) skipped: event claim unavailable",
                event_id,
                envelope["event"],
                exc_info=True,
            )
            return
        if won is not True:
            return
        self.claimed += 1
        from app.tasks.webhooks import deliver_event

        # No queue=: an explicit queue on apply_async overrides the task's own
        # routing. It routes to "default", which every tier's workers consume.
        #
        # This hop is where at-least-once begins. The bus itself is not durable,
        # and every other worker has already seen this event and lost the claim,
        # so a failed enqueue here used to lose the event silently, with the
        # claim still held for an hour. Try a few times; if the broker still
        # refuses, release the claim and say plainly that the event was dropped.
        for attempt in range(_ENQUEUE_ATTEMPTS):
            try:
                deliver_event.apply_async(args=[envelope])
            except Exception:
                if attempt + 1 < _ENQUEUE_ATTEMPTS:
                    time.sleep(_ENQUEUE_BACKOFF_SECONDS * (attempt + 1))
                    continue
                with contextlib.suppress(Exception):
                    self._redis_client().delete(_CLAIM_PREFIX + event_id)
                self.enqueue_failed += 1
                logger.error(
                    "Webhook delivery for event %s (%s) NOT queued: the task broker "
                    "refused it %d times; webhooks will not receive this event",
                    event_id,
                    envelope["event"],
                    _ENQUEUE_ATTEMPTS,
                    exc_info=True,
                )
                return
            self.enqueued += 1
            return


webhook_event_forwarder = WebhookEventForwarder()

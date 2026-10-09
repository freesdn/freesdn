# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Publish committed bell events, with recoverable publication attempts.

Each due row is locked through publication and commit. A competing worker skips
that row. A crash after Redis accepts an event but before commit can republish
it with the same ID. Redis pub/sub is not a durable subscriber acknowledgment;
the persisted bell row remains the source of truth for disconnected clients.
"""

import asyncio
import json
import logging
import time
from datetime import UTC, datetime, timedelta

from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from sqlalchemy import exists, func, select

from app.core.events import Event, EventCategory, EventPriority
from app.core.redis_client import get_async_redis
from app.db.session import CelerySessionLocal
from app.models.core import Organization, User
from app.models.notification import InAppNotification
from app.models.notification_outbox import InAppNotificationEvent

logger = logging.getLogger(__name__)


def notification_event(notification: InAppNotification) -> Event:
    """Use the durable notification identity, including on ambiguous retries."""
    severity = notification.severity
    return Event(
        id=str(notification.id),
        correlation_id=str(notification.id),
        event_type="notification.created",
        category=EventCategory.USER,
        priority=EventPriority.CRITICAL
        if severity == "critical"
        else EventPriority.HIGH
        if severity == "error"
        else EventPriority.NORMAL,
        organization_id=str(notification.organization_id) if notification.organization_id else None,
        timestamp=notification.created_at,
        source="notification-outbox",
        payload={
            "user_id": str(notification.user_id),
            "notification": {
                "id": str(notification.id),
                "user_id": str(notification.user_id),
                "title": notification.title,
                "body": notification.body,
                "category": notification.category,
                "severity": notification.severity,
                "action_url": notification.action_url,
                "data": notification.data or {},
                "read": notification.read,
                "created_at": notification.created_at.isoformat(),
            },
        },
    )


async def publish_pending_notifications(limit: int = 50) -> dict[str, int]:
    """Drain a bounded batch; each row has an independent transaction.

    No subscriber or a failed/uncertain publish leaves the row pending with
    capped backoff. Database failures propagate, retaining the last committed
    state for the next beat. Current recipient/scope checks are not a fence
    against an administrative edit after the check and before publication.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Notification publication limit must be between 1 and 100")
    counts = {"published": 0, "deferred": 0, "suppressed": 0}
    deadline = time.monotonic() + 20
    client = get_async_redis(
        socket_timeout=2, socket_connect_timeout=2, retry=Retry(NoBackoff(), 0)
    )
    try:
        for _ in range(limit):
            if time.monotonic() >= deadline:
                break
            async with CelerySessionLocal() as db, db.begin():
                pending = (
                    await db.execute(
                        select(InAppNotificationEvent)
                        .where(
                            InAppNotificationEvent.status == "pending",
                            InAppNotificationEvent.next_attempt_at <= func.now(),
                        )
                        .order_by(
                            InAppNotificationEvent.next_attempt_at,
                            InAppNotificationEvent.notification_id,
                        )
                        .with_for_update(skip_locked=True)
                        .limit(1)
                    )
                ).scalar_one_or_none()
                if pending is None:
                    break
                statement = (
                    select(InAppNotification)
                    .join(User, User.id == InAppNotification.user_id)
                    .where(
                        InAppNotification.id == pending.notification_id,
                        InAppNotification.user_id == pending.user_id,
                        InAppNotification.organization_id == pending.organization_id,
                        InAppNotification.read.is_(False),
                        InAppNotification.dismissed.is_(False),
                        User.organization_id == pending.organization_id,
                        User.is_active.is_(True),
                        User.deleted_at.is_(None),
                    )
                )
                if pending.organization_id is not None:
                    statement = statement.where(
                        exists(
                            select(Organization.id).where(
                                Organization.id == pending.organization_id,
                                Organization.is_active.is_(True),
                                Organization.deleted_at.is_(None),
                            )
                        )
                    )
                notification = (await db.execute(statement)).scalar_one_or_none()
                now = datetime.now(UTC)
                if notification is None:
                    pending.status = "suppressed"
                    pending.suppressed_at = now
                    pending.last_failure = "recipient_or_notification_ineligible"
                    outcome = "suppressed"
                else:
                    pending.attempts = min(pending.attempts + 1, 2_147_483_647)
                    event = notification_event(notification)
                    channel = "freesdn:events:user:" + (event.organization_id or "system")
                    try:
                        async with asyncio.timeout(3):
                            subscribers = await client.publish(channel, json.dumps(event.to_dict()))
                        accepted = type(subscribers) is int and subscribers > 0
                        pending.last_failure = None if accepted else "no_subscribers"
                    except Exception:
                        accepted = False
                        pending.last_failure = "publication_unavailable"
                        logger.warning(
                            "In-app event publication unavailable; pending event retained"
                        )
                    if accepted:
                        pending.status = "published"
                        pending.published_at = now
                        outcome = "published"
                    else:
                        pending.next_attempt_at = now + timedelta(
                            seconds=min(60, 2 ** min(pending.attempts, 6))
                        )
                        outcome = "deferred"
            # Count only after the owning transaction has committed successfully.
            counts[outcome] += 1
    finally:
        try:
            await client.aclose()
        except Exception:
            logger.warning("In-app event publisher connection cleanup unavailable")
    return counts

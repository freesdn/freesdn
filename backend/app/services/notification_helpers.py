# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Notification Dispatch Helpers
==========================================

Shared helper to dispatch notifications from alert rules and SLA breaches.
Parses the notification_channels JSONB config and calls NotificationService.

Retry behavior
--------------
``asyncio.gather`` runs all channels concurrently. Before the retry queue
existed, any transient SMTP / Slack 5xx returned
``DeliveryResult(success=False)`` and was silently dropped. Now, every
unsuccessful result whose error shape looks transient is enqueued onto
:func:`app.tasks.notification_retry.schedule_retry` for exponential
backoff. Permanent failures (header injection, SSRF, 4xx-except-429)
short-circuit and skip the retry queue. See ``notification_retry.py``
for the classification logic.
"""

import asyncio
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.notification import NotificationDelivery
from app.services.notification import (
    DeliveryResult,
    DeliveryStatus,
    NotificationChannel,
    NotificationService,
)

logger = logging.getLogger(__name__)

# Channel name → NotificationChannel enum mapping
_CHANNEL_MAP: dict[str, NotificationChannel] = {
    "email": NotificationChannel.EMAIL,
    "slack": NotificationChannel.SLACK,
    "teams": NotificationChannel.TEAMS,
    "webhook": NotificationChannel.WEBHOOK,
    "in_app": NotificationChannel.IN_APP,
    "sms": NotificationChannel.SMS,
}


async def dispatch_notifications(
    db: AsyncSession,
    channels_config: dict[str, Any] | None,
    title: str,
    body: str,
    organization_id: UUID | None = None,
    body_html: str | None = None,
) -> list[DeliveryResult]:
    """
    Parse a notification_channels JSONB config and send notifications.

    The config format (from AlertRule / SLAPolicy models):
        {
            "email": {"to": ["admin@example.com", "ops@example.com"]},
            "slack": {"channel": "#alerts"},
            "webhook": {"url": "https://..."},
            "teams": {"webhook_url": "https://..."},
        }

    Returns a list of DeliveryResult for each send attempt. Transient
    failures are also enqueued onto the retry queue — the original
    ``DeliveryResult(success=False)`` is still returned so callers can
    surface the first-attempt error to the user immediately.
    """
    if not channels_config:
        return []

    service = NotificationService(db)
    results: list[DeliveryResult] = []

    # Build all send tasks, then dispatch concurrently
    async def _send_one(
        ch_name: str, ch_enum: NotificationChannel, recipient: str
    ) -> tuple[str, NotificationChannel, str, DeliveryResult] | None:
        try:
            result = await service.send(
                channel=ch_enum,
                recipient=recipient,
                title=title,
                body=body,
                body_html=body_html,
                organization_id=organization_id,
            )
            if result.success:
                logger.debug("Notification sent via %s to %s", ch_name, recipient)
            else:
                logger.warning(
                    "Notification failed via %s to %s: %s",
                    ch_name,
                    recipient,
                    result.error,
                )
            return (ch_name, ch_enum, recipient, result)
        except Exception as e:
            logger.error("Error sending notification via %s: %s", ch_name, e)
            return None

    # The in_app channel has NO provider in NotificationService.send (only
    # email/slack/teams/webhook are registered), so routing it through send()
    # always returns "No provider configured for channel: in_app" and the bell
    # row is never written. Write the real InAppNotification row directly via
    # create_in_app (which also publishes the notification.created event for the
    # realtime toast). Handled before the generic provider loop so it doesn't
    # produce a spurious FAILED DeliveryResult / retry-queue entry.
    in_app_cfg = channels_config.get("in_app")
    if in_app_cfg is not None:
        for uid in _extract_recipients("in_app", in_app_cfg):
            try:
                await service.create_in_app(
                    user_id=UUID(str(uid)),
                    title=title,
                    body=body,
                    organization_id=organization_id,
                    commit=True,
                )
                results.append(
                    DeliveryResult(
                        success=True,
                        channel=NotificationChannel.IN_APP,
                        status=DeliveryStatus.SENT,
                    )
                )
            except Exception as e:  # one bad user_id must not abort the batch
                logger.warning("in_app notification failed for user %s: %s", uid, e)

    # Load the org's configured providers into the service BEFORE sending. Without
    # this, send() finds no provider for email/slack/teams/webhook/sms and every
    # network-channel alert is silently dropped ("No provider configured") — only
    # in_app (handled above) ever delivers. Skip the DB hit when nothing but
    # in_app is configured.
    if any(name != "in_app" for name in channels_config):
        await service.load_providers_from_db(organization_id=organization_id)

    tasks = []
    for channel_name, config in channels_config.items():
        if channel_name == "in_app":
            continue  # already handled above
        channel_enum = _CHANNEL_MAP.get(channel_name)
        if not channel_enum:
            logger.warning("Unknown notification channel: %s", channel_name)
            continue

        recipients = _extract_recipients(channel_name, config)
        for recipient in recipients:
            tasks.append(_send_one(channel_name, channel_enum, recipient))

    if not tasks:
        return results

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Import here to avoid pulling Celery into hot import paths.
    from app.tasks.notification_retry import schedule_retry

    for r in raw_results:
        if isinstance(r, BaseException):
            logger.error("Notification dispatch raised exception: %s", r)
            continue
        if not isinstance(r, tuple):
            continue
        ch_name, _ch_enum, recipient, result = r
        results.append(result)

        # Only retry failed sends. SKIPPED (preference / quiet hours) is a
        # success path, not a failure. Permanent failures are filtered out
        # inside ``schedule_retry`` itself.
        if result.success or result.status == DeliveryStatus.SKIPPED:
            continue

        delivery_id = await _find_latest_delivery_id(
            db,
            organization_id=organization_id,
            channel=result.channel.value,
            subject=title,
        )
        if delivery_id is None:
            # We could not correlate a delivery row to this result —
            # still emit the structured log so an external runner can
            # see the failure.
            logger.warning(
                "notification.delivery.retry_no_row channel=%s recipient=%s err=%s",
                ch_name,
                recipient,
                result.error,
            )
            continue

        schedule_retry(
            delivery_id=delivery_id,
            provider_id=None,  # dispatch path uses in-memory provider
            channel=result.channel.value,
            recipient=recipient,
            title=title,
            body=body,
            body_html=body_html,
            organization_id=str(organization_id) if organization_id else None,
            error=result.error,
            attempt=1,
        )

    return results


async def _find_latest_delivery_id(
    db: AsyncSession,
    *,
    organization_id: UUID | None,
    channel: str,
    subject: str,
) -> str | None:
    """Look up the NotificationDelivery row written by the most recent send.

    ``NotificationService._track_delivery`` flushes a row before returning
    the ``DeliveryResult``, so by the time we get here the row exists in
    the same session. We match on (org, channel, subject) ordered by
    sent_at desc — close enough for the retry queue without adding a
    surrogate key path.
    """
    try:
        stmt = (
            select(NotificationDelivery.id)
            .where(NotificationDelivery.channel == channel)
            .where(NotificationDelivery.subject == subject)
            .order_by(NotificationDelivery.sent_at.desc())
            .limit(1)
        )
        if organization_id is not None:
            stmt = stmt.where(NotificationDelivery.organization_id == organization_id)
        result = await db.execute(stmt)
        row = result.scalar_one_or_none()
        return str(row) if row else None
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("Failed to look up delivery row: %s", exc)
        return None


def _extract_recipients(channel_name: str, config: dict[str, Any]) -> list[str]:
    """Extract recipient addresses from a channel config block."""
    if not isinstance(config, dict):
        return []

    if channel_name == "email":
        to = config.get("to", [])
        return to if isinstance(to, list) else [to]

    if channel_name == "slack":
        channel = config.get("channel")
        return [channel] if channel else []

    if channel_name == "teams":
        url = config.get("webhook_url")
        return [url] if url else []

    if channel_name == "webhook":
        url = config.get("url")
        return [url] if url else []

    if channel_name == "sms":
        numbers = config.get("to", [])
        return numbers if isinstance(numbers, list) else [numbers]

    if channel_name == "in_app":
        user_ids = config.get("user_ids", [])
        return user_ids if isinstance(user_ids, list) else [user_ids]

    return []

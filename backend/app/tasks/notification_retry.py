# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Notification Retry Task
=====================================

Background retry queue for transient notification delivery failures.

Why this exists
---------------
``notification_helpers.dispatch_notifications`` runs channel sends
concurrently via ``asyncio.gather``. Before this task existed, any
transient SMTP / Slack 5xx / timeout returned
``DeliveryResult(success=False)`` and the notification was lost forever
— there was no DLQ and no observability. That meant a single 30-second
Slack outage could silently drop hundreds of alerts.

How it works
------------
``dispatch_notifications`` calls :func:`schedule_retry` for every
``DeliveryResult(success=False)`` whose error shape looks transient
(network error, 5xx, timeout). That helper either:

  1. Enqueues this Celery task with an exponential-backoff
     ``countdown=`` (2 ** attempt minutes, capped at 60 min), OR
  2. If Celery is unavailable, emits a structured log line
     ``notification.delivery.retry_scheduled`` carrying all the context
     an external retry runner / SRE script needs to re-drive the send.

The task itself rebuilds the runtime provider from the
``NotificationProviderRecord`` row (the same way ``test_stored_provider``
does), invokes ``provider.send()``, and either:

  - On success: updates the ``NotificationDelivery`` row to
    ``status=sent``, ``success=true``, ``last_error=null``.
  - On transient failure with attempts left: re-enqueues itself with
    the next backoff window.
  - On permanent failure or final attempt: flips ``retry_dead_letter=true``,
    sets ``status=failed``, populates ``last_error``, and emits a
    structured DLQ log line.

Configuration knobs
-------------------
- ``DEFAULT_MAX_RETRIES = 5`` — total attempts before DLQ (initial + 4 retries).
- ``MAX_BACKOFF_MINUTES = 60`` — backoff is min(2**attempt, 60) minutes.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import update as sa_update

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.models.notification import NotificationDelivery
from app.services.notification import (
    DeliveryResult,
    DeliveryStatus,
    NotificationChannel,
    NotificationPayload,
    NotificationService,
)

logger = logging.getLogger("freesdn.tasks.notification_retry")

# Public knobs — referenced from dispatch_notifications too.
DEFAULT_MAX_RETRIES: int = 5
MAX_BACKOFF_MINUTES: int = 60


# ---------------------------------------------------------------------------
# Helpers — error classification + backoff
# ---------------------------------------------------------------------------

# Substrings indicating a *permanent* failure that should NOT be retried.
# Anything outside this list is treated as transient (network blip, 5xx,
# rate limit, timeout) and retried with backoff.
_PERMANENT_ERROR_MARKERS: tuple[str, ...] = (
    "header injection",
    "invalid email",
    "config error",
    "no provider configured",
    "ssrf",
    "unauthorized",  # 401 — credentials wrong, retry won't help
    "forbidden",  # 403
    "bad request",  # 400
    "not found",  # 404
    "user-disabled",
    "channel disabled",
)


def is_transient_error(error: str | None) -> bool:
    """Return True if ``error`` looks like a retryable transient failure.

    Permanent failures (bad config, 4xx-except-429, SSRF, header injection)
    are intentionally NOT retried — flooding a misconfigured webhook with
    100 retries serves no one.
    """
    if not error:
        # Generic failure with no error string — assume transient and retry
        # rather than silently dropping. The DLQ guard prevents loops.
        return True
    e = error.lower()
    # 429 (rate limit) IS transient — Slack/Twilio will accept later.
    if "429" in e or "rate limit" in e or "too many requests" in e:
        return True
    return not any(marker in e for marker in _PERMANENT_ERROR_MARKERS)


def _backoff_minutes(attempt: int) -> int:
    """Exponential backoff capped at ``MAX_BACKOFF_MINUTES`` minutes.

    attempt=1 → 2 min, 2 → 4, 3 → 8, 4 → 16, 5 → 32, 6+ → 60.
    """
    return min(2**attempt, MAX_BACKOFF_MINUTES)


# ---------------------------------------------------------------------------
# Public scheduling helper (called from dispatch_notifications)
# ---------------------------------------------------------------------------


def schedule_retry(
    *,
    delivery_id: str,
    provider_id: str | None,
    channel: str,
    recipient: str,
    title: str,
    body: str,
    body_html: str | None,
    organization_id: str | None,
    error: str | None,
    attempt: int = 1,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> None:
    """Enqueue a retry attempt — or emit a structured DLQ log if we cannot.

    ``delivery_id`` is the PK of the ``NotificationDelivery`` row that
    captured the failed send. If we can't enqueue (Celery broker down,
    not configured), we log enough context that an external retry runner
    or SRE script can pick up the failure manually.
    """
    if attempt > max_retries:
        logger.error(
            "notification.delivery.dlq",
            extra={
                "delivery_id": delivery_id,
                "provider_id": provider_id,
                "channel": channel,
                "organization_id": organization_id,
                "attempt": attempt,
                "error": error,
            },
        )
        return

    if not is_transient_error(error):
        logger.info(
            "notification.delivery.permanent_failure",
            extra={
                "delivery_id": delivery_id,
                "provider_id": provider_id,
                "channel": channel,
                "organization_id": organization_id,
                "attempt": attempt,
                "error": error,
            },
        )
        return

    countdown = _backoff_minutes(attempt) * 60

    # Always emit the structured "scheduled" log so external retry runners
    # (or operators tailing logs) can observe the queue even when Celery is
    # not reachable.
    logger.info(
        "notification.delivery.retry_scheduled",
        extra={
            "delivery_id": delivery_id,
            "provider_id": provider_id,
            "channel": channel,
            "organization_id": organization_id,
            "attempt": attempt,
            "next_attempt": attempt + 1,
            "countdown_seconds": countdown,
            "error": error,
        },
    )

    try:
        retry_notification_delivery.apply_async(
            kwargs={
                "delivery_id": delivery_id,
                "provider_id": provider_id,
                "channel": channel,
                "recipient": recipient,
                "title": title,
                "body": body,
                "body_html": body_html,
                "organization_id": organization_id,
                "attempt": attempt + 1,
                "max_retries": max_retries,
            },
            countdown=countdown,
            queue="default",
        )
    except Exception as exc:  # pragma: no cover — broker outage path
        # If we cannot enqueue, the structured log above is the DLQ
        # signal an external runner needs.
        logger.warning(
            "notification.delivery.retry_enqueue_failed delivery_id=%s err=%s",
            delivery_id,
            exc,
        )


# ---------------------------------------------------------------------------
# Async worker body
# ---------------------------------------------------------------------------


async def _do_retry(
    *,
    delivery_id: str,
    provider_id: str | None,
    channel: str,
    recipient: str,
    title: str,
    body: str,
    body_html: str | None,
    organization_id: str | None,
    attempt: int,
    max_retries: int,
) -> dict[str, Any]:
    """Re-attempt a single notification send, recording the outcome."""
    async with AsyncSessionLocal() as session:
        service = NotificationService(session)
        try:
            ch_enum = NotificationChannel(channel)
        except ValueError:
            logger.error(
                "notification.delivery.retry_invalid_channel delivery_id=%s ch=%s",
                delivery_id,
                channel,
            )
            return {"success": False, "error": "invalid_channel"}

        # Resolve provider — either an explicit stored record or the
        # currently-registered in-memory provider for this channel.
        runtime = None
        if provider_id:
            try:
                record = await service.get_provider(UUID(provider_id))
            except Exception:
                record = None
            if record is not None:
                runtime = service._build_runtime_provider(record)
        if runtime is None:
            runtime = service._providers.get(ch_enum)

        if runtime is None:
            await _mark_dead_letter(
                session,
                delivery_id=delivery_id,
                attempt=attempt,
                error=f"No provider available for channel {channel}",
            )
            await session.commit()
            return {"success": False, "error": "no_provider"}

        payload = NotificationPayload(title=title, body=body, body_html=body_html)
        try:
            result: DeliveryResult = await runtime.send(recipient, payload)
        except Exception as exc:  # noqa: BLE001 — any provider exception
            result = DeliveryResult(
                success=False,
                channel=ch_enum,
                status=DeliveryStatus.FAILED,
                error=str(exc),
                provider=getattr(runtime, "provider_type", None),
            )

        if result.success:
            await session.execute(
                sa_update(NotificationDelivery)
                .where(NotificationDelivery.id == UUID(delivery_id))
                .values(
                    status=DeliveryStatus.SENT.value,
                    success=True,
                    attempt=attempt,
                    last_error=None,
                    error_message=None,
                    retry_dead_letter=False,
                    sent_at=datetime.now(UTC),
                )
            )
            await session.commit()
            logger.info(
                "notification.delivery.retry_succeeded delivery_id=%s attempt=%d",
                delivery_id,
                attempt,
            )
            return {"success": True, "attempt": attempt}

        # Failure path — decide between DLQ and another retry.
        if attempt >= max_retries or not is_transient_error(result.error):
            await _mark_dead_letter(
                session,
                delivery_id=delivery_id,
                attempt=attempt,
                error=result.error,
            )
            await session.commit()
            logger.error(
                "notification.delivery.dlq delivery_id=%s attempt=%d err=%s",
                delivery_id,
                attempt,
                result.error,
            )
            return {"success": False, "dead_letter": True, "error": result.error}

        # Update row, schedule next attempt.
        await session.execute(
            sa_update(NotificationDelivery)
            .where(NotificationDelivery.id == UUID(delivery_id))
            .values(
                status=DeliveryStatus.FAILED.value,
                success=False,
                attempt=attempt,
                last_error=result.error,
                error_message=result.error,
            )
        )
        await session.commit()

        schedule_retry(
            delivery_id=delivery_id,
            provider_id=provider_id,
            channel=channel,
            recipient=recipient,
            title=title,
            body=body,
            body_html=body_html,
            organization_id=organization_id,
            error=result.error,
            attempt=attempt,
            max_retries=max_retries,
        )
        return {"success": False, "rescheduled": True, "error": result.error}


async def _mark_dead_letter(
    session: Any,
    *,
    delivery_id: str,
    attempt: int,
    error: str | None,
) -> None:
    """Flip the row to DLQ state with the final error."""
    await session.execute(
        sa_update(NotificationDelivery)
        .where(NotificationDelivery.id == UUID(delivery_id))
        .values(
            status=DeliveryStatus.FAILED.value,
            success=False,
            attempt=attempt,
            last_error=error,
            error_message=error,
            retry_dead_letter=True,
        )
    )


# ---------------------------------------------------------------------------
# Celery task entry point
# ---------------------------------------------------------------------------


@celery_app.task(
    name="app.tasks.notification_retry.retry_notification_delivery",
    bind=True,
    max_retries=0,  # We own retry scheduling ourselves via schedule_retry().
    soft_time_limit=60,
    time_limit=120,
)
def retry_notification_delivery(
    self: Any,
    delivery_id: str,
    provider_id: str | None,
    channel: str,
    recipient: str,
    title: str,
    body: str,
    body_html: str | None = None,
    organization_id: str | None = None,
    attempt: int = 2,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> dict[str, Any]:
    """Celery task: retry a single notification delivery."""
    return asyncio.run(
        _do_retry(
            delivery_id=delivery_id,
            provider_id=provider_id,
            channel=channel,
            recipient=recipient,
            title=title,
            body=body,
            body_html=body_html,
            organization_id=organization_id,
            attempt=attempt,
            max_retries=max_retries,
        )
    )

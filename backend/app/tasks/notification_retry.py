# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Retry failed notifications under the persisted delivery's authority.

Only the next attempt on an owned failed row may send. A PostgreSQL row lock
serializes competing retries until their outcome commits. Explicit providers
must remain enabled and match the delivery organization and channel. Platform
retries may use only platform providers, never a tenant's default provider.

Queue submission logs success only after the broker call returns; a failed
submission remains visible and is not a durable dead-letter queue. Delivery
content still comes from the trusted task payload. A crash after a provider
accepts a message but before commit can cause a duplicate on a later retry;
this module does not provide a transactional outbox or exactly-once effects.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy import update as sa_update

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.models.core import Organization
from app.models.notification import NotificationDelivery, NotificationProviderRecord
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
    "smtp permanent failure",
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
    return min(2 ** min(attempt, 6), MAX_BACKOFF_MINUTES)


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
) -> bool:
    """Return whether the broker accepted scheduling the next bounded attempt.

    The caller owns committing the failed delivery before this operation.
    False means no acknowledgement, not proof that a timed-out broker could
    not have accepted a task. Logs contain identifiers, not message content
    or transport exceptions. They are not a recoverable payload store.
    """
    if (
        type(attempt) is not int
        or type(max_retries) is not int
        or not 1 <= attempt < max_retries <= DEFAULT_MAX_RETRIES
    ):
        logger.error(
            "notification.delivery.retry_not_scheduled",
            extra={
                "delivery_id": delivery_id,
                "provider_id": provider_id,
                "channel": channel,
                "organization_id": organization_id,
                "attempt": attempt,
            },
        )
        return False

    if not is_transient_error(error):
        logger.info(
            "notification.delivery.permanent_failure",
            extra={
                "delivery_id": delivery_id,
                "provider_id": provider_id,
                "channel": channel,
                "organization_id": organization_id,
                "attempt": attempt,
            },
        )
        return False

    countdown = _backoff_minutes(attempt) * 60

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
    except Exception:
        logger.warning(
            "notification.delivery.retry_enqueue_failed delivery_id=%s",
            delivery_id,
        )
        return False
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
        },
    )
    return True


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
    """Retry only the current failed attempt under its persisted tenant scope.

    The row lock prevents concurrent workers from sending the same committed
    attempt. A provider effect followed by a failed database commit is still
    uncertain: this is not an exactly-once protocol or a transactional outbox.
    """
    try:
        delivery_uuid = UUID(delivery_id)
        organization_uuid = UUID(organization_id) if organization_id is not None else None
        provider_uuid = UUID(provider_id) if provider_id is not None else None
        ch_enum = NotificationChannel(channel)
    except (ValueError, TypeError, AttributeError):
        return {"success": False, "error": "invalid_retry_arguments"}
    if (
        type(attempt) is not int
        or type(max_retries) is not int
        or not 2 <= attempt <= max_retries <= DEFAULT_MAX_RETRIES
    ):
        return {"success": False, "error": "invalid_retry_arguments"}

    try:
        async with AsyncSessionLocal() as session:
            statement = (
                select(NotificationDelivery)
                .where(
                    NotificationDelivery.id == delivery_uuid,
                    NotificationDelivery.organization_id == organization_uuid,
                    NotificationDelivery.channel == ch_enum.value,
                    NotificationDelivery.subject == title,
                    NotificationDelivery.success.is_(False),
                    NotificationDelivery.status == DeliveryStatus.FAILED.value,
                    NotificationDelivery.retry_dead_letter.is_(False),
                    NotificationDelivery.attempt == attempt - 1,
                )
                .with_for_update()
            )
            delivery = (await session.execute(statement)).scalar_one_or_none()
            if delivery is None:
                return {"success": False, "error": "delivery_not_retryable"}
            if organization_uuid is not None:
                organization = await session.execute(
                    select(Organization.id).where(
                        Organization.id == organization_uuid,
                        Organization.is_active.is_(True),
                        Organization.deleted_at.is_(None),
                    )
                )
                if organization.scalar_one_or_none() is None:
                    return {"success": False, "error": "delivery_not_retryable"}

            service = NotificationService(session)
            runtime = None
            if provider_uuid is not None:
                # No fallback from an explicit stale, disabled or foreign ID.
                record = (
                    await session.execute(
                        select(NotificationProviderRecord).where(
                            NotificationProviderRecord.id == provider_uuid,
                            NotificationProviderRecord.organization_id == organization_uuid,
                            NotificationProviderRecord.channel == ch_enum.value,
                            NotificationProviderRecord.is_enabled.is_(True),
                        )
                    )
                ).scalar_one_or_none()
                if record is not None:
                    runtime = service._build_runtime_provider(record)
            elif organization_uuid is not None:
                # A fresh worker has no in-memory providers. Load only this org.
                await service.load_providers_from_db(organization_id=organization_uuid)
                runtime = service._providers.get(ch_enum)
            else:
                # list_providers(None) means all organizations for management.
                # A platform-scoped delivery may use only a platform provider.
                record = (
                    await session.execute(
                        select(NotificationProviderRecord)
                        .where(
                            NotificationProviderRecord.organization_id.is_(None),
                            NotificationProviderRecord.channel == ch_enum.value,
                            NotificationProviderRecord.is_enabled.is_(True),
                        )
                        .order_by(
                            NotificationProviderRecord.is_default.desc(),
                            NotificationProviderRecord.created_at.desc(),
                            NotificationProviderRecord.id,
                        )
                        .limit(1)
                    )
                ).scalar_one_or_none()
                if record is not None:
                    runtime = service._build_runtime_provider(record)

            if runtime is None:
                await _mark_dead_letter(
                    session,
                    delivery_id=delivery_id,
                    attempt=attempt,
                    error="No provider available for retry",
                )
                await session.commit()
                return {"success": False, "error": "no_provider", "dead_letter": True}

            payload = NotificationPayload(title=title, body=body, body_html=body_html)
            try:
                result: DeliveryResult = await runtime.send(recipient, payload)
            except Exception:
                result = DeliveryResult(
                    success=False,
                    channel=ch_enum,
                    status=DeliveryStatus.FAILED,
                    error="Notification retry failed",
                    provider=getattr(runtime, "provider_type", None),
                )

            if result.success:
                await session.execute(
                    sa_update(NotificationDelivery)
                    .where(NotificationDelivery.id == delivery_uuid)
                    .values(
                        status=result.status.value,
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
                    "notification.delivery.retry_completed delivery_id=%s attempt=%d",
                    delivery_id,
                    attempt,
                )
                return {"success": True, "attempt": attempt, "status": result.status.value}

            if attempt >= max_retries or not is_transient_error(result.error):
                await _mark_dead_letter(
                    session, delivery_id=delivery_id, attempt=attempt, error=result.error
                )
                await session.commit()
                logger.error(
                    "notification.delivery.dlq delivery_id=%s attempt=%d",
                    delivery_id,
                    attempt,
                )
                return {"success": False, "dead_letter": True, "error": result.error}

            await session.execute(
                sa_update(NotificationDelivery)
                .where(NotificationDelivery.id == delivery_uuid)
                .values(
                    status=DeliveryStatus.FAILED.value,
                    success=False,
                    attempt=attempt,
                    last_error=result.error,
                    error_message=result.error,
                )
            )
            await session.commit()
            scheduled = schedule_retry(
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
            return {"success": False, "rescheduled": scheduled, "error": result.error}
    except Exception:
        # Includes a failed/uncertain commit after a provider effect. Never
        # report successful persistence or serialize database/transport secrets.
        logger.warning("notification.delivery.retry_state_unavailable")
        return {"success": False, "error": "retry_state_unavailable"}


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

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Notification Dispatch Helpers
==========================================

Shared helper to dispatch notifications from alert rules and SLA breaches.
Parses the notification_channels JSONB config and calls NotificationService.

Retry behavior
--------------
Recipients are sent sequentially because provider checks and tracking share the
caller's mutable database session. Before the retry queue existed, a transient SMTP / Slack 5xx returned
``DeliveryResult(success=False)`` and was silently dropped. Now, every
unsuccessful result whose error shape looks transient is enqueued onto
:func:`app.tasks.notification_retry.schedule_retry` for exponential
backoff. Permanent failures (header injection, SSRF, 4xx-except-429)
short-circuit and skip the retry queue. See ``notification_retry.py``
for the classification logic.
"""

import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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

    # Prepare sends without sharing the session across concurrent tasks
    async def _send_one(
        ch_name: str, ch_enum: NotificationChannel, recipient: str
    ) -> tuple[str, NotificationChannel, str, DeliveryResult]:
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
                logger.debug("Notification attempt completed via %s", ch_name)
            else:
                logger.warning("Notification attempt failed via %s", ch_name)
        except Exception:
            # Retain the failed attempt without disclosing transport credentials
            # or looking up an unrelated row for an untracked exception.
            logger.error("Error sending notification via %s", ch_name)
            result = DeliveryResult(
                success=False,
                channel=ch_enum,
                status=DeliveryStatus.FAILED,
                error="Notification attempt failed",
            )
        return (ch_name, ch_enum, recipient, result)

    # The in_app channel has NO provider in NotificationService.send (only
    # email/slack/teams/webhook are registered), so routing it through send()
    # always returns "No provider configured for channel: in_app" and the bell
    # row is never written. Write the real InAppNotification row directly via
    # create_in_app (which queues its event in the same transaction for a
    # worker to publish after the caller commits). Handled before the generic provider loop so it doesn't
    # produce a spurious FAILED DeliveryResult / retry-queue entry.
    in_app_cfg = channels_config.get("in_app")
    if in_app_cfg is not None:
        in_app_targets = _extract_recipients("in_app", in_app_cfg)
        if not in_app_targets:
            # The Alert Rules dialog offers In-App as a bare enable toggle and
            # collects no user IDs at all, so this list was ALWAYS empty and the
            # channel could never deliver. Enabling it plainly means "raise this
            # in the bell for this organization", so resolve the org's active
            # users rather than doing nothing. Scoped to the org and skipped
            # entirely when organization_id is unknown, so this cannot fan out
            # across tenants.
            if organization_id is not None:
                in_app_targets = [str(uid) for uid in await _org_user_ids(db, organization_id)]
            if not in_app_targets:
                logger.warning(
                    "in_app notification channel is enabled but resolved no "
                    "recipients (organization_id=%s)",
                    organization_id,
                )
        for uid in in_app_targets:
            try:
                await service.create_in_app(
                    user_id=UUID(str(uid)),
                    title=title,
                    body=body,
                    organization_id=organization_id,
                    commit=False,
                )
                results.append(
                    DeliveryResult(
                        success=True,
                        channel=NotificationChannel.IN_APP,
                        status=DeliveryStatus.SENT,
                    )
                )
            except Exception:  # one bad user_id must not abort the batch
                logger.warning("In-app notification attempt failed")
                results.append(
                    DeliveryResult(
                        success=False,
                        channel=NotificationChannel.IN_APP,
                        status=DeliveryStatus.FAILED,
                        error="In-app notification attempt failed",
                    )
                )

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
            tasks.append((channel_name, channel_enum, recipient))

    if not tasks:
        return results

    # SQLAlchemy sessions represent one mutable transaction. Provider policy
    # queries and tracking flushes must finish before another recipient uses
    # that session. Construct no background coroutines: cancellation propagates
    # immediately and later recipients have not started. Collect all outcomes
    # before retry publication so a cancelled dispatch publishes no retries.
    raw_results = [await _send_one(*task) for task in tasks]

    # Import here to avoid pulling Celery into hot import paths.
    from app.tasks.notification_retry import schedule_retry

    for outcome in raw_results:
        ch_name, _ch_enum, recipient, result = outcome
        results.append(result)

        # Only retry failed sends. SKIPPED (preference / quiet hours) is a
        # success path, not a failure. Permanent failures are filtered out
        # inside ``schedule_retry`` itself.
        if result.success or result.status == DeliveryStatus.SKIPPED:
            continue

        delivery_id = result.delivery_id
        if delivery_id is None:
            # An absent tracking identity is not permission to guess by title,
            # channel or organization. Two recipients can share all three.
            logger.warning("notification.delivery.retry_no_row channel=%s", ch_name)
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


# Which config keys hold the recipients, per channel.
#
# This map exists because the reader and the writer disagreed. The Alert Rules
# dialog persists ``recipients`` for email and ``phone_numbers`` for SMS
# (AlertRulesPage.tsx: updateChannelConfig('email', 'recipients', ...) and
# ('sms', 'phone_numbers', ...)), while this function read ``to`` for both. The
# key never matched, so ``_extract_recipients`` returned [] and NO email or SMS
# alert has ever been delivered from an alert rule -- silently, because an empty
# recipient list produces no task, no DeliveryResult and no error. Slack, Teams
# and webhook happened to agree on their key and worked fine, which is why the
# feature looked healthy.
#
# Both spellings are accepted rather than picking one: existing rows in the
# database carry whichever key was written when they were saved, and a
# notification config is exactly the kind of thing nobody notices is broken
# until an incident.
_RECIPIENT_KEYS: dict[str, tuple[str, ...]] = {
    "email": ("to", "recipients", "emails"),
    "sms": ("to", "phone_numbers", "numbers"),
    "in_app": ("user_ids", "users"),
    "slack": ("channel",),
    "teams": ("webhook_url",),
    "webhook": ("url",),
}

# Channels whose recipient field is genuinely multi-valued and may arrive as one
# delimited string from a text input. A slack channel or webhook URL is single
# valued and must never be split -- a URL containing a comma would be shredded.
_SPLITTABLE = {"email", "sms", "in_app"}

_RECIPIENT_DELIMITERS = (",", ";", chr(10), chr(13), chr(9))


def _split_recipients(raw: Any) -> list[str]:
    """Normalise a recipient field into a clean list.

    The dialog's inputs are free-text, so ``recipients`` arrives as
    ``"ops@example.com, devops@example.com"`` -- a single string. Passing that
    through unsplit is not merely untidy: ``email.utils.parseaddr`` returns
    ``("", "")`` for it, so ``_validate_email_address`` rejects the whole thing
    and the send fails. Re-keying without splitting would have swapped a silent
    no-op for a hard failure.
    """
    if raw is None:
        return []
    values = raw if isinstance(raw, list | tuple | set) else [raw]

    out: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value)
        for delimiter in _RECIPIENT_DELIMITERS[1:]:
            text = text.replace(delimiter, _RECIPIENT_DELIMITERS[0])
        for part in text.split(_RECIPIENT_DELIMITERS[0]):
            part = part.strip()
            if part and part not in out:
                out.append(part)
    return out


async def _org_user_ids(db: Any, organization_id: Any) -> list[Any]:
    """Active, non-deleted user ids for one organization.

    Used only as the in_app fallback when a rule enables the channel without
    naming anyone. Org-scoped by construction.
    """

    from app.models.core import User

    stmt = select(User.id).where(
        User.organization_id == organization_id,
        User.is_active.is_(True),
    )
    if hasattr(User, "deleted_at"):
        stmt = stmt.where(User.deleted_at.is_(None))
    try:
        rows = await db.execute(stmt)
        return list(rows.scalars().all())
    except Exception as exc:  # pragma: no cover - never break dispatch on this
        logger.warning("Could not resolve in_app recipients for org %s: %s", organization_id, exc)
        return []


def _extract_recipients(channel_name: str, config: dict[str, Any]) -> list[str]:
    """Extract recipient addresses from a channel config block."""
    if not isinstance(config, dict):
        return []

    keys = _RECIPIENT_KEYS.get(channel_name)
    if not keys:
        return []

    for key in keys:
        if key not in config:
            continue
        raw = config[key]
        if channel_name in _SPLITTABLE:
            found = _split_recipients(raw)
        else:
            found = [str(raw).strip()] if raw else []
        if found:
            return found

    return []

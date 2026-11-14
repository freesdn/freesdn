# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Webhook Delivery Celery Tasks
============================================

Async retry logic for failed webhook deliveries with exponential backoff.

Retry schedule (seconds between attempts):
  Attempt 1  → 60 s
  Attempt 2  → 120 s
  Attempt 3  → 240 s
  Attempt 4  → 480 s
  Attempt 5  → 960 s  (last attempt — on failure moves to DLQ)

After all retries are exhausted the delivery is moved to WebhookDeadLetter
so admins can inspect and replay it manually from the UI.
"""

import json
import logging
import time
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.tasks.base import async_task

logger = logging.getLogger(__name__)

# Explicit countdown (seconds) for each retry attempt index (0-based)
# SECURITY: limited to 3 retries to reduce DDoS amplification risk
_RETRY_DELAYS = [60, 120, 240]

# Attempts a delivery gets in total: the first POST plus one per retry delay.
# Counted on the row (``attempt_number``), not on the Celery message: a retry
# requeued by ``requeue_stalled_deliveries`` is a fresh message whose
# ``request.retries`` starts at 0 again, and must not reset the budget.
MAX_ATTEMPTS = 1 + len(_RETRY_DELAYS)


@celery_app.task(
    bind=True,
    name="app.tasks.webhooks.retry_webhook_delivery",
    max_retries=3,
    soft_time_limit=60,
    time_limit=90,
    # Routes to "default", which every deployment tier consumes (see
    # WORKER_QUEUES in .env.{lite,pro,max}.example). Do NOT name a queue here
    # unless it is also declared in celery_app.task_queues AND consumed by a
    # worker in every tier — an unconsumed queue strands deliveries silently.
    ignore_result=True,
)
@async_task
async def retry_webhook_delivery(self, delivery_id: str) -> None:
    """
    Retry a failed webhook delivery.

    Called after the initial synchronous delivery attempt fails in
    PersistentWebhookService.dispatch_webhook().  Uses exponential backoff
    (see _RETRY_DELAYS above).  On final failure the delivery is moved to
    the WebhookDeadLetter table.

    Args:
        delivery_id: UUID string of the WebhookDelivery record to retry.
    """
    from app.core.security_utils import safe_http_request
    from app.db.session import CelerySessionLocal
    from app.models.webhooks import (
        DeliveryStatus,
        Webhook,
        WebhookDeadLetter,
        WebhookDelivery,
    )

    async with CelerySessionLocal() as session:
        # ── Load delivery (C-2: FOR UPDATE prevents two workers from racing on
        #    the same delivery — one will block until the first commits/rolls
        #    back, guaranteeing attempt_number is incremented exactly once per
        #    retry even if a task is duplicated by Celery's at-least-once
        #    delivery guarantee.) ────────────────────────────────────────────
        delivery = (
            await session.execute(
                select(WebhookDelivery)
                .where(WebhookDelivery.id == UUID(delivery_id))
                .with_for_update()
            )
        ).scalar_one_or_none()

        if not delivery:
            logger.warning(f"retry_webhook_delivery: delivery {delivery_id} not found — skipping")
            return

        # Only a delivery that is still owed an attempt. A duplicate message (a
        # redelivered task, or the sweeper requeueing a delivery whose own retry
        # then ran) must not POST an event that was already delivered or
        # dead-lettered.
        if delivery.status not in (DeliveryStatus.PENDING, DeliveryStatus.RETRYING):
            logger.info(
                "retry_webhook_delivery: delivery %s is %s; nothing to do",
                delivery_id,
                delivery.status,
            )
            return

        wh = (
            await session.execute(select(Webhook).where(Webhook.id == delivery.webhook_id))
        ).scalar_one_or_none()

        if not wh or not wh.enabled:
            delivery.status = DeliveryStatus.FAILED
            delivery.error_message = "Webhook disabled or deleted during retry"
            await session.commit()
            return

        # ── SSRF guard is applied by safe_http_request below
        #    (DNS-rebinding-safe: resolves + pins hostname to validated IP).

        # ── Build request ──────────────────────────────────────────────────
        body = json.dumps(delivery.payload or {}, default=str)
        attempt_num = delivery.attempt_number + 1

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Webhook-Event": delivery.event_type,
            "X-Webhook-Delivery": str(delivery.id),
            "X-Webhook-Attempt": str(attempt_num),
        }
        payload_id = (delivery.payload or {}).get("id")
        event_id = delivery.event_id or (str(payload_id)[:64] if payload_id else None)
        if event_id:
            headers["X-Webhook-Event-Id"] = event_id
        if wh.secret:
            # F-2: decrypt before signing (secret stored encrypted at rest).
            # Timestamp-bound signature (X-Webhook-Timestamp) for replay resistance.
            from app.core.security_utils import decrypt_webhook_secret, sign_webhook_payload

            raw_secret = decrypt_webhook_secret(wh.secret)
            ts = int(time.time())
            headers["X-Webhook-Timestamp"] = str(ts)
            headers["X-Webhook-Signature"] = sign_webhook_payload(raw_secret, body, ts)

        # ── Attempt delivery ───────────────────────────────────────────────
        delivery.attempt_number = attempt_num
        delivery.status = DeliveryStatus.RETRYING

        start = time.monotonic()
        success = False
        error_msg: str | None = None

        try:
            from app.services.webhooks import webhook_allowed_hosts

            resp = await safe_http_request(
                "POST",
                wh.url,
                content=body,
                headers=headers,
                verify_tls=wh.verify_ssl,
                timeout=30.0,
                allow_hosts=webhook_allowed_hosts(),
            )

            elapsed_ms = (time.monotonic() - start) * 1000
            delivery.response_code = resp.status_code
            delivery.response_time_ms = elapsed_ms
            delivery.sent_at = datetime.now(UTC)

            if 200 <= resp.status_code < 300:
                success = True
                delivery.status = DeliveryStatus.DELIVERED
                wh.success_count += 1
                wh.last_success = datetime.now(UTC)
            else:
                error_msg = f"HTTP {resp.status_code}"

        except ValueError as exc:
            # SSRF / URL validation failure from safe_http_request
            elapsed_ms = (time.monotonic() - start) * 1000
            delivery.response_time_ms = elapsed_ms
            delivery.sent_at = datetime.now(UTC)
            error_msg = f"SSRF blocked: {exc}"
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            delivery.response_time_ms = elapsed_ms
            delivery.sent_at = datetime.now(UTC)
            error_msg = str(exc)

        # ── Handle failure ─────────────────────────────────────────────────
        if not success:
            # Same sanitizer as the dispatch path: strip URLs +
            # length-cap before persisting so webhook secrets embedded
            # in failing URLs don't leak into the delivery log.
            from app.services.webhooks import _sanitize_webhook_error

            delivery.error_message = _sanitize_webhook_error(error_msg)
            # Bounded by the attempts recorded on the row (see MAX_ATTEMPTS), so
            # a requeued or replayed delivery gets the same budget as a live one:
            # attempts 1 to 4, then the dead-letter queue.
            if attempt_num < MAX_ATTEMPTS and self.request.retries < self.max_retries:
                # Schedule next retry with backoff
                delay = _RETRY_DELAYS[min(max(attempt_num - 1, 0), len(_RETRY_DELAYS) - 1)]
                delivery.status = DeliveryStatus.RETRYING
                wh.failure_count += 1
                wh.last_failure = datetime.now(UTC)
                wh.last_triggered = datetime.now(UTC)
                await session.commit()
                # Raise to trigger Celery's built-in retry with our countdown
                raise self.retry(exc=Exception(error_msg), countdown=delay)
            else:
                # All retries exhausted → dead-letter queue
                delivery.status = DeliveryStatus.FAILED
                wh.failure_count += 1
                wh.last_failure = datetime.now(UTC)

                dlq_entry = WebhookDeadLetter(
                    webhook_id=wh.id,
                    delivery_id=delivery.id,
                    organization_id=wh.organization_id,
                    event_type=delivery.event_type,
                    payload=delivery.payload,
                    failure_reason=error_msg,
                    attempt_count=delivery.attempt_number,
                    final_attempt_at=datetime.now(UTC),
                )
                session.add(dlq_entry)
                logger.error(
                    f"Webhook delivery {delivery_id} exhausted {self.max_retries} retries. "
                    f"Moved to dead-letter queue. Last error: {error_msg}"
                )

        wh.last_triggered = datetime.now(UTC)
        await session.commit()


@celery_app.task(
    bind=True,
    name="app.tasks.webhooks.deliver_event",
    soft_time_limit=150,
    time_limit=180,
    # "default", like retry_webhook_delivery above: every tier consumes it.
    ignore_result=True,
    # A worker that dies mid-task gets the message back (acks_late +
    # reject_on_worker_lost, celery_app.py). A task that RAISES is acknowledged
    # all the same, so before this a database error while recording the
    # deliveries dropped the event for every webhook. Retrying is safe:
    # dispatch_event skips the webhooks that already have a delivery for this
    # event id, so only the rest are sent.
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    max_retries=5,
)
@async_task
async def deliver_event(self, envelope: dict) -> dict:
    """Deliver one event-bus event to the webhooks of its organization.

    Enqueued by ``app.services.webhook_events.WebhookEventForwarder`` (one claim
    per event across all API workers). ``envelope`` is the webhook body built by
    ``build_envelope``; its ``id`` is the bus event id.
    """
    from app.db.session import CelerySessionLocal
    from app.services.webhooks import PersistentWebhookService

    org = envelope.get("organization_id")
    if not org:
        return {"delivered_to": 0, "reason": "event has no organization"}
    async with CelerySessionLocal() as session:
        count = await PersistentWebhookService.dispatch_event(
            session,
            envelope["event"],
            envelope,
            event_id=str(envelope["id"]),
            organization_id=UUID(str(org)),
        )
        await session.commit()
    return {"delivered_to": count}


@celery_app.task(
    bind=True,
    name="app.tasks.webhooks.requeue_stalled_deliveries",
    soft_time_limit=60,
    time_limit=90,
    # "default", like the two tasks above.
    ignore_result=True,
)
@async_task
async def requeue_stalled_deliveries(self, limit: int = 200) -> dict:
    """Give every delivery that lost its task another attempt.

    A delivery row is written before its POST and records every outcome, but
    the task that is meant to act on it can still be lost: the broker refused
    the retry message, a worker died holding a countdown, a replay's enqueue
    failed after its commit. Such a row sat in ``pending`` or ``retrying``
    forever and the event never arrived. This finds rows in those states that
    have not changed for ``STALLED_DELIVERY_SECONDS``, touches them (so the next
    sweep leaves them alone while this attempt runs) and queues
    ``retry_webhook_delivery``. The attempt budget is on the row, so a requeue
    never grants extra attempts, and the retry task ignores a delivery that has
    meanwhile been delivered or dead-lettered.
    """
    from datetime import timedelta

    from sqlalchemy import update

    from app.db.session import CelerySessionLocal
    from app.models.webhooks import DeliveryStatus, WebhookDelivery
    from app.services.webhooks import STALLED_DELIVERY_SECONDS

    cutoff = datetime.now(UTC) - timedelta(seconds=STALLED_DELIVERY_SECONDS)
    async with CelerySessionLocal() as session:
        stalled = (
            select(WebhookDelivery.id)
            .where(
                WebhookDelivery.status.in_([DeliveryStatus.PENDING, DeliveryStatus.RETRYING]),
                WebhookDelivery.updated_at < cutoff,
            )
            .order_by(WebhookDelivery.updated_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
            .cte("stalled_webhook_deliveries")
            .prefix_with("MATERIALIZED")
        )
        ids = (
            (
                await session.execute(
                    update(WebhookDelivery)
                    .where(WebhookDelivery.id.in_(select(stalled.c.id)))
                    .values(updated_at=datetime.now(UTC))
                    .returning(WebhookDelivery.id)
                    .execution_options(synchronize_session=False)
                )
            )
            .scalars()
            .all()
        )
        await session.commit()

    queued = 0
    for delivery_id in ids:
        try:
            # No queue=: see retry_webhook_delivery's routing note.
            retry_webhook_delivery.apply_async(args=[str(delivery_id)])
            queued += 1
        except Exception:
            # Touched but not queued: the next sweep after the stall window
            # picks it up again.
            logger.warning("Could not requeue stalled webhook delivery %s", delivery_id)
    if ids:
        logger.warning("Requeued %d of %d stalled webhook deliveries", queued, len(ids))
    return {"stalled": len(ids), "requeued": queued}

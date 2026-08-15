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
            resp = await safe_http_request(
                "POST",
                wh.url,
                content=body,
                headers=headers,
                verify_tls=wh.verify_ssl,
                timeout=30.0,
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
            # self.request.retries is 0-based (0 on first execution, 1 on first retry…).
            # We use max_retries-1 as the threshold so the final allowed retry (index
            # max_retries-1 == 4) falls through to the DLQ branch instead of trying to
            # schedule a 6th attempt that Celery would reject with MaxRetriesExceededError.
            retry_index = self.request.retries

            if retry_index < self.max_retries - 1:
                # Schedule next retry with backoff
                delay = _RETRY_DELAYS[min(retry_index, len(_RETRY_DELAYS) - 1)]
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

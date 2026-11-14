# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Webhook Management Service
==========================================

DB-backed service for webhook lifecycle management:
- CRUD for webhook configurations
- Delivery dispatch with HMAC signing
- Delivery log tracking
- Retry logic
- Statistics
"""

import json
import logging
import re
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


def _sanitize_webhook_error(msg: str | None) -> str | None:
    """Strip URLs from delivery error messages and cap length.

    ``httpx`` / asyncio exception strings include the full failing
    URL, so any querystring-bearer-token or basic-auth-in-URL ended
    up in ``WebhookDelivery.error_message`` (JSONB, exposed via
    ``GET /deliveries``). Replacing the URL with ``<redacted-url>``
    keeps the diagnostic value of the error type while making the
    delivery log safe to expose to anyone with
    ``alert:read``-equivalent scope on the webhook.
    """
    if msg is None:
        return None
    return re.sub(r"https?://\S+", "<redacted-url>", msg)[:1024]


def webhook_allowed_hosts() -> frozenset[str]:
    """Hosts the deploy owner trusts as webhook targets even on a private network.

    ``WEBHOOK_ALLOWED_HOSTS`` (comma-separated). Without an entry, a webhook can
    only reach public addresses, which rules out the most common target of all
    on a self-hosted controller: the n8n / Node-RED / Home Assistant on the same
    LAN or tailnet. Entries are still DNS-pinned and TLS-verified at delivery,
    and loopback, link-local and cloud-metadata addresses stay unreachable. Read
    per call so an operator does not have to restart to add a host.
    """
    from app.core.config import settings as _settings

    raw = getattr(_settings, "WEBHOOK_ALLOWED_HOSTS", "") or ""
    return frozenset(h.strip().lower() for h in raw.split(",") if h.strip())


def _validate_webhook_target(url: str) -> None:
    """Form-field SSRF check at create/update time (delivery re-checks, pinned).

    A host on the deploy owner's allow-list may resolve to a private address;
    every other host must be public. Cloud-metadata hosts are refused either way.
    """
    from urllib.parse import urlparse

    from app.core.security_utils import validate_url_ssrf

    host = (urlparse(url).hostname or "").lower()
    validate_url_ssrf(url, allow_private=bool(host) and host in webhook_allowed_hosts())


# Event deliveries to an endpoint that has failed this many attempted
# deliveries in a row, the newest within the pause window, are not attempted:
# they go straight to the dead-letter queue, where they can be replayed. A dead
# receiver otherwise costs one HTTP timeout per event on the shared "default"
# Celery lane, which every heartbeat and notification also waits behind.
CIRCUIT_FAILURE_THRESHOLD = 5
CIRCUIT_PAUSE_SECONDS = 300
EVENT_DELIVERY_TIMEOUT_SECONDS = 10.0

# A delivery still pending or retrying this long after its row last changed has
# lost its task (a worker died before acknowledging, the broker refused the
# retry, a replay's enqueue failed). The sweeper requeues it. Longer than the
# longest retry countdown (240 s) plus the retry task's time limit, so a
# delivery that is merely waiting for its next attempt is never touched.
STALLED_DELIVERY_SECONDS = 900


def _subscriptions_changed() -> None:
    """Make this process's event forwarder re-read the webhook map.

    Other API workers pick the change up within ``SUBSCRIPTION_CACHE_SECONDS``.
    """
    try:
        from app.services.webhook_events import webhook_event_forwarder

        webhook_event_forwarder.invalidate()
    except Exception:  # noqa: BLE001 - a cache hint must never fail a CRUD call
        logger.debug("webhook forwarder invalidate failed", exc_info=True)


class PersistentWebhookService:
    """DB-backed webhook management service."""

    # =====================================================================
    # Webhook CRUD
    # =====================================================================

    @staticmethod
    async def list_webhooks(
        session: AsyncSession,
        *,
        enabled: bool | None = None,
        organization_id: UUID | None = None,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        from app.models.webhooks import Webhook

        q = select(Webhook)
        count_q = select(func.count(Webhook.id))

        if organization_id is not None:
            q = q.where(Webhook.organization_id == organization_id)
            count_q = count_q.where(Webhook.organization_id == organization_id)

        if enabled is not None:
            q = q.where(Webhook.enabled == enabled)
            count_q = count_q.where(Webhook.enabled == enabled)

        total = (await session.execute(count_q)).scalar() or 0
        pages = max(1, (total + per_page - 1) // per_page)
        offset = (page - 1) * per_page
        q = q.order_by(Webhook.created_at.desc()).offset(offset).limit(per_page)
        rows = (await session.execute(q)).scalars().all()

        return {
            "items": rows,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }

    @staticmethod
    async def get_webhook(
        session: AsyncSession,
        webhook_id: UUID,
        organization_id: UUID | None = None,
    ) -> Any:
        from app.models.webhooks import Webhook

        q = select(Webhook).where(Webhook.id == webhook_id)
        if organization_id is not None:
            q = q.where(Webhook.organization_id == organization_id)
        result = await session.execute(q)
        return result.scalars().first()

    @staticmethod
    async def create_webhook(
        session: AsyncSession, data: dict[str, Any], user_id: UUID | None = None
    ) -> Any:
        from app.models.webhooks import Webhook

        # F-1: require organization_id at service layer to prevent tenant-less
        # (globally-visible) webhooks from being created.
        if not data.get("organization_id"):
            raise ValueError("organization_id is required to create a webhook")

        # Validate webhook URL at creation time. This is FORM-FIELD validation
        # only (fail-fast on an obviously-bad URL); the DNS-rebinding-safe guard
        # is applied at dispatch time by safe_http_request, which resolves once
        # and pins the IP. See security_utils.validate_url_ssrf docstring.
        url = data.get("url")
        if url:
            _validate_webhook_target(url)  # raises ValueError on SSRF

        # D-4: explicit field allowlist prevents mass-assignment of internal counters
        _CREATE_FIELDS = {
            "name",
            "description",
            "url",
            "event_types",
            "enabled",
            "secret",
            "verify_ssl",
            "max_retries",
            "organization_id",
            "headers",
        }
        safe_data = {k: v for k, v in data.items() if k in _CREATE_FIELDS}

        # F-2: encrypt HMAC secret at rest
        if safe_data.get("secret"):
            from app.core.security_utils import encrypt_webhook_secret

            safe_data["secret"] = encrypt_webhook_secret(safe_data["secret"])

        wh = Webhook(**safe_data, created_by=user_id)
        session.add(wh)
        await session.flush()
        await session.refresh(wh)
        _subscriptions_changed()
        return wh

    @staticmethod
    async def update_webhook(
        session: AsyncSession,
        webhook_id: UUID,
        data: dict[str, Any],
        organization_id: UUID | None = None,
    ) -> Any:
        wh = await PersistentWebhookService.get_webhook(
            session, webhook_id, organization_id=organization_id
        )
        if not wh:
            return None

        # Validate new URL if being changed
        if "url" in data and data["url"]:
            _validate_webhook_target(data["url"])

        # D-3: use key-presence check (not `v is not None`) so callers can
        # explicitly clear nullable fields like `secret` by passing None.
        _ALLOWED_FIELDS = {
            "name",
            "url",
            "event_types",
            "enabled",
            "secret",
            "headers",
            "description",
            "retry_policy",
            "verify_ssl",
            "max_retries",
        }
        for k, v in data.items():
            if k in _ALLOWED_FIELDS:
                # F-2: encrypt any new secret value before storing
                if k == "secret" and v:
                    from app.core.security_utils import encrypt_webhook_secret

                    v = encrypt_webhook_secret(v)
                setattr(wh, k, v)
        wh.updated_at = datetime.now(UTC)
        await session.flush()
        await session.refresh(wh)
        _subscriptions_changed()
        return wh

    @staticmethod
    async def delete_webhook(
        session: AsyncSession,
        webhook_id: UUID,
        organization_id: UUID | None = None,
    ) -> bool:

        wh = await PersistentWebhookService.get_webhook(
            session, webhook_id, organization_id=organization_id
        )
        if not wh:
            return False
        await session.delete(wh)
        await session.flush()
        _subscriptions_changed()
        return True

    @staticmethod
    async def enable_webhook(
        session: AsyncSession, webhook_id: UUID, organization_id: UUID | None = None
    ) -> Any:
        # D-1: always scope to org to prevent cross-tenant enable
        wh = await PersistentWebhookService.get_webhook(
            session, webhook_id, organization_id=organization_id
        )
        if not wh:
            return None
        wh.enabled = True
        wh.updated_at = datetime.now(UTC)
        await session.flush()
        await session.refresh(wh)
        _subscriptions_changed()
        return wh

    @staticmethod
    async def disable_webhook(
        session: AsyncSession, webhook_id: UUID, organization_id: UUID | None = None
    ) -> Any:
        # D-1: always scope to org to prevent cross-tenant disable
        wh = await PersistentWebhookService.get_webhook(
            session, webhook_id, organization_id=organization_id
        )
        if not wh:
            return None
        wh.enabled = False
        wh.updated_at = datetime.now(UTC)
        await session.flush()
        await session.refresh(wh)
        _subscriptions_changed()
        return wh

    # =====================================================================
    # Delivery Log
    # =====================================================================

    @staticmethod
    async def get_deliveries(
        session: AsyncSession,
        webhook_id: UUID,
        *,
        status: str | None = None,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        from app.models.webhooks import WebhookDelivery

        q = select(WebhookDelivery).where(WebhookDelivery.webhook_id == webhook_id)
        count_q = select(func.count(WebhookDelivery.id)).where(
            WebhookDelivery.webhook_id == webhook_id
        )

        if status:
            q = q.where(WebhookDelivery.status == status)
            count_q = count_q.where(WebhookDelivery.status == status)

        total = (await session.execute(count_q)).scalar() or 0
        offset = (page - 1) * per_page
        q = q.order_by(WebhookDelivery.created_at.desc()).offset(offset).limit(per_page)
        rows = (await session.execute(q)).scalars().all()

        return {"items": rows, "total": total, "page": page, "per_page": per_page}

    # =====================================================================
    # Statistics
    # =====================================================================

    @staticmethod
    async def get_stats(
        session: AsyncSession, webhook_id: UUID, organization_id: UUID | None = None
    ) -> dict[str, Any]:
        from app.models.webhooks import WebhookDelivery

        # D-2: scope to org to prevent cross-tenant stat exposure
        wh = await PersistentWebhookService.get_webhook(
            session, webhook_id, organization_id=organization_id
        )
        if not wh:
            return {}

        # D-2: single GROUP BY query instead of one query per DeliveryStatus value
        rows = (
            await session.execute(
                select(WebhookDelivery.status, func.count(WebhookDelivery.id))
                .where(WebhookDelivery.webhook_id == webhook_id)
                .group_by(WebhookDelivery.status)
            )
        ).all()
        status_counts = {str(r[0]): int(r[1]) for r in rows}

        total = sum(status_counts.values())
        success = status_counts.get("delivered", 0)

        # Avg response time (single query)
        avg_rt = (
            await session.execute(
                select(func.avg(WebhookDelivery.response_time_ms)).where(
                    WebhookDelivery.webhook_id == webhook_id,
                    WebhookDelivery.response_time_ms.isnot(None),
                )
            )
        ).scalar()

        return {
            "webhook_id": str(webhook_id),
            "total_deliveries": total,
            "success": success,
            "failed": status_counts.get("failed", 0),
            "pending": status_counts.get("pending", 0),
            "retrying": status_counts.get("retrying", 0),
            "success_rate": (success / total * 100) if total > 0 else 0.0,
            "avg_response_time_ms": float(avg_rt) if avg_rt else None,
            "enabled": wh.enabled,
            "failure_count": wh.failure_count,
            "last_triggered": wh.last_triggered.isoformat() if wh.last_triggered else None,
        }

    # =====================================================================
    # Dispatch / Send
    # =====================================================================

    @staticmethod
    async def dispatch_webhook(
        session: AsyncSession,
        webhook_id: UUID,
        event_type: str,
        payload: dict[str, Any],
        event_id: str | None = None,
        *,
        _webhook: Any = None,  # D-5: pre-loaded Webhook to avoid N+1 re-fetch
        timeout: float = 30.0,
        durable: bool = False,
    ) -> Any:
        """Send a webhook delivery.

        ``durable=True`` (event deliveries, see ``dispatch_event``) commits the
        pending row BEFORE the POST and the outcome right after it, and only then
        enqueues a retry. Without it the row, the outcome and the retry all
        rode on the caller's single commit at the end of the task: a commit that
        failed after a POST had been sent, or had failed, left no record and a
        retry task with nothing to find, and the event was lost. Now the worst
        case is a pending row with no task, which ``requeue_stalled_deliveries``
        sends again: a duplicate, never a loss (at-least-once, deduplicated by
        ``X-Webhook-Event-Id``).
        """
        from app.models.webhooks import DeliveryStatus, WebhookDelivery

        wh = _webhook or await PersistentWebhookService.get_webhook(session, webhook_id)
        if not wh or not wh.enabled:
            return None

        body_id = payload.get("id") if isinstance(payload, dict) else None
        delivery = WebhookDelivery(
            webhook_id=webhook_id,
            # The header must equal the body's ``id`` whenever the body has one.
            event_id=event_id or (str(body_id)[:64] if body_id else None) or str(uuid4()),
            event_type=event_type,
            status=DeliveryStatus.PENDING,
            payload=payload,
        )
        session.add(delivery)
        await session.flush()
        if durable:
            await session.commit()

        # Attempt HTTP delivery
        # safe_http_request applies DNS-rebinding-safe SSRF guard
        # (resolves + validates hostname, pins to IP, rejects redirects).
        from app.core.security_utils import safe_http_request

        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Event": event_type,
            "X-Webhook-Delivery": str(delivery.id),
            # Stable across retries and replays of the same event, so a
            # receiver can drop a duplicate (delivery is at-least-once).
            "X-Webhook-Event-Id": delivery.event_id,
        }

        body = json.dumps(payload, default=str)

        # HMAC Signature — F-2: decrypt secret before signing. The signature now
        # binds a timestamp (X-Webhook-Timestamp) so a receiver can reject a
        # replayed delivery outside its skew window (audit: webhook replay).
        if wh.secret:
            from app.core.security_utils import decrypt_webhook_secret, sign_webhook_payload

            raw_secret = decrypt_webhook_secret(wh.secret)
            ts = int(time.time())
            headers["X-Webhook-Timestamp"] = str(ts)
            headers["X-Webhook-Signature"] = sign_webhook_payload(raw_secret, body, ts)

        start_time = time.monotonic()
        try:
            resp = await safe_http_request(
                "POST",
                wh.url,
                content=body,
                headers=headers,
                verify_tls=wh.verify_ssl,
                timeout=timeout,
                allow_hosts=webhook_allowed_hosts(),
            )

            elapsed = (time.monotonic() - start_time) * 1000
            delivery.response_code = resp.status_code
            delivery.response_time_ms = elapsed
            delivery.sent_at = datetime.now(UTC)

            if 200 <= resp.status_code < 300:
                delivery.status = DeliveryStatus.DELIVERED
                wh.success_count += 1
                wh.last_success = datetime.now(UTC)
            else:
                delivery.status = DeliveryStatus.FAILED
                delivery.error_message = f"HTTP {resp.status_code}"
                wh.failure_count += 1
                wh.last_failure = datetime.now(UTC)

        except ValueError as e:
            # SSRF / URL validation failure — safe_http_request raises ValueError
            elapsed = (time.monotonic() - start_time) * 1000
            delivery.status = DeliveryStatus.FAILED
            delivery.error_message = _sanitize_webhook_error(f"SSRF blocked: {e}")
            delivery.response_time_ms = elapsed
            delivery.sent_at = datetime.now(UTC)
            wh.failure_count += 1
            wh.last_failure = datetime.now(UTC)
        except Exception as e:
            elapsed = (time.monotonic() - start_time) * 1000
            delivery.status = DeliveryStatus.FAILED
            # ``str(e)`` from httpx/asyncio includes the full failing
            # URL — querystring tokens + basic-auth-in-URL would land
            # in the delivery log verbatim. Strip URLs + cap length
            # before persisting.
            delivery.error_message = _sanitize_webhook_error(str(e))
            delivery.response_time_ms = elapsed
            delivery.sent_at = datetime.now(UTC)
            wh.failure_count += 1
            wh.last_failure = datetime.now(UTC)

        wh.last_triggered = datetime.now(UTC)
        wh.retry_count += 1 if delivery.status == DeliveryStatus.FAILED else 0
        if delivery.status == DeliveryStatus.FAILED and wh.max_retries > 0:
            # Recorded as retrying before the retry is queued, so the row says
            # what will happen even if the enqueue below fails (the sweeper then
            # requeues it).
            delivery.status = DeliveryStatus.RETRYING
        await session.flush()
        if durable:
            await session.commit()
        await session.refresh(delivery)

        # C-3: On initial failure, enqueue retry AFTER flush so the delivery row
        # is at minimum written (and, for a durable delivery, committed). For a
        # non-durable delivery the caller commits; if that transaction rolls back
        # the Celery task does not find the delivery and logs a warning.
        if delivery.status == DeliveryStatus.RETRYING:
            try:
                from app.tasks.webhooks import retry_webhook_delivery

                # No queue= here: an explicit queue kwarg on apply_async overrides
                # both the task's own routing and task_routes, so naming one would
                # re-strand these retries in an unconsumed queue. Let it route to
                # "default", which every deployment tier consumes.
                retry_webhook_delivery.apply_async(
                    args=[str(delivery.id)],
                    countdown=60,  # first retry after 60 s
                )
            except Exception as enqueue_err:
                logger.warning(
                    f"Failed to enqueue webhook retry for delivery {delivery.id}: {enqueue_err}"
                )

        return delivery

    @staticmethod
    async def test_webhook(session: AsyncSession, webhook_id: UUID) -> dict[str, Any]:
        """Send a test payload to a webhook."""
        event_id = str(uuid4())
        test_payload = {
            # Same id as X-Webhook-Event-Id, like every real delivery.
            "id": event_id,
            "event": "webhook.test",
            "timestamp": datetime.now(UTC).isoformat(),
            "message": "This is a test webhook delivery from FreeSDN",
            "data": {"test": True},
        }

        delivery = await PersistentWebhookService.dispatch_webhook(
            session,
            webhook_id,
            event_type="webhook.test",
            payload=test_payload,
            event_id=event_id,
        )

        if not delivery:
            return {"status": "error", "error": "Webhook not found or disabled"}

        result: dict[str, Any] = {
            "status": delivery.status,
            "delivery_id": str(delivery.id),
        }
        if delivery.response_code:
            result["response_status"] = delivery.response_code
        if delivery.response_time_ms:
            result["response_time_ms"] = delivery.response_time_ms
        if delivery.error_message:
            result["error"] = delivery.error_message

        return result

    # =====================================================================
    # Event Dispatch (called by other services)
    # =====================================================================

    @staticmethod
    async def dispatch_event(
        session: AsyncSession,
        event_type: str,
        payload: dict[str, Any],
        event_id: str | None = None,
        organization_id: UUID | None = None,
    ) -> int:
        """
        Deliver one event to every enabled webhook of its organization that wants it.

        Called by the ``app.tasks.webhooks.deliver_event`` task, which the
        event-bus forwarder (``app.services.webhook_events``) enqueues.

        Args:
            session: DB session (the caller commits).
            event_type: The event type string (e.g. "device.status.changed").
            payload: The JSON body to send (see ``webhook_events.build_envelope``).
            event_id: The bus event id. A webhook that already has a delivery
                for it is skipped, so a redelivered task does not post twice.
            organization_id: REQUIRED. ``None`` delivers to nobody: an event
                that belongs to no tenant must not reach every tenant's hooks.

        Returns:
            Number of webhooks a delivery was recorded for.
        """
        from app.models.webhooks import Webhook, WebhookDelivery
        from app.services.webhook_events import webhook_wants

        if organization_id is None:
            return 0

        webhooks = (
            (
                await session.execute(
                    select(Webhook).where(
                        Webhook.enabled.is_(True),
                        Webhook.organization_id == organization_id,
                    )
                )
            )
            .scalars()
            .all()
        )

        count = 0
        for wh in webhooks:
            if not webhook_wants(wh.event_types, event_type):
                continue

            if event_id:
                already = await session.scalar(
                    select(func.count(WebhookDelivery.id)).where(
                        WebhookDelivery.webhook_id == wh.id,
                        WebhookDelivery.event_id == event_id,
                    )
                )
                if already:
                    continue

            if await PersistentWebhookService._circuit_open(session, wh.id):
                await PersistentWebhookService._dead_letter_unsent(
                    session, wh, event_type, payload, event_id
                )
                # Per webhook, like the durable send below: a later webhook's
                # failure must not roll this record back.
                await session.commit()
                count += 1
                continue

            # D-5: pass the already-loaded wh object to avoid an N+1 re-fetch.
            # durable: each webhook's delivery is committed on its own, so a
            # redelivered task skips the webhooks already recorded (the check
            # above) instead of losing or repeating all of them together.
            await PersistentWebhookService.dispatch_webhook(
                session,
                wh.id,
                event_type,
                payload,
                event_id,
                _webhook=wh,
                timeout=EVENT_DELIVERY_TIMEOUT_SECONDS,
                durable=True,
            )
            count += 1

        return count

    @staticmethod
    async def _circuit_open(session: AsyncSession, webhook_id: UUID) -> bool:
        """True when the last N ATTEMPTED deliveries all failed, newest recently.

        Only attempted deliveries (``sent_at`` set) count, so the deliveries
        this skips do not keep the circuit open: once the newest attempt is
        older than the pause window, the next event is tried again.
        """
        from datetime import timedelta

        from app.models.webhooks import DeliveryStatus, WebhookDelivery

        recent = (
            await session.execute(
                select(WebhookDelivery.status, WebhookDelivery.sent_at)
                .where(
                    WebhookDelivery.webhook_id == webhook_id,
                    WebhookDelivery.sent_at.isnot(None),
                )
                .order_by(WebhookDelivery.sent_at.desc())
                .limit(CIRCUIT_FAILURE_THRESHOLD)
            )
        ).all()
        if len(recent) < CIRCUIT_FAILURE_THRESHOLD:
            return False
        if any(
            str(status) not in (DeliveryStatus.FAILED, DeliveryStatus.RETRYING)
            for status, _ in recent
        ):
            return False
        newest: datetime | None = recent[0][1]
        if newest is None:
            return False
        return newest >= datetime.now(UTC) - timedelta(seconds=CIRCUIT_PAUSE_SECONDS)

    @staticmethod
    async def _dead_letter_unsent(
        session: AsyncSession,
        wh: Any,
        event_type: str,
        payload: dict[str, Any],
        event_id: str | None,
    ) -> None:
        """Record an event that was not sent because the endpoint is failing.

        It is visible in the delivery log as failed and sits in the dead-letter
        queue, so the operator can replay it once the receiver is back.
        """
        from app.models.webhooks import DeliveryStatus, WebhookDeadLetter, WebhookDelivery

        reason = (
            f"Not sent: the last {CIRCUIT_FAILURE_THRESHOLD} deliveries to this endpoint "
            f"failed, so deliveries are paused for {CIRCUIT_PAUSE_SECONDS // 60} minutes. "
            "Replay this from the dead-letter queue once the receiver is back."
        )
        now = datetime.now(UTC)
        delivery = WebhookDelivery(
            webhook_id=wh.id,
            event_id=event_id or str(uuid4()),
            event_type=event_type,
            status=DeliveryStatus.FAILED,
            payload=payload,
            attempt_number=0,
            error_message=reason,
        )
        session.add(delivery)
        await session.flush()
        session.add(
            WebhookDeadLetter(
                webhook_id=wh.id,
                delivery_id=delivery.id,
                organization_id=wh.organization_id,
                event_type=event_type,
                payload=payload,
                failure_reason=reason,
                attempt_count=0,
                final_attempt_at=now,
            )
        )
        wh.failure_count += 1
        wh.last_failure = now
        await session.flush()

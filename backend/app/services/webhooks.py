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

from sqlalchemy import delete, func, select
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
        from app.core.security_utils import validate_url_ssrf
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
            validate_url_ssrf(url)  # raises ValueError on SSRF

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
        return wh

    @staticmethod
    async def update_webhook(
        session: AsyncSession,
        webhook_id: UUID,
        data: dict[str, Any],
        organization_id: UUID | None = None,
    ) -> Any:
        from app.core.security_utils import validate_url_ssrf

        wh = await PersistentWebhookService.get_webhook(
            session, webhook_id, organization_id=organization_id
        )
        if not wh:
            return None

        # Validate new URL if being changed
        if "url" in data and data["url"]:
            validate_url_ssrf(data["url"])

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
    ) -> Any:
        """Send a webhook delivery."""
        from app.models.webhooks import DeliveryStatus, WebhookDelivery

        wh = _webhook or await PersistentWebhookService.get_webhook(session, webhook_id)
        if not wh or not wh.enabled:
            return None

        delivery = WebhookDelivery(
            webhook_id=webhook_id,
            event_id=event_id or str(uuid4()),
            event_type=event_type,
            status=DeliveryStatus.PENDING,
            payload=payload,
        )
        session.add(delivery)
        await session.flush()

        # Attempt HTTP delivery
        # safe_http_request applies DNS-rebinding-safe SSRF guard
        # (resolves + validates hostname, pins to IP, rejects redirects).
        from app.core.security_utils import safe_http_request

        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Event": event_type,
            "X-Webhook-Delivery": str(delivery.id),
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
                timeout=30.0,
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
        await session.flush()
        await session.refresh(delivery)

        # C-3: On initial failure, enqueue retry AFTER flush so the delivery row
        # is at minimum written (and will be committed by the caller).  If the
        # parent transaction subsequently rolls back, the Celery task will not
        # find the delivery and will log a warning — preferable to never
        # persisting the delivery at all.
        if delivery.status == DeliveryStatus.FAILED and wh.max_retries > 0:
            try:
                delivery.status = DeliveryStatus.RETRYING
                await session.flush()  # write before enqueue so delivery exists
                from app.tasks.webhooks import retry_webhook_delivery

                retry_webhook_delivery.apply_async(
                    args=[str(delivery.id)],
                    countdown=60,  # first retry after 60 s
                    queue="webhooks",
                )
            except Exception as enqueue_err:
                logger.warning(
                    f"Failed to enqueue webhook retry for delivery {delivery.id}: {enqueue_err}"
                )

        return delivery

    @staticmethod
    async def test_webhook(session: AsyncSession, webhook_id: UUID) -> dict[str, Any]:
        """Send a test payload to a webhook."""
        test_payload = {
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
        Dispatch an event to all subscribed webhooks for the given organization.

        Args:
            session: DB session
            event_type: The event type string (e.g. "device.status.changed")
            payload: Event data payload
            event_id: Optional unique event ID for dedup/logging
            organization_id: Scope delivery to this org's webhooks only.
                             Passing None will dispatch to ALL enabled webhooks
                             (super-admin use case). Always pass org_id from
                             user-facing code to prevent cross-org delivery.

        Returns:
            Number of webhooks notified.
        """
        from app.models.webhooks import Webhook

        # SECURITY: always scope to the org that owns the event when provided.
        # Without this, a device.offline event for org A could fire org B's webhooks.
        q = select(Webhook).where(Webhook.enabled.is_(True))
        if organization_id is not None:
            q = q.where(Webhook.organization_id == organization_id)
        webhooks = (await session.execute(q)).scalars().all()

        count = 0
        for wh in webhooks:
            # Check if webhook is subscribed to this event type
            if wh.event_types and event_type not in wh.event_types:
                continue

            # D-5: pass the already-loaded wh object to avoid an N+1 re-fetch
            await PersistentWebhookService.dispatch_webhook(
                session, wh.id, event_type, payload, event_id, _webhook=wh
            )
            count += 1

        return count

    # =====================================================================
    # Cleanup
    # =====================================================================

    @staticmethod
    async def cleanup_old_deliveries(session: AsyncSession, days: int = 30) -> int:
        """Clean up old delivery log entries."""
        from datetime import timedelta

        from app.models.webhooks import WebhookDelivery

        cutoff = datetime.now(UTC) - timedelta(days=days)
        result = await session.execute(
            delete(WebhookDelivery).where(WebhookDelivery.created_at < cutoff)
        )
        await session.flush()
        return result.rowcount or 0  # type: ignore[attr-defined]

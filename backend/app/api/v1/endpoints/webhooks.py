# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Webhook Management API Endpoints
================================================

REST endpoints for webhook management.
Matches the frontend webhooksApi client at /api/v1/webhooks/*.
"""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user, get_session
from app.core.dependencies import (
    is_unscoped_org_admin,
    is_unscoped_superuser,
    org_scope_or_platform,
)
from app.schemas.webhooks import (
    WebhookCreate,
    WebhookDeliveryListResponse,
    WebhookListResponse,
    WebhookResponse,
    WebhookStatsResponse,
    WebhookTestResponse,
    WebhookUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def require_admin(user: Any) -> None:
    # a raw ``user.role`` check IGNORES the API-key scope
    # ceiling, letting a deliberately narrowed (scoped) super_admin/org_admin key
    # still pass via its role. Gate on the scope-aware unscoped-admin helpers so a
    # scoped key narrowed away from webhook operations fails closed.
    if not (is_unscoped_superuser(user) or is_unscoped_org_admin(user)):
        raise HTTPException(status_code=403, detail="Admin access required")


def _org_id(user: Any) -> UUID | None:
    """Return the tenant filter for webhook queries.

    a scoped super_admin key (``organization_id`` None) must NOT fall
    through to an unfiltered (cross-tenant) webhook query — the webhook service
    treats ``organization_id=None`` as "no org filter". ``org_scope_or_platform``
    returns None (platform-wide) ONLY for an UNSCOPED super_admin and raises 403
    for a non-unscoped caller with no org, so every webhook endpoint here is
    either confined to the caller's org or fails closed.
    """
    return org_scope_or_platform(user)


# =========================================================================
# CRUD
# =========================================================================


@router.get("/", response_model=WebhookListResponse)
async def list_webhooks(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    enabled: bool | None = None,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    require_admin(user)
    from app.services.webhooks import PersistentWebhookService as svc

    return await svc.list_webhooks(
        session,
        enabled=enabled,
        organization_id=_org_id(user),
        page=page,
        per_page=per_page,
    )


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    require_admin(user)
    from app.services.webhooks import PersistentWebhookService as svc

    wh = await svc.get_webhook(session, webhook_id, organization_id=_org_id(user))
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return wh


@router.post("/", response_model=WebhookResponse, status_code=201)
async def create_webhook(
    data: WebhookCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    require_admin(user)
    from app.services.webhooks import PersistentWebhookService as svc

    create_data = data.model_dump(exclude_unset=True)
    create_data["organization_id"] = _org_id(user)
    try:
        wh = await svc.create_webhook(session, create_data, user_id=user.id)
    except ValueError as exc:
        # SSRF guard or input-shape rejection from the service —
        # surface as 422 instead of 500. Previously every
        # ``http://127.0.0.1`` / metadata-IP URL fell through to an
        # uncaught traceback in the ASGI log.
        logger.info("Webhook create rejected: %s", exc)
        raise HTTPException(status_code=422, detail=str(exc))
    await session.commit()
    return wh


@router.patch("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: UUID,
    data: WebhookUpdate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    require_admin(user)
    from app.services.webhooks import PersistentWebhookService as svc

    try:
        wh = await svc.update_webhook(
            session,
            webhook_id,
            data.model_dump(exclude_unset=True),
            organization_id=_org_id(user),
        )
    except ValueError as exc:
        logger.info("Webhook update rejected: %s", exc)
        raise HTTPException(status_code=422, detail=str(exc))
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await session.commit()
    return wh


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    require_admin(user)
    from app.services.webhooks import PersistentWebhookService as svc

    deleted = await svc.delete_webhook(session, webhook_id, organization_id=_org_id(user))
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await session.commit()


# =========================================================================
# Enable / Disable
# =========================================================================


@router.post("/{webhook_id}/enable", response_model=WebhookResponse)
async def enable_webhook(
    webhook_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    require_admin(user)
    from app.services.webhooks import PersistentWebhookService as svc

    wh = await svc.enable_webhook(session, webhook_id, organization_id=_org_id(user))
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await session.commit()
    return wh


@router.post("/{webhook_id}/disable", response_model=WebhookResponse)
async def disable_webhook(
    webhook_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    require_admin(user)
    from app.services.webhooks import PersistentWebhookService as svc

    wh = await svc.disable_webhook(session, webhook_id, organization_id=_org_id(user))
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await session.commit()
    return wh


# =========================================================================
# Stats & Deliveries
# =========================================================================


@router.get("/{webhook_id}/stats", response_model=WebhookStatsResponse)
async def get_stats(
    webhook_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    # Stats expose failure_count + last_triggered which carry
    # operational signal that should be admin-only, matching the
    # rest of the file. Previously any org member could enumerate.
    require_admin(user)
    from app.services.webhooks import PersistentWebhookService as svc

    stats = await svc.get_stats(session, webhook_id, organization_id=_org_id(user))
    if not stats:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return stats


@router.get("/{webhook_id}/deliveries", response_model=WebhookDeliveryListResponse)
async def get_deliveries(
    webhook_id: UUID,
    status: str | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    # Delivery rows carry ``error_message`` which (despite the
    # sanitizer below) may quote response bodies / fragments; admin-
    # only matches the rest of the file.
    require_admin(user)
    from app.services.webhooks import PersistentWebhookService as svc

    # Verify the webhook belongs to the caller's org before exposing delivery history
    wh = await svc.get_webhook(session, webhook_id, organization_id=_org_id(user))
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return await svc.get_deliveries(
        session, webhook_id, status=status, page=page, per_page=per_page
    )


# =========================================================================
# Test
# =========================================================================


@router.post("/{webhook_id}/test", response_model=WebhookTestResponse)
async def test_webhook(
    webhook_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    require_admin(user)
    from app.services.webhooks import PersistentWebhookService as svc

    # Verify the webhook belongs to the caller's org BEFORE dispatching
    # the test. Previously ``/test`` returned 200 with ``{status:'error',
    # error:'Webhook not found or disabled'}`` for any UUID, including
    # foreign ones — operator couldn't tell "wrong UUID" from "disabled".
    wh = await svc.get_webhook(session, webhook_id, organization_id=_org_id(user))
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    result = await svc.test_webhook(session, webhook_id)
    await session.commit()
    return result


# =========================================================================
# Dead-Letter Queue (DLQ)
# =========================================================================


@router.get("/{webhook_id}/dead-letters")
async def list_dead_letters(
    webhook_id: UUID,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """List dead-letter queue entries for a webhook (deliveries that exhausted all retries)."""
    require_admin(user)
    from sqlalchemy import func, select

    from app.models.webhooks import Webhook, WebhookDeadLetter

    # Verify the webhook belongs to the caller's org
    wh = (
        await session.execute(
            select(Webhook).where(
                Webhook.id == webhook_id,
                Webhook.organization_id == _org_id(user),
            )
        )
    ).scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    count_q = (
        select(func.count())
        .select_from(WebhookDeadLetter)
        .where(WebhookDeadLetter.webhook_id == webhook_id)
    )
    total = (await session.execute(count_q)).scalar() or 0
    pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page

    rows = (
        (
            await session.execute(
                select(WebhookDeadLetter)
                .where(WebhookDeadLetter.webhook_id == webhook_id)
                .order_by(WebhookDeadLetter.created_at.desc())
                .offset(offset)
                .limit(per_page)
            )
        )
        .scalars()
        .all()
    )

    return {
        "items": [
            {
                "id": str(r.id),
                "webhook_id": str(r.webhook_id),
                "delivery_id": str(r.delivery_id),
                "event_type": r.event_type,
                "failure_reason": r.failure_reason,
                "attempt_count": r.attempt_count,
                "final_attempt_at": r.final_attempt_at.isoformat() if r.final_attempt_at else None,
                "replayed_at": r.replayed_at.isoformat() if r.replayed_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.post("/{webhook_id}/dead-letters/{dlq_id}/replay", status_code=202)
async def replay_dead_letter(
    webhook_id: UUID,
    dlq_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """
    Replay a dead-letter queue entry.

    Creates a fresh WebhookDelivery from the stored payload and enqueues it
    for immediate delivery (attempt 1, full retry budget).
    """
    require_admin(user)
    from sqlalchemy import select

    from app.models.webhooks import (
        DeliveryStatus,
        Webhook,
        WebhookDeadLetter,
        WebhookDelivery,
    )
    from app.tasks.webhooks import retry_webhook_delivery

    # Verify ownership
    wh = (
        await session.execute(
            select(Webhook).where(
                Webhook.id == webhook_id,
                Webhook.organization_id == _org_id(user),
            )
        )
    ).scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    dlq = (
        await session.execute(
            select(WebhookDeadLetter).where(
                WebhookDeadLetter.id == dlq_id,
                WebhookDeadLetter.webhook_id == webhook_id,
            )
        )
    ).scalar_one_or_none()
    if not dlq:
        raise HTTPException(status_code=404, detail="Dead-letter entry not found")

    if dlq.replayed_at:
        raise HTTPException(status_code=409, detail="Entry has already been replayed")

    # Create a fresh delivery record for this replay
    from uuid import uuid4

    new_delivery = WebhookDelivery(
        webhook_id=webhook_id,
        event_id=str(uuid4()),
        event_type=dlq.event_type,
        status=DeliveryStatus.PENDING,
        payload=dlq.payload,
        attempt_number=0,
    )
    session.add(new_delivery)
    await session.flush()
    await session.refresh(new_delivery)

    # Mark DLQ entry as replayed
    dlq.replayed_at = datetime.now(UTC)
    dlq.replayed_by = user.id

    await session.commit()

    # Enqueue immediate retry (no countdown — replay is user-initiated).
    # No queue= : an explicit queue kwarg overrides the task's routing, so naming
    # one here would strand the replay in an unconsumed queue. Routes to "default".
    retry_webhook_delivery.apply_async(
        args=[str(new_delivery.id)],
        countdown=0,
    )

    return {
        "status": "queued",
        "new_delivery_id": str(new_delivery.id),
        "message": "Replay queued. Check delivery history for result.",
    }


@router.post("/{webhook_id}/dead-letters/replay-all", status_code=202)
async def replay_all_dead_letters(
    webhook_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Replay all un-replayed DLQ entries for this webhook."""
    require_admin(user)
    from uuid import uuid4

    from sqlalchemy import select

    from app.models.webhooks import (
        DeliveryStatus,
        Webhook,
        WebhookDeadLetter,
        WebhookDelivery,
    )
    from app.tasks.webhooks import retry_webhook_delivery

    wh = (
        await session.execute(
            select(Webhook).where(
                Webhook.id == webhook_id,
                Webhook.organization_id == _org_id(user),
            )
        )
    ).scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    dlq_entries = (
        (
            await session.execute(
                select(WebhookDeadLetter).where(
                    WebhookDeadLetter.webhook_id == webhook_id,
                    WebhookDeadLetter.replayed_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )

    queued = 0
    for dlq in dlq_entries:
        new_delivery = WebhookDelivery(
            webhook_id=webhook_id,
            event_id=str(uuid4()),
            event_type=dlq.event_type,
            status=DeliveryStatus.PENDING,
            payload=dlq.payload,
            attempt_number=0,
        )
        session.add(new_delivery)
        await session.flush()
        await session.refresh(new_delivery)

        dlq.replayed_at = datetime.now(UTC)
        dlq.replayed_by = user.id

        # No queue= : see the note on the single-replay path above.
        retry_webhook_delivery.apply_async(
            args=[str(new_delivery.id)],
            countdown=queued * 2,  # stagger replays by 2 s each to avoid thundering herd
        )
        queued += 1

    await session.commit()

    return {"status": "queued", "count": queued}

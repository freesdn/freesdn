# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — WebPush service
=========================

Browser push notifications for camera alerts (and, in time, any module).

Design notes:
  * ``pywebpush`` is an OPTIONAL dependency and the VAPID keys are optional
    config. Both are imported/read defensively: if either is missing, push is
    simply *disabled* (``push_enabled()`` is False, endpoints 503, dispatch is a
    no-op) — the app never crashes for lack of push.
  * ``pywebpush`` does blocking HTTP, so every send runs in a thread
    (``asyncio.to_thread``) to avoid stalling the event loop.
  * A push service returning 404/410 means the subscription is permanently gone
    (browser uninstalled / unsubscribed) — those rows are pruned automatically.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

logger = logging.getLogger(__name__)

try:  # optional dependency — push is disabled if it's not installed
    from pywebpush import WebPushException, webpush
except Exception:  # pragma: no cover - import guard
    webpush = None  # type: ignore[assignment]
    WebPushException = Exception  # type: ignore[assignment,misc]


def push_enabled() -> bool:
    """True only when the dependency is installed AND VAPID keys are configured."""
    return bool(webpush is not None and settings.VAPID_PUBLIC_KEY and settings.VAPID_PRIVATE_KEY)


def vapid_public_key() -> str:
    return settings.VAPID_PUBLIC_KEY


class PushService:
    """Manage WebPush subscriptions and fan out notifications to an org."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def subscribe(
        self,
        *,
        user_id: UUID,
        organization_id: UUID,
        endpoint: str,
        p256dh: str,
        auth: str,
        user_agent: str | None = None,
    ) -> None:
        """Upsert a subscription keyed on its endpoint (re-subscribing a browser
        that rotated its keys must update, not duplicate or 409)."""
        from app.modules.cameras.models import PushSubscription

        stmt = pg_insert(PushSubscription).values(
            user_id=user_id,
            organization_id=organization_id,
            endpoint=endpoint,
            p256dh=p256dh,
            auth=auth,
            user_agent=(user_agent or "")[:255] or None,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_push_subscriptions_endpoint",
            set_={
                "user_id": user_id,
                "organization_id": organization_id,
                "p256dh": p256dh,
                "auth": auth,
                "user_agent": (user_agent or "")[:255] or None,
            },
        )
        await self.db.execute(stmt)
        await self.db.commit()

    async def unsubscribe(self, *, endpoint: str, organization_id: UUID) -> int:
        """Remove a subscription by endpoint (org-scoped so a user can only drop
        their own org's rows)."""
        from app.modules.cameras.models import PushSubscription

        result = await self.db.execute(
            delete(PushSubscription).where(
                PushSubscription.endpoint == endpoint,
                PushSubscription.organization_id == organization_id,
            )
        )
        await self.db.commit()
        return result.rowcount or 0

    @staticmethod
    def _send_one(sub_info: dict[str, Any], data: str) -> int | None:
        """Blocking send of one push. Returns an HTTP status code on failure
        (for dead-endpoint pruning) or None on success."""
        try:
            webpush(  # type: ignore[misc]
                subscription_info=sub_info,
                data=data,
                vapid_private_key=settings.VAPID_PRIVATE_KEY,
                vapid_claims={"sub": settings.VAPID_SUBJECT},
                ttl=60,
            )
            return None
        except WebPushException as exc:  # type: ignore[misc]
            status = getattr(getattr(exc, "response", None), "status_code", None)
            return int(status) if status else 0
        except Exception:  # pragma: no cover - defensive
            return 0

    async def _recipient_user_ids(
        self, organization_id: UUID, site_id: UUID | None
    ) -> set[UUID] | None:
        """User IDs in the org that may be notified about an event at ``site_id``.

        Returns ``None`` (== "no scoping, everyone in the org") when ``site_id``
        is None — an org-level alert with no site dimension keeps the legacy
        org-wide fan-out. Otherwise returns the explicit allowed set, mirroring
        ``CurrentUser.can_access_site`` exactly: a user is included iff they are
        super_admin / admin / org_admin, OR have NO ``user_site_access`` rows
        (grant-less → unrestricted, backward-compatible), OR have a grant for
        ``site_id``. Site-limited users without a grant for the site are excluded
        (an empty set therefore means "notify no one"). ``is_superuser`` is not a
        column on ``User`` — the superuser concept is the ``super_admin`` role."""
        if site_id is None:
            return None
        from app.models.core import User, UserSiteAccess

        _ADMIN_ROLES = ("super_admin", "admin", "org_admin")

        # Admins are never site-limited → always notified.
        admin_rows = (
            await self.db.execute(
                select(User.id).where(
                    User.organization_id == organization_id,
                    User.role.in_(_ADMIN_ROLES),
                )
            )
        ).all()
        allowed: set[UUID] = {r[0] for r in admin_rows}

        # Users with at least one site grant in this org (i.e. site-limited).
        granted_user_rows = (
            await self.db.execute(
                select(UserSiteAccess.user_id)
                .join(User, User.id == UserSiteAccess.user_id)
                .where(User.organization_id == organization_id)
                .distinct()
            )
        ).all()
        users_with_grants: set[UUID] = {r[0] for r in granted_user_rows}

        # Grant-less non-admin users → unrestricted (matches can_access_site).
        nonadmin_rows = (
            await self.db.execute(
                select(User.id).where(
                    User.organization_id == organization_id,
                    User.role.not_in(_ADMIN_ROLES),
                )
            )
        ).all()
        for (uid,) in nonadmin_rows:
            if uid not in users_with_grants:
                allowed.add(uid)

        # Users explicitly granted this site.
        site_grant_rows = (
            await self.db.execute(
                select(UserSiteAccess.user_id).where(UserSiteAccess.site_id == site_id)
            )
        ).all()
        allowed.update(r[0] for r in site_grant_rows)
        return allowed

    async def send_to_org(
        self,
        organization_id: UUID,
        payload: dict[str, Any],
        *,
        site_id: UUID | None = None,
    ) -> int:
        """Fan a notification out to subscriptions in the org. Prunes any
        endpoint the push service reports as permanently gone (404/410).
        Returns the number successfully delivered. Never raises.

        When ``site_id`` is supplied, recipients are scoped to users who may
        access that site (per the same rule as ``CurrentUser.can_access_site``):
        super_admin / org_admin, users with NO site grants at all, or users with
        a grant for ``site_id``. A site-limited operator without a grant for the
        camera's site is therefore NOT notified — closing the org-wide fan-out
        leak (a notification body referencing a sibling-site camera). ``None``
        (org-level alert, no site dimension) preserves the legacy org-wide fan."""
        if not push_enabled():
            return 0
        from app.modules.cameras.models import PushSubscription

        recipient_ids = await self._recipient_user_ids(organization_id, site_id)
        if recipient_ids is not None and not recipient_ids:
            return 0

        q = select(PushSubscription).where(PushSubscription.organization_id == organization_id)
        if recipient_ids is not None:
            q = q.where(PushSubscription.user_id.in_(recipient_ids))
        rows = (await self.db.execute(q)).scalars().all()
        if not rows:
            return 0

        data = json.dumps(payload)
        dead: list[str] = []
        delivered = 0

        async def _dispatch(row: Any) -> None:
            nonlocal delivered
            sub_info = {
                "endpoint": row.endpoint,
                "keys": {"p256dh": row.p256dh, "auth": row.auth},
            }
            status = await asyncio.to_thread(self._send_one, sub_info, data)
            if status is None:
                delivered += 1
            elif status in (404, 410):
                dead.append(row.endpoint)

        # Bounded fan-out so a big org doesn't open hundreds of sockets at once.
        sem = asyncio.Semaphore(16)

        async def _bounded(row: Any) -> None:
            async with sem:
                await _dispatch(row)

        await asyncio.gather(*(_bounded(r) for r in rows), return_exceptions=True)

        if dead:
            await self.db.execute(
                delete(PushSubscription).where(PushSubscription.endpoint.in_(dead))
            )
        # Stamp last_used on the live ones so we can later reap stale subs.
        live = [r.endpoint for r in rows if r.endpoint not in dead]
        if live:
            from datetime import UTC, datetime

            await self.db.execute(
                update(PushSubscription)
                .where(PushSubscription.endpoint.in_(live))
                .values(last_used_at=datetime.now(UTC))
            )
        await self.db.commit()
        if dead:
            logger.info(
                "Pruned %d dead push subscription(s) for org %s", len(dead), organization_id
            )
        return delivered

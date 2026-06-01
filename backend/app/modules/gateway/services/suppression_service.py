# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Suppression Service
===================================

Manages DHCP / DNS suppression rules on limb devices to prevent
double-service conflicts (e.g. brain and limb both serving DHCP).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.site_access import site_ids_for_request
from app.modules.gateway.models import SuppressionRule

logger = logging.getLogger(__name__)


class SuppressionService:
    """CRUD for active suppression rules."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_rules(
        self,
        org_id: UUID,
        *,
        site_id: UUID | None = None,
        device_id: UUID | None = None,
        active_only: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SuppressionRule], int]:
        q = select(SuppressionRule).where(
            SuppressionRule.organization_id == org_id,
        )
        cq = (
            select(func.count())
            .select_from(SuppressionRule)
            .where(
                SuppressionRule.organization_id == org_id,
            )
        )
        if site_id:
            q = q.where(SuppressionRule.site_id == site_id)
            cq = cq.where(SuppressionRule.site_id == site_id)
        if device_id:
            q = q.where(SuppressionRule.device_id == device_id)
            cq = cq.where(SuppressionRule.device_id == device_id)
        if active_only:
            q = q.where(SuppressionRule.is_active.is_(True))
            cq = cq.where(SuppressionRule.is_active.is_(True))
        # (R5): fold the request caller's per-user site grant into
        # SQL (authoritative) so a site-limited operator never receives or counts
        # sibling-site suppression rules. site_id is NOT NULL on this model.
        # None = unrestricted / admin / background (no-op).
        _granted = site_ids_for_request()
        if _granted is not None:
            q = q.where(SuppressionRule.site_id.in_(_granted))
            cq = cq.where(SuppressionRule.site_id.in_(_granted))

        total = (await self.db.execute(cq)).scalar() or 0
        items = list((await self.db.execute(q.limit(limit).offset(offset))).scalars().all())
        return items, total

    async def create_rule(
        self,
        org_id: UUID,
        *,
        site_id: UUID,
        device_id: UUID,
        resource_type: str,
        scope: str,
        reason: str,
        suppression_action: str,
    ) -> SuppressionRule:
        rule = SuppressionRule(
            organization_id=org_id,
            site_id=site_id,
            device_id=device_id,
            resource_type=resource_type,
            scope=scope,
            reason=reason,
            suppression_action=suppression_action,
            is_active=True,
            applied_at=datetime.now(UTC),
        )
        self.db.add(rule)
        await self.db.flush()
        await self.db.refresh(rule)
        return rule

    async def deactivate_rule(
        self,
        rule_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> SuppressionRule | None:
        q = select(SuppressionRule).where(SuppressionRule.id == rule_id)
        if org_id is not None:
            q = q.where(SuppressionRule.organization_id == org_id)
        result = await self.db.execute(q)
        rule = result.scalar_one_or_none()
        if rule:
            rule.is_active = False
            await self.db.flush()
            await self.db.refresh(rule)
        return rule

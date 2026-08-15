# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — VLAN Template Service
=====================================

CRUD for org-level VLAN templates.  Templates are reusable
blueprints that can be applied when creating canonical VLANs
for new sites.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.gateway.models import (
    CanonicalVLAN,
    ManagementState,
    VLANPurpose,
    VLANTemplate,
)

logger = logging.getLogger(__name__)


class TemplateError(Exception):
    """Base template error."""


class TemplateNotFoundError(TemplateError):
    def __init__(self, template_id: UUID):
        super().__init__(f"VLAN template not found: {template_id}")


class TemplateConflictError(TemplateError):
    pass


class TemplateService:
    """CRUD operations for VLAN templates."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ── List ─────────────────────────────────────────────────────────────

    async def list_templates(
        self,
        org_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[VLANTemplate], int]:
        """List all active templates for an organization."""
        base = select(VLANTemplate).where(
            VLANTemplate.organization_id == org_id,
            VLANTemplate.deleted_at.is_(None),
        )
        count_q = select(func.count()).select_from(base.subquery())
        total = (await self.db.execute(count_q)).scalar() or 0

        items_q = base.order_by(VLANTemplate.vlan_id).limit(limit).offset(offset)
        items = list((await self.db.execute(items_q)).scalars().all())
        return items, total

    # ── Get ──────────────────────────────────────────────────────────────

    async def get_template(self, template_id: UUID, *, org_id: UUID | None = None) -> VLANTemplate:
        """Fetch a single template by UUID."""
        q = select(VLANTemplate).where(
            VLANTemplate.id == template_id,
            VLANTemplate.deleted_at.is_(None),
        )
        if org_id is not None:
            q = q.where(VLANTemplate.organization_id == org_id)
        result = await self.db.execute(q)
        tmpl = result.scalar_one_or_none()
        if tmpl is None:
            raise TemplateNotFoundError(template_id)
        return tmpl

    # ── Create ───────────────────────────────────────────────────────────

    async def create_template(
        self,
        org_id: UUID,
        *,
        name: str,
        vlan_id: int,
        subnet_template: str,
        purpose: str = VLANPurpose.GENERAL,
        description: str | None = None,
        dhcp_enabled: bool = True,
        dhcp_options: dict[str, Any] | None = None,
        settings: dict[str, Any] | None = None,
        created_by: UUID | None = None,
    ) -> VLANTemplate:
        """Create a new VLAN template."""
        # Check for duplicate name within org
        dup = await self.db.execute(
            select(VLANTemplate).where(
                VLANTemplate.organization_id == org_id,
                VLANTemplate.name == name,
                VLANTemplate.deleted_at.is_(None),
            )
        )
        if dup.scalar_one_or_none() is not None:
            raise TemplateConflictError(f"Template '{name}' already exists in this organization")

        tmpl = VLANTemplate(
            organization_id=org_id,
            name=name,
            description=description,
            vlan_id=vlan_id,
            subnet_template=subnet_template,
            purpose=purpose,
            dhcp_enabled=dhcp_enabled,
            dhcp_options=dhcp_options or {},
            settings=settings or {},
            created_by=created_by,
        )
        self.db.add(tmpl)
        await self.db.flush()
        await self.db.refresh(tmpl)
        logger.info("Created VLAN template '%s' (VLAN %d) for org %s", name, vlan_id, org_id)
        return tmpl

    # ── Update ───────────────────────────────────────────────────────────

    async def update_template(
        self,
        template_id: UUID,
        org_id: UUID,
        *,
        updated_by: UUID | None = None,
        **fields: Any,
    ) -> VLANTemplate:
        """Partial-update a VLAN template."""
        tmpl = await self.get_template(template_id, org_id=org_id)

        allowed = {
            "name",
            "description",
            "vlan_id",
            "subnet_template",
            "purpose",
            "dhcp_enabled",
            "dhcp_options",
            "settings",
        }
        # Fields whose DB column is nullable (None is a valid value)
        _nullable = {"description"}

        for key, value in fields.items():
            if key not in allowed:
                continue
            # Allow None only for nullable columns
            if value is None and key not in _nullable:
                continue
            setattr(tmpl, key, value)

        if updated_by:
            tmpl.updated_by = updated_by

        await self.db.flush()
        await self.db.refresh(tmpl)
        logger.info("Updated VLAN template %s", template_id)
        return tmpl

    # ── Delete (soft) ────────────────────────────────────────────────────

    async def delete_template(
        self,
        template_id: UUID,
        org_id: UUID,
    ) -> None:
        """Soft-delete a VLAN template."""
        tmpl = await self.get_template(template_id, org_id=org_id)
        tmpl.deleted_at = datetime.now(UTC)
        await self.db.flush()
        logger.info("Soft-deleted VLAN template %s", template_id)

    # ── Apply to Site ────────────────────────────────────────────────────

    async def apply_template(
        self,
        template_id: UUID,
        org_id: UUID,
        site_id: UUID,
        *,
        created_by: UUID | None = None,
    ) -> CanonicalVLAN:
        """
        Create a CanonicalVLAN from a template for a specific site.

        Returns the newly created CanonicalVLAN. Raises
        TemplateConflictError if a canonical VLAN with the same
        tag already exists at the site.
        """
        tmpl = await self.get_template(template_id, org_id=org_id)

        # Check for existing canonical VLAN at this site with same tag
        existing = await self.db.execute(
            select(CanonicalVLAN).where(
                CanonicalVLAN.organization_id == org_id,
                CanonicalVLAN.site_id == site_id,
                CanonicalVLAN.vlan_id == tmpl.vlan_id,
                CanonicalVLAN.deleted_at.is_(None),
            )
        )
        if existing.scalar_one_or_none() is not None:
            raise TemplateConflictError(
                f"Canonical VLAN {tmpl.vlan_id} already exists at site {site_id}"
            )

        vlan = CanonicalVLAN(
            organization_id=org_id,
            site_id=site_id,
            vlan_id=tmpl.vlan_id,
            name=tmpl.name,
            description=tmpl.description,
            purpose=tmpl.purpose,
            subnet=tmpl.subnet_template,
            gateway_ip=tmpl.gateway_ip_template,
            management_state=ManagementState.MANAGED,
            template_id=tmpl.id,
            dhcp_enabled=tmpl.dhcp_enabled,
            created_by=created_by,
        )
        self.db.add(vlan)
        await self.db.flush()
        await self.db.refresh(vlan)
        logger.info(
            "Applied template '%s' → CanonicalVLAN %s at site %s",
            tmpl.name,
            vlan.id,
            site_id,
        )
        return vlan

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Site Role Map Service
====================================

CRUD + validation for the Site Role Map: which device is the brain,
which devices are limbs, and what resource authorities apply.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.site_access import assert_site_access_for_request, site_ids_for_request
from app.modules.gateway.models import (
    NetworkRole,
    SiteRoleAssignment,
    SiteRoleMap,
)

logger = logging.getLogger(__name__)


class RoleMapError(Exception):
    """Base error for role map operations."""


class RoleMapNotFoundError(RoleMapError):
    def __init__(self, site_id: UUID):
        super().__init__(f"No role map for site {site_id}")
        self.site_id = site_id


class RoleMapService:
    """Business logic for Site Role Map."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ── Queries ──────────────────────────────────────────────────────────

    async def get_role_map(
        self,
        site_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> SiteRoleMap | None:
        """Return the role map for *site_id*, or ``None``."""
        # Defense in depth: even if a caller reaches the service
        # without the API guard, enforce the request-scoped per-user site grant.
        # No-op in system/background context or for unrestricted users.
        assert_site_access_for_request(site_id, detail="No role map for this site")
        q = (
            select(SiteRoleMap)
            .options(selectinload(SiteRoleMap.assignments))
            .where(SiteRoleMap.site_id == site_id)
        )
        if org_id is not None:
            q = q.where(SiteRoleMap.organization_id == org_id)
        result = await self.db.execute(q)
        return result.scalar_one_or_none()

    async def get_role_map_or_raise(
        self,
        site_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> SiteRoleMap:
        rm = await self.get_role_map(site_id, org_id=org_id)
        if rm is None:
            raise RoleMapNotFoundError(site_id)
        return rm

    async def get_brain(
        self,
        site_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> SiteRoleAssignment | None:
        """Return the brain assignment for a site, or ``None``."""
        rm = await self.get_role_map(site_id, org_id=org_id)
        if rm is None:
            return None
        return next(
            (a for a in rm.assignments if a.role == NetworkRole.BRAIN),
            None,
        )

    async def get_limbs(
        self,
        site_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> list[SiteRoleAssignment]:
        """Return all limb assignments for a site."""
        rm = await self.get_role_map(site_id, org_id=org_id)
        if rm is None:
            return []
        return [a for a in rm.assignments if a.role == NetworkRole.LIMB]

    # ── Mutations ────────────────────────────────────────────────────────

    async def upsert_role_map(
        self,
        org_id: UUID,
        site_id: UUID,
        assignments: list[dict[str, Any]],
        authority_map: dict[str, str] | None = None,
    ) -> SiteRoleMap:
        """Create or replace the role map for *site_id*."""
        # Defense in depth: enforce the request-scoped per-user
        # site grant before any site-addressed write. No-op for unrestricted
        # users / system context.
        assert_site_access_for_request(site_id, detail="Site not found")
        # Validate assignment structure
        errors = self._validate_assignments(assignments)
        if errors:
            raise RoleMapError("; ".join(errors))

        # IDOR guard: the API extracts
        # ``org_id`` from the current user but never bound ``site_id``
        # to that org. An operator with a UUID for another tenant's
        # site could PATCH /gateway/topology/{their_site_id} and edit
        # its role map. Verify site belongs to org BEFORE checking
        # any gateway/controller refs. 404 not 403 — don't leak
        # "exists elsewhere" via differential codes.
        from app.models.core import Site

        site = await self.db.get(Site, site_id)
        if site is None or site.organization_id != org_id:
            raise RoleMapError(f"Site {site_id} not found or does not belong to this organization")

        # Per-user site grant for the BODY-referenced devices. The path site_id
        # is grant-checked above (assert_site_access_for_request), but the
        # gateway_id / controller_id in the body each carry their OWN site_id and
        # could point at a SIBLING site the caller isn't granted (same org). Fold
        # the caller's grant into the validation queries below — mirroring
        # network/service.py _sites_for_org and controllers.py so a
        # sibling-site device UUID is indistinguishable from a bogus one (same
        # not-found error, no cross-site existence oracle). None ⇒ unrestricted /
        # system context (no extra filter).
        granted = site_ids_for_request()

        # Verify all referenced gateways belong to this org (and granted site)
        gw_ids = [a["gateway_id"] for a in assignments if a.get("gateway_id")]
        if gw_ids:
            from app.modules.firewall.models import GatewayConnection

            gw_query = select(GatewayConnection.id).where(
                GatewayConnection.id.in_(gw_ids),
                GatewayConnection.org_id == org_id,
                GatewayConnection.deleted_at.is_(None),
            )
            if granted is not None:
                # org-level gateways (no site) stay bindable; site-bound ones must
                # be in the caller's grant.
                gw_query = gw_query.where(
                    or_(
                        GatewayConnection.site_id.is_(None),
                        GatewayConnection.site_id.in_(granted),
                    )
                )
            gw_result = await self.db.execute(gw_query)
            valid_ids = {row[0] for row in gw_result.all()}
            for gw_id in gw_ids:
                if UUID(str(gw_id)) not in valid_ids:
                    raise RoleMapError(
                        f"Gateway {gw_id} not found or does not belong to this organization"
                    )

        # Verify all referenced controllers belong to this org (and granted site)
        ctrl_ids = [a["controller_id"] for a in assignments if a.get("controller_id")]
        if ctrl_ids:
            from app.models.core import Controller, Site

            ctrl_query = (
                select(Controller.id)
                .join(Site, Controller.site_id == Site.id)
                .where(
                    Controller.id.in_(ctrl_ids),
                    Site.organization_id == org_id,
                    Controller.deleted_at.is_(None),
                )
            )
            if granted is not None:
                # Controller.site_id is NOT NULL, so every controller has a site.
                ctrl_query = ctrl_query.where(Site.id.in_(granted))
            ctrl_result = await self.db.execute(ctrl_query)
            valid_ctrl_ids = {row[0] for row in ctrl_result.all()}
            for ctrl_id in ctrl_ids:
                if UUID(str(ctrl_id)) not in valid_ctrl_ids:
                    raise RoleMapError(
                        f"Controller {ctrl_id} not found or does not belong to this organization"
                    )

        existing = await self.get_role_map(site_id, org_id=org_id)

        if existing:
            # Drop old assignments
            await self.db.execute(
                delete(SiteRoleAssignment).where(SiteRoleAssignment.role_map_id == existing.id)
            )
            role_map = existing
            if authority_map:
                role_map.authority_map = authority_map
        else:
            role_map = SiteRoleMap(
                organization_id=org_id,
                site_id=site_id,
                authority_map=authority_map or SiteRoleMap.authority_map.default.arg(),
            )
            self.db.add(role_map)
            await self.db.flush()

        # Create new assignments
        for ad in assignments:
            device_type = ad.get("device_type", "gateway")
            assign = SiteRoleAssignment(
                role_map_id=role_map.id,
                gateway_id=ad.get("gateway_id"),
                controller_id=ad.get("controller_id"),
                device_type=device_type,
                role=ad["role"],
                priority=ad.get("priority", 0),
                suppress_dhcp=ad.get("suppress_dhcp", False),
                capabilities=ad.get("capabilities", {}),
            )
            self.db.add(assign)

        await self.db.flush()
        await self.db.refresh(role_map)
        return role_map

    async def remove_role_map(
        self,
        site_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> None:
        """Delete role map for *site_id* (reverts site to per-controller mode)."""
        rm = await self.get_role_map(site_id, org_id=org_id)
        if rm:
            await self.db.delete(rm)
            await self.db.flush()

    # ── Validation ───────────────────────────────────────────────────────

    def _validate_assignments(self, assignments: list[dict[str, Any]]) -> list[str]:
        errors: list[str] = []
        brains = [a for a in assignments if a.get("role") == NetworkRole.BRAIN]
        if len(brains) > 1:
            errors.append("Only one brain device allowed per site")
        standby = [a for a in assignments if a.get("role") == NetworkRole.BRAIN_STANDBY]
        if len(standby) > 1:
            errors.append("Only one brain_standby device allowed per site")

        # Brain must be a gateway (firewall/router), not a controller
        for b in brains:
            if b.get("device_type") == "controller":
                errors.append("Brain must be a gateway device (firewall/router)")

        # Validate no duplicate device references
        seen_ids: set[str] = set()
        for a in assignments:
            device_id = str(a.get("gateway_id") or a.get("controller_id") or "")
            if not device_id:
                errors.append("Each assignment must have gateway_id or controller_id")
                continue
            if device_id in seen_ids:
                errors.append(f"Duplicate device: {device_id}")
            seen_ids.add(device_id)

            # Validate device_type consistency
            dt = a.get("device_type", "gateway")
            if dt == "gateway" and not a.get("gateway_id"):
                errors.append("device_type 'gateway' requires gateway_id")
            if dt == "controller" and not a.get("controller_id"):
                errors.append("device_type 'controller' requires controller_id")

        return errors

    def validate_dry_run(
        self, assignments: list[dict[str, Any]]
    ) -> tuple[bool, list[str], list[str]]:
        """Dry-run validation. Returns (is_valid, errors, warnings)."""
        errors = self._validate_assignments(assignments)
        warnings: list[str] = []

        has_brain = any(a.get("role") == NetworkRole.BRAIN for a in assignments)
        if not has_brain:
            warnings.append("No brain assigned — orchestration features will be unavailable")

        limbs_with_dhcp = [
            a
            for a in assignments
            if a.get("role") == NetworkRole.LIMB and not a.get("suppress_dhcp")
        ]
        if has_brain and limbs_with_dhcp:
            warnings.append(
                "Some limbs have DHCP enabled — consider suppressing to avoid conflicts"
            )

        return len(errors) == 0, errors, warnings

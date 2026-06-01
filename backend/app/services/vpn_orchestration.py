# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Orchestration Service
=========================================

Creates, manages, and tears down site-to-site VPN tunnels
using tunnel templates.  Supports point-to-point and full-mesh
topologies.
"""

import asyncio
import copy
import itertools
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.core import Site
from app.models.devices import Device
from app.models.vpn import SiteToSiteTunnel, VPNTunnelTemplate

logger = logging.getLogger(__name__)


def _safe_decrypt(value: str | None) -> str:
    """Decrypt a credential, falling back to the raw value if not encrypted."""
    if not value:
        return ""
    try:
        from app.core.crypto import decrypt_credential, is_encrypted

        if not is_encrypted(value):
            return value
        return decrypt_credential(value)
    except Exception:
        logger.warning("Failed to decrypt credential value, returning raw value")
        return value


class VPNOrchestrationService:
    """Orchestration layer for site-to-site VPN tunnels."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ──────────────────────────────────────────────────────────────────────
    # Templates
    # ──────────────────────────────────────────────────────────────────────

    async def list_templates(
        self,
        org_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[VPNTunnelTemplate], int]:
        """List tunnel templates for the organisation."""
        from sqlalchemy import func

        base = select(VPNTunnelTemplate).where(
            VPNTunnelTemplate.organization_id == org_id,
            VPNTunnelTemplate.deleted_at.is_(None),
        )
        total = (
            await self.db.execute(select(func.count()).select_from(base.subquery()))
        ).scalar() or 0

        q = base.order_by(VPNTunnelTemplate.created_at.desc()).offset(offset).limit(limit)
        result = await self.db.execute(q)
        return list(result.scalars().all()), total

    async def get_template(self, template_id: UUID, org_id: UUID) -> VPNTunnelTemplate | None:
        filters = [
            VPNTunnelTemplate.id == template_id,
            VPNTunnelTemplate.deleted_at.is_(None),
            VPNTunnelTemplate.organization_id == org_id,
        ]
        result = await self.db.execute(select(VPNTunnelTemplate).where(*filters))
        return result.scalar_one_or_none()

    async def create_template(
        self,
        org_id: UUID,
        data: dict[str, Any],
        *,
        created_by: UUID | None = None,
    ) -> VPNTunnelTemplate:
        template = VPNTunnelTemplate(
            organization_id=org_id,
            name=data["name"],
            vpn_type=data["vpn_type"],
            topology=data.get("topology", "point_to_point"),
            config_template=data.get("config_template", {}),
            default_subnets=data.get("default_subnets", []),
            mtu=data.get("mtu"),
            mss_clamp=data.get("mss_clamp"),
        )
        if created_by and hasattr(template, "created_by"):
            template.created_by = created_by
        self.db.add(template)
        await self.db.flush()
        return template

    # ──────────────────────────────────────────────────────────────────────
    # Tunnels
    # ──────────────────────────────────────────────────────────────────────

    async def list_tunnels(
        self,
        org_id: UUID,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SiteToSiteTunnel], int]:
        """List site-to-site tunnels for the organisation.

        Site-grant scoping: a site-limited caller only
        sees tunnels touching one of their granted sites — never a tunnel between
        two sibling sites they lack a grant for. The per-tunnel action endpoints
        already gate via ``_assert_tunnel_sites``; this closes the matching gap on
        the ``GET /tunnels`` list. Reads the request-scoped contextvar (no-op for
        super_admin / org_admin / grant-less callers and in background context).
        """
        from sqlalchemy import func, or_

        from app.core.site_access import site_ids_for_request

        base = select(SiteToSiteTunnel).where(
            SiteToSiteTunnel.organization_id == org_id,
        )
        if status:
            base = base.where(SiteToSiteTunnel.status == status)

        granted_site_ids = site_ids_for_request()
        if granted_site_ids is not None:
            ids = list(granted_site_ids)
            base = base.where(
                or_(
                    SiteToSiteTunnel.site_a_id.in_(ids),
                    SiteToSiteTunnel.site_b_id.in_(ids),
                )
            )

        total = (
            await self.db.execute(select(func.count()).select_from(base.subquery()))
        ).scalar() or 0

        q = base.order_by(SiteToSiteTunnel.created_at.desc()).offset(offset).limit(limit)
        result = await self.db.execute(q)
        return list(result.scalars().all()), total

    async def get_tunnel(self, tunnel_id: UUID, org_id: UUID) -> SiteToSiteTunnel | None:
        filters = [
            SiteToSiteTunnel.id == tunnel_id,
            SiteToSiteTunnel.organization_id == org_id,
        ]
        result = await self.db.execute(select(SiteToSiteTunnel).where(*filters))
        return result.scalar_one_or_none()

    async def create_tunnel(
        self,
        org_id: UUID,
        template_id: UUID,
        site_a_id: UUID,
        site_b_id: UUID,
        *,
        gateway_a_device_id: UUID | None = None,
        gateway_b_device_id: UUID | None = None,
        created_by: UUID | None = None,
    ) -> SiteToSiteTunnel:
        """
        Create a single tunnel between two sites using a template.

        The template's ``config_template`` is copied into ``config_a`` and
        ``config_b`` as the starting configuration for each side.
        """
        # Load the template to populate default config
        template = await self.get_template(template_id, org_id=org_id)
        if not template:
            raise ValueError("Template not found")

        # Validate that both sites belong to the organization
        site_check_q = select(Site.id).where(
            Site.id.in_([site_a_id, site_b_id]),
            Site.organization_id == org_id,
            Site.deleted_at.is_(None),
        )
        site_result = await self.db.execute(site_check_q)
        found_site_ids = set(site_result.scalars().all())
        if site_a_id not in found_site_ids:
            raise ValueError("Site A does not belong to this organisation")
        if site_b_id not in found_site_ids:
            raise ValueError("Site B does not belong to this organisation")

        # Check for existing tunnel between these sites (either direction)
        from sqlalchemy import or_

        existing = await self.db.execute(
            select(SiteToSiteTunnel.id).where(
                SiteToSiteTunnel.organization_id == org_id,
                or_(
                    (SiteToSiteTunnel.site_a_id == site_a_id)
                    & (SiteToSiteTunnel.site_b_id == site_b_id),
                    (SiteToSiteTunnel.site_a_id == site_b_id)
                    & (SiteToSiteTunnel.site_b_id == site_a_id),
                ),
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("A tunnel between these two sites already exists")

        # Validate gateway devices belong to the org and correct sites
        for gw_id, site_id_check in [
            (gateway_a_device_id, site_a_id),
            (gateway_b_device_id, site_b_id),
        ]:
            if gw_id:
                gw_check = await self.db.execute(
                    select(Device.id)
                    .join(Site)
                    .where(
                        Device.id == gw_id,
                        Device.site_id == site_id_check,
                        Site.organization_id == org_id,
                        Device.deleted_at.is_(None),
                    )
                )
                if not gw_check.scalar_one_or_none():
                    raise ValueError(
                        "Gateway device not found or does not belong to the specified site"
                    )

        base_config = copy.deepcopy(template.config_template or {})

        tunnel = SiteToSiteTunnel(
            organization_id=org_id,
            template_id=template_id,
            site_a_id=site_a_id,
            site_b_id=site_b_id,
            gateway_a_device_id=gateway_a_device_id,
            gateway_b_device_id=gateway_b_device_id,
            status="pending",
            config_a={**base_config, "role": "site_a"},
            config_b={**base_config, "role": "site_b"},
        )
        if created_by and hasattr(tunnel, "created_by"):
            tunnel.created_by = created_by

        self.db.add(tunnel)
        await self.db.flush()

        logger.info(
            "Created S2S tunnel %s between sites %s <-> %s (template %s)",
            tunnel.id,
            site_a_id,
            site_b_id,
            template_id,
        )

        # Attempt to provision tunnel config on gateway devices
        # Load both devices in a single query, then provision concurrently
        from app.services.adapter_factory import get_adapter

        gw_ids = [gw for gw in [gateway_a_device_id, gateway_b_device_id] if gw]
        devices_by_id: dict[UUID, Device] = {}
        if gw_ids:
            dev_result = await self.db.execute(
                select(Device).options(selectinload(Device.controller)).where(Device.id.in_(gw_ids))
            )
            for dev in dev_result.scalars().all():
                devices_by_id[dev.id] = dev

        provisioned = True

        async def _provision_side(side: str, gw_id: UUID, config_dict: dict[str, Any]) -> None:
            nonlocal provisioned
            device = devices_by_id.get(gw_id)
            if not device or not device.controller:
                logger.warning("Gateway %s has no controller, skipping VPN push", gw_id)
                return
            try:
                ctrl = device.controller
                adapter = get_adapter(
                    ctrl.controller_type,
                    host=ctrl.host,
                    username=_safe_decrypt(ctrl.username),
                    password=_safe_decrypt(ctrl.password),
                    port=ctrl.port,
                    ssl=ctrl.use_ssl,
                    verify_ssl=ctrl.verify_ssl,
                )
                if hasattr(adapter, "push_vpn_config"):
                    async with adapter:
                        await adapter.push_vpn_config(device.mac_address, config_dict)
                    logger.info("VPN config pushed to gateway %s (side %s)", gw_id, side)
                else:
                    logger.info(
                        "Adapter for gateway %s does not support VPN push — config saved in DB",
                        gw_id,
                    )
            except Exception:
                logger.warning("Failed to push VPN config to gateway %s", gw_id, exc_info=True)
                provisioned = False
                tunnel.error_message = f"Failed to provision side {side}"

        tasks = []
        for side, gw_id, config_dict in [
            ("a", gateway_a_device_id, tunnel.config_a),
            ("b", gateway_b_device_id, tunnel.config_b),
        ]:
            if gw_id:
                tasks.append(_provision_side(side, gw_id, config_dict))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        if provisioned and gw_ids:
            tunnel.status = "active"
            tunnel.provisioned_at = datetime.now(UTC)
        elif not provisioned:
            tunnel.status = "error"

        return tunnel

    async def create_mesh(
        self,
        org_id: UUID,
        template_id: UUID,
        site_ids: list[UUID],
        *,
        created_by: UUID | None = None,
    ) -> list[SiteToSiteTunnel]:
        """
        Create full-mesh tunnels among all provided sites.

        For N sites this produces N*(N-1)/2 tunnels.
        Existing tunnels between any pair are skipped.
        """
        if len(site_ids) < 2:
            raise ValueError("At least 2 sites are required for a mesh")

        # Pre-fetch template once to avoid re-querying per tunnel
        template = await self.get_template(template_id, org_id=org_id)
        if not template:
            raise ValueError("Template not found")

        # Validate that all sites belong to the organization
        site_check_q = select(Site.id).where(
            Site.id.in_(site_ids),
            Site.organization_id == org_id,
            Site.deleted_at.is_(None),
        )
        site_result = await self.db.execute(site_check_q)
        found_site_ids = set(site_result.scalars().all())
        missing_sites = set(site_ids) - found_site_ids
        if missing_sites:
            raise ValueError("One or more sites do not belong to this organisation")

        # Pre-fetch all existing tunnels for this org to avoid N+1 queries
        existing_q = (
            select(SiteToSiteTunnel.site_a_id, SiteToSiteTunnel.site_b_id)
            .where(SiteToSiteTunnel.organization_id == org_id)
            .with_for_update()
        )
        existing_result = await self.db.execute(existing_q)
        existing_pairs: set[frozenset[UUID]] = set()
        for row in existing_result.all():
            existing_pairs.add(frozenset([row[0], row[1]]))

        tunnels: list[SiteToSiteTunnel] = []
        for a, b in itertools.combinations(site_ids, 2):
            pair = frozenset([a, b])
            if pair in existing_pairs:
                logger.info("Tunnel between %s and %s already exists, skipping", a, b)
                continue

            base_config = copy.deepcopy(template.config_template or {})
            tunnel = SiteToSiteTunnel(
                organization_id=org_id,
                template_id=template_id,
                site_a_id=a,
                site_b_id=b,
                status="pending",
                config_a={**base_config, "role": "site_a"},
                config_b={**base_config, "role": "site_b"},
            )
            if created_by and hasattr(tunnel, "created_by"):
                tunnel.created_by = created_by

            self.db.add(tunnel)
            tunnels.append(tunnel)
            existing_pairs.add(pair)

        if tunnels:
            await self.db.flush()

        logger.info(
            "Created %d mesh tunnels for %d sites (template %s)",
            len(tunnels),
            len(site_ids),
            template_id,
        )
        return tunnels

    async def teardown_tunnel(
        self,
        tunnel_id: UUID,
        org_id: UUID,
    ) -> bool:
        """
        Tear down (delete) a site-to-site tunnel.

        Returns True if the tunnel was found and deleted.
        """
        result = await self.db.execute(
            select(SiteToSiteTunnel).where(
                SiteToSiteTunnel.id == tunnel_id,
                SiteToSiteTunnel.organization_id == org_id,
            )
        )
        tunnel = result.scalar_one_or_none()
        if not tunnel:
            return False

        # Attempt to remove VPN config from gateway devices (batch query + parallel)
        from app.services.adapter_factory import get_adapter

        gw_ids = [gw for gw in [tunnel.gateway_a_device_id, tunnel.gateway_b_device_id] if gw]
        devices_by_id: dict[UUID, Device] = {}
        if gw_ids:
            dev_result = await self.db.execute(
                select(Device).options(selectinload(Device.controller)).where(Device.id.in_(gw_ids))
            )
            for dev in dev_result.scalars().all():
                devices_by_id[dev.id] = dev

        async def _remove_side(gw_id: UUID) -> None:
            device = devices_by_id.get(gw_id)
            if not device or not device.controller:
                return
            try:
                ctrl = device.controller
                adapter = get_adapter(
                    ctrl.controller_type,
                    host=ctrl.host,
                    username=_safe_decrypt(ctrl.username),
                    password=_safe_decrypt(ctrl.password),
                    port=ctrl.port,
                    ssl=ctrl.use_ssl,
                    verify_ssl=ctrl.verify_ssl,
                )
                if hasattr(adapter, "remove_vpn_config"):
                    async with adapter:
                        await adapter.remove_vpn_config(device.mac_address, str(tunnel.id))
                    logger.info("VPN config removed from gateway %s", gw_id)
            except Exception:
                logger.warning("Failed to remove VPN config from gateway %s", gw_id, exc_info=True)

        if gw_ids:
            await asyncio.gather(*[_remove_side(gw) for gw in gw_ids], return_exceptions=True)

        await self.db.delete(tunnel)
        await self.db.flush()

        logger.info("Torn down S2S tunnel %s", tunnel_id)
        return True

    async def _reprovision_tunnel(self, tunnel: SiteToSiteTunnel) -> None:
        """Re-push VPN config to gateway devices for an existing tunnel."""
        from app.services.adapter_factory import get_adapter

        gw_ids = [gw for gw in [tunnel.gateway_a_device_id, tunnel.gateway_b_device_id] if gw]
        if not gw_ids:
            tunnel.status = "active"
            tunnel.provisioned_at = datetime.now(UTC)
            return

        dev_result = await self.db.execute(
            select(Device).options(selectinload(Device.controller)).where(Device.id.in_(gw_ids))
        )
        devices_by_id = {dev.id: dev for dev in dev_result.scalars().all()}

        provisioned = True

        async def _push(side: str, gw_id: UUID, config_dict: dict[str, Any]) -> None:
            nonlocal provisioned
            device = devices_by_id.get(gw_id)
            if not device or not device.controller:
                return
            try:
                ctrl = device.controller
                adapter = get_adapter(
                    ctrl.controller_type,
                    host=ctrl.host,
                    username=_safe_decrypt(ctrl.username),
                    password=_safe_decrypt(ctrl.password),
                    port=ctrl.port,
                    ssl=ctrl.use_ssl,
                    verify_ssl=ctrl.verify_ssl,
                )
                if hasattr(adapter, "push_vpn_config"):
                    async with adapter:
                        await adapter.push_vpn_config(device.mac_address, config_dict)
            except Exception:
                logger.warning("Reprovision failed for gateway %s", gw_id, exc_info=True)
                provisioned = False
                tunnel.error_message = f"Failed to reprovision side {side}"

        tasks = []
        for side, gw_id, cfg in [
            ("a", tunnel.gateway_a_device_id, tunnel.config_a),
            ("b", tunnel.gateway_b_device_id, tunnel.config_b),
        ]:
            if gw_id:
                tasks.append(_push(side, gw_id, cfg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        if provisioned:
            tunnel.status = "active"
            tunnel.provisioned_at = datetime.now(UTC)
        else:
            tunnel.status = "error"

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Orchestration Service
=========================================

Creates, manages, and tears down site-to-site VPN tunnels
using tunnel templates.  Supports point-to-point and full-mesh
topologies.
"""

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


class TunnelTeardownError(Exception):
    """A gateway refused to remove the tunnel; FreeSDN kept it."""


def _implements(adapter: Any, name: str) -> bool:
    """True when the adapter overrides ``name`` (BaseAdapter's is a NOT_SUPPORTED stub)."""
    from app.adapters.base import BaseAdapter

    method = getattr(type(adapter), name, None)
    return method is not None and method is not getattr(BaseAdapter, name, None)


def _safe_decrypt(value: str | None) -> str:
    """Decrypt a credential, falling back to the raw value if not encrypted."""
    if not value:
        return ""
    from app.core.crypto import decrypt_credential, is_encrypted

    if not is_encrypted(value):
        return value
    try:
        return decrypt_credential(value)
    except ValueError:
        raise ValueError("Stored controller credential could not be decrypted") from None


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

        # Push each side's config to its gateway. A tunnel with no gateway stays
        # "pending": nothing was pushed, so it is not active and not broken.
        if await self._push_to_gateways(tunnel):
            tunnel.status = "active"
            tunnel.provisioned_at = datetime.now(UTC)
        elif tunnel.gateway_a_device_id or tunnel.gateway_b_device_id:
            tunnel.status = "error"

        return tunnel

    def _gateway_adapter(self, device: Device) -> Any:
        from app.services.adapter_factory import get_adapter

        ctrl = device.controller
        return get_adapter(
            ctrl.controller_type,
            host=ctrl.host,
            username=_safe_decrypt(ctrl.username),
            password=_safe_decrypt(ctrl.password),
            port=ctrl.port,
            ssl=ctrl.use_ssl,
            verify_ssl=ctrl.verify_ssl,
        )

    async def _push_to_gateways(self, tunnel: SiteToSiteTunnel) -> bool:
        """Push the tunnel to both gateways as ONE change group.

        True only when every assigned side accepted it. Create and reprovision
        both use this, so neither can mark a tunnel active on a push nobody
        confirmed. Every failure reason is written to ``tunnel.error_message``.

        The two sides are one staged change group (a ledger row per gateway).
        Every side is preflighted before either is pushed: the gateway and its
        controller must still be registered, its adapter must be able to
        receive a tunnel (only OPNsense can today), and it must answer. A
        refused preflight on either side pushes nothing, so a tunnel can no
        longer end up configured on one gateway because the other could never
        take it. If a push then fails, the side already pushed is removed again
        where its adapter can do that, and the result says so.
        """
        from app.services.adapter_staging import GroupMember
        from app.services.device_writes import apply_group_through_staging, request_actor_id

        sides = [
            (side, gw_id, config_dict or {})
            for side, gw_id, config_dict in (
                ("a", tunnel.gateway_a_device_id, tunnel.config_a),
                ("b", tunnel.gateway_b_device_id, tunnel.config_b),
            )
            if gw_id
        ]
        if not sides:
            tunnel.error_message = "No gateway is assigned, so nothing was pushed to a device."
            return False

        dev_result = await self.db.execute(
            select(Device)
            .options(selectinload(Device.controller))
            .where(
                Device.id.in_([gw_id for _, gw_id, _ in sides]),
                Device.deleted_at.is_(None),
            )
        )
        devices_by_id = {dev.id: dev for dev in dev_result.scalars().all()}
        tunnel_id = str(tunnel.id)
        members: list[GroupMember] = []
        for side, gw_id, config_dict in sides:
            device = devices_by_id.get(gw_id)
            adapter = None
            build_error: str | None = None
            if device is not None and device.controller is not None:
                try:
                    adapter = self._gateway_adapter(device)
                except Exception as exc:  # noqa: BLE001 - reported by the preflight
                    build_error = type(exc).__name__

            async def _preflight(
                device: Device | None = device,
                adapter: Any = adapter,
                build_error: str | None = build_error,
            ) -> str | None:
                if device is None or device.controller is None:
                    return (
                        "the gateway or its controller is no longer registered, "
                        "so nothing was pushed"
                    )
                if adapter is None:
                    return f"its controller could not be reached ({build_error})"
                if not _implements(adapter, "push_vpn_config"):
                    return (
                        f"a {device.controller.controller_type} gateway cannot receive a "
                        "site-to-site tunnel from FreeSDN"
                    )
                try:
                    async with adapter:
                        pass
                except Exception as exc:  # noqa: BLE001 - the reason is the answer
                    return f"the gateway did not answer ({type(exc).__name__})"
                return None

            async def _push(
                adapter: Any = adapter, device: Any = device, config: Any = config_dict
            ) -> Any:
                async with adapter:
                    return await adapter.push_vpn_config(device.mac_address, config)

            async def _undo(_result: Any, adapter: Any = adapter, device: Any = device) -> Any:
                async with adapter:
                    return await adapter.remove_vpn_config(device.mac_address, tunnel_id)

            can_undo = adapter is not None and _implements(adapter, "remove_vpn_config")
            member = GroupMember(
                key=f"Side {side}",
                organization_id=tunnel.organization_id,
                controller_id=getattr(device, "controller_id", None),
                site_id=getattr(device, "site_id", None),
                feature="vpn.s2s.push",
                operation="update",
                target_id=tunnel_id,
                payload={"tunnel_id": tunnel_id, "side": side, "config": config_dict},
                perform=_push,
                preflight=_preflight,
                compensate=_undo,
            )
            if not can_undo:
                member.compensate = None
            members.append(member)

        try:
            outcome = await apply_group_through_staging(
                self.db,
                members,
                # The tunnel routes have never taken a force flag; unchanged.
                force=True,
                actor_id=request_actor_id(),
                notes=f"site-to-site tunnel {tunnel.id}",
            )
        except Exception as exc:
            from fastapi import HTTPException

            tunnel.error_message = (
                str(exc.detail) if isinstance(exc, HTTPException) else type(exc).__name__
            )[:500]
            return False

        if outcome.applied:
            tunnel.error_message = None
            for member in outcome.members:
                logger.info("VPN config pushed to gateway (%s)", member.key)
            return True
        failures = []
        for member in outcome.members:
            if member.status == "applied":
                continue
            failures.append(f"{member.key}: {member.reason or member.status}")
        if outcome.preflight_refused:
            failures.append("nothing was pushed to either gateway")
        tunnel.error_message = "; ".join(failures)[:500]
        return False

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
        *,
        local_only: bool = False,
    ) -> bool:
        """
        Tear down (delete) a site-to-site tunnel.

        Returns True if the tunnel was found and deleted. The tunnel is removed
        from both gateways first, as ONE change group; when a gateway refuses,
        FreeSDN keeps the tunnel (status ``error``, the reason in
        ``error_message``) and raises :class:`TunnelTeardownError`. It used to
        delete the record whatever the gateways answered, which left the tunnel
        configured on a gateway with nothing in FreeSDN pointing at it.
        ``local_only`` removes only FreeSDN's record.
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

        if not local_only and not await self._remove_from_gateways(tunnel):
            reason = tunnel.error_message or "a gateway refused the removal"
            if not reason.startswith("Read-only mode is on"):
                # A gateway refused (one side may already be removed). In
                # read-only mode nothing was touched, so the status stays.
                tunnel.status = "error"
            await self.db.flush()
            raise TunnelTeardownError(reason)

        await self.db.delete(tunnel)
        await self.db.flush()

        logger.info("Torn down S2S tunnel %s", tunnel_id)
        return True

    async def _remove_from_gateways(self, tunnel: SiteToSiteTunnel) -> bool:
        """Remove the tunnel from both gateways as one change group.

        True when every gateway that can hold it removed it (or there is none).
        A side whose gateway is gone (deleted or soft-deleted: FreeSDN never
        writes to either) or whose adapter cannot hold a site-to-site tunnel has
        nothing FreeSDN could have pushed, so it is skipped. Every other side is
        preflighted (the gateway must answer) before either is changed. In
        read-only mode nothing is contacted and the reason is recorded.
        """
        from fastapi import HTTPException

        from app.services.adapter_staging import GroupMember
        from app.services.device_writes import apply_group_through_staging, request_actor_id

        sides = [
            (side, gw_id)
            for side, gw_id in (
                ("a", tunnel.gateway_a_device_id),
                ("b", tunnel.gateway_b_device_id),
            )
            if gw_id
        ]
        if not sides:
            return True
        dev_result = await self.db.execute(
            select(Device)
            .options(selectinload(Device.controller))
            .where(Device.id.in_([gw_id for _, gw_id in sides]), Device.deleted_at.is_(None))
        )
        devices_by_id = {dev.id: dev for dev in dev_result.scalars().all()}
        tunnel_id = str(tunnel.id)
        members: list[GroupMember] = []
        for side, gw_id in sides:
            device = devices_by_id.get(gw_id)
            if device is None or device.controller is None:
                continue
            try:
                adapter = self._gateway_adapter(device)
            except Exception as exc:  # noqa: BLE001 - the reason is the answer
                tunnel.error_message = (
                    f"Side {side}: its controller could not be reached ({type(exc).__name__})"
                )
                return False
            if not _implements(adapter, "remove_vpn_config"):
                continue

            async def _preflight(adapter: Any = adapter) -> str | None:
                try:
                    async with adapter:
                        pass
                except Exception as exc:  # noqa: BLE001 - the reason is the answer
                    return f"the gateway did not answer ({type(exc).__name__})"
                return None

            async def _remove(adapter: Any = adapter, device: Any = device) -> Any:
                async with adapter:
                    return await adapter.remove_vpn_config(device.mac_address, tunnel_id)

            members.append(
                GroupMember(
                    key=f"Side {side}",
                    organization_id=tunnel.organization_id,
                    controller_id=getattr(device, "controller_id", None),
                    site_id=getattr(device, "site_id", None),
                    feature="vpn.s2s.remove",
                    operation="delete",
                    target_id=tunnel_id,
                    payload={"tunnel_id": tunnel_id, "side": side, "gateway_id": str(gw_id)},
                    perform=_remove,
                    preflight=_preflight,
                )
            )
        if not members:
            return True
        try:
            outcome = await apply_group_through_staging(
                self.db,
                members,
                # The tunnel routes have never taken a force flag; unchanged.
                force=True,
                actor_id=request_actor_id(),
                notes=f"remove site-to-site tunnel {tunnel.id}",
            )
        except HTTPException as exc:
            # Read-only mode: refused before either gateway was contacted.
            tunnel.error_message = str(exc.detail)[:500]
            return False
        except Exception as exc:  # noqa: BLE001 - reported on the kept tunnel
            tunnel.error_message = type(exc).__name__
            return False
        if outcome.applied:
            return True
        reasons = [
            f"{m.key}: {m.reason or m.status}" for m in outcome.members if m.status != "applied"
        ]
        removed = [m.key for m in outcome.members if m.status == "applied"]
        if removed:
            reasons.append(f"already removed from {', '.join(removed)}")
        if outcome.preflight_refused:
            reasons.append("nothing was removed from either gateway")
        tunnel.error_message = "; ".join(reasons)[:500]
        return False

    async def _reprovision_tunnel(self, tunnel: SiteToSiteTunnel) -> bool:
        """Re-push VPN config to gateway devices for an existing tunnel.

        Returns True only when every assigned side accepted the push. This used
        to mark a tunnel with no gateway "active", and to ignore the adapter's
        answer, so every adapter but OPNsense came back active with nothing
        pushed. A tunnel with no gateway now stays "pending".
        """
        if await self._push_to_gateways(tunnel):
            tunnel.status = "active"
            tunnel.provisioned_at = datetime.now(UTC)
            return True
        has_gateway = bool(tunnel.gateway_a_device_id or tunnel.gateway_b_device_id)
        tunnel.status = "error" if has_gateway else "pending"
        return False

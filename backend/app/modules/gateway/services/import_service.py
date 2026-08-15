# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Import Wizard Service
====================================

6-step brownfield import and reconciliation workflow.

Steps:
  1. Discover  – scan connected devices at the site
  2. Assign    – user picks brain / limb roles
  3. Scan      – full config pull from brain + limbs
  4. Reconcile – user resolves conflicts
  5. Apply     – execute reconciliation via Distribution Engine
  6. Verify    – re-scan and confirm
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.firewall.models import GatewayConnection
from app.modules.gateway.adapter_helpers import build_adapter
from app.modules.gateway.models import (
    ImportSession,
    ImportStatus,
)

logger = logging.getLogger(__name__)


class ImportWizardError(Exception):
    """Base import wizard error."""


class ImportSessionNotFoundError(ImportWizardError):
    def __init__(self, session_id: UUID):
        super().__init__(f"Import session not found: {session_id}")


class ImportService:
    """6-step brownfield import wizard."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ── Session CRUD ─────────────────────────────────────────────────────

    async def _get_session(
        self,
        session_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> ImportSession:
        q = select(ImportSession).where(ImportSession.id == session_id)
        if org_id is not None:
            q = q.where(ImportSession.organization_id == org_id)
        result = await self.db.execute(q)
        sess = result.scalar_one_or_none()
        if sess is None:
            raise ImportSessionNotFoundError(session_id)
        return sess

    async def get_session(
        self,
        session_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> ImportSession:
        return await self._get_session(session_id, org_id=org_id)

    # ── Step 1: Discover ─────────────────────────────────────────────────

    async def start_session(
        self,
        org_id: UUID,
        site_id: UUID,
        *,
        initiated_by: UUID | None = None,
    ) -> ImportSession:
        """Start a new import session — runs Step 1 (Discover)."""
        session = ImportSession(
            organization_id=org_id,
            site_id=site_id,
            current_step=1,
            status=ImportStatus.IN_PROGRESS,
            initiated_by=initiated_by,
        )
        self.db.add(session)
        await self.db.flush()

        # Auto-discover devices at the site (scoped to org)
        devices = await self._discover_devices(site_id, org_id=org_id)
        session.discovered_devices = devices
        session.current_step = 2
        await self.db.flush()
        await self.db.refresh(session)
        return session

    async def _discover_devices(
        self,
        site_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Scan for gateway-capable devices at the site (org-scoped)."""
        from app.modules.firewall.models import GatewayConnection

        q = select(GatewayConnection).where(
            GatewayConnection.site_id == site_id,
            GatewayConnection.deleted_at.is_(None),
        )
        if org_id is not None:
            q = q.where(GatewayConnection.org_id == org_id)
        result = await self.db.execute(q)
        gateways = result.scalars().all()

        devices: dict[str, Any] = {}
        for gw in gateways:
            devices[str(gw.id)] = {
                "name": gw.name,
                "vendor": gw.vendor,
                "host": gw.host,
                "is_online": gw.is_online,
                "capabilities": gw.capabilities or [],
                "detected_version": gw.detected_version,
            }
        return devices

    # ── Step 2→3: Assign Roles & Scan ────────────────────────────────────

    async def submit_roles(
        self,
        session_id: UUID,
        assignments: list[dict[str, Any]],
        *,
        org_id: UUID | None = None,
    ) -> ImportSession:
        """Save role assignments and trigger config scan (Step 3)."""
        session = await self._get_session(session_id, org_id=org_id)
        if session.current_step != 2:
            raise ImportWizardError(f"Expected step 2, got step {session.current_step}")

        session.role_assignments = {
            "assignments": assignments,
        }

        # Step 3 — scan devices
        scan = await self._scan_devices(session)
        session.scan_results = scan["results"]
        session.conflicts = scan["conflicts"]
        session.current_step = 4
        await self.db.flush()
        await self.db.refresh(session)
        return session

    async def _scan_devices(self, session: ImportSession) -> dict[str, Any]:
        """Pull full config from all devices and identify conflicts."""
        results: dict[str, Any] = {
            "brain_vlans": [],
            "limb_vlans": {},
            "brain_dhcp": [],
            "brain_dns": [],
            "brain_interfaces": [],
        }
        conflicts: list[dict[str, Any]] = []
        assignments = (session.role_assignments or {}).get("assignments", [])

        # Batch-load all referenced gateways in one query (avoid N+1)
        # Scoped to organization to prevent cross-org device access
        gw_ids = [a.get("gateway_id") for a in assignments if a.get("gateway_id")]
        gw_map: dict[str, GatewayConnection] = {}
        if gw_ids:
            gw_result = await self.db.execute(
                select(GatewayConnection).where(
                    GatewayConnection.id.in_(gw_ids),
                    GatewayConnection.org_id == session.organization_id,
                    GatewayConnection.deleted_at.is_(None),
                )
            )
            gw_map = {str(gw.id): gw for gw in gw_result.scalars().all()}

        for assignment in assignments:
            gw_id = assignment.get("gateway_id")
            role = assignment.get("role", "limb")
            if not gw_id:
                continue

            gw = gw_map.get(str(gw_id))
            if gw is None:
                continue

            adapter = build_adapter(gw)
            try:
                async with adapter:
                    if role == "brain":
                        # Pull VLANs
                        vlan_res = await adapter.get_vlan_devices()
                        if vlan_res.success and vlan_res.data:
                            results["brain_vlans"] = vlan_res.data.get("vlans", [])

                        # Pull interfaces
                        iface_res = await adapter.get_interfaces()
                        if iface_res.success and iface_res.data:
                            results["brain_interfaces"] = iface_res.data.get("interfaces", [])

                        # Pull DHCP leases (to detect active scopes)
                        dhcp_res = await adapter.get_dhcp_leases()
                        if dhcp_res.success and dhcp_res.data:
                            results["brain_dhcp"] = dhcp_res.data.get("leases", [])

                        # Pull DNS overrides
                        if hasattr(adapter, "get_dns_overrides"):
                            dns_res = await adapter.get_dns_overrides()
                            if dns_res.success and dns_res.data:
                                results["brain_dns"] = dns_res.data.get("records", [])

                    elif role == "limb":
                        # Limbs: pull VLANs to detect L2 config
                        if hasattr(adapter, "get_vlans"):
                            vlan_res = await adapter.get_vlans()
                            if vlan_res.success and vlan_res.data:
                                results["limb_vlans"][str(gw_id)] = vlan_res.data.get("vlans", [])
            except Exception as exc:
                logger.warning("Scan failed for device %s: %s", gw_id, exc)
                conflicts.append(
                    {
                        "type": "scan_error",
                        "device_id": str(gw_id),
                        "error": f"Device scan failed ({type(exc).__name__})",
                    }
                )

        # Detect double DHCP scopes
        brain_dhcp_ifaces = {l.get("interface") for l in results.get("brain_dhcp", [])}
        for limb_id, limb_vlans in results.get("limb_vlans", {}).items():
            for lv in limb_vlans:
                vlan_tag = lv.get("vlan_id") or lv.get("tag")
                if vlan_tag and f"vlan{vlan_tag}" in brain_dhcp_ifaces:
                    conflicts.append(
                        {
                            "type": "double_dhcp",
                            "vlan_id": vlan_tag,
                            "brain": "brain",
                            "limb": limb_id,
                            "message": f"VLAN {vlan_tag} has DHCP on both brain and limb",
                        }
                    )

        return {"results": results, "conflicts": conflicts}

    # ── Step 4→5: Reconcile & Apply ──────────────────────────────────────

    async def submit_reconciliation(
        self,
        session_id: UUID,
        decisions: dict[str, str],
        *,
        org_id: UUID | None = None,
    ) -> ImportSession:
        """Apply reconciliation decisions (Step 5)."""
        session = await self._get_session(session_id, org_id=org_id)
        if session.current_step != 4:
            raise ImportWizardError(f"Expected step 4, got step {session.current_step}")

        session.reconciliation_decisions = decisions

        # Step 5 — apply via Distribution Engine
        distributions = await self._apply_decisions(session, decisions)
        session.distribution_ids = [str(d) for d in distributions]

        # Step 6 — verify
        verification = await self._verify(session)
        session.verification_report = verification
        session.current_step = 6
        session.status = ImportStatus.COMPLETED
        await self.db.flush()
        await self.db.refresh(session)
        return session

    async def _apply_decisions(
        self, session: ImportSession, decisions: dict[str, str]
    ) -> list[UUID]:
        """Execute reconciliation decisions using the Distribution Engine."""
        from app.modules.gateway.models import (
            CanonicalVLAN,
            SiteRoleMap,
        )
        from app.modules.gateway.services.distribution_service import (
            DistributionService,
        )

        distribution_ids: list[UUID] = []
        dist_svc = DistributionService(self.db)

        # Load the role map for the site (org-scoped)
        rm_result = await self.db.execute(
            select(SiteRoleMap).where(
                SiteRoleMap.site_id == session.site_id,
                SiteRoleMap.organization_id == session.organization_id,
            )
        )
        role_map = rm_result.scalar_one_or_none()
        if role_map is None:
            logger.warning(
                "No role map for site %s — skipping distribution",
                session.site_id,
            )
            return distribution_ids

        # Process each decision that creates canonical resources
        for key, action in decisions.items():
            if action == "import" and key.startswith("vlan:"):
                # Import VLAN from brain scan results
                parts = key.split(":", 1)
                if len(parts) < 2:
                    continue
                try:
                    vlan_tag = int(parts[1])
                except (ValueError, IndexError):
                    logger.warning("Invalid VLAN key in decisions: %s", key)
                    continue
                brain_vlans = (session.scan_results or {}).get("brain_vlans", [])
                match = next(
                    (v for v in brain_vlans if v.get("tag") == vlan_tag),
                    None,
                )
                if not match:
                    continue

                # Create canonical VLAN
                vlan = CanonicalVLAN(
                    organization_id=session.organization_id,
                    site_id=session.site_id,
                    vlan_id=vlan_tag,
                    name=match.get("description", f"VLAN {vlan_tag}"),
                    subnet=match.get("subnet", ""),
                    gateway_ip=match.get("gateway", ""),
                    dhcp_enabled=False,
                    management_state="adopted",
                )
                self.db.add(vlan)
                await self.db.flush()

                # Distribute to limbs
                record = await dist_svc.distribute_vlan(
                    vlan, role_map, triggered_by=session.initiated_by
                )
                distribution_ids.append(record.id)

        logger.info(
            "Applied %d distributions for import session %s",
            len(distribution_ids),
            session.id,
        )
        return distribution_ids

    async def _verify(self, session: ImportSession) -> dict[str, Any]:
        """Re-scan brain device and confirm canonical state matches."""
        mismatches: list[dict[str, Any]] = []

        assignments = (session.role_assignments or {}).get("assignments", [])
        brain_assignment = next(
            (a for a in assignments if a.get("role") == "brain"),
            None,
        )
        if brain_assignment:
            gw_id = brain_assignment.get("gateway_id")
            if gw_id:
                gw_result = await self.db.execute(
                    select(GatewayConnection).where(
                        GatewayConnection.id == gw_id,
                        GatewayConnection.org_id == session.organization_id,
                        GatewayConnection.deleted_at.is_(None),
                    )
                )
                gw = gw_result.scalar_one_or_none()
                if gw:
                    adapter = build_adapter(gw)
                    try:
                        async with adapter:
                            vlan_res = await adapter.get_vlan_devices()
                            if vlan_res.success and vlan_res.data:
                                live_tags = {v.get("tag") for v in vlan_res.data.get("vlans", [])}
                                # Compare with what we imported
                                from app.modules.gateway.models import CanonicalVLAN

                                q = await self.db.execute(
                                    select(CanonicalVLAN).where(
                                        CanonicalVLAN.organization_id == session.organization_id,
                                        CanonicalVLAN.site_id == session.site_id,
                                        CanonicalVLAN.deleted_at.is_(None),
                                    )
                                )
                                for cv in q.scalars().all():
                                    if cv.vlan_id not in live_tags:
                                        mismatches.append(
                                            {
                                                "type": "vlan_missing_on_device",
                                                "vlan_id": cv.vlan_id,
                                                "name": cv.name,
                                            }
                                        )
                    except Exception as exc:
                        logger.warning("Verification scan failed: %s", exc)

        return {
            "status": "verified" if not mismatches else "mismatches_found",
            "timestamp": datetime.now(UTC).isoformat(),
            "mismatches": mismatches,
        }

    # ── Cancel ───────────────────────────────────────────────────────────

    async def cancel_session(
        self,
        session_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> ImportSession:
        session = await self._get_session(session_id, org_id=org_id)
        session.status = ImportStatus.CANCELLED
        await self.db.flush()
        await self.db.refresh(session)
        return session

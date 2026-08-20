# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Reconciliation Service
====================================

Bridges Layer 0 (controller-direct) and Layer 2 (gateway orchestration).

Three core operations:
  1. **import_from_brain** — Read VLAN interfaces from the brain device
     and upsert CanonicalVLAN records.
  2. **check_alignment** — Compare canonical state against actual device
     state across all role-assigned devices.
  3. **distribute_to_limbs** — Push L2 VLAN config to limb devices
     (Omada, UniFi controllers).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.gateway.models import (
    CanonicalVLAN,
    ManagementState,
    NetworkRole,
    SiteRoleAssignment,
    SiteRoleMap,
    VLANPurpose,
)

logger = logging.getLogger(__name__)

# Concurrency bound for parallel device queries
_DEVICE_SEMAPHORE = asyncio.Semaphore(5)
_DEVICE_TIMEOUT = 15.0  # seconds


# ═══════════════════════════════════════════════════════════════════════════════
# Result dataclasses
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class ImportResult:
    """Result of importing VLANs from the brain device.

    ``orphaned``: canonical VLANs that
    exist in FreeSDN but were NOT found on the brain during this
    import run. Without flagging these, a second ``import_from_brain``
    silently leaves them in canonical state — and a subsequent
    ``distribute_to_limbs()`` will push their (now possibly stale)
    config to limbs, causing conflicts with whatever the brain has.
    Operators see this list in the import response and decide:
    delete the orphan, mark it ignored, or update the brain to
    match it.
    """

    created: int = 0
    updated: int = 0
    unchanged: int = 0
    errors: list[str] = field(default_factory=list)
    vlans: list[dict[str, Any]] = field(default_factory=list)
    orphaned: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AlignmentItem:
    """Alignment status for a single VLAN on a single device."""

    vlan_id: int
    vlan_name: str
    canonical_vlan_uuid: UUID | None = None
    device_id: UUID | None = None
    device_type: str = ""
    device_role: str = ""
    # ``error``: the device was
    # unreachable / adapter raised. Previously every device-level
    # exception was reported as a single ``status="missing"`` row with
    # ``vlan_id=0`` — operators saw "Site has 1 missing VLAN" when in
    # truth a switch was offline.
    status: str = "aligned"  # aligned | missing | modified | extra | error
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AlignmentReport:
    """Result of checking alignment across all devices at a site."""

    site_id: UUID | None = None
    total_vlans: int = 0
    aligned: int = 0
    missing: int = 0
    modified: int = 0
    extra: int = 0
    errored: int = 0
    items: list[AlignmentItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    score: float = 100.0  # percentage


@dataclass
class DistributeResult:
    """Result of distributing VLANs to limb devices.

    ``partial_failure`` + ``failed_devices``
    surface the across-limb consistency status. A multi-limb push is
    not transactional — by the time we discover limb #3 rejects the
    write, limbs #1-#2 already have the new VLAN. Operators MUST be
    able to see that state is incomplete (``partial_failure=True``)
    AND target just the broken limbs on retry via
    ``failed_devices`` rather than re-running the full distribute
    against the already-correct limbs.
    """

    distributed: int = 0
    skipped: int = 0
    failed: int = 0
    details: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    partial_failure: bool = False
    failed_devices: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Service
# ═══════════════════════════════════════════════════════════════════════════════


class ReconciliationError(Exception):
    """Base error for reconciliation operations."""


class ReconciliationService:
    """
    Orchestrates VLAN reconciliation between brain and limb devices.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ── 1. Import from Brain ─────────────────────────────────────────────

    async def import_from_brain(
        self,
        role_map: SiteRoleMap,
        *,
        org_id: UUID,
        dry_run: bool = False,
    ) -> ImportResult:
        """
        Read VLAN interfaces from the brain device and create/update
        CanonicalVLAN records.

        If *dry_run* is True, returns what would be imported without persisting.
        """
        result = ImportResult()

        # Find brain assignment
        brain = next(
            (a for a in role_map.assignments if a.role == NetworkRole.BRAIN),
            None,
        )
        if brain is None:
            result.errors.append("No brain device assigned to this site")
            return result

        if brain.device_type != "gateway" or not brain.gateway_id:
            result.errors.append("Brain must be a gateway device")
            return result

        # Get the adapter for the brain device
        try:
            adapter = await self._get_gateway_adapter(brain.gateway_id)
        except Exception as exc:
            result.errors.append(f"Cannot connect to brain: {exc}")
            return result

        # Fetch VLAN interfaces from brain
        try:
            async with _DEVICE_SEMAPHORE:
                adapter_result = await asyncio.wait_for(
                    adapter.get_vlan_devices(),
                    timeout=_DEVICE_TIMEOUT,
                )
            if not adapter_result.success:
                result.errors.append(f"Brain returned error: {adapter_result.error or 'unknown'}")
                return result
            brain_vlans = adapter_result.data or []
        except TimeoutError:
            result.errors.append("Timeout reading VLANs from brain")
            return result
        except Exception as exc:
            result.errors.append(f"Error reading brain VLANs: {exc}")
            return result

        # Load existing canonical VLANs for this site
        existing_stmt = select(CanonicalVLAN).where(
            CanonicalVLAN.site_id == role_map.site_id,
            CanonicalVLAN.organization_id == org_id,
            CanonicalVLAN.deleted_at.is_(None),
        )
        existing_rows = (await self.db.execute(existing_stmt)).scalars().all()
        existing_map = {v.vlan_id: v for v in existing_rows}

        # Reconcile — same alias set as the alignment check below
        # so vendor responses that use ``vid`` / ``VlanID`` don't
        # silently disappear from imports.
        for bv in brain_vlans:
            vlan_id = (
                bv.get("vlan_id")
                or bv.get("tag")
                or bv.get("vlan")
                or bv.get("vid")
                or bv.get("VlanID")
            )
            if vlan_id is None:
                continue
            try:
                vlan_id = int(vlan_id)
            except (TypeError, ValueError):
                continue

            name = bv.get("name") or bv.get("description") or f"VLAN {vlan_id}"
            subnet = bv.get("subnet") or bv.get("ipv4_address") or ""
            gateway_ip = bv.get("gateway") or bv.get("ipv4_address") or ""
            iface_id = bv.get("external_id") or bv.get("if") or bv.get("interface") or ""

            vlan_data = {
                "vlan_id": vlan_id,
                "name": str(name)[:64],
                "subnet": str(subnet)[:18],
                "gateway_ip": str(gateway_ip)[:45],
                "external_id": str(iface_id),
            }

            if vlan_id in existing_map:
                existing = existing_map[vlan_id]
                # Check if anything changed
                changed = (
                    existing.name != vlan_data["name"]
                    or existing.subnet != vlan_data["subnet"]
                    or existing.gateway_ip != vlan_data["gateway_ip"]
                )
                if changed:
                    if not dry_run:
                        existing.name = vlan_data["name"]
                        existing.subnet = vlan_data["subnet"]
                        existing.gateway_ip = vlan_data["gateway_ip"]
                        existing.external_ids = {
                            **existing.external_ids,
                            str(brain.gateway_id): vlan_data["external_id"],
                        }
                    result.updated += 1
                else:
                    result.unchanged += 1
            else:
                if not dry_run:
                    new_vlan = CanonicalVLAN(
                        organization_id=org_id,
                        site_id=role_map.site_id,
                        vlan_id=vlan_id,
                        name=vlan_data["name"],
                        subnet=vlan_data["subnet"] or "0.0.0.0/0",
                        gateway_ip=vlan_data["gateway_ip"] or "0.0.0.0",
                        source_device_id=brain.gateway_id,
                        management_state=ManagementState.ADOPTED,
                        purpose=VLANPurpose.GENERAL,
                        external_ids={str(brain.gateway_id): vlan_data["external_id"]},
                    )
                    self.db.add(new_vlan)
                result.created += 1

            result.vlans.append(vlan_data)

        # Orphan detection: any canonical VLAN that DIDN'T appear in
        # brain_vlans this run is now flagged. Subsequent
        # ``distribute_to_limbs()`` will otherwise push these to
        # limbs with stale config (e.g., custom DHCP range that no
        # longer reflects brain). Surface them so the operator can
        # delete / re-import / mark ignored.
        brain_vlan_ids = {v["vlan_id"] for v in result.vlans}
        for vid, existing in existing_map.items():
            if vid in brain_vlan_ids:
                continue
            result.orphaned.append(
                {
                    "canonical_vlan_uuid": str(existing.id),
                    "vlan_id": vid,
                    "name": existing.name,
                    "subnet": existing.subnet,
                    "reason": "exists in canonical state but not on brain",
                }
            )

        if not dry_run:
            # Update last_reconciled_at timestamp
            role_map.last_reconciled_at = datetime.now(UTC)
            await self.db.flush()

        return result

    # ── 2. Check Alignment ───────────────────────────────────────────────

    async def check_alignment(
        self,
        role_map: SiteRoleMap,
        *,
        org_id: UUID,
    ) -> AlignmentReport:
        """
        Compare canonical VLANs against actual device state on all
        role-assigned devices.
        """
        report = AlignmentReport(site_id=role_map.site_id)

        # Load canonical VLANs
        canon_stmt = select(CanonicalVLAN).where(
            CanonicalVLAN.site_id == role_map.site_id,
            CanonicalVLAN.organization_id == org_id,
            CanonicalVLAN.deleted_at.is_(None),
        )
        canon_vlans = (await self.db.execute(canon_stmt)).scalars().all()
        report.total_vlans = len(canon_vlans)
        canon_by_id = {v.vlan_id: v for v in canon_vlans}

        if not canon_vlans:
            report.score = 100.0
            return report

        # Check each device in parallel
        tasks = []
        for assign in role_map.assignments:
            if assign.role in (NetworkRole.BRAIN, NetworkRole.LIMB):
                tasks.append(self._check_device_alignment(assign, canon_by_id))

        if not tasks:
            report.errors.append("No brain or limb devices to check")
            return report

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                report.errors.append(str(r))
                continue
            for item in r:
                report.items.append(item)
                if item.status == "aligned":
                    report.aligned += 1
                elif item.status == "missing":
                    report.missing += 1
                elif item.status == "modified":
                    report.modified += 1
                elif item.status == "extra":
                    report.extra += 1
                elif item.status == "error":
                    report.errored += 1

        # Previously the denominator was ``aligned + missing + modified``
        # so a site with 5 aligned + 50 extra VLANs reported **100 %**
        # aligned. ``extra`` IS drift (canonical and actual disagree)
        # so include it. ``errored`` devices we can't measure — exclude
        # them from the score and surface separately so operators can
        # tell "Device offline" apart from "VLAN drift".
        total_checks = report.aligned + report.missing + report.modified + report.extra
        if total_checks > 0:
            report.score = round((report.aligned / total_checks) * 100, 1)

        return report

    async def _check_device_alignment(
        self,
        assign: SiteRoleAssignment,
        canon_by_id: dict[int, CanonicalVLAN],
    ) -> list[AlignmentItem]:
        """Check a single device's VLANs against canonical state."""
        items: list[AlignmentItem] = []

        try:
            if assign.device_type == "gateway":
                adapter = await self._get_gateway_adapter(assign.gateway_id)
                async with _DEVICE_SEMAPHORE:
                    ar = await asyncio.wait_for(
                        adapter.get_vlan_devices(),
                        timeout=_DEVICE_TIMEOUT,
                    )
                device_vlans = ar.data or [] if ar.success else []
            else:
                # Controller — get VLANs via network module
                device_vlans = await self._get_controller_vlans(assign.controller_id)
        except Exception as exc:
            # Was ``status="missing"`` with ``vlan_id=0`` — inflated the
            # ``missing`` counter for every offline device and hid the
            # real cause (unreachable adapter) behind a confusing "VLAN
            # 0 is missing" row. Surface a distinct ``error`` status so
            # the FE can render "Device unreachable" separately.
            items.append(
                AlignmentItem(
                    vlan_id=0,
                    vlan_name="",
                    device_id=assign.device_id,
                    device_type=assign.device_type,
                    device_role=assign.role,
                    status="error",
                    details={"error": type(exc).__name__, "message": str(exc)[:200]},
                )
            )
            return items

        # Normalize VLAN id across vendor response shapes — adapters
        # variously surface the field as ``vlan_id``, ``tag``,
        # ``vlan``, or embed it in the name (e.g., "vlan10"). Skip
        # entries with no numeric id but log them so a vendor that
        # adds a new key doesn't silently disappear from alignment
        # checks.
        device_vlan_ids = set()
        skipped_no_vlan_id: list[Any] = []
        for dv in device_vlans:
            vid_raw = (
                dv.get("vlan_id")
                or dv.get("tag")
                or dv.get("vlan")
                or dv.get("vid")  # MikroTik / OPNsense surface
                or dv.get("VlanID")  # UniFi camelCase
            )
            if vid_raw is None:
                # Last resort: extract digits from the name field
                # (covers "vlan10" / "VLAN 20" / "vlan_30" styles).
                name = str(dv.get("name", "")) or str(dv.get("description", ""))
                import re

                m = re.search(r"\d+", name)
                if m:
                    vid_raw = m.group(0)
            if vid_raw is None:
                skipped_no_vlan_id.append(dv)
                continue
            try:
                device_vlan_ids.add(int(vid_raw))
            except (TypeError, ValueError):
                skipped_no_vlan_id.append(dv)
        if skipped_no_vlan_id:
            logger.warning(
                "Drift check for device %s skipped %d VLAN row(s) with no "
                "parseable id — vendor response shape may have drifted",
                assign.device_id,
                len(skipped_no_vlan_id),
            )

        # Check canonical VLANs exist on device
        for vid, canon in canon_by_id.items():
            if vid in device_vlan_ids:
                items.append(
                    AlignmentItem(
                        vlan_id=vid,
                        vlan_name=canon.name,
                        canonical_vlan_uuid=canon.id,
                        device_id=assign.device_id,
                        device_type=assign.device_type,
                        device_role=assign.role,
                        status="aligned",
                    )
                )
            else:
                items.append(
                    AlignmentItem(
                        vlan_id=vid,
                        vlan_name=canon.name,
                        canonical_vlan_uuid=canon.id,
                        device_id=assign.device_id,
                        device_type=assign.device_type,
                        device_role=assign.role,
                        status="missing",
                    )
                )

        # Check for extra VLANs on device (not in canonical)
        for vid in device_vlan_ids:
            if vid not in canon_by_id:
                items.append(
                    AlignmentItem(
                        vlan_id=vid,
                        vlan_name=f"VLAN {vid}",
                        device_id=assign.device_id,
                        device_type=assign.device_type,
                        device_role=assign.role,
                        status="extra",
                    )
                )

        return items

    # ── 3. Distribute to Limbs ───────────────────────────────────────────

    async def distribute_to_limbs(
        self,
        role_map: SiteRoleMap,
        *,
        org_id: UUID,
        vlan_ids: list[int] | None = None,
        device_ids: list[UUID] | None = None,
        dry_run: bool = False,
    ) -> DistributeResult:
        """
        Push canonical VLAN L2 configuration to all limb devices.

        Only pushes L2 config (VLAN ID + name + tagged ports).
        L3 config (subnet, gateway, DHCP) stays on the brain.

        If *vlan_ids* is provided, only distribute those specific VLANs.

        If *device_ids* is provided, only distribute to those specific
        limb devices — used to retry a partial failure against just
        the previously-failed limbs without re-running the full
        distribution against limbs that already accepted the change.

        """
        result = DistributeResult()

        # Load canonical VLANs
        canon_stmt = select(CanonicalVLAN).where(
            CanonicalVLAN.site_id == role_map.site_id,
            CanonicalVLAN.organization_id == org_id,
            CanonicalVLAN.deleted_at.is_(None),
        )
        if vlan_ids:
            canon_stmt = canon_stmt.where(CanonicalVLAN.vlan_id.in_(vlan_ids))
        canon_vlans = (await self.db.execute(canon_stmt)).scalars().all()

        if not canon_vlans:
            result.errors.append("No canonical VLANs to distribute")
            return result

        # Get limb assignments
        limbs = [a for a in role_map.assignments if a.role == NetworkRole.LIMB]

        # Targeted retry — only push to the operator-supplied subset.
        # Used to re-run against previously-failed limbs without
        # re-touching the already-correct ones.
        if device_ids:
            allowed = {str(d) for d in device_ids}
            limbs = [a for a in limbs if str(a.device_id) in allowed]

        if not limbs:
            result.errors.append("No limb devices assigned")
            return result

        # Track per-limb failure separately so we can summarise
        # ``partial_failure`` + ``failed_devices`` at the end. A push
        # is "per limb × per vlan" — if ANY VLAN fails on a limb, the
        # whole limb is considered to be in an incomplete state and
        # surfaces in ``failed_devices`` for targeted retry.
        failed_device_ids: set[str] = set()

        # Distribute to each limb
        for limb in limbs:
            for vlan in canon_vlans:
                detail = {
                    "device_id": str(limb.device_id),
                    "device_type": limb.device_type,
                    "vlan_id": vlan.vlan_id,
                    "vlan_name": vlan.name,
                }

                if dry_run:
                    detail["action"] = "would_create"
                    result.distributed += 1
                    result.details.append(detail)
                    continue

                try:
                    if limb.device_type == "controller":
                        success = await self._push_vlan_to_controller(
                            limb.controller_id,
                            vlan,
                        )
                    else:
                        success = await self._push_vlan_to_gateway(
                            limb.gateway_id,
                            vlan,
                        )

                    if success:
                        detail["action"] = "created"
                        result.distributed += 1
                    else:
                        detail["action"] = "skipped"
                        result.skipped += 1
                except Exception as exc:
                    detail["action"] = "failed"
                    # Don't echo ``str(exc)`` — adapter exceptions can
                    # carry controller URLs / auth fragments (Phase-A
                    # error-sanitization audit pattern). Class name +
                    # short message is enough for the UI; the full
                    # repr stays in the server-side log below.
                    detail["error"] = type(exc).__name__
                    result.failed += 1
                    failed_device_ids.add(str(limb.device_id))
                    logger.warning(
                        "Failed to push VLAN %d to device %s: %s",
                        vlan.vlan_id,
                        limb.device_id,
                        exc,
                    )

                result.details.append(detail)

        # Cross-limb consistency status: if ANY limb saw a failure,
        # the site is in an incomplete state. ``partial_failure``
        # tells the UI to render a warning banner; ``failed_devices``
        # gives the operator the exact device IDs to feed back into
        # ``device_ids=`` for a targeted retry.
        if failed_device_ids:
            result.partial_failure = True
            result.failed_devices = sorted(failed_device_ids)
            logger.error(
                "Limb distribution partial failure on site %s — %d device(s) need retry: %s",
                role_map.site_id,
                len(failed_device_ids),
                result.failed_devices,
            )

        if not dry_run:
            role_map.last_reconciled_at = datetime.now(UTC)
            await self.db.flush()

        return result

    # ── Adapter helpers ──────────────────────────────────────────────────

    async def _get_gateway_adapter(self, gateway_id: UUID):
        """Load the appropriate adapter for a gateway device."""
        from app.modules.firewall.gateway_service import GatewayService
        from app.modules.firewall.models import GatewayConnection

        gw = await self.db.get(GatewayConnection, gateway_id)
        if gw is None:
            raise ReconciliationError(f"Gateway {gateway_id} not found")

        gw_svc = GatewayService(self.db)
        return gw_svc._build_adapter(gw)

    async def _get_controller_vlans(self, controller_id: UUID) -> list[dict]:
        """Get VLANs from a controller via the network module."""
        from app.models.core import Controller
        from app.models.network import VLAN

        ctrl = await self.db.get(Controller, controller_id)
        if ctrl is None:
            raise ReconciliationError(f"Controller {controller_id} not found")

        # Query Layer 0 VLANs for this controller
        vlan_stmt = select(VLAN).where(
            VLAN.controller_id == controller_id,
            VLAN.deleted_at.is_(None),
        )
        vlans = (await self.db.execute(vlan_stmt)).scalars().all()
        return [
            {
                "vlan_id": v.vlan_id,
                "name": v.name,
                "subnet": getattr(v, "subnet", ""),
            }
            for v in vlans
        ]

    async def _push_vlan_to_controller(
        self,
        controller_id: UUID,
        vlan: CanonicalVLAN,
    ) -> bool:
        """Push a VLAN to a controller via the network adapter."""
        from app.models.core import Controller
        from app.services.adapter_factory import build_adapter_for_controller

        ctrl = await self.db.get(Controller, controller_id)
        if ctrl is None:
            raise ReconciliationError(f"Controller {controller_id} not found")

        try:
            # Was `await get_adapter(ctrl, self.db)`. get_adapter is synchronous
            # and takes (controller_type, host, username, password), so that
            # call raised TypeError before a single packet reached the device --
            # every VLAN push to a controller limb failed 100% of the time.
            adapter = build_adapter_for_controller(ctrl)
            async with _DEVICE_SEMAPHORE:
                result = await asyncio.wait_for(
                    adapter.create_vlan(
                        {
                            "vlan_id": vlan.vlan_id,
                            "name": vlan.name,
                            "purpose": vlan.purpose,
                        }
                    ),
                    timeout=_DEVICE_TIMEOUT,
                )
            return result.success if hasattr(result, "success") else bool(result)
        except Exception as exc:
            logger.error(
                "Push VLAN %d to controller %s failed: %s",
                vlan.vlan_id,
                controller_id,
                exc,
            )
            raise

    async def _push_vlan_to_gateway(
        self,
        gateway_id: UUID,
        vlan: CanonicalVLAN,
    ) -> bool:
        """Push a VLAN to a gateway device (L2 only — tagged interface)."""
        try:
            adapter = await self._get_gateway_adapter(gateway_id)
            async with _DEVICE_SEMAPHORE:
                result = await asyncio.wait_for(
                    adapter.create_vlan_device(
                        {
                            "vlan_id": vlan.vlan_id,
                            "name": vlan.name,
                            "parent_interface": "lan",
                        }
                    ),
                    timeout=_DEVICE_TIMEOUT,
                )
            return result.success if hasattr(result, "success") else bool(result)
        except Exception as exc:
            logger.error(
                "Push VLAN %d to gateway %s failed: %s",
                vlan.vlan_id,
                gateway_id,
                exc,
            )
            raise

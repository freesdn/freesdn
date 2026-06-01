# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Drift Detection Service
=======================================

Periodic comparison of canonical resource models against live
device state.  Creates DriftEvent records for mismatches.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.firewall.models import GatewayConnection
from app.modules.gateway.adapter_helpers import build_adapter
from app.modules.gateway.models import (
    CanonicalDHCPScope,
    CanonicalDNSRecord,
    CanonicalVLAN,
    DriftEvent,
    DriftResolution,
    DriftSeverity,
    DriftType,
    ManagementState,
    NetworkRole,
    SiteRoleAssignment,
    SiteRoleMap,
    SuppressionRule,
)

logger = logging.getLogger(__name__)


class DriftService:
    """Detects and manages configuration drift."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ── Check ────────────────────────────────────────────────────────────

    async def check_site(
        self,
        site_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> list[DriftEvent]:
        """Run a drift check for *site_id*.

        Compares canonical models against device state and
        stores any resulting DriftEvent rows.
        """
        from sqlalchemy.orm import selectinload

        q = (
            select(SiteRoleMap)
            .options(selectinload(SiteRoleMap.assignments))
            .where(SiteRoleMap.site_id == site_id)
        )
        if org_id is not None:
            q = q.where(SiteRoleMap.organization_id == org_id)
        result = await self.db.execute(q)
        role_map = result.scalar_one_or_none()
        if not role_map:
            return []

        events: list[DriftEvent] = []
        events.extend(await self._check_brain_vlans(role_map))
        events.extend(await self._check_brain_dhcp(role_map))
        events.extend(await self._check_brain_dns(role_map))
        events.extend(await self._check_suppressions(role_map))

        # Persist
        for ev in events:
            self.db.add(ev)
        if events:
            await self.db.flush()

        return events

    async def _check_brain_vlans(self, role_map: SiteRoleMap) -> list[DriftEvent]:
        """Compare canonical VLANs against what the brain device reports."""
        brain = next(
            (a for a in role_map.assignments if a.role == NetworkRole.BRAIN),
            None,
        )
        if not brain:
            return []

        # Load the brain gateway
        gw_result = await self.db.execute(
            select(GatewayConnection).where(GatewayConnection.id == brain.gateway_id)
        )
        gw = gw_result.scalar_one_or_none()
        if gw is None:
            return []

        # Load canonical VLANs for this site (org-scoped for defense-in-depth)
        cv_result = await self.db.execute(
            select(CanonicalVLAN).where(
                CanonicalVLAN.organization_id == role_map.organization_id,
                CanonicalVLAN.site_id == role_map.site_id,
                CanonicalVLAN.deleted_at.is_(None),
                CanonicalVLAN.management_state == ManagementState.MANAGED,
            )
        )
        canonical_vlans = list(cv_result.scalars().all())
        if not canonical_vlans:
            return []

        events: list[DriftEvent] = []
        adapter = build_adapter(gw)
        try:
            async with adapter:
                vlan_result = await adapter.get_vlan_devices()
                if not vlan_result.success:
                    logger.warning(
                        "Could not probe VLANs on brain %s: %s",
                        gw.id,
                        vlan_result.error,
                    )
                    return []
                device_tags: set[int] = set()
                for v in vlan_result.data.get("vlans", []):
                    tag = v.get("tag")
                    if isinstance(tag, int):
                        device_tags.add(tag)

                for cv in canonical_vlans:
                    if cv.vlan_id not in device_tags:
                        events.append(
                            DriftEvent(
                                organization_id=cv.organization_id,
                                site_id=cv.site_id,
                                device_id=brain.gateway_id,
                                drift_type=DriftType.RESOURCE_MISSING,
                                resource_type="vlan",
                                resource_id=cv.id,
                                expected_value={
                                    "vlan_id": cv.vlan_id,
                                    "name": cv.name,
                                    "subnet": cv.subnet,
                                },
                                actual_value=None,
                                severity=DriftSeverity.CRITICAL,
                                message=f"VLAN {cv.vlan_id} ({cv.name}) missing on brain device",
                            )
                        )
        except Exception as exc:
            logger.warning("Drift check failed for brain %s: %s", gw.id, exc)

        return events

    async def _get_brain_gw(
        self,
        role_map: SiteRoleMap,
    ) -> tuple[SiteRoleAssignment | None, GatewayConnection | None]:
        """Helper: find the brain assignment and its GatewayConnection."""
        brain = next(
            (a for a in role_map.assignments if a.role == NetworkRole.BRAIN),
            None,
        )
        if not brain:
            return None, None
        gw_result = await self.db.execute(
            select(GatewayConnection).where(GatewayConnection.id == brain.gateway_id)
        )
        return brain, gw_result.scalar_one_or_none()

    async def _check_brain_dhcp(self, role_map: SiteRoleMap) -> list[DriftEvent]:
        """Compare canonical DHCP scopes against brain device state."""
        brain, gw = await self._get_brain_gw(role_map)
        if not brain or gw is None:
            return []

        # Load canonical DHCP scopes for this site (org-scoped)
        scope_result = await self.db.execute(
            select(CanonicalDHCPScope).where(
                CanonicalDHCPScope.organization_id == role_map.organization_id,
                CanonicalDHCPScope.site_id == role_map.site_id,
            )
        )
        canonical_scopes = list(scope_result.scalars().all())
        if not canonical_scopes:
            return []

        # Batch-load parent VLANs for all scopes (avoid N+1 queries)
        vlan_ids = list({cs.vlan_id for cs in canonical_scopes})
        vlan_result = await self.db.execute(
            select(CanonicalVLAN).where(
                CanonicalVLAN.id.in_(vlan_ids),
                CanonicalVLAN.deleted_at.is_(None),
                CanonicalVLAN.management_state == ManagementState.MANAGED,
            )
        )
        vlan_map: dict[UUID, CanonicalVLAN] = {v.id: v for v in vlan_result.scalars().all()}

        events: list[DriftEvent] = []
        adapter = build_adapter(gw)
        try:
            async with adapter:
                if not hasattr(adapter, "get_dhcp_leases"):
                    return []
                leases_result = await adapter.get_dhcp_leases()
                if not leases_result.success:
                    logger.warning(
                        "Could not probe DHCP on brain %s: %s",
                        gw.id,
                        leases_result.error,
                    )
                    return []

                # Also check DHCP server configs if adapter supports it
                device_interfaces: set[str] = set()
                if hasattr(adapter, "get_dhcp_scopes"):
                    scopes_result = await adapter.get_dhcp_scopes()
                    if scopes_result.success and scopes_result.data:
                        for s in scopes_result.data.get("scopes", []):
                            iface = s.get("interface", "")
                            if s.get("enabled") and iface:
                                device_interfaces.add(iface)

                # Check each canonical scope has a matching device scope
                for cs in canonical_scopes:
                    vlan = vlan_map.get(cs.vlan_id)
                    if not vlan:
                        continue

                    expected_iface = f"vlan{vlan.vlan_id}"
                    if device_interfaces and expected_iface not in device_interfaces:
                        events.append(
                            DriftEvent(
                                organization_id=cs.organization_id,
                                site_id=cs.site_id,
                                device_id=brain.gateway_id,
                                drift_type=DriftType.RESOURCE_MISSING,
                                resource_type="dhcp_scope",
                                resource_id=cs.id,
                                expected_value={
                                    "interface": expected_iface,
                                    "range_start": cs.range_start,
                                    "range_end": cs.range_end,
                                },
                                actual_value=None,
                                severity=DriftSeverity.WARNING,
                                message=(
                                    f"DHCP scope for {expected_iface} "
                                    f"({cs.range_start}-{cs.range_end}) "
                                    f"missing on brain device"
                                ),
                            )
                        )
        except Exception as exc:
            logger.warning("DHCP drift check failed for brain %s: %s", gw.id, exc)

        return events

    async def _check_brain_dns(self, role_map: SiteRoleMap) -> list[DriftEvent]:
        """Compare canonical DNS records against brain device host overrides."""
        brain, gw = await self._get_brain_gw(role_map)
        if not brain or gw is None:
            return []

        # Load canonical DNS records for this site (org-scoped, only MANAGED)
        dns_result = await self.db.execute(
            select(CanonicalDNSRecord).where(
                CanonicalDNSRecord.organization_id == role_map.organization_id,
                CanonicalDNSRecord.site_id == role_map.site_id,
                CanonicalDNSRecord.management_state == ManagementState.MANAGED,
            )
        )
        canonical_dns = list(dns_result.scalars().all())
        if not canonical_dns:
            return []

        events: list[DriftEvent] = []
        adapter = build_adapter(gw)
        try:
            async with adapter:
                if not hasattr(adapter, "get_dns_overrides"):
                    return []
                dns_data = await adapter.get_dns_overrides()
                if not dns_data.success:
                    logger.warning(
                        "Could not probe DNS on brain %s: %s",
                        gw.id,
                        dns_data.error,
                    )
                    return []

                # Build lookup set of device DNS entries by FQDN
                # Adapters return {host, domain, ip} — combine to FQDN
                device_hostnames: set[str] = set()
                for entry in dns_data.data.get("overrides", []):
                    host = entry.get("host", entry.get("hostname", "")).lower()
                    domain = entry.get("domain", "").lower()
                    if host and domain:
                        device_hostnames.add(f"{host}.{domain}")
                    elif host:
                        device_hostnames.add(host)

                for cr in canonical_dns:
                    # Canonical hostname may be FQDN or short name
                    canonical_name = cr.hostname.lower()
                    if canonical_name not in device_hostnames:
                        events.append(
                            DriftEvent(
                                organization_id=cr.organization_id,
                                site_id=cr.site_id,
                                device_id=brain.gateway_id,
                                drift_type=DriftType.RESOURCE_MISSING,
                                resource_type="dns_record",
                                resource_id=cr.id,
                                expected_value={
                                    "hostname": cr.hostname,
                                    "value": cr.value,
                                    "record_type": cr.record_type,
                                },
                                actual_value=None,
                                severity=DriftSeverity.INFO,
                                message=(
                                    f"DNS record {cr.hostname} "
                                    f"({cr.record_type} → {cr.value}) "
                                    f"missing on brain device"
                                ),
                            )
                        )
        except Exception as exc:
            logger.warning("DNS drift check failed for brain %s: %s", gw.id, exc)

        return events

    async def _check_suppressions(self, role_map: SiteRoleMap) -> list[DriftEvent]:
        """Verify that suppression rules are still enforced on devices."""
        events: list[DriftEvent] = []
        result = await self.db.execute(
            select(SuppressionRule).where(
                SuppressionRule.site_id == role_map.site_id,
                SuppressionRule.is_active.is_(True),
            )
        )
        suppressions = list(result.scalars().all())
        if not suppressions:
            return events

        # Filter to DHCP suppression rules only
        dhcp_rules = [r for r in suppressions if r.resource_type == "dhcp"]
        if not dhcp_rules:
            return events

        # Batch-load all referenced gateways in one query (avoid N+1)
        device_ids = list({r.device_id for r in dhcp_rules})
        gw_result = await self.db.execute(
            select(GatewayConnection).where(GatewayConnection.id.in_(device_ids))
        )
        gw_map: dict[UUID, GatewayConnection] = {gw.id: gw for gw in gw_result.scalars().all()}

        # Group rules by device so we open one adapter connection per device
        from collections import defaultdict

        rules_by_device: dict[UUID, list[SuppressionRule]] = defaultdict(list)
        for rule in dhcp_rules:
            rules_by_device[rule.device_id].append(rule)

        for dev_id, rules in rules_by_device.items():
            gw = gw_map.get(dev_id)
            if gw is None:
                continue

            adapter = build_adapter(gw)
            try:
                async with adapter:
                    if not hasattr(adapter, "get_dhcp_scopes"):
                        continue
                    scope_result = await adapter.get_dhcp_scopes()
                    if not (scope_result.success and scope_result.data):
                        continue
                    scopes = scope_result.data.get("scopes", [])
                    for rule in rules:
                        for scope in scopes:
                            if scope.get("enabled") and rule.scope in (
                                scope.get("interface", ""),
                                "*",
                            ):
                                events.append(
                                    DriftEvent(
                                        organization_id=rule.organization_id,
                                        site_id=rule.site_id,
                                        device_id=rule.device_id,
                                        drift_type=DriftType.SUPPRESSION_VIOLATED,
                                        resource_type="dhcp",
                                        severity=DriftSeverity.WARNING,
                                        message=(
                                            f"DHCP still active on {scope.get('interface', '?')} "
                                            f"despite suppression rule"
                                        ),
                                    )
                                )
            except Exception as exc:
                logger.warning(
                    "Suppression check failed for device %s: %s",
                    dev_id,
                    exc,
                )

        return events

    # ── Queries ──────────────────────────────────────────────────────────

    async def list_events(
        self,
        org_id: UUID,
        *,
        site_id: UUID | None = None,
        severity: str | None = None,
        resolution: str | None = None,
        exclude_resolution: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[DriftEvent], int]:
        from app.core.site_access import current_user_var, site_scope_filter

        # Per-user site grant: fold the request-scoped caller's
        # granted-site set into the SQL so a site-limited operator never sees
        # sibling-site drift events and ``total`` reflects only granted rows.
        # No-op for super/org admins, grant-less users, and background context
        # (``current_user_var`` unset); fail-closed for a grant-less site-limited
        # user.
        grant_filter = site_scope_filter(current_user_var.get(), DriftEvent.site_id)

        q = (
            select(DriftEvent)
            .where(
                DriftEvent.organization_id == org_id,
                grant_filter,
            )
            .order_by(DriftEvent.created_at.desc())
        )
        cq = (
            select(func.count())
            .select_from(DriftEvent)
            .where(
                DriftEvent.organization_id == org_id,
                grant_filter,
            )
        )
        if site_id:
            q = q.where(DriftEvent.site_id == site_id)
            cq = cq.where(DriftEvent.site_id == site_id)
        if severity:
            q = q.where(DriftEvent.severity == severity)
            cq = cq.where(DriftEvent.severity == severity)
        if resolution:
            q = q.where(DriftEvent.resolution == resolution)
            cq = cq.where(DriftEvent.resolution == resolution)
        if exclude_resolution:
            q = q.where(DriftEvent.resolution != exclude_resolution)
            cq = cq.where(DriftEvent.resolution != exclude_resolution)

        total = (await self.db.execute(cq)).scalar() or 0
        items = list((await self.db.execute(q.limit(limit).offset(offset))).scalars().all())
        return items, total

    async def get_summary(
        self,
        org_id: UUID,
        *,
        site_id: UUID | None = None,
    ) -> dict[str, int]:
        """Return counts of drift events by severity/resolution.

        Optimised: uses two GROUP BY queries instead of 5+ individual COUNTs.
        """

        from app.core.site_access import current_user_var, site_scope_filter

        # Per-user site grant: a site-limited caller must not get
        # an org-wide aggregate. Fold the granted-site set into every GROUP BY /
        # COUNT below so the summary sums only over sites the caller can see.
        # No-op for super/org admins, grant-less users, and background context.
        filters = [
            DriftEvent.organization_id == org_id,
            site_scope_filter(current_user_var.get(), DriftEvent.site_id),
        ]
        if site_id:
            filters.append(DriftEvent.site_id == site_id)

        # Single query for severity breakdown + total
        sev_q = (
            select(
                DriftEvent.severity,
                func.count().label("cnt"),
            )
            .where(*filters)
            .group_by(DriftEvent.severity)
        )
        sev_rows = (await self.db.execute(sev_q)).all()

        counts: dict[str, int] = {
            "total": 0,
            DriftSeverity.CRITICAL: 0,
            DriftSeverity.WARNING: 0,
            DriftSeverity.INFO: 0,
        }
        for sev, cnt in sev_rows:
            counts[sev] = cnt
            counts["total"] += cnt

        # Single query for pending count
        pending_q = (
            select(func.count())
            .select_from(DriftEvent)
            .where(*filters, DriftEvent.resolution == DriftResolution.PENDING)
        )
        counts["pending"] = (await self.db.execute(pending_q)).scalar() or 0
        counts["resolved"] = counts["total"] - counts["pending"]
        return counts

    # ── Resolution ───────────────────────────────────────────────────────

    async def resolve_event(
        self,
        event_id: UUID,
        action: str,
        user_id: UUID | None = None,
        *,
        org_id: UUID | None = None,
    ) -> DriftEvent:
        """Resolve a drift event.

        Actions:
          reapply  – push FreeSdn canonical state back to device
          accept   – update canonical state to match device
          ignore   – mark resource as 'monitored' and dismiss
        """
        q = select(DriftEvent).where(DriftEvent.id == event_id)
        if org_id is not None:
            q = q.where(DriftEvent.organization_id == org_id)
        result = await self.db.execute(q)
        event = result.scalar_one_or_none()
        if event is None:
            raise ValueError(f"Drift event not found: {event_id}")

        # Defense in depth: a site-limited caller must not
        # resolve a drift event in a sibling site even if a future non-route
        # caller skips the API-layer guard. No-op for super/org admins and
        # background context (contextvar unset).
        from app.core.site_access import assert_site_access_for_request

        assert_site_access_for_request(event.site_id, detail="Drift event not found")

        if action == "reapply":
            event.resolution = DriftResolution.MANUALLY_FIXED
            # Schedule re-distribution for VLAN resources via Celery
            if event.resource_type == "vlan" and event.resource_id:
                cv_result = await self.db.execute(
                    select(CanonicalVLAN).where(
                        CanonicalVLAN.id == event.resource_id,
                        CanonicalVLAN.deleted_at.is_(None),
                    )
                )
                cv = cv_result.scalar_one_or_none()
                if cv:
                    try:
                        from app.modules.gateway.tasks.distribution_tasks import (
                            execute_distribution,
                        )

                        execute_distribution.delay(
                            str(cv.id),
                            str(cv.site_id),
                            triggered_by=str(user_id) if user_id else None,
                        )
                    except Exception:
                        logger.warning(
                            "Failed to schedule re-distribution for VLAN %s",
                            event.resource_id,
                            exc_info=True,
                        )
        elif action == "accept":
            event.resolution = DriftResolution.ACCEPTED
            # For missing resources, downgrade canonical to MONITORED so
            # the distribution engine no longer tries to push it
            if event.resource_type == "vlan" and event.resource_id:
                cv_result = await self.db.execute(
                    select(CanonicalVLAN).where(
                        CanonicalVLAN.id == event.resource_id,
                        CanonicalVLAN.deleted_at.is_(None),
                    )
                )
                cv = cv_result.scalar_one_or_none()
                if cv and event.drift_type == DriftType.RESOURCE_MISSING:
                    cv.management_state = ManagementState.MONITORED
        elif action == "ignore":
            event.resolution = DriftResolution.IGNORED
        else:
            raise ValueError(f"Unknown drift resolution action: {action}")

        event.resolved_at = datetime.now(UTC)
        event.resolved_by = user_id
        await self.db.flush()
        await self.db.refresh(event)
        return event

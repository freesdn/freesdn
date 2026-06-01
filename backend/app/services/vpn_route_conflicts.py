# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Route Conflict Detection Service
========================================================

Scans all VPN-advertised subnets across connections, site configs, and
site-to-site tunnels, then reports overlapping CIDR ranges that could
cause routing ambiguity or black-holes.
"""

import ipaddress
import logging
from itertools import combinations
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vpn import (
    SiteToSiteTunnel,
    SiteVPNConfiguration,
    VPNConnectionRecord,
)

logger = logging.getLogger(__name__)


class VPNRouteConflictService:
    """Detect overlapping subnet advertisements across all VPN sources."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def detect_conflicts(self, org_id: UUID) -> dict:
        """
        Collect every advertised subnet, compare all pairs, and return
        a report of conflicts.

        Returns::

            {
                "conflicts": [ ... ],
                "total": int,          # number of conflicts found
                "scanned_sources": int  # number of (subnet, source) entries compared
            }
        """
        sources = await self._collect_sources(org_id)
        conflicts = self._find_conflicts(sources)
        return {
            "conflicts": conflicts,
            "total": len(conflicts),
            "scanned_sources": len(sources),
        }

    # ------------------------------------------------------------------
    # Source collection
    # ------------------------------------------------------------------

    async def _collect_sources(self, org_id: UUID) -> list[tuple[str, str, str]]:
        """
               Gather (subnet_cidr, source_label, source_type) from every VPN
               data source.  Each query is wrapped in try/except so a single
               table failure does not block the whole scan.

               Site-scoped sources (site VPN configs, site-to-site tunnels) are
               additionally constrained to the request caller's granted sites
        so a site-limited operator does not see —
               and cannot infer the subnets of — sibling sites in the same org. The
               guard reads the request-scoped contextvar; it is a no-op for
               super_admin / org_admin / grant-less callers and in background context.

               For site-to-site tunnels, a tunnel spans two sites and a
               site-limited caller may hold a grant for only ONE endpoint. The tunnel
               is surfaced when either endpoint is granted, but only the GRANTED side's
               ``config`` subnets are emitted — emitting both sides would leak the
               ungranted sibling endpoint's network through the conflict report.

               ``VPNConnectionRecord`` rows are org-level (no ``site_id``) and remain
               org-scoped, matching the org-resource rule.
        """
        from app.core.site_access import site_ids_for_request

        granted_site_ids = site_ids_for_request()
        sources: list[tuple[str, str, str]] = []

        # 1. VPN connections — allowed_ips JSONB
        try:
            result = await self._session.execute(
                select(VPNConnectionRecord).where(
                    VPNConnectionRecord.organization_id == org_id,
                )
            )
            for conn in result.scalars().all():
                for cidr in conn.allowed_ips or []:
                    cidr_s = str(cidr).strip()
                    if cidr_s:
                        label = f"{conn.vpn_type}:{conn.name}"
                        sources.append((cidr_s, label, "connection"))
        except Exception:
            logger.exception(
                "Failed to collect subnets from vpn_connections for org %s",
                org_id,
            )

        # 2. Site VPN configs — remote_subnets + local_subnets JSONB
        try:
            from sqlalchemy.orm import selectinload

            cfg_q = (
                select(SiteVPNConfiguration)
                .where(
                    SiteVPNConfiguration.organization_id == org_id,
                )
                .options(selectinload(SiteVPNConfiguration.site))
            )
            if granted_site_ids is not None:
                cfg_q = cfg_q.where(SiteVPNConfiguration.site_id.in_(granted_site_ids))
            result = await self._session.execute(cfg_q)
            for cfg in result.scalars().all():
                site_name = cfg.site.name if cfg.site else str(cfg.site_id)[:8]
                label = f"site_config:{site_name}"
                for cidr in cfg.remote_subnets or []:
                    cidr_s = str(cidr).strip()
                    if cidr_s:
                        sources.append((cidr_s, label, "site_config"))
                for cidr in cfg.local_subnets or []:
                    cidr_s = str(cidr).strip()
                    if cidr_s:
                        sources.append((cidr_s, label, "site_config"))
        except Exception:
            logger.exception(
                "Failed to collect subnets from site_vpn_configs for org %s",
                org_id,
            )

        # 3. Site-to-site tunnels — config_a / config_b "subnets" key
        try:
            from sqlalchemy import or_

            granted_set = set(granted_site_ids) if granted_site_ids is not None else None

            tun_q = select(SiteToSiteTunnel).where(
                SiteToSiteTunnel.organization_id == org_id,
            )
            if granted_set is not None:
                # A tunnel spans two sites; surface it if the caller is granted
                # either endpoint (so conflicts touching their own site remain
                # visible) but never a tunnel between two ungranted sibling sites.
                ids = list(granted_set)
                tun_q = tun_q.where(
                    or_(
                        SiteToSiteTunnel.site_a_id.in_(ids),
                        SiteToSiteTunnel.site_b_id.in_(ids),
                    )
                )
            result = await self._session.execute(tun_q)
            for tunnel in result.scalars().all():
                tunnel_label = f"tunnel:{str(tunnel.id)[:8]}"
                # config_a describes site_a's network, config_b describes
                # site_b's. A site-limited caller may be granted only ONE endpoint
                # of a tunnel (the or_ above surfaces it); emitting BOTH sides'
                # subnets would leak the ungranted sibling site's network. So for
                # a site-limited caller emit only the granted side(s); an admin /
                # grant-less caller (granted_set is None) sees both sides.
                for side_cfg, side_tag, side_site_id in [
                    (tunnel.config_a, "a", tunnel.site_a_id),
                    (tunnel.config_b, "b", tunnel.site_b_id),
                ]:
                    if granted_set is not None and side_site_id not in granted_set:
                        continue
                    if not isinstance(side_cfg, dict):
                        continue
                    for cidr in side_cfg.get("subnets", []):
                        cidr_s = str(cidr).strip()
                        if cidr_s:
                            sources.append((cidr_s, f"{tunnel_label}:{side_tag}", "tunnel"))
        except Exception:
            logger.exception(
                "Failed to collect subnets from site_to_site_tunnels for org %s",
                org_id,
            )

        return sources

    # ------------------------------------------------------------------
    # Conflict detection
    # ------------------------------------------------------------------

    @staticmethod
    def _find_conflicts(
        sources: list[tuple[str, str, str]],
    ) -> list[dict[str, Any]]:
        """
        Compare every unique pair of sources and classify overlaps.
        """
        # Pre-parse networks, skip malformed CIDRs
        parsed: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str]] = []
        for cidr, label, stype in sources:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                parsed.append((net, label, stype))
            except ValueError:
                logger.warning("Skipping invalid CIDR %r from %s", cidr, label)

        conflicts: list[dict[str, Any]] = []

        for (net_a, label_a, type_a), (net_b, label_b, type_b) in combinations(parsed, 2):
            # Skip comparison across different address families
            if net_a.version != net_b.version:
                continue

            if not net_a.overlaps(net_b):
                continue

            # Classify the overlap
            if net_a == net_b:
                overlap_type = "exact"
                severity = "error"
                subnet_display = str(net_a)
            elif net_a.subnet_of(net_b):
                overlap_type = "subset"
                severity = "warning"
                subnet_display = str(net_a)
            elif net_a.supernet_of(net_b):
                overlap_type = "superset"
                severity = "warning"
                subnet_display = str(net_b)
            else:
                # Partial overlap (shouldn't normally happen with
                # standard CIDR but possible with non-aligned masks)
                overlap_type = "subset"
                severity = "warning"
                subnet_display = f"{net_a} <-> {net_b}"

            conflicts.append(
                {
                    "subnet": subnet_display,
                    "source_a": label_a,
                    "source_b": label_b,
                    "source_a_type": type_a,
                    "source_b_type": type_b,
                    "severity": severity,
                    "overlap_type": overlap_type,
                }
            )

        return conflicts

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Canonical Resource Service
=========================================

CRUD for platform-agnostic resources: VLANs, DHCP scopes,
DNS records, address groups.  Modifications trigger
distribution via the Distribution Service.
"""

from __future__ import annotations

import logging
from datetime import UTC
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.site_access import assert_can_access_site, site_scope_filter
from app.modules.gateway.models import (
    AddressGroupType,
    CanonicalAddressGroup,
    CanonicalDHCPReservation,
    CanonicalDHCPScope,
    CanonicalDNSRecord,
    CanonicalVLAN,
)

logger = logging.getLogger(__name__)


class CanonicalError(Exception):
    """Base canonical resource error."""


class VLANConflictError(CanonicalError):
    pass


class VLANNotFoundError(CanonicalError):
    def __init__(self, vlan_uuid: UUID):
        super().__init__(f"Canonical VLAN not found: {vlan_uuid}")


class DNSRecordNotFoundError(CanonicalError):
    def __init__(self, record_id: UUID):
        super().__init__(f"DNS record not found: {record_id}")


class SiteNotInOrgError(CanonicalError):
    def __init__(self, site_id: UUID):
        super().__init__(f"Site {site_id} not found in organization")


class CanonicalService:
    """CRUD for canonical (platform-agnostic) resources."""

    def __init__(self, db: AsyncSession, current_user: Any | None = None):
        self.db = db
        # the per-user site grant. When a
        # site-limited caller is threaded in, list queries are scoped to their
        # granted sites and object read/create-by-reference paths assert the
        # row's (or referenced VLAN's) site. Fall back to the request-scoped
        # contextvar so callers that construct CanonicalService(session) without
        # threading the user (e.g. distribution_api) are still enforced; ``None``
        # (system/background context, no request user) is a no-op — the org-scope
        # check upstream still applies.
        from app.core.site_access import current_user_var

        self.current_user = current_user if current_user is not None else current_user_var.get()

    async def _assert_site_in_org(self, site_id: UUID, org_id: UUID) -> None:
        """Reject a client-supplied site_id that doesn't belong to ``org_id``.

        create_vlan and create_dns_record stamp
        organization_id=org_id but accept a client-supplied site_id whose FK
        only validates existence, not org ownership. Without this a caller
        could plant a canonical row in their own org bound to a foreign site,
        breaking the (org, site) data-model invariant. Mirrors create_dhcp_scope
        which already derives site_id from an org-scoped get_vlan().
        """
        from app.models.core import Site

        exists = await self.db.scalar(
            select(Site.id).where(Site.id == site_id, Site.organization_id == org_id)
        )
        if exists is None:
            raise SiteNotInOrgError(site_id)

    # ═══════════════════════════════════════════════════════════════════════
    # Canonical VLANs
    # ═══════════════════════════════════════════════════════════════════════

    async def list_vlans(
        self,
        org_id: UUID,
        *,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[CanonicalVLAN], int]:
        scope = site_scope_filter(self.current_user, CanonicalVLAN.site_id)
        q = (
            select(CanonicalVLAN)
            .where(
                CanonicalVLAN.organization_id == org_id,
                CanonicalVLAN.deleted_at.is_(None),
                scope,
            )
            .order_by(CanonicalVLAN.vlan_id)
        )
        cq = (
            select(func.count())
            .select_from(CanonicalVLAN)
            .where(
                CanonicalVLAN.organization_id == org_id,
                CanonicalVLAN.deleted_at.is_(None),
                scope,
            )
        )
        if site_id:
            q = q.where(CanonicalVLAN.site_id == site_id)
            cq = cq.where(CanonicalVLAN.site_id == site_id)

        total = (await self.db.execute(cq)).scalar() or 0
        items = list((await self.db.execute(q.limit(limit).offset(offset))).scalars().all())
        return items, total

    async def get_vlan(
        self,
        vlan_uuid: UUID,
        *,
        org_id: UUID | None = None,
    ) -> CanonicalVLAN:
        q = (
            select(CanonicalVLAN)
            .options(
                selectinload(CanonicalVLAN.dhcp_scope),
                selectinload(CanonicalVLAN.dhcp_reservations),
            )
            .where(
                CanonicalVLAN.id == vlan_uuid,
                CanonicalVLAN.deleted_at.is_(None),
            )
        )
        if org_id is not None:
            q = q.where(CanonicalVLAN.organization_id == org_id)
        result = await self.db.execute(q)
        vlan = result.scalar_one_or_none()
        if vlan is None:
            raise VLANNotFoundError(vlan_uuid)
        # enforce the per-user site grant on the fetched row.
        # Raises 404 (existence-oracle-safe) for a site-limited caller lacking
        # the grant; no-op for super/org admins. Covers detail, update, delete,
        # and create-by-reference (create_dhcp_scope/reservation route here).
        if self.current_user is not None:
            try:
                assert_can_access_site(self.current_user, vlan.site_id, detail="VLAN not found")
            except Exception:
                raise VLANNotFoundError(vlan_uuid) from None
        return vlan

    async def create_vlan(
        self,
        org_id: UUID,
        **fields: Any,
    ) -> CanonicalVLAN:
        """Create a canonical VLAN.  Returns the new row; caller should
        trigger distribution separately if ``distribute=True``."""
        site_id = fields["site_id"]

        # ensure the supplied site_id belongs to the caller's org
        # before stamping a canonical VLAN against it.
        await self._assert_site_in_org(site_id, org_id)

        # Conflict check (org-scoped for defense-in-depth)
        existing = await self.db.execute(
            select(CanonicalVLAN).where(
                CanonicalVLAN.organization_id == org_id,
                CanonicalVLAN.site_id == site_id,
                CanonicalVLAN.vlan_id == fields["vlan_id"],
                CanonicalVLAN.deleted_at.is_(None),
            )
        )
        if existing.scalar_one_or_none():
            raise VLANConflictError(f"VLAN {fields['vlan_id']} already exists at this site")

        vlan = CanonicalVLAN(
            organization_id=org_id,
            site_id=site_id,
            vlan_id=fields["vlan_id"],
            name=fields["name"],
            description=fields.get("description"),
            subnet=fields["subnet"],
            gateway_ip=fields["gateway_ip"],
            dhcp_enabled=fields.get("dhcp_enabled", True),
            dhcp_range_start=fields.get("dhcp_range_start"),
            dhcp_range_end=fields.get("dhcp_range_end"),
            dhcp_lease_time=fields.get("dhcp_lease_time", 86400),
            dhcp_dns_servers=fields.get("dhcp_dns_servers", []),
            dhcp_domain=fields.get("dhcp_domain"),
            purpose=fields.get("purpose", "general"),
            template_id=fields.get("template_id"),
        )
        self.db.add(vlan)
        await self.db.flush()

        # Auto-create DHCP scope if enabled
        if vlan.dhcp_enabled and vlan.dhcp_range_start and vlan.dhcp_range_end:
            scope = CanonicalDHCPScope(
                organization_id=org_id,
                site_id=site_id,
                vlan_id=vlan.id,
                range_start=vlan.dhcp_range_start,
                range_end=vlan.dhcp_range_end,
                subnet_mask=self._subnet_to_mask(vlan.subnet),
                gateway=vlan.gateway_ip,
                lease_time=vlan.dhcp_lease_time,
                dns_servers=vlan.dhcp_dns_servers,
                domain_name=vlan.dhcp_domain,
            )
            self.db.add(scope)

        # Auto-create address group for the subnet
        addr_group = CanonicalAddressGroup(
            organization_id=org_id,
            site_id=site_id,
            name=f"FreeSdn_VLAN{vlan.vlan_id}_net",
            description=f"[FreeSdn:managed] {vlan.name} subnet",
            group_type=AddressGroupType.NETWORK,
            members=[vlan.subnet],
            auto_generated=True,
            source_vlan_id=vlan.id,
        )
        self.db.add(addr_group)

        await self.db.flush()
        await self.db.refresh(vlan)
        return vlan

    async def update_vlan(
        self,
        vlan_uuid: UUID,
        *,
        org_id: UUID | None = None,
        **fields: Any,
    ) -> CanonicalVLAN:
        vlan = await self.get_vlan(vlan_uuid, org_id=org_id)
        updatable = {
            "name",
            "description",
            "subnet",
            "gateway_ip",
            "dhcp_enabled",
            "dhcp_range_start",
            "dhcp_range_end",
            "dhcp_lease_time",
            "dhcp_dns_servers",
            "dhcp_domain",
            "purpose",
        }
        for key in updatable:
            if key in fields and fields[key] is not None:
                setattr(vlan, key, fields[key])

        await self.db.flush()
        await self.db.refresh(vlan)
        return vlan

    async def delete_vlan(
        self,
        vlan_uuid: UUID,
        *,
        org_id: UUID | None = None,
    ) -> None:
        vlan = await self.get_vlan(vlan_uuid, org_id=org_id)
        from datetime import datetime

        vlan.deleted_at = datetime.now(UTC)
        await self.db.flush()

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP Scopes
    # ═══════════════════════════════════════════════════════════════════════

    async def list_dhcp_scopes(
        self,
        org_id: UUID,
        *,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[CanonicalDHCPScope], int]:
        scope_filter = site_scope_filter(self.current_user, CanonicalDHCPScope.site_id)
        q = (
            select(CanonicalDHCPScope)
            .where(
                CanonicalDHCPScope.organization_id == org_id,
                scope_filter,
            )
            .order_by(CanonicalDHCPScope.created_at.desc())
        )
        cq = (
            select(func.count())
            .select_from(CanonicalDHCPScope)
            .where(
                CanonicalDHCPScope.organization_id == org_id,
                scope_filter,
            )
        )
        if site_id:
            q = q.where(CanonicalDHCPScope.site_id == site_id)
            cq = cq.where(CanonicalDHCPScope.site_id == site_id)
        total = (await self.db.execute(cq)).scalar() or 0
        items = list((await self.db.execute(q.limit(limit).offset(offset))).scalars().all())
        return items, total

    async def create_dhcp_scope(self, org_id: UUID, **fields: Any) -> CanonicalDHCPScope:
        # Verify the VLAN belongs to the same organization
        vlan = await self.get_vlan(fields["vlan_id"], org_id=org_id)
        scope = CanonicalDHCPScope(
            organization_id=org_id,
            site_id=vlan.site_id,
            **fields,
        )
        self.db.add(scope)
        await self.db.flush()
        await self.db.refresh(scope)
        return scope

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP Reservations
    # ═══════════════════════════════════════════════════════════════════════

    async def create_dhcp_reservation(
        self,
        org_id: UUID,
        **fields: Any,
    ) -> CanonicalDHCPReservation:
        # validate the referenced vlan_id belongs to the caller's
        # org (sibling create_dhcp_scope already does this via get_vlan).
        # Without it, an attacker's reservation joins onto a foreign VLAN's
        # read view by vlan_id alone (cross-tenant view-injection).
        if fields.get("vlan_id") is not None:
            await self.get_vlan(fields["vlan_id"], org_id=org_id)
        res = CanonicalDHCPReservation(
            organization_id=org_id,
            **fields,
        )
        self.db.add(res)
        await self.db.flush()
        await self.db.refresh(res)
        return res

    async def delete_dhcp_reservation(
        self,
        res_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> None:
        # this delete-by-id path was org-only — a site-limited
        # caller could remove a reservation belonging to a sibling site. The
        # reservation has no site_id of its own, so resolve the parent VLAN's
        # site and assert the per-user grant. No-op for super/org
        # admins; falls back to the request-scoped current_user via __init__.
        q = (
            select(CanonicalDHCPReservation)
            .options(selectinload(CanonicalDHCPReservation.vlan))
            .where(
                CanonicalDHCPReservation.id == res_id,
            )
        )
        if org_id is not None:
            q = q.where(CanonicalDHCPReservation.organization_id == org_id)
        result = await self.db.execute(q)
        res = result.scalar_one_or_none()
        if res:
            if self.current_user is not None:
                site_id = res.vlan.site_id if res.vlan is not None else None
                assert_can_access_site(
                    self.current_user, site_id, detail="DHCP reservation not found"
                )
            await self.db.delete(res)
            await self.db.flush()

    # ═══════════════════════════════════════════════════════════════════════
    # DNS Records
    # ═══════════════════════════════════════════════════════════════════════

    async def list_dns_records(
        self,
        org_id: UUID,
        *,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[CanonicalDNSRecord], int]:
        scope_filter = site_scope_filter(self.current_user, CanonicalDNSRecord.site_id)
        q = (
            select(CanonicalDNSRecord)
            .where(
                CanonicalDNSRecord.organization_id == org_id,
                scope_filter,
            )
            .order_by(CanonicalDNSRecord.hostname)
        )
        cq = (
            select(func.count())
            .select_from(CanonicalDNSRecord)
            .where(
                CanonicalDNSRecord.organization_id == org_id,
                scope_filter,
            )
        )
        if site_id:
            q = q.where(CanonicalDNSRecord.site_id == site_id)
            cq = cq.where(CanonicalDNSRecord.site_id == site_id)
        total = (await self.db.execute(cq)).scalar() or 0
        items = list((await self.db.execute(q.limit(limit).offset(offset))).scalars().all())
        return items, total

    async def create_dns_record(self, org_id: UUID, **fields: Any) -> CanonicalDNSRecord:
        # same reference-injection class as create_vlan — validate
        # the supplied site_id belongs to the caller's org before stamping.
        if fields.get("site_id") is not None:
            await self._assert_site_in_org(fields["site_id"], org_id)
        rec = CanonicalDNSRecord(
            organization_id=org_id,
            **fields,
        )
        self.db.add(rec)
        await self.db.flush()
        await self.db.refresh(rec)
        return rec

    async def update_dns_record(
        self,
        record_id: UUID,
        *,
        org_id: UUID | None = None,
        **fields: Any,
    ) -> CanonicalDNSRecord:
        q = select(CanonicalDNSRecord).where(CanonicalDNSRecord.id == record_id)
        if org_id is not None:
            q = q.where(CanonicalDNSRecord.organization_id == org_id)
        result = await self.db.execute(q)
        rec = result.scalar_one_or_none()
        if rec is None:
            raise DNSRecordNotFoundError(record_id)
        # enforce the per-user site grant on this update-by-id
        # path (was org-only). A site-limited caller must not modify a DNS record
        # in a sibling site. 404-shape (existence-oracle-safe); no-op for admins.
        if self.current_user is not None:
            try:
                assert_can_access_site(
                    self.current_user, rec.site_id, detail="DNS record not found"
                )
            except Exception:
                raise DNSRecordNotFoundError(record_id) from None
        for key in ("value", "ttl", "priority", "description"):
            if key in fields and fields[key] is not None:
                setattr(rec, key, fields[key])
        await self.db.flush()
        await self.db.refresh(rec)
        return rec

    async def delete_dns_record(
        self,
        record_id: UUID,
        *,
        org_id: UUID | None = None,
    ) -> None:
        q = select(CanonicalDNSRecord).where(CanonicalDNSRecord.id == record_id)
        if org_id is not None:
            q = q.where(CanonicalDNSRecord.organization_id == org_id)
        result = await self.db.execute(q)
        rec = result.scalar_one_or_none()
        if rec:
            # enforce the per-user site grant on this
            # delete-by-id path (was org-only). A site-limited caller must not
            # delete a DNS record in a sibling site. No-op for super/org admins.
            if self.current_user is not None:
                assert_can_access_site(
                    self.current_user, rec.site_id, detail="DNS record not found"
                )
            await self.db.delete(rec)
            await self.db.flush()

    # ═══════════════════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _subnet_to_mask(cidr: str) -> str:
        """Convert CIDR '10.30.0.0/24' → '255.255.255.0'."""
        import ipaddress

        net = ipaddress.ip_network(cidr, strict=False)
        return str(net.netmask)

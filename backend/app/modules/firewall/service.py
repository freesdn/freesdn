# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Firewall Module Service
=====================================

Business logic for firewall and network security management.
"""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================


class FirewallError(Exception):
    """Base firewall error."""

    pass


class RuleNotFoundError(FirewallError):
    """Firewall rule not found."""

    def __init__(self, rule_id: UUID):
        super().__init__(f"Firewall rule not found: {rule_id}")


class DeviceNotFoundError(FirewallError):
    """Firewall device not found."""

    def __init__(self, device_id: UUID):
        super().__init__(f"Firewall device not found: {device_id}")


class NATNotFoundError(FirewallError):
    """NAT rule not found."""

    def __init__(self, nat_id: UUID):
        super().__init__(f"NAT rule not found: {nat_id}")


class VPNNotFoundError(FirewallError):
    """VPN tunnel not found."""

    def __init__(self, vpn_id: UUID):
        super().__init__(f"VPN tunnel not found: {vpn_id}")


# =============================================================================
# Firewall Service
# =============================================================================

# ── Mutable field whitelists (prevent mass-assignment attacks) ──────────────
_RULE_MUTABLE_FIELDS = frozenset(
    {
        "name",
        "description",
        "rule_order",
        "source_address",
        "source_port",
        "source_zone",
        "dest_address",
        "dest_port",
        "dest_zone",
        "protocol",
        "action",
        "log_enabled",
        "schedule_id",
        "is_enabled",
    }
)

_NAT_RULE_MUTABLE_FIELDS = frozenset(
    {
        "name",
        "description",
        "nat_type",
        "original_address",
        "original_port",
        "translated_address",
        "translated_port",
        "protocol",
        "interface",
        "is_enabled",
    }
)

_VPN_TUNNEL_MUTABLE_FIELDS = frozenset(
    {
        "name",
        "description",
        "vpn_type",
        "remote_address",
        "remote_id",
        "local_address",
        "local_id",
        "local_subnets",
        "remote_subnets",
        "auth_type",
        "is_enabled",
        "settings",
    }
)


class FirewallService:
    """Service for firewall management."""

    def __init__(
        self,
        db: AsyncSession,
        organization_id: UUID,
        accessible_site_ids: set[UUID] | None = None,
    ):
        self.db = db
        self.organization_id = organization_id
        # intersect the org-device scope with per-user site
        # grants (covers firewall rules / NAT / IDS / device routes at once).
        self.accessible_site_ids = accessible_site_ids

    def _devices_for_org(self, site_id: UUID | None = None):
        """Subquery of firewall device IDs for the current organization, optionally filtered by site."""
        from app.models.core import Site
        from app.modules.firewall.models import FirewallDevice

        stmt = (
            select(FirewallDevice.id)
            .join(Site, FirewallDevice.site_id == Site.id)
            .where(
                Site.organization_id == self.organization_id,
                Site.deleted_at.is_(None),
            )
        )
        if site_id:
            stmt = stmt.where(FirewallDevice.site_id == site_id)
        if self.accessible_site_ids is not None:
            stmt = stmt.where(FirewallDevice.site_id.in_(self.accessible_site_ids))
        return stmt.subquery()

    async def _verify_device_org(self, device_id: UUID | None) -> None:
        """Verify that a device belongs to the current organization."""
        if device_id is None:
            return
        dev_sq = self._devices_for_org()
        result = await self.db.execute(
            select(func.count()).select_from(dev_sq).where(dev_sq.c.id == device_id)
        )
        if result.scalar() == 0:
            raise DeviceNotFoundError(device_id)

    # -------------------------------------------------------------------------
    # Firewall Rules
    # -------------------------------------------------------------------------

    async def list_rules(
        self,
        device_id: UUID | None = None,
        is_enabled: bool | None = None,
        action: str | None = None,
        site_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Any], int]:
        """List firewall rules.

        Returns ``(rows, total)``. The annotation used to say ``list[Any]``
        while the body returned a 2-tuple, which is how ``reorder_rules`` below
        ended up handing an endpoint something it could not iterate.
        """
        from app.modules.firewall.models import FirewallRule

        dev_sq = self._devices_for_org(site_id=site_id)
        query = select(FirewallRule).where(
            FirewallRule.deleted_at.is_(None),
            FirewallRule.device_id.in_(select(dev_sq.c.id)),
        )

        if device_id:
            query = query.where(FirewallRule.device_id == device_id)
        if is_enabled is not None:
            query = query.where(FirewallRule.is_enabled == is_enabled)
        if action:
            query = query.where(FirewallRule.action == action)

        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(FirewallRule.rule_order).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_rule(self, rule_id: UUID) -> Any:
        """Get a firewall rule by ID."""
        from app.modules.firewall.models import FirewallRule

        dev_sq = self._devices_for_org()
        result = await self.db.execute(
            select(FirewallRule).where(
                FirewallRule.id == rule_id,
                FirewallRule.deleted_at.is_(None),
                FirewallRule.device_id.in_(select(dev_sq.c.id)),
            )
        )
        rule = result.scalar_one_or_none()

        if not rule:
            raise RuleNotFoundError(rule_id)

        return rule

    async def create_rule(self, data: dict[str, Any]) -> Any:
        """Create a new firewall rule."""
        from app.modules.firewall.models import FirewallRule

        await self._verify_device_org(data.get("device_id"))
        rule = FirewallRule(**data)
        self.db.add(rule)
        await self.db.commit()
        await self.db.refresh(rule)

        return rule

    async def update_rule(self, rule_id: UUID, data: dict[str, Any]) -> Any:
        """Update a firewall rule."""
        rule = await self.get_rule(rule_id)

        for key, value in data.items():
            if key in _RULE_MUTABLE_FIELDS and hasattr(rule, key):
                setattr(rule, key, value)

        await self.db.commit()
        await self.db.refresh(rule)

        return rule

    async def delete_rule(self, rule_id: UUID) -> bool:
        """Soft delete a firewall rule."""
        rule = await self.get_rule(rule_id)
        rule.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    async def reorder_rules(self, device_id: UUID, rule_ids: list[UUID]) -> list[Any]:
        """Reorder firewall rules, returning the rules in their new order."""
        from app.modules.firewall.models import FirewallRule

        await self._verify_device_org(device_id)
        # Fetch all active rules for this device in one query (avoid N+1)
        result = await self.db.execute(
            select(FirewallRule).where(
                FirewallRule.device_id == device_id,
                FirewallRule.deleted_at.is_(None),
                FirewallRule.id.in_(rule_ids),
            )
        )
        rules_by_id = {rule.id: rule for rule in result.scalars().all()}
        for order, rule_id in enumerate(rule_ids, start=1):
            rule = rules_by_id.get(rule_id)
            if rule:
                rule.rule_order = order

        await self.db.commit()
        # ``list_rules`` returns ``(rows, total)``. This returned it whole, and
        # the endpoint does ``[FirewallRuleResponse.model_validate(r) for r in
        # rules]`` -- iterating a 2-tuple yields the LIST and then the int, so
        # validating a list against a rule model raised and every single call
        # to POST /firewall/rules/reorder came back 500.
        #
        # The rule_order writes above had already been committed by then, so
        # the reorder actually took effect and only the response failed. The
        # UI treats the 500 as a failure and refetches, showing the new order
        # under an error toast -- which is exactly the shape that gets a bug
        # written off as cosmetic.
        #
        # Also bump the page cap: the default limit is 100, and reordering is
        # the one operation where returning a truncated list would tell the
        # operator their rules had been reordered into a shorter set.
        rows, _total = await self.list_rules(device_id=device_id, limit=max(len(rule_ids), 100))
        return rows

    # -------------------------------------------------------------------------
    # NAT Rules
    # -------------------------------------------------------------------------

    async def list_nat_rules(
        self,
        device_id: UUID | None = None,
        nat_type: str | None = None,
        is_enabled: bool | None = None,
        site_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Any]:
        """List NAT rules."""
        from app.modules.firewall.models import NATRule

        dev_sq = self._devices_for_org(site_id=site_id)
        query = select(NATRule).where(
            NATRule.deleted_at.is_(None),
            NATRule.device_id.in_(select(dev_sq.c.id)),
        )

        if device_id:
            query = query.where(NATRule.device_id == device_id)
        if nat_type:
            query = query.where(NATRule.nat_type == nat_type)
        if is_enabled is not None:
            query = query.where(NATRule.is_enabled == is_enabled)

        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(NATRule.name).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def create_nat_rule(self, data: dict[str, Any]) -> Any:
        """Create a NAT rule."""
        from app.modules.firewall.models import NATRule

        await self._verify_device_org(data.get("device_id"))
        rule = NATRule(**data)
        self.db.add(rule)
        await self.db.commit()
        await self.db.refresh(rule)

        return rule

    async def get_nat_rule(self, nat_id: UUID) -> Any:
        """Get a single NAT rule by ID."""
        from app.modules.firewall.models import NATRule

        dev_sq = self._devices_for_org()
        result = await self.db.execute(
            select(NATRule).where(
                NATRule.id == nat_id,
                NATRule.deleted_at.is_(None),
                NATRule.device_id.in_(select(dev_sq.c.id)),
            )
        )
        rule = result.scalar_one_or_none()
        if not rule:
            raise NATNotFoundError(nat_id)
        return rule

    async def update_nat_rule(self, nat_id: UUID, data: dict[str, Any]) -> Any:
        """Update a NAT rule."""
        rule = await self.get_nat_rule(nat_id)
        for key, value in data.items():
            if key in _NAT_RULE_MUTABLE_FIELDS and hasattr(rule, key):
                setattr(rule, key, value)
        await self.db.commit()
        await self.db.refresh(rule)
        return rule

    async def delete_nat_rule(self, nat_id: UUID) -> bool:
        """Soft delete a NAT rule."""
        rule = await self.get_nat_rule(nat_id)
        rule.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    # -------------------------------------------------------------------------
    # VPN Management
    # -------------------------------------------------------------------------

    async def list_vpn_tunnels(
        self,
        device_id: UUID | None = None,
        vpn_type: str | None = None,
        status: str | None = None,
        site_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Any]:
        """List VPN tunnels."""
        from app.modules.firewall.models import VPNTunnel

        dev_sq = self._devices_for_org(site_id=site_id)
        query = select(VPNTunnel).where(
            VPNTunnel.deleted_at.is_(None),
            VPNTunnel.device_id.in_(select(dev_sq.c.id)),
        )

        if device_id:
            query = query.where(VPNTunnel.device_id == device_id)
        if vpn_type:
            query = query.where(VPNTunnel.vpn_type == vpn_type)
        if status:
            query = query.where(VPNTunnel.status == status)

        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(VPNTunnel.name).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get_vpn_tunnel(self, vpn_id: UUID) -> Any:
        """Get a VPN tunnel by ID."""
        from app.modules.firewall.models import VPNTunnel

        dev_sq = self._devices_for_org()
        result = await self.db.execute(
            select(VPNTunnel).where(
                VPNTunnel.id == vpn_id,
                VPNTunnel.deleted_at.is_(None),
                VPNTunnel.device_id.in_(select(dev_sq.c.id)),
            )
        )
        tunnel = result.scalar_one_or_none()

        if not tunnel:
            raise VPNNotFoundError(vpn_id)

        return tunnel

    async def create_vpn_tunnel(self, data: dict[str, Any]) -> Any:
        """Create a VPN tunnel."""
        from app.modules.firewall.models import VPNTunnel

        await self._verify_device_org(data.get("device_id"))
        tunnel = VPNTunnel(**data)
        self.db.add(tunnel)
        await self.db.commit()
        await self.db.refresh(tunnel)

        return tunnel

    async def update_vpn_tunnel(self, vpn_id: UUID, data: dict[str, Any]) -> Any:
        """Update a VPN tunnel."""
        tunnel = await self.get_vpn_tunnel(vpn_id)
        for key, value in data.items():
            if key in _VPN_TUNNEL_MUTABLE_FIELDS and hasattr(tunnel, key):
                setattr(tunnel, key, value)
        await self.db.commit()
        await self.db.refresh(tunnel)
        return tunnel

    async def delete_vpn_tunnel(self, vpn_id: UUID) -> bool:
        """Soft delete a VPN tunnel."""
        tunnel = await self.get_vpn_tunnel(vpn_id)
        tunnel.deleted_at = datetime.now(UTC)
        await self.db.commit()
        return True

    async def get_vpn_stats(self, site_id: UUID | None = None) -> dict[str, Any]:
        """Get VPN statistics."""
        from app.modules.firewall.models import VPNStatus, VPNTunnel

        dev_sq = self._devices_for_org(site_id=site_id)
        query = (
            select(VPNTunnel.status, func.count(VPNTunnel.id))
            .where(
                VPNTunnel.deleted_at.is_(None),
                VPNTunnel.device_id.in_(select(dev_sq.c.id)),
            )
            .group_by(VPNTunnel.status)
        )

        result = await self.db.execute(query)
        stats = dict(result.all())

        return {
            "total": sum(stats.values()),
            "up": stats.get(VPNStatus.UP.value, 0),
            "down": stats.get(VPNStatus.DOWN.value, 0),
            "error": stats.get(VPNStatus.ERROR.value, 0),
        }

    # -------------------------------------------------------------------------
    # IDS/IPS Alerts
    # -------------------------------------------------------------------------

    async def search_alerts(
        self,
        device_id: UUID | None = None,
        severity: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        is_acknowledged: bool | None = None,
        site_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Any]:
        """Search IDS/IPS alerts."""
        from app.modules.firewall.models import IDSAlert

        dev_sq = self._devices_for_org(site_id=site_id)
        query = select(IDSAlert).where(
            IDSAlert.device_id.in_(select(dev_sq.c.id)),
        )

        if device_id:
            query = query.where(IDSAlert.device_id == device_id)
        if severity:
            query = query.where(IDSAlert.severity == severity)
        if start_time:
            query = query.where(IDSAlert.timestamp >= start_time)
        if end_time:
            query = query.where(IDSAlert.timestamp <= end_time)
        if is_acknowledged is not None:
            query = query.where(IDSAlert.is_acknowledged == is_acknowledged)

        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(IDSAlert.timestamp.desc()).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def acknowledge_alert(self, alert_id: UUID, user_id: UUID) -> Any:
        """Acknowledge an IDS alert."""
        from app.modules.firewall.models import IDSAlert

        dev_sq = self._devices_for_org()
        result = await self.db.execute(
            select(IDSAlert).where(
                IDSAlert.id == alert_id,
                IDSAlert.device_id.in_(select(dev_sq.c.id)),
            )
        )
        alert = result.scalar_one_or_none()

        if not alert:
            raise FirewallError(f"Alert not found: {alert_id}")

        alert.is_acknowledged = True
        alert.acknowledged_by = user_id
        alert.acknowledged_at = datetime.now(UTC)
        await self.db.commit()

        return alert

    async def get_alert_stats(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        site_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Get IDS alert statistics."""
        from app.modules.firewall.models import AlertSeverity, IDSAlert

        dev_sq = self._devices_for_org(site_id=site_id)
        query = select(IDSAlert.severity, func.count(IDSAlert.id)).where(
            IDSAlert.device_id.in_(select(dev_sq.c.id)),
        )

        if start_time:
            query = query.where(IDSAlert.timestamp >= start_time)
        if end_time:
            query = query.where(IDSAlert.timestamp <= end_time)

        query = query.group_by(IDSAlert.severity)

        result = await self.db.execute(query)
        stats = dict(result.all())

        # Count unacknowledged
        unack_query = select(func.count(IDSAlert.id)).where(
            IDSAlert.is_acknowledged == False,  # noqa: E712
            IDSAlert.device_id.in_(select(dev_sq.c.id)),
        )
        if start_time:
            unack_query = unack_query.where(IDSAlert.timestamp >= start_time)
        if end_time:
            unack_query = unack_query.where(IDSAlert.timestamp <= end_time)
        unacknowledged = await self.db.scalar(unack_query) or 0

        return {
            "total": sum(stats.values()),
            "critical": stats.get(AlertSeverity.CRITICAL.value, 0),
            "high": stats.get(AlertSeverity.HIGH.value, 0),
            "medium": stats.get(AlertSeverity.MEDIUM.value, 0),
            "low": stats.get(AlertSeverity.LOW.value, 0),
            "unacknowledged": unacknowledged,
        }

    # -------------------------------------------------------------------------
    # Firewall Logs
    # -------------------------------------------------------------------------

    async def search_logs(
        self,
        device_id: UUID | None = None,
        action: str | None = None,
        source_ip: str | None = None,
        dest_ip: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        site_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Any]:
        """Search firewall logs."""
        from app.modules.firewall.models import FirewallLog

        dev_sq = self._devices_for_org(site_id=site_id)
        query = select(FirewallLog).where(
            FirewallLog.device_id.in_(select(dev_sq.c.id)),
        )

        if device_id:
            query = query.where(FirewallLog.device_id == device_id)
        if action:
            query = query.where(FirewallLog.action == action)
        if source_ip:
            query = query.where(FirewallLog.source_ip == source_ip)
        if dest_ip:
            query = query.where(FirewallLog.dest_ip == dest_ip)
        if start_time:
            query = query.where(FirewallLog.timestamp >= start_time)
        if end_time:
            query = query.where(FirewallLog.timestamp <= end_time)

        total = (
            await self.db.execute(select(func.count()).select_from(query.subquery()))
        ).scalar_one()
        query = query.order_by(FirewallLog.timestamp.desc()).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all()), total

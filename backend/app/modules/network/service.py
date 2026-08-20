# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Network Module - Service Layer
======================================

Business logic for network management operations.

Organisation-scope filtering is done by joining through the Site
model (Device→Site→Organization) since devices, VLANs, etc. carry
``site_id`` – not ``organization_id`` – directly.
"""

import logging
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.events import Event, EventCategory, get_event_bus
from app.core.security_utils import escape_like
from app.models.core import Site

# Device models - used by switch port, client, device services.
from app.models.devices import (
    Device as NetworkDevice,
)
from app.models.devices import (
    DeviceClient as NetworkClient,
)
from app.models.devices import (
    DevicePort as SwitchPort,
)
from app.modules.network.models import (
    Network as Vlan,
)
from app.modules.network.models import (
    TopologyLink,
    WifiNetwork,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sites_for_org(organization_id: UUID):
    """Subquery returning site IDs belonging to an organization (∩ per-user
    site grants when the request's caller is site-limited)."""
    from app.core.site_access import site_ids_for_request

    q = select(Site.id).where(
        Site.organization_id == organization_id,
        Site.deleted_at.is_(None),
    )
    ids = site_ids_for_request()
    if ids is not None:
        q = q.where(Site.id.in_(ids))
    return q.scalar_subquery()


# ── Mutable field whitelists (prevent mass-assignment attacks) ──────────────
_VLAN_MUTABLE_FIELDS = frozenset(
    {
        "name",
        "description",
        "vlan_id",
        "purpose",
        "gateway",
        "subnet",
        "subnet_mask",
        "cidr",
        "dhcp_enabled",
        "dhcp_start",
        "dhcp_end",
        "domain",
        "is_active",
    }
)

_WIFI_MUTABLE_FIELDS = frozenset(
    {
        "ssid",
        "security",
        "password_hash",
        "vlan_id",
        "hidden",
        "enabled",
        "band",
        "client_isolation",
        "band_steering",
        "fast_roaming",
        "rate_limit_enabled",
        "rate_limit_up",
        "rate_limit_down",
        "roaming_protocol",
        "minimum_rssi",
    }
)

_PORT_MUTABLE_FIELDS = frozenset(
    {
        "name",
        "is_enabled",
        "is_poe_enabled",
        "vlan_id",
        "speed_mbps",
        "duplex",
    }
)

_CLIENT_MUTABLE_FIELDS = frozenset(
    {
        "hostname",
        "ip_address",
    }
)

_PORT_FIELD_ALIASES = {
    "enabled": "is_enabled",
    "poe_enabled": "is_poe_enabled",
    "native_vlan": "vlan_id",
}


class NetworkServiceError(Exception):
    """Base exception for network service errors."""

    pass


class VlanNotFoundError(NetworkServiceError):
    """VLAN not found."""

    pass


class WifiNetworkNotFoundError(NetworkServiceError):
    """WiFi network not found."""

    pass


class DeviceNotFoundError(NetworkServiceError):
    """Device not found."""

    pass


class PortNotFoundError(NetworkServiceError):
    """Port not found."""

    pass


class ClientNotFoundError(NetworkServiceError):
    """Client not found."""

    pass


class DuplicateError(NetworkServiceError):
    """Duplicate resource error."""

    pass


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------


def _network_event(event_type: str, **payload) -> Event:
    """Create a network-module domain event.

    SECURITY: if the caller put ``organization_id``
    into ``**payload`` (every existing caller does — e.g.
    ``_emit("network.vlan.created", site_id=..., organization_id=...)``)
    we also lift it onto ``Event.organization_id`` so the fail-closed
    WS router can route correctly. The payload key is preserved so
    existing consumers that read ``event.payload['organization_id']``
    (e.g. ``modules/gateway/events/handlers.py:53``) keep working.
    """
    org_id = payload.get("organization_id")
    return Event(
        event_type=event_type,
        category=EventCategory.SYSTEM,
        source="network",
        organization_id=str(org_id) if org_id else None,
        payload=payload,
    )


async def _emit(event_type: str, **payload) -> None:
    """Fire-and-forget publish to the global EventBus."""
    try:
        bus = get_event_bus()
        await bus.publish(_network_event(event_type, **payload))
    except Exception:
        logger.debug("Failed to emit event %s", event_type, exc_info=True)


# ============================================================================
# VLAN Service
# ============================================================================


class VlanService:
    """Service for VLAN management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------

    async def list(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        skip: int = 0,
        limit: int = 100,
        site_ids: set[UUID] | None = None,
    ) -> tuple[list[Vlan], int]:
        """List VLANs for an organization.

        ``site_ids`` restricts results to a site-limited
        user's granted sites — applied at the query level so the count
        stays accurate. None = no site-limit (org scope only).
        """
        query = select(Vlan).where(Vlan.site_id.in_(_sites_for_org(organization_id)))
        if site_ids is not None:
            query = query.where(Vlan.site_id.in_(site_ids))
        if site_id:
            query = query.where(Vlan.site_id == site_id)

        count_query = select(func.count()).select_from(query.subquery())
        total = await self.db.scalar(count_query) or 0

        query = query.order_by(Vlan.vlan_id).offset(skip).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get(self, vlan_uuid: UUID, organization_id: UUID) -> Vlan:
        """Get a VLAN by UUID."""
        result = await self.db.execute(
            select(Vlan).where(
                Vlan.id == vlan_uuid,
                Vlan.site_id.in_(_sites_for_org(organization_id)),
            )
        )
        vlan = result.scalar_one_or_none()
        if not vlan:
            raise VlanNotFoundError(f"VLAN {vlan_uuid} not found")
        return vlan

    async def get_by_vlan_id(
        self,
        vlan_id: int,
        organization_id: UUID,
        site_id: UUID | None = None,
    ) -> Vlan | None:
        """Get a VLAN by VLAN ID number."""
        query = select(Vlan).where(
            Vlan.vlan_id == vlan_id,
            Vlan.site_id.in_(_sites_for_org(organization_id)),
        )
        if site_id:
            query = query.where(Vlan.site_id == site_id)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create(
        self,
        organization_id: UUID,
        vlan_id: int,
        name: str,
        description: str | None = None,
        site_id: UUID | None = None,
        dhcp_enabled: bool = False,
        dhcp_start: str | None = None,
        dhcp_end: str | None = None,
        gateway: str | None = None,
        subnet_mask: str | None = None,
    ) -> Vlan:
        """Create a new VLAN."""
        existing = await self.get_by_vlan_id(vlan_id, organization_id, site_id)
        if existing:
            raise DuplicateError(f"VLAN {vlan_id} already exists")

        vlan = Vlan(
            site_id=site_id,
            vlan_id=vlan_id,
            name=name,
            description=description,
            dhcp_enabled=dhcp_enabled,
            dhcp_start=dhcp_start,
            dhcp_end=dhcp_end,
            gateway=gateway,
            subnet_mask=subnet_mask,
        )
        self.db.add(vlan)
        await self.db.commit()
        await self.db.refresh(vlan)
        logger.info("Created VLAN %s (%s) for org %s", vlan_id, name, organization_id)
        await _emit(
            "network.vlan.created",
            vlan_id=vlan_id,
            vlan_uuid=str(vlan.id),
            name=name,
            site_id=str(site_id) if site_id else None,
            dhcp_enabled=dhcp_enabled,
        )
        return vlan

    async def update(
        self,
        vlan_uuid: UUID,
        organization_id: UUID,
        **updates,
    ) -> Vlan:
        """Update a VLAN."""
        vlan = await self.get(vlan_uuid, organization_id)
        for key, value in updates.items():
            if key in _VLAN_MUTABLE_FIELDS and value is not None and hasattr(vlan, key):
                setattr(vlan, key, value)
        await self.db.commit()
        await self.db.refresh(vlan)
        logger.info("Updated VLAN %s", vlan.vlan_id)
        await _emit(
            "network.vlan.updated",
            vlan_id=vlan.vlan_id,
            vlan_uuid=str(vlan.id),
            site_id=str(vlan.site_id) if vlan.site_id else None,
            updated_fields=list(updates.keys()),
        )
        return vlan

    async def delete(self, vlan_uuid: UUID, organization_id: UUID) -> None:
        """Delete a VLAN."""
        vlan = await self.get(vlan_uuid, organization_id)
        vlan_id = vlan.vlan_id
        site_id = vlan.site_id
        await self.db.delete(vlan)
        await self.db.commit()
        logger.info("Deleted VLAN %s", vlan_id)
        await _emit(
            "network.vlan.deleted",
            vlan_id=vlan_id,
            vlan_uuid=str(vlan_uuid),
            site_id=str(site_id) if site_id else None,
        )


# ============================================================================
# WiFi Network Service
# ============================================================================


class WifiNetworkService:
    """Service for WiFi network management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------

    async def list(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        enabled: bool | None = None,
        skip: int = 0,
        limit: int = 100,
        site_ids: set[UUID] | None = None,
    ) -> tuple[list[WifiNetwork], int]:
        """List WiFi networks.

        ``site_ids`` restricts results to a site-limited
        user's granted sites — applied at the query level so the count
        stays accurate. None = no site-limit (org scope only).
        """
        query = select(WifiNetwork).where(WifiNetwork.site_id.in_(_sites_for_org(organization_id)))
        if site_ids is not None:
            query = query.where(WifiNetwork.site_id.in_(site_ids))
        if site_id:
            query = query.where(WifiNetwork.site_id == site_id)
        if enabled is not None:
            query = query.where(WifiNetwork.enabled == enabled)

        count_query = select(func.count()).select_from(query.subquery())
        total = await self.db.scalar(count_query) or 0

        query = query.order_by(WifiNetwork.ssid).offset(skip).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get(self, wifi_id: UUID, organization_id: UUID) -> WifiNetwork:
        """Get a WiFi network by ID."""
        result = await self.db.execute(
            select(WifiNetwork).where(
                WifiNetwork.id == wifi_id,
                WifiNetwork.site_id.in_(_sites_for_org(organization_id)),
            )
        )
        network = result.scalar_one_or_none()
        if not network:
            raise WifiNetworkNotFoundError(f"WiFi network {wifi_id} not found")
        return network

    async def get_by_ssid(
        self,
        ssid: str,
        organization_id: UUID,
    ) -> WifiNetwork | None:
        """Get a WiFi network by SSID."""
        result = await self.db.execute(
            select(WifiNetwork).where(
                WifiNetwork.ssid == ssid,
                WifiNetwork.site_id.in_(_sites_for_org(organization_id)),
            )
        )
        return result.scalar_one_or_none()

    async def create(
        self,
        organization_id: UUID,
        ssid: str,
        security: str = "wpa2_personal",
        password_hash: str | None = None,
        vlan_id: int | None = None,
        site_id: UUID | None = None,
        hidden: bool = False,
        enabled: bool = True,
        band: str = "both",
        client_isolation: bool = False,
        band_steering: bool = False,
        fast_roaming: bool = False,
        rate_limit_enabled: bool = False,
        rate_limit_up: int | None = None,
        rate_limit_down: int | None = None,
    ) -> WifiNetwork:
        """Create a new WiFi network."""
        existing = await self.get_by_ssid(ssid, organization_id)
        if existing:
            raise DuplicateError(f"WiFi network '{ssid}' already exists")

        network = WifiNetwork(
            site_id=site_id,
            ssid=ssid,
            security=security,
            password_hash=password_hash,
            vlan_id=vlan_id,
            hidden=hidden,
            enabled=enabled,
            band=band,
            client_isolation=client_isolation,
            band_steering=band_steering,
            fast_roaming=fast_roaming,
            rate_limit_enabled=rate_limit_enabled,
            rate_limit_up=rate_limit_up,
            rate_limit_down=rate_limit_down,
        )
        self.db.add(network)
        await self.db.commit()
        await self.db.refresh(network)
        logger.info("Created WiFi network '%s' for org %s", ssid, organization_id)
        await _emit(
            "network.wifi.created",
            ssid=ssid,
            wifi_uuid=str(network.id),
            site_id=str(site_id) if site_id else None,
            vlan_id=vlan_id,
            enabled=enabled,
        )
        return network

    async def update(
        self,
        wifi_id: UUID,
        organization_id: UUID,
        **updates,
    ) -> WifiNetwork:
        """Update a WiFi network."""
        network = await self.get(wifi_id, organization_id)
        for key, value in updates.items():
            if key in _WIFI_MUTABLE_FIELDS and value is not None and hasattr(network, key):
                setattr(network, key, value)
        await self.db.commit()
        await self.db.refresh(network)
        logger.info("Updated WiFi network '%s'", network.ssid)
        await _emit(
            "network.wifi.updated",
            ssid=network.ssid,
            wifi_uuid=str(network.id),
            site_id=str(network.site_id) if network.site_id else None,
            updated_fields=list(updates.keys()),
        )
        return network

    async def delete(self, wifi_id: UUID, organization_id: UUID) -> None:
        """Delete a WiFi network."""
        network = await self.get(wifi_id, organization_id)
        ssid = network.ssid
        site_id = network.site_id
        await self.db.delete(network)
        await self.db.commit()
        logger.info("Deleted WiFi network '%s'", ssid)
        await _emit(
            "network.wifi.deleted",
            ssid=ssid,
            wifi_uuid=str(wifi_id),
            site_id=str(site_id) if site_id else None,
        )

    async def toggle_enabled(
        self,
        wifi_id: UUID,
        organization_id: UUID,
        enabled: bool,
    ) -> WifiNetwork:
        """Enable or disable a WiFi network."""
        return await self.update(wifi_id, organization_id, enabled=enabled)


# ============================================================================
# Switch Port Service
# ============================================================================


class SwitchPortService:
    """Service for switch port management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------

    async def _verify_device_ownership(
        self, device_id: UUID, organization_id: UUID
    ) -> NetworkDevice:
        """Verify a device belongs to the given organization via its site."""
        result = await self.db.execute(
            select(NetworkDevice).where(
                NetworkDevice.id == device_id,
                NetworkDevice.site_id.in_(_sites_for_org(organization_id)),
            )
        )
        device = result.scalar_one_or_none()
        if not device:
            raise DeviceNotFoundError(f"Device {device_id} not found")
        return device

    async def list_by_device(
        self,
        device_id: UUID,
        organization_id: UUID,
    ) -> list[SwitchPort]:
        """List all ports on a device."""
        await self._verify_device_ownership(device_id, organization_id)
        result = await self.db.execute(
            select(SwitchPort)
            .where(SwitchPort.device_id == device_id)
            .order_by(SwitchPort.port_number)
        )
        return list(result.scalars().all())

    async def get(
        self,
        port_id: UUID,
        device_id: UUID,
        organization_id: UUID,
    ) -> SwitchPort:
        """Get a specific port."""
        await self._verify_device_ownership(device_id, organization_id)
        result = await self.db.execute(
            select(SwitchPort).where(
                SwitchPort.id == port_id,
                SwitchPort.device_id == device_id,
            )
        )
        port = result.scalar_one_or_none()
        if not port:
            raise PortNotFoundError(f"Port {port_id} not found")
        return port

    async def update(
        self,
        port_id: UUID,
        device_id: UUID,
        organization_id: UUID,
        **updates,
    ) -> SwitchPort:
        """Update a port configuration."""
        port = await self.get(port_id, device_id, organization_id)
        port_metadata = dict(port.port_metadata or {})
        tagged_vlans = updates.pop("tagged_vlans", None)

        for key, value in updates.items():
            if value is None:
                continue
            mapped_key = _PORT_FIELD_ALIASES.get(key, key)
            if mapped_key in _PORT_MUTABLE_FIELDS and hasattr(port, mapped_key):
                setattr(port, mapped_key, value)

        if tagged_vlans is not None:
            port_metadata["tagged_vlans"] = tagged_vlans
            port.port_metadata = port_metadata

        await self.db.commit()
        await self.db.refresh(port)
        logger.info("Updated port %s on device %s", port.port_number, device_id)
        return port

    async def set_poe(
        self,
        port_id: UUID,
        device_id: UUID,
        organization_id: UUID,
        enabled: bool,
    ) -> SwitchPort:
        """Enable or disable PoE on a port."""
        return await self.update(
            port_id,
            device_id,
            organization_id,
            is_poe_enabled=enabled,
        )

    async def set_enabled(
        self,
        port_id: UUID,
        device_id: UUID,
        organization_id: UUID,
        enabled: bool,
    ) -> SwitchPort:
        """Enable or disable a port."""
        return await self.update(
            port_id,
            device_id,
            organization_id,
            is_enabled=enabled,
        )

    async def set_vlan(
        self,
        port_id: UUID,
        device_id: UUID,
        organization_id: UUID,
        vlan_id: int | None = None,
        native_vlan: int | None = None,
        tagged_vlans: list[int] | None = None,
    ) -> SwitchPort:
        """Set port VLAN configuration."""
        effective_vlan_id = native_vlan if native_vlan is not None else vlan_id
        return await self.update(
            port_id,
            device_id,
            organization_id,
            vlan_id=effective_vlan_id,
            tagged_vlans=tagged_vlans,
        )


# ============================================================================
# Network Client Service
# ============================================================================


class NetworkClientService:
    """Service for network client management.

    DeviceClient has no ``site_id`` or ``organization_id``; it references
    its parent ``device_id`` → Device → site_id → Site → organization_id.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _org_scope(self, organization_id: UUID):
        """Subquery: device IDs belonging to an organization."""
        return (
            select(NetworkDevice.id)
            .where(NetworkDevice.site_id.in_(_sites_for_org(organization_id)))
            .scalar_subquery()
        )

    # ------------------------------------------------------------------

    async def list(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        is_online: bool | None = None,
        connection_type: str | None = None,
        blocked: bool | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 100,
        site_ids: set[UUID] | None = None,
    ) -> tuple[list[NetworkClient], int]:
        """List network clients.

        ``site_ids`` restricts the device set (and thus the
        clients) to a site-limited user's granted sites. None = no
        site-limit (org scope only).
        """
        if site_ids is not None:
            # Site-limited user: only clients on devices at granted sites.
            device_ids = (
                select(NetworkDevice.id)
                .where(NetworkDevice.site_id.in_(site_ids))
                .scalar_subquery()
            )
        elif site_id:
            # Narrow to devices at a specific site
            device_ids = (
                select(NetworkDevice.id).where(NetworkDevice.site_id == site_id).scalar_subquery()
            )
        else:
            device_ids = self._org_scope(organization_id)

        query = select(NetworkClient).where(NetworkClient.device_id.in_(device_ids))

        if is_online is not None:
            query = query.where(NetworkClient.is_online == is_online)

        if connection_type == "wired":
            query = query.where(NetworkClient.ssid.is_(None))
        elif connection_type == "wireless":
            query = query.where(NetworkClient.ssid.is_not(None))

        if blocked is not None:
            # ``blocked`` only exists in client_metadata once the block endpoint
            # has written it, so a client that was never blocked has NO key --
            # the JSONB expression is NULL, not False. ``is_(False)`` therefore
            # matched only clients that had been explicitly unblocked, and
            # filtering for "not blocked" returned almost nothing.
            metadata_filter = NetworkClient.client_metadata["blocked"].as_boolean()
            query = query.where(
                metadata_filter.is_(True)
                if blocked
                else or_(metadata_filter.is_(False), metadata_filter.is_(None))
            )

        if search:
            escaped = escape_like(search)
            pattern = f"%{escaped}%"
            query = query.where(
                (NetworkClient.mac_address.ilike(pattern, escape="\\"))
                | (NetworkClient.hostname.ilike(pattern, escape="\\"))
                | (NetworkClient.ip_address.ilike(pattern, escape="\\"))
            )

        count_query = select(func.count()).select_from(query.subquery())
        total = await self.db.scalar(count_query) or 0

        query = query.order_by(NetworkClient.last_seen.desc()).offset(skip).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all()), total

    async def get(self, client_id: UUID, organization_id: UUID) -> NetworkClient:
        """Get a client by ID."""
        result = await self.db.execute(
            select(NetworkClient).where(
                NetworkClient.id == client_id,
                NetworkClient.device_id.in_(self._org_scope(organization_id)),
            )
        )
        client = result.scalar_one_or_none()
        if not client:
            raise ClientNotFoundError(f"Client {client_id} not found")
        return client

    async def get_by_mac(
        self,
        mac_address: str,
        organization_id: UUID,
    ) -> NetworkClient | None:
        """Get a client by MAC address."""
        result = await self.db.execute(
            select(NetworkClient).where(
                NetworkClient.mac_address == mac_address.upper(),
                NetworkClient.device_id.in_(self._org_scope(organization_id)),
            )
        )
        return result.scalar_one_or_none()

    async def update(
        self,
        client_id: UUID,
        organization_id: UUID,
        **updates,
    ) -> NetworkClient:
        """Update a client."""
        client = await self.get(client_id, organization_id)
        client_metadata = dict(client.client_metadata or {})

        for key, value in updates.items():
            if value is None:
                continue
            if key in _CLIENT_MUTABLE_FIELDS and hasattr(client, key):
                setattr(client, key, value)
                continue
            if key == "display_name":
                client_metadata["display_name"] = value
                if not updates.get("hostname"):
                    client.hostname = value
                continue
            if key in {"blocked", "notes"}:
                client_metadata[key] = value

        if client_metadata != (client.client_metadata or {}):
            client.client_metadata = client_metadata

        await self.db.commit()
        await self.db.refresh(client)
        logger.info("Updated client %s", client.mac_address)
        return client

    async def block(self, client_id: UUID, organization_id: UUID) -> NetworkClient:
        """Mark a client as blocked."""
        return await self.update(client_id, organization_id, blocked=True)

    async def unblock(self, client_id: UUID, organization_id: UUID) -> NetworkClient:
        """Mark a client as unblocked."""
        return await self.update(client_id, organization_id, blocked=False)

    async def get_stats(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        site_ids: set[UUID] | None = None,
    ) -> dict[str, Any]:
        """Get client statistics.

        ``site_ids`` restricts the device set to a
        site-limited user's granted sites. None = no site-limit.
        """
        if site_ids is not None:
            device_ids = (
                select(NetworkDevice.id)
                .where(NetworkDevice.site_id.in_(site_ids))
                .scalar_subquery()
            )
        elif site_id:
            device_ids = (
                select(NetworkDevice.id).where(NetworkDevice.site_id == site_id).scalar_subquery()
            )
        else:
            device_ids = self._org_scope(organization_id)

        base = select(NetworkClient).where(NetworkClient.device_id.in_(device_ids))

        total = await self.db.scalar(select(func.count()).select_from(base.subquery())) or 0

        online_q = base.where(NetworkClient.is_online.is_(True))
        online = await self.db.scalar(select(func.count()).select_from(online_q.subquery())) or 0

        wired_q = base.where(NetworkClient.ssid.is_(None))
        wired = await self.db.scalar(select(func.count()).select_from(wired_q.subquery())) or 0

        wifi_q = base.where(NetworkClient.ssid.is_not(None))
        wifi = await self.db.scalar(select(func.count()).select_from(wifi_q.subquery())) or 0

        return {
            "total_clients": total,
            "online_clients": online,
            "wired_clients": wired,
            "wifi_clients": wifi,
            "offline_clients": total - online,
        }


# ============================================================================
# Network Device Service
# ============================================================================


class NetworkDeviceService:
    """Service for network device management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------

    async def list(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        device_type: str | None = None,
        status: str | None = None,
        skip: int = 0,
        limit: int = 100,
        site_ids: set[UUID] | None = None,
    ) -> tuple[list[NetworkDevice], int]:
        """List network devices.

        ``site_ids`` restricts results to a set of sites a
        site-limited user is granted — applied at the query level so the
        count stays accurate. None = no site-limit (org scope only).
        """
        query = select(NetworkDevice).where(
            NetworkDevice.site_id.in_(_sites_for_org(organization_id))
        )
        if site_ids is not None:
            query = query.where(NetworkDevice.site_id.in_(site_ids))
        if site_id:
            query = query.where(NetworkDevice.site_id == site_id)
        if device_type:
            query = query.where(NetworkDevice.device_type == device_type)
        if status:
            query = query.where(NetworkDevice.status == status)

        count_query = select(func.count()).select_from(query.subquery())
        total = await self.db.scalar(count_query) or 0

        query = (
            query.options(selectinload(NetworkDevice.ports))
            .order_by(NetworkDevice.name)
            .offset(skip)
            .limit(limit)
        )
        result = await self.db.execute(query)
        return list(result.scalars().unique().all()), total

    async def get(
        self,
        device_id: UUID,
        organization_id: UUID,
        site_ids: set[UUID] | None = None,
    ) -> NetworkDevice:
        """Get a device by ID.

        ``site_ids`` restricts to a site-limited user's
        granted sites — a device outside them reads as not-found.
        """
        query = (
            select(NetworkDevice)
            .options(selectinload(NetworkDevice.ports))
            .where(
                NetworkDevice.id == device_id,
                NetworkDevice.site_id.in_(_sites_for_org(organization_id)),
            )
        )
        if site_ids is not None:
            query = query.where(NetworkDevice.site_id.in_(site_ids))
        result = await self.db.execute(query)
        device = result.scalar_one_or_none()
        if not device:
            raise DeviceNotFoundError(f"Device {device_id} not found")
        return device

    async def get_stats(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        site_ids: set[UUID] | None = None,
    ) -> dict[str, Any]:
        """Get device statistics.

        ``site_ids`` restricts to a site-limited user's
        granted sites. None = no site-limit (org scope only).
        """
        base = select(NetworkDevice).where(
            NetworkDevice.site_id.in_(_sites_for_org(organization_id))
        )
        if site_ids is not None:
            base = base.where(NetworkDevice.site_id.in_(site_ids))
        if site_id:
            base = base.where(NetworkDevice.site_id == site_id)

        total = await self.db.scalar(select(func.count()).select_from(base.subquery())) or 0

        online_q = base.where(NetworkDevice.status == "online")
        online = await self.db.scalar(select(func.count()).select_from(online_q.subquery())) or 0

        type_stats: dict[str, int] = {}
        for dtype in ["switch", "router", "access_point", "gateway"]:
            tq = base.where(NetworkDevice.device_type == dtype)
            count = await self.db.scalar(select(func.count()).select_from(tq.subquery())) or 0
            type_stats[dtype] = count

        return {
            "total_devices": total,
            "online_devices": online,
            "offline_devices": total - online,
            "by_type": type_stats,
        }


# ============================================================================
# Topology Service
# ============================================================================


class TopologyService:
    """Service for network topology management."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------

    async def get_topology(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        site_ids: set[UUID] | None = None,
    ) -> dict[str, Any]:
        """Get network topology data (nodes + links).

        ``site_ids`` restricts the device set (nodes, and
        thus links) to a site-limited user's granted sites. None = no
        site-limit (org scope only).
        """
        # ---- devices (nodes) ----
        device_query = select(NetworkDevice).where(
            NetworkDevice.site_id.in_(_sites_for_org(organization_id))
        )
        if site_ids is not None:
            device_query = device_query.where(NetworkDevice.site_id.in_(site_ids))
        if site_id:
            device_query = device_query.where(NetworkDevice.site_id == site_id)

        result = await self.db.execute(device_query)
        devices = result.scalars().all()
        device_ids = {d.id for d in devices}

        # ---- links (edges) – scoped to discovered devices ----
        link_query = select(TopologyLink).where(
            TopologyLink.source_device_id.in_(device_ids)
            | TopologyLink.target_device_id.in_(device_ids)
        )
        result = await self.db.execute(link_query)
        links = result.scalars().all()

        nodes = [
            {
                "id": str(d.id),
                "name": d.name,
                "device_type": d.device_type,
                "ip_address": d.ip_address,
                "status": d.status,
                "model": d.model,
                "manufacturer": d.manufacturer,
            }
            for d in devices
        ]

        topology_links = [
            {
                "source": str(link.source_device_id),
                "target": str(link.target_device_id),
                "source_port": link.source_port,
                "target_port": link.target_port,
                "speed": link.speed,
                "status": link.status,
            }
            for link in links
        ]

        return {"nodes": nodes, "links": topology_links}


# ============================================================================
# Network Summary Service
# ============================================================================


class NetworkSummaryService:
    """Service for network summary statistics."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.device_service = NetworkDeviceService(db)
        self.client_service = NetworkClientService(db)
        self.vlan_service = VlanService(db)
        self.wifi_service = WifiNetworkService(db)

    async def get_summary(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        site_ids: set[UUID] | None = None,
    ) -> dict[str, Any]:
        """Get comprehensive network summary.

        ``site_ids`` restricts every aggregate to a
        site-limited user's granted sites by threading it into each
        sub-service. None = no site-limit (org scope only).
        """
        device_stats = await self.device_service.get_stats(
            organization_id, site_id, site_ids=site_ids
        )
        client_stats = await self.client_service.get_stats(
            organization_id, site_id, site_ids=site_ids
        )
        vlans, vlan_count = await self.vlan_service.list(
            organization_id, site_id, limit=0, site_ids=site_ids
        )
        wifi_networks, wifi_count = await self.wifi_service.list(
            organization_id, site_id, limit=0, site_ids=site_ids
        )

        return {
            "devices": device_stats,
            "clients": client_stats,
            "total_vlans": vlan_count,
            "total_wifi_networks": wifi_count,
        }

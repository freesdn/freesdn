# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Device Pydantic Schemas
=====================================

Request/Response schemas for device entities.
"""

import re
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.devices import ConnectionType, DeviceStatus, DeviceType

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")
_BARE_MAC_RE = re.compile(r"^[0-9A-Fa-f]{12}$")  # unseparated MAC like AABBCCDDEEFF
_IP4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
_IP6_RE = re.compile(r"^[0-9a-fA-F:]+$")  # lightweight check, max_length=45 caps it


# ===========================================
# Base Schemas
# ===========================================


class BaseSchema(BaseModel):
    """Base schema with common configuration."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


class TimestampSchema(BaseSchema):
    """Schema with timestamp fields."""

    created_at: datetime
    updated_at: datetime


# ===========================================
# Device Schemas
# ===========================================


class DeviceBase(BaseSchema):
    """Base device schema."""

    name: str = Field(min_length=1, max_length=255)
    device_type: DeviceType
    mac_address: str | None = Field(None, max_length=17)
    ip_address: str | None = Field(None, max_length=45)
    model: str | None = Field(None, max_length=100)
    manufacturer: str | None = Field(None, max_length=100)
    firmware_version: str | None = Field(None, max_length=50)
    location: str | None = Field(None, max_length=255)
    floor: str | None = Field(None, max_length=50)
    room: str | None = Field(None, max_length=100)

    @field_validator("mac_address")
    @classmethod
    def _validate_mac(cls, v: str | None) -> str | None:
        # Allow None or non-MAC identifiers (e.g. hypervisor hostnames like "proxmox-pve1")
        if v is None:
            return v
        # Reject unseparated 12-hex-char strings (should use separators)
        if _BARE_MAC_RE.match(v):
            raise ValueError("Invalid MAC address format (expected XX:XX:XX:XX:XX:XX)")
        # Reject colon-containing strings that don't match valid MAC pattern
        if ":" in v and not _MAC_RE.match(v):
            raise ValueError("Invalid MAC address format (expected XX:XX:XX:XX:XX:XX)")
        return v

    @field_validator("ip_address")
    @classmethod
    def _validate_ip(cls, v: str | None) -> str | None:
        if v is not None and not (_IP4_RE.match(v) or _IP6_RE.match(v)):
            raise ValueError("Invalid IP address format")
        return v


class DeviceCreate(DeviceBase):
    """Device creation schema (typically from controller sync)."""

    controller_id: UUID | None = None
    site_id: UUID
    serial_number: str | None = None
    external_id: str | None = None
    connection_type: ConnectionType | None = None
    vlan_id: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    capabilities: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mac_address")
    @classmethod
    def _validate_mac_strict(cls, v: str | None) -> str | None:
        """Strict MAC validation for device creation.

        Allows None and non-MAC identifiers (e.g. hypervisor hostnames like
        'PROXMOX-S1') while rejecting malformed MAC addresses (colon-separated
        strings that don't match XX:XX:XX:XX:XX:XX, and bare 12-hex-char
        strings without separators).
        """
        if v is None:
            return v
        # Reject unseparated 12-hex-char strings (should use separators)
        if _BARE_MAC_RE.match(v):
            raise ValueError("Invalid MAC address format (expected XX:XX:XX:XX:XX:XX)")
        # Reject colon-containing strings that don't match valid MAC pattern
        if ":" in v and not _MAC_RE.match(v):
            raise ValueError("Invalid MAC address format (expected XX:XX:XX:XX:XX:XX)")
        return v


class DeviceUpdate(BaseSchema):
    """Device update schema.

    Caps mirror the DB column widths (``devices.devices`` table) so
    payloads can't slip past pydantic into a psycopg
    StringDataRightTruncation 500. ``notes`` was unbounded and a 50 KB
    blob was 200'd into the column.
    """

    name: str | None = Field(None, min_length=1, max_length=255)
    location: str | None = Field(None, max_length=255)
    floor: str | None = Field(None, max_length=50)
    room: str | None = Field(None, max_length=100)
    notes: str | None = Field(None, max_length=10000)
    is_active: bool | None = None
    is_managed: bool | None = None
    # Operator escape-hatch: assign / change a credential after adoption
    # (e.g. an agent-discovered device that needs creds to be fully
    # manageable). Validated against the caller's org in the endpoint.
    credential_id: UUID | None = None


class DeviceResponse(DeviceBase, TimestampSchema):
    """Device response schema."""

    id: UUID
    controller_id: UUID | None = None
    credential_id: UUID | None = None
    driver_id: str | None = None
    discovery_method: str | None = None
    site_id: UUID
    serial_number: str | None
    external_id: str | None
    connection_type: ConnectionType | None
    vlan_id: int | None
    status: DeviceStatus
    last_seen: datetime | None
    uptime_seconds: int | None
    cpu_usage_percent: float | None
    memory_usage_percent: float | None
    is_active: bool
    is_managed: bool
    notes: str | None
    # Lifecycle FSM state (enterprise) — surfaced on the list so the
    # Lifecycle page reflects real state instead of defaulting every row
    # to "discovered". Columns live on the Device model.
    lifecycle_state: str = "discovered"
    lifecycle_changed_at: datetime | None = None
    lifecycle_error: str | None = None


class DeviceWithStats(DeviceResponse):
    """Device with detailed statistics."""

    port_count: int = 0
    active_port_count: int = 0
    client_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    capabilities: dict[str, Any] = Field(default_factory=dict)


class DeviceSummary(BaseSchema):
    """Minimal device summary for lists."""

    id: UUID
    name: str
    device_type: DeviceType
    status: DeviceStatus
    ip_address: str | None
    mac_address: str | None


# ===========================================
# Device Port Schemas
# ===========================================


class DevicePortBase(BaseSchema):
    """Base device port schema."""

    port_number: int
    name: str | None = None
    vlan_id: int | None = None
    is_enabled: bool = True
    is_poe_enabled: bool = False


class DevicePortResponse(DevicePortBase):
    """Device port response schema."""

    id: UUID
    device_id: UUID
    port_type: str
    status: str
    speed_mbps: int | None
    duplex: str | None
    poe_power_watts: float | None
    poe_class: int | None
    tx_bytes: int | None
    rx_bytes: int | None
    connected_mac: str | None


# ===========================================
# Device Client Schemas
# ===========================================


class DeviceClientBase(BaseSchema):
    """Base device client schema."""

    mac_address: str
    hostname: str | None = None
    ip_address: str | None = None


class DeviceClientResponse(DeviceClientBase):
    """Device client response schema."""

    id: UUID
    device_id: UUID
    ssid: str | None
    band: str | None
    channel: int | None
    signal_dbm: int | None
    connected_at: datetime | None
    last_seen: datetime | None
    is_online: bool
    tx_bytes: int | None
    rx_bytes: int | None
    tx_rate_mbps: float | None
    rx_rate_mbps: float | None


# ===========================================
# Statistics Schemas
# ===========================================


class DeviceStats(BaseSchema):
    """Device statistics summary."""

    total_devices: int = 0
    online_devices: int = 0
    offline_devices: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)


class SiteDeviceStats(BaseSchema):
    """Site-level device statistics."""

    site_id: UUID
    total_devices: int = 0
    online_devices: int = 0
    total_clients: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)

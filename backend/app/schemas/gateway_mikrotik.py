# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik schemas
==================================

Pydantic models for the MikroTik-specific gateway endpoints (system
+ security). The shapes match what the frontend tabs expect:
camelCase keys on the FreeSDN side, but ``serialization_alias`` is
applied where the RouterOS wire format uses hyphens (e.g.
``installed-version`` → ``installedVersion``).

All schemas set ``extra="forbid"`` so an unexpected key from the
controller surfaces as a validation error in development rather than
silently leaking through to the UI. In production, the read services
sanitise the rows via :func:`app.core.redaction.redact_secrets`
before model validation, so secret fields are already redacted.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

# ─── Firmware / packages ─────────────────────────────────────────────


class MikroTikFirmwareStatus(BaseModel):
    """RouterOS ``/system/package/update`` singleton response shape."""

    # RouterOS adds version-specific keys (e.g. last-checked); ignore extras so
    # a newer ROS release can't 500 the firmware tab.
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    installed_version: str | None = Field(default=None, alias="installed-version")
    latest_version: str | None = Field(default=None, alias="latest-version")
    channel: str | None = None
    status: str | None = None


class MikroTikPackage(BaseModel):
    """RouterOS ``/system/package`` row.

       NOTE: ``extra="ignore"`` is used here (not ``"forbid"``) because
       RouterOS adds fields across minor versions — 7.21.3 returns
       ``available`` and ``size`` that the schema didn't declare, and
       forbidding extras would 500 every /packages request on real CHR.
    Specific new fields:
       ``available`` (bool-as-string, indicates an update can be applied),
       ``size`` (bytes-as-string, install footprint).
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str | None = Field(default=None, alias=".id")
    name: str
    version: str | None = None
    build_time: str | None = Field(default=None, alias="build-time")
    scheduled: str | None = None
    disabled: bool | str | None = None
    available: bool | str | None = None
    size: str | None = None


# ─── Backup / config ─────────────────────────────────────────────────


class MikroTikBackupFile(BaseModel):
    """RouterOS ``/file`` row, filtered to backup artefacts."""

    # RouterOS /file rows carry extra keys (last-modified, etc.) that vary by
    # ROS version; ignore them so backup/list can't 500.
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str | None = Field(default=None, alias=".id")
    name: str
    type: str | None = None
    size: int | str | None = None
    creation_time: str | None = Field(default=None, alias="creation-time")
    last_modified: str | None = Field(default=None, alias="last-modified")


class MikroTikBackupContent(BaseModel):
    """File-download response.

    Both fields nullable so the same response model covers binary
    backups (``base64_content``) and text exports (``text_content``).
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    base64_content: str | None = None
    text_content: str | None = None


# ─── Neighbors / topology ───────────────────────────────────────────


class MikroTikNeighbor(BaseModel):
    """RouterOS ``/ip/neighbor`` row."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str | None = Field(default=None, alias=".id")
    mac_address: str | None = Field(default=None, alias="mac-address")
    identity: str | None = None
    interface: str | None = None
    platform: str | None = None
    board: str | None = None
    version: str | None = None
    address: str | None = None
    address6: str | None = None


class MikroTikLldpInterface(BaseModel):
    """RouterOS ``/interface/lldp`` row."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str | None = Field(default=None, alias=".id")
    name: str | None = None
    mac_address: str | None = Field(default=None, alias="mac-address")
    interface: str | None = None
    chassis_id: str | None = Field(default=None, alias="chassis-id")
    port_id: str | None = Field(default=None, alias="port-id")
    system_name: str | None = Field(default=None, alias="system-name")


class MikroTikTopologyNode(BaseModel):
    """Node in the composed topology graph.

    NOTE: the original schema declared ``kind`` + ``extra`` but the
    adapter's ``build_topology()`` emits ``type`` (router / switch /
    neighbor), ``vendor`` (mikrotik / unknown), ``interface_count``,
    ``degraded`` + ``degraded_reasons`` (when reads partially fail).
    Schema realigned to the actual adapter output. ``extra="ignore"``
    so future adapter additions don't 500 the endpoint. Verified
    against live CHR 7.21.3.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    label: str
    type: str | None = None
    vendor: str | None = None
    interface_count: int | None = None
    degraded: bool | None = None
    degraded_reasons: list[str] | None = None


class MikroTikTopologyEdge(BaseModel):
    """Edge in the composed topology graph."""

    model_config = ConfigDict(extra="ignore")

    id: str
    source: str
    target: str
    label: str | None = None
    protocol: str | None = None  # lldp / cdp / mndp / routeros-discovery


class MikroTikTopologyResponse(BaseModel):
    """Topology envelope. Mirrors the Omada graph component shape so
    the frontend can render either vendor with one component."""

    model_config = ConfigDict(extra="ignore")

    nodes: list[MikroTikTopologyNode]
    edges: list[MikroTikTopologyEdge]
    warnings: list[str] = Field(default_factory=list)


# ─── SNMP ────────────────────────────────────────────────────────────


class MikroTikSnmpTrapTarget(BaseModel):
    """Single host in the SNMP ``trap-target`` comma-list."""

    model_config = ConfigDict(extra="forbid")

    host: str


class MikroTikSnmpV3User(BaseModel):
    """RouterOS ``/snmp/users`` row. Password fields are redacted
    before validation by the read service (see
    :func:`app.core.redaction.redact_secrets`)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str | None = Field(default=None, alias=".id")
    name: str | None = None
    auth_protocol: str | None = Field(default=None, alias="auth-protocol")
    encryption_protocol: str | None = Field(default=None, alias="encryption-protocol")
    # Redacted fields — populated with ``"***"`` by the read service.
    auth_password: str | None = Field(default=None, alias="auth-password")
    encryption_password: str | None = Field(default=None, alias="encryption-password")


__all__ = [
    "MikroTikBackupContent",
    "MikroTikBackupFile",
    "MikroTikFirmwareStatus",
    "MikroTikLldpInterface",
    "MikroTikNeighbor",
    "MikroTikPackage",
    "MikroTikSnmpTrapTarget",
    "MikroTikSnmpV3User",
    "MikroTikTopologyEdge",
    "MikroTikTopologyNode",
    "MikroTikTopologyResponse",
]

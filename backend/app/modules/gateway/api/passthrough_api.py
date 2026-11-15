# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Passthrough Diagnostics API
=====================================================

Live diagnostic endpoints that proxy commands through to
gateway devices via adapters: ping, traceroute, DNS lookup,
backup, firmware info, and service restart.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.device_slot import gateway_slot_key
from app.db import get_session
from app.modules.gateway.adapter_helpers import build_adapter, get_gateway
from app.services.adapter_staging import AdapterStagingService
from app.services.device_writes import audited_device_action


def _refuse_in_read_only_mode() -> None:
    """Backup and service restart act on the gateway: refused in read-only
    mode before it is contacted, as GatewayService.device_action does."""
    if AdapterStagingService.is_read_only():
        raise HTTPException(403, detail="Read-only mode is on: gateway actions are refused.")


router = APIRouter(prefix="/diagnostics", tags=["Gateway Diagnostics"])


DbSession = Annotated[AsyncSession, Depends(get_session)]


def _org_id(user) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


# ── Request / Response models ───────────────────────────────────────────


class PingRequest(BaseModel):
    gateway_id: UUID
    target: str = Field(
        ...,
        min_length=1,
        max_length=253,
        pattern=r"^[a-zA-Z0-9.:\-]+$",
        description="Target IP or hostname (no spaces or special chars)",
    )
    count: int = Field(default=4, ge=1, le=20)


class TracerouteRequest(BaseModel):
    gateway_id: UUID
    target: str = Field(
        ...,
        min_length=1,
        max_length=253,
        pattern=r"^[a-zA-Z0-9.:\-]+$",
    )


class DNSLookupRequest(BaseModel):
    gateway_id: UUID
    hostname: str = Field(
        ...,
        min_length=1,
        max_length=253,
        pattern=r"^[a-zA-Z0-9.\-]+$",
    )
    record_type: str = Field(
        default="A",
        pattern=r"^(A|AAAA|CNAME|MX|TXT|NS|SOA|PTR|SRV)$",
    )


# Allowlisted service names that can be restarted
_ALLOWED_SERVICES = frozenset(
    {
        "unbound",
        "dhcpd",
        "openvpn",
        "ipsec",
        "suricata",
        "haproxy",
        "nginx",
        "ntpd",
        "syslogd",
        "dpinger",
        "configd",
        "squid",
        "dnsmasq",
    }
)


class ServiceRestartRequest(BaseModel):
    gateway_id: UUID
    service_name: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-]+$",
    )


# ── POST  /gateway/diagnostics/ping ─────────────────────────────────────


@router.post("/ping")
async def ping(
    body: PingRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.diagnostics"))],
    db: DbSession,
):
    """Execute a ping from the gateway device."""
    org_id = _org_id(current_user)
    gw = await get_gateway(db, body.gateway_id, organization_id=org_id, current_user=current_user)
    adapter = build_adapter(gw)
    async with adapter:
        result = await adapter.run_ping(body.target, count=body.count)
    if not result.success:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            result.error or "Ping failed",
        )
    return result.data


# ── POST  /gateway/diagnostics/traceroute ────────────────────────────────


@router.post("/traceroute")
async def traceroute(
    body: TracerouteRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.diagnostics"))],
    db: DbSession,
):
    """Execute a traceroute from the gateway device."""
    org_id = _org_id(current_user)
    gw = await get_gateway(db, body.gateway_id, organization_id=org_id, current_user=current_user)
    adapter = build_adapter(gw)
    async with adapter:
        result = await adapter.run_traceroute(body.target)
    if not result.success:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            result.error or "Traceroute failed",
        )
    return result.data


# ── POST  /gateway/diagnostics/dns-lookup ────────────────────────────────


@router.post("/dns-lookup")
async def dns_lookup(
    body: DNSLookupRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.diagnostics"))],
    db: DbSession,
):
    """Perform a DNS lookup from the gateway device."""
    org_id = _org_id(current_user)
    gw = await get_gateway(db, body.gateway_id, organization_id=org_id, current_user=current_user)
    adapter = build_adapter(gw)
    async with adapter:
        result = await adapter.run_dns_lookup(
            body.hostname,
            record_type=body.record_type,
        )
    if not result.success:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            result.error or "DNS lookup failed",
        )
    return result.data


# ── POST  /gateway/diagnostics/backup ────────────────────────────────────


@router.post("/backup")
async def trigger_backup(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.diagnostics"))],
    db: DbSession,
):
    """Trigger a configuration backup on the gateway."""
    org_id = _org_id(current_user)
    gw = await get_gateway(db, gateway_id, organization_id=org_id, current_user=current_user)
    _refuse_in_read_only_mode()
    adapter = build_adapter(gw)

    async def _backup():
        async with adapter:
            return await adapter.create_backup()

    result = await audited_device_action(
        db,
        action="create_backup",
        target_type="gateway",
        target_id=gw.id,
        target_name=getattr(gw, "name", None),
        organization_id=gw.org_id,
        site_id=gw.site_id,
        actor_id=current_user.id,
        parameters={},
        perform=_backup,
        slot_key=gateway_slot_key(gw),
    )
    if not result.success:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            result.error or "Backup failed",
        )
    return result.data


# ── GET  /gateway/diagnostics/firmware/{gateway_id} ─────────────────────


@router.get("/firmware/{gateway_id}")
async def get_firmware_info(
    gateway_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.diagnostics"))],
    db: DbSession,
):
    """Get firmware / version info from the gateway."""
    org_id = _org_id(current_user)
    gw = await get_gateway(db, gateway_id, organization_id=org_id, current_user=current_user)
    adapter = build_adapter(gw)
    async with adapter:
        result = await adapter.get_firmware_info()
    if not result.success:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            result.error or "Failed to retrieve firmware info",
        )
    return result.data


# ── POST  /gateway/diagnostics/restart-service ──────────────────────────


@router.post("/restart-service")
async def restart_service(
    body: ServiceRestartRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.diagnostics"))],
    db: DbSession,
):
    """Restart a named service on the gateway."""
    if body.service_name not in _ALLOWED_SERVICES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Service '{body.service_name}' is not in the allowlist. "
            f"Allowed: {', '.join(sorted(_ALLOWED_SERVICES))}",
        )
    org_id = _org_id(current_user)
    gw = await get_gateway(db, body.gateway_id, organization_id=org_id, current_user=current_user)
    _refuse_in_read_only_mode()
    adapter = build_adapter(gw)

    async def _restart():
        async with adapter:
            return await adapter.restart_service(body.service_name)

    result = await audited_device_action(
        db,
        action="restart_service",
        target_type="gateway",
        target_id=gw.id,
        target_name=getattr(gw, "name", None),
        organization_id=gw.org_id,
        site_id=gw.site_id,
        actor_id=current_user.id,
        parameters={"service": body.service_name},
        perform=_restart,
        slot_key=gateway_slot_key(gw),
    )
    if not result.success:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            result.error or "Service restart failed",
        )
    return result.data

# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OpenWrt endpoint.

URL layout::

    GET /api/v1/gateway-openwrt/{controller_id}/device-info
    GET /api/v1/gateway-openwrt/{controller_id}/interfaces
    GET /api/v1/gateway-openwrt/{controller_id}/firewall-rules
    GET /api/v1/gateway-openwrt/{controller_id}/port-forwards
    GET /api/v1/gateway-openwrt/{controller_id}/dhcp-leases
    GET /api/v1/gateway-openwrt/{controller_id}/dhcp-static-mappings
    GET /api/v1/gateway-openwrt/{controller_id}/arp-table
    GET /api/v1/gateway-openwrt/{controller_id}/summary

All endpoints are read-only in this commit. Writes / staged-change
plumbing for OpenWrt will land in follow-up commits (the underlying
adapter has full CRUD but the staged-apply registration is the part
that needs vendor-specific work).
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.services.adapter_openwrt import GatewayOpenWrtService

router = APIRouter(
    prefix="/gateway-openwrt",
    tags=["gateway-openwrt"],
)


@router.get("/{controller_id}/device-info")
async def get_device_info(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Device hostname, model, firmware version, uptime, memory, load."""
    svc = GatewayOpenWrtService(session)
    return await svc.get_device_info(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/interfaces")
async def list_interfaces(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Network interfaces with status + IPs."""
    svc = GatewayOpenWrtService(session)
    return await svc.list_interfaces(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/firewall-rules")
async def list_firewall_rules(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Firewall rules from UCI."""
    svc = GatewayOpenWrtService(session)
    return await svc.list_firewall_rules(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/port-forwards")
async def list_port_forwards(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Port forwards (UCI firewall.redirect sections)."""
    svc = GatewayOpenWrtService(session)
    return await svc.list_port_forwards(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/dhcp-leases")
async def list_dhcp_leases(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Active DHCP leases (v4 + v6)."""
    svc = GatewayOpenWrtService(session)
    return await svc.list_dhcp_leases(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/dhcp-static-mappings")
async def list_dhcp_static_mappings(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Static DHCP mappings (reservations)."""
    svc = GatewayOpenWrtService(session)
    return await svc.list_dhcp_static_mappings(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/arp-table")
async def list_arp_table(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Neighbor / ARP table."""
    svc = GatewayOpenWrtService(session)
    return await svc.list_arp_table(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )


@router.get("/{controller_id}/summary")
async def get_summary(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """One-shot dashboard rollup."""
    svc = GatewayOpenWrtService(session)
    return await svc.get_summary(
        controller_id,
        user.organization_id,
        is_superuser=user.is_superuser,
    )

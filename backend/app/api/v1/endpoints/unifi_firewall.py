# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — UniFi firewall + port-forwarding + VPN read endpoints.

URL layout::

    GET   /api/v1/unifi/{controller_id}/sites/{site}/firewall/rules
    GET   /api/v1/unifi/{controller_id}/sites/{site}/firewall/groups
    GET   /api/v1/unifi/{controller_id}/sites/{site}/firewall/port-forwards
    GET   /api/v1/unifi/{controller_id}/sites/{site}/firewall/radius-users
    GET   /api/v1/unifi/{controller_id}/sites/{site}/firewall/vpn-clients

Writes against firewall config are not yet implemented; only the read
surface is exposed, so operators can review existing configuration
through FreeSDN's tenant-scoped wrapper.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.adapters.unifi import UniFiAdapter
from app.api.v1.deps import CurrentUser, require_permissions
from app.api.v1.endpoints.unifi_deps import get_adapter_for_controller

router = APIRouter(prefix="/unifi", tags=["UniFi"])


class _ListResponse(BaseModel):
    site: str
    items: list[dict[str, Any]]
    count: int


@router.get(
    "/{controller_id}/sites/{site}/firewall/rules",
    response_model=_ListResponse,
    summary="List firewall rules at a site",
)
async def list_firewall_rules(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> _ListResponse:
    try:
        rules = await adapter.list_firewall_rules(site)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return _ListResponse(site=site, items=rules, count=len(rules))


@router.get(
    "/{controller_id}/sites/{site}/firewall/groups",
    response_model=_ListResponse,
    summary="List firewall address/port groups",
)
async def list_firewall_groups(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> _ListResponse:
    try:
        groups = await adapter.list_firewall_groups(site)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return _ListResponse(site=site, items=groups, count=len(groups))


@router.get(
    "/{controller_id}/sites/{site}/firewall/port-forwards",
    response_model=_ListResponse,
    summary="List port-forwarding (DNAT) rules",
)
async def list_port_forwards(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> _ListResponse:
    try:
        pfs = await adapter.list_port_forwards(site)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return _ListResponse(site=site, items=pfs, count=len(pfs))


@router.get(
    "/{controller_id}/sites/{site}/firewall/radius-users",
    response_model=_ListResponse,
    summary="List RADIUS accounts (per-user secret redacted)",
)
async def list_radius_users(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> _ListResponse:
    try:
        users = await adapter.list_radius_users(site)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return _ListResponse(site=site, items=users, count=len(users))


@router.get(
    "/{controller_id}/sites/{site}/firewall/vpn-clients",
    response_model=_ListResponse,
    summary="List currently-connected remote-user VPN sessions",
)
async def list_vpn_clients(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> _ListResponse:
    try:
        sessions = await adapter.list_vpn_clients(site)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return _ListResponse(site=site, items=sessions, count=len(sessions))

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — UniFi networks endpoints (VLANs / DHCP scopes).

URL layout::

    GET   /api/v1/unifi/{controller_id}/sites/{site}/networks
    GET   /api/v1/unifi/{controller_id}/sites/{site}/networks/{network_id}

Read-only; mutation endpoints are not yet implemented.
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


class UniFiNetworksResponse(BaseModel):
    site: str
    networks: list[dict[str, Any]]
    count: int


class UniFiNetworkResponse(BaseModel):
    site: str
    network_id: str
    network: dict[str, Any] | None


@router.get(
    "/{controller_id}/sites/{site}/networks",
    response_model=UniFiNetworksResponse,
    summary="List networks (VLANs / DHCP scopes) at a site",
)
async def list_networks(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiNetworksResponse:
    try:
        networks = await adapter.list_networks(site)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiNetworksResponse(
        site=site,
        networks=networks,
        count=len(networks),
    )


@router.get(
    "/{controller_id}/sites/{site}/networks/{network_id}",
    response_model=UniFiNetworkResponse,
    summary="Get one network by Mongo ObjectID",
)
async def get_network(
    controller_id: UUID,
    site: str,
    network_id: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiNetworkResponse:
    try:
        network = await adapter.get_network(site, network_id)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    # surface a clean 404 rather than 200 + ``network: null``.
    if network is None:
        raise HTTPException(
            404,
            detail=f"network {network_id} not found at site {site}",
        )
    return UniFiNetworkResponse(
        site=site,
        network_id=network_id,
        network=network,
    )

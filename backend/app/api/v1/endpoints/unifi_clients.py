# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — UniFi client (station) endpoints.

URL layout::

    GET   /api/v1/unifi/{controller_id}/sites/{site}/clients
    GET   /api/v1/unifi/{controller_id}/sites/{site}/clients/{mac}
    POST  /api/v1/unifi/{controller_id}/sites/{site}/clients/{mac}/block
    POST  /api/v1/unifi/{controller_id}/sites/{site}/clients/{mac}/unblock
    POST  /api/v1/unifi/{controller_id}/sites/{site}/clients/{mac}/forget

All write endpoints require ``site_admin`` (via ``require_min_role``)
and an explicit ``force=true`` in the body — the adapter refuses
the write unless ``ADAPTER_READ_ONLY=false`` is also set in env.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field

from app.adapters.unifi import UniFiAdapter
from app.api.v1.deps import CurrentUser, require_min_role, require_permissions
from app.api.v1.endpoints.unifi_deps import get_adapter_for_controller

router = APIRouter(prefix="/unifi", tags=["UniFi"])


class UniFiClientsResponse(BaseModel):
    site: str
    clients: list[dict[str, Any]]
    count: int


class UniFiClientResponse(BaseModel):
    site: str
    mac: str
    client: dict[str, Any] | None


class UniFiClientWriteResponse(BaseModel):
    success: bool = True
    action: str
    site: str
    mac: str
    detail: dict[str, Any] | None = None


class _ClientForceBody(BaseModel):
    force: bool = Field(False, description="Required + ADAPTER_READ_ONLY=false.")


@router.get(
    "/{controller_id}/sites/{site}/clients",
    response_model=UniFiClientsResponse,
    summary="List active clients at a site",
)
async def list_clients(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiClientsResponse:
    try:
        clients = await adapter.list_clients(site)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiClientsResponse(site=site, clients=clients, count=len(clients))


@router.get(
    "/{controller_id}/sites/{site}/clients/{mac}",
    response_model=UniFiClientResponse,
    summary="Look up one client by MAC",
)
async def get_client(
    controller_id: UUID,
    site: str,
    mac: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiClientResponse:
    try:
        client = await adapter.get_client(site, mac)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    # surface a clean 404 rather than 200 + ``client: null``.
    if client is None:
        raise HTTPException(404, detail=f"client {mac} not found at site {site}")
    return UniFiClientResponse(site=site, mac=mac, client=client)


@router.post(
    "/{controller_id}/sites/{site}/clients/{mac}/block",
    response_model=UniFiClientWriteResponse,
    summary="Block a client (dual-gated)",
)
async def block_client(
    controller_id: UUID,
    site: str,
    mac: str,
    body: Annotated[_ClientForceBody, Body()],
    user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiClientWriteResponse:
    try:
        detail = await adapter.block_client(site, mac, force=body.force)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiClientWriteResponse(
        action="block_client",
        site=site,
        mac=mac,
        detail=detail,
    )


@router.post(
    "/{controller_id}/sites/{site}/clients/{mac}/unblock",
    response_model=UniFiClientWriteResponse,
    summary="Unblock a previously-blocked client (dual-gated)",
)
async def unblock_client(
    controller_id: UUID,
    site: str,
    mac: str,
    body: Annotated[_ClientForceBody, Body()],
    user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiClientWriteResponse:
    try:
        detail = await adapter.unblock_client(site, mac, force=body.force)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiClientWriteResponse(
        action="unblock_client",
        site=site,
        mac=mac,
        detail=detail,
    )


@router.post(
    "/{controller_id}/sites/{site}/clients/{mac}/forget",
    response_model=UniFiClientWriteResponse,
    summary="Forget a client (clears historical record, dual-gated)",
)
async def forget_client(
    controller_id: UUID,
    site: str,
    mac: str,
    body: Annotated[_ClientForceBody, Body()],
    user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiClientWriteResponse:
    try:
        detail = await adapter.forget_client(site, mac, force=body.force)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiClientWriteResponse(
        action="forget_client",
        site=site,
        mac=mac,
        detail=detail,
    )

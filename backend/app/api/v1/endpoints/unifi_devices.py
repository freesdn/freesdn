# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — UniFi devices endpoints (switches / APs / gateways).

URL layout::

    GET   /api/v1/unifi/{controller_id}/sites/{site}/devices
    GET   /api/v1/unifi/{controller_id}/sites/{site}/devices/{mac}
    GET   /api/v1/unifi/{controller_id}/sites/{site}/devices/{mac}/port-overrides
    POST  /api/v1/unifi/{controller_id}/sites/{site}/devices/{mac}/restart
    POST  /api/v1/unifi/{controller_id}/sites/{site}/devices/{mac}/disable
    POST  /api/v1/unifi/{controller_id}/sites/{site}/devices/{mac}/ports/{port_idx}/profile
    POST  /api/v1/unifi/{controller_id}/sites/{site}/devices/{mac}/ports/{port_idx}/poe

All write endpoints require ``site_admin`` (via ``require_min_role``)
and explicit ``force=true`` in the body — the adapter refuses the
write unless ``ADAPTER_READ_ONLY=false`` is also set in env.
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


# ─────────────────────────────────────────────────────────────────────
# Response models
# ─────────────────────────────────────────────────────────────────────


class UniFiDevicesResponse(BaseModel):
    site: str
    devices: list[dict[str, Any]]
    count: int


class UniFiDeviceResponse(BaseModel):
    site: str
    mac: str
    device: dict[str, Any] | None


class UniFiPortOverridesResponse(BaseModel):
    site: str
    mac: str
    port_overrides: list[dict[str, Any]]


class UniFiWriteResponse(BaseModel):
    """Shared response shape for every write endpoint."""

    success: bool = True
    action: str
    site: str
    mac: str
    detail: dict[str, Any] | None = None


class _RestartBody(BaseModel):
    force: bool = Field(False, description="Required + ADAPTER_READ_ONLY=false.")


class _DisableBody(BaseModel):
    disabled: bool
    force: bool = False


class _PortProfileBody(BaseModel):
    profile_id: str = Field(..., description="Mongo ObjectID of the port profile.")
    force: bool = False


class _PortPoeBody(BaseModel):
    poe_mode: str = Field(
        ...,
        description="One of: auto, off, passive24, passthrough.",
    )
    force: bool = False


# ─────────────────────────────────────────────────────────────────────
# Reads
# ─────────────────────────────────────────────────────────────────────


@router.get(
    "/{controller_id}/sites/{site}/devices",
    response_model=UniFiDevicesResponse,
    summary="List adopted devices at a site",
)
async def list_devices(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiDevicesResponse:
    try:
        devices = await adapter.list_devices(site)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiDevicesResponse(site=site, devices=devices, count=len(devices))


@router.get(
    "/{controller_id}/sites/{site}/devices/{mac}",
    response_model=UniFiDeviceResponse,
    summary="Get one adopted device by MAC",
)
async def get_device(
    controller_id: UUID,
    site: str,
    mac: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiDeviceResponse:
    try:
        device = await adapter.get_device(site, mac)
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    # The adapter returns None when the controller has no such device.
    # Without this 404 conversion the endpoint
    # returned 200 with ``device: null``, forcing every caller to
    # null-check the body instead of catching a clean status. REST
    # convention is 404; align here.
    if device is None:
        raise HTTPException(404, detail=f"device {mac} not found at site {site}")
    return UniFiDeviceResponse(site=site, mac=mac, device=device)


@router.get(
    "/{controller_id}/sites/{site}/devices/{mac}/port-overrides",
    response_model=UniFiPortOverridesResponse,
    summary="Read port overrides for a switch",
)
async def list_port_overrides(
    controller_id: UUID,
    site: str,
    mac: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiPortOverridesResponse:
    try:
        # Verify the device exists before fetching overrides — the
        # adapter's ``list_port_overrides`` returned an empty list
        # for unknown MACs, indistinguishable from a real switch
        # with zero overrides — inconsistent with the 404
        # contract on the sibling lookup endpoints. Surface a clean
        # 404 here too.
        device = await adapter.get_device(site, mac)
        if device is None:
            raise HTTPException(
                404,
                detail=f"device {mac} not found at site {site}",
            )
        overrides = await adapter.list_port_overrides(site, mac)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiPortOverridesResponse(
        site=site,
        mac=mac,
        port_overrides=overrides,
    )


# ─────────────────────────────────────────────────────────────────────
# Writes — all gated on site_admin + force=True
# ─────────────────────────────────────────────────────────────────────


@router.post(
    "/{controller_id}/sites/{site}/devices/{mac}/restart",
    response_model=UniFiWriteResponse,
    summary="Reboot a device (dual-gated)",
)
async def restart_device(
    controller_id: UUID,
    site: str,
    mac: str,
    body: Annotated[_RestartBody, Body()],
    user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiWriteResponse:
    try:
        detail = await adapter.restart_device(site, mac, force=body.force)
    except Exception as exc:
        # ReadOnly + invalid-MAC + connection errors all funnel here.
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiWriteResponse(
        action="restart_device",
        site=site,
        mac=mac,
        detail=detail,
    )


@router.post(
    "/{controller_id}/sites/{site}/devices/{mac}/disable",
    response_model=UniFiWriteResponse,
    summary="Admin-disable / re-enable a device (dual-gated)",
)
async def disable_device(
    controller_id: UUID,
    site: str,
    mac: str,
    body: Annotated[_DisableBody, Body()],
    user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiWriteResponse:
    try:
        detail = await adapter.disable_device(
            site,
            mac,
            body.disabled,
            force=body.force,
        )
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiWriteResponse(
        action="disable_device",
        site=site,
        mac=mac,
        detail=detail,
    )


@router.post(
    "/{controller_id}/sites/{site}/devices/{mac}/ports/{port_idx}/profile",
    response_model=UniFiWriteResponse,
    summary="Apply a port profile to a switch port (dual-gated)",
)
async def update_port_profile(
    controller_id: UUID,
    site: str,
    mac: str,
    port_idx: int,
    body: Annotated[_PortProfileBody, Body()],
    user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiWriteResponse:
    try:
        detail = await adapter.update_port_override(
            site,
            mac,
            port_idx,
            body.profile_id,
            force=body.force,
        )
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiWriteResponse(
        action="update_port_override",
        site=site,
        mac=mac,
        detail=detail,
    )


@router.post(
    "/{controller_id}/sites/{site}/devices/{mac}/ports/{port_idx}/poe",
    response_model=UniFiWriteResponse,
    summary="Set PoE mode on a switch port (dual-gated)",
)
async def set_port_poe(
    controller_id: UUID,
    site: str,
    mac: str,
    port_idx: int,
    body: Annotated[_PortPoeBody, Body()],
    user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiWriteResponse:
    try:
        detail = await adapter.set_port_poe_on_site(
            site,
            mac,
            port_idx,
            body.poe_mode,
            force=body.force,
        )
    except Exception as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiWriteResponse(
        action="set_port_poe",
        site=site,
        mac=mac,
        detail=detail,
    )

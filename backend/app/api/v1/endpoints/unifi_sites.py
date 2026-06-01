# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — UniFi sites endpoints.

URL layout::

    GET   /api/v1/unifi/{controller_id}/sites
    GET   /api/v1/unifi/{controller_id}/sites/{site}/health

Every endpoint:
  * resolves the controller through :func:`_get_controller`
    (tenant-scoped — refuses controllers owned by another org)
  * builds an adapter via :func:`get_adapter_for_controller` which
    runs the SSRF guard on the controller host
  * declares an explicit ``response_model`` so the OpenAPI schema
    documents the (intentionally permissive) shape
  * returns redacted dicts straight from the adapter
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.adapters.unifi import UniFiAdapter
from app.api.v1.deps import CurrentUser, require_permissions
from app.api.v1.endpoints.unifi_deps import get_adapter_for_controller

router = APIRouter(prefix="/unifi", tags=["UniFi"])


# ─────────────────────────────────────────────────────────────────────
# Response models
# ─────────────────────────────────────────────────────────────────────


class UniFiSite(BaseModel):
    """A UniFi site visible to the authenticated controller account."""

    name: str = Field(..., description="Internal site slug (path segment).")
    desc: str | None = Field(default=None, description="Human-readable site name.")
    role: str | None = Field(default=None, description="Account role on the site.")
    site_id: str | None = Field(default=None, alias="_id")
    health: dict[str, Any] | None = Field(default=None)

    model_config = {"populate_by_name": True, "extra": "allow"}


class UniFiSitesResponse(BaseModel):
    sites: list[dict[str, Any]]
    count: int


class UniFiSiteHealthResponse(BaseModel):
    site: str
    subsystems: list[dict[str, Any]]


# ─────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────


@router.get(
    "/{controller_id}/sites",
    response_model=UniFiSitesResponse,
    summary="List sites on a UniFi controller",
)
async def list_sites(
    controller_id: UUID,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiSitesResponse:
    """Return every site visible to the controller's bound account."""
    try:
        sites = await adapter.list_sites()
    finally:
        await adapter.disconnect()
    return UniFiSitesResponse(sites=sites, count=len(sites))


@router.get(
    "/{controller_id}/sites/{site}/health",
    response_model=UniFiSiteHealthResponse,
    summary="Per-subsystem health summary for a site",
)
async def get_site_health(
    controller_id: UUID,
    site: str,
    user: Annotated[
        CurrentUser,
        Depends(require_permissions("controller:read")),
    ],
    adapter: Annotated[UniFiAdapter, Depends(get_adapter_for_controller)],
) -> UniFiSiteHealthResponse:
    """Health rollup across WAN / LAN / WLAN / VPN / WWW subsystems."""
    try:
        subsystems = await adapter.get_site_health(site)
    except Exception as exc:
        # validators raise AdapterError(400); rewrap to HTTPException.
        raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await adapter.disconnect()
    return UniFiSiteHealthResponse(site=site, subsystems=subsystems)

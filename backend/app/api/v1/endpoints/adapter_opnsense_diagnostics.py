# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Diagnostics endpoint.

URL layout::

    GET   /api/v1/gateway-opnsense-diagnostics/{controller_id}/logs?category=...&count=...
    GET   /api/v1/gateway-opnsense-diagnostics/{controller_id}/traffic
    GET   /api/v1/gateway-opnsense-diagnostics/{controller_id}/arp
    GET   /api/v1/gateway-opnsense-diagnostics/{controller_id}/ndp
    POST  /api/v1/gateway-opnsense-diagnostics/{controller_id}/ping
    POST  /api/v1/gateway-opnsense-diagnostics/{controller_id}/traceroute
    POST  /api/v1/gateway-opnsense-diagnostics/{controller_id}/dns-lookup

Reads run live. Probes (ping / traceroute / dns-lookup) POST to the
controller but are non-mutating — they trigger one-shot measurements.
We expose them as DIRECT endpoints (NOT staged) gated behind
``firewall:write`` so a reader can't probe arbitrary hosts from the
operator's network. Each probe still flows through the OPNsense client
which applies its universal ``ADAPTER_READ_ONLY`` gate, so the service
layer passes ``force=True`` to let the probe through.

There is no ``/changes/{feature}`` endpoint here: every diagnostic
operation is either a live read or a direct probe — nothing in this
module is genuinely state-changing, so the staging machinery would
just add latency and audit-log noise.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.validation import validate_id
from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.services.adapter_opnsense_diagnostics import (
    GatewayOpnsenseDiagnosticsService,
)

router = APIRouter(
    prefix="/gateway-opnsense-diagnostics",
    tags=["gateway-opnsense-diagnostics"],
)


# ── Probe request bodies ────────────────────────────────────────────────
#
# Tight bounds: hostnames cap at 253 chars (RFC 1035), counts at 10
# packets so a probe can't be turned into a low-grade DoS against an
# arbitrary host. The hostname is also re-validated by the OPNsense
# client's path-safety regex when it interpolates into the URL — the
# bounds here are the FreeSDN-edge defense.


class _PingRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    count: int = Field(default=3, ge=1, le=10)


class _TracerouteRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)


class _DnsLookupRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=253)


# ── Live reads ──────────────────────────────────────────────────────────


@router.get("/{controller_id}/logs")
async def get_logs(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    category: Annotated[Literal["system", "firewall"], Query()] = "system",
    count: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> Any:
    svc = GatewayOpnsenseDiagnosticsService(session)
    return await svc.get_logs(controller_id, user.organization_id, category, count)


@router.get("/{controller_id}/traffic")
async def get_traffic_stats(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseDiagnosticsService(session)
    return await svc.get_traffic_stats(controller_id, user.organization_id)


@router.get("/{controller_id}/arp")
async def get_arp_table(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseDiagnosticsService(session)
    return await svc.get_arp_table(controller_id, user.organization_id)


@router.get("/{controller_id}/ndp")
async def get_ndp_table(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseDiagnosticsService(session)
    return await svc.get_ndp_table(controller_id, user.organization_id)


# ── Direct probes (not staged) ──────────────────────────────────────────
#
# Gated behind ``firewall:write``: ping / traceroute can be used to
# enumerate the operator's internal network from the controller's
# vantage point, so a read-only viewer must not be able to fire them.


@router.post("/{controller_id}/ping")
async def ping(
    controller_id: UUID,
    body: _PingRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseDiagnosticsService(session)
    return await svc.ping(controller_id, user.organization_id, body.host, body.count)


@router.post("/{controller_id}/traceroute")
async def traceroute(
    controller_id: UUID,
    body: _TracerouteRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseDiagnosticsService(session)
    return await svc.traceroute(controller_id, user.organization_id, body.host)


@router.post("/{controller_id}/dns-lookup")
async def dns_lookup(
    controller_id: UUID,
    body: _DnsLookupRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # The hostname is interpolated into the OPNsense URL path for the
    # reverse-lookup endpoint. Validate it BEFORE the client sees it so
    # a path-traversal payload cannot reach the controller.
    hostname = validate_id(body.hostname, label="hostname")
    svc = GatewayOpnsenseDiagnosticsService(session)
    return await svc.dns_lookup(controller_id, user.organization_id, hostname)

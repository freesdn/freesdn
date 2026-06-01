# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Omada Open API auth endpoints
=======================================================

Wraps the OAuth2 client-credentials flow against the controller's
``/openapi/v1/...`` surface. The Open API is documented and stable
across controller upgrades, unlike the v2 web API the rest of the
adapter uses today. We expose it here so adapters can migrate
individual methods over progressively.

Tokens are NEVER persisted — every call performs the OAuth handshake
fresh. That keeps secrets out of our DB at the cost of a roundtrip;
real production deployments should store the resulting access token
in Redis with a short TTL.

URL layout::

    POST  /api/v1/gateway-openapi/{controller_id}/token
    POST  /api/v1/gateway-openapi/{controller_id}/refresh
    POST  /api/v1/gateway-openapi/{controller_id}/introspect
    GET   /api/v1/gateway-openapi/{controller_id}/sites
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db.session import get_session
from app.services.adapter_base import GatewayServiceBase

router = APIRouter(prefix="/gateway-openapi", tags=["gateway-openapi"])


class TokenRequest(BaseModel):
    client_id: str = Field(min_length=1, max_length=256)
    client_secret: str = Field(min_length=1, max_length=512)


class RefreshRequest(BaseModel):
    client_id: str
    client_secret: str
    refresh_token: str


class IntrospectRequest(BaseModel):
    access_token: str


class _OpenApiService(GatewayServiceBase):
    """Thin service wrapping the four bootstrap calls on the client."""


@router.post("/{controller_id}/token")
async def open_api_token(
    controller_id: UUID,
    body: TokenRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = _OpenApiService(session)
    ctrl = await svc._get_controller(controller_id, user.organization_id)
    client = await svc._get_client(ctrl)
    return await client.open_api_get_token(
        client_id=body.client_id, client_secret=body.client_secret
    )


@router.post("/{controller_id}/refresh")
async def open_api_refresh(
    controller_id: UUID,
    body: RefreshRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = _OpenApiService(session)
    ctrl = await svc._get_controller(controller_id, user.organization_id)
    client = await svc._get_client(ctrl)
    return await client.open_api_refresh_token(
        client_id=body.client_id,
        client_secret=body.client_secret,
        refresh_token=body.refresh_token,
    )


@router.post("/{controller_id}/introspect")
async def open_api_introspect(
    controller_id: UUID,
    body: IntrospectRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = _OpenApiService(session)
    ctrl = await svc._get_controller(controller_id, user.organization_id)
    client = await svc._get_client(ctrl)
    return await client.open_api_introspect(access_token=body.access_token)


@router.get("/{controller_id}/sites")
async def open_api_sites(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    authorization: Annotated[
        str | None,
        Header(
            alias="Authorization",
            description=(
                "Bearer token from /token call. Preferred over the legacy "
                "access_token query param, which leaks into access logs."
            ),
        ),
    ] = None,
    access_token: Annotated[
        str,
        # DEPRECATED: as a query param this lands in nginx access logs and the
        # request_id correlated trace. Pass the token in the Authorization
        # header (``Bearer <token>``) instead. Retained only for backward
        # compatibility; the length is bounded to limit its usefulness as a
        # credential channel.
        Query(
            description="DEPRECATED — use the Authorization header instead.",
            min_length=0,
            max_length=4096,
        ),
    ] = "",
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=500)] = 100,
) -> Any:
    # Prefer the Authorization header so the token stays out of access logs and
    # correlated traces. Fall back to the legacy query param if no header is
    # supplied, to avoid breaking existing callers.
    token = access_token
    if authorization:
        scheme, _, header_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not header_token.strip():
            raise HTTPException(
                status_code=401,
                detail="Authorization header must be of the form 'Bearer <token>'.",
            )
        token = header_token.strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing access token. Provide an 'Authorization: Bearer <token>' header.",
        )

    svc = _OpenApiService(session)
    ctrl = await svc._get_controller(controller_id, user.organization_id)
    client = await svc._get_client(ctrl)
    return await client.open_api_get_sites(access_token=token, page=page, page_size=page_size)

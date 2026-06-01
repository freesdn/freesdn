# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Shared gateway adapter construction helpers.
=============================================

Provides reusable helpers for building adapters from
``GatewayConnection`` records.  Used by gateway services,
passthrough endpoints, and the legacy firewall gateway API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import BaseAdapter
from app.adapters.registry import adapter_registry
from app.core.crypto import decrypt_dict
from app.core.site_access import assert_can_access_site
from app.modules.firewall.models import GatewayConnection

if TYPE_CHECKING:
    from app.core.dependencies import CurrentUser


async def get_gateway(
    db: AsyncSession,
    gateway_id: UUID,
    *,
    organization_id: UUID | None = None,
    current_user: CurrentUser | None = None,
) -> GatewayConnection:
    """
    Fetch a non-deleted ``GatewayConnection`` by ID, or raise *404*.

    When *organization_id* is supplied the gateway's owning site
    must belong to that organisation — otherwise a 404 is returned,
    preventing cross-tenant access.

    When *current_user* is supplied the per-user site grant is also
    enforced (no-op for super_admin / org_admin), so a site-limited
    user cannot reach a gateway in a sibling site of the same org.
    """
    q = select(GatewayConnection).where(
        GatewayConnection.id == gateway_id,
        GatewayConnection.deleted_at.is_(None),
    )
    if organization_id is not None:
        from app.models.core import Site

        org_sites = select(Site.id).where(Site.organization_id == organization_id).scalar_subquery()
        q = q.where(GatewayConnection.site_id.in_(org_sites))
    result = await db.execute(q)
    gw = result.scalar_one_or_none()
    if gw is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Gateway not found")
    if current_user is not None:
        assert_can_access_site(current_user, gw.site_id, detail="Gateway not found")
    return gw


def build_adapter(gw: GatewayConnection) -> BaseAdapter:
    """
    Create an adapter instance from a ``GatewayConnection``.

    Decrypts credentials and resolves the vendor-specific
    username / password mapping automatically.
    """
    creds = decrypt_dict(gw.credentials or {})
    if gw.vendor in ("opnsense", "pfsense"):
        username = creds.get("api_key", "")
        password = creds.get("api_secret", "")
    else:
        username = creds.get("username", "")
        password = creds.get("password", "")
    return adapter_registry.create_adapter(
        adapter_id=gw.vendor,
        host=gw.host,
        username=username,
        password=password,
        port=gw.port,
        verify_ssl=gw.verify_ssl,
        **gw.settings,
    )

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Config Versions API
==================================

REST endpoints for browsing, diffing, and rolling back
immutable config version snapshots.

Routes:
    GET  /devices/{device_id}/config-versions          - list versions
    GET  /config-versions/{version_id}                 - get version detail
    GET  /config-versions/{version_id}/diff/{other_id} - diff two versions
    POST /devices/{device_id}/config-versions/{version_id}/rollback
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.models.core import Site
from app.models.devices import Device
from app.services.config_versions import ConfigVersionService

logger = logging.getLogger(__name__)
router = APIRouter()


# =====================================================================
# Schemas
# =====================================================================


class ConfigVersionOut(BaseModel):
    id: str
    device_id: str
    organization_id: str | None = None
    version_number: int
    config_snapshot: dict[str, Any] = Field(default_factory=dict)
    change_summary: str | None = None
    source: str
    created_by: str | None = None
    created_at: datetime | None = None


class ConfigVersionListOut(BaseModel):
    id: str
    version_number: int
    change_summary: str | None = None
    source: str
    created_by: str | None = None
    created_at: datetime | None = None


class ConfigDiffOut(BaseModel):
    version_a: dict[str, Any]
    version_b: dict[str, Any]
    added: dict[str, Any] = Field(default_factory=dict)
    removed: dict[str, Any] = Field(default_factory=dict)
    changed: dict[str, Any] = Field(default_factory=dict)
    has_changes: bool = False
    unified_diff: str = ""


class RollbackOut(BaseModel):
    success: bool = True
    new_version_id: str
    new_version_number: int
    rolled_back_to: int


# =====================================================================
# Helpers
# =====================================================================


def _org_id(user: Any) -> Any:
    """Extract organization_id, raising 400 if missing."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


async def _device_site_id(session: AsyncSession, device_id: UUID) -> UUID | None:
    """Resolve the owning device's site_id for a config version.

       Config versions reference a device, and the per-user site grant
    is enforced on that device's site.
       The version's device may be soft-deleted; we still resolve its site
       so :func:`assert_can_access_site` can gate sibling-site access.
    """
    result = await session.execute(select(Device.site_id).where(Device.id == device_id))
    return result.scalar_one_or_none()


# =====================================================================
# Routes
# =====================================================================


@router.get(
    "/devices/{device_id}/config-versions",
    response_model=list[ConfigVersionListOut],
)
async def list_config_versions(
    device_id: UUID,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """List config versions for a device, newest first."""
    org_id = _org_id(_user)

    # Verify device belongs to user's org
    dev_q = select(Device).where(
        Device.id == device_id,
        Device.deleted_at.is_(None),
        Device.site_id.in_(
            select(Site.id).where(Site.organization_id == org_id, Site.deleted_at.is_(None))
        ),
    )
    result = await session.execute(dev_q)
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, detail="Device not found")

    # site-limited users only see versions from granted sites
    assert_can_access_site(_user, device.site_id, detail="Device not found")

    svc = ConfigVersionService(session)
    versions = await svc.list_versions(device_id, limit=limit, offset=offset)

    return [
        ConfigVersionListOut(
            id=str(v.id),
            version_number=v.version_number,
            change_summary=v.change_summary,
            source=v.source,
            created_by=str(v.created_by) if v.created_by else None,
            created_at=v.created_at,
        )
        for v in versions
    ]


@router.get(
    "/config-versions/{version_id}",
    response_model=ConfigVersionOut,
)
async def get_config_version(
    version_id: UUID,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Get full detail for a config version including the snapshot."""
    org_id = _org_id(_user)

    svc = ConfigVersionService(session)
    version = await svc.get_version(version_id)
    if not version:
        raise HTTPException(404, detail="Config version not found")

    # Verify org ownership
    if version.organization_id != org_id:
        raise HTTPException(404, detail="Config version not found")

    # enforce site grant for the version's device site
    site_id = await _device_site_id(session, version.device_id)
    assert_can_access_site(_user, site_id, detail="Config version not found")

    from app.core.redaction import redact_secrets  # redact secret-bearing config

    return ConfigVersionOut(
        id=str(version.id),
        device_id=str(version.device_id),
        organization_id=str(version.organization_id) if version.organization_id else None,
        version_number=version.version_number,
        config_snapshot=redact_secrets(version.config_snapshot or {}),
        change_summary=version.change_summary,
        source=version.source,
        created_by=str(version.created_by) if version.created_by else None,
        created_at=version.created_at,
    )


@router.get(
    "/config-versions/{version_id}/diff/{other_id}",
    response_model=ConfigDiffOut,
)
async def diff_config_versions(
    version_id: UUID,
    other_id: UUID,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:read")),
) -> Any:
    """Diff two config versions."""
    org_id = _org_id(_user)

    svc = ConfigVersionService(session)

    # Verify both versions belong to user's org
    version_a = await svc.get_version(version_id)
    version_b = await svc.get_version(other_id)

    if not version_a or version_a.organization_id != org_id:
        raise HTTPException(404, detail="Config version not found")
    if not version_b or version_b.organization_id != org_id:
        raise HTTPException(404, detail="Config version not found")

    # verify site grant for both versions' devices
    site_a = await _device_site_id(session, version_a.device_id)
    assert_can_access_site(_user, site_a, detail="Config version not found")
    site_b = await _device_site_id(session, version_b.device_id)
    assert_can_access_site(_user, site_b, detail="Config version not found")

    try:
        diff_result = await svc.diff_versions(version_id, other_id)
    except ValueError as e:
        logger.error("Config version diff failed: %s", e, exc_info=True)
        raise HTTPException(404, detail="Configuration version not found")

    return ConfigDiffOut(**diff_result)


@router.post(
    "/devices/{device_id}/config-versions/{version_id}/rollback",
    response_model=RollbackOut,
)
async def rollback_config_version(
    device_id: UUID,
    version_id: UUID,
    session: AsyncSession = Depends(get_session),
    _user: CurrentUser = Depends(require_permissions("config:write")),
) -> Any:
    """Rollback a device to a previous config version."""
    org_id = _org_id(_user)

    # Verify device belongs to user's org
    dev_q = (
        select(Device)
        .options(selectinload(Device.controller))
        .where(
            Device.id == device_id,
            Device.deleted_at.is_(None),
            Device.site_id.in_(
                select(Site.id).where(Site.organization_id == org_id, Site.deleted_at.is_(None))
            ),
        )
    )
    result = await session.execute(dev_q)
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, detail="Device not found")

    # Verify version exists and belongs to this device
    svc = ConfigVersionService(session)
    target_version = await svc.get_version(version_id)
    if not target_version or target_version.device_id != device_id:
        raise HTTPException(404, detail="Config version not found for this device")

    if target_version.organization_id != org_id:
        raise HTTPException(404, detail="Config version not found")

    # verify site grant for the device's site
    assert_can_access_site(_user, device.site_id, detail="Device not found")

    # Get adapter for the device
    if not device.controller:
        raise HTTPException(400, detail="Device has no controller for rollback")

    from app.api.v1.endpoints.poe import _get_adapter_for_device

    try:
        adapter = await _get_adapter_for_device(device)
    except HTTPException:
        raise HTTPException(400, detail="Unable to get adapter for device")

    try:
        new_version = await svc.rollback(
            device_id=device_id,
            version_id=version_id,
            adapter=adapter,
            session=session,
            user_id=_user.id,
        )
    except ValueError as e:
        logger.error("Rollback version lookup failed: %s", e, exc_info=True)
        raise HTTPException(404, detail="Configuration version not found")
    except RuntimeError as e:
        logger.error("Rollback failed for device %s version %s: %s", device_id, version_id, e)
        raise HTTPException(502, detail="Rollback failed: unable to push config to device")

    return RollbackOut(
        success=True,
        new_version_id=str(new_version.id),
        new_version_number=new_version.version_number,
        rolled_back_to=target_version.version_number,
    )

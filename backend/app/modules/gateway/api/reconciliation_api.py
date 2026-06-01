# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Reconciliation API
=============================================

Endpoints for importing VLAN config from brain devices,
checking alignment across brain + limbs, and distributing
canonical VLANs to limb devices.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.modules.gateway.services.reconciliation_service import (
    ReconciliationService,
)
from app.modules.gateway.services.role_map_service import RoleMapService

router = APIRouter(prefix="/reconciliation", tags=["Gateway Reconciliation"])


# ── Helpers ──────────────────────────────────────────────────────────────


def _org_id(user) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _svc(session: Annotated[AsyncSession, Depends(get_session)]) -> ReconciliationService:
    return ReconciliationService(session)


def _roles(session: Annotated[AsyncSession, Depends(get_session)]) -> RoleMapService:
    return RoleMapService(session)


# ── Request / Response schemas ───────────────────────────────────────────


import logging

logger = logging.getLogger(__name__)


class ImportRequest(BaseModel):
    dry_run: bool = False


class ImportResponse(BaseModel):
    created: int
    updated: int
    unchanged: int
    errors: list[str]
    vlans: list[dict[str, Any]]


class AlignmentItemResponse(BaseModel):
    vlan_id: int
    vlan_name: str
    canonical_vlan_uuid: str | None = None
    device_id: str | None = None
    device_type: str
    device_role: str
    status: str
    details: dict[str, Any] = Field(default_factory=dict)


class AlignmentResponse(BaseModel):
    site_id: str
    total_vlans: int
    aligned: int
    missing: int
    modified: int
    extra: int
    # ``errored``: devices that were unreachable during alignment.
    # Distinct from ``missing`` so a UI can render "Device offline"
    # rather than inflate the drift count.
    errored: int = 0
    score: float
    items: list[AlignmentItemResponse]
    errors: list[str]


class DistributeRequest(BaseModel):
    # 512 covers any realistic site (802.1Q caps at 4094 VLAN IDs and
    # most sites use a small fraction); rejects 10 000-element
    # payloads that would otherwise drive an O(limbs × vlans) loop.
    vlan_ids: list[int] | None = Field(default=None, max_length=512)
    dry_run: bool = False


class DistributeResponse(BaseModel):
    distributed: int
    skipped: int
    failed: int
    details: list[dict[str, Any]]
    errors: list[str]


# ── POST  /gateway/reconciliation/{site_id}/import ──────────────────────


@router.post("/{site_id}/import", response_model=ImportResponse)
async def import_from_brain(
    site_id: UUID,
    body: ImportRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.import"))],
    svc: Annotated[ReconciliationService, Depends(_svc)],
    roles: Annotated[RoleMapService, Depends(_roles)],
):
    """
    Import VLAN interfaces from the brain device into canonical VLANs.

    Set ``dry_run=true`` to preview what would be imported without persisting.
    """
    org_id = _org_id(current_user)
    assert_can_access_site(current_user, site_id)
    role_map = await roles.get_role_map(site_id, org_id=org_id)
    if role_map is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No role map for this site")

    try:
        result = await svc.import_from_brain(
            role_map,
            org_id=org_id,
            dry_run=body.dry_run,
        )
    except Exception as exc:
        # ``str(exc)`` from adapter layers carries controller URLs,
        # response bodies, and SQL fragments — exposing them via the
        # 500 detail leaked credentials embedded in gateway URLs to
        # any operator with ``gateway.import``. Log the full
        # exception, surface only the type name to the client.
        logger.exception("import_from_brain failed for site %s", site_id)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Import failed: {type(exc).__name__}",
        )

    return ImportResponse(**asdict(result))


# ── GET  /gateway/reconciliation/{site_id}/alignment ─────────────────────


@router.get("/{site_id}/alignment", response_model=AlignmentResponse)
async def check_alignment(
    site_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.view"))],
    svc: Annotated[ReconciliationService, Depends(_svc)],
    roles: Annotated[RoleMapService, Depends(_roles)],
):
    """
    Check VLAN alignment between canonical state and actual device state
    across all brain + limb devices at this site.
    """
    org_id = _org_id(current_user)
    assert_can_access_site(current_user, site_id)
    role_map = await roles.get_role_map(site_id, org_id=org_id)
    if role_map is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No role map for this site")

    try:
        report = await svc.check_alignment(role_map, org_id=org_id)
    except Exception as exc:
        logger.exception("check_alignment failed for site %s", site_id)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Alignment check failed: {type(exc).__name__}",
        )

    return AlignmentResponse(
        site_id=str(report.site_id),
        total_vlans=report.total_vlans,
        aligned=report.aligned,
        missing=report.missing,
        modified=report.modified,
        extra=report.extra,
        errored=report.errored,
        score=report.score,
        items=[
            AlignmentItemResponse(
                vlan_id=i.vlan_id,
                vlan_name=i.vlan_name,
                canonical_vlan_uuid=str(i.canonical_vlan_uuid) if i.canonical_vlan_uuid else None,
                device_id=str(i.device_id) if i.device_id else None,
                device_type=i.device_type,
                device_role=i.device_role,
                status=i.status,
                details=i.details,
            )
            for i in report.items
        ],
        errors=report.errors,
    )


# ── POST  /gateway/reconciliation/{site_id}/distribute ──────────────────


@router.post("/{site_id}/distribute", response_model=DistributeResponse)
async def distribute_to_limbs(
    site_id: UUID,
    body: DistributeRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.distribute"))],
    svc: Annotated[ReconciliationService, Depends(_svc)],
    roles: Annotated[RoleMapService, Depends(_roles)],
):
    """
    Distribute canonical VLANs (L2 only) to all limb devices.

    Optionally specify ``vlan_ids`` to distribute only specific VLANs.
    Set ``dry_run=true`` to preview what would be pushed.
    """
    org_id = _org_id(current_user)
    assert_can_access_site(current_user, site_id)
    role_map = await roles.get_role_map(site_id, org_id=org_id)
    if role_map is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No role map for this site")

    try:
        result = await svc.distribute_to_limbs(
            role_map,
            org_id=org_id,
            vlan_ids=body.vlan_ids,
            dry_run=body.dry_run,
        )
    except Exception as exc:
        logger.exception("distribute_to_limbs failed for site %s", site_id)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Distribution failed: {type(exc).__name__}",
        )

    return DistributeResponse(**asdict(result))

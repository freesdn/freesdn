# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Gateway Orchestration — Import Wizard API
==========================================

Endpoints for the brownfield import wizard (6-step state machine).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.db import get_session
from app.modules.gateway.schemas import (
    ImportSessionCreate,
    ImportSessionResponse,
    ImportSessionStep,
)
from app.modules.gateway.services.import_service import ImportService

router = APIRouter(prefix="/import", tags=["Gateway Import Wizard"])


def _org_id(user) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _svc(session: Annotated[AsyncSession, Depends(get_session)]) -> ImportService:
    return ImportService(session)


# ── GET  /gateway/import/sessions ───────────────────────────────────────


@router.get("/sessions", response_model=list[ImportSessionResponse])
async def list_sessions(
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.import"))],
    svc: Annotated[ImportService, Depends(_svc)],
    site_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List import sessions, optionally filtered by site."""
    from sqlalchemy import select

    from app.modules.gateway.models import ImportSession

    org_id = _org_id(current_user)
    if site_id:
        assert_can_access_site(current_user, site_id)
    stmt = (
        select(ImportSession)
        .where(
            ImportSession.organization_id == org_id,
            site_scope_filter(current_user, ImportSession.site_id),
        )
        .order_by(ImportSession.created_at.desc())
    )
    if site_id:
        stmt = stmt.where(ImportSession.site_id == site_id)
    stmt = stmt.limit(limit).offset(offset)
    result = await svc.db.execute(stmt)
    sessions = result.scalars().all()
    return [ImportSessionResponse.model_validate(s) for s in sessions]


# ── POST  /gateway/import/start ─────────────────────────────────────────


@router.post(
    "/start",
    response_model=ImportSessionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def start_import(
    body: ImportSessionCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.import"))],
    svc: Annotated[ImportService, Depends(_svc)],
):
    """Start a new import session — discover devices at the site."""
    org_id = _org_id(current_user)
    assert_can_access_site(current_user, body.site_id)
    session = await svc.start_session(
        org_id=org_id,
        site_id=body.site_id,
        initiated_by=current_user.id,
    )
    return ImportSessionResponse.model_validate(session)


# ── GET  /gateway/import/{session_id} ───────────────────────────────────


@router.get("/{session_id}", response_model=ImportSessionResponse)
async def get_import_session(
    session_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.import"))],
    svc: Annotated[ImportService, Depends(_svc)],
):
    """Get current import session state."""
    org_id = _org_id(current_user)
    session = await svc.get_session(session_id, org_id=org_id)
    assert_can_access_site(current_user, session.site_id, detail="Import session not found")
    return ImportSessionResponse.model_validate(session)


# ── POST  /gateway/import/{session_id}/step ─────────────────────────────


@router.post("/{session_id}/step", response_model=ImportSessionResponse)
async def advance_step(
    session_id: UUID,
    body: ImportSessionStep,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.import"))],
    svc: Annotated[ImportService, Depends(_svc)],
):
    """Advance to the next wizard step.

    The payload varies by step:
    - Step 2-3 (roles): ``{"roles": {"<gw_id>": "brain"}}``
    - Step 4-6 (reconciliation): ``{"decisions": {"<resource_id>": "adopt"}}``
    """
    org_id = _org_id(current_user)
    session = await svc.get_session(session_id, org_id=org_id)
    assert_can_access_site(current_user, session.site_id, detail="Import session not found")

    if session.current_step == 2:
        # Submit role assignments — convert {gw_id: role} dict to list
        roles_dict = body.payload.get("roles", {})
        if not isinstance(roles_dict, dict):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "roles must be a dict")
        assignments = [{"gateway_id": gw_id, "role": role} for gw_id, role in roles_dict.items()]
        session = await svc.submit_roles(session_id, assignments, org_id=org_id)
    elif session.current_step == 4:
        # Submit reconciliation decisions
        decisions = body.payload.get("decisions", {})
        if not isinstance(decisions, dict):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "decisions must be a dict")
        # SECURITY: validate decision values against allowed enum
        _ALLOWED_DECISIONS = {"adopt", "skip", "merge", "ignore"}
        for resource_id, decision in decisions.items():
            if decision not in _ALLOWED_DECISIONS:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    f"Invalid decision '{decision}' for resource '{resource_id}'. "
                    f"Allowed: {', '.join(sorted(_ALLOWED_DECISIONS))}",
                )
        session = await svc.submit_reconciliation(session_id, decisions, org_id=org_id)
    else:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Session is on step {session.current_step} — cannot advance",
        )

    return ImportSessionResponse.model_validate(session)


# ── POST  /gateway/import/{session_id}/cancel ───────────────────────────


@router.post("/{session_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_import(
    session_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("gateway.import"))],
    svc: Annotated[ImportService, Depends(_svc)],
):
    """Cancel an in-progress import session."""
    org_id = _org_id(current_user)
    session = await svc.get_session(session_id, org_id=org_id)
    assert_can_access_site(current_user, session.site_id, detail="Import session not found")
    await svc.cancel_session(session_id, org_id=org_id)

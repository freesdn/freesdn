# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Access Control Module API Endpoints
=================================================

REST API endpoints for access control management.

NOTE (C3): All write endpoints accept explicit Pydantic schemas defined
in ``schemas.py``. The previous ``dict[str, Any]`` bodies allowed any
caller-supplied field through to the ORM, enabling mass-assignment
attacks (most importantly, supplying ``site_id`` or ``controller_id``
belonging to another tenant). The service layer also re-validates FKs
against the caller's organization.
"""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_permissions
from app.db import get_session
from app.modules.access_control.schemas import (
    AccessCredentialListResponse,
    AccessCredentialResponse,
    CardholderCreate,
    CardholderUpdate,
    ControllerCreate,
    ControllerUpdate,
    CredentialCreate,
    CredentialUpdate,
    DoorCreate,
    DoorUpdate,
    ScheduleCreate,
    ScheduleUpdate,
)
from app.modules.access_control.service import (
    AccessControlError,
    AccessControllerNotFoundError,
    AccessControlService,
    CardholderNotFoundError,
    CredentialNotFoundError,
    CrossTenantError,
    DoorControlUnavailableError,
    DoorNotFoundError,
    EventNotFoundError,
    ScheduleNotFoundError,
)

router = APIRouter(prefix="/access", tags=["Access Control"])


def _org_id(user: CurrentUser) -> UUID:
    """Extract and validate organization_id from the current user."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(status_code=400, detail="Organization context required")
    return oid  # type: ignore[no-any-return]


def _get_service(session: AsyncSession, user: CurrentUser) -> AccessControlService:
    """Build an AccessControlService scoped to the user's organization (+ site grants)."""
    return AccessControlService(
        db=session,
        organization_id=_org_id(user),
        accessible_site_ids=(
            user.accessible_site_ids if getattr(user, "is_site_limited", False) else None
        ),
    )


def _xtenant_to_403(exc: CrossTenantError) -> HTTPException:
    """Convert a CrossTenantError to a 403 with a generic message.

    We deliberately don't echo the offending ID back — that would leak
    confirmation that the ID exists somewhere in the system.
    """
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Resource is not in your organization",
    )


# =============================================================================
# Door Endpoints
# =============================================================================


@router.get("/doors")
async def list_doors(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
    controller_id: UUID | None = None,
    door_status: str | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Any:
    """List all doors with optional filters."""
    service = _get_service(session, current_user)
    doors, total = await service.list_doors(
        site_id=site_id,
        controller_id=controller_id,
        status=door_status,
        limit=limit,
        offset=offset,
    )
    return {"items": doors, "total": total}


@router.get("/doors/stats")
async def get_door_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
) -> Any:
    """Get door statistics."""
    service = _get_service(session, current_user)
    return await service.get_door_stats(site_id=site_id)


@router.get("/doors/{door_id}")
async def get_door(
    door_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a door by ID."""
    service = _get_service(session, current_user)
    try:
        return await service.get_door(door_id)
    except DoorNotFoundError:
        raise HTTPException(status_code=404, detail="Door not found")


@router.post("/doors", status_code=status.HTTP_201_CREATED)
async def create_door(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_doors"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    body: DoorCreate = Body(...),
) -> Any:
    """Create a new door."""
    service = _get_service(session, current_user)
    try:
        return await service.create_door(body.model_dump(exclude_unset=False))
    except CrossTenantError as exc:
        raise _xtenant_to_403(exc)


@router.patch("/doors/{door_id}")
async def update_door(
    door_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_doors"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    body: DoorUpdate = Body(...),
) -> Any:
    """Update a door."""
    service = _get_service(session, current_user)
    try:
        return await service.update_door(door_id, body.model_dump(exclude_unset=True))
    except DoorNotFoundError:
        raise HTTPException(status_code=404, detail="Door not found")
    except CrossTenantError as exc:
        raise _xtenant_to_403(exc)


@router.delete("/doors/{door_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_door(
    door_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_doors"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a door."""
    service = _get_service(session, current_user)
    try:
        await service.delete_door(door_id)
    except DoorNotFoundError:
        raise HTTPException(status_code=404, detail="Door not found")


# =============================================================================
# Door Control Endpoints
# =============================================================================


@router.post("/doors/{door_id}/lock")
async def lock_door(
    door_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.door_control"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Lock a door remotely.

    NOTE (C4): Returns HTTP 501 if no hardware adapter is registered.
    Audit log: writes an AccessEvent of type ``remote_lock`` with
    the calling user's id and the door_id (forensic requirement).
    """
    service = _get_service(session, current_user)
    try:
        # a site-limited operator must not control doors at sites
        # outside their UserSiteAccess grant. get_door is org-scoped; this adds
        # the per-user site-containment check the broadcast/REST model enforces.
        door = await service.get_door(door_id)
        if current_user.is_site_limited and not current_user.can_access_site(door.site_id):
            raise HTTPException(status_code=404, detail="Door not found")
        # Pass actor_id so the audit event records who issued the command.
        return await service.lock_door(door_id, actor_id=current_user.id)
    except DoorNotFoundError:
        raise HTTPException(status_code=404, detail="Door not found")
    except DoorControlUnavailableError:
        # Don't leak internal adapter messages — fixed 501 + generic.
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Door control adapter not available",
        )
    except AccessControlError as exc:
        # URL-strip adapter exception text before surfacing — vendor
        # adapter errors may embed full controller URLs incl. auth.
        import re as _re

        safe = _re.sub(r"https?://\S+", "<redacted-url>", str(exc))[:300]
        raise HTTPException(status_code=502, detail=safe)


@router.post("/doors/{door_id}/unlock")
async def unlock_door(
    door_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.door_control"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    duration: int | None = Query(None, ge=1, le=300, description="Unlock duration in seconds"),
) -> Any:
    """Unlock a door remotely.

    NOTE: Returns HTTP 501 if no hardware adapter is registered.
    Audit log: writes an AccessEvent of type ``remote_unlock`` with
    the calling user's id, the door_id, and the duration (a forensic
    record of who unlocked which door).
    """
    service = _get_service(session, current_user)
    try:
        # per-user site containment for physical door control.
        door = await service.get_door(door_id)
        if current_user.is_site_limited and not current_user.can_access_site(door.site_id):
            raise HTTPException(status_code=404, detail="Door not found")
        return await service.unlock_door(door_id, duration, actor_id=current_user.id)
    except DoorNotFoundError:
        raise HTTPException(status_code=404, detail="Door not found")
    except DoorControlUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Door control adapter not available",
        )
    except AccessControlError as exc:
        import re as _re

        safe = _re.sub(r"https?://\S+", "<redacted-url>", str(exc))[:300]
        raise HTTPException(status_code=502, detail=safe)


# =============================================================================
# Credential Endpoints
# =============================================================================


@router.get("/credentials", response_model=AccessCredentialListResponse)
async def list_credentials(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    cardholder_id: UUID | None = None,
    credential_type: str | None = None,
    is_active: bool | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Any:
    """List credentials.

    response_model strips the Argon2id pin hash + Fernet
    card/facility ciphertext that raw-ORM serialization previously leaked.
    """
    service = _get_service(session, current_user)
    credentials, total = await service.list_credentials(
        cardholder_id=cardholder_id,
        credential_type=credential_type,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )
    return {"items": credentials, "total": total}


@router.get("/credentials/{credential_id}", response_model=AccessCredentialResponse)
async def get_credential(
    credential_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a credential by ID."""
    service = _get_service(session, current_user)
    try:
        return await service.get_credential(credential_id)
    except CredentialNotFoundError:
        raise HTTPException(status_code=404, detail="Credential not found")


@router.post(
    "/credentials",
    status_code=status.HTTP_201_CREATED,
    response_model=AccessCredentialResponse,
)
async def create_credential(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_credentials"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    body: CredentialCreate = Body(...),
) -> Any:
    """Create a new credential.

    NOTE (C2): ``pin`` is Argon2id-hashed, ``card_number`` +
    ``facility_code`` are Fernet-encrypted before persistence.
    """
    service = _get_service(session, current_user)
    try:
        return await service.create_credential(body.model_dump(exclude_unset=False))
    except CrossTenantError as exc:
        raise _xtenant_to_403(exc)


@router.patch("/credentials/{credential_id}", response_model=AccessCredentialResponse)
async def update_credential(
    credential_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_credentials"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    body: CredentialUpdate = Body(...),
) -> Any:
    """Update a credential. (H3 — endpoint added)"""
    service = _get_service(session, current_user)
    try:
        return await service.update_credential(credential_id, body.model_dump(exclude_unset=True))
    except CredentialNotFoundError:
        raise HTTPException(status_code=404, detail="Credential not found")


@router.post("/credentials/{credential_id}/revoke")
async def revoke_credential(
    credential_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_credentials"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Revoke a credential."""
    service = _get_service(session, current_user)
    try:
        await service.revoke_credential(credential_id)
        return {"status": "ok", "credential_id": str(credential_id), "is_active": False}
    except CredentialNotFoundError:
        raise HTTPException(status_code=404, detail="Credential not found")


# =============================================================================
# Cardholder Endpoints
# =============================================================================


@router.get("/cardholders")
async def list_cardholders(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
    is_active: bool | None = None,
    search: str | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Any:
    """List cardholders."""
    service = _get_service(session, current_user)
    cardholders, total = await service.list_cardholders(
        site_id=site_id,
        is_active=is_active,
        search=search,
        limit=limit,
        offset=offset,
    )
    return {"items": cardholders, "total": total}


@router.get("/cardholders/{cardholder_id}")
async def get_cardholder(
    cardholder_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a cardholder by ID."""
    service = _get_service(session, current_user)
    try:
        return await service.get_cardholder(cardholder_id)
    except CardholderNotFoundError:
        raise HTTPException(status_code=404, detail="Cardholder not found")


@router.post("/cardholders", status_code=status.HTTP_201_CREATED)
async def create_cardholder(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_credentials"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    body: CardholderCreate = Body(...),
) -> Any:
    """Create a cardholder."""
    service = _get_service(session, current_user)
    try:
        return await service.create_cardholder(body.model_dump(exclude_unset=False))
    except CrossTenantError as exc:
        raise _xtenant_to_403(exc)


@router.patch("/cardholders/{cardholder_id}")
async def update_cardholder(
    cardholder_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_credentials"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    body: CardholderUpdate = Body(...),
) -> Any:
    """Update a cardholder. (H3 — endpoint added)"""
    service = _get_service(session, current_user)
    try:
        return await service.update_cardholder(cardholder_id, body.model_dump(exclude_unset=True))
    except CardholderNotFoundError:
        raise HTTPException(status_code=404, detail="Cardholder not found")


@router.delete("/cardholders/{cardholder_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_cardholder(
    cardholder_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_credentials"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a cardholder. (H3 — endpoint added)"""
    service = _get_service(session, current_user)
    try:
        await service.delete_cardholder(cardholder_id)
    except CardholderNotFoundError:
        raise HTTPException(status_code=404, detail="Cardholder not found")


# =============================================================================
# Schedule Endpoints (H3)
# =============================================================================


@router.get("/schedules")
async def list_schedules(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Any:
    """List schedules. (H3)"""
    service = _get_service(session, current_user)
    schedules, total = await service.list_schedules(site_id=site_id, limit=limit, offset=offset)
    return {"items": schedules, "total": total}


@router.get("/schedules/{schedule_id}")
async def get_schedule(
    schedule_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a schedule by ID. (H3)"""
    service = _get_service(session, current_user)
    try:
        return await service.get_schedule(schedule_id)
    except ScheduleNotFoundError:
        raise HTTPException(status_code=404, detail="Schedule not found")


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
async def create_schedule(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_schedules"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    body: ScheduleCreate = Body(...),
) -> Any:
    """Create a schedule. (H3)"""
    service = _get_service(session, current_user)
    try:
        return await service.create_schedule(body.model_dump(exclude_unset=False))
    except CrossTenantError as exc:
        raise _xtenant_to_403(exc)


@router.patch("/schedules/{schedule_id}")
async def update_schedule(
    schedule_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_schedules"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    body: ScheduleUpdate = Body(...),
) -> Any:
    """Update a schedule. (H3)"""
    service = _get_service(session, current_user)
    try:
        return await service.update_schedule(schedule_id, body.model_dump(exclude_unset=True))
    except ScheduleNotFoundError:
        raise HTTPException(status_code=404, detail="Schedule not found")


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_schedules"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete a schedule. (H3)"""
    service = _get_service(session, current_user)
    try:
        await service.delete_schedule(schedule_id)
    except ScheduleNotFoundError:
        raise HTTPException(status_code=404, detail="Schedule not found")


# =============================================================================
# Access Controller Endpoints (H3)
# =============================================================================


@router.get("/controllers")
async def list_controllers(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Any:
    """List access controllers. (H3)"""
    service = _get_service(session, current_user)
    items, total = await service.list_controllers(site_id=site_id, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/controllers/{controller_id}")
async def get_controller(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a controller by ID. (H3)"""
    service = _get_service(session, current_user)
    try:
        return await service.get_controller(controller_id)
    except AccessControllerNotFoundError:
        raise HTTPException(status_code=404, detail="Controller not found")


@router.post("/controllers", status_code=status.HTTP_201_CREATED)
async def create_controller(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_doors"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    body: ControllerCreate = Body(...),
) -> Any:
    """Create an access controller. (H3)"""
    service = _get_service(session, current_user)
    try:
        return await service.create_controller(body.model_dump(exclude_unset=False))
    except CrossTenantError as exc:
        raise _xtenant_to_403(exc)


@router.patch("/controllers/{controller_id}")
async def update_controller(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_doors"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    body: ControllerUpdate = Body(...),
) -> Any:
    """Update an access controller. (H3)"""
    service = _get_service(session, current_user)
    try:
        return await service.update_controller(controller_id, body.model_dump(exclude_unset=True))
    except AccessControllerNotFoundError:
        raise HTTPException(status_code=404, detail="Controller not found")


@router.delete("/controllers/{controller_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_controller(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.manage_doors"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete an access controller. (H3)"""
    service = _get_service(session, current_user)
    try:
        await service.delete_controller(controller_id)
    except AccessControllerNotFoundError:
        raise HTTPException(status_code=404, detail="Controller not found")


# =============================================================================
# Event Endpoints
# =============================================================================


@router.get("/events")
async def search_events(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view_events"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    door_id: UUID | None = None,
    cardholder_id: UUID | None = None,
    event_type: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
) -> Any:
    """Search access events."""
    service = _get_service(session, current_user)
    try:
        events, total = await service.search_events(
            door_id=door_id,
            cardholder_id=cardholder_id,
            event_type=event_type,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )
    except CardholderNotFoundError:
        # NOTE (H2): caller asked for a cardholder outside their org.
        raise HTTPException(status_code=404, detail="Cardholder not found")
    # ACC-CARD: mask the full card number in the audit-event list to last-4. The
    # sibling AccessCredential read path masks card_number, and a
    # viewer (access.view_events) should not be able to harvest full card numbers.
    # Detach FIRST: get_session() auto-commits, so masking an attached row would
    # persist over the real stored value.
    for ev in events:
        session.expunge(ev)
        if ev.card_number:
            ev.card_number = "****" + ev.card_number[-4:] if len(ev.card_number) > 4 else "****"
    return {"items": events, "total": total}


@router.get("/events/stats")
async def get_event_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view_events"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> Any:
    """Get access event statistics."""
    service = _get_service(session, current_user)
    return await service.get_event_stats(
        site_id=site_id,
        start_time=start_time,
        end_time=end_time,
    )


@router.post("/events/{event_id}/ack")
async def acknowledge_event(
    event_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view_events"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Acknowledge an access event. (H3 — endpoint added)"""
    service = _get_service(session, current_user)
    try:
        event = await service.acknowledge_event(event_id, current_user.id)
    except EventNotFoundError:
        raise HTTPException(status_code=404, detail="Event not found")
    return {
        "status": "ok",
        "event_id": str(event.id),
        "is_acknowledged": event.is_acknowledged,
        "acknowledged_by": str(event.acknowledged_by) if event.acknowledged_by else None,
        "acknowledged_at": event.acknowledged_at.isoformat() if event.acknowledged_at else None,
    }


@router.get("/events/chain/validate")
async def validate_event_chain(
    current_user: Annotated[CurrentUser, Depends(require_permissions("access.view_events"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    door_id: UUID | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> Any:
    """Validate the access-event tamper-evidence hash chain. (H1)"""
    service = _get_service(session, current_user)
    return await service.validate_event_chain(
        door_id=door_id,
        start_at=start_time,
        end_at=end_time,
    )

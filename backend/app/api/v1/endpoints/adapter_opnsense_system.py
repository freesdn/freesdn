# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense System endpoint.

URL layout::

    GET   /api/v1/gateway-opnsense-system/{controller_id}/info
    GET   /api/v1/gateway-opnsense-system/{controller_id}/firmware-status
    GET   /api/v1/gateway-opnsense-system/{controller_id}/backups
    GET   /api/v1/gateway-opnsense-system/{controller_id}/config-download
    POST  /api/v1/gateway-opnsense-system/{controller_id}/changes/{feature}
    GET   /api/v1/gateway-opnsense-system/{controller_id}/changes

Reads run live; reboots / firmware updates / backup ops go through
staging. Apply path is the shared
``/gateway-vpn/changes/{change_id}/apply`` endpoint.

The ``config-download`` route is special: it returns the raw
``config.xml`` as ``application/octet-stream`` and audit-logs the
access intent BEFORE invoking the controller, mirroring the Omada
``download_backup`` pattern in ``gateway_system.py``. If the audit log
itself fails we refuse the download with 503 — compliance regimes
require that backup-access is recorded, and a silent leak is worse
than a denied download.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.validation import validate_id
from app.core.dependencies import (
    CurrentUser,
    require_min_role,
    require_permissions,
)
from app.db.session import get_session
from app.schemas.gateway_vpn import (
    PendingChangeRequest,
    PendingChangeResponse,
)
from app.services.adapter_opnsense_system import (
    GatewayOpnsenseSystemService,
)
from app.services.adapter_staging import AdapterStagingService
from app.services.audit import AuditAction, AuditService, ResourceType

router = APIRouter(
    prefix="/gateway-opnsense-system",
    tags=["gateway-opnsense-system"],
)


# ── Reads ───────────────────────────────────────────────────────────────


@router.get("/{controller_id}/info")
async def get_system_info(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseSystemService(session)
    return await svc.get_info(controller_id, user.organization_id)


@router.get("/{controller_id}/firmware-status")
async def get_firmware_status(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseSystemService(session)
    return await svc.get_firmware_status(controller_id, user.organization_id)


@router.get("/{controller_id}/backups")
async def list_backups(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewayOpnsenseSystemService(session)
    return await svc.list_backups(controller_id, user.organization_id)


@router.get("/{controller_id}/config-download")
async def download_config(
    controller_id: UUID,
    # The OPNsense ``config.xml`` ships every secret on the firewall —
    # CA private keys, IPsec PSKs, RADIUS shared secrets, password
    # hashes. It is by far the most secret-leaking single endpoint on
    # the platform, so we double-gate: ``controller:write`` (not just
    # ``firewall:read``) AND a minimum ``super_admin`` role check.
    # Anything less is unsuitable for a tenant operator.
    user: Annotated[CurrentUser, Depends(require_permissions("controller:write"))],
    _enforce_role: Annotated[CurrentUser, Depends(require_min_role("super_admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    """Stream the raw ``config.xml`` from the controller.

    Audit-logs BEFORE the fetch so the access intent is recorded even
    if the fetch fails or the audit-log itself fails. If the audit log
    can't be written we 503 — never leak a backup silently.

    Requires ``controller:write`` permission AND the ``super_admin``
    minimum role: the response contains the firewall's complete secret
    state (CA private keys, IPsec PSKs, password hashes), so a tenant
    operator must not be able to call this even with a leaked
    ``firewall:read`` token.
    """
    audit = AuditService(db=session)
    try:
        await audit.log(
            action=AuditAction.READ,
            resource_type=ResourceType.BACKUP,
            resource_id=controller_id,
            organization_id=user.organization_id,
            actor_id=user.id,
            extra_metadata={"source": "opnsense-config"},
        )
    except Exception as exc:
        raise HTTPException(
            503,
            detail="audit log unavailable; refusing config download",
        ) from exc

    svc = GatewayOpnsenseSystemService(session)
    raw = await svc.download_config_xml(controller_id, user.organization_id)
    # OPNsense returns XML text; encode to bytes for the stream.
    return Response(
        content=raw.encode("utf-8") if isinstance(raw, str) else raw,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (f'attachment; filename="opnsense-config-{controller_id}.xml"'),
        },
    )


# ── Writes (staged) ─────────────────────────────────────────────────────


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_opnsense_system_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    if not feature.startswith("opnsense.system."):
        raise HTTPException(
            400,
            detail=("OPNsense system endpoint only accepts opnsense.system.* features"),
        )
    # Backup delete / restore target a backup by filename — validate it
    # before staging so a path-traversal payload never lands in the
    # staging table where it would only be checked at apply-time.
    if feature in (
        "opnsense.system.backup_delete",
        "opnsense.system.backup_restore",
    ):
        # Caller may put the filename in target_id (preferred) or in
        # payload['filename']. Either way: validate.
        #
        # CAREFUL: ``str(None)`` produces the literal string ``"None"``
        # which would happily pass the validator regex
        # ``[A-Za-z0-9_.\-]{1,64}``. Reject ``None`` candidates BEFORE
        # we ever stringify, so a missing-filename request can't sneak
        # through as the literal "None" filename.
        target_id_val = body.target_id
        payload_filename = (body.payload or {}).get("filename")
        if target_id_val is None and payload_filename is None:
            raise HTTPException(
                400,
                detail=(
                    f"feature={feature!r} requires target_id or "
                    "payload['filename'] (the backup filename)"
                ),
            )
        candidate = target_id_val if target_id_val is not None else payload_filename
        if not candidate:
            raise HTTPException(
                400,
                detail=(f"feature={feature!r} requires non-empty target_id or payload['filename']"),
            )
        validate_id(str(candidate), label="backup_id")

    svc = GatewayOpnsenseSystemService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,  # OPNsense is controller-scoped
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_opnsense_system(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("firewall:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix="opnsense.system.",
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]

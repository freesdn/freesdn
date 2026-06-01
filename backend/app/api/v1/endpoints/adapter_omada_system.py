# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway system endpoints.

URL layout::

    GET    /api/v1/gateway-system/{controller_id}/configs/{config_name}
    GET    /api/v1/gateway-system/{controller_id}/backups
    GET    /api/v1/gateway-system/{controller_id}/backups/{backup_id}/download
    GET    /api/v1/gateway-system/{controller_id}/admins
    GET    /api/v1/gateway-system/{controller_id}/sites/{site_id}/configs/{config_name}
    GET    /api/v1/gateway-system/{controller_id}/sites/{site_id}/reboot-schedules
    POST   /api/v1/gateway-system/{controller_id}/sites/{site_id}/changes/{feature}
    POST   /api/v1/gateway-system/{controller_id}/changes/{feature}    (controller-scoped)
    GET    /api/v1/gateway-system/{controller_id}/changes
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_min_role, require_permissions
from app.db.session import get_session
from app.schemas.gateway_vpn import PendingChangeRequest, PendingChangeResponse
from app.services.adapter_base import validate_omada_id
from app.services.adapter_omada_system import GatewaySystemService
from app.services.adapter_staging import AdapterStagingService

router = APIRouter(prefix="/gateway-system", tags=["gateway-system"])

# Site-scoped staging endpoint may only stage features whose effect is
# site-scoped or monitoring-scoped. Controller-level features
# (system.smtp, system.admin, system.ssl_cert, ...) require the
# controller-scoped staging endpoint guarded by ``controller:write``.
_SITE_STAGE_ALLOWED_PREFIXES = ("site.", "monitoring.")
# Controller-scoped staging endpoint accepts only true controller-level
# features. Refuses ``site.*`` to keep the privilege boundary visible.
_CTRL_STAGE_ALLOWED_PREFIXES = ("system.",)


# ── Reads ───────────────────────────────────────────────────────────────


@router.get("/{controller_id}/configs/{config_name}")
async def get_controller_config(
    controller_id: UUID,
    config_name: str,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewaySystemService(session)
    return await svc.get_controller_config(controller_id, user.organization_id, config_name)


@router.get("/{controller_id}/backups")
async def list_backups(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewaySystemService(session)
    return await svc.list_backups(controller_id, user.organization_id)


@router.get("/{controller_id}/backups/{backup_id}/download")
async def download_backup(
    controller_id: UUID,
    backup_id: str,
    # a controller backup is the full config archive (admin
    # passwords, PSKs, RADIUS secrets). Treat it as a secret EXPORT, not a
    # read — double-gate like the OPNsense config-download: controller:write
    # AND super_admin, so the lowest roles (viewer/operator) cannot pull it.
    user: Annotated[CurrentUser, Depends(require_permissions("controller:write"))],
    _enforce_role: Annotated[CurrentUser, Depends(require_min_role("super_admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    # Validate before it flows into the Omada client URL path; without
    # this an attacker could pass ``../config`` to walk the API surface.
    backup_id = validate_omada_id(backup_id, label="backup_id")

    # Audit-log BEFORE the controller fetch so the access INTENT is
    # recorded even if the fetch fails or the audit-log itself fails.
    # If the audit log can't be written we refuse the download —
    # compliance regimes (SOC2/HIPAA) require an audit trail for
    # backup access. Better to 503 a download than to leak a backup
    # silently.
    from app.services.audit import AuditAction, AuditService, ResourceType

    audit = AuditService(db=session)
    try:
        await audit.log(
            action=AuditAction.READ,
            resource_type=ResourceType.BACKUP,
            resource_id=controller_id,
            organization_id=user.organization_id,
            actor_id=user.id,
            extra_metadata={
                "backup_id": backup_id,
                "source": "omada-controller",
            },
        )
    except Exception as exc:
        from fastapi import HTTPException

        raise HTTPException(
            503,
            detail="audit log unavailable; refusing backup download",
        ) from exc

    svc = GatewaySystemService(session)
    raw = await svc.download_backup(controller_id, user.organization_id, backup_id)
    return Response(
        content=raw,
        media_type="application/octet-stream",
        headers={
            # backup_id is regex-validated above; safe to interpolate.
            "Content-Disposition": (f'attachment; filename="omada-backup-{backup_id}.bin"'),
        },
    )


@router.get("/{controller_id}/admins")
async def list_admins(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewaySystemService(session)
    return await svc.list_admins(controller_id, user.organization_id)


@router.get("/{controller_id}/sites/{site_id}/configs/{config_name}")
async def get_site_config(
    controller_id: UUID,
    site_id: UUID,
    config_name: str,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewaySystemService(session)
    return await svc.get_site_config(controller_id, user.organization_id, site_id, config_name)


@router.get("/{controller_id}/sites/{site_id}/reboot-schedules")
async def list_reboot_schedules(
    controller_id: UUID,
    site_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("network:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    svc = GatewaySystemService(session)
    return await svc.list_reboot_schedules(controller_id, user.organization_id, site_id)


# ── Writes (staged) ─────────────────────────────────────────────────────


@router.post(
    "/{controller_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Stage a controller-scoped change (no site_id required)",
)
async def stage_controller_change(
    controller_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # Lock the controller-scoped endpoint to system.* features so an
    # operator cannot smuggle a ``site.*`` write through here and have
    # the apply-time dispatcher route it elsewhere.
    if not feature.startswith(_CTRL_STAGE_ALLOWED_PREFIXES):
        raise HTTPException(
            400,
            detail=("controller-scoped staging only accepts system.* features"),
        )
    svc = GatewaySystemService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=None,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.post(
    "/{controller_id}/sites/{site_id}/changes/{feature}",
    response_model=PendingChangeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def stage_site_system_change(
    controller_id: UUID,
    site_id: UUID,
    feature: str,
    operation: Annotated[str, Query(description="create | update | delete")],
    body: PendingChangeRequest,
    user: Annotated[CurrentUser, Depends(require_permissions("network:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    # Site-scoped endpoint requires only ``network:write``. Lock it to
    # site.*/monitoring.* features so a site operator cannot stage a
    # ``system.admin`` create here and then ride the apply-time
    # dispatcher into the controller-level service.
    if not feature.startswith(_SITE_STAGE_ALLOWED_PREFIXES):
        raise HTTPException(
            400,
            detail=(
                "site-scoped staging only accepts site.* / monitoring.* "
                "features; use the controller-scoped endpoint with "
                "controller:write for system.* features"
            ),
        )
    svc = GatewaySystemService(session)
    change = await svc.stage_change(
        feature=feature,
        operation=operation,
        payload=body.payload,
        controller_id=controller_id,
        organization_id=user.organization_id,
        site_id=site_id,
        target_id=body.target_id,
        notes=body.notes,
        actor_id=user.id,
    )
    return PendingChangeResponse.from_model(change)


@router.get(
    "/{controller_id}/changes",
    response_model=list[PendingChangeResponse],
)
async def list_pending_system(
    controller_id: UUID,
    user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    feature_prefix: Annotated[str, Query()] = "system.",
    status_filter: Annotated[str, Query(alias="status")] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> Any:
    # System-level pending may include SMTP / SSL / admin payloads —
    # gate behind controller:read, not network:read.
    staging = AdapterStagingService(session)
    changes = await staging.list_pending(
        organization_id=user.organization_id,
        controller_id=controller_id,
        feature_prefix=feature_prefix,
        status_filter=status_filter,
        limit=limit,
    )
    return [PendingChangeResponse.from_model(c) for c in changes]

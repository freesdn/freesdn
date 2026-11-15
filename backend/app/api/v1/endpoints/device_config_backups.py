# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Network device configuration backup API
=================================================

Read the scheduled, versioned config snapshots of exportable devices (OPNsense,
OpenWrt), compare versions, and ask for one gentle manual export.

* Listing, version history, the REDACTED configuration and REDACTED diffs need
  ``firewall.view``. Secrets never leave the server unredacted on these paths.
* The raw export (every secret on the device -- it is what you would restore
  from, through the vendor's own UI) needs ``controller:write`` AND the
  ``super_admin`` role, and is audit-logged BEFORE it is decrypted, exactly like
  the live ``config-download`` endpoints.
* Manual capture / schedule changes need ``firewall.manage_rules``.

There is no restore endpoint: this module never writes to a device.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_min_role, require_permissions
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.modules.backup.models import DeviceConfigBackupTarget, DeviceConfigSnapshot
from app.services.device_config_backup import (
    INTERVAL_HOURS_RANGE,
    RETENTION_RANGE,
    CaptureRefused,
    DeviceConfigBackupService,
    SnapshotUnavailable,
)
from app.services.device_config_render import (
    OPENWRT_SYSUPGRADE,
    ConfigFormatError,
    redacted_diff,
)

router = APIRouter()


class ConfigBackupTargetResponse(BaseModel):
    id: UUID
    source_kind: str
    source_id: UUID
    vendor: str
    display_name: str
    site_id: UUID | None
    enabled: bool
    interval_hours: int
    retention_versions: int
    next_due_at: datetime | None
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_changed_at: datetime | None
    last_status: str
    last_error_code: str | None
    consecutive_failures: int
    capture_running: bool
    latest_version: int | None
    latest_captured_at: datetime | None


class ConfigSnapshotResponse(BaseModel):
    id: UUID
    version: int
    captured_at: datetime
    format: str
    size_bytes: int
    trigger: str
    summary: dict[str, int] | None


class ConfigSnapshotContentResponse(ConfigSnapshotResponse):
    redacted: bool = True
    content: str


class ConfigDiffResponse(BaseModel):
    target_id: UUID
    from_version: int | None
    to_version: int
    redacted: bool = True
    lines: list[str]
    truncated: bool
    added: int
    removed: int


class ConfigBackupTargetUpdate(BaseModel):
    enabled: bool | None = None
    interval_hours: int | None = Field(None, ge=INTERVAL_HOURS_RANGE[0], le=INTERVAL_HOURS_RANGE[1])
    retention_versions: int | None = Field(None, ge=RETENTION_RANGE[0], le=RETENTION_RANGE[1])


class ConfigCaptureAccepted(BaseModel):
    target_id: UUID
    status: str = "queued"


async def _target(
    session: AsyncSession, user: CurrentUser, target_id: UUID
) -> DeviceConfigBackupTarget:
    target = (
        await session.execute(
            select(DeviceConfigBackupTarget).where(
                DeviceConfigBackupTarget.id == target_id,
                tenant_filter(DeviceConfigBackupTarget, user),
            )
        )
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Config backup target not found")
    return target


def _target_response(
    target: DeviceConfigBackupTarget, latest: tuple[int, datetime] | None
) -> ConfigBackupTargetResponse:
    from datetime import UTC

    now = datetime.now(UTC)
    return ConfigBackupTargetResponse(
        id=target.id,
        source_kind=target.source_kind,
        source_id=target.source_id,
        vendor=target.vendor,
        display_name=target.display_name,
        site_id=target.site_id,
        enabled=target.enabled,
        interval_hours=target.interval_hours,
        retention_versions=target.retention_versions,
        next_due_at=target.next_due_at,
        last_attempt_at=target.last_attempt_at,
        last_success_at=target.last_success_at,
        last_changed_at=target.last_changed_at,
        last_status=target.last_status,
        last_error_code=target.last_error_code,
        consecutive_failures=target.consecutive_failures,
        capture_running=bool(target.lease_until and target.lease_until > now),
        latest_version=latest[0] if latest else None,
        latest_captured_at=latest[1] if latest else None,
    )


def _snapshot_response(snapshot: DeviceConfigSnapshot) -> dict[str, Any]:
    return {
        "id": snapshot.id,
        "version": snapshot.version,
        "captured_at": snapshot.captured_at,
        "format": snapshot.format,
        "size_bytes": snapshot.size_bytes,
        "trigger": snapshot.trigger,
        "summary": snapshot.summary,
    }


async def _snapshot(
    service: DeviceConfigBackupService, target_id: UUID, version: int
) -> DeviceConfigSnapshot:
    snapshot = await service.snapshot(target_id, version)
    if snapshot is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Config version not found")
    return snapshot


def _render(snapshot: DeviceConfigSnapshot) -> str:
    try:
        return DeviceConfigBackupService.redacted(snapshot)
    except (SnapshotUnavailable, ConfigFormatError):
        # SECRET_KEY changed since capture, or a damaged row. No detail.
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This config version can no longer be decrypted"
        ) from None


@router.get("/", response_model=list[ConfigBackupTargetResponse])
async def list_config_backup_targets(
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Every device whose configuration FreeSDN backs up, with its last outcome."""
    targets = list(
        (
            await session.execute(
                select(DeviceConfigBackupTarget)
                .where(tenant_filter(DeviceConfigBackupTarget, current_user))
                .order_by(DeviceConfigBackupTarget.display_name)
            )
        ).scalars()
    )
    latest = await DeviceConfigBackupService(session).latest_versions([t.id for t in targets])
    return [_target_response(t, latest.get(t.id)) for t in targets]


@router.patch("/{target_id}", response_model=ConfigBackupTargetResponse)
async def update_config_backup_target(
    target_id: UUID,
    body: ConfigBackupTargetUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Enable/disable, change the cadence (6-168 h) or the versions kept (1-365)."""
    target = await _target(session, current_user, target_id)
    changes = body.model_dump(exclude_none=True)
    for key, value in changes.items():
        setattr(target, key, value)
    if (
        changes.get("enabled")
        and target.next_due_at is None
        and target.last_status
        not in (
            "source_removed",
            "unsupported",
        )
    ):
        from datetime import UTC, timedelta

        target.next_due_at = datetime.now(UTC) + timedelta(minutes=10)
    await session.commit()
    latest = await DeviceConfigBackupService(session).latest_versions([target.id])
    return _target_response(target, latest.get(target.id))


@router.post(
    "/{target_id}/capture",
    response_model=ConfigCaptureAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def capture_config_now(
    target_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.manage_rules"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Queue ONE read-only export now. Refused while one runs or within 10 minutes
    of the last attempt, so a button cannot hammer the device."""
    target = await _target(session, current_user, target_id)
    service = DeviceConfigBackupService(session)
    try:
        claim = await service.claim_manual(target)
    except CaptureRefused as exc:
        raise HTTPException(exc.status_code, exc.detail) from None
    await session.commit()
    from app.tasks.config_backup import capture

    capture.delay(str(claim.target_id), str(claim.token), "manual", str(current_user.id))
    return ConfigCaptureAccepted(target_id=target.id)


@router.get("/{target_id}/versions/", response_model=list[ConfigSnapshotResponse])
async def list_config_versions(
    target_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    await _target(session, current_user, target_id)
    versions = await DeviceConfigBackupService(session).versions(target_id)
    return [_snapshot_response(v) for v in versions]


@router.get("/{target_id}/versions/{version}", response_model=ConfigSnapshotContentResponse)
async def get_config_version(
    target_id: UUID,
    version: int,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """The configuration with every secret-looking value replaced by a fingerprint."""
    await _target(session, current_user, target_id)
    snapshot = await _snapshot(DeviceConfigBackupService(session), target_id, version)
    return {**_snapshot_response(snapshot), "redacted": True, "content": _render(snapshot)}


@router.get("/{target_id}/versions/{version}/diff", response_model=ConfigDiffResponse)
async def diff_config_version(
    target_id: UUID,
    version: int,
    current_user: Annotated[CurrentUser, Depends(require_permissions("firewall.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    against: int | None = Query(None, ge=1, description="Older version; default: the previous"),
) -> Any:
    """Unified diff of two REDACTED renderings (a changed secret shows as a
    changed fingerprint, never as its value)."""
    await _target(session, current_user, target_id)
    service = DeviceConfigBackupService(session)
    newer = await _snapshot(service, target_id, version)
    older = (
        await _snapshot(service, target_id, against)
        if against is not None
        else await service.previous(target_id, version)
    )
    older_text = _render(older) if older is not None else ""
    lines, truncated = redacted_diff(
        older_text,
        _render(newer),
        older_label=f"v{older.version}" if older is not None else "(none)",
        newer_label=f"v{newer.version}",
    )
    added = sum(1 for line in lines if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in lines if line.startswith("-") and not line.startswith("---"))
    return ConfigDiffResponse(
        target_id=target_id,
        from_version=older.version if older is not None else None,
        to_version=newer.version,
        lines=lines,
        truncated=truncated,
        added=added,
        removed=removed,
    )


@router.get("/{target_id}/versions/{version}/download")
async def download_config_version(
    target_id: UUID,
    version: int,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:write"))],
    _role: Annotated[CurrentUser, Depends(require_min_role("super_admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    """The UNREDACTED export, for restoring through the vendor's own UI.

    It carries every secret on the device, so it is gated like the live
    config-download endpoints and audit-logged before decryption; if the audit
    entry cannot be written the download is refused.
    """
    from app.services.audit import AuditAction, AuditService, ResourceType
    from app.services.device_config_backup import unseal

    target = await _target(session, current_user, target_id)
    snapshot = await _snapshot(DeviceConfigBackupService(session), target_id, version)
    try:
        await AuditService(db=session).log(
            action=AuditAction.EXPORT,
            resource_type=ResourceType.BACKUP,
            resource_id=snapshot.id,
            organization_id=target.organization_id,
            site_id=target.site_id,
            actor_id=current_user.id,
            extra_metadata={
                "source": "device-config-backup",
                "target_id": str(target.id),
                "version": snapshot.version,
            },
        )
        await session.commit()
    except Exception as exc:
        raise HTTPException(503, detail="audit log unavailable; refusing config download") from exc
    try:
        raw = unseal(snapshot.ciphertext)
    except SnapshotUnavailable:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "This config version can no longer be decrypted"
        ) from None
    extension = "tar.gz" if snapshot.format == OPENWRT_SYSUPGRADE else "xml"
    stamp = snapshot.captured_at.strftime("%Y%m%d-%H%M%S")
    return Response(
        content=raw,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{target.vendor}-config-v{snapshot.version}-{stamp}.{extension}"'
            ),
            "Cache-Control": "no-store",
        },
    )

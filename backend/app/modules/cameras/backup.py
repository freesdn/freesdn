# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Cameras backup contributor — NVRs, cameras (channels), groups, views,
recording-schedule templates (NOT footage / events / health telemetry).

Second module-owned contributor. Uses the shared ``restore_records``
helper so the tenant-isolation + FK-ordering logic lives in one place
(see ``app/services/backup_contributors/restore_helpers.py``).

Scope (the audit's "Cameras — NVRs, channels, motion config NOT footage"):

  Included (portable configuration):
    - cameras.nvrs                        (secrets redacted)
    - cameras.cameras                     (the "channels"; secrets redacted)
    - cameras.camera_groups + members     (organizational grouping)
    - cameras.camera_views                (saved multi-view layouts)
    - cameras.recording_schedule_templates (motion / retention config)

  Excluded:
    - cameras.recordings                  (footage — not config)
    - cameras.camera_events               (motion/alert telemetry)
    - cameras.camera_health_snapshots     (bandwidth/health telemetry)
    - cameras.camera_reports              (generated reports)
    - cameras.camera_access_grants        (per-user ACLs — instance-tied;
                                           deferred to a later contributor)
    - Camera/NVR ``password_encrypted``   (Fernet ciphertext tied to this
                                           instance's key; re-entered after
                                           restore)
    - any secret-shaped key in settings JSONB

Tenant scoping: Camera + NVR + CameraGroup + CameraView +
RecordingScheduleTemplate all carry a DIRECT ``organization_id`` column
(simpler than VoIP's site-join). Restore forces ``organization_id`` to
the caller's org on every insert and rejects records claiming a
different org. ``site_id`` (non-null FK on Camera + NVR) is validated
against the caller's org sites.

Restore order (FK dependency): NVR → Camera (nvr_id nullable FK) →
CameraGroup → CameraGroupMember (group_id + camera_id) → CameraView →
RecordingScheduleTemplate. Sites + controllers come from the ``core``
contributor (``depends_on=("core",)``).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import select

from app.services.backup_contributors import (
    ContributorPayload,
    NullableFK,
    RejectGuard,
    RestoreResult,
    restore_records,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


_SECRET_SETTINGS_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
        "rtsp_password",
        "onvif_password",
        "auth_password",
        "admin_password",
    }
)


def _redact(blob: Any) -> Any:
    if isinstance(blob, dict):
        return {k: _redact(v) for k, v in blob.items() if k.lower() not in _SECRET_SETTINGS_KEYS}
    if isinstance(blob, list):
        return [_redact(v) for v in blob]
    return blob


def _vault_dec(value: Any) -> Any:
    """Decrypt a single encrypt_credential field for a vault payload."""
    from app.core.crypto import decrypt_credential, is_encrypted

    return decrypt_credential(value) if (isinstance(value, str) and is_encrypted(value)) else value


def _settings_for(blob: Any, include_secrets: bool) -> Any:
    """Vault keeps settings intact (sealed); config snapshot redacts secret keys."""
    return (blob or {}) if include_secrets else _redact(blob or {})


class CamerasBackupContributor:
    """Backup/restore for the Cameras module's portable configuration."""

    contributor_id: str = "cameras"
    schema_version: str = "1.0.0"
    depends_on: tuple[str, ...] = ("core",)
    default_included: bool = True

    # ── collect ────────────────────────────────────────────────────────

    async def collect(
        self,
        session: AsyncSession,
        organization_id: UUID,
        options: dict[str, Any],
    ) -> ContributorPayload:
        from app.modules.cameras.models import (
            NVR,
            Camera,
            CameraGroup,
            CameraGroupMember,
            CameraView,
            RecordingScheduleTemplate,
        )

        site_filter = options.get("site_id")
        include_secrets = bool(options.get("include_secrets", False))

        # --- NVRs (direct org column) ---
        nvr_q = select(NVR).where(
            NVR.organization_id == organization_id,
            NVR.deleted_at.is_(None),
        )
        if site_filter:
            nvr_q = nvr_q.where(NVR.site_id == site_filter)
        nvr_rows = (await session.execute(nvr_q)).scalars().all()
        nvr_data = [
            {
                "id": str(n.id),
                "site_id": str(n.site_id),
                "controller_id": str(n.controller_id) if n.controller_id else None,
                "organization_id": str(n.organization_id),
                "name": n.name,
                "description": n.description,
                "ip_address": n.ip_address,
                "port": n.port,
                "mac_address": n.mac_address,
                "vendor": n.vendor,
                "model": n.model,
                "firmware_version": n.firmware_version,
                "serial_number": n.serial_number,
                "device_type": n.device_type,
                "username": n.username,  # password_encrypted excluded unless vault
                "external_device_id": n.external_device_id,
                "channel_count": n.channel_count,
                **(
                    {"password_encrypted": _vault_dec(n.password_encrypted)}
                    if include_secrets
                    else {}
                ),
                "settings": _settings_for(n.settings, include_secrets),
            }
            for n in nvr_rows
        ]

        # --- Cameras (the "channels") ---
        cam_q = select(Camera).where(
            Camera.organization_id == organization_id,
            Camera.deleted_at.is_(None),
        )
        if site_filter:
            cam_q = cam_q.where(Camera.site_id == site_filter)
        cam_rows = (await session.execute(cam_q)).scalars().all()
        cam_data = [
            {
                "id": str(c.id),
                "site_id": str(c.site_id),
                "nvr_id": str(c.nvr_id) if c.nvr_id else None,
                "controller_id": str(c.controller_id) if c.controller_id else None,
                "organization_id": str(c.organization_id),
                "channel_id": c.channel_id,
                "name": c.name,
                "description": c.description,
                "camera_type": c.camera_type,
                "ip_address": c.ip_address,
                "port": c.port,
                "mac_address": c.mac_address,
                "vendor": c.vendor,
                "model": c.model,
                "firmware_version": c.firmware_version,
                "serial_number": c.serial_number,
                "rtsp_main_stream": c.rtsp_main_stream,
                "rtsp_sub_stream": c.rtsp_sub_stream,
                "snapshot_url": c.snapshot_url,
                "device_type": c.device_type,
                "username": c.username,  # password_encrypted excluded unless vault
                **(
                    {"password_encrypted": _vault_dec(c.password_encrypted)}
                    if include_secrets
                    else {}
                ),
                "has_ptz": c.has_ptz,
                "has_audio": c.has_audio,
                "has_two_way_audio": c.has_two_way_audio,
                "has_ir": c.has_ir,
                "resolution_width": c.resolution_width,
                "resolution_height": c.resolution_height,
                "motion_detection_enabled": c.motion_detection_enabled,
                "location": c.location,
                "floor": c.floor,
                "settings": _settings_for(c.settings, include_secrets),
            }
            for c in cam_rows
        ]

        # --- Camera groups + members ---
        grp_rows = (
            (
                await session.execute(
                    select(CameraGroup).where(
                        CameraGroup.organization_id == organization_id,
                        CameraGroup.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        grp_ids = [g.id for g in grp_rows]
        grp_data = [
            {
                "id": str(g.id),
                "organization_id": str(g.organization_id),
                "name": g.name,
                "description": g.description,
                "color": g.color,
                "icon": g.icon,
                "sort_order": g.sort_order,
                "is_default": g.is_default,
            }
            for g in grp_rows
        ]
        member_data: list[dict[str, Any]] = []
        if grp_ids:
            member_rows = (
                (
                    await session.execute(
                        select(CameraGroupMember).where(
                            CameraGroupMember.group_id.in_(grp_ids),
                        )
                    )
                )
                .scalars()
                .all()
            )
            member_data = [
                {
                    "id": str(m.id),
                    "group_id": str(m.group_id),
                    "camera_id": str(m.camera_id),
                    "sort_order": m.sort_order,
                }
                for m in member_rows
            ]

        # --- Camera views ---
        view_rows = (
            (
                await session.execute(
                    select(CameraView).where(
                        CameraView.organization_id == organization_id,
                        CameraView.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        view_data = [
            {
                "id": str(v.id),
                "organization_id": str(v.organization_id),
                "user_id": str(v.user_id) if v.user_id else None,
                "name": v.name,
                "description": v.description,
                "layout": v.layout,
                "camera_ids": [str(cid) for cid in (v.camera_ids or [])],
                "filters": _redact(v.filters or {}),
                "is_default": v.is_default,
                "is_shared": v.is_shared,
                "sort_order": v.sort_order,
            }
            for v in view_rows
        ]

        # --- Recording-schedule templates (motion / retention config) ---
        tmpl_rows = (
            (
                await session.execute(
                    select(RecordingScheduleTemplate).where(
                        RecordingScheduleTemplate.organization_id == organization_id,
                        RecordingScheduleTemplate.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        tmpl_data = [
            {
                "id": str(t.id),
                "organization_id": str(t.organization_id),
                "name": t.name,
                "description": t.description,
                "is_builtin": t.is_builtin,
                "schedule": t.schedule or {},
            }
            for t in tmpl_rows
        ]

        data = {
            "nvrs": nvr_data,
            "cameras": cam_data,
            "camera_groups": grp_data,
            "camera_group_members": member_data,
            "camera_views": view_data,
            "recording_schedule_templates": tmpl_data,
        }
        counts = {k: len(v) for k, v in data.items()}

        return ContributorPayload(
            schema_version=self.schema_version,
            counts=counts,
            data=data,
            metadata={
                "captured_at": time.time(),
                "source": "cameras_contributor.collect",
                "secrets_excluded": True,
            },
        )

    # ── restore ────────────────────────────────────────────────────────

    async def restore(
        self,
        session: AsyncSession,
        organization_id: UUID,
        payload: ContributorPayload,
        *,
        dry_run: bool,
        options: dict[str, Any],
    ) -> RestoreResult:
        from app.models.core import Controller, Site, User
        from app.modules.cameras.models import (
            NVR,
            Camera,
            CameraGroup,
            CameraGroupMember,
            CameraView,
            RecordingScheduleTemplate,
        )

        start = time.monotonic()
        result = RestoreResult(
            contributor_id=self.contributor_id,
            status="dry_run_ok" if dry_run else "ok",
        )
        overwrite = options.get("overwrite_existing", False)
        include_secrets = bool(options.get("include_secrets", False))
        data = payload.data

        # Vault restore: NVR/Camera password_encrypted arrived DECRYPTED in the
        # passphrase-sealed payload — re-encrypt under THIS instance's key first.
        if include_secrets:
            from app.core.crypto import encrypt_credential, is_encrypted

            for key in ("nvrs", "cameras"):
                for rec in data.get(key, []):
                    v = rec.get("password_encrypted")
                    if isinstance(v, str) and v and not is_encrypted(v):
                        rec["password_encrypted"] = encrypt_credential(v)

        # Valid id sets for guards (all org-scoped).
        org_site_ids = {
            str(s)
            for s in (
                await session.execute(
                    select(Site.id).where(
                        Site.organization_id == organization_id,
                        Site.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        }
        org_controller_ids = {
            str(c)
            for c in (
                await session.execute(
                    select(Controller.id)
                    .join(Site, Controller.site_id == Site.id)
                    .where(Site.organization_id == organization_id)
                )
            )
            .scalars()
            .all()
        }
        # scope the CameraView.user_id allowlist to THIS org's
        # users (every other FK in this restore is org-scoped). Otherwise a
        # tampered .fsdn archive could stamp a foreign org's user UUID onto a
        # restored view, polluting the ownership/audit trail. Out-of-org IDs
        # now null out (NullableFK behavior) instead of persisting.
        valid_user_ids = {
            str(u)
            for u in (
                await session.execute(
                    select(User.id).where(User.organization_id == organization_id)
                )
            )
            .scalars()
            .all()
        }

        # Config snapshot blocks the credential column; vault restores it (re-encrypted above).
        cred_blocked: set[str] = set() if include_secrets else {"password_encrypted"}

        # --- NVRs first (Camera.nvr_id FK target) ---
        restored_nvr_ids = await restore_records(
            session,
            model_cls=NVR,
            records=data.get("nvrs", []),
            result=result,
            resource="nvrs",
            dry_run=dry_run,
            overwrite=overwrite,
            force_org=organization_id,
            reject_guards=[RejectGuard("site_id", org_site_ids, "cross-tenant")],
            nullable_fks=[NullableFK("controller_id", org_controller_ids)],
            blocked_fields=cred_blocked,
        )

        # --- Cameras (channels) — nvr_id nullable → restored NVRs ---
        await restore_records(
            session,
            model_cls=Camera,
            records=data.get("cameras", []),
            result=result,
            resource="cameras",
            dry_run=dry_run,
            overwrite=overwrite,
            force_org=organization_id,
            reject_guards=[RejectGuard("site_id", org_site_ids, "cross-tenant")],
            nullable_fks=[
                NullableFK("nvr_id", restored_nvr_ids),
                NullableFK("controller_id", org_controller_ids),
            ],
            blocked_fields=cred_blocked,
        )

        # --- Camera groups ---
        restored_group_ids = await restore_records(
            session,
            model_cls=CameraGroup,
            records=data.get("camera_groups", []),
            result=result,
            resource="camera_groups",
            dry_run=dry_run,
            overwrite=overwrite,
            force_org=organization_id,
        )

        # --- Group members (FK group_id + camera_id both must exist) ---
        # camera_id validity = the cameras we just restored. We don't have
        # a restored-camera-id set returned above, so re-derive it from the
        # records we accepted: a camera is valid if its site was in-org.
        restored_camera_ids = {
            str(c["id"])
            for c in data.get("cameras", [])
            if str(c.get("site_id")) in org_site_ids and c.get("id")
        }
        await restore_records(
            session,
            model_cls=CameraGroupMember,
            records=data.get("camera_group_members", []),
            result=result,
            resource="camera_group_members",
            dry_run=dry_run,
            overwrite=overwrite,
            reject_guards=[
                RejectGuard("group_id", restored_group_ids, "orphan"),
                RejectGuard("camera_id", restored_camera_ids, "orphan"),
            ],
        )

        # --- Camera views (user_id nullable → valid users) ---
        await restore_records(
            session,
            model_cls=CameraView,
            records=data.get("camera_views", []),
            result=result,
            resource="camera_views",
            dry_run=dry_run,
            overwrite=overwrite,
            force_org=organization_id,
            nullable_fks=[NullableFK("user_id", valid_user_ids)],
        )

        # --- Recording-schedule templates ---
        await restore_records(
            session,
            model_cls=RecordingScheduleTemplate,
            records=data.get("recording_schedule_templates", []),
            result=result,
            resource="recording_schedule_templates",
            dry_run=dry_run,
            overwrite=overwrite,
            force_org=organization_id,
        )

        if not dry_run:
            await session.flush()
        result.duration_sec = time.monotonic() - start
        return result


__all__ = ["CamerasBackupContributor"]

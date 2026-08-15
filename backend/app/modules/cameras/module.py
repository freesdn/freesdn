# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN Cameras Module - Main Module Class
==========================================

The Cameras module provides video surveillance functionality including
camera management, live streaming, recording playback, and PTZ control.
"""

import logging
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter

from app.modules.base import BaseModule, DeviceSource, ModuleCapability
from app.modules.manifest import (
    ModuleCategory,
    ModuleManifest,
    ModuleNavItem,
    ModulePermission,
    ModuleWidget,
)

logger = logging.getLogger(__name__)


async def _fabric_snapshot_handler(ctx: Any) -> Any:
    """Fabric handler for ``cameras.snapshot``.

    Captures a still JPEG from the camera (org-scoped, fail-closed) and brokers
    it as an ``image/jpeg`` artifact so a downstream storage operation (e.g. a
    TrueNAS ``store_blob``) can pick it up — the camera→storage vertical. Never
    raises: returns a normalized ``OperationResult`` for the executor.
    """
    from uuid import UUID

    from app.core.fabric.execution import OperationResult

    camera_raw = ctx.params.get("camera_id")
    if not camera_raw:
        return OperationResult.fail("cameras.snapshot requires 'camera_id'", "NO_TARGET")
    try:
        camera_id = UUID(str(camera_raw))
    except (ValueError, TypeError):
        return OperationResult.fail("invalid camera_id", "BAD_TARGET")
    if ctx.db is None:
        return OperationResult.fail("snapshot requires a DB session", "NO_DB")

    # get_snapshot lives on StreamService (it resolves the vendor adapter +
    # decrypts creds), NOT CameraService — the previous import was wrong, so the
    # operation always failed with "'CameraService' has no attribute
    # 'get_snapshot'" (swallowed into a failed result). The camera→snapshot→
    # store/notify vertical was dead at the snapshot step until this fix.
    from app.modules.cameras.service import StreamService

    svc = StreamService(ctx.db)
    try:
        data = await svc.get_snapshot(camera_id, organization_id=ctx.organization_id)
    except Exception as exc:  # noqa: BLE001 — normalize for the executor
        return OperationResult.fail(f"snapshot failed: {exc}", "SNAPSHOT_FAILED")
    if not data:
        return OperationResult.fail("camera returned no snapshot", "NO_SNAPSHOT")

    if ctx.artifacts is None:
        # No broker (degraded): still report success with the captured size.
        return OperationResult.ok(output={"camera_id": str(camera_id), "size": len(data)})
    ref = await ctx.artifacts.put(data, "image/jpeg", ctx.organization_id)
    return OperationResult.ok(
        output={"camera_id": str(camera_id), "size": ref.size, "sha256": ref.sha256},
        artifact=ref,
    )


class CamerasModule(BaseModule):
    """
    Cameras Module for FreeSDN.

    Provides video surveillance capabilities including:
    - IP Camera management
    - NVR/DVR integration
    - Live streaming (RTSP/WebRTC)
    - Recording playback
    - PTZ control
    - Motion/event detection
    """

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        """Return the module manifest."""
        return ModuleManifest(
            id="cameras",
            name="Video Surveillance",
            version="1.0.0",
            description="IP camera management, live streaming, and recording playback",
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category=ModuleCategory.SURVEILLANCE,
            icon="video",
            color="#EF4444",  # Red
            # Dependencies
            dependencies=[],
            # Capabilities this module provides
            capabilities=[
                ModuleCapability.CAMERA_LIVE_VIEW,
                ModuleCapability.CAMERA_PLAYBACK,
                ModuleCapability.CAMERA_PTZ,
                ModuleCapability.CAMERA_EVENTS,
                ModuleCapability.NVR_MANAGEMENT,
            ],
            # Required capabilities from other modules
            required_capabilities=[],
            # Device types this module supports
            device_types=[
                "camera",
                "nvr",
                "dvr",
                "video_intercom",
            ],
            # Permissions
            permissions=[
                ModulePermission(
                    code="cameras.view",
                    name="View Cameras",
                    description="View camera list and live streams",
                    resource="camera",
                    action="read",
                ),
                ModulePermission(
                    code="cameras.manage",
                    name="Manage Cameras",
                    description="Add, edit, and remove cameras",
                    resource="camera",
                    action="update",
                ),
                ModulePermission(
                    code="cameras.ptz",
                    name="PTZ Control",
                    description="Control PTZ cameras",
                    resource="camera_ptz",
                    action="execute",
                ),
                ModulePermission(
                    code="cameras.playback",
                    name="View Recordings",
                    description="View recorded footage",
                    resource="recording",
                    action="read",
                ),
                ModulePermission(
                    code="cameras.export",
                    name="Export Recordings",
                    description="Download recorded footage",
                    resource="recording",
                    action="execute",
                ),
                ModulePermission(
                    code="cameras.nvr",
                    name="Manage NVRs",
                    description="Configure NVR/DVR devices",
                    resource="nvr",
                    action="update",
                ),
                ModulePermission(
                    code="cameras.access",
                    name="Manage Camera Access",
                    description="Grant and revoke per-camera user permissions",
                    resource="camera_access",
                    action="update",
                ),
            ],
            # Navigation items
            nav_items=[
                ModuleNavItem(
                    path="/cameras",
                    label="Cameras",
                    icon="video",
                    order=20,
                    permission="cameras.view",
                ),
                ModuleNavItem(
                    path="/cameras/live",
                    label="Live View",
                    icon="play",
                    order=1,
                    parent="/cameras",
                    permission="cameras.view",
                ),
                ModuleNavItem(
                    path="/cameras/list",
                    label="Camera List",
                    icon="list",
                    order=2,
                    parent="/cameras",
                    permission="cameras.view",
                ),
                ModuleNavItem(
                    path="/cameras/recordings",
                    label="Recordings",
                    icon="film",
                    order=3,
                    parent="/cameras",
                    permission="cameras.playback",
                ),
                ModuleNavItem(
                    path="/cameras/events",
                    label="Events",
                    icon="bell",
                    order=4,
                    parent="/cameras",
                    permission="cameras.view",
                ),
                ModuleNavItem(
                    path="/cameras/nvr",
                    label="NVR Management",
                    icon="hard-drive",
                    order=5,
                    parent="/cameras",
                    permission="cameras.nvr",
                ),
            ],
            # Dashboard widgets
            widgets=[
                ModuleWidget(
                    id="camera_grid",
                    name="Camera Grid",
                    description="Live view grid of selected cameras",
                    component="CameraGridWidget",
                    default_size="large",
                    refresh_interval=0,  # Real-time
                    permission="cameras.view",
                ),
                ModuleWidget(
                    id="camera_events",
                    name="Recent Events",
                    description="Recent motion and alert events",
                    component="CameraEventsWidget",
                    default_size="medium",
                    refresh_interval=30,
                    permission="cameras.view",
                ),
                ModuleWidget(
                    id="camera_status",
                    name="Camera Status",
                    description="Online/offline camera status summary",
                    component="CameraStatusWidget",
                    default_size="small",
                    refresh_interval=60,
                    permission="cameras.view",
                ),
            ],
            # Settings schema
            settings_schema={
                "type": "object",
                "properties": {
                    "stream_protocol": {
                        "type": "string",
                        "enum": ["rtsp", "hls", "webrtc"],
                        "default": "hls",
                        "description": "Default streaming protocol",
                    },
                    "snapshot_quality": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 80,
                        "description": "JPEG snapshot quality",
                    },
                    "motion_detection_enabled": {
                        "type": "boolean",
                        "default": True,
                        "description": "Enable motion detection events",
                    },
                    "recording_retention_days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 365,
                        "default": 30,
                        "description": "Days to retain recordings",
                    },
                },
            },
            # Default settings
            default_settings={
                "stream_protocol": "hls",
                "snapshot_quality": 80,
                "motion_detection_enabled": True,
                "recording_retention_days": 30,
            },
        )

    @property
    def manifest(self) -> ModuleManifest:
        """Return the module manifest."""
        return self.get_manifest()

    def get_router(self) -> APIRouter:
        """Return the FastAPI router for camera endpoints."""
        from app.modules.cameras.api import (
            access_router,
            discovery_router,
            event_router,
            evidence_router,
            group_router,
            hls_router,
            lpr_router,
            nvr_router,
            push_router,
            report_router,
            router,
            template_router,
            view_router,
        )

        # Create a parent router so sub-routers with specific prefixes
        # (/nvrs, /events, /groups, /views, /access, /streams/hls, /reports,
        # /lpr) are registered BEFORE the main camera router which has
        # /{camera_id} catch-all routes.
        parent = APIRouter()
        parent.include_router(nvr_router)
        parent.include_router(event_router)
        parent.include_router(group_router)
        parent.include_router(view_router)
        parent.include_router(template_router)
        parent.include_router(access_router)
        parent.include_router(hls_router)
        parent.include_router(report_router)
        parent.include_router(lpr_router)
        parent.include_router(push_router)
        parent.include_router(discovery_router)
        parent.include_router(evidence_router)
        parent.include_router(router)

        return parent

    def get_device_sources(self) -> list[DeviceSource]:
        """Declare NVRs as devices managed by this module."""
        from app.modules.cameras.models import NVR

        return [
            DeviceSource(
                model=NVR,
                device_type="nvr",
                external_id_prefix="nvr",
                status_map={"online": "online", "offline": "offline", "error": "error"},
                default_manufacturer="Hikvision",
            )
        ]

    def get_models(self) -> list[type]:
        """Return SQLAlchemy models for this module."""
        from app.modules.cameras.models import (
            NVR,
            Camera,
            CameraAccessGrant,
            CameraEvent,
            CameraGroup,
            CameraGroupMember,
            CameraHealthSnapshot,
            CameraReport,
            CameraView,
            Recording,
            RecordingScheduleTemplate,
        )

        return [
            Camera,
            NVR,
            Recording,
            CameraEvent,
            CameraGroup,
            CameraGroupMember,
            CameraView,
            CameraAccessGrant,
            CameraHealthSnapshot,
            RecordingScheduleTemplate,
            CameraReport,
        ]

    def get_tasks(self) -> dict[str, Callable[..., Any]]:
        """Return Celery tasks for this module."""
        return {}

    def get_operations(self):  # type: ignore[no-untyped-def]
        """Fabric operations this module offers as wiring targets.

        ``cameras.snapshot`` is the reference read-operation that *produces* an
        image artifact, which the negotiator can hand to a storage target (the
        camera→TrueNAS vertical). Its handler captures the frame org-scoped and
        brokers it as an ``image/jpeg`` artifact.
        """
        from app.core.fabric.operations import Operation, OperationTier

        return [
            Operation(
                id="cameras.snapshot",
                title="Capture camera snapshot",
                description="Grab a still JPEG frame from a camera channel.",
                input_schema={
                    "type": "object",
                    "properties": {"camera_id": {"type": "string", "format": "uuid"}},
                    "required": ["camera_id"],
                },
                produces=("image/jpeg",),
                permission="cameras.view",
                write=False,
                handler=_fabric_snapshot_handler,
                tier=OperationTier.NATIVE,
                provider_id="cameras",
            ),
        ]

    def get_emitted_events(self):  # type: ignore[no-untyped-def]
        """Fabric event sources (triggers) this module emits.

        The ``camera.alert.*`` triggers are built from the canonical taxonomy in
        ``event_types.py`` — the SAME source the ingest dispatch gate uses — so
        the advertised automation triggers can never drift from what actually
        fires on the bus (a drift the previous hard-coded ``cameras.event.*``
        declarations suffered: they were advertised but never published).
        """
        from app.core.fabric.operations import EventSpec, OperationTier
        from app.modules.cameras.event_types import ALERT_EVENT_META

        # Payload shape published by tasks/cameras._dispatch_alerts.
        _alert_payload = {
            "type": "object",
            "properties": {
                "camera_id": {"type": "string"},
                "camera_name": {"type": "string"},
                "nvr_id": {"type": "string"},
                "nvr_name": {"type": "string"},
                "site_id": {"type": "string"},
                "event_type": {"type": "string"},
                "timestamp": {"type": "string"},
            },
        }
        _status_payload = {
            "type": "object",
            "properties": {
                "camera_id": {"type": "string"},
                "site_id": {"type": "string"},
            },
        }

        specs = [
            # Smart-detection alerts → first-class automation triggers. Each can
            # carry a freshly-captured snapshot (produces image/jpeg) so the
            # negotiator can wire "<alert> → cameras.snapshot → notify/store".
            EventSpec(
                event_type=f"camera.alert.{canonical}",
                title=title,
                description=description,
                payload_schema=_alert_payload,
                produces=("image/jpeg",),
                tier=OperationTier.NATIVE,
                provider_id="cameras",
            )
            for canonical, (title, description) in ALERT_EVENT_META.items()
        ]
        specs.extend(
            [
                EventSpec(
                    event_type="camera.status.online",
                    title="Camera came online",
                    description="A camera transitioned to reachable/online.",
                    payload_schema=_status_payload,
                    tier=OperationTier.NATIVE,
                    provider_id="cameras",
                ),
                EventSpec(
                    event_type="camera.status.offline",
                    title="Camera went offline",
                    description="A camera stopped responding (lost connectivity).",
                    payload_schema=_status_payload,
                    tier=OperationTier.NATIVE,
                    provider_id="cameras",
                ),
            ]
        )
        return specs

    def get_backup_contributor(self):  # type: ignore[no-untyped-def]
        """Expose the Cameras portable-config contributor to the backup
        framework. See app/modules/cameras/backup.py for the
        captured/excluded scope (NVRs + channels + groups + views +
        schedule templates; NOT footage/events/telemetry/credentials)."""
        from app.modules.cameras.backup import CamerasBackupContributor

        return CamerasBackupContributor()

    async def on_load(self) -> None:
        """Called when module is loaded."""
        await super().on_load()
        logger.info("Cameras module loaded")

    async def on_unload(self) -> None:
        """Called when module is unloaded."""
        await super().on_unload()
        logger.info("Cameras module unloaded")

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Cameras Module Models
===================================

Database models for video surveillance.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin


class CameraStatus(StrEnum):
    """Camera connection status."""

    ONLINE = "online"
    OFFLINE = "offline"
    RECORDING = "recording"
    ERROR = "error"
    UNKNOWN = "unknown"


class CameraType(StrEnum):
    """Camera device type."""

    IP_CAMERA = "ip_camera"
    PTZ_CAMERA = "ptz_camera"
    DOORBELL = "doorbell"
    INTERCOM = "intercom"


class EventType(StrEnum):
    """Camera event types."""

    MOTION = "motion"
    LINE_CROSS = "line_cross"
    INTRUSION = "intrusion"
    FACE_DETECT = "face_detect"
    TAMPER = "tamper"
    VIDEO_LOSS = "video_loss"
    AUDIO_DETECT = "audio_detect"


class Camera(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    IP Camera device.
    """

    __tablename__ = "cameras"
    __table_args__ = (
        Index("ix_cameras_site_id", "site_id"),
        Index("ix_cameras_nvr_id", "nvr_id"),
        Index("ix_cameras_status", "status"),
        Index("ix_cameras_organization_id", "organization_id"),
        Index("ix_cameras_channel_id", "channel_id"),
        Index("ix_cameras_org_deleted", "organization_id", "deleted_at"),
        CheckConstraint(
            "status IN ('online','offline','recording','error','unknown','maintenance')",
            name="ck_cameras_status",
        ),
        CheckConstraint("port >= 1 AND port <= 65535", name="ck_cameras_port"),
        {"schema": "cameras"},
    )

    # Foreign Keys
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    nvr_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cameras.nvrs.id", ondelete="SET NULL"),
        nullable=True,
    )
    controller_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # NVR channel mapping (1, 2, 3, ... — NULL for standalone cameras)
    channel_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    camera_type: Mapped[str] = mapped_column(String(50), default=CameraType.IP_CAMERA.value)

    # Connection
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=554)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)

    # Device Info
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Streams
    rtsp_main_stream: Mapped[str | None] = mapped_column(String(500), nullable=True)
    rtsp_sub_stream: Mapped[str | None] = mapped_column(String(500), nullable=True)
    snapshot_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Adapter / credentials
    device_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    password_encrypted: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Capabilities
    has_ptz: Mapped[bool] = mapped_column(Boolean, default=False)
    has_audio: Mapped[bool] = mapped_column(Boolean, default=False)
    has_two_way_audio: Mapped[bool] = mapped_column(Boolean, default=False)
    has_ir: Mapped[bool] = mapped_column(Boolean, default=False)

    # Resolution
    resolution_width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolution_height: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Status
    status: Mapped[str] = mapped_column(String(20), default=CameraStatus.UNKNOWN.value)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_recording: Mapped[bool] = mapped_column(Boolean, default=False)

    # Settings
    motion_detection_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Location
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    floor: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Relationships
    nvr: Mapped["NVR | None"] = relationship("NVR", back_populates="cameras", lazy="raise")
    events: Mapped[list["CameraEvent"]] = relationship(
        "CameraEvent", back_populates="camera", lazy="raise"
    )


class NVR(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Network Video Recorder device.
    """

    __tablename__ = "nvrs"
    __table_args__ = (
        Index("ix_nvrs_site_id", "site_id"),
        Index("ix_nvrs_status", "status"),
        Index("ix_nvrs_organization_id", "organization_id"),
        Index("ix_nvrs_org_deleted", "organization_id", "deleted_at"),
        # Partial unique PER ORG: an NVR serial is unique within an
        # organization (matches the org-scoped duplicate check in import_nvr).
        # Was global (external_device_id alone), which crashed cross-org imports
        # of the same physical device — two tenants may legitimately register
        # the same serial. Still partial so re-import after soft-delete works.
        Index(
            "uq_nvrs_org_external_device_id_active",
            "organization_id",
            "external_device_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL AND external_device_id IS NOT NULL"),
        ),
        CheckConstraint(
            "status IN ('online','offline','recording','error','unknown','maintenance')",
            name="ck_nvrs_status",
        ),
        CheckConstraint("port >= 1 AND port <= 65535", name="ck_nvrs_port"),
        {"schema": "cameras"},
    )

    # Foreign Keys
    site_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    controller_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.controllers.id", ondelete="SET NULL"),
        nullable=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Connection
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=80)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)

    # Device Info
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Adapter / credentials
    device_type: Mapped[str] = mapped_column(String(50), default="hikvision")
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    password_encrypted: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # External device ID from ISAPI deviceInfo (for idempotent import)
    external_device_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Capacity
    channel_count: Mapped[int] = mapped_column(Integer, default=0)
    storage_total_gb: Mapped[float | None] = mapped_column(Float, nullable=True)
    storage_used_gb: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Status
    status: Mapped[str] = mapped_column(String(20), default=CameraStatus.UNKNOWN.value)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Settings
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Relationships
    cameras: Mapped[list["Camera"]] = relationship("Camera", back_populates="nvr", lazy="raise")


class Recording(Base, UUIDMixin):
    """
    Video recording segment.
    """

    __tablename__ = "recordings"
    __table_args__ = (
        Index("ix_recordings_camera_id", "camera_id"),
        Index("ix_recordings_nvr_id", "nvr_id"),
        Index("ix_recordings_start_time", "start_time"),
        Index("ix_recordings_camera_time", "camera_id", "start_time"),
        Index("ix_recordings_org_id", "organization_id"),
        CheckConstraint(
            "recording_type IN ('continuous','motion','manual','alarm','event')",
            name="ck_recordings_type",
        ),
        {"schema": "cameras"},
    )

    # Tenant isolation (denormalized from Camera for direct scoping)
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Foreign Keys
    camera_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cameras.cameras.id", ondelete="CASCADE"),
        nullable=False,
    )
    nvr_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cameras.nvrs.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Time Range
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # File Info
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    file_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Type
    recording_type: Mapped[str] = mapped_column(
        String(20), default="continuous"
    )  # continuous, motion, manual

    # Status
    is_locked: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    nvr: Mapped["NVR | None"] = relationship("NVR", lazy="raise")


class CameraEvent(Base, UUIDMixin):
    """
    Camera event (motion, alert, etc.).
    """

    __tablename__ = "camera_events"
    __table_args__ = (
        Index("ix_camera_events_camera_id", "camera_id"),
        Index("ix_camera_events_event_type", "event_type"),
        Index("ix_camera_events_timestamp", "timestamp"),
        Index("ix_camera_events_org_id", "organization_id"),
        # list_events / count_events scope via the Camera JOIN then ORDER BY
        # timestamp DESC + LIMIT — served by (camera_id, timestamp).
        Index("ix_camera_events_camera_ts", "camera_id", "timestamp"),
        # the daily report counts CameraEvent.organization_id + timestamp directly.
        Index("ix_camera_events_org_ts", "organization_id", "timestamp"),
        # the unacknowledged-count badge polls COUNT WHERE is_acknowledged=false
        # every 30s — a partial index keeps it a tiny index-only scan.
        Index(
            "ix_camera_events_unack",
            "organization_id",
            postgresql_where=text("is_acknowledged = false"),
        ),
        {"schema": "cameras"},
    )

    # Tenant isolation (denormalized from Camera for direct scoping)
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Foreign Keys
    camera_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cameras.cameras.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Event Info
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Details
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_path: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Metadata
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    # Status
    is_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    camera: Mapped["Camera"] = relationship("Camera", back_populates="events", lazy="raise")


class PushSubscription(Base, UUIDMixin):
    """A browser WebPush subscription (one per device/browser per user).

    General-purpose (any module can target a user/org), but currently driven by
    camera-alert ingestion. ``endpoint`` is the push service URL the browser
    handed us; ``p256dh``/``auth`` are the client keys used to encrypt payloads.
    Dead endpoints (404/410 on send) are pruned automatically.
    """

    __tablename__ = "push_subscriptions"
    __table_args__ = (
        UniqueConstraint("endpoint", name="uq_push_subscriptions_endpoint"),
        Index("ix_push_subscriptions_org", "organization_id"),
        Index("ix_push_subscriptions_user", "user_id"),
        {"schema": "cameras"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    p256dh: Mapped[str] = mapped_column(String(255), nullable=False)
    auth: Mapped[str] = mapped_column(String(255), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EvidenceArchive(Base, UUIDMixin):
    """A clip exported off the NVR to durable storage for legal hold / evidence.

    FreeSDN doesn't record, so footage lives on the NVR and is subject to its
    overwrite cycle — the ONLY reliable way to preserve a moment is to copy it
    out. This row tracks that copy: the time window, who held it, the on-disk
    file, its size, and a SHA-256 integrity hash so the export can be proven
    untampered later (chain-of-custody).
    """

    __tablename__ = "evidence_archives"
    __table_args__ = (
        Index("ix_evidence_org", "organization_id"),
        Index("ix_evidence_camera", "camera_id"),
        {"schema": "cameras"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    camera_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cameras.cameras.id", ondelete="CASCADE"),
        nullable=False,
    )
    camera_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    watermarked: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # pending | archiving | ready | failed
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    file_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("core.users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CameraGroup(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Camera group for organizing cameras into logical collections.
    """

    __tablename__ = "camera_groups"
    __table_args__ = (
        Index("ix_camera_groups_org", "organization_id"),
        {"schema": "cameras"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    color: Mapped[str] = mapped_column(String(7), default="#3b82f6")
    icon: Mapped[str] = mapped_column(String(50), default="folder")
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    members: Mapped[list["CameraGroupMember"]] = relationship(
        "CameraGroupMember", back_populates="group", cascade="all, delete-orphan"
    )


class CameraGroupMember(Base, UUIDMixin):
    """
    Association between a camera and a group.
    """

    __tablename__ = "camera_group_members"
    __table_args__ = (
        UniqueConstraint("group_id", "camera_id", name="uq_group_camera"),
        Index("ix_camera_group_members_group", "group_id"),
        Index("ix_camera_group_members_camera", "camera_id"),
        {"schema": "cameras"},
    )

    group_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cameras.camera_groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    camera_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cameras.cameras.id", ondelete="CASCADE"),
        nullable=False,
    )
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default="now()")

    # Relationships
    group: Mapped["CameraGroup"] = relationship("CameraGroup", back_populates="members")
    camera: Mapped["Camera"] = relationship("Camera")


class CameraView(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Custom camera view / layout configuration.
    Stores a selection of cameras with a layout for multi-view display.
    """

    __tablename__ = "camera_views"
    __table_args__ = (
        Index("ix_camera_views_org", "organization_id"),
        Index("ix_camera_views_user", "user_id"),
        {"schema": "cameras"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    layout: Mapped[str] = mapped_column(String(20), default="2x2")
    camera_ids: Mapped[list[Any]] = mapped_column(ARRAY(PGUUID(as_uuid=True)), default=list)
    filters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)


class CameraHealthSnapshot(Base, UUIDMixin):
    """
    Point-in-time health / bandwidth measurement for a camera channel.
    Periodically captured and used for sparklines & alerting.
    """

    __tablename__ = "camera_health_snapshots"
    __table_args__ = (
        Index("ix_camera_health_camera", "camera_id"),
        Index("ix_camera_health_ts", "captured_at"),
        Index("ix_camera_health_camera_ts", "camera_id", "captured_at"),
        Index("ix_camera_health_org_id", "organization_id"),
        # daily-report rollups count org-scoped snapshots in a time window
        Index("ix_camera_health_org_ts", "organization_id", "captured_at"),
        {"schema": "cameras"},
    )

    # Tenant isolation (denormalized from Camera for direct scoping)
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    camera_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cameras.cameras.id", ondelete="CASCADE"),
        nullable=False,
    )
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default="now()")

    # Stream metrics
    bitrate_kbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    frame_rate: Mapped[int | None] = mapped_column(Integer, nullable=True)
    codec: Mapped[str | None] = mapped_column(String(20), nullable=True)
    resolution_width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolution_height: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Availability
    is_online: Mapped[bool] = mapped_column(Boolean, default=True)

    # Time sync drift (seconds difference between device and server time)
    time_drift_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Relationships
    camera: Mapped["Camera"] = relationship("Camera", lazy="raise")


class RecordingScheduleTemplate(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Reusable recording schedule template.
    Stores a weekly schedule definition that can be applied to any camera/NVR channel.
    """

    __tablename__ = "recording_schedule_templates"
    __table_args__ = (
        Index("ix_rec_sched_org", "organization_id"),
        {"schema": "cameras"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)

    # 7-day schedule: JSON array of 7 objects, each with time_blocks
    # [ { "day": 0, "blocks": [{"start":"00:00","end":"23:59","type":"continuous"}] }, … ]
    schedule: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# Per-Camera Access Control
# ═══════════════════════════════════════════════════════════════════════════════


class CameraAccessLevel(StrEnum):
    """Granular camera permission level."""

    VIEWER = "viewer"  # Live view + snapshot only
    OPERATOR = "operator"  # + PTZ control + playback
    FULL = "full"  # + export + config changes


class CameraAccessGrant(Base, UUIDMixin, AuditMixin):
    """
    Per-camera or per-group access grant for a specific user.
    Supplements org-wide role-based permissions with fine-grained camera RBAC.

    When camera_id is set: grants access to a specific camera.
    When group_id is set: grants access to all cameras in that group.
    Exactly one of camera_id / group_id must be set (enforced by CHECK constraint).
    """

    __tablename__ = "camera_access_grants"
    __table_args__ = (
        UniqueConstraint("user_id", "camera_id", name="uq_camera_access_user_camera"),
        UniqueConstraint("user_id", "group_id", name="uq_camera_access_user_group"),
        CheckConstraint(
            "(camera_id IS NOT NULL AND group_id IS NULL) OR "
            "(camera_id IS NULL AND group_id IS NOT NULL)",
            name="ck_camera_access_target",
        ),
        CheckConstraint(
            "access_level IN ('viewer','operator','full')",
            name="ck_camera_access_level",
        ),
        Index("ix_camera_access_user", "user_id"),
        Index("ix_camera_access_camera", "camera_id"),
        Index("ix_camera_access_group", "group_id"),
        Index("ix_camera_access_org", "organization_id"),
        {"schema": "cameras"},
    )

    # Who
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=False,
    )

    # What (polymorphic: exactly one of camera_id / group_id)
    camera_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cameras.cameras.id", ondelete="CASCADE"),
        nullable=True,
    )
    group_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cameras.camera_groups.id", ondelete="CASCADE"),
        nullable=True,
    )

    # Permission level
    access_level: Mapped[str] = mapped_column(
        String(20),
        default=CameraAccessLevel.VIEWER,
        nullable=False,
    )

    # Granular permission flags (override access_level when explicitly set)
    can_live: Mapped[bool] = mapped_column(Boolean, default=True)
    can_playback: Mapped[bool] = mapped_column(Boolean, default=False)
    can_ptz: Mapped[bool] = mapped_column(Boolean, default=False)
    can_export: Mapped[bool] = mapped_column(Boolean, default=False)
    can_configure: Mapped[bool] = mapped_column(Boolean, default=False)

    # Scope
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Optional time-limited access (e.g., contractor has access for 30 days)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    camera: Mapped["Camera | None"] = relationship(
        "Camera",
        foreign_keys=[camera_id],
        lazy="raise",
    )
    group: Mapped["CameraGroup | None"] = relationship(
        "CameraGroup",
        foreign_keys=[group_id],
        lazy="raise",
    )


class CameraReport(Base, UUIDMixin):
    """
    Periodic camera system report (daily event summary, uptime %, etc.).
    Generated by Celery task and queryable via API.
    """

    __tablename__ = "camera_reports"
    __table_args__ = (
        Index("ix_camera_reports_org", "organization_id"),
        Index("ix_camera_reports_type", "report_type"),
        Index("ix_camera_reports_generated", "generated_at"),
        {"schema": "cameras"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    report_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # currently only "daily_summary" (data carries counts + 24h events + uptime%)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default="now()")
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

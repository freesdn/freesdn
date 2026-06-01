# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Remote Agent Models
=================================

Database models for remote site agents.
Agents enable network management at sites not directly
accessible from the FreeSDN server.

Tables:
- remote_agents: Agent registration and status
- agent_heartbeats: Time-series health data
- agent_tasks: Command queue for agents
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, LogBase, SoftDeleteMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Organization, Site, User


# =============================================================================
# Enums
# =============================================================================


class AgentType(StrEnum):
    """Agent deployment type."""

    SITE = "site"
    SCANNER = "scanner"
    COLLECTOR = "collector"
    GATEWAY = "gateway"


class AgentStatus(StrEnum):
    """Agent connection status."""

    ONLINE = "online"
    OFFLINE = "offline"
    CONNECTING = "connecting"
    ERROR = "error"
    MAINTENANCE = "maintenance"


class AgentTaskStatus(StrEnum):
    """Task execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentTaskType(StrEnum):
    """Types of tasks that can be assigned to agents."""

    SCAN_NETWORK = "scan_network"
    FINGERPRINT_DEVICE = "fingerprint_device"
    PROBE_API = "probe_api"
    EXECUTE_ACTION = "execute_action"
    PUSH_CONFIG = "push_config"
    BACKUP_CONFIG = "backup_config"
    UPDATE_CREDENTIALS = "update_credentials"
    COLLECT_METRICS = "collect_metrics"
    GET_DEVICE_STATUS = "get_device_status"
    UPDATE_AGENT = "update_agent"


# =============================================================================
# Remote Agent Model
# =============================================================================


class RemoteAgent(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Remote Agent - Represents a site agent installation.

    Agents run at remote sites and communicate with FreeSDN
    via WebSocket or REST polling to perform network operations.
    """

    __tablename__ = "remote_agents"
    __table_args__ = (
        # Partial unique: agent_key is unique only among LIVE agents, so a key can
        # be re-registered after an agent is soft-deleted (matches AgentSchedule).
        Index(
            "ix_remote_agents_agent_key",
            "agent_key",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_remote_agents_organization_id", "organization_id"),
        Index("ix_remote_agents_site_id", "site_id"),
        Index("ix_remote_agents_status", "status"),
        {"schema": "agents"},
    )

    # Identity
    agent_key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        # Uniqueness enforced by the partial index above (live rows only).
        comment="SHA-256 hash of the agent API key",
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Type & capabilities
    agent_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=AgentType.SITE,
    )
    version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(100), nullable=True)
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    supported_vendors: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Network info
    last_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    last_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Status
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=AgentStatus.OFFLINE,
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_heartbeat: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Offline-detection alert config (chapter 11).
    # NOTE: agent_schedules ALSO has a `notification_channels` column
    # for schedule-level (failure/new-device) alerts. Same JSONB shape;
    # this one drives offline alerts, that one drives run alerts.
    # When joining both tables, alias one to avoid SELECT ambiguity.
    notification_channels: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    offline_notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    # Threshold for "this agent is offline" — used by the periodic
    # detector. Default 180s = 3× the default 60s heartbeat interval.
    offline_threshold_seconds: Mapped[int] = mapped_column(
        Integer,
        default=180,
        nullable=False,
        server_default=text("180"),
    )

    # Uptime & stats
    uptime_seconds: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    connected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    disconnected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    total_connections: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tasks_executed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed_tasks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Polling
    poll_interval: Mapped[int] = mapped_column(
        Integer,
        default=30,
        nullable=False,
        comment="Polling interval in seconds",
    )

    # Approval flow
    is_approved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    approved_by_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=True,
    )

    site: Mapped["Site | None"] = relationship(
        "Site",
        foreign_keys=[site_id],
        lazy="selectin",
    )
    organization: Mapped["Organization | None"] = relationship(
        "Organization",
        foreign_keys=[organization_id],
        lazy="selectin",
    )
    approved_by: Mapped["User | None"] = relationship(
        "User",
        foreign_keys=[approved_by_id],
        lazy="selectin",
    )
    # NOTE: heartbeats live in LogDB (separate TimescaleDB instance).
    # No cross-DB ORM relationship — cleanup is handled explicitly in
    # soft_delete_agent() and the purge_orphan_heartbeats scheduled task.

    tasks: Mapped[list["AgentTask"]] = relationship(
        "AgentTask",
        back_populates="agent",
        cascade="all, delete-orphan",
        order_by="AgentTask.created_at.desc()",
    )


# =============================================================================
# Agent Heartbeat Model
# =============================================================================


class AgentHeartbeat(LogBase):
    """
    Agent Heartbeat - Time-series health telemetry from agents.

    Uses TimescaleDB hypertable for efficient time-series queries.
    Composite PK on (id, timestamp) for hypertable compatibility.
    """

    __tablename__ = "agent_heartbeats"
    __table_args__ = (
        Index("ix_agent_heartbeats_agent_timestamp", "agent_id", "timestamp"),
        {"schema": "agents"},
    )

    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    # Plain UUID — no real FK in LogDB (separate database).
    # Cleanup is handled by soft_delete_agent() and purge_orphan_heartbeats().
    agent_id: Mapped[UUID] = mapped_column(nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        primary_key=True,
    )

    # System metrics
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    memory_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    disk_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Status
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=AgentStatus.ONLINE,
    )
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    managed_devices: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    active_tasks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # NOTE: No back-reference to RemoteAgent — heartbeats live in LogDB,
    # agents live in the primary DB.  Cross-DB relationships are not possible.


# =============================================================================
# Agent Task Model
# =============================================================================


class AgentTask(Base, UUIDMixin):
    """
    Agent Task - Commands queued for agent execution.

    Agents poll for pending tasks and report progress/results.
    Supports priority queuing, retries, and progress tracking.
    """

    __tablename__ = "agent_tasks"
    __table_args__ = (
        Index("ix_agent_tasks_agent_status", "agent_id", "status"),
        Index("ix_agent_tasks_scheduled_at", "scheduled_at"),
        {"schema": "agents"},
    )

    agent_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.remote_agents.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Task definition
    task_type: Mapped[str] = mapped_column(String(100), nullable=False)
    task_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    priority: Mapped[int] = mapped_column(
        Integer,
        default=5,
        nullable=False,
        comment="Priority 1 (highest) to 10 (lowest)",
    )

    # Execution status
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default=AgentTaskStatus.PENDING,
    )
    progress: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Progress percentage 0-100",
    )
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Scheduling
    scheduled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Retry
    max_retries: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationship
    agent: Mapped["RemoteAgent"] = relationship(
        "RemoteAgent",
        back_populates="tasks",
    )


# =============================================================================
# Agent Release Model
# =============================================================================


class AgentRelease(Base, UUIDMixin):
    """
    Agent Release - Tracks published agent binaries.

    Stores metadata about each release so the frontend can display
    download links and agents can self-update.
    """

    __tablename__ = "agent_releases"
    __table_args__ = (
        Index("ix_agent_releases_platform_type_latest", "platform", "agent_type", "is_latest"),
        Index("ix_agent_releases_version", "version"),
        {"schema": "agents"},
    )

    version: Mapped[str] = mapped_column(String(50), nullable=False)
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    agent_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="daemon",
        comment="daemon or desktop",
    )
    download_url: Mapped[str] = mapped_column(String(500), nullable=False)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    release_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    min_backend_version: Mapped[str] = mapped_column(String(50), default="", nullable=False)
    is_latest: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_prerelease: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    download_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # ECDSA-P256 signature of the SHA-256 digest, base64 ASN.1 DER.
    # Generated by backend during upload; verified by agent before staging.
    # NULL on legacy rows uploaded before the signing chapter.
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Multi-tenant scope. NULL = legacy global release (super_admin only
    # mutates). Populated for all new uploads from the caller's org.
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    # Original filename of the uploaded binary. Used to build the
    # deterministic on-disk path; older rows are NULL and the download
    # endpoint falls back to a glob.
    filename: Mapped[str | None] = mapped_column(String(128), nullable=True)


class AgentSchedule(Base, UUIDMixin, SoftDeleteMixin):
    """
    Backend-managed scheduled scan definition.

    Agent already has a SchedulerService + cron parser; until this model
    schedules lived only in agent-local config.json. This row gets
    pushed to the relevant agent(s) via WS ``update_schedule`` command
    so the operator can manage all schedules from the control plane.

    `agent_id=NULL` means "all agents at this site". Backend pushes the
    matching subset to each agent on every WS connect + on every change.
    """

    __tablename__ = "agent_schedules"
    __table_args__ = (
        Index("ix_agent_schedules_site", "site_id"),
        Index("ix_agent_schedules_agent", "agent_id"),
        Index("ix_agent_schedules_org", "organization_id"),
        # Dedup (site_id, name) among non-deleted rows — mirrors migration 023.
        # Without it on the model, a non-alembic create_all() (fresh install via
        # scripts/migrate.py) would allow duplicate schedules per (site, name),
        # diverging from upgraded DBs and silently breaking the create-time 409
        # dedup. Name + predicate must match the migration exactly.
        Index(
            "uq_agent_schedules_dedup",
            "site_id",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        {"schema": "agents"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.remote_agents.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, default="quick")
    cron: Mapped[str] = mapped_column(String(64), nullable=False)
    targets: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        server_default=text("'[]'::jsonb"),
    )
    interface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_fired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Notification config — same JSONB shape as AlertRule.notification_channels,
    # routed through services.notification_helpers.dispatch_notifications.
    # Empty dict = no notifications. See migration 025 for the field
    # semantics.
    notification_channels: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    notify_on_failure: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    notify_on_new_devices: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    created_by: Mapped[UUID | None] = mapped_column(nullable=True)


class AgentScheduleRun(Base, UUIDMixin):
    """One execution record per scheduled scan firing.

    Inserted by the backend's WS scan_result handler when the report
    payload includes `schedule_name`. Lets the operator answer:
    "Did my schedule actually run last night, and what did it find?"
    """

    __tablename__ = "agent_schedule_runs"
    __table_args__ = (
        Index("ix_schedule_runs_schedule", "schedule_id", "started_at"),
        Index("ix_schedule_runs_agent", "agent_id"),
        {"schema": "agents"},
    )

    schedule_id: Mapped[UUID] = mapped_column(
        ForeignKey("agents.agent_schedules.id", ondelete="CASCADE"),
        nullable=False,
    )
    agent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("agents.remote_agents.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # completed | failed | running
    device_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

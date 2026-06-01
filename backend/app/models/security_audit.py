# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Security Audit Models
=====================================

SQLAlchemy models for the enhanced security audit module:
- AuditLogRecord: Persistent audit log entries
- SecurityEventRecord: Security events with risk scoring
- FailedLoginRecord: Failed login tracking for brute-force detection
- IPBlockRecord: IP address blocking
- SecurityAnomalyRecord: Detected security anomalies
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
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDMixin

if TYPE_CHECKING:
    pass


# =============================================================================
# Enums
# =============================================================================


class AuditActionType(StrEnum):
    """Audit action classification."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    EXPORT = "export"
    IMPORT = "import"
    APPROVE = "approve"
    REJECT = "reject"
    ENABLE = "enable"
    DISABLE = "disable"
    CONFIGURE = "configure"
    BACKUP = "backup"
    RESTORE = "restore"
    SCAN = "scan"
    DEPLOY = "deploy"
    REVOKE = "revoke"


class AuditResourceType(StrEnum):
    """Resource types for audit tracking."""

    USER = "user"
    ORGANIZATION = "organization"
    SITE = "site"
    DEVICE = "device"
    CONTROLLER = "controller"
    AGENT = "agent"
    VPN = "vpn"
    CERTIFICATE = "certificate"
    API_KEY = "api_key"
    ROLE = "role"
    PERMISSION = "permission"
    SETTING = "setting"
    BACKUP = "backup"
    MODULE = "module"
    ALERT = "alert"
    POLICY = "policy"
    SESSION = "session"


class SecuritySeverity(StrEnum):
    """Security event severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEventCategory(StrEnum):
    """Security event category."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    CONFIGURATION = "configuration"
    NETWORK = "network"
    SYSTEM = "system"
    COMPLIANCE = "compliance"
    ANOMALY = "anomaly"


class IPBlockReason(StrEnum):
    """Reason for IP blocking."""

    BRUTE_FORCE = "brute_force"
    RATE_LIMIT = "rate_limit"
    MANUAL = "manual"
    ANOMALY = "anomaly"
    GEO_RESTRICTION = "geo_restriction"


class AnomalyType(StrEnum):
    """Security anomaly types."""

    UNUSUAL_LOGIN_LOCATION = "unusual_login_location"
    UNUSUAL_LOGIN_TIME = "unusual_login_time"
    EXCESSIVE_FAILED_LOGINS = "excessive_failed_logins"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MASS_DATA_ACCESS = "mass_data_access"
    CONFIGURATION_TAMPERING = "configuration_tampering"
    API_ABUSE = "api_abuse"
    SESSION_HIJACKING = "session_hijacking"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    UNUSUAL_DEVICE_ACCESS = "unusual_device_access"


# =============================================================================
# Models
# =============================================================================


class AuditLogRecord(Base, UUIDMixin):
    """Persistent audit log entry stored in the database."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_timestamp", "timestamp"),
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_actor", "actor_id"),
        Index("ix_audit_logs_org", "organization_id"),
        Index("ix_audit_logs_status", "status"),
        # Tamper-evidence hash-chain index — mirrors migration 010 so a fresh
        # create_all() matches the upgraded schema (index-parity).
        Index("ix_audit_logs_row_hmac", "row_hmac", postgresql_where=text("row_hmac IS NOT NULL")),
        {"schema": "audit"},
    )

    # Timing
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    # Action
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(64))
    resource_name: Mapped[str | None] = mapped_column(String(255))

    # Actor
    actor_id: Mapped[str | None] = mapped_column(String(64))
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False, default="user")
    actor_name: Mapped[str | None] = mapped_column(String(255))
    actor_email: Mapped[str | None] = mapped_column(String(255))

    # Organization context
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL")
    )
    site_id: Mapped[UUID | None] = mapped_column(ForeignKey("core.sites.id", ondelete="SET NULL"))

    # Request context
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(Text)
    session_id: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    request_method: Mapped[str | None] = mapped_column(String(10))
    request_path: Mapped[str | None] = mapped_column(String(512))

    # Result
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="success")
    response_code: Mapped[int | None] = mapped_column(Integer)
    response_time_ms: Mapped[float | None] = mapped_column(Float)
    error_message: Mapped[str | None] = mapped_column(Text)

    # Change tracking
    changes: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    previous_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    new_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    # Metadata
    tags: Mapped[list[str] | None] = mapped_column(JSONB, default=list)
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSONB, default=dict)

    # Tamper-evidence chain.
    #
    # ``prev_hash``: hex digest of the previous (most-recent) row's
    # ``row_hmac``. NULL only for the genesis row.
    # ``row_hmac``:  HMAC-SHA256 of ``prev_hash || canonical_json(row)``
    # keyed by ``settings.AUDIT_HMAC_KEY``. NULL for rows written before
    # this column was added; the validator treats those as "unchained"
    # and reports them rather than failing the whole audit.
    #
    # Both columns are nullable in the schema for back-compat with rows
    # written before the migration ran. New rows always populate both.
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    row_hmac: Mapped[str | None] = mapped_column(String(64))


class SecurityEventRecord(Base, UUIDMixin):
    """Security event with risk scoring and review tracking."""

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_timestamp", "timestamp"),
        Index("ix_security_events_type", "event_type"),
        Index("ix_security_events_severity", "severity"),
        Index("ix_security_events_user", "user_id"),
        Index("ix_security_events_ip", "ip_address"),
        Index("ix_security_events_reviewed", "reviewed"),
        Index("ix_security_events_category", "category"),
        {"schema": "audit"},
    )

    # Timing
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    # Event classification
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False, default="system")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")

    # Subject
    user_id: Mapped[UUID | None] = mapped_column(ForeignKey("core.users.id", ondelete="SET NULL"))
    user_email: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(Text)

    # Outcome
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, default="success")

    # Risk assessment
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_factors: Mapped[list[str] | None] = mapped_column(JSONB, default=list)

    # Context
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, default=dict)
    source: Mapped[str | None] = mapped_column(String(50))
    geo_location: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    # Review workflow
    reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reviewed_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL")
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_notes: Mapped[str | None] = mapped_column(Text)

    # Organization context
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL")
    )


class FailedLoginRecord(Base, UUIDMixin):
    """Track failed login attempts for brute-force detection."""

    __tablename__ = "failed_logins"
    __table_args__ = (
        Index("ix_failed_logins_timestamp", "timestamp"),
        Index("ix_failed_logins_ip", "ip_address"),
        Index("ix_failed_logins_user", "username"),
        Index("ix_failed_logins_ip_time", "ip_address", "timestamp"),
        {"schema": "audit"},
    )

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(String(50), nullable=False, default="invalid_credentials")
    geo_location: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    request_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class IPBlockRecord(Base, UUIDMixin):
    """IP addresses blocked due to security events."""

    __tablename__ = "ip_blocks"
    __table_args__ = (
        Index("ix_ip_blocks_ip", "ip_address"),
        Index("ix_ip_blocks_active", "is_active"),
        Index("ix_ip_blocks_expires", "expires_at"),
        UniqueConstraint("ip_address", name="uq_ip_blocks_ip"),
        {"schema": "audit"},
    )

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    reason: Mapped[str] = mapped_column(String(30), nullable=False)
    blocked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Context
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blocked_username: Mapped[str | None] = mapped_column(String(255))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB, default=dict)

    # Unblock
    unblocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    unblocked_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL")
    )
    unblock_reason: Mapped[str | None] = mapped_column(Text)


class SecurityAnomalyRecord(Base, UUIDMixin):
    """Detected security anomalies."""

    __tablename__ = "security_anomalies"
    __table_args__ = (
        Index("ix_anomalies_timestamp", "detected_at"),
        Index("ix_anomalies_type", "anomaly_type"),
        Index("ix_anomalies_severity", "severity"),
        Index("ix_anomalies_resolved", "resolved"),
        {"schema": "audit"},
    )

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    anomaly_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")

    # Source
    user_id: Mapped[UUID | None] = mapped_column(ForeignKey("core.users.id", ondelete="SET NULL"))
    user_email: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))

    # Details
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSONB, default=dict)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=50)

    # Related events
    related_event_ids: Mapped[list[str] | None] = mapped_column(JSONB, default=list)

    # Resolution
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL")
    )
    resolution_notes: Mapped[str | None] = mapped_column(Text)

    # Organization context
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL")
    )

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Security Audit Schemas
======================================

Pydantic schemas for the enhanced security audit API endpoints.
Matches frontend types expected by SecurityPage.tsx, SecurityAuditPage.tsx,
and lib/api.ts securityAuditApi methods.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.security_audit import (
    IPBlockReason,
)

# =============================================================================
# Base
# =============================================================================


class BaseSchema(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


# =============================================================================
# Audit Log Schemas
# =============================================================================


class AuditLogResponse(BaseSchema):
    """Audit log entry response."""

    id: UUID
    timestamp: datetime
    action: str
    resource_type: str
    resource_id: str | None = None
    resource_name: str | None = None
    actor_id: str | None = None
    actor_type: str = "user"
    actor_name: str | None = None
    actor_email: str | None = None
    organization_id: UUID | None = None
    site_id: UUID | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    session_id: str | None = None
    request_id: str | None = None
    request_method: str | None = None
    request_path: str | None = None
    status: str = "success"
    response_code: int | None = None
    response_time_ms: float | None = None
    error_message: str | None = None
    changes: dict[str, Any] | None = None
    previous_state: dict[str, Any] | None = None
    new_state: dict[str, Any] | None = None
    tags: list[str] | None = None
    extra_metadata: dict[str, Any] | None = None


class AuditLogListResponse(BaseSchema):
    """Paginated audit log list."""

    items: list[AuditLogResponse]
    total: int
    page: int = 1
    page_size: int = 50
    has_more: bool = False


class AuditLogQuery(BaseSchema):
    """Query parameters for audit logs."""

    start_date: datetime | None = None
    end_date: datetime | None = None
    actions: list[str] | None = None
    resource_types: list[str] | None = None
    resource_id: str | None = None
    actor_id: str | None = None
    status: str | None = None
    search: str | None = None
    organization_id: UUID | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


# =============================================================================
# Security Event Schemas
# =============================================================================


class SecurityEventResponse(BaseSchema):
    """Security event response."""

    id: UUID
    timestamp: datetime
    event_type: str
    category: str = "system"
    severity: str = "info"
    user_id: UUID | None = None
    user_email: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    success: bool = True
    outcome: str = "success"
    risk_score: int = 0
    risk_factors: list[str] | None = None
    details: dict[str, Any] | None = None
    source: str | None = None
    geo_location: dict[str, Any] | None = None
    reviewed: bool = False
    reviewed_by: UUID | None = None
    reviewed_at: datetime | None = None
    review_notes: str | None = None
    organization_id: UUID | None = None


class SecurityEventListResponse(BaseSchema):
    """Paginated security event list."""

    items: list[SecurityEventResponse]
    total: int
    page: int = 1
    page_size: int = 50
    has_more: bool = False


class SecurityEventQuery(BaseSchema):
    """Query parameters for security events."""

    start_date: datetime | None = None
    end_date: datetime | None = None
    event_types: list[str] | None = None
    severities: list[str] | None = None
    categories: list[str] | None = None
    user_id: UUID | None = None
    ip_address: str | None = None
    success: bool | None = None
    reviewed: bool | None = None
    min_risk_score: int | None = None
    search: str | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class SecurityEventReview(BaseSchema):
    """Review a security event."""

    reviewed: bool = True
    review_notes: str | None = None


# =============================================================================
# Security Summary
# =============================================================================


class SecuritySummaryResponse(BaseSchema):
    """Security summary with aggregated counts."""

    total_events: int = 0
    failed_logins: int = 0
    successful_logins: int = 0
    account_lockouts: int = 0
    suspicious_activities: int = 0
    high_risk_events: int = 0
    critical_events: int = 0
    blocked_ips: int = 0
    active_anomalies: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_event_type: dict[str, int] = Field(default_factory=dict)
    period: dict[str, str] | None = None
    trend: dict[str, Any] | None = None


# =============================================================================
# IP Block Schemas
# =============================================================================


class IPBlockResponse(BaseSchema):
    """IP block entry response."""

    id: UUID
    ip_address: str
    reason: str
    blocked_at: datetime
    expires_at: datetime | None = None
    is_active: bool = True
    failed_attempts: int = 0
    blocked_username: str | None = None
    details: dict[str, Any] | None = None
    unblocked_at: datetime | None = None
    unblocked_by: UUID | None = None
    unblock_reason: str | None = None


class IPBlockCreate(BaseSchema):
    """Manually block an IP."""

    # Previously ``str`` with only a length cap — ``not-an-ip``,
    # ``"1.2.3.4'; DROP --"``, and other non-IP strings were happily
    # 201'd into the block table. The DB row is just data (queries
    # are parametrized so no SQLi) but it pollutes the block list +
    # the value gets compared against ``request.client.host`` in the
    # auth middleware. Validate at the schema layer.
    ip_address: str = Field(min_length=1, max_length=45)
    reason: str = IPBlockReason.MANUAL
    expires_at: datetime | None = None
    details: dict[str, Any] | None = None

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        import ipaddress

        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {v!r}") from exc
        return v


class IPBlockListResponse(BaseSchema):
    """Paginated IP block list."""

    items: list[IPBlockResponse]
    total: int
    page: int = 1
    page_size: int = 50


class IPActivityResponse(BaseSchema):
    """Activity summary for an IP address."""

    ip_address: str
    total_events: int = 0
    failed_logins: int = 0
    successful_logins: int = 0
    security_events: int = 0
    is_blocked: bool = False
    block_info: IPBlockResponse | None = None
    last_seen: datetime | None = None
    associated_users: list[str] = Field(default_factory=list)
    recent_events: list[SecurityEventResponse] = Field(default_factory=list)


# =============================================================================
# Failed Login Schemas
# =============================================================================


class FailedLoginResponse(BaseSchema):
    """Failed login attempt response."""

    id: UUID
    timestamp: datetime
    username: str
    ip_address: str
    user_agent: str | None = None
    reason: str = "invalid_credentials"
    geo_location: dict[str, Any] | None = None


class FailedLoginListResponse(BaseSchema):
    """Paginated failed login list."""

    items: list[FailedLoginResponse]
    total: int
    page: int = 1
    page_size: int = 50


# =============================================================================
# Anomaly Schemas
# =============================================================================


class SecurityAnomalyResponse(BaseSchema):
    """Security anomaly response."""

    id: UUID
    detected_at: datetime
    anomaly_type: str
    severity: str = "medium"
    user_id: UUID | None = None
    user_email: str | None = None
    ip_address: str | None = None
    title: str
    description: str | None = None
    evidence: dict[str, Any] | None = None
    risk_score: int = 50
    related_event_ids: list[str] | None = None
    resolved: bool = False
    resolved_at: datetime | None = None
    resolved_by: UUID | None = None
    resolution_notes: str | None = None
    organization_id: UUID | None = None


class SecurityAnomalyListResponse(BaseSchema):
    """Paginated anomaly list."""

    items: list[SecurityAnomalyResponse]
    total: int
    page: int = 1
    page_size: int = 50


class AnomalyResolve(BaseSchema):
    """Resolve an anomaly."""

    resolution_notes: str | None = None


# =============================================================================
# User Activity
# =============================================================================


class UserActivityResponse(BaseSchema):
    """Activity summary for a user."""

    user_id: UUID
    total_actions: int = 0
    login_count: int = 0
    failed_login_count: int = 0
    last_login: datetime | None = None
    last_activity: datetime | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    recent_events: list[SecurityEventResponse] = Field(default_factory=list)
    recent_actions: list[AuditLogResponse] = Field(default_factory=list)
    risk_summary: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Compliance Report
# =============================================================================


class ComplianceReportResponse(BaseSchema):
    """Compliance report data."""

    generated_at: datetime
    period_start: datetime
    period_end: datetime
    organization_id: UUID | None = None

    # Summary
    total_audit_entries: int = 0
    total_security_events: int = 0
    total_anomalies: int = 0
    total_ip_blocks: int = 0

    # Authentication
    login_summary: dict[str, Any] = Field(default_factory=dict)

    # Access control
    access_summary: dict[str, Any] = Field(default_factory=dict)

    # Configuration changes
    config_changes: int = 0

    # Data access
    data_access_summary: dict[str, Any] = Field(default_factory=dict)

    # Incidents
    incidents: list[dict[str, Any]] = Field(default_factory=list)

    # Compliance score (0-100)
    compliance_score: int = 0
    compliance_details: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Export
# =============================================================================


class SecurityExportRequest(BaseSchema):
    """Request to export security data."""

    export_type: str = "events"  # events, audit_logs, anomalies, compliance
    format: str = "csv"  # csv, json
    start_date: datetime | None = None
    end_date: datetime | None = None
    filters: dict[str, Any] | None = None
    max_rows: int = Field(default=10000, ge=1, le=100000)


class SecurityExportResponse(BaseSchema):
    """Export response with download info."""

    filename: str
    content_type: str
    row_count: int
    size_bytes: int

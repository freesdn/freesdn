# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Remote Agent Pydantic Schemas
============================================

Request/Response schemas for remote agent management.
"""

import ipaddress
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.agents import AgentStatus, AgentTaskStatus, AgentTaskType, AgentType
from app.schemas.discovery import (
    MAX_SCAN_HOSTS_TOTAL,
    _estimate_target_hosts,
    _reject_unsafe_scan_ip,
    _validate_scan_target,
)

# =============================================================================
# Base
# =============================================================================


class BaseSchema(BaseModel):
    """Base schema with common configuration."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


class TimestampSchema(BaseSchema):
    """Schema with timestamp fields."""

    created_at: datetime
    updated_at: datetime


# =============================================================================
# Agent Registration
# =============================================================================


class AgentRegisterRequest(BaseSchema):
    """Request to register a new agent."""

    name: str = Field(min_length=1, max_length=255)
    site_id: UUID
    # ``description`` was unbounded text; a 100 KB description
    # previously bubbled to a 500 (DB column overflow). Cap at 2000.
    description: str | None = Field(None, max_length=2000)
    agent_type: AgentType = AgentType.SITE


class AgentRegisterResponse(BaseSchema):
    """One-time response containing credentials."""

    agent_id: str = Field(description="UUID of the registered agent")
    agent_key: str = Field(description="One-time API key - store securely")
    websocket_url: str = Field(description="WebSocket endpoint for agent connection")
    instructions: str = Field(description="Setup instructions")


# =============================================================================
# Agent CRUD
# =============================================================================


class AgentUpdateRequest(BaseSchema):
    """Request to update agent configuration."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    is_enabled: bool | None = None
    config: dict[str, Any] | None = None
    poll_interval: int | None = Field(None, ge=10, le=3600)
    # Offline-detection alert config (chapter 11). None means "leave
    # unchanged"; pass {} to clear.
    notification_channels: dict[str, Any] | None = None
    offline_threshold_seconds: int | None = Field(None, ge=60, le=86400)

    @field_validator("config")
    @classmethod
    def _config_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return v
        import json as _json

        size = len(_json.dumps(v, default=str).encode("utf-8"))
        if size > 16 * 1024:
            raise ValueError(f"config exceeds 16384 bytes (got {size})")
        return v


class AgentResponse(TimestampSchema):
    """Full agent response."""

    id: UUID
    name: str
    description: str | None
    agent_type: AgentType
    version: str | None
    platform: str | None
    capabilities: dict[str, Any]
    supported_vendors: list[str]
    config: dict[str, Any]

    # Network
    last_ip: str | None
    last_hostname: str | None

    # Status
    status: AgentStatus
    last_seen: datetime | None
    last_heartbeat: datetime | None

    # Stats
    uptime_seconds: int
    connected_at: datetime | None
    disconnected_at: datetime | None
    total_connections: int
    total_tasks_executed: int
    failed_tasks: int

    # Configuration
    poll_interval: int
    is_approved: bool
    approved_at: datetime | None
    is_enabled: bool

    # Relations
    site_id: UUID | None
    organization_id: UUID | None
    site_name: str | None = None
    organization_name: str | None = None
    approved_by_name: str | None = None

    # Offline-detection
    notification_channels: dict[str, Any] = Field(default_factory=dict)
    offline_threshold_seconds: int = 180
    offline_notified_at: datetime | None = None


class AgentSummary(BaseSchema):
    """Minimal agent summary for lists."""

    id: UUID
    name: str
    agent_type: AgentType
    status: AgentStatus
    last_ip: str | None
    last_heartbeat: datetime | None
    site_id: UUID | None
    site_name: str | None = None
    is_approved: bool
    is_enabled: bool


class AgentStatsResponse(BaseSchema):
    """Aggregate agent statistics."""

    total: int = 0
    online: int = 0
    offline: int = 0
    error: int = 0
    pending_approval: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_platform: dict[str, int] = Field(default_factory=dict)


# =============================================================================
# Heartbeats
# =============================================================================


class HeartbeatCreate(BaseSchema):
    """Heartbeat report from agent."""

    cpu_percent: float = Field(ge=0, le=100)
    memory_percent: float = Field(ge=0, le=100)
    disk_percent: float = Field(ge=0, le=100)
    status: AgentStatus = AgentStatus.ONLINE
    latency_ms: float | None = None
    managed_devices: int = 0
    active_tasks: int = 0


class HeartbeatResponse(BaseSchema):
    """Heartbeat response."""

    id: UUID
    agent_id: UUID
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    status: str
    latency_ms: float | None
    managed_devices: int
    active_tasks: int


# =============================================================================
# Agent Tasks
# =============================================================================


class TaskCreate(BaseSchema):
    """Create a task for an agent."""

    task_type: AgentTaskType
    task_data: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=5, ge=1, le=10)
    scheduled_at: datetime | None = None
    max_retries: int = Field(default=3, ge=0, le=10)


class TaskUpdate(BaseSchema):
    """Update task status (agent reports progress/completion)."""

    status: AgentTaskStatus | None = None
    progress: int | None = Field(None, ge=0, le=100)
    result: dict[str, Any] | None = None
    error_message: str | None = None


class TaskResponse(BaseSchema):
    """Task response."""

    id: UUID
    agent_id: UUID
    task_type: str
    task_data: dict[str, Any]
    priority: int
    status: AgentTaskStatus
    progress: int
    result: dict[str, Any] | None
    error_message: str | None
    scheduled_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    max_retries: int
    retry_count: int
    created_at: datetime
    updated_at: datetime


# =============================================================================
# Interactive scan (web-UI triggered, WS-push dispatched)
# =============================================================================


class InteractiveScanRequest(BaseSchema):
    """Operator-triggered network scan via WS push.

    Validates against the agent's advertised ``capabilities.scan_types``
    before dispatch (so we don't queue a ``camera`` scan against an
    agent that lacks scapy).
    """

    scan_type: str = Field(
        default="quick",
        max_length=32,
        description=(
            "Scanner family — quick / full / voip / iot / port / "
            "windows / camera. Server-side validated against the "
            "agent's capabilities."
        ),
    )
    targets: list[str] | None = Field(
        default=None,
        max_length=256,
        description=(
            "Optional CIDR / host list. When omitted, the agent scans its auto-detected interfaces."
        ),
    )
    timeout_seconds: int = Field(default=300, ge=10, le=1800)

    @field_validator("targets")
    @classmethod
    def _validate_targets(cls, v: list[str] | None) -> list[str] | None:
        """validate every target via the same SSRF/size guards used
        by the discovery AgentScanRequest, and enforce the aggregate host-count
        cap so a batch of /16 CIDRs can't DoS the scanner."""
        if v is None:
            return v
        validated = [_validate_scan_target(t) for t in v]
        total = sum(_estimate_target_hosts(t) for t in validated)
        if total > MAX_SCAN_HOSTS_TOTAL:
            raise ValueError(
                f"total hosts across targets exceeds {MAX_SCAN_HOSTS_TOTAL} "
                f"(currently: {total}). Break your scan into smaller batches."
            )
        return validated


class InteractiveScanResponse(BaseSchema):
    """Returned immediately after the scan command is dispatched."""

    task_id: UUID
    agent_id: UUID
    scan_type: str
    status: AgentTaskStatus
    dispatched_at: datetime
    message: str


class AgentFingerprintRequest(BaseSchema):
    """Typed body for /{agent_id}/fingerprint.

    Replaces the untyped ``dict[str, Any]`` body to enforce that
    ``ip_address`` is a syntactically valid, single, routable IP (not a
    CIDR block or range) and is not an SSRF-sensitive address.
    """

    ip_address: str = Field(..., max_length=64, description="Single IP address to fingerprint")

    @field_validator("ip_address")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ip_address must be a non-empty string")
        # Reject CIDR notation — fingerprint operates on a single host only.
        if "/" in v:
            raise ValueError("ip_address must be a single IP, not a CIDR block")
        # Reject hyphen range notation.
        if "-" in v:
            raise ValueError("ip_address must be a single IP, not a range")
        try:
            ip = ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"invalid ip_address {v!r}: {exc}") from exc
        _reject_unsafe_scan_ip(ip)
        return str(ip)


# =============================================================================
# Agent Authentication
# =============================================================================


class AgentAuthRequest(BaseSchema):
    """Agent authentication verify request."""

    agent_id: str
    agent_key: str


class AgentAuthResponse(BaseSchema):
    """Agent authentication result."""

    valid: bool
    agent_id: str | None = None
    site_id: str | None = None
    message: str = ""


# =============================================================================
# WebSocket Messages
# =============================================================================


class AgentWebSocketAuth(BaseSchema):
    """WebSocket authentication message from agent."""

    agent_key: str
    site_id: str


class AgentCommandMessage(BaseSchema):
    """Command message sent to agent via WebSocket."""

    id: str
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = None
    priority: int = 5
    timeout_seconds: float = 30.0

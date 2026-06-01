# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Enterprise Schemas
=================================

Pydantic request/response models for enterprise config management:
Site Groups, Device Groups, Config Templates, Device Config,
Lifecycle, Health Scores.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# ==========================================================================
# Site Groups
# ==========================================================================


class SiteGroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1024)
    parent_id: UUID | None = None


class SiteGroupUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1024)
    parent_id: UUID | None = None


class SiteGroupResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    description: str | None
    parent_id: UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ==========================================================================
# Device Groups
# ==========================================================================

# Same 64 KB cap rationale as ConfigTemplate.config — see _validate_config_size.
_MAX_MATCH_RULES_BYTES = 64 * 1024


def _validate_match_rules_size(v: dict[str, Any] | None) -> dict[str, Any] | None:
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > _MAX_MATCH_RULES_BYTES:
        raise ValueError(
            f"match_rules exceeds {_MAX_MATCH_RULES_BYTES} bytes (got {size})",
        )
    return v


class DeviceGroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1024)
    site_id: UUID
    match_rules: dict[str, Any] = Field(default_factory=dict)

    @field_validator("match_rules")
    @classmethod
    def _match_rules_size_limit(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_match_rules_size(v) or {}


class DeviceGroupUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1024)
    match_rules: dict[str, Any] | None = None
    is_active: bool | None = None
    # the edit dialog let users change the site, but the field
    # was absent from this schema so the PATCH silently ignored it.
    site_id: UUID | None = None

    @field_validator("match_rules")
    @classmethod
    def _match_rules_size_limit(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_match_rules_size(v)


class DeviceGroupResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    name: str
    description: str | None
    match_rules: dict[str, Any]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ==========================================================================
# Device Tags
# ==========================================================================


class DeviceTagsUpdate(BaseModel):
    """Set tags for a device (replaces all existing tags)."""

    tags: list[str] = Field(..., max_length=50)


class DeviceTagsResponse(BaseModel):
    device_id: UUID
    tags: list[str]


# ==========================================================================
# Config Templates
# ==========================================================================

# Hard cap on the serialised size of a template's ``config`` dict.
# The request body middleware caps at 1 MB but a single template at
# ~999 KB times N templates is still a DB-bloat path; 64 KB per template
# is comfortable for any real config tree and ~1 page of devices'-worth
# of overrides.
_MAX_CONFIG_BYTES = 64 * 1024


def _validate_config_size(v: dict[str, Any] | None) -> dict[str, Any] | None:
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > _MAX_CONFIG_BYTES:
        raise ValueError(
            f"config exceeds {_MAX_CONFIG_BYTES} bytes (got {size})",
        )
    return v


class ConfigTemplateCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1024)
    scope: str = Field(..., pattern=r"^(organization|site_group|site|device_group)$")
    scope_id: UUID | None = None
    device_type: str | None = Field(None, max_length=64)
    config: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=100, ge=0, le=999)

    @field_validator("config")
    @classmethod
    def _config_size_limit(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_config_size(v) or {}


class ConfigTemplateUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1024)
    scope: str | None = Field(None, pattern=r"^(organization|site_group|site|device_group)$")
    scope_id: UUID | None = None
    device_type: str | None = Field(None, max_length=64)
    config: dict[str, Any] | None = None
    priority: int | None = Field(None, ge=0, le=999)
    is_active: bool | None = None

    @field_validator("config")
    @classmethod
    def _config_size_limit(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_config_size(v)


class ConfigTemplateResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    description: str | None
    scope: str
    scope_id: UUID | None
    device_type: str | None
    config: dict[str, Any]
    priority: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ==========================================================================
# Device Config (Three-State)
# ==========================================================================


class DeviceConfigResponse(BaseModel):
    device_id: UUID
    organization_id: UUID
    desired_config: dict[str, Any]
    pushed_config: dict[str, Any]
    running_config: dict[str, Any]
    desired_updated_at: datetime | None
    pushed_at: datetime | None
    push_result: str | None
    push_error: str | None
    running_synced_at: datetime | None
    has_drift: bool
    drift_details: dict[str, Any] | None
    drift_detected_at: datetime | None
    drift_acknowledged: bool
    auto_remediate: bool
    config_version: int
    device_overrides: dict[str, Any]

    model_config = {"from_attributes": True}


class DeviceConfigOverridesUpdate(BaseModel):
    """Update per-device config overrides."""

    device_overrides: dict[str, Any]

    @field_validator("device_overrides")
    @classmethod
    def _device_overrides_size_limit(cls, v: dict[str, Any]) -> dict[str, Any]:
        # Same 64 KB cap as ConfigTemplate.config / DeviceGroup.match_rules —
        # the per-device override blob is JSONB and was previously unbounded
        # below the 1 MB body cap, a DB-bloat path. See _validate_config_size.
        return _validate_config_size(v) or {}


class DeviceConfigSettingsUpdate(BaseModel):
    """Update device config settings (auto_remediate, acknowledge drift, etc.)."""

    auto_remediate: bool | None = None
    drift_acknowledged: bool | None = None


class ResolvedConfigResponse(BaseModel):
    """The fully resolved desired_config from template hierarchy."""

    device_id: UUID
    resolved_config: dict[str, Any]
    template_chain: list[str] = Field(
        default_factory=list,
        description="Names of templates applied, in order",
    )


# ==========================================================================
# Device Lifecycle
# ==========================================================================


class LifecycleTransitionRequest(BaseModel):
    # ``discovered`` is included so the FSM's "cancel adoption" edge
    # (adopting → discovered) is reachable through the API. Backend
    # FSM still enforces which transitions are legal from the current
    # state; this regex only enforces the type system.
    to_state: str = Field(
        ...,
        pattern=r"^(discovered|adopting|provisioning|managed|updating|offline|error|decommissioned|ignored)$",
    )
    # ``trigger`` writes to a String(30) column on DeviceLifecycleLog
    # and is then coerced to ``LifecycleTrigger`` in the route. Pin to
    # the enum values here so the validation error tells the caller
    # exactly which values are accepted instead of bubbling up as a
    # generic "Invalid lifecycle state transition" later.
    trigger: str = Field(
        default="user_action",
        pattern=r"^(user_action|auto_discovery|auto_reconcile|health_check|firmware_update|system|agent)$",
        max_length=30,
    )
    # ``error_message`` is rendered in the UI + persisted; cap so the
    # transition path can't be used to inflate Text-column storage
    # arbitrarily.
    error_message: str | None = Field(None, max_length=2048)
    # ``details`` is free-form JSONB — apply the same 64 KB cap we
    # already use for templates/correlation/SLA/site-groups.
    details: dict[str, Any] | None = None

    @field_validator("details")
    @classmethod
    def _details_size_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return v
        import json as _json

        size = len(_json.dumps(v, default=str).encode("utf-8"))
        if size > 64 * 1024:
            raise ValueError(f"details exceeds 65536 bytes (got {size})")
        return v


class LifecycleLogEntry(BaseModel):
    id: UUID
    device_id: UUID
    from_state: str
    to_state: str
    trigger: str
    triggered_by: UUID | None
    details: dict[str, Any] | None
    created_at: datetime

    model_config = {"from_attributes": True}


class DeviceLifecycleResponse(BaseModel):
    device_id: UUID
    lifecycle_state: str
    lifecycle_changed_at: datetime | None
    lifecycle_error: str | None


# ==========================================================================
# Device Health
# ==========================================================================


class DeviceHealthResponse(BaseModel):
    device_id: UUID
    organization_id: UUID
    site_id: UUID | None = None
    health_score: int
    health_status: str
    reachability_score: int | None
    latency_score: int | None
    drift_score: int | None
    error_score: int | None
    utilization_score: int | None
    firmware_score: int | None
    updated_at: datetime | None
    score_history: list[dict[str, Any]]

    model_config = {"from_attributes": True}


class SiteHealthSummary(BaseModel):
    site_id: UUID
    site_name: str
    device_count: int
    avg_health_score: float
    health_status: str
    healthy: int
    warning: int
    degraded: int
    critical: int
    uptime_percent: float | None = None


class OrgHealthSummary(BaseModel):
    organization_id: UUID
    site_count: int
    device_count: int
    avg_health_score: float
    health_status: str
    sites: list[SiteHealthSummary]


# ==========================================================================
# Reconciliation
# ==========================================================================


class ReconcileRequest(BaseModel):
    """Trigger reconciliation for a scope.

    ``scope_id`` is required for ``scope=device|site``; for
    ``scope=organization`` the endpoint always uses the caller's own
    organization (see ``trigger_reconciliation`` in
    ``api/v1/endpoints/enterprise.py``) so an explicit UUID adds no
    information. Making the field optional lets the FE omit it for
    the org-wide path instead of sending an all-zeros placeholder
    that pydantic could legitimately reject in the future.
    """

    scope: str = Field(..., pattern=r"^(device|site|organization)$")
    scope_id: UUID | None = None


class ReconcileResultResponse(BaseModel):
    total: int
    compliant: int
    drifted: int
    errors: int
    devices: list[dict[str, Any]]


# ==========================================================================
# Bulk Operations
# ==========================================================================


class BulkTarget(BaseModel):
    scope: str = Field(..., pattern=r"^(site|device_group|tag|device_list)$")
    scope_id: UUID | None = None
    # ``device_type`` is matched verbatim against ``Device.device_type``
    # (e.g. "switch", "access_point"); 64 chars covers every type we
    # actually support and rejects 1 MB JSONB-stuffing attempts at the
    # validation layer rather than after a global body cap.
    device_type: str | None = Field(None, max_length=64)
    tag: str | None = Field(None, max_length=128)
    # 500 devices in a single bulk op is already extreme — most real
    # ops target a tag or device_group. Previously a 10 000-UUID list
    # was 201'd straight into JSONB. Cap covers the worst legitimate
    # case without enabling DoS via target.device_ids.
    device_ids: list[UUID] | None = Field(None, max_length=500)


class RolloutStage(BaseModel):
    percent: int = Field(..., ge=1, le=100)
    # 24 h covers every staged rollout we actually run. Without a cap a
    # single stage could pin a Celery worker on ``asyncio.sleep`` for
    # MAXINT * 60 seconds.
    wait_minutes: int = Field(default=0, ge=0, le=1440)


class RolloutStrategy(BaseModel):
    strategy: str = Field(default="immediate", pattern=r"^(immediate|staged)$")
    # A real staged rollout uses 2-5 stages; 20 is generous enough for
    # canary-heavy workflows and blocks 10 000-element submissions that
    # would bloat the rollout_strategy JSONB on every job.
    stages: list[RolloutStage] | None = Field(None, max_length=20)
    failure_threshold_percent: int = Field(default=5, ge=1, le=100)
    rollback_on_failure: bool = True


class BulkOperationCreate(BaseModel):
    operation: str = Field(
        ...,
        pattern=r"^(push_config|reboot|firmware_update)$",
    )
    target: BulkTarget
    config: dict[str, Any] | None = None
    rollout: RolloutStrategy | None = None

    @field_validator("config")
    @classmethod
    def _config_size_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return v
        import json as _json

        size = len(_json.dumps(v, default=str).encode("utf-8"))
        # 256 KiB. The global 1 MiB body cap catches absolute outliers,
        # but config blobs that large are operator error anyway —
        # actual device configs are kilobytes.
        if size > 256 * 1024:
            raise ValueError(f"config exceeds 262144 bytes (got {size})")
        return v


class BulkOperationResponse(BaseModel):
    job_id: UUID
    operation: str
    status: str
    devices_total: int
    devices_completed: int = 0
    devices_failed: int = 0
    # ``devices_skipped`` is the path takes when site
    # permission was revoked between dispatch and execution. Without
    # exposing it the UI shows ghost-failures.
    devices_skipped: int = 0
    current_stage: int = 0
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None


# ==========================================================================
# Health Dashboard (expanded)
# ==========================================================================


class DeviceHealthDetail(DeviceHealthResponse):
    """Device health with device metadata for the health table."""

    device_name: str
    device_type: str
    ip_address: str | None = None
    site_name: str | None = None
    site_id: UUID | None = None


class DeviceHealthListResponse(BaseModel):
    devices: list[DeviceHealthDetail] = Field(default_factory=list)
    total: int = 0


class TopHealthIssue(BaseModel):
    device_id: UUID
    device_name: str
    device_type: str
    site_name: str | None = None
    site_id: UUID | None = None
    health_score: int
    health_status: str
    worst_component: str
    worst_component_score: int


class TopIssuesResponse(BaseModel):
    issues: list[TopHealthIssue] = Field(default_factory=list)


class InfraComponentHealth(BaseModel):
    name: str
    status: str  # "healthy", "degraded", "unhealthy"
    latency_ms: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class PlatformVersionInfo(BaseModel):
    """Platform/runtime version metadata for the System Info page.

    All fields except ``app_version`` are nullable — non-admin callers
    receive the public app version only; framework + DB versions are
    redacted to avoid handing CVE-target recon data to ordinary
    operators. See the ``is_admin`` gate in ``get_infrastructure_health``.
    """

    app_version: str
    python_version: str | None = None
    fastapi_version: str | None = None
    sqlalchemy_version: str | None = None
    pydantic_version: str | None = None
    cryptography_version: str | None = None
    node_version: str | None = None
    redis_version: str | None = None
    postgres_version: str | None = None


class InfrastructureHealthResponse(BaseModel):
    status: str
    uptime_seconds: float = 0
    components: list[InfraComponentHealth] = Field(default_factory=list)
    platform: PlatformVersionInfo | None = None


class ModuleHealthSummary(BaseModel):
    module: str
    device_count: int = 0
    avg_health_score: float = 0
    healthy: int = 0
    warning: int = 0
    degraded: int = 0
    critical: int = 0


# ==========================================================================
# Health Daily Snapshots (Feature 2)
# ==========================================================================


class HealthDailySnapshotResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID | None = None
    snapshot_date: date
    avg_health_score: float
    device_count: int
    healthy_count: int
    warning_count: int
    degraded_count: int
    critical_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


# ==========================================================================
# WAN Device Health (Feature 3)
# ==========================================================================


class WANDeviceHealth(BaseModel):
    device_id: UUID
    device_name: str
    device_type: str
    site_name: str | None = None
    ip_address: str | None = None
    health_score: int
    latency_score: int | None = None
    reachability_score: int | None = None
    utilization_score: int | None = None


# ==========================================================================
# Site Ranking (Feature 4)
# ==========================================================================


class SiteRanking(BaseModel):
    site_id: UUID
    site_name: str
    avg_health_score: float
    device_count: int
    uptime_percent: float | None = None
    trend: Literal["up", "down", "stable"] = "stable"
    trend_delta: float = 0.0

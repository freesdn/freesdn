# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SLA Monitoring Schemas
======================================

Pydantic request/response models for:
  - SLA Policies (CRUD)
  - SLA Breaches (query + acknowledge)
  - SLA Compliance snapshots
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# 64 KB cap on JSONB fields. Matches templates/correlation/site-group
# cap. Covers any real escalation chain + channel routing config.
_MAX_SLA_FIELD_BYTES = 64 * 1024


def _size_capped_jsonb(field_name: str, v: Any) -> Any:
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > _MAX_SLA_FIELD_BYTES:
        raise ValueError(
            f"{field_name} exceeds {_MAX_SLA_FIELD_BYTES} bytes (got {size})",
        )
    return v


# ==========================================================================
# SLA Policy
# ==========================================================================


class SLAThresholds(BaseModel):
    """Threshold definitions for an SLA policy."""

    health_score_min: float | None = Field(None, ge=0, le=100)
    uptime_percent_min: float | None = Field(None, ge=0, le=100)
    latency_ms_max: float | None = Field(None, ge=0)
    packet_loss_percent_max: float | None = Field(None, ge=0, le=100)
    client_satisfaction_min: float | None = Field(None, ge=0, le=100)
    error_rate_max: float | None = Field(None, ge=0, le=100)


class SLAPolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2048)
    scope: str = Field(
        "site", pattern=r"^(organization|site|site_group|device_group|ssid|camera|nvr)$"
    )
    scope_id: UUID | None = None
    scope_name: str | None = Field(None, max_length=255)
    thresholds: SLAThresholds
    evaluation_window_minutes: int = Field(15, ge=1, le=1440)
    breach_after_consecutive: int = Field(3, ge=1, le=100)
    warning_threshold_percent: float = Field(90.0, ge=50, le=100)
    notification_channels: dict[str, Any] | None = None
    escalation_policy: dict[str, Any] | None = None

    @field_validator("notification_channels")
    @classmethod
    def _channels_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _size_capped_jsonb("notification_channels", v)

    @field_validator("escalation_policy")
    @classmethod
    def _escalation_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _size_capped_jsonb("escalation_policy", v)


class SLAPolicyUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2048)
    status: str | None = Field(None, pattern=r"^(active|disabled|draft)$")
    scope: str | None = Field(
        None, pattern=r"^(organization|site|site_group|device_group|ssid|camera|nvr)$"
    )
    scope_id: UUID | None = None
    scope_name: str | None = Field(None, max_length=255)
    thresholds: SLAThresholds | None = None
    evaluation_window_minutes: int | None = Field(None, ge=1, le=1440)
    breach_after_consecutive: int | None = Field(None, ge=1, le=100)
    warning_threshold_percent: float | None = Field(None, ge=50, le=100)
    notification_channels: dict[str, Any] | None = None
    escalation_policy: dict[str, Any] | None = None

    @field_validator("notification_channels")
    @classmethod
    def _channels_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _size_capped_jsonb("notification_channels", v)

    @field_validator("escalation_policy")
    @classmethod
    def _escalation_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _size_capped_jsonb("escalation_policy", v)


class SLAPolicyResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    description: str | None
    status: str
    scope: str
    scope_id: UUID | None
    scope_name: str | None
    thresholds: dict[str, Any]
    evaluation_window_minutes: int
    breach_after_consecutive: int
    warning_threshold_percent: float
    notification_channels: dict[str, Any] | None
    escalation_policy: dict[str, Any] | None
    current_compliance_percent: float | None
    last_evaluated_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ==========================================================================
# SLA Breach
# ==========================================================================


class SLABreachResponse(BaseModel):
    id: UUID
    policy_id: UUID
    organization_id: UUID
    severity: str
    status: str
    violated_metric: str
    threshold_value: float
    actual_value: float
    deviation_percent: float
    started_at: datetime
    resolved_at: datetime | None
    acknowledged_at: datetime | None
    acknowledged_by: UUID | None
    duration_minutes: int | None
    context: dict[str, Any]
    notes: str | None

    model_config = {"from_attributes": True}


class SLABreachAcknowledge(BaseModel):
    notes: str | None = None


# ==========================================================================
# SLA Snapshot (compliance trend)
# ==========================================================================


class SLASnapshotResponse(BaseModel):
    id: UUID
    policy_id: UUID
    recorded_at: datetime
    compliance_percent: float
    metrics: dict[str, Any]
    in_breach: bool

    model_config = {"from_attributes": True}


# ==========================================================================
# List / Stats Responses
# ==========================================================================


class SLAPolicyListResponse(BaseModel):
    policies: list[SLAPolicyResponse]
    total: int


class SLABreachListResponse(BaseModel):
    breaches: list[SLABreachResponse]
    total: int


class SLAComplianceSummary(BaseModel):
    """Organization-wide SLA compliance overview."""

    total_policies: int
    active_policies: int
    active_breaches: int
    avg_compliance_percent: float | None
    worst_policy: SLAPolicyResponse | None
    breaches_last_24h: int
    compliance_trend: list[SLASnapshotResponse]

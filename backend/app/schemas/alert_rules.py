# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Alert Rules Engine Schemas
==========================================

Pydantic request/response models for:
  - Alert Rules (CRUD)
  - Alerts (list, acknowledge, resolve, suppress)
  - Evaluation trigger
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# ==========================================================================
# Alert Rules
# ==========================================================================

# Sized to leave headroom for non-trivial rules but reject 1 MB JSONB-
# stuffing on every write.
_JSONB_MAX_BYTES = 64 * 1024


def _validate_jsonb_size(name: str, v: dict[str, Any] | None) -> dict[str, Any] | None:
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > _JSONB_MAX_BYTES:
        raise ValueError(f"{name} exceeds {_JSONB_MAX_BYTES} bytes (got {size})")
    return v


class AlertCondition(BaseModel):
    """Flexible condition definition for alert rules."""

    metric: str | None = Field(None, max_length=128, description="Metric name for threshold rules")
    event_type: str | None = Field(
        None, max_length=128, description="Event type glob for pattern rules"
    )
    operator: str | None = Field(
        None, max_length=4, description="Comparison operator: >, <, >=, <=, ==, !="
    )
    value: float | None = Field(None, description="Threshold value")
    min_count: int | None = Field(
        None, ge=1, le=1_000_000, description="Minimum event count for pattern rules"
    )
    std_dev_threshold: float | None = Field(
        None, description="Std deviation threshold for anomaly rules"
    )
    # RESERVED: never evaluated by the service. If someone wires up
    # custom-rule evaluation later this MUST be parsed via a safe AST
    # visitor, never ``eval``/``exec`` — keep that contract.
    custom_expression: str | None = Field(
        None, max_length=2048, description="Reserved — must not be eval()'d"
    )


class AlertRuleCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = Field(None, max_length=2000)
    rule_type: str = Field("threshold", pattern=r"^(threshold|pattern|anomaly|custom)$")
    severity: str = Field("warning", pattern=r"^(info|warning|critical)$")
    conditions: dict[str, Any] = Field(..., description="Rule conditions as JSONB")
    scope: str = Field("organization", pattern=r"^(organization|site|device_group|device)$")
    # ``scope_ids`` were ``list[str]`` — accepted ``["not-a-uuid"]`` and
    # foreign-org UUIDs alike. Typed strictly + capped; the endpoint
    # additionally verifies every UUID belongs to the caller's org.
    scope_ids: list[UUID] | None = Field(None, max_length=200)
    device_types: list[str] | None = Field(None, max_length=20)
    check_interval_seconds: int = Field(300, ge=30, le=86400)
    for_duration_seconds: int = Field(0, ge=0, le=86400)
    cooldown_seconds: int = Field(300, ge=0, le=86400)
    auto_resolve: bool = True
    auto_resolve_after_seconds: int | None = Field(None, ge=60)
    notification_channels: dict[str, Any] = Field(default_factory=dict)
    notify_on_resolve: bool = True
    dedupe_window_seconds: int = Field(3600, ge=60, le=604800)
    tags: list[str] = Field(default_factory=list, max_length=50)
    extra_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("device_types")
    @classmethod
    def _device_types_items_capped(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for item in v:
            if len(item) > 64:
                raise ValueError("device_types item exceeds 64 chars")
        return v

    @field_validator("tags")
    @classmethod
    def _tags_items_capped(cls, v: list[str]) -> list[str]:
        for item in v:
            if len(item) > 64:
                raise ValueError("tag item exceeds 64 chars")
        return v

    @field_validator("conditions")
    @classmethod
    def _conditions_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_jsonb_size("conditions", v) or v

    @field_validator("notification_channels")
    @classmethod
    def _channels_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_jsonb_size("notification_channels", v) or v

    @field_validator("extra_metadata")
    @classmethod
    def _meta_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_jsonb_size("extra_metadata", v) or v


class AlertRuleUpdate(BaseModel):
    name: str | None = Field(None, max_length=255)
    description: str | None = Field(None, max_length=2000)
    status: str | None = Field(None, pattern=r"^(active|disabled|draft)$")
    rule_type: str | None = Field(None, pattern=r"^(threshold|pattern|anomaly|custom)$")
    severity: str | None = Field(None, pattern=r"^(info|warning|critical)$")
    conditions: dict[str, Any] | None = None
    scope: str | None = Field(None, pattern=r"^(organization|site|device_group|device)$")
    scope_ids: list[UUID] | None = Field(None, max_length=200)
    device_types: list[str] | None = Field(None, max_length=20)
    check_interval_seconds: int | None = Field(None, ge=30, le=86400)
    for_duration_seconds: int | None = Field(None, ge=0, le=86400)
    cooldown_seconds: int | None = Field(None, ge=0, le=86400)
    auto_resolve: bool | None = None
    auto_resolve_after_seconds: int | None = None
    notification_channels: dict[str, Any] | None = None
    notify_on_resolve: bool | None = None
    dedupe_window_seconds: int | None = Field(None, ge=60, le=604800)
    tags: list[str] | None = Field(None, max_length=50)
    extra_metadata: dict[str, Any] | None = None

    @field_validator("conditions")
    @classmethod
    def _conditions_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_jsonb_size("conditions", v)

    @field_validator("notification_channels")
    @classmethod
    def _channels_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_jsonb_size("notification_channels", v)

    @field_validator("extra_metadata")
    @classmethod
    def _meta_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_jsonb_size("extra_metadata", v)


class AlertRuleResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    description: str | None
    rule_type: str
    status: str
    severity: str
    conditions: dict[str, Any]
    scope: str
    scope_ids: list[str] | None
    device_types: list[str] | None
    check_interval_seconds: int
    for_duration_seconds: int
    cooldown_seconds: int
    auto_resolve: bool
    auto_resolve_after_seconds: int | None
    notification_channels: dict[str, Any]
    notify_on_resolve: bool
    dedupe_window_seconds: int
    tags: list[str]
    extra_metadata: dict[str, Any]
    last_evaluated_at: datetime | None
    last_fired_at: datetime | None
    fire_count: int
    is_system: bool
    created_at: datetime
    updated_at: datetime | None

    model_config = {"from_attributes": True}


class AlertRuleListResponse(BaseModel):
    rules: list[AlertRuleResponse]
    total: int


# ==========================================================================
# Alerts
# ==========================================================================


class AlertResponse(BaseModel):
    id: UUID
    organization_id: UUID
    rule_id: UUID
    site_id: UUID | None
    device_id: UUID | None
    severity: str
    title: str
    message: str
    details: dict[str, Any]
    status: str
    fired_at: datetime
    acknowledged_at: datetime | None
    acknowledged_by: UUID | None
    resolved_at: datetime | None
    resolved_by: UUID | None
    fingerprint: str
    occurrence_count: int
    last_occurrence_at: datetime
    suppressed: bool
    suppressed_until: datetime | None
    suppression_reason: str | None
    notifications_sent: int
    last_notified_at: datetime | None
    tags: list[str]
    extra_metadata: dict[str, Any]
    source: str | None
    created_at: datetime
    updated_at: datetime | None

    model_config = {"from_attributes": True}


class AlertListResponse(BaseModel):
    alerts: list[AlertResponse]
    total: int


class AlertAcknowledge(BaseModel):
    """Acknowledge an alert."""

    note: str | None = Field(None, max_length=1000)


class AlertResolve(BaseModel):
    """Manually resolve an alert."""

    resolution_note: str | None = Field(None, max_length=1000)


class AlertSuppress(BaseModel):
    """Suppress an alert for a duration."""

    suppress_minutes: int = Field(..., ge=5, le=43200, description="Duration to suppress (minutes)")
    reason: str | None = Field(None, max_length=1000)


# ==========================================================================
# Evaluation & Stats
# ==========================================================================


class AlertRuleEvaluateRequest(BaseModel):
    """Trigger alert rule evaluation.

    ``organization_id`` used to be accepted on this request and was
    trusted verbatim — a P0 cross-tenant evaluation/notification
    injection vector. The endpoint now always derives the org from the
    authenticated user; the body is retained for forward compatibility
    but accepts no fields.
    """

    model_config = {"extra": "ignore"}


class AlertRuleStatsResponse(BaseModel):
    total_rules: int
    active_rules: int
    disabled_rules: int
    total_alerts: int
    firing_alerts: int
    acknowledged_alerts: int
    alerts_last_24h: int
    critical_firing: int

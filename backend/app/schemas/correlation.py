# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Event Correlation Schemas
=========================================

Pydantic request/response models for:
  - Correlation Rules (CRUD)
  - Incidents (CRUD + lifecycle)
  - Event correlation triggering
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# Hard cap on the serialised JSONB size of correlation-rule fields that
# accept free-form structure (``event_patterns``, ``conditions``,
# ``notification_channels``). 64 KB matches the templates / device-group
# caps; covers any real rule + leaves DB room for thousands of rules
# without bloat. Rejects 5000-element pattern arrays that the audit
# probe showed could otherwise be 201ed at ~500 KB each.
_MAX_RULE_FIELD_BYTES = 64 * 1024


def _size_capped_json(field_name: str, v: Any) -> Any:
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > _MAX_RULE_FIELD_BYTES:
        raise ValueError(
            f"{field_name} exceeds {_MAX_RULE_FIELD_BYTES} bytes (got {size})",
        )
    return v


# ==========================================================================
# Correlation Rules
# ==========================================================================


class EventPatternItem(BaseModel):
    """A single event pattern within a correlation rule."""

    event_type: str = Field(
        ..., max_length=255, description="Event type glob, e.g. 'device.offline'"
    )
    min_count: int = Field(1, ge=1, description="Minimum matching events required")
    category: str | None = Field(None, description="Optional event category filter")
    conditions: dict[str, Any] | None = Field(
        None, description="Additional JSONB conditions to match"
    )


class CorrelationRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2048)
    event_patterns: list[EventPatternItem] = Field(..., min_length=1, max_length=64)
    time_window_seconds: int = Field(300, ge=30, le=86400)
    scope: str = Field("site", pattern=r"^(site|device_group|organization)$")
    conditions: dict[str, Any] | None = None
    severity: str = Field("medium", pattern=r"^(info|low|medium|high|critical)$")
    auto_resolve_seconds: int | None = Field(None, ge=60)
    notification_channels: dict[str, Any] | None = None

    @field_validator("event_patterns")
    @classmethod
    def _patterns_size_cap(cls, v: list[EventPatternItem]) -> list[EventPatternItem]:
        _size_capped_json("event_patterns", [p.model_dump() for p in v])
        return v

    @field_validator("conditions")
    @classmethod
    def _conditions_size_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _size_capped_json("conditions", v)

    @field_validator("notification_channels")
    @classmethod
    def _channels_size_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _size_capped_json("notification_channels", v)


class CorrelationRuleUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2048)
    status: str | None = Field(None, pattern=r"^(active|disabled|draft)$")
    event_patterns: list[EventPatternItem] | None = Field(None, min_length=1, max_length=64)
    time_window_seconds: int | None = Field(None, ge=30, le=86400)
    scope: str | None = Field(None, pattern=r"^(site|device_group|organization)$")
    conditions: dict[str, Any] | None = None
    severity: str | None = Field(None, pattern=r"^(info|low|medium|high|critical)$")
    auto_resolve_seconds: int | None = None
    notification_channels: dict[str, Any] | None = None

    @field_validator("event_patterns")
    @classmethod
    def _patterns_size_cap(cls, v: list[EventPatternItem] | None) -> list[EventPatternItem] | None:
        if v is None:
            return v
        _size_capped_json("event_patterns", [p.model_dump() for p in v])
        return v

    @field_validator("conditions")
    @classmethod
    def _conditions_size_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _size_capped_json("conditions", v)

    @field_validator("notification_channels")
    @classmethod
    def _channels_size_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _size_capped_json("notification_channels", v)


class CorrelationRuleResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    description: str | None
    status: str
    event_patterns: list[dict[str, Any]]
    time_window_seconds: int
    scope: str
    conditions: dict[str, Any] | None
    severity: str
    auto_resolve_seconds: int | None
    notification_channels: dict[str, Any] | None
    fire_count: int
    last_fired_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ==========================================================================
# Incidents
# ==========================================================================


class IncidentCreate(BaseModel):
    """Manual incident creation (auto-incidents are created by the engine)."""

    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = Field(None, max_length=10_000)
    severity: str = Field("medium", pattern=r"^(info|low|medium|high|critical)$")
    site_id: UUID | None = None
    tags: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("tags")
    @classmethod
    def _tags_item_cap(cls, v: list[str]) -> list[str]:
        # 64-char per-tag cap so a single 1 MB tag string can't sneak in.
        for t in v:
            if len(t) > 64:
                raise ValueError(f"tag too long (max 64): {t[:32]}…")
        return v


class IncidentUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = Field(None, max_length=10_000)
    severity: str | None = Field(None, pattern=r"^(info|low|medium|high|critical)$")
    status: str | None = Field(None, pattern=r"^(open|investigating|mitigating|resolved|closed)$")
    assigned_to: UUID | None = None
    root_cause: str | None = Field(None, max_length=10_000)
    resolution_notes: str | None = Field(None, max_length=10_000)
    tags: list[str] | None = Field(None, max_length=32)

    @field_validator("tags")
    @classmethod
    def _tags_item_cap(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for t in v:
            if len(t) > 64:
                raise ValueError(f"tag too long (max 64): {t[:32]}…")
        return v


class IncidentEventResponse(BaseModel):
    id: UUID
    event_id: UUID
    matched_pattern: str | None
    added_at: datetime
    # Inline event summary
    event_type: str | None = None
    event_category: str | None = None
    event_timestamp: datetime | None = None
    event_payload: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class IncidentResponse(BaseModel):
    id: UUID
    organization_id: UUID
    rule_id: UUID | None
    site_id: UUID | None
    title: str
    description: str | None
    severity: str
    status: str
    opened_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    assigned_to: UUID | None
    event_count: int
    affected_devices: list[Any]
    root_cause: str | None
    resolution_notes: str | None
    tags: list[Any]
    context: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class IncidentListResponse(BaseModel):
    incidents: list[IncidentResponse]
    total: int


class CorrelationRuleListResponse(BaseModel):
    rules: list[CorrelationRuleResponse]
    total: int


# ==========================================================================
# Trigger / Stats
# ==========================================================================


class CorrelationTriggerRequest(BaseModel):
    """Manually trigger event correlation scan."""

    time_window_minutes: int = Field(15, ge=1, le=1440)
    site_id: UUID | None = None
    dry_run: bool = False


class CorrelationStatsResponse(BaseModel):
    total_rules: int
    active_rules: int
    open_incidents: int
    incidents_last_24h: int
    events_correlated_last_24h: int
    top_firing_rules: list[dict[str, Any]]

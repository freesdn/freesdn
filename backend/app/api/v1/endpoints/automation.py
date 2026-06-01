# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Automation Endpoints
===================================

Automation rule management and execution endpoints.
"""

from __future__ import annotations

import math
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user
from app.core.dependencies import is_unscoped_org_admin, is_unscoped_superuser
from app.db import get_session
from app.models import User
from app.models.automation import AutomationExecutionRecord, AutomationRuleRecord
from app.services.automation import (
    IMPLEMENTED_TRIGGER_TYPES,
    ActionType,
    AutomationService,
    RuleStatus,
    TriggerType,
    automation_engine,
)

router = APIRouter()


# =============================================================================
# Schemas
# =============================================================================

# Per-field caps for automation rule JSONB columns. Without these
# the entire schema was effectively ``dict[str, Any]`` unbounded —
# a rule with a 700 KB ``trigger_config`` and 10 000 actions was
# happily 201'd into the DB and re-evaluated on every trigger.
_TRIGGER_CONFIG_MAX_BYTES = 64 * 1024
_ACTION_PARAMS_MAX_BYTES = 16 * 1024
_MAX_ACTIONS_PER_RULE = 50
_MAX_CONDITION_DEPTH = 10


def _validate_jsonb_size(name: str, v: dict[str, Any] | None, limit: int) -> dict[str, Any] | None:
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > limit:
        raise ValueError(f"{name} exceeds {limit} bytes (got {size})")
    return v


class ConditionSchema(BaseModel):
    """Condition definition."""

    field: str = Field(..., max_length=128)
    operator: str = Field(..., max_length=16)
    # ``list[Any]`` was uncapped — a single condition could carry a
    # 10 000-element list. Bound the list at 64 items; the operators
    # that actually consume lists (``in`` / ``not_in``) wouldn't be
    # used with more.
    value: str | int | float | bool | list[Any] = Field(...)

    @field_validator("value")
    @classmethod
    def _value_size(cls, v: Any) -> Any:
        if isinstance(v, list) and len(v) > 64:
            raise ValueError(f"value list exceeds 64 items (got {len(v)})")
        if isinstance(v, str) and len(v) > 1024:
            raise ValueError(f"value string exceeds 1024 chars (got {len(v)})")
        return v


class ConditionGroupSchema(BaseModel):
    """Condition group with logic."""

    logic: str = Field("and", pattern=r"^(and|or)$")
    conditions: list[ConditionSchema | ConditionGroupSchema] = Field(..., max_length=32)


def _condition_depth(node: Any, current: int = 0) -> int:
    """Return the max nesting depth of a ConditionGroupSchema tree."""
    if current > _MAX_CONDITION_DEPTH:
        return current
    if isinstance(node, ConditionGroupSchema):
        if not node.conditions:
            return current + 1
        return max(_condition_depth(c, current + 1) for c in node.conditions)
    return current


class ActionSchema(BaseModel):
    """Action definition."""

    action_type: ActionType
    params: dict[str, Any] = {}
    # 24 hours is more than enough — without an upper bound a single
    # action could pin a Celery worker on ``asyncio.sleep`` for
    # ``MAXINT`` seconds.
    delay_seconds: int = Field(default=0, ge=0, le=86400)
    continue_on_error: bool = True

    @field_validator("params")
    @classmethod
    def _params_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_jsonb_size("params", v, _ACTION_PARAMS_MAX_BYTES) or v


class AutomationRuleCreate(BaseModel):
    """Create automation rule request."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    trigger_type: TriggerType
    trigger_config: dict[str, Any]
    conditions: ConditionGroupSchema | None = None
    actions: list[ActionSchema] = Field(..., min_length=1, max_length=_MAX_ACTIONS_PER_RULE)
    priority: int = Field(default=0, ge=0, le=1000)
    cooldown_seconds: int = Field(default=60, ge=0, le=86400)
    max_triggers_per_hour: int = Field(default=100, ge=1, le=1000)

    @field_validator("trigger_config")
    @classmethod
    def _trigger_config_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_jsonb_size("trigger_config", v, _TRIGGER_CONFIG_MAX_BYTES) or v

    @field_validator("conditions")
    @classmethod
    def _conditions_depth(cls, v: ConditionGroupSchema | None) -> ConditionGroupSchema | None:
        if v is None:
            return v
        depth = _condition_depth(v)
        if depth > _MAX_CONDITION_DEPTH:
            raise ValueError(f"conditions nested too deeply: {depth} > {_MAX_CONDITION_DEPTH}")
        return v


class AutomationRuleUpdate(BaseModel):
    """Update automation rule request."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    trigger_type: TriggerType | None = None
    trigger_config: dict[str, Any] | None = None
    conditions: ConditionGroupSchema | None = None
    actions: list[ActionSchema] | None = Field(None, min_length=1, max_length=_MAX_ACTIONS_PER_RULE)
    priority: int | None = Field(None, ge=0, le=1000)
    cooldown_seconds: int | None = Field(None, ge=0, le=86400)
    max_triggers_per_hour: int | None = Field(None, ge=1, le=1000)

    @field_validator("trigger_config")
    @classmethod
    def _trigger_config_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_jsonb_size("trigger_config", v, _TRIGGER_CONFIG_MAX_BYTES)

    @field_validator("conditions")
    @classmethod
    def _conditions_depth(cls, v: ConditionGroupSchema | None) -> ConditionGroupSchema | None:
        if v is None:
            return v
        depth = _condition_depth(v)
        if depth > _MAX_CONDITION_DEPTH:
            raise ValueError(f"conditions nested too deeply: {depth} > {_MAX_CONDITION_DEPTH}")
        return v


class AutomationRuleResponse(BaseModel):
    """Automation rule response."""

    id: str
    name: str
    description: str | None
    trigger_type: str
    trigger_config: dict[str, Any]
    conditions: dict[str, Any] | None
    actions: list[dict[str, Any]]
    status: str
    priority: int
    cooldown_seconds: int
    max_triggers_per_hour: int
    created_at: str
    updated_at: str | None
    last_triggered: str | None
    trigger_count: int

    model_config = {"from_attributes": True}


class RuleExecutionResponse(BaseModel):
    """Rule execution response."""

    id: str
    rule_id: str
    triggered_at: str
    success: bool
    error: str | None
    duration_ms: float
    actions_executed: list[dict[str, Any]]


class TriggerRuleRequest(BaseModel):
    """Manual rule trigger request."""

    data: dict[str, Any] = {}


# =============================================================================
# Helpers
# =============================================================================


def _paginate(items: list[Any], page: int, per_page: int) -> dict[str, Any]:
    """Build a paginated envelope from an in-memory list."""
    total = len(items)
    pages = max(1, math.ceil(total / per_page))
    start = (page - 1) * per_page
    return {
        "items": items[start : start + per_page],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


def _record_to_response(r: AutomationRuleRecord) -> AutomationRuleResponse:
    """Convert a DB AutomationRuleRecord directly to a response (B-3: avoids loading into engine)."""
    return AutomationRuleResponse(
        id=str(r.id),
        name=r.name,
        description=r.description,
        trigger_type=r.trigger_type,
        trigger_config=r.trigger_config or {},
        conditions=r.conditions,
        actions=r.actions or [],
        status=r.status,
        priority=r.priority,
        cooldown_seconds=r.cooldown_seconds,
        max_triggers_per_hour=r.max_triggers_per_hour,
        created_at=r.created_at.isoformat() if r.created_at else "",
        updated_at=r.updated_at.isoformat() if r.updated_at else None,
        last_triggered=r.last_triggered.isoformat() if r.last_triggered else None,
        trigger_count=r.trigger_count,
    )


def _rule_to_response(r: Any) -> AutomationRuleResponse:
    """Convert an in-memory AutomationRule to a response."""
    return AutomationRuleResponse(
        id=str(r.id),
        name=r.name,
        description=r.description,
        trigger_type=r.trigger_type.value
        if hasattr(r.trigger_type, "value")
        else str(r.trigger_type),
        trigger_config=r.trigger_config,
        conditions=r.conditions.to_dict()
        if r.conditions and hasattr(r.conditions, "to_dict")
        else r.conditions,
        actions=[a.to_dict() for a in r.actions]
        if r.actions and hasattr(r.actions[0], "to_dict")
        else (r.actions or []),
        status=r.status.value if hasattr(r.status, "value") else str(r.status),
        priority=r.priority,
        cooldown_seconds=r.cooldown_seconds,
        max_triggers_per_hour=r.max_triggers_per_hour,
        created_at=r.created_at.isoformat() if r.created_at else "",
        updated_at=r.updated_at.isoformat() if r.updated_at else None,
        last_triggered=r.last_triggered.isoformat() if r.last_triggered else None,
        trigger_count=r.trigger_count,
    )


def _require_admin(user: User) -> None:
    # scope-aware admission. A raw role check ignores the
    # API-key scope ceiling, so a super_admin/org_admin holding a deliberately
    # narrowed (scoped) key still passed via its role. Require an UNSCOPED
    # admin principal instead.
    if not (is_unscoped_superuser(user) or is_unscoped_org_admin(user)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    if not user.organization_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Organization context required")


def _exec_to_dict(r: AutomationExecutionRecord) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "rule_id": str(r.rule_id),
        "triggered_at": r.triggered_at.isoformat() if r.triggered_at else "",
        "success": r.success,
        "error": r.error,
        "duration_ms": r.duration_ms or 0,
        "actions_executed": r.actions_executed or [],
    }


# =============================================================================
# Static / aggregate routes — MUST come before /{rule_id}
# =============================================================================


@router.get("/summary")
async def get_automation_summary(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get automation summary statistics."""
    _require_admin(current_user)
    org_id = current_user.organization_id

    rows = (
        await session.execute(
            select(AutomationRuleRecord.status, func.count())
            .where(AutomationRuleRecord.organization_id == org_id)
            .group_by(AutomationRuleRecord.status)
        )
    ).all()
    status_counts: dict[str, int] = {r[0]: r[1] for r in rows}
    total_rules = sum(status_counts.values())

    trigger_rows = (
        await session.execute(
            select(AutomationRuleRecord.trigger_type, func.count())
            .where(AutomationRuleRecord.organization_id == org_id)
            .group_by(AutomationRuleRecord.trigger_type)
        )
    ).all()
    by_trigger_type = {r[0]: r[1] for r in trigger_rows}

    exec_total = (
        await session.execute(
            select(func.count())
            .select_from(AutomationExecutionRecord)
            .where(AutomationExecutionRecord.organization_id == org_id)
        )
    ).scalar() or 0
    exec_success = (
        await session.execute(
            select(func.count())
            .select_from(AutomationExecutionRecord)
            .where(
                AutomationExecutionRecord.organization_id == org_id,
                AutomationExecutionRecord.success.is_(True),
            )
        )
    ).scalar() or 0

    return {
        "total_rules": total_rules,
        "active_rules": status_counts.get("active", 0),
        "paused_rules": status_counts.get("paused", 0),
        "disabled_rules": status_counts.get("disabled", 0),
        "error_rules": status_counts.get("error", 0),
        "total_executions": exec_total,
        "successful_executions": exec_success,
        "failed_executions": exec_total - exec_success,
        "by_trigger_type": by_trigger_type,
    }


@router.get("/executions/all")
async def list_all_executions(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    rule_id: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> Any:
    """List all automation executions for the current organization."""
    _require_admin(current_user)
    org_id = current_user.organization_id

    # SECURITY: always scope to the current user's org via the denormalized
    # organization_id column (added in the hardening migration).
    q = (
        select(AutomationExecutionRecord)
        .where(AutomationExecutionRecord.organization_id == org_id)
        .order_by(AutomationExecutionRecord.triggered_at.desc())
    )
    count_q = (
        select(func.count())
        .select_from(AutomationExecutionRecord)
        .where(AutomationExecutionRecord.organization_id == org_id)
    )

    if rule_id:
        q = q.where(AutomationExecutionRecord.rule_id == rule_id)
        count_q = count_q.where(AutomationExecutionRecord.rule_id == rule_id)
    if status_filter:
        is_success = status_filter.lower() in ("success", "true")
        q = q.where(AutomationExecutionRecord.success == is_success)
        count_q = count_q.where(AutomationExecutionRecord.success == is_success)

    total = (await session.execute(count_q)).scalar() or 0
    pages = max(1, math.ceil(total / per_page))
    offset = (page - 1) * per_page

    rows = (await session.execute(q.offset(offset).limit(per_page))).scalars().all()
    return {
        "items": [_exec_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.get("/actions/types")
async def get_action_types(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get available action types. Only types with a live handler are returned
    — the UI must not offer an action that would always fail at execution
    (B-2: requires authentication)."""
    supported = automation_engine.implemented_action_types()
    return {
        "action_types": [
            {"value": a.value, "label": a.value.replace("_", " ").title()}
            for a in ActionType
            if a in supported
        ]
    }


@router.get("/triggers/types")
async def get_trigger_types(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get available trigger types. Only types with a live driver are returned
    — SCHEDULE / WEBHOOK / THRESHOLD have none yet (B-2)."""
    return {
        "trigger_types": [
            {"value": t.value, "label": t.value.replace("_", " ").title()}
            for t in TriggerType
            if t in IMPLEMENTED_TRIGGER_TYPES
        ]
    }


@router.get("/meta/trigger-types", response_model=list[str])
async def get_trigger_types_meta(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get available trigger types (legacy). Implemented types only (B-2)."""
    return [t.value for t in TriggerType if t in IMPLEMENTED_TRIGGER_TYPES]


@router.get("/meta/action-types", response_model=list[str])
async def get_action_types_meta(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get available action types (legacy). Implemented types only (B-2)."""
    supported = automation_engine.implemented_action_types()
    return [a.value for a in ActionType if a in supported]


@router.get("/meta/operators", response_model=list[str])
async def get_condition_operators(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get available condition operators. Requires authentication (B-2)."""
    from app.services.automation import ConditionOperator

    return [o.value for o in ConditionOperator]


# =============================================================================
# Rule CRUD — paginated list + /{rule_id} routes
# =============================================================================


@router.get("/")
async def list_automation_rules(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    trigger_type: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
) -> Any:
    """List automation rules for the organization (DB-paginated, B-3 fix)."""
    _require_admin(current_user)

    # B-3: Push all filtering + pagination to SQL — previous impl loaded ALL
    # rules into memory then paginated in Python (O(n) memory + query time).
    org_id = current_user.organization_id

    q = select(AutomationRuleRecord).where(AutomationRuleRecord.organization_id == org_id)
    count_q = (
        select(func.count())
        .select_from(AutomationRuleRecord)
        .where(AutomationRuleRecord.organization_id == org_id)
    )

    if status_filter and status_filter in [s.value for s in RuleStatus]:
        q = q.where(AutomationRuleRecord.status == status_filter)
        count_q = count_q.where(AutomationRuleRecord.status == status_filter)

    if trigger_type:
        q = q.where(AutomationRuleRecord.trigger_type == trigger_type)
        count_q = count_q.where(AutomationRuleRecord.trigger_type == trigger_type)

    total = (await session.execute(count_q)).scalar() or 0
    pages = max(1, math.ceil(total / per_page))
    offset = (page - 1) * per_page
    rows = (
        (
            await session.execute(
                q.order_by(AutomationRuleRecord.created_at.desc()).offset(offset).limit(per_page)
            )
        )
        .scalars()
        .all()
    )

    return {
        "items": [_record_to_response(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.post("/", response_model=AutomationRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_automation_rule(
    rule_data: AutomationRuleCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Create a new automation rule."""
    _require_admin(current_user)

    # Honesty gate: refuse to create a rule whose trigger has no live driver or
    # whose action has no live handler — otherwise the rule would silently never
    # fire (trigger) or always fail at execution (action).
    if rule_data.trigger_type not in IMPLEMENTED_TRIGGER_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Trigger type '{rule_data.trigger_type.value}' is not supported yet. "
                f"Supported: {', '.join(sorted(t.value for t in IMPLEMENTED_TRIGGER_TYPES))}."
            ),
        )
    supported_actions = automation_engine.implemented_action_types()
    for a in rule_data.actions:
        if a.action_type not in supported_actions:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"Action type '{a.action_type.value}' is not supported yet. "
                    f"Supported: {', '.join(sorted(t.value for t in supported_actions))}."
                ),
            )

    service = AutomationService(db=session, engine=automation_engine)
    rule = await service.create_rule(
        name=rule_data.name,
        organization_id=current_user.organization_id,  # type: ignore[arg-type]
        trigger_type=rule_data.trigger_type,
        trigger_config=rule_data.trigger_config,
        actions=[a.model_dump() for a in rule_data.actions],
        conditions=rule_data.conditions.model_dump() if rule_data.conditions else None,
        description=rule_data.description,
        priority=rule_data.priority,
        cooldown_seconds=rule_data.cooldown_seconds,
        max_triggers_per_hour=rule_data.max_triggers_per_hour,
        created_by=current_user.id,
    )
    return _rule_to_response(rule)


@router.get("/{rule_id}", response_model=AutomationRuleResponse)
async def get_automation_rule(
    rule_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get a specific automation rule."""
    _require_admin(current_user)

    # Read from DB rather than the engine's in-memory ``_rules`` cache.
    # The cache is process-global and only updates ``trigger_count`` /
    # ``last_triggered`` on the in-memory dataclass — the DB row has
    # the authoritative count (persisted in ``_execute_rule``). Reading
    # from cache here meant the rule-detail page always showed
    # ``trigger_count=0`` no matter how many times the rule fired.
    org_id = current_user.organization_id
    q = select(AutomationRuleRecord).where(AutomationRuleRecord.id == rule_id)
    if not is_unscoped_superuser(current_user):  # scope-aware
        q = q.where(AutomationRuleRecord.organization_id == org_id)
    record = (await session.execute(q)).scalar_one_or_none()
    if not record:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return _record_to_response(record)


@router.patch("/{rule_id}", response_model=AutomationRuleResponse)
async def update_automation_rule(
    rule_id: UUID,
    rule_data: AutomationRuleUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Update an automation rule."""
    _require_admin(current_user)

    service = AutomationService(db=session, engine=automation_engine)

    updates = rule_data.model_dump(exclude_unset=True)
    if "actions" in updates and rule_data.actions:
        updates["actions"] = [a.model_dump() for a in rule_data.actions]
    if "conditions" in updates and rule_data.conditions:
        updates["conditions"] = rule_data.conditions.model_dump()

    rule = await service.update_rule(
        rule_id, organization_id=current_user.organization_id, **updates
    )
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rule not found")

    return _rule_to_response(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_automation_rule(
    rule_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Delete an automation rule."""
    _require_admin(current_user)

    service = AutomationService(db=session, engine=automation_engine)
    if not await service.delete_rule(rule_id, organization_id=current_user.organization_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rule not found")


# =============================================================================
# Rule Status
# =============================================================================


@router.post("/{rule_id}/enable", status_code=status.HTTP_204_NO_CONTENT)
async def enable_automation_rule(
    rule_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Enable an automation rule."""
    _require_admin(current_user)
    service = AutomationService(db=session, engine=automation_engine)
    if not await service.enable_rule(rule_id, organization_id=current_user.organization_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rule not found")


@router.post("/{rule_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_automation_rule(
    rule_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Disable an automation rule."""
    _require_admin(current_user)
    service = AutomationService(db=session, engine=automation_engine)
    if not await service.disable_rule(rule_id, organization_id=current_user.organization_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rule not found")


# =============================================================================
# Manual Trigger & Per-Rule Executions
# =============================================================================


@router.post("/{rule_id}/trigger", response_model=RuleExecutionResponse)
async def trigger_automation_rule(
    rule_id: UUID,
    trigger_request: TriggerRuleRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Manually trigger an automation rule."""
    _require_admin(current_user)

    service = AutomationService(db=session, engine=automation_engine)
    execution = await service.trigger_rule(
        rule_id, trigger_request.data, organization_id=current_user.organization_id
    )

    if not execution:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rule not found")

    return RuleExecutionResponse(
        id=str(execution.id),
        rule_id=str(execution.rule_id),
        triggered_at=execution.triggered_at.isoformat(),
        success=execution.success,
        error=execution.error,
        duration_ms=execution.duration_ms,
        actions_executed=[
            {
                "action_type": ar.action_type.value
                if hasattr(ar.action_type, "value")
                else str(ar.action_type),
                "success": ar.success,
                "error": ar.error,
                "execution_time_ms": ar.execution_time_ms,
            }
            for ar in execution.actions_executed
        ],
    )


@router.get("/{rule_id}/executions")
async def get_rule_executions(
    rule_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> Any:
    """Get execution history for a specific rule."""
    _require_admin(current_user)

    # B-1: scope by org so admins cannot enumerate executions of foreign rules
    org_id = current_user.organization_id

    # Previously this endpoint returned 200 with ``{items:[],total:0}``
    # for foreign / non-existent rule_ids — operators couldn't tell
    # "rule has no execution history" from "I typo'd the UUID". Match
    # the pattern from /enterprise/devices/{id}/config-versions: 404
    # if the rule doesn't exist in the caller's org.
    rule_check = await session.execute(
        select(AutomationRuleRecord.id).where(
            AutomationRuleRecord.id == rule_id,
            AutomationRuleRecord.organization_id == org_id,
        )
    )
    if rule_check.scalar_one_or_none() is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rule not found")

    count_q = (
        select(func.count())
        .select_from(AutomationExecutionRecord)
        .where(
            AutomationExecutionRecord.rule_id == rule_id,
            AutomationExecutionRecord.organization_id == org_id,
        )
    )
    total = (await session.execute(count_q)).scalar() or 0
    pages = max(1, math.ceil(total / per_page))
    offset = (page - 1) * per_page

    rows = (
        (
            await session.execute(
                select(AutomationExecutionRecord)
                .where(
                    AutomationExecutionRecord.rule_id == rule_id,
                    AutomationExecutionRecord.organization_id == org_id,
                )
                .order_by(AutomationExecutionRecord.triggered_at.desc())
                .offset(offset)
                .limit(per_page)
            )
        )
        .scalars()
        .all()
    )

    return {
        "items": [_exec_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }

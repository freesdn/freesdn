# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — Agent scheduled scans (CRUD + WS push).

Backend-managed scan schedules. The agent already has a SchedulerService
+ cron parser; this module adds the storage and the push-via-WS so
operators can manage schedules from the control plane.

`agent_id=None` on a row means "all agents at this site". The push
helper filters per-agent so each connection only receives schedules
that target it (or are site-wide).
"""

import logging
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, is_unscoped_superuser, require_permissions
from app.core.site_access import assert_can_access_site
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.models.agents import AgentSchedule, AgentScheduleRun, RemoteAgent
from app.models.core import Site
from app.schemas.discovery import (
    MAX_SCAN_HOSTS_TOTAL,
    _estimate_target_hosts,
    _validate_scan_target,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class AgentScheduleIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    scan_type: str = Field(default="quick", max_length=32)
    cron: str = Field(min_length=1, max_length=64)
    targets: list[str] = Field(default_factory=list, max_length=64)
    interface: str | None = Field(None, max_length=64)
    enabled: bool = True
    agent_id: UUID | None = None
    # Notification config — same JSONB shape as AlertRule:
    #   {"email": {"to": [...]}, "slack": {"channel": "..."}, ...}
    notification_channels: dict[str, Any] = Field(default_factory=dict)
    notify_on_failure: bool = False
    notify_on_new_devices: int = Field(default=0, ge=0, le=10000)

    @field_validator("scan_type")
    @classmethod
    def _validate_scan_type(cls, v: str) -> str:
        allowed = {"quick", "camera", "voip", "iot", "port", "windows", "full"}
        if v not in allowed:
            raise ValueError(f"scan_type must be one of {sorted(allowed)}")
        return v

    @field_validator("cron")
    @classmethod
    def _validate_cron_shape(cls, v: str) -> str:
        parts = v.strip().split()
        if len(parts) != 5:
            raise ValueError(
                f"cron must have 5 fields (minute hour day month weekday), got {len(parts)}"
            )
        return v.strip()

    @field_validator("targets")
    @classmethod
    def _cap_target_length(cls, v: list[str]) -> list[str]:
        # run each target through the shared SSRF-reject + CIDR-size
        # validator so scheduled scans are subject to the same guards as
        # on-demand scans in discovery.py AgentScanRequest._validate_agent_targets.
        return [_validate_scan_target(t) for t in v]

    @model_validator(mode="after")
    def _check_total_host_count(self) -> "AgentScheduleIn":
        # enforce the aggregate host-count cap across all targets so
        # that N × /16 targets cannot DoS the scanner worker.
        total = 0
        for target in self.targets:
            total += _estimate_target_hosts(target)
            if total > MAX_SCAN_HOSTS_TOTAL:
                raise ValueError(
                    f"total hosts across targets exceeds {MAX_SCAN_HOSTS_TOTAL} "
                    f"(currently: {total}). Break your scan into smaller batches."
                )
        return self


class AgentScheduleResponse(BaseModel):
    id: UUID
    organization_id: UUID
    site_id: UUID
    agent_id: UUID | None
    name: str
    scan_type: str
    cron: str
    targets: list[str]
    interface: str | None
    enabled: bool
    last_fired_at: datetime | None
    notification_channels: dict[str, Any] = Field(default_factory=dict)
    notify_on_failure: bool = False
    notify_on_new_devices: int = 0
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# WS push helper
# ---------------------------------------------------------------------------


async def push_schedules_to_agents(
    session: AsyncSession,
    *,
    site_id: UUID,
    agent_id: UUID | None = None,
) -> None:
    """Push current schedules to one or all agents at a site via WS.

    Called after create/update/delete so connected agents hot-reload via
    SchedulerService.update_schedules(). Best-effort: failures here do
    not fail the API call that triggered the push.
    """
    from app.api.v1.endpoints.agents import get_agent_registry
    from app.services.remote_agent import AgentCommand, AgentCommandType

    q = select(AgentSchedule).where(
        AgentSchedule.site_id == site_id,
        AgentSchedule.deleted_at.is_(None),
        AgentSchedule.enabled.is_(True),
    )
    rows = (await session.execute(q)).scalars().all()

    all_schedules = [
        {
            "name": r.name,
            "scan_type": r.scan_type,
            "cron": r.cron,
            "targets": r.targets or [],
            "interface": r.interface or "",
            "enabled": r.enabled,
            "agent_id": str(r.agent_id) if r.agent_id else None,
        }
        for r in rows
    ]

    try:
        registry = await get_agent_registry(session)
    except Exception:
        return

    # use the thread-safe accessor instead of
    # reaching into the private _connections dict.
    if agent_id:
        target_pairs: list[tuple[str, Any]] = []
        c = registry.get_connection(str(agent_id))
        # H2 (defense-in-depth): get_connection is a process-wide
        # lookup with no site filtering. Even though callers now validate
        # agent_id against the site, refuse to deliver to a connection whose
        # reported site_id doesn't match — so a stored mismatched pair can
        # never push a command onto an out-of-site agent.
        if c and getattr(getattr(c, "info", None), "site_id", None) == site_id:
            target_pairs.append((str(agent_id), c))
    else:
        target_pairs = list(registry.connections_for_site(site_id))

    for aid, connection in target_pairs:
        if not connection:
            continue
        scoped = [s for s in all_schedules if s["agent_id"] is None or s["agent_id"] == aid]
        try:
            # Fire and forget — the agent will process and ack via the
            # standard action_result channel. Waiting here would add
            # network RTT to every CRUD call for no real benefit.
            await connection.send_command(
                AgentCommand(
                    type=AgentCommandType.UPDATE_SCHEDULE,
                    payload={"schedules": scoped},
                ),
                wait_result=False,
            )
        except Exception:
            logger.exception("Failed to push schedules to agent %s", aid)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/schedules",
    response_model=list[AgentScheduleResponse],
    summary="List scheduled scans at a site",
)
async def list_schedules(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    site_id: UUID | None = Query(None),
    agent_id: UUID | None = Query(None),
) -> Any:
    q = select(AgentSchedule).where(AgentSchedule.deleted_at.is_(None))
    # Canonical tenant scoping: org filter (+ per-user site grant) in one call.
    q = q.where(tenant_filter(AgentSchedule, current_user))
    if site_id:
        q = q.where(AgentSchedule.site_id == site_id)
    if agent_id:
        q = q.where(AgentSchedule.agent_id == agent_id)
    q = q.order_by(AgentSchedule.created_at.desc())
    rows = (await session.execute(q)).scalars().all()
    return [AgentScheduleResponse.model_validate(r, from_attributes=True) for r in rows]


async def _validate_schedule_agent(
    session: AsyncSession,
    agent_id: UUID | None,
    site_id: UUID,
    scan_type: str,
) -> None:
    """Validate that ``agent_id`` belongs to ``site_id`` and supports ``scan_type``.

    Shared by create_schedule and update_schedule_endpoint. Validating
    ``ag.site_id == site_id`` transitively enforces org isolation because the
    caller has already been confirmed to own ``site_id`` (the schedule's own
    site is org-checked before this is called), and an agent's site_id is
    org-bound. Without this on the PATCH path an org-A operator could repoint a
    schedule's agent_id at another tenant's online agent, turning the
    subsequent push into a cross-tenant scan-command injection.
    """
    if not agent_id:
        return
    ag_q = await session.execute(
        select(RemoteAgent).where(
            RemoteAgent.id == agent_id,
            RemoteAgent.deleted_at.is_(None),
        )
    )
    ag = ag_q.scalar_one_or_none()
    if not ag or ag.site_id != site_id:
        raise HTTPException(status_code=400, detail="agent_id not in site")

    # Chapter B: if the agent has reported capabilities, validate
    # the requested scan_type is one it actually supports. Empty
    # `scan_types` is treated as "agent hasn't reported yet" —
    # accept everything until first heartbeat.
    # Same defence as the interactive-scan gate: a non-object capabilities
    # blob must read as "hasn't reported yet", not 500 the schedule form.
    caps = ag.capabilities if isinstance(ag.capabilities, dict) else {}
    supported = caps.get("scan_types") or []
    if not isinstance(supported, list):
        supported = []
    if supported and scan_type not in supported:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Agent {ag.name} does not support scan_type "
                f"'{scan_type}'. Supported: {sorted(supported)}"
            ),
        )


@router.post(
    "/schedules",
    response_model=AgentScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a scheduled scan",
)
async def create_schedule(
    payload: AgentScheduleIn,
    site_id: Annotated[UUID, Query(...)],
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:write"))],
) -> Any:
    site_q = await session.execute(
        select(Site).where(Site.id == site_id, Site.deleted_at.is_(None))
    )
    site = site_q.scalar_one_or_none()
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    if not is_unscoped_superuser(current_user):
        if site.organization_id != current_user.organization_id:
            raise HTTPException(status_code=404, detail="Site not found")
    # per-user site-grant check (no-op for non-site-limited users).
    assert_can_access_site(current_user, site_id, detail="Site not found")

    await _validate_schedule_agent(session, payload.agent_id, site_id, payload.scan_type)

    row = AgentSchedule(
        organization_id=site.organization_id,
        site_id=site_id,
        agent_id=payload.agent_id,
        name=payload.name,
        scan_type=payload.scan_type,
        cron=payload.cron,
        targets=payload.targets,
        interface=payload.interface,
        enabled=payload.enabled,
        notification_channels=payload.notification_channels or {},
        notify_on_failure=payload.notify_on_failure,
        notify_on_new_devices=payload.notify_on_new_devices,
        created_by=current_user.id,
    )
    session.add(row)
    try:
        await session.commit()
    except Exception as exc:
        await session.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"Schedule name already in use for this site: {exc}",
        )
    await session.refresh(row)

    try:
        await push_schedules_to_agents(
            session,
            site_id=site_id,
            agent_id=payload.agent_id,
        )
    except Exception:
        logger.exception("Schedule push failed (schedule still persisted)")

    return AgentScheduleResponse.model_validate(row, from_attributes=True)


@router.patch(
    "/schedules/{schedule_id}",
    response_model=AgentScheduleResponse,
    summary="Update a scheduled scan",
)
async def update_schedule_endpoint(
    schedule_id: UUID,
    payload: AgentScheduleIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:write"))],
) -> Any:
    q = await session.execute(
        select(AgentSchedule).where(
            AgentSchedule.id == schedule_id,
            AgentSchedule.deleted_at.is_(None),
        )
    )
    row = q.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if not is_unscoped_superuser(current_user):
        if row.organization_id != current_user.organization_id:
            raise HTTPException(status_code=404, detail="Schedule not found")
    # per-user site-grant check (no-op for non-site-limited users).
    assert_can_access_site(current_user, row.site_id, detail="Schedule not found")

    # the create path validates agent_id against the site; the
    # PATCH path previously did not, letting a caller repoint agent_id at
    # another tenant's online agent (cross-tenant scan-command injection on the
    # subsequent push). Validate against the schedule's own (org-owned) site.
    await _validate_schedule_agent(session, payload.agent_id, row.site_id, payload.scan_type)

    row.name = payload.name
    row.scan_type = payload.scan_type
    row.cron = payload.cron
    row.targets = payload.targets
    row.interface = payload.interface
    row.enabled = payload.enabled
    row.agent_id = payload.agent_id
    row.notification_channels = payload.notification_channels or {}
    row.notify_on_failure = payload.notify_on_failure
    row.notify_on_new_devices = payload.notify_on_new_devices
    row.updated_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(row)

    try:
        await push_schedules_to_agents(
            session,
            site_id=row.site_id,
            agent_id=payload.agent_id,
        )
    except Exception:
        logger.exception("Schedule push failed (schedule still updated)")

    return AgentScheduleResponse.model_validate(row, from_attributes=True)


@router.delete(
    "/schedules/{schedule_id}",
    summary="Soft-delete a scheduled scan",
)
async def delete_schedule(
    schedule_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:write"))],
) -> Any:
    q = await session.execute(
        select(AgentSchedule).where(
            AgentSchedule.id == schedule_id,
            AgentSchedule.deleted_at.is_(None),
        )
    )
    row = q.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if not is_unscoped_superuser(current_user):
        if row.organization_id != current_user.organization_id:
            raise HTTPException(status_code=404, detail="Schedule not found")
    # per-user site-grant check (no-op for non-site-limited users).
    assert_can_access_site(current_user, row.site_id, detail="Schedule not found")

    row.deleted_at = datetime.now(UTC)
    site_id = row.site_id
    agent_id = row.agent_id
    await session.commit()

    try:
        await push_schedules_to_agents(session, site_id=site_id, agent_id=agent_id)
    except Exception:
        logger.exception("Schedule push failed after delete")

    return {"message": "Schedule deleted"}


# ---------------------------------------------------------------------------
# Run history — list past executions of a schedule
# ---------------------------------------------------------------------------


class AgentScheduleRunResponse(BaseModel):
    id: UUID
    schedule_id: UUID
    agent_id: UUID | None
    status: str
    device_count: int
    duration_seconds: float | None
    error_message: str | None
    started_at: datetime
    completed_at: datetime | None


class AgentRunWithScheduleName(BaseModel):
    """Run row plus the parent schedule's name for the agent-detail view."""

    id: UUID
    schedule_id: UUID
    schedule_name: str | None
    agent_id: UUID | None
    status: str
    device_count: int
    duration_seconds: float | None
    error_message: str | None
    started_at: datetime
    completed_at: datetime | None


@router.get(
    "/schedules/{schedule_id}/runs",
    response_model=list[AgentScheduleRunResponse],
    summary="Recent execution history for a schedule",
)
async def list_schedule_runs(
    schedule_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("discovery:run"))],
    limit: int = Query(50, ge=1, le=500),
) -> Any:
    """Return last N execution records for a scheduled scan.

    Org-scoped via the parent schedule. Each row reports status, device
    count, and (when known) duration + error message. Inserted by the
    backend's WS scan_result handler whenever the agent reports a fired
    scheduled scan.
    """
    sched_q = await session.execute(
        select(AgentSchedule).where(
            AgentSchedule.id == schedule_id,
            AgentSchedule.deleted_at.is_(None),
        )
    )
    schedule = sched_q.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if not is_unscoped_superuser(current_user):
        if schedule.organization_id != current_user.organization_id:
            raise HTTPException(status_code=404, detail="Schedule not found")
    # per-user site-grant check on the parent schedule's site.
    assert_can_access_site(current_user, schedule.site_id, detail="Schedule not found")

    q = (
        select(AgentScheduleRun)
        .where(AgentScheduleRun.schedule_id == schedule_id)
        .order_by(AgentScheduleRun.started_at.desc())
        .limit(limit)
    )
    rows = (await session.execute(q)).scalars().all()
    return [AgentScheduleRunResponse.model_validate(r, from_attributes=True) for r in rows]

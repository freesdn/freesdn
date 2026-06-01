# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — per-agent activity drilldown endpoints.

Powers the /agents/{id} detail page on the frontend. Each endpoint
scopes to a single agent via the path param and joins the relevant
contextual tables (schedule name on runs, etc.) so the page renders
without follow-up requests per row.

All endpoints require `agent:read` and auto-filter by org via the
parent RemoteAgent → Site → Organization chain.
"""

import logging
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import Integer, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, is_unscoped_superuser, require_permissions
from app.core.site_access import assert_can_access_site
from app.db import get_session
from app.models.agents import (
    AgentSchedule,
    AgentScheduleRun,
    RemoteAgent,
)
from app.models.core import Site
from app.models.devices import DiscoveredHost, TopologyEdge

logger = logging.getLogger(__name__)
router = APIRouter()


async def _verify_agent_access(
    session: AsyncSession,
    agent_id: UUID,
    current_user: CurrentUser,
) -> RemoteAgent:
    """Fetch the agent row and 404 if the caller can't see it.

    Same shape as the existing _verify_agent_org helper in agents.py but
    returns the row instead of just bool, so the detail endpoints have
    site_id/org_id without re-querying.
    """
    q = await session.execute(
        select(RemoteAgent).where(
            RemoteAgent.id == agent_id,
            RemoteAgent.deleted_at.is_(None),
        )
    )
    agent = q.scalar_one_or_none()
    if not agent:
        raise HTTPException(404, "Agent not found")
    if not is_unscoped_superuser(current_user):
        # Walk to the site to check org
        sq = await session.execute(
            select(Site).where(Site.id == agent.site_id, Site.deleted_at.is_(None))
        )
        site = sq.scalar_one_or_none()
        if not site or site.organization_id != current_user.organization_id:
            raise HTTPException(404, "Agent not found")
        # site-limited callers only reach agents in granted sites.
        assert_can_access_site(current_user, agent.site_id, detail="Agent not found")
    return agent


class AgentRunRow(BaseModel):
    id: UUID
    schedule_id: UUID
    schedule_name: str | None
    status: str
    device_count: int
    duration_seconds: float | None
    error_message: str | None
    started_at: datetime
    completed_at: datetime | None


@router.get(
    "/{agent_id}/runs",
    response_model=list[AgentRunRow],
    summary="Recent scheduled-scan runs executed by this agent",
)
async def list_agent_runs(
    agent_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = Query(50, ge=1, le=500),
) -> Any:
    """Cross-schedule run history for one agent (newest first).

    Joins AgentSchedule so the schedule name shows up in the UI
    without another roundtrip per row.
    """
    await _verify_agent_access(session, agent_id, current_user)
    q = (
        select(AgentScheduleRun, AgentSchedule.name.label("schedule_name"))
        .join(AgentSchedule, AgentScheduleRun.schedule_id == AgentSchedule.id)
        .where(AgentScheduleRun.agent_id == agent_id)
        .order_by(AgentScheduleRun.started_at.desc())
        .limit(limit)
    )
    rows = (await session.execute(q)).all()
    return [
        AgentRunRow(
            id=r[0].id,
            schedule_id=r[0].schedule_id,
            schedule_name=r[1],
            status=r[0].status,
            device_count=r[0].device_count,
            duration_seconds=r[0].duration_seconds,
            error_message=r[0].error_message,
            started_at=r[0].started_at,
            completed_at=r[0].completed_at,
        )
        for r in rows
    ]


@router.get(
    "/{agent_id}/discoveries",
    response_model=list[dict],
    summary="Discovered hosts attributed to this agent (latest first)",
)
async def list_agent_discoveries(
    agent_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = Query(100, ge=1, le=1000),
) -> Any:
    """DiscoveredHost rows where discovered_by_agent_id == this agent.

    Newest-first by last_seen. Includes is_adopted so the page can
    distinguish managed-by-now devices from still-discovery rows.
    """
    agent = await _verify_agent_access(session, agent_id, current_user)
    # filter to the agent's CURRENT site so a moved
    # agent doesn't keep returning rows from its previous site.
    q = (
        select(DiscoveredHost)
        .where(
            DiscoveredHost.discovered_by_agent_id == agent_id,
            DiscoveredHost.site_id == agent.site_id,
            DiscoveredHost.deleted_at.is_(None),
        )
        .order_by(DiscoveredHost.last_seen.desc())
        .limit(limit)
    )
    rows = (await session.execute(q)).scalars().all()
    return [
        {
            "id": str(r.id),
            "ip_address": r.ip_address,
            "mac_address": r.mac_address,
            "hostname": r.hostname,
            "vendor": r.vendor,
            "device_type": r.device_type,
            "is_adopted": r.is_adopted,
            "adopted_device_id": str(r.adopted_device_id) if r.adopted_device_id else None,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in rows
    ]


@router.get(
    "/{agent_id}/topology-edges",
    response_model=list[dict],
    summary="LLDP/CDP edges observed by this agent",
)
async def list_agent_topology(
    agent_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = Query(200, ge=1, le=1000),
) -> Any:
    """TopologyEdge rows captured by this agent's listeners.

    Useful for "which neighbors is this agent seeing?" debugging when
    LLDP doesn't show up in the org-wide topology view.
    """
    agent = await _verify_agent_access(session, agent_id, current_user)
    # filter to the agent's CURRENT site.
    q = (
        select(TopologyEdge)
        .where(
            TopologyEdge.discovered_by_agent_id == agent_id,
            TopologyEdge.site_id == agent.site_id,
            TopologyEdge.deleted_at.is_(None),
        )
        .order_by(TopologyEdge.last_seen.desc())
        .limit(limit)
    )
    rows = (await session.execute(q)).scalars().all()
    return [
        {
            "id": str(r.id),
            "protocol": r.protocol,
            "local_interface": r.local_interface,
            "neighbor_chassis_id": r.neighbor_chassis_id,
            "neighbor_port_id": r.neighbor_port_id,
            "neighbor_system_name": r.neighbor_system_name,
            "vlan_id": r.vlan_id,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in rows
    ]


@router.get(
    "/{agent_id}/schedules",
    response_model=list[dict],
    summary="Schedules that target this agent (pinned + site-wide)",
)
async def list_agent_schedules(
    agent_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """All schedules this agent will execute.

    Both schedules pinned via agent_id AND site-wide schedules
    (agent_id=NULL) at the agent's site. Mirrors the filter logic the
    bootstrap-push uses so the UI shows exactly what the daemon sees.
    """
    agent = await _verify_agent_access(session, agent_id, current_user)
    q = (
        select(AgentSchedule)
        .where(
            AgentSchedule.site_id == agent.site_id,
            AgentSchedule.deleted_at.is_(None),
            ((AgentSchedule.agent_id == agent_id) | (AgentSchedule.agent_id.is_(None))),
        )
        .order_by(AgentSchedule.created_at.desc())
    )
    rows = (await session.execute(q)).scalars().all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "scan_type": r.scan_type,
            "cron": r.cron,
            "targets": r.targets or [],
            "enabled": r.enabled,
            "last_fired_at": r.last_fired_at.isoformat() if r.last_fired_at else None,
            "is_pinned": r.agent_id == agent_id,
        }
        for r in rows
    ]


@router.get(
    "/{agent_id}/metrics",
    summary="Prometheus text-format metrics for one agent",
)
async def agent_metrics(
    agent_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Per-agent metrics in Prometheus text format.

    Exposes the metrics the existing UI surfaces (heartbeat age,
    runs/24h, last fired ago, discovered host count) so an operator's
    Prometheus can scrape them without going through the JSON API.

    All counter names are prefixed ``freesdn_agent_`` and labeled
    with ``agent_id``, ``agent_name``, and ``site_id``. Returned as
    ``text/plain; version=0.0.4; charset=utf-8`` to satisfy
    Prometheus exposition format.
    """
    from datetime import UTC, datetime, timedelta

    from fastapi.responses import PlainTextResponse
    from sqlalchemy import func

    agent = await _verify_agent_access(session, agent_id, current_user)

    now = datetime.now(UTC)
    cutoff_24h = now - timedelta(hours=24)

    # Heartbeat age
    heartbeat_age = (now - agent.last_heartbeat).total_seconds() if agent.last_heartbeat else -1
    status_value = 1.0 if agent.status == "online" else 0.0

    # Runs in last 24h
    runs_row = (
        await session.execute(
            select(
                func.count(AgentScheduleRun.id),
                func.sum(func.cast(AgentScheduleRun.status == "failed", Integer)),
                func.max(AgentScheduleRun.started_at),
            ).where(
                AgentScheduleRun.agent_id == agent_id,
                AgentScheduleRun.started_at >= cutoff_24h,
            )
        )
    ).one()
    runs_24h_total = int(runs_row[0] or 0)
    runs_24h_failed = int(runs_row[1] or 0)
    last_run_at = runs_row[2]
    last_run_age = (now - last_run_at).total_seconds() if last_run_at else -1

    # Schedule count
    schedule_count = (
        await session.execute(
            select(func.count(AgentSchedule.id)).where(
                AgentSchedule.site_id == agent.site_id,
                AgentSchedule.deleted_at.is_(None),
                ((AgentSchedule.agent_id == agent_id) | (AgentSchedule.agent_id.is_(None))),
            )
        )
    ).scalar_one() or 0

    # Discoveries contributed
    discoveries = (
        await session.execute(
            select(func.count(DiscoveredHost.id)).where(
                DiscoveredHost.discovered_by_agent_id == agent_id,
                DiscoveredHost.deleted_at.is_(None),
            )
        )
    ).scalar_one() or 0

    labels = f'agent_id="{agent.id}",agent_name="{agent.name}",site_id="{agent.site_id}"'

    lines = [
        "# HELP freesdn_agent_up 1 if agent status=online, 0 otherwise",
        "# TYPE freesdn_agent_up gauge",
        f"freesdn_agent_up{{{labels}}} {status_value}",
        "",
        "# HELP freesdn_agent_heartbeat_age_seconds Seconds since last heartbeat (-1 if never)",
        "# TYPE freesdn_agent_heartbeat_age_seconds gauge",
        f"freesdn_agent_heartbeat_age_seconds{{{labels}}} {heartbeat_age}",
        "",
        "# HELP freesdn_agent_runs_24h_total Scheduled scans run in the last 24h",
        "# TYPE freesdn_agent_runs_24h_total counter",
        f"freesdn_agent_runs_24h_total{{{labels}}} {runs_24h_total}",
        "",
        "# HELP freesdn_agent_runs_24h_failed Scheduled scans that failed in the last 24h",
        "# TYPE freesdn_agent_runs_24h_failed counter",
        f"freesdn_agent_runs_24h_failed{{{labels}}} {runs_24h_failed}",
        "",
        "# HELP freesdn_agent_last_run_age_seconds Seconds since last scheduled-scan run (-1 if never)",
        "# TYPE freesdn_agent_last_run_age_seconds gauge",
        f"freesdn_agent_last_run_age_seconds{{{labels}}} {last_run_age}",
        "",
        "# HELP freesdn_agent_schedules_total Schedules targeting this agent (pinned + site-wide)",
        "# TYPE freesdn_agent_schedules_total gauge",
        f"freesdn_agent_schedules_total{{{labels}}} {schedule_count}",
        "",
        "# HELP freesdn_agent_discovered_hosts_total Hosts contributed to discovered_hosts by this agent",
        "# TYPE freesdn_agent_discovered_hosts_total gauge",
        f"freesdn_agent_discovered_hosts_total{{{labels}}} {discoveries}",
        "",
    ]
    return PlainTextResponse(
        "\n".join(lines),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )

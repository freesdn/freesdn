# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Remote Agent API Endpoints
=========================================

REST API for managing remote site agents.
Includes agent registration, approval, CRUD, heartbeats,
task management, WebSocket connections, and cleanup utilities.
"""

import asyncio
import hashlib
import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Integer, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import (
    CurrentUser,
    is_unscoped_superuser,
    require_permissions,
)
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.db.session import get_logdb_session
from app.models.agents import AgentSchedule, AgentScheduleRun, AgentTaskType, RemoteAgent
from app.models.core import Site
from app.models.devices import DiscoveredHost
from app.schemas.agents import (
    AgentAuthRequest,
    AgentAuthResponse,
    AgentFingerprintRequest,
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentResponse,
    AgentStatsResponse,
    AgentSummary,
    AgentUpdateRequest,
    HeartbeatCreate,
    HeartbeatResponse,
    InteractiveScanRequest,
    InteractiveScanResponse,
    TaskCreate,
    TaskResponse,
    TaskUpdate,
)
from app.schemas.core import MessageResponse, PaginatedResponse
from app.services.remote_agent import (
    AgentCommand,
    AgentCommandType,
    AgentNotFoundError,
    AgentRegistryService,
    PersistentAgentService,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# =============================================================================
# Helpers
# =============================================================================


def _org_id(user: Any) -> UUID:
    """Extract organization_id from the current user; raise if missing."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _org_site_filter(organization_id: UUID) -> Any:
    """Return a scalar subquery of site IDs belonging to the organization."""
    return (
        select(Site.id)
        .where(Site.organization_id == organization_id, Site.deleted_at.is_(None))
        .scalar_subquery()
    )


async def _verify_agent_org(
    agent_id: UUID,
    organization_id: UUID,
    session: AsyncSession,
    current_user: "CurrentUser | None" = None,
) -> "RemoteAgent":
    """
    Fetch an agent by ID and verify it belongs to the given organization
    AND that a site-limited caller is granted the agent's
    site — without this, a site-limited user could read or dispatch commands to
    agents in sibling sites of the same org. Raises 404 otherwise.
    """
    svc = PersistentAgentService(session)
    agent = await svc.get_agent(agent_id)
    if not agent or agent.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Agent not found")
    if current_user is not None:
        assert_can_access_site(current_user, agent.site_id, detail="Agent not found")
    return agent


def _agent_to_response(agent: Any) -> AgentResponse:
    """Convert DB model to response schema."""
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        agent_type=agent.agent_type,
        version=agent.version,
        platform=agent.platform,
        capabilities=agent.capabilities or {},
        supported_vendors=agent.supported_vendors or [],
        config=agent.config or {},
        last_ip=agent.last_ip,
        last_hostname=agent.last_hostname,
        status=agent.status,
        last_seen=agent.last_seen,
        last_heartbeat=agent.last_heartbeat,
        uptime_seconds=agent.uptime_seconds or 0,
        connected_at=agent.connected_at,
        disconnected_at=agent.disconnected_at,
        total_connections=agent.total_connections or 0,
        total_tasks_executed=agent.total_tasks_executed or 0,
        failed_tasks=agent.failed_tasks or 0,
        poll_interval=agent.poll_interval or 30,
        is_approved=agent.is_approved,
        approved_at=agent.approved_at,
        is_enabled=agent.is_enabled,
        site_id=agent.site_id,
        organization_id=agent.organization_id,
        site_name=agent.site.name if agent.site else None,
        organization_name=agent.organization.name if agent.organization else None,
        approved_by_name=(agent.approved_by.username if agent.approved_by else None),
        notification_channels=agent.notification_channels or {},
        offline_threshold_seconds=agent.offline_threshold_seconds or 180,
        offline_notified_at=agent.offline_notified_at,
        created_at=agent.created_at,
        updated_at=agent.updated_at,
    )


def _agent_to_summary(agent: Any) -> AgentSummary:
    """Convert DB model to summary schema."""
    return AgentSummary(
        id=agent.id,
        name=agent.name,
        agent_type=agent.agent_type,
        status=agent.status,
        last_ip=agent.last_ip,
        last_heartbeat=agent.last_heartbeat,
        site_id=agent.site_id,
        site_name=agent.site.name if agent.site else None,
        is_approved=agent.is_approved,
        is_enabled=agent.is_enabled,
    )


async def _authenticate_agent(
    session: AsyncSession,
    agent_id: UUID,
    agent_key: str,
) -> RemoteAgent:
    """Authenticate an agent using its plaintext key against the stored hash."""
    svc = PersistentAgentService(session)
    agent = await svc.verify_credentials(agent_id, agent_key)
    # reject unapproved agents the same way disabled ones are rejected.
    # Previously only is_enabled was checked, allowing an unapproved agent to
    # authenticate and receive commands through _authenticate_agent callers.
    if not agent or not agent.is_enabled or not agent.is_approved:
        raise HTTPException(status_code=401, detail="Invalid agent key")
    return agent


# =============================================================================
# Agent Registration
# =============================================================================


@router.post("/register", response_model=AgentRegisterResponse)
async def register_agent(
    data: AgentRegisterRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:create"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """
    Register a new remote agent for a site.

    Returns a one-time API key that must be stored securely.
    The key is never shown again after this response.
    """
    svc = PersistentAgentService(session)

    org_id = _org_id(current_user)

    # Verify site belongs to caller's org BEFORE registering — without
    # this, an org_admin could mint an agent attached to a foreign org's
    # site, and the FK constraint would only bubble a 500 (instead of a
    # clean 404) since core.sites is a global table.
    site_check = await session.execute(
        select(Site.id).where(
            Site.id == data.site_id,
            Site.organization_id == org_id,
            Site.deleted_at.is_(None),
        )
    )
    if site_check.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Site not found")
    # a site-limited user may only register agents at granted sites.
    assert_can_access_site(current_user, data.site_id, detail="Site not found")

    agent, api_key = await svc.register_agent(
        name=data.name,
        site_id=data.site_id,
        organization_id=org_id,
        description=data.description,
        agent_type=data.agent_type,
    )
    await session.commit()

    # NOTE: audit agent registration. Previously this endpoint
    # minted a long-lived API key without any audit trail — an attacker
    # who briefly compromised an org_admin could register a back-door
    # agent and leave no record. We log the registration with the agent
    # ID + site, but explicitly DO NOT include ``api_key`` in metadata
    # (the key would otherwise persist in the audit log forever).
    try:
        from app.services.audit import AuditService

        audit = AuditService(session)
        await audit.log(
            action="agent.register",
            resource_type="agent",
            resource_id=agent.id,
            resource_name=data.name,
            actor_id=current_user.id,
            actor_name=getattr(current_user, "full_name", None)
            or getattr(current_user, "email", None),
            actor_email=getattr(current_user, "email", None),
            organization_id=org_id,
            site_id=data.site_id,
            extra_metadata={
                "agent_type": data.agent_type,
                "agent_id": str(agent.id),
                # NOTE: do NOT include api_key here — it must never
                # land in the audit trail.
            },
            tags=["agent", "registration"],
        )
        await session.commit()
    except Exception:
        # Audit-log failure must never break the registration response;
        # the key has already been minted and the operator needs it back.
        logger.warning(
            "Failed to create audit log for agent registration %s",
            agent.id,
            exc_info=True,
        )

    # Build WebSocket URL from PUBLIC_BASE_URL
    base = settings.PUBLIC_BASE_URL.rstrip("/")
    ws_base = base.replace("https://", "wss://").replace("http://", "ws://")
    ws_url = f"{ws_base}{settings.API_V1_PREFIX}/agents/ws/{agent.id}"

    return AgentRegisterResponse(
        agent_id=str(agent.id),
        agent_key=api_key,
        websocket_url=ws_url,
        instructions=(
            f"Set these environment variables on the agent:\n"
            f"  FREESDN_AGENT_ID={agent.id}\n"
            f"  FREESDN_API_KEY={api_key}\n"
            f"  FREESDN_SERVER_URL={ws_url}\n"
            f"\nThen start the agent process."
        ),
    )


# =============================================================================
# Agent CRUD
# =============================================================================


@router.get("/", response_model=PaginatedResponse[AgentSummary])
async def list_agents(
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
    agent_status: str | None = Query(None, alias="status"),
    agent_type: str | None = None,
    is_approved: bool | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=200),
) -> Any:
    """List agents with optional filtering and pagination."""
    svc = PersistentAgentService(session)

    org_id = _org_id(current_user)
    offset = (page - 1) * per_page

    agents, total = await svc.list_agents(
        organization_id=org_id,
        site_id=site_id,
        status=agent_status,
        agent_type=agent_type,
        is_approved=is_approved,
        limit=per_page,
        offset=offset,
        accessible_site_ids=(
            current_user.accessible_site_ids if current_user.is_site_limited else None
        ),
    )

    items = [_agent_to_summary(a) for a in agents]
    return PaginatedResponse.create(items, total, page, per_page)


@router.get("/stats", response_model=AgentStatsResponse)
async def get_agent_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get aggregate agent statistics."""
    org_id = _org_id(current_user)

    # a site-limited caller must only see aggregate
    # counts for agents in their granted sites — the org-wide service aggregate
    # would otherwise leak sibling-site agent totals. Apply the canonical
    # site_scope_filter here (the service method is org-scoped only).
    if current_user.is_site_limited:
        from sqlalchemy import case
        from sqlalchemy import func as sa_func

        query = (
            select(
                sa_func.count(RemoteAgent.id).label("total"),
                sa_func.count(case((RemoteAgent.status == "online", 1))).label("online"),
                sa_func.count(case((RemoteAgent.status == "offline", 1))).label("offline"),
                sa_func.count(case((RemoteAgent.status == "error", 1))).label("error"),
                sa_func.count(
                    case((RemoteAgent.is_approved == False, 1))  # noqa: E712
                ).label("pending_approval"),
            )
            .where(RemoteAgent.deleted_at.is_(None))
            .where(site_scope_filter(current_user, RemoteAgent.site_id))
        )
        if org_id:
            query = query.where(RemoteAgent.organization_id == org_id)
        row = (await session.execute(query)).one()
        return AgentStatsResponse(
            total=row.total,
            online=row.online,
            offline=row.offline,
            error=row.error,
            pending_approval=row.pending_approval,
        )

    svc = PersistentAgentService(session)
    stats = await svc.get_agent_stats(organization_id=org_id)
    return AgentStatsResponse(**stats)


@router.get("/site/{site_id}", response_model=list[AgentSummary])
async def get_agents_for_site(
    site_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get all agents for a specific site."""
    org_id = _org_id(current_user)

    # Verify the site belongs to the caller's organization
    site_result = await session.execute(
        select(Site).where(
            Site.id == site_id, Site.organization_id == org_id, Site.deleted_at.is_(None)
        )
    )
    if not site_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Site not found")

    # Enforce per-user site grant: a site-limited user must
    # not be able to probe sibling sites within the same org.
    assert_can_access_site(current_user, site_id, detail="Site not found")

    svc = PersistentAgentService(session)
    agents = await svc.get_agents_for_site(site_id)
    return [_agent_to_summary(a) for a in agents]


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a single agent by ID."""
    org_id = _org_id(current_user)
    agent = await _verify_agent_org(agent_id, org_id, session, current_user)
    return _agent_to_response(agent)


@router.patch("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: UUID,
    data: AgentUpdateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update agent configuration."""
    org_id = _org_id(current_user)
    await _verify_agent_org(agent_id, org_id, session, current_user)

    svc = PersistentAgentService(session)

    update_data = data.model_dump(exclude_unset=True)
    # Never trust user-supplied organization_id
    update_data.pop("organization_id", None)
    agent = await svc.update_agent(agent_id, **update_data)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    await session.commit()
    return _agent_to_response(agent)


@router.post("/{agent_id}/approve", response_model=AgentResponse)
async def approve_agent(
    agent_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Approve an agent to allow task execution."""
    org_id = _org_id(current_user)
    await _verify_agent_org(agent_id, org_id, session, current_user)

    svc = PersistentAgentService(session)
    agent = await svc.approve_agent(agent_id, approved_by_id=current_user.id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    await session.commit()
    return _agent_to_response(agent)


@router.delete("/{agent_id}", response_model=MessageResponse)
async def delete_agent(
    agent_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:delete"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    logdb: Annotated[AsyncSession, Depends(get_logdb_session)],
) -> Any:
    """Soft-delete an agent and purge its heartbeats from LogDB."""
    org_id = _org_id(current_user)
    await _verify_agent_org(agent_id, org_id, session, current_user)

    svc = PersistentAgentService(session)
    deleted = await svc.soft_delete_agent(agent_id, logdb_session=logdb)
    if not deleted:
        raise HTTPException(status_code=404, detail="Agent not found")

    await logdb.commit()
    await session.commit()
    return MessageResponse(message="Agent deleted successfully")


# =============================================================================
# Heartbeats
# =============================================================================


@router.post("/{agent_id}/heartbeat", response_model=HeartbeatResponse)
async def record_heartbeat(
    agent_id: UUID,
    data: HeartbeatCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    logdb: Annotated[AsyncSession, Depends(get_logdb_session)],
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
) -> Any:
    """
    Record agent heartbeat.

    Called by the agent process to report health status.
    Requires X-Agent-Key header for authentication.
    """
    svc = PersistentAgentService(session)
    await _authenticate_agent(session, agent_id, x_agent_key)

    heartbeat = await svc.record_heartbeat(
        agent_id=agent_id,
        cpu_percent=data.cpu_percent,
        memory_percent=data.memory_percent,
        disk_percent=data.disk_percent,
        status=data.status,
        latency_ms=data.latency_ms,
        managed_devices=data.managed_devices,
        active_tasks=data.active_tasks,
        logdb_session=logdb,
    )

    await logdb.commit()
    await session.commit()
    return HeartbeatResponse(
        id=heartbeat.id,
        agent_id=heartbeat.agent_id,
        timestamp=heartbeat.timestamp,
        cpu_percent=heartbeat.cpu_percent,
        memory_percent=heartbeat.memory_percent,
        disk_percent=heartbeat.disk_percent,
        status=heartbeat.status,
        latency_ms=heartbeat.latency_ms,
        managed_devices=heartbeat.managed_devices,
        active_tasks=heartbeat.active_tasks,
    )


@router.get("/{agent_id}/heartbeats", response_model=list[HeartbeatResponse])
async def get_heartbeats(
    agent_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    logdb: Annotated[AsyncSession, Depends(get_logdb_session)],
    limit: int = Query(100, ge=1, le=1000),
    since_hours: int = Query(24, ge=1, le=168),
) -> Any:
    """Get heartbeat history for an agent (default last 24 hours)."""
    org_id = _org_id(current_user)
    await _verify_agent_org(agent_id, org_id, session, current_user)

    svc = PersistentAgentService(session)
    since = datetime.now(UTC) - timedelta(hours=since_hours)
    heartbeats = await svc.get_heartbeats(agent_id, limit=limit, since=since, logdb_session=logdb)

    return [
        HeartbeatResponse(
            id=hb.id,
            agent_id=hb.agent_id,
            timestamp=hb.timestamp,
            cpu_percent=hb.cpu_percent,
            memory_percent=hb.memory_percent,
            disk_percent=hb.disk_percent,
            status=hb.status,
            latency_ms=hb.latency_ms,
            managed_devices=hb.managed_devices,
            active_tasks=hb.active_tasks,
        )
        for hb in heartbeats
    ]


# =============================================================================
# Tasks
# =============================================================================


# Catastrophic / device-mutating task types. Queueing one of these tells the
# remote agent to change live device state (run an action, push config, rotate
# credentials) or to self-update — none are reversible from FreeSDN's side once
# the agent picks them up. Like the staged-write catastrophic gate
# (adapter_proxmox_preflight.gate), these require an explicit
# ``task_data["confirmed"] = true`` so a stray automation or a single
# agent:write toggle can't silently dispatch a destructive op. Read-only task
# types (scan_network, fingerprint_device, probe_api, backup_config,
# collect_metrics, get_device_status) are intentionally NOT gated.
_CONFIRM_REQUIRED_TASK_TYPES: frozenset[str] = frozenset(
    {
        AgentTaskType.EXECUTE_ACTION.value,
        AgentTaskType.PUSH_CONFIG.value,
        AgentTaskType.UPDATE_CREDENTIALS.value,
        AgentTaskType.UPDATE_AGENT.value,
    }
)


@router.post("/{agent_id}/tasks", response_model=TaskResponse)
async def create_task(
    agent_id: UUID,
    data: TaskCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Create a task for an agent to execute."""
    org_id = _org_id(current_user)
    agent = await _verify_agent_org(agent_id, org_id, session, current_user)

    svc = PersistentAgentService(session)

    if not agent.is_approved:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent must be approved before assigning tasks",
        )

    # Catastrophic-op gate: device/config-mutating task types must carry an
    # explicit confirmation token, mirroring the staged-write confirmed=true
    # idiom. Without this a single agent:write call queues a live config push
    # / credential rotation / agent self-update with no second factor.
    if str(data.task_type) in _CONFIRM_REQUIRED_TASK_TYPES and not bool(
        (data.task_data or {}).get("confirmed")
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Task type {str(data.task_type)!r} mutates live device/agent state; "
                "re-submit with task_data.confirmed=true to proceed"
            ),
        )

    task = await svc.create_task(
        agent_id=agent_id,
        task_type=data.task_type,
        task_data=data.task_data,
        priority=data.priority,
        scheduled_at=data.scheduled_at,
        max_retries=data.max_retries,
    )

    await session.commit()
    return TaskResponse.model_validate(task)


@router.get("/{agent_id}/tasks", response_model=list[TaskResponse])
async def list_agent_tasks(
    agent_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    task_status: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Any:
    """List tasks for a specific agent."""
    org_id = _org_id(current_user)
    await _verify_agent_org(agent_id, org_id, session, current_user)

    svc = PersistentAgentService(session)
    tasks = await svc.get_agent_tasks(
        agent_id,
        status=task_status,
        limit=limit,
        offset=offset,
    )
    return [TaskResponse.model_validate(t) for t in tasks]


@router.get("/{agent_id}/tasks/pending", response_model=list[TaskResponse])
async def get_pending_tasks(
    agent_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
) -> Any:
    """
    Get pending tasks for an agent.

    Called by the agent process to poll for work.
    Tasks are returned in priority order (1 = highest).
    Requires X-Agent-Key header for authentication.
    """
    svc = PersistentAgentService(session)
    await _authenticate_agent(session, agent_id, x_agent_key)
    tasks = await svc.get_pending_tasks(agent_id)
    return [TaskResponse.model_validate(t) for t in tasks]


@router.patch("/tasks/{task_id}", response_model=TaskResponse)
async def update_task(
    task_id: UUID,
    data: TaskUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
) -> Any:
    """
    Update task status/progress.

    Called by the agent to report progress and results.
    Requires X-Agent-Key header for authentication.
    """
    svc = PersistentAgentService(session)

    # Verify the task belongs to an agent that matches the key
    from app.models.agents import AgentTask

    result = await session.execute(select(AgentTask).where(AgentTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    await _authenticate_agent(session, task.agent_id, x_agent_key)

    update_data = data.model_dump(exclude_unset=True)
    task = await svc.update_task(task_id, **update_data)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    await session.commit()
    return TaskResponse.model_validate(task)


@router.delete("/tasks/{task_id}", response_model=MessageResponse)
async def cancel_task(
    task_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Cancel a pending or running task."""
    org_id = _org_id(current_user)

    # Verify the task's agent belongs to the caller's organization
    from app.models.agents import AgentTask

    result = await session.execute(select(AgentTask).where(AgentTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    await _verify_agent_org(task.agent_id, org_id, session, current_user)

    svc = PersistentAgentService(session)
    cancelled = await svc.cancel_task(task_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail="Task not found")

    await session.commit()
    return MessageResponse(message="Task cancelled")


# =============================================================================
# Interactive scan (operator-triggered, WS push)
# =============================================================================


@router.post(
    "/{agent_id}/scan",
    response_model=InteractiveScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def run_interactive_scan(
    agent_id: UUID,
    data: InteractiveScanRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Dispatch a network scan to the agent via the live WebSocket.

    Unlike the legacy ``POST /discovery/agent-scan`` (which creates a
    pending DB task that the agent later polls for), this endpoint
    pushes the command immediately. The agent's ``scan_progress`` /
    ``scan_result`` reports are mirrored into the ``agent_tasks`` row
    so the web UI can poll ``GET /agents/{id}/scan/{task_id}`` to
    render a live progress card.

    Returns 409 if the agent is offline (no WS connection) since
    queueing a command we can't deliver would leave the task pinned
    in ``running`` forever.
    """
    org_id = _org_id(current_user)
    agent = await _verify_agent_org(agent_id, org_id, session, current_user)

    if not agent.is_approved or not agent.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent must be approved and enabled before running scans",
        )

    # Capability gate — matches the schedule-create validation so the
    # operator gets the same 400 they'd see when scheduling a scan_type
    # the agent can't run.
    caps = agent.capabilities or {}
    supported_types = caps.get("scan_types") or []
    if supported_types and data.scan_type not in supported_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Agent does not support scan_type={data.scan_type!r}; supported: {supported_types}"
            ),
        )

    # Live WS in the registry is the ground truth, not the DB status
    # column. There's a known lag where ``cleanup_stale_agents`` flips
    # the row to offline because heartbeat WS messages don't currently
    # persist ``last_heartbeat`` (followed up separately). Trusting the
    # registry here means an operator can still dispatch as long as the
    # daemon's WebSocket is genuinely connected.
    registry = await get_agent_registry(session)
    connection = registry.get_connection_for_site(agent.site_id)
    if connection is None or connection.info.agent_id != str(agent.id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(f"Agent has no active WebSocket connection (DB status: {agent.status})"),
        )

    svc = PersistentAgentService(session)
    task = await svc.create_task(
        agent_id=agent.id,
        task_type=AgentCommandType.SCAN_NETWORK.value,
        task_data={
            "scan_type": data.scan_type,
            "targets": data.targets or [],
            "requested_by": str(current_user.id),
            "interactive": True,
        },
        priority=3,
    )
    # Mark running immediately — the agent's first scan_progress tick
    # may not arrive for a few seconds, and we don't want the UI to
    # show "pending" against a command we've already wired.
    task.status = "running"
    task.started_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(task)

    command = AgentCommand(
        id=str(task.id),
        type=AgentCommandType.SCAN_NETWORK,
        payload={
            "scan_type": data.scan_type,
            "targets": data.targets or [],
        },
        priority=3,
        timeout_seconds=float(data.timeout_seconds),
    )

    registry.register_interactive_task(str(task.id))
    try:
        await connection.send_command(command, wait_result=False)
    except AgentNotFoundError as exc:
        registry.unregister_interactive_task(str(task.id))
        task.status = "failed"
        task.error_message = str(exc)
        task.completed_at = datetime.now(UTC)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Agent disconnected before scan could be dispatched",
        ) from exc
    except Exception as exc:
        registry.unregister_interactive_task(str(task.id))
        task.status = "failed"
        task.error_message = f"Dispatch failed: {exc}"
        task.completed_at = datetime.now(UTC)
        await session.commit()
        logger.exception("Interactive scan dispatch failed for agent %s", agent.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to dispatch scan command",
        ) from exc

    return InteractiveScanResponse(
        task_id=task.id,
        agent_id=agent.id,
        scan_type=data.scan_type,
        status=task.status,
        dispatched_at=task.started_at or datetime.now(UTC),
        message=f"Scan dispatched to agent {agent.name!r}",
    )


@router.post(
    "/{agent_id}/fingerprint",
    response_model=InteractiveScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def run_fingerprint(
    agent_id: UUID,
    data: AgentFingerprintRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Deep-probe a single device via the agent's FINGERPRINT_DEVICE command.

    Body must include ``ip_address`` (a single routable IP — CIDRs and
    ranges are rejected). The fingerprint runs every available scanner
    against the host (ICMP + port + HTTP banner + SNMP + mDNS + SSDP)
    and returns the merged result. Mirrors the interactive-scan dispatch
    pattern so progress + result land in the agent_tasks row and the same
    polling endpoint works.
    """
    # ip_address is now validated by AgentFingerprintRequest (single
    # routable IP, SSRF-safe) — no manual extraction or empty-check needed.
    ip = data.ip_address

    org_id = _org_id(current_user)
    agent = await _verify_agent_org(agent_id, org_id, session, current_user)

    if not agent.is_approved or not agent.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent must be approved and enabled before fingerprinting",
        )

    registry = await get_agent_registry(session)
    connection = registry.get_connection_for_site(agent.site_id)
    if connection is None or connection.info.agent_id != str(agent.id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(f"Agent has no active WebSocket connection (DB status: {agent.status})"),
        )

    svc = PersistentAgentService(session)
    task = await svc.create_task(
        agent_id=agent.id,
        task_type=AgentCommandType.FINGERPRINT_DEVICE.value,
        task_data={
            "ip_address": ip,
            "requested_by": str(current_user.id),
            "interactive": True,
        },
        priority=3,
    )
    task.status = "running"
    task.started_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(task)

    command = AgentCommand(
        id=str(task.id),
        type=AgentCommandType.FINGERPRINT_DEVICE,
        payload={"ip_address": ip},
        priority=3,
        timeout_seconds=120.0,
    )

    registry.register_interactive_task(str(task.id))
    try:
        await connection.send_command(command, wait_result=False)
    except Exception as exc:
        registry.unregister_interactive_task(str(task.id))
        task.status = "failed"
        task.error_message = f"Dispatch failed: {exc}"
        task.completed_at = datetime.now(UTC)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to dispatch fingerprint command",
        ) from exc

    return InteractiveScanResponse(
        task_id=task.id,
        agent_id=agent.id,
        scan_type="fingerprint",
        status=task.status,
        dispatched_at=task.started_at or datetime.now(UTC),
        message=f"Fingerprint dispatched to agent {agent.name!r} for {ip}",
    )


@router.get("/{agent_id}/scan/{task_id}", response_model=TaskResponse)
async def get_interactive_scan_status(
    agent_id: UUID,
    task_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Return current state of an interactive scan task.

    Frontend polls this every ~1.5s while a scan is running. Status
    transitions from ``running`` → ``completed`` (devices in
    ``result``) or ``failed`` (reason in ``error_message``).
    """
    org_id = _org_id(current_user)
    await _verify_agent_org(agent_id, org_id, session, current_user)

    from app.models.agents import AgentTask

    result = await session.execute(
        select(AgentTask).where(
            AgentTask.id == task_id,
            AgentTask.agent_id == agent_id,
        )
    )
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")

    return TaskResponse.model_validate(task)


# =============================================================================
# Agent Authentication
# =============================================================================


@router.post("/auth/verify", response_model=AgentAuthResponse)
async def verify_agent_auth(
    data: AgentAuthRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Verify agent credentials (agent_id + agent_key).

    NOTE: previously this endpoint returned three distinct
    failure shapes — bad UUID format, valid creds but ``is_enabled=False``,
    not-approved, and invalid creds. An attacker holding only a leaked
    agent_id could probe to learn whether the agent existed and whether it
    was enabled, which is useful intel for targeted social-engineering of
    the site operator (e.g. "your agent X is offline — please enable it").
    All failure cases now collapse to a single
    ``{"valid": false, "message": "Invalid credentials"}`` response and the
    real reason is logged server-side at WARNING for ops triage.
    """
    svc = PersistentAgentService(session)

    invalid_response = AgentAuthResponse(valid=False, message="Invalid credentials")

    try:
        agent_uuid = UUID(data.agent_id)
    except ValueError:
        logger.warning(
            "agent verify failed: agent_id=%r reason=invalid_uuid_format",
            data.agent_id,
        )
        return invalid_response

    agent = await svc.verify_credentials(agent_uuid, data.agent_key)
    if not agent:
        logger.warning(
            "agent verify failed: agent_id=%s reason=no_match_or_bad_key",
            agent_uuid,
        )
        return invalid_response

    # Collapse the disabled/not-approved branches into the same generic
    # failure so the caller learns nothing more than they would from a
    # plain bad-key response.
    if not agent.is_enabled:
        logger.warning(
            "agent verify failed: agent_id=%s reason=disabled",
            agent.id,
        )
        return invalid_response

    if not agent.is_approved:
        logger.warning(
            "agent verify failed: agent_id=%s reason=not_approved",
            agent.id,
        )
        return invalid_response

    return AgentAuthResponse(
        valid=True,
        agent_id=str(agent.id),
        site_id=str(agent.site_id) if agent.site_id else None,
        message="Authentication successful",
    )


# =============================================================================
# Maintenance Utilities
# =============================================================================


@router.post("/cleanup/stale", response_model=MessageResponse)
async def cleanup_stale_agents(
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    timeout_seconds: int = Query(120, ge=60, le=3600),
) -> Any:
    """Mark agents as offline if they haven't sent a heartbeat recently."""
    from sqlalchemy import update as sa_update

    org_id = _org_id(current_user)
    cutoff = datetime.now(UTC) - timedelta(seconds=timeout_seconds)

    # a site-limited operator must only flip agents OFFLINE in their
    # granted sites. Without site_scope_filter this org-scoped UPDATE would
    # mutate sibling-site agent rows (status/disconnected_at). No-op for
    # org-admins / grant-less users.
    result = await session.execute(
        sa_update(RemoteAgent)
        .where(
            RemoteAgent.organization_id == org_id,
            RemoteAgent.status == "online",
            RemoteAgent.last_heartbeat < cutoff,
            RemoteAgent.deleted_at.is_(None),
            site_scope_filter(current_user, RemoteAgent.site_id),
        )
        .values(
            status="offline",
            disconnected_at=datetime.now(UTC),
        )
    )
    count = result.rowcount or 0
    await session.commit()
    return MessageResponse(
        message=f"Marked {count} stale agent(s) as offline",
        details={"count": count},
    )


@router.delete("/heartbeats/old", response_model=MessageResponse)
async def purge_old_heartbeats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:admin"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    logdb: Annotated[AsyncSession, Depends(get_logdb_session)],
    days: int = Query(7, ge=1, le=365),
) -> Any:
    """Purge heartbeat records older than N days."""
    from sqlalchemy import delete as sa_delete

    from app.models.agents import AgentHeartbeat

    _org_id(current_user)  # 400 if the caller has no organization context
    cutoff = datetime.now(UTC) - timedelta(days=days)

    # Resolve agent IDs from primary DB first (LogDB has no remote_agents table)
    # scope the agent-ID set to the caller's granted sites so a
    # site-limited operator can't DELETE sibling-site agents' heartbeat
    # history. The LogDB DELETE below is bounded by this id set, so this is
    # the only enforcement point. tenant_filter applies org + per-user site
    # grant; no-op for unscoped super, own-org for org-admins / grant-less users.
    org_agent_result = await session.execute(
        select(RemoteAgent.id).where(tenant_filter(RemoteAgent, current_user))
    )
    org_agent_ids = [row[0] for row in org_agent_result.all()]

    if not org_agent_ids:
        return MessageResponse(
            message="Purged 0 old heartbeat record(s)",
            details={"count": 0, "older_than_days": days},
        )

    # Delete heartbeats from LogDB (time-series database)
    result = await logdb.execute(
        sa_delete(AgentHeartbeat).where(
            AgentHeartbeat.timestamp < cutoff,
            AgentHeartbeat.agent_id.in_(org_agent_ids),
        )
    )
    count = result.rowcount or 0
    await logdb.commit()
    return MessageResponse(
        message=f"Purged {count} old heartbeat record(s)",
        details={"count": count, "older_than_days": days},
    )


# =============================================================================
# WebSocket Endpoint (Agent Connection)
# =============================================================================

# Global in-memory registry for WebSocket connections
_agent_registry: AgentRegistryService | None = None
_agent_registry_lock: asyncio.Lock | None = None


async def get_agent_registry(db: AsyncSession) -> AgentRegistryService:
    """Get or create the global agent registry singleton (thread-safe)."""
    global _agent_registry, _agent_registry_lock
    if _agent_registry is not None:
        return _agent_registry
    if _agent_registry_lock is None:
        _agent_registry_lock = asyncio.Lock()
    async with _agent_registry_lock:
        if _agent_registry is None:
            _agent_registry = AgentRegistryService(db)
        return _agent_registry


@router.websocket("/ws/{agent_id}")
async def agent_websocket(
    websocket: WebSocket,
    agent_id: str,
    session: AsyncSession = Depends(get_session),
) -> None:
    """
    WebSocket endpoint for agent connections.

    Protocol:
    1. Agent connects and sends auth message: {"agent_key": "...", "site_id": "..."}
    2. Server verifies credentials
    3. Bidirectional message exchange begins
    4. Agent sends heartbeats and reports
    5. Server sends commands
    """
    # CSWSH protection: if an Origin header is present (browser client),
    # require it to be in the CORS allowlist. Non-browser agents typically
    # omit the Origin header and are allowed through.
    from app.api.v1.endpoints.websocket import _validate_ws_origin_optional

    if not await _validate_ws_origin_optional(websocket):
        return

    await websocket.accept()

    try:
        # Step 1: Receive authentication message (10s timeout prevents connection exhaustion)
        try:
            auth_data = await asyncio.wait_for(websocket.receive_json(), timeout=10.0)
        except TimeoutError:
            await websocket.close(code=4001)
            return
        auth_data: dict
        agent_key = auth_data.get("agent_key", "")
        site_id_str = auth_data.get("site_id", "")

        if not agent_key or not site_id_str:
            await websocket.send_json(
                {
                    "type": "auth_error",
                    "message": "Missing agent_key or site_id",
                }
            )
            await websocket.close(code=4001)
            return

        # Step 2: Verify credentials via DB
        svc = PersistentAgentService(session)
        try:
            agent_uuid = UUID(agent_id)
        except ValueError:
            await websocket.send_json(
                {
                    "type": "auth_error",
                    "message": "Invalid agent ID",
                }
            )
            await websocket.close(code=4001)
            return

        agent = await svc.verify_credentials(agent_uuid, agent_key)
        if not agent:
            await websocket.send_json(
                {
                    "type": "auth_error",
                    "message": "Invalid credentials",
                }
            )
            await websocket.close(code=4003)
            return

        if not agent.is_enabled:
            await websocket.send_json(
                {
                    "type": "auth_error",
                    "message": "Agent is disabled",
                }
            )
            await websocket.close(code=4003)
            return

        # mirror the is_enabled gate for unapproved agents so a
        # pending-approval agent cannot establish a WS channel and receive
        # commands. Matches the invariant enforced at /auth/verify and create_task.
        if not agent.is_approved:
            await websocket.send_json(
                {
                    "type": "auth_error",
                    "message": "Agent is not approved",
                }
            )
            await websocket.close(code=4003)
            return

        # Step 3: Verify site_id matches agent's assigned site (prevent spoofing)
        site_id = UUID(site_id_str)
        if site_id != agent.site_id:
            await websocket.send_json(
                {
                    "type": "auth_error",
                    "message": "Site mismatch",
                }
            )
            await websocket.close(code=4003)
            return

        registry = await get_agent_registry(session)

        connection = await registry.register_connection(
            agent_id=str(agent.id),
            site_id=site_id,
            site_name=agent.site.name if agent.site else agent.name,
            websocket=websocket,
        )

        await svc.update_agent(
            agent.id,
            status="online",
            connected_at=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            total_connections=(agent.total_connections or 0) + 1,
        )
        # Clear offline_notified_at so the next online→offline transition
        # fires a fresh alert. Direct attribute set because update_agent
        # skips None values (it's defensive against accidental clears).
        agent.offline_notified_at = None
        await session.commit()

        # Send auth success
        await websocket.send_json(
            {
                "type": "auth_success",
                "message": f"Connected as {agent.name}",
                "agent_id": str(agent.id),
            }
        )

        logger.info("Agent WebSocket connected: %s (%s)", agent.name, agent.id)

        # Bootstrap-push: send the current schedule set so a fresh
        # daemon doesn't have to wait for the next CRUD mutation to
        # learn about its existing schedules. Best-effort — failure
        # here doesn't drop the WS.
        #
        # SECURITY (HIGH #4 from audit): the WS handshake's `session`
        # gets reused across the lifetime of the connection, so calling
        # push_schedules_to_agents(session, ...) here couples the long-
        # lived WS session to a committed transaction. Use a fresh
        # async_session_factory() the same way _persist_scan_result does.
        try:
            from app.api.v1.endpoints.agent_schedules import (
                push_schedules_to_agents,
            )
            from app.db import async_session_factory

            async with async_session_factory() as bootstrap_session:
                await push_schedules_to_agents(
                    bootstrap_session,
                    site_id=site_id,
                    agent_id=agent.id,
                )
        except Exception:
            logger.exception(
                "Schedule bootstrap-push failed for agent %s",
                agent.id,
            )

        # Step 4: Keep connection alive (receiver loop handles messages)
        # Wait until connection tasks finish (they run until disconnection)
        while connection._running:
            await asyncio.sleep(1)

    except WebSocketDisconnect:
        logger.info("Agent WebSocket disconnected: %s", agent_id)
    except Exception as e:
        logger.error("Agent WebSocket error: %s", e)
    finally:
        # Cleanup
        try:
            registry = await get_agent_registry(session)
            await registry.unregister_connection(str(agent_id))
        except Exception:
            pass

        # Update DB status
        try:
            svc = PersistentAgentService(session)
            try:
                agent_uuid = UUID(agent_id)
                await svc.update_agent(
                    agent_uuid,
                    status="offline",
                    disconnected_at=datetime.now(UTC),
                )
                await session.commit()
            except ValueError:
                pass
        except Exception:
            pass


# =============================================================================
# Agent subnet report — auto-populate Site.subnets from agent discovery
# =============================================================================


class _ReportedSubnet(BaseModel):
    """A single subnet reported by an agent."""

    cidr: str = Field(max_length=43)
    name: str = Field(default="auto-discovered", max_length=100)
    vlan_id: int | None = Field(None, ge=1, le=4094)

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        import ipaddress as _ip

        from app.schemas.core import assert_safe_site_cidr

        try:
            network = _ip.ip_network(v.strip(), strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR: {v}")
        # an agent-reported subnet feeds Site.subnets, which gates
        # unauthenticated VoIP provisioning — reject default-route / special-use /
        # overbroad-public so a compromised agent can't open MAC-only provisioning.
        assert_safe_site_cidr(network)
        return str(network)


class _ReportSubnetsRequest(BaseModel):
    """Payload for agent subnet discovery reports."""

    subnets: list[_ReportedSubnet] = Field(max_length=500)


MAX_TOTAL_SUBNETS = 2000


@router.post(
    "/site/{site_id}/report-subnets",
    response_model=MessageResponse,
    summary="Agent reports discovered subnets for auto-population",
)
async def report_discovered_subnets(
    site_id: UUID,
    payload: _ReportSubnetsRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
) -> Any:
    """
    Called by agents after scanning. Merges discovered subnets into
    Site.subnets (adds new ones, doesn't remove user-defined ones).

    Input validated via Pydantic: CIDR format, bounded arrays, typed fields.
    """
    # Verify agent via key hash + site_id match
    # filter is_enabled + is_approved in the SELECT
    # so a disabled/unapproved agent's key hash doesn't even hit a row.
    # Saves a roundtrip on the rejection path; prevents an operator
    # from inadvertently leaking row-existence via timing.
    agent_key_hash = hashlib.sha256(x_agent_key.encode()).hexdigest()
    agent = (
        await session.execute(
            select(RemoteAgent).where(
                RemoteAgent.agent_key == agent_key_hash,
                RemoteAgent.site_id == site_id,
                RemoteAgent.deleted_at.is_(None),
                RemoteAgent.is_approved.is_(True),
                RemoteAgent.is_enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    if not agent:
        raise HTTPException(403, detail="Invalid agent key or site mismatch")

    # Fetch site with row lock to prevent concurrent merge race condition (TOCTOU)
    site = (
        await session.execute(
            select(Site)
            .where(
                Site.id == site_id,
                Site.organization_id == agent.organization_id,
                Site.deleted_at.is_(None),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if not site:
        raise HTTPException(404, detail="Site not found")

    # Merge: keep existing (user-defined), add new discovered CIDRs
    existing_cidrs = {s.get("cidr") for s in (site.subnets or []) if isinstance(s, dict)}
    merged = list(site.subnets or [])
    added = 0
    for entry in payload.subnets:
        if entry.cidr not in existing_cidrs:
            merged.append(
                {
                    "cidr": entry.cidr,
                    "name": entry.name[:100],
                    "vlan_id": entry.vlan_id,
                    "description": f"Discovered by agent {agent.name}",
                }
            )
            existing_cidrs.add(entry.cidr)
            added += 1

    if len(merged) > MAX_TOTAL_SUBNETS:
        raise HTTPException(400, detail=f"Site subnet limit ({MAX_TOTAL_SUBNETS}) exceeded")

    if added > 0:
        site.subnets = merged
        await session.flush()

    return {"message": f"Merged {added} new subnet(s), total {len(merged)}"}


# ===========================================================================
# Fleet overview — aggregated activity across all agents for the dashboard
# ===========================================================================


class FleetOverviewResponse(BaseModel):
    """Aggregated counters + recent activity for the fleet dashboard.

    Returned by GET /agents/fleet/overview. Single round-trip so the
    dashboard doesn't have to fan out four separate queries.
    """

    agents_total: int
    agents_online: int
    agents_offline: int
    schedules_total: int
    schedules_enabled: int
    runs_24h: int
    runs_24h_failed: int
    discovered_hosts_total: int
    discovered_hosts_unadopted: int
    last_run_at: datetime | None


class FleetRunResponse(BaseModel):
    """Cross-fleet run row for the activity panel."""

    id: UUID
    schedule_id: UUID
    schedule_name: str | None
    agent_id: UUID | None
    agent_name: str | None
    site_id: UUID
    site_name: str | None
    status: str
    device_count: int
    duration_seconds: float | None
    error_message: str | None
    started_at: datetime
    completed_at: datetime | None


@router.get("/fleet/overview", response_model=FleetOverviewResponse)
async def get_fleet_overview(
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Aggregated fleet metrics for the Agents page dashboard.

    Org-scoped automatically. All counters are bounded by deleted_at
    soft-delete + (when applicable) the discovered_hosts.ignored flag.
    """
    from sqlalchemy import func as _func

    org_id = _org_id(current_user)
    is_super = is_unscoped_superuser(current_user)

    # every counter below must be bounded by the caller's granted
    # sites — otherwise a site-limited operator's fleet dashboard leaks
    # sibling-site aggregates (agent / schedule / discovered-host totals).
    # site_scope_filter is a no-op for org-admins / grant-less users.
    # Agents — total / online / offline
    a_q = select(
        _func.count(RemoteAgent.id),
        _func.sum(_func.cast(RemoteAgent.status == "online", Integer)),
    ).where(RemoteAgent.deleted_at.is_(None))
    if not is_super and org_id:
        a_q = a_q.join(Site, RemoteAgent.site_id == Site.id).where(Site.organization_id == org_id)
    a_q = a_q.where(site_scope_filter(current_user, RemoteAgent.site_id))
    a_row = (await session.execute(a_q)).one()
    agents_total = int(a_row[0] or 0)
    agents_online = int(a_row[1] or 0)
    agents_offline = max(0, agents_total - agents_online)

    # Schedules — total / enabled
    s_q = select(
        _func.count(AgentSchedule.id),
        _func.sum(_func.cast(AgentSchedule.enabled, Integer)),
    ).where(AgentSchedule.deleted_at.is_(None))
    if not is_super and org_id:
        s_q = s_q.where(AgentSchedule.organization_id == org_id)
    s_q = s_q.where(site_scope_filter(current_user, AgentSchedule.site_id))
    s_row = (await session.execute(s_q)).one()
    schedules_total = int(s_row[0] or 0)
    schedules_enabled = int(s_row[1] or 0)

    # Runs in last 24h
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    r_q = (
        select(
            _func.count(AgentScheduleRun.id),
            _func.sum(_func.cast(AgentScheduleRun.status == "failed", Integer)),
            _func.max(AgentScheduleRun.started_at),
        )
        .join(AgentSchedule, AgentScheduleRun.schedule_id == AgentSchedule.id)
        .where(AgentScheduleRun.started_at >= cutoff)
    )
    if not is_super and org_id:
        r_q = r_q.where(AgentSchedule.organization_id == org_id)
    # scope the run aggregate to the caller's granted sites too (no-op for
    # org-admins) so a site-limited user's overview reflects only their sites.
    r_q = r_q.where(site_scope_filter(current_user, AgentSchedule.site_id))
    r_row = (await session.execute(r_q)).one()
    runs_24h = int(r_row[0] or 0)
    runs_24h_failed = int(r_row[1] or 0)
    last_run_at = r_row[2]

    # Discovered hosts — total / unadopted
    h_q = select(
        _func.count(DiscoveredHost.id),
        _func.sum(_func.cast(DiscoveredHost.is_adopted.is_(False), Integer)),
    ).where(
        DiscoveredHost.deleted_at.is_(None),
        DiscoveredHost.ignored.is_(False),
    )
    if not is_super and org_id:
        h_q = h_q.where(DiscoveredHost.organization_id == org_id)
    h_q = h_q.where(site_scope_filter(current_user, DiscoveredHost.site_id))
    h_row = (await session.execute(h_q)).one()
    discovered_hosts_total = int(h_row[0] or 0)
    discovered_hosts_unadopted = int(h_row[1] or 0)

    return FleetOverviewResponse(
        agents_total=agents_total,
        agents_online=agents_online,
        agents_offline=agents_offline,
        schedules_total=schedules_total,
        schedules_enabled=schedules_enabled,
        runs_24h=runs_24h,
        runs_24h_failed=runs_24h_failed,
        discovered_hosts_total=discovered_hosts_total,
        discovered_hosts_unadopted=discovered_hosts_unadopted,
        last_run_at=last_run_at,
    )


@router.get("/fleet/runs", response_model=list[FleetRunResponse])
async def get_fleet_runs(
    current_user: Annotated[CurrentUser, Depends(require_permissions("agent:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: int = Query(20, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status", max_length=16),
) -> Any:
    """Recent scheduled-scan runs across the whole fleet.

    Joins schedule + site + agent so the dashboard panel can render
    schedule/agent/site labels in a single payload without follow-up
    queries. Org-scoped via the parent schedule's organization_id.
    """
    _org_id(current_user)  # 400 if the caller has no organization context

    q = (
        select(
            AgentScheduleRun,
            AgentSchedule.name.label("schedule_name"),
            AgentSchedule.site_id.label("schedule_site_id"),
            Site.name.label("site_name"),
            RemoteAgent.name.label("agent_name"),
        )
        .join(AgentSchedule, AgentScheduleRun.schedule_id == AgentSchedule.id)
        .join(Site, AgentSchedule.site_id == Site.id)
        .outerjoin(RemoteAgent, AgentScheduleRun.agent_id == RemoteAgent.id)
        .where(AgentSchedule.deleted_at.is_(None))
    )
    # Org + per-user site grant via the parent schedule (AgentScheduleRun is a
    # viaparent child reached through AgentSchedule). (sibling list path):
    # a site-limited user must not enumerate sibling-site scheduled-scan run history
    # (site/agent names, failure messages) across the whole org. No-op for unscoped
    # super; own-org + granted-sites for everyone else.
    q = q.where(tenant_filter(AgentSchedule, current_user))
    if status_filter:
        q = q.where(AgentScheduleRun.status == status_filter)
    q = q.order_by(AgentScheduleRun.started_at.desc()).limit(limit)

    rows = (await session.execute(q)).all()
    return [
        FleetRunResponse(
            id=r[0].id,
            schedule_id=r[0].schedule_id,
            schedule_name=r[1],
            agent_id=r[0].agent_id,
            agent_name=r[4],
            site_id=r[2],
            site_name=r[3],
            status=r[0].status,
            device_count=r[0].device_count,
            duration_seconds=r[0].duration_seconds,
            error_message=r[0].error_message,
            started_at=r[0].started_at,
            completed_at=r[0].completed_at,
        )
        for r in rows
    ]

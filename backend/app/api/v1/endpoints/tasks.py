# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Task Monitoring API
=================================

REST API for monitoring and managing background tasks.
"""

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.celery_app import celery_app
from app.core.dependencies import (
    CurrentUser,
    get_current_active_user,
    is_unscoped_superuser,
    require_permissions,
)
from app.tasks.base import (
    TaskProgress,
    TaskStatus,
    get_active_tasks,
    get_task_progress,
    get_task_result,
    progress_store,
    revoke_task,
)

router = APIRouter(tags=["tasks"])
logger = logging.getLogger(__name__)


MANUALLY_TRIGGERABLE_TASKS: dict[str, dict[str, Any]] = {
    "backup.run_scheduled": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "backup.cleanup_expired": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "firmware.check_scheduled": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "firmware.refresh_status": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "sync.check_controller_health": {
        "queue": "sync",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "sync.sync_module_devices": {
        "queue": "sync",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "security.scan_brute_force": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "security.expire_ip_blocks": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "security.cleanup_audit_data": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "security.detect_anomalies": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "agents.health_check": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "agents.cleanup_stuck_tasks": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "agents.cleanup_stale": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "agents.purge_heartbeats": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "agents.purge_orphan_heartbeats": {
        "queue": "default",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "radius.sync_dot1x_events": {
        "queue": "sync",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
    "radius.check_health": {
        "queue": "sync",
        "allow_args": False,
        "allow_kwargs": False,
        "superadmin_only": True,
    },
}


# ===========================================
# Tenant helpers
# ===========================================


def _org_id(user: Any) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _check_task_org(progress: Any, organization_id: UUID) -> None:
    """Verify that a task belongs to the requesting user's organization.

    Fails closed: if the progress row has no organization_id recorded
    we cannot verify ownership, so we deny access with a generic 404.
    """
    if not progress:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    if progress.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    if str(progress.organization_id) != str(organization_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )


# ===========================================
# Request/Response Models
# ===========================================


class TaskSubmitResponse(BaseModel):
    """Response when a task is submitted."""

    task_id: str
    task_name: str
    status: str = "queued"
    message: str = "Task submitted successfully"


class TaskProgressResponse(BaseModel):
    """Task progress response."""

    task_id: str
    task_name: str
    status: TaskStatus
    progress: int = Field(ge=0, le=100)
    current: int = 0
    total: int = 0
    message: str = ""
    result: Any = None
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    retries: int = 0
    max_retries: int = 3


class TaskResultResponse(BaseModel):
    """Task result response."""

    task_id: str
    task_name: str
    status: TaskStatus
    result: Any = None
    error: str | None = None
    traceback: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    retries: int = 0


class TaskListResponse(BaseModel):
    """List of tasks response."""

    tasks: list[TaskProgressResponse]
    total: int


class WorkerInfo(BaseModel):
    """Celery worker information."""

    hostname: str
    status: str
    active_tasks: int
    processed: int
    pid: int | None = None
    software: str | None = None
    pool: str | None = None


class CeleryStatsResponse(BaseModel):
    """Celery cluster statistics."""

    workers: list[WorkerInfo]
    total_workers: int
    total_active_tasks: int
    queues: dict[str, int]


class TaskRevokeRequest(BaseModel):
    """Request to revoke a task."""

    terminate: bool = False


class TaskTriggerRequest(BaseModel):
    """Request to manually trigger a task."""

    task_name: str
    args: list[Any] = Field(default_factory=list)
    kwargs: dict[str, Any] = Field(default_factory=dict)
    queue: str | None = None


# ===========================================
# Task Progress Endpoints
# ===========================================


@router.get("/progress/{task_id}", response_model=TaskProgressResponse)
async def get_task_progress_endpoint(
    task_id: str,
    current_user: CurrentUser = Depends(get_current_active_user),
) -> Any:
    """
    Get progress for a specific task.

    Returns real-time progress information including:
    - Current status
    - Progress percentage
    - Current/total items processed
    - Status message
    """
    organization_id = _org_id(current_user)
    progress = get_task_progress(task_id)

    if progress:
        _check_task_org(progress, organization_id)
        return TaskProgressResponse(
            task_id=progress.task_id,
            task_name=progress.task_name,
            status=progress.status,
            progress=progress.progress,
            current=progress.current,
            total=progress.total,
            message=progress.message,
            result=progress.result,
            error=progress.error,
            started_at=progress.started_at,
            completed_at=progress.completed_at,
            retries=progress.retries,
            max_retries=progress.max_retries,
        )

    # Fall back to Celery result — only for tasks without progress-store data.
    # Because the Celery result backend does not store organization_id,
    # we cannot verify ownership and must deny access.
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Task not found",
    )


@router.get("/result/{task_id}", response_model=TaskResultResponse)
async def get_task_result_endpoint(
    task_id: str,
    current_user: CurrentUser = Depends(get_current_active_user),
) -> Any:
    """
    Get the result of a completed task.

    Returns the final result or error information.
    """
    organization_id = _org_id(current_user)
    result = get_task_result(task_id)

    if result:
        _check_task_org(result, organization_id)
        return TaskResultResponse(
            task_id=result.task_id,
            task_name=result.task_name,
            status=result.status,
            result=result.result,
            error=result.error,
            traceback=result.traceback,
            started_at=result.started_at,
            completed_at=result.completed_at,
            duration_seconds=result.duration_seconds,
            retries=result.retries,
        )

    # No result in the progress store — cannot verify ownership via the
    # raw Celery result backend, so deny access.
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Task not found",
    )


@router.get("/active", response_model=TaskListResponse)
async def list_active_tasks_endpoint(
    current_user: CurrentUser = Depends(get_current_active_user),
) -> Any:
    """
    List all active (running or pending) tasks for the current organization.
    """
    organization_id = _org_id(current_user)
    active = get_active_tasks(organization_id=str(organization_id))

    return TaskListResponse(
        tasks=[
            TaskProgressResponse(
                task_id=p.task_id,
                task_name=p.task_name,
                status=p.status,
                progress=p.progress,
                current=p.current,
                total=p.total,
                message=p.message,
                started_at=p.started_at,
                retries=p.retries,
                max_retries=p.max_retries,
            )
            for p in active
        ],
        total=len(active),
    )


# ===========================================
# Task Control Endpoints
# ===========================================


@router.delete("/{task_id}", response_model=dict[str, Any])
async def revoke_task_endpoint(
    task_id: str,
    request: TaskRevokeRequest = None,
    current_user: CurrentUser = Depends(require_permissions("tasks:manage")),
) -> Any:
    """
    Revoke (cancel) a running or pending task.

    **Requires permission:** tasks:manage

    Args:
        task_id: ID of task to revoke
        terminate: If true, send SIGTERM to worker process
    """
    organization_id = _org_id(current_user)
    request = request or TaskRevokeRequest()

    # Verify the task belongs to this organization before revoking
    progress = get_task_progress(task_id)
    if not progress:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    _check_task_org(progress, organization_id)

    revoke_task(task_id, terminate=request.terminate)

    return {
        "task_id": task_id,
        "revoked": True,
        "terminated": request.terminate,
    }


@router.post("/trigger", response_model=TaskSubmitResponse)
async def trigger_task(
    request: TaskTriggerRequest,
    current_user: CurrentUser = Depends(require_permissions("tasks:manage")),
) -> Any:
    """
    Manually trigger a task.

    **Requires permission:** tasks:manage

    This allows administrators to manually run scheduled tasks
    or trigger one-off background jobs.

    The caller's organization_id is injected into the task kwargs
    automatically; any user-supplied organization_id is overwritten.
    """
    organization_id = _org_id(current_user)

    config = MANUALLY_TRIGGERABLE_TASKS.get(request.task_name)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Task cannot be triggered manually",
        )

    if config.get("superadmin_only") and not is_unscoped_superuser(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super admins can manually trigger this task",
        )

    if request.args and not config.get("allow_args", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This task does not accept manual positional arguments",
        )

    if request.kwargs and not config.get("allow_kwargs", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This task does not accept manual keyword arguments",
        )

    expected_queue = config["queue"]
    if request.queue and request.queue != expected_queue:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Task must run on queue '{expected_queue}'",
        )

    # Validate task exists
    try:
        task = celery_app.tasks.get(request.task_name)
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Task '{request.task_name}' not found",
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task '{request.task_name}' not found",
        )

    task_kwargs = dict(request.kwargs)
    # Enforce tenant safety: the task always runs under the CALLER's org,
    # overwriting any caller-supplied organization_id. This honors the endpoint's
    # documented contract so the guarantee already holds the moment a
    # future triggerable task sets allow_kwargs=True.
    task_kwargs["organization_id"] = str(organization_id)

    # Submit task
    options = {"queue": expected_queue}

    result = task.apply_async(
        args=request.args,
        kwargs=task_kwargs,
        **options,
    )

    # Seed the progress store with org context so subsequent lookups
    # can enforce tenant isolation.
    progress_store.set_progress(
        result.id,
        TaskProgress(
            task_id=result.id,
            task_name=request.task_name,
            organization_id=str(organization_id),
            status=TaskStatus.PENDING,
            message="Task queued",
        ),
    )

    logger.info(
        f"Task {request.task_name} triggered by {current_user.user.email} "
        f"(org={organization_id}): {result.id}"
    )

    return TaskSubmitResponse(
        task_id=result.id,
        task_name=request.task_name,
        status="queued",
        message="Task submitted successfully",
    )


# ===========================================
# Celery Cluster Endpoints
# ===========================================


@router.get("/workers", response_model=CeleryStatsResponse)
async def get_worker_stats(
    current_user: CurrentUser = Depends(require_permissions("tasks:view")),
) -> Any:
    """
    Get Celery worker statistics.

    **Requires permission:** tasks:view

    Returns information about all connected workers including:
    - Active tasks
    - Processed count
    - Worker status
    """
    _org_id(current_user)  # enforce org context

    # Get worker stats using Celery inspect
    inspect = celery_app.control.inspect()

    # Active tasks
    active = inspect.active() or {}

    # Worker stats
    stats = inspect.stats() or {}

    # Queue lengths (approximate)
    # Note: This requires redis-py
    try:
        from app.core.redis_client import get_sync_redis

        r = get_sync_redis()
        queues = {
            "default": r.llen("default") or 0,
            "discovery": r.llen("discovery") or 0,
            "sync": r.llen("sync") or 0,
            "metrics": r.llen("metrics") or 0,
            "priority": r.llen("priority") or 0,
        }
    except Exception:
        queues = {}

    workers = []
    for hostname, worker_stats in stats.items():
        active_count = len(active.get(hostname, []))
        workers.append(
            WorkerInfo(
                hostname=hostname,
                status="online",
                active_tasks=active_count,
                processed=worker_stats.get("total", {}).get("total", 0),
                pid=worker_stats.get("pid"),
                software=worker_stats.get("broker", {}).get("transport"),
                pool=worker_stats.get("pool", {}).get("implementation"),
            )
        )

    return CeleryStatsResponse(
        workers=workers,
        total_workers=len(workers),
        total_active_tasks=sum(w.active_tasks for w in workers),
        queues=queues,
    )


@router.get("/scheduled", response_model=list[dict[str, Any]])
async def get_scheduled_tasks(
    current_user: CurrentUser = Depends(require_permissions("tasks:view")),
) -> Any:
    """
    Get list of scheduled periodic tasks.

    **Requires permission:** tasks:view

    Returns the beat schedule configuration.
    """
    _org_id(current_user)  # enforce org context

    schedule = celery_app.conf.beat_schedule or {}

    return [
        {
            "name": name,
            "task": config.get("task"),
            "schedule": str(config.get("schedule")),
            "options": config.get("options", {}),
        }
        for name, config in schedule.items()
    ]


@router.get("/registered", response_model=list[str])
async def get_registered_tasks(
    current_user: CurrentUser = Depends(require_permissions("tasks:view")),
) -> Any:
    """
    Get list of all registered task names.

    **Requires permission:** tasks:view
    """
    _org_id(current_user)  # enforce org context

    return sorted(celery_app.tasks.keys())

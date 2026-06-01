# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Task Base Classes
===============================

Base classes for Celery tasks with:
- Progress tracking
- Retry logic with exponential backoff
- Event publishing
- Result storage
"""

import asyncio
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from functools import wraps
from typing import Any, TypeVar

from celery import Task
from pydantic import BaseModel, Field

from app.core.celery_app import celery_app

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ===========================================
# Task Status & Progress Models
# ===========================================


class TaskStatus(StrEnum):
    """Task execution status."""

    PENDING = "pending"
    STARTED = "started"
    PROGRESS = "progress"
    SUCCESS = "success"
    FAILURE = "failure"
    RETRY = "retry"
    REVOKED = "revoked"


class TaskProgress(BaseModel):
    """Task progress information."""

    task_id: str
    task_name: str
    organization_id: str | None = None
    status: TaskStatus = TaskStatus.PENDING
    progress: int = Field(default=0, ge=0, le=100)
    current: int = 0
    total: int = 0
    message: str = ""
    result: Any = None
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    retries: int = 0
    max_retries: int = 3
    eta: datetime | None = None

    class Config:
        use_enum_values = True


class TaskResult(BaseModel):
    """Task execution result."""

    task_id: str
    task_name: str
    organization_id: str | None = None
    status: TaskStatus
    result: Any = None
    error: str | None = None
    traceback: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    retries: int = 0

    class Config:
        use_enum_values = True


# ===========================================
# Progress Storage (Redis)
# ===========================================


class TaskProgressStore:
    """
    Store task progress in Redis for real-time tracking.
    """

    PREFIX = "task_progress:"
    TTL = 3600 * 24  # 24 hours

    def __init__(self) -> None:
        self._redis: Any = None

    @property
    def redis(self) -> Any:
        """Lazy load Redis connection."""
        if self._redis is None:
            from app.core.redis_client import get_sync_redis

            # Sentinel-aware factory (resolves master on failover); falls back to
            # a direct REDIS_URL connection when no sentinels are configured.
            self._redis = get_sync_redis(decode_responses=True)
        return self._redis

    def _key(self, task_id: str) -> str:
        return f"{self.PREFIX}{task_id}"

    def set_progress(self, task_id: str, progress: TaskProgress) -> None:
        """Store task progress."""
        try:
            self.redis.setex(
                self._key(task_id),
                self.TTL,
                progress.model_dump_json(),
            )
        except Exception as e:
            logger.warning("Failed to store task progress: %s", e)

    def get_progress(self, task_id: str) -> TaskProgress | None:
        """Get task progress."""
        try:
            data = self.redis.get(self._key(task_id))
            if data:
                return TaskProgress.model_validate_json(data)
        except Exception as e:
            logger.warning("Failed to get task progress: %s", e)
        return None

    def delete_progress(self, task_id: str) -> None:
        """Delete task progress."""
        try:
            self.redis.delete(self._key(task_id))
        except Exception as e:
            logger.warning("Failed to delete task progress: %s", e)

    def get_all_active(
        self, pattern: str = "*", organization_id: str | None = None
    ) -> list[TaskProgress]:
        """Get all active task progress entries using non-blocking SCAN.

        Optionally filtered by organization_id. Uses SCAN instead of KEYS to
        avoid blocking Redis on large keyspaces.
        """
        results: list[TaskProgress] = []
        match = f"{self.PREFIX}{pattern}"
        try:
            # redis-py sync scan_iter wraps SCAN cursor loop internally
            for key in self.redis.scan_iter(match=match, count=100):
                data = self.redis.get(key)
                if not data:
                    continue
                try:
                    progress = TaskProgress.model_validate_json(data)
                except Exception:
                    continue
                if progress.status not in (
                    TaskStatus.PENDING,
                    TaskStatus.STARTED,
                    TaskStatus.PROGRESS,
                ):
                    continue
                if organization_id and progress.organization_id != organization_id:
                    continue
                results.append(progress)
        except Exception as e:
            logger.warning("Failed to scan task progress: %s", e)
        return results


# Global progress store
progress_store = TaskProgressStore()


# ===========================================
# Base Task Class
# ===========================================


class FreeSDNTask(Task):  # type: ignore[misc]
    """
    Base Celery task with enhanced features:
    - Progress tracking
    - Exponential backoff retry
    - Event publishing
    - Structured logging
    """

    abstract = True

    # Retry configuration
    autoretry_for = (Exception,)
    retry_backoff = True
    retry_backoff_max = 600  # Max 10 minutes between retries
    retry_jitter = True
    max_retries = 3

    # Time limits (can be overridden)
    soft_time_limit = 300  # 5 minutes
    time_limit = 600  # 10 minutes

    # Track execution
    track_started = True

    def __init__(self) -> None:
        super().__init__()
        self._progress: TaskProgress | None = None
        self._start_time: float | None = None

    # =========================================
    # Progress Tracking
    # =========================================

    def update_progress(
        self,
        current: int,
        total: int,
        message: str = "",
        status: TaskStatus = TaskStatus.PROGRESS,
    ) -> None:
        """
        Update task progress.

        Preserves ``organization_id`` from the seeded progress row so the
        task remains visible only to its owning org.

        Args:
            current: Current progress count
            total: Total items to process
            message: Progress message
            status: Task status
        """
        progress = int((current / total * 100) if total > 0 else 0)

        # Preserve organization_id from the seeded row (or from the cached
        # _progress field) so org-scoped queries keep matching.
        existing_org_id: str | None = None
        if self._progress is not None and self._progress.organization_id is not None:
            existing_org_id = self._progress.organization_id
        else:
            existing = progress_store.get_progress(self.request.id)
            if existing is not None:
                existing_org_id = existing.organization_id

        self._progress = TaskProgress(
            task_id=self.request.id,
            task_name=self.name,
            organization_id=existing_org_id,
            status=status,
            progress=progress,
            current=current,
            total=total,
            message=message,
            started_at=datetime.fromtimestamp(self._start_time, tz=UTC)
            if self._start_time
            else None,
            retries=self.request.retries,
            max_retries=self.max_retries,
        )

        # Store in Redis
        progress_store.set_progress(self.request.id, self._progress)

        # Update Celery state
        self.update_state(
            state="PROGRESS",
            meta={
                "progress": progress,
                "current": current,
                "total": total,
                "message": message,
            },
        )

        logger.debug(
            f"Task {self.name}[{self.request.id}] progress: {progress}% ({current}/{total}) - {message}"
        )

    def set_message(self, message: str) -> None:
        """Update progress message without changing counts."""
        if self._progress:
            self._progress.message = message
            progress_store.set_progress(self.request.id, self._progress)

    # =========================================
    # Lifecycle Hooks
    # =========================================

    def before_start(self, task_id: str, args: Any, kwargs: Any) -> None:
        """Called before task starts."""
        self._start_time = time.time()

        self._progress = TaskProgress(
            task_id=task_id,
            task_name=self.name,
            status=TaskStatus.STARTED,
            message="Task started",
            started_at=datetime.now(UTC),
            retries=self.request.retries if self.request else 0,
            max_retries=self.max_retries,
        )
        progress_store.set_progress(task_id, self._progress)

        logger.info("Task %s[%s] started", self.name, task_id)

    def _preserved_org_id(self, task_id: str) -> str | None:
        """Look up organization_id for the given task_id, preserving the seeded row."""
        if self._progress is not None and self._progress.organization_id is not None:
            return self._progress.organization_id
        existing = progress_store.get_progress(task_id)
        if existing is not None:
            return existing.organization_id
        return None

    def on_success(self, retval: Any, task_id: str, args: Any, kwargs: Any) -> None:
        """Called on task success."""
        duration = time.time() - self._start_time if self._start_time else 0

        self._progress = TaskProgress(
            task_id=task_id,
            task_name=self.name,
            organization_id=self._preserved_org_id(task_id),
            status=TaskStatus.SUCCESS,
            progress=100,
            message="Task completed successfully",
            result=retval,
            started_at=datetime.fromtimestamp(self._start_time, tz=UTC)
            if self._start_time
            else None,
            completed_at=datetime.now(UTC),
            retries=self.request.retries,
            max_retries=self.max_retries,
        )
        progress_store.set_progress(task_id, self._progress)

        logger.info("Task %s[%s] completed in %.2fs", self.name, task_id, duration)

    def on_failure(self, exc: Exception, task_id: str, args: Any, kwargs: Any, einfo: Any) -> None:
        """Called on task failure."""
        duration = time.time() - self._start_time if self._start_time else 0

        self._progress = TaskProgress(
            task_id=task_id,
            task_name=self.name,
            organization_id=self._preserved_org_id(task_id),
            status=TaskStatus.FAILURE,
            message=f"Task failed: {str(exc)}",
            error=str(exc),
            started_at=datetime.fromtimestamp(self._start_time, tz=UTC)
            if self._start_time
            else None,
            completed_at=datetime.now(UTC),
            retries=self.request.retries,
            max_retries=self.max_retries,
        )
        progress_store.set_progress(task_id, self._progress)

        logger.error("Task %s[%s] failed after %.2fs: %s", self.name, task_id, duration, exc)

    def on_retry(self, exc: Exception, task_id: str, args: Any, kwargs: Any, einfo: Any) -> None:
        """Called on task retry."""
        self._progress = TaskProgress(
            task_id=task_id,
            task_name=self.name,
            organization_id=self._preserved_org_id(task_id),
            status=TaskStatus.RETRY,
            message=f"Retrying ({self.request.retries + 1}/{self.max_retries}): {str(exc)}",
            error=str(exc),
            started_at=datetime.fromtimestamp(self._start_time, tz=UTC)
            if self._start_time
            else None,
            retries=self.request.retries + 1,
            max_retries=self.max_retries,
        )
        progress_store.set_progress(task_id, self._progress)

        logger.warning(
            f"Task {self.name}[{task_id}] retry {self.request.retries + 1}/{self.max_retries}: {exc}"
        )


# ===========================================
# Async Task Support
# ===========================================


def async_task(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to run async functions in Celery tasks.

    Usage:
        @celery_app.task(base=FreeSDNTask)
        @async_task
        async def my_async_task():
            await some_async_operation()
    """

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return asyncio.run(func(*args, **kwargs))

    return wrapper


# ===========================================
# Task Decorators
# ===========================================


def freesdn_task(
    name: str | None = None,
    max_retries: int = 3,
    soft_time_limit: int = 300,
    time_limit: int = 600,
    queue: str | None = None,
    **celery_kwargs: Any,
) -> Callable[..., Any]:
    """
    Decorator to create a FreeSDN task with standard configuration.

    Usage:
        @freesdn_task(name="myapp.mytask", queue="high-priority")
        async def my_task(self, arg1, arg2):
            self.update_progress(1, 10, "Starting...")
            # do work
    """

    def decorator(func: Callable[..., Any]) -> Any:
        task_name = name or f"app.tasks.{func.__module__}.{func.__name__}"

        @celery_app.task(  # type: ignore[untyped-decorator]
            bind=True,
            base=FreeSDNTask,
            name=task_name,
            max_retries=max_retries,
            soft_time_limit=soft_time_limit,
            time_limit=time_limit,
            queue=queue,
            **celery_kwargs,
        )
        @wraps(func)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            if asyncio.iscoroutinefunction(func):
                return asyncio.run(func(self, *args, **kwargs))
            return func(self, *args, **kwargs)

        return wrapper

    return decorator


# ===========================================
# Task Utilities
# ===========================================


def get_task_progress(task_id: str) -> TaskProgress | None:
    """Get progress for a specific task."""
    return progress_store.get_progress(task_id)


def get_active_tasks(organization_id: str | None = None) -> list[TaskProgress]:
    """Get all active tasks, optionally filtered by organization_id."""
    return progress_store.get_all_active(organization_id=organization_id)


def get_task_result(task_id: str) -> TaskResult | None:
    """
    Get the result of a completed task.

    Checks both the progress store and Celery result backend.
    """
    # First check progress store
    progress = progress_store.get_progress(task_id)
    if progress and progress.status in (TaskStatus.SUCCESS, TaskStatus.FAILURE):
        return TaskResult(
            task_id=task_id,
            task_name=progress.task_name,
            organization_id=progress.organization_id,
            status=progress.status,
            result=progress.result,
            error=progress.error,
            started_at=progress.started_at,
            completed_at=progress.completed_at,
            retries=progress.retries,
        )

    # Fall back to Celery result backend
    from celery.result import AsyncResult

    result = AsyncResult(task_id, app=celery_app)

    if result.ready():
        return TaskResult(
            task_id=task_id,
            task_name=result.name or "unknown",
            status=TaskStatus.SUCCESS if result.successful() else TaskStatus.FAILURE,
            result=result.result if result.successful() else None,
            error=str(result.result) if not result.successful() else None,
            traceback=result.traceback,
        )

    return None


def revoke_task(task_id: str, terminate: bool = False) -> bool:
    """
    Revoke (cancel) a task.

    Args:
        task_id: Task ID to revoke
        terminate: If True, send SIGTERM to worker

    Returns:
        True if revocation was sent
    """
    celery_app.control.revoke(task_id, terminate=terminate)

    progress = progress_store.get_progress(task_id)
    if progress:
        progress.status = TaskStatus.REVOKED
        progress.message = "Task was revoked"
        progress_store.set_progress(task_id, progress)

    return True

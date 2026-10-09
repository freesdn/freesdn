# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Trusted organization/site ownership for tenant-submitted discovery jobs."""

import logging
from contextlib import suppress
from typing import Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, ValidationError

from app.core.redis_client import get_async_redis

logger = logging.getLogger(__name__)
DISCOVERY_TASK: Final = "app.tasks.discovery.discover_all_devices"
SCOPE_TTL_SECONDS = 86400
SCOPE_PREFIX = "network_discovery_scope:"


class DiscoveryScopeUnavailable(RuntimeError):
    """The ownership store could not provide a trustworthy answer."""


class DiscoveryJobScope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1]
    task_id: UUID
    task_name: Literal["app.tasks.discovery.discover_all_devices"]
    organization_id: UUID
    site_id: UUID | None


async def reserve_discovery_scope(scope: DiscoveryJobScope) -> bool:
    client = None
    try:
        client = get_async_redis(decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
        return bool(
            await client.set(
                SCOPE_PREFIX + str(scope.task_id),
                scope.model_dump_json(),
                nx=True,
                ex=SCOPE_TTL_SECONDS,
            )
        )
    except Exception:
        raise DiscoveryScopeUnavailable("Discovery ownership store unavailable") from None
    finally:
        if client is not None:
            with suppress(Exception):
                await client.aclose()


async def get_discovery_scope(task_id: str) -> DiscoveryJobScope | None:
    try:
        identity = UUID(task_id)
    except (ValueError, TypeError, AttributeError):
        return None
    client = None
    try:
        client = get_async_redis(decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
        data = await client.get(SCOPE_PREFIX + str(identity))
    except Exception:
        raise DiscoveryScopeUnavailable("Discovery ownership store unavailable") from None
    finally:
        if client is not None:
            with suppress(Exception):
                await client.aclose()
    if not isinstance(data, (str, bytes)) or not data or len(data) > 2048:
        return None
    try:
        scope = DiscoveryJobScope.model_validate_json(data)
    except (ValidationError, ValueError):
        return None
    return scope if scope.task_id == identity else None


def discovery_status(task_id: UUID) -> dict[str, object]:
    """Read a previously authorized ID and project only fixed status/count fields.

    Callers must verify the separate scope record and current site authority
    before entering this synchronous Celery backend path.
    """
    from celery.result import AsyncResult

    from app.core.celery_app import celery_app

    result = AsyncResult(str(task_id), app=celery_app)
    state = result.state
    messages = {
        "PENDING": "Discovery awaiting worker",
        "RECEIVED": "Discovery awaiting worker",
        "STARTED": "Discovery running",
        "PROGRESS": "Discovery running",
        "RETRY": "Discovery retrying",
        "FAILURE": "Discovery task failed",
        "REVOKED": "Discovery was revoked",
        "SUCCESS": "Discovery completed",
    }
    if state not in messages:
        raise DiscoveryScopeUnavailable("Discovery result unavailable")
    count = 0
    message = messages[state]
    if state == "SUCCESS":
        payload = result.result
        if not isinstance(payload, dict):
            raise DiscoveryScopeUnavailable("Discovery result unavailable")
        candidate_count = payload.get("total_devices_discovered", payload.get("devices_found", 0))
        if type(candidate_count) is not int or not 0 <= candidate_count <= 2**31 - 1:
            raise DiscoveryScopeUnavailable("Discovery result unavailable")
        count = candidate_count
        if payload.get("success") is False:
            state, message = "FAILURE", messages["FAILURE"]
        elif payload.get("skipped") is True:
            message = "Discovery skipped because another run is active"
    return {
        "task_id": str(task_id),
        "status": state.lower(),
        "progress": 100 if state == "SUCCESS" else 0,
        "devices_found": count,
        "message": message,
        "started_at": None,
        "completed_at": None,
    }

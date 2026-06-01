# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Event History API Endpoints
=========================================

REST API for querying event history and managing subscriptions.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    CurrentUser,
    get_current_active_user,
    is_unscoped_superuser,
    org_scope_or_platform,
    require_permissions,
)
from app.core.events import EventCategory
from app.core.security_utils import validate_target_host
from app.core.site_access import assert_can_access_site, site_ids_for_request
from app.db import get_logdb_session, get_session
from app.schemas.core import MessageResponse, PaginatedResponse
from app.services.event_service import EventService


def _grant_for(current_user: CurrentUser) -> set[UUID] | None:
    """Granted site-id set for a site-limited caller, else ``None``.

    site-grantevents / subscriptions carry a site dimension but were
    filtered by ``organization_id`` only, so a site-limited operator could read,
    replay, list, create, retarget, or delete events/subscriptions for SIBLING
    sites of the same org. ``None`` for super / org admin (guards no-op).
    """
    return site_ids_for_request(current_user)


def _assert_requested_sites_granted(
    current_user: CurrentUser,
    site_ids: list[UUID] | None,
    *,
    site_ids_provided: bool = True,
) -> None:
    """a site-limited caller may only scope a subscription to
    sites they were granted, and may NOT create or retarget an org-level
    (no-site_ids) subscription.

    Org-level subscriptions receive (and webhook-exfiltrate) events for EVERY
    site in the org, including sibling sites the caller cannot access — so for a
    site-limited caller a missing/null/empty ``site_ids`` must FAIL CLOSED, not
    silently default to org-level. Org-level subscriptions are admin-only.

    No-op for super / org admin (``is_site_limited`` False).

    Args:
        site_ids: the requested site scope (None when omitted or explicitly null).
        site_ids_provided: True when the request actually carried a ``site_ids``
            field (create: always; update: only when present in the body). When
            False on an update, the existing scope is untouched, so a site-limited
            caller is NOT forced to re-supply it — the stored value is already
            grant-constrained from create time. Used to distinguish "field
            omitted" (leave as-is) from "explicitly cleared to null/[]" (forbidden).
    """
    if not getattr(current_user, "is_site_limited", False):
        return
    if site_ids_provided and not site_ids:
        # Site-limited caller tried to create or retarget to an org-level
        # subscription (no/empty site scope). 404 shape (no existence oracle).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription not found",
        )
    for sid in site_ids or []:
        assert_can_access_site(current_user, sid, detail="Subscription not found")


def _validate_webhook_url(v: str | None) -> str | None:
    """SSRF guard for subscription target_url.

    Webhook subscriptions cause the backend to POST event payloads to
    this URL on every match. Without an SSRF check an events:subscribe-
    permitted user (org_admin+) could:
      - Point target_url at AWS / GCP metadata service IP and have
        the backend exfiltrate event data to internal endpoints
      - Use 127.0.0.1 / private IPs to probe other services on the
        FreeSDN host
    Accept relative paths (rare but used for self-loop tests) and
    https:// only (no plaintext http:// for outbound POSTs).
    """
    if v is None or v == "":
        return v
    if len(v) > 2048:
        raise ValueError("target_url too long (max 2048 chars)")
    if v.startswith("/"):
        return v
    if not v.startswith(("https://", "http://")):
        raise ValueError("target_url must be a relative path or http(s):// URL")
    # Extract host and run through the same loopback/metadata guard
    # used by /controllers and /discovery endpoints.
    from urllib.parse import urlparse

    try:
        parsed = urlparse(v)
        host = parsed.hostname or ""
    except Exception as exc:
        raise ValueError(f"target_url malformed: {exc}") from exc
    if not host:
        raise ValueError("target_url missing host")
    try:
        validate_target_host(host)
    except ValueError as exc:
        raise ValueError(f"target_url SSRF check failed: {exc}") from exc
    return v


def _validate_target_config(v: dict | None) -> dict | None:
    """Cap subscription target_config JSONB (32 keys / 4 KB per value)."""
    if v is None:
        return v
    if len(v) > 32:
        raise ValueError("target_config must contain at most 32 keys")
    for key, val in v.items():
        if not isinstance(key, str) or len(key) > 128:
            raise ValueError("target_config keys must be strings <= 128 chars")
        if isinstance(val, str) and len(val) > 4096:
            raise ValueError(f"target_config['{key}'] exceeds 4096 chars")
    return v


router = APIRouter(tags=["events"])
logger = logging.getLogger(__name__)


# ===========================================
# Request/Response Schemas
# ===========================================


class EventResponse(BaseModel):
    """Event history record response."""

    id: str
    event_type: str
    category: str
    priority: str
    payload: dict
    metadata: dict
    source: str
    correlation_id: str | None
    causation_id: str | None
    organization_id: str | None
    site_id: str | None
    user_id: str | None
    timestamp: datetime


class EventStatsResponse(BaseModel):
    """Event statistics response."""

    total: int
    by_category: dict[str, int]
    by_type: dict[str, int]


class ReplayRequest(BaseModel):
    """Event replay request."""

    start_time: datetime
    end_time: datetime | None = None
    # Cap event_types list to keep the IN(...) build bounded; each
    # type follows the same dot-delimited form as a routing key.
    event_types: list[str] | None = Field(None, max_length=64)
    delay_ms: int = Field(default=100, ge=0, le=10000)

    @field_validator("event_types")
    @classmethod
    def _cap_types(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        for t in v:
            if not isinstance(t, str) or len(t) > 128:
                raise ValueError("each event_type must be a string <= 128 chars")
        return v


class ReplayResponse(BaseModel):
    """Event replay response."""

    replayed_count: int
    start_time: datetime
    end_time: datetime


class SubscriptionCreate(BaseModel):
    """Create event subscription request."""

    name: str = Field(min_length=1, max_length=255)
    pattern: str = Field(min_length=1, max_length=255)
    target_type: str = Field(min_length=1, max_length=50)
    # target_url SSRF-validated below; cap site_ids to keep array
    # bounded (sites per org are well under 200).
    target_url: str | None = Field(None, max_length=2048)
    target_config: dict = Field(default_factory=dict)
    site_ids: list[UUID] | None = Field(None, max_length=200)

    @field_validator("target_url")
    @classmethod
    def _v_url(cls, v: str | None) -> str | None:
        return _validate_webhook_url(v)

    @field_validator("target_config")
    @classmethod
    def _v_cfg(cls, v: dict) -> dict:
        return _validate_target_config(v) or {}


class SubscriptionUpdate(BaseModel):
    """Update event subscription request."""

    name: str | None = Field(None, min_length=1, max_length=255)
    pattern: str | None = Field(None, min_length=1, max_length=255)
    target_url: str | None = Field(None, max_length=2048)
    target_config: dict | None = None
    is_active: bool | None = None
    site_ids: list[UUID] | None = Field(None, max_length=200)

    @field_validator("target_url")
    @classmethod
    def _v_url(cls, v: str | None) -> str | None:
        return _validate_webhook_url(v)

    @field_validator("target_config")
    @classmethod
    def _v_cfg(cls, v: dict | None) -> dict | None:
        return _validate_target_config(v)


class SubscriptionResponse(BaseModel):
    """Event subscription response."""

    id: UUID
    name: str
    pattern: str
    target_type: str
    target_url: str | None
    target_config: dict
    organization_id: UUID | None
    site_ids: list[str] | None
    is_active: bool
    last_triggered: datetime | None
    trigger_count: int
    created_at: datetime
    updated_at: datetime


# ===========================================
# Event History Endpoints
# ===========================================


@router.get("/", response_model=PaginatedResponse[EventResponse])
async def list_events(
    # Wildcard ``*`` is substituted with SQL ``%`` below, so a
    # ``"%%%%"*1000`` query would build an expensive LIKE pattern.
    # Cap at 128 chars (well above any real event_type).
    event_type: str | None = Query(
        None, max_length=128, description="Filter by event type (supports wildcards with *)"
    ),
    category: EventCategory | None = Query(None, description="Filter by category"),
    correlation_id: UUID | None = Query(None, description="Filter by correlation ID"),
    site_id: UUID | None = Query(None, description="Filter by site"),
    start_time: datetime | None = Query(None, description="Events after this time"),
    end_time: datetime | None = Query(None, description="Events before this time"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    # EventRecord lives in the LogDB (it's a LogBase model); this endpoint
    # previously used the main session and 500'd "relation events.event_records
    # does not exist".
    session: AsyncSession = Depends(get_logdb_session),
    current_user: CurrentUser = Depends(get_current_active_user),
) -> dict[str, Any]:
    """
    List event history with filtering.

    Supports filtering by:
    - **event_type**: Exact match or wildcard with * (e.g., "device.*")
    - **category**: Event category (system, device, network, etc.)
    - **correlation_id**: Get all events in a correlation chain
    - **site_id**: Filter to specific site
    - **start_time/end_time**: Time range
    """
    service = EventService(session)

    # an explicitly-requested site must be one the caller can access
    # (no-op for super / org admin and None). The grant set below additionally
    # scopes the un-pinned case for a site-limited caller.
    assert_can_access_site(current_user, site_id, detail="Event not found")

    return await service.get_events(
        organization_id=org_scope_or_platform(current_user),
        site_id=site_id,
        event_type=event_type.replace("*", "%") if event_type else None,
        category=category,
        correlation_id=correlation_id,
        start_time=start_time,
        end_time=end_time,
        page=page,
        per_page=per_page,
        accessible_site_ids=_grant_for(current_user),
    )


@router.get("/stats", response_model=EventStatsResponse)
async def get_event_stats(
    start_time: datetime | None = Query(None, description="Stats from this time"),
    end_time: datetime | None = Query(None, description="Stats until this time"),
    session: AsyncSession = Depends(get_logdb_session),  # EventRecord → LogDB
    current_user: CurrentUser = Depends(get_current_active_user),
) -> dict[str, Any]:
    """
    Get event statistics.

    Returns counts by category and top event types.
    """
    service = EventService(session)

    return await service.get_event_stats(
        organization_id=org_scope_or_platform(current_user),
        start_time=start_time,
        end_time=end_time,
        accessible_site_ids=_grant_for(current_user),
    )


@router.get("/correlation/{correlation_id}", response_model=list[EventResponse])
async def get_correlation_chain(
    correlation_id: UUID,
    session: AsyncSession = Depends(get_logdb_session),  # EventRecord → LogDB
    current_user: CurrentUser = Depends(get_current_active_user),
) -> dict[str, Any]:
    """
    Get all events in a correlation chain.

    Returns events ordered by timestamp, useful for tracing
    related events across the system.
    """
    service = EventService(session)
    return await service.get_correlation_chain(
        correlation_id,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_grant_for(current_user),
    )


# ===========================================
# Event Replay Endpoints
# ===========================================


@router.post("/replay", response_model=ReplayResponse)
async def replay_events(
    request: ReplayRequest,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("events:replay")),
) -> dict[str, Any]:
    """
    Replay historical events.

    Re-publishes events from the specified time range to the event bus.
    Useful for:
    - Rebuilding derived state
    - Re-triggering automation rules
    - Testing event handlers

    **Requires permission:** events:replay
    """
    service = EventService(session)

    end_time = request.end_time or datetime.now(UTC)

    # /events/replay re-publishes each historical event through the
    # FULL event-bus pipeline (automation eval + webhook + WS broadcast + Redis
    # pub-sub). Unbounded, an org_admin could replay the org's entire history
    # (millions of rows) and saturate the cluster-wide WS/Redis fan-out. Bound
    # the window, cap the event count, and single-flight per org.
    _MAX_REPLAY_WINDOW = timedelta(days=7)
    _MAX_REPLAY_EVENTS = 10_000
    if end_time < request.start_time:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="end_time precedes start_time")
    if end_time - request.start_time > _MAX_REPLAY_WINDOW:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"replay window exceeds {_MAX_REPLAY_WINDOW.days} days — narrow the range",
        )

    from app.core.celery_app import acquire_solo_lock, release_solo_lock

    lock_name = f"event_replay:{current_user.organization_id}"
    if not acquire_solo_lock(lock_name, ttl_seconds=600):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="A replay is already running for this organization. Try again shortly.",
        )
    try:
        count = await service.replay_and_publish(
            start_time=request.start_time,
            end_time=end_time,
            event_types=request.event_types,
            organization_id=org_scope_or_platform(current_user),
            delay_ms=request.delay_ms,
            max_events=_MAX_REPLAY_EVENTS,
            # only super / org admin hold events:replay today (guard
            # no-ops for them), but keep the grant threaded so a future
            # site-limited grant of events:replay can only replay its own
            # sites' events into the cluster-wide fan-out.
            accessible_site_ids=_grant_for(current_user),
        )
    finally:
        release_solo_lock(lock_name)

    return ReplayResponse(
        replayed_count=count,
        start_time=request.start_time,
        end_time=end_time,
    )


# ===========================================
# Subscription Endpoints
# (Defined BEFORE /{event_id} catch-all to
# avoid "subscriptions" failing UUID parse)
# ===========================================


@router.get("/subscriptions", response_model=list[SubscriptionResponse])
async def list_subscriptions(
    is_active: bool | None = Query(None, description="Filter by active status"),
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(get_current_active_user),
) -> dict[str, Any]:
    """List event subscriptions for the organization."""
    service = EventService(session)

    subscriptions = await service.get_subscriptions(
        organization_id=org_scope_or_platform(current_user),
        is_active=is_active,
        accessible_site_ids=_grant_for(current_user),
    )

    return [
        SubscriptionResponse(
            id=s.id,
            name=s.name,
            pattern=s.pattern,
            target_type=s.target_type,
            target_url=s.target_url,
            target_config=s.target_config,
            organization_id=s.organization_id,
            site_ids=s.site_ids,
            is_active=s.is_active,
            last_triggered=s.last_triggered,
            trigger_count=s.trigger_count,
            created_at=s.created_at,
            updated_at=s.updated_at,
        )
        for s in subscriptions
    ]


@router.post(
    "/subscriptions", response_model=SubscriptionResponse, status_code=status.HTTP_201_CREATED
)
async def create_subscription(
    request: SubscriptionCreate,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("events:subscribe")),
) -> dict[str, Any]:
    """
    Create a new event subscription.

    Subscriptions can deliver events to:
    - **webhook**: HTTP POST to a URL
    - **email**: Email notification
    - **slack**: Slack webhook

    Patterns support wildcards:
    - `*` matches single segment (e.g., `device.*.created`)
    - `#` matches any segments (e.g., `device.#`)
    """
    service = EventService(session)

    # a site-limited caller may only scope a subscription to a
    # non-empty subset of granted sites — otherwise it would receive (and
    # webhook-exfiltrate) sibling-site events. Missing/empty site_ids (org-level,
    # org-wide fanout) FAILS CLOSED for a site-limited caller (org-level subs are
    # admin-only). No-op for super / org admin.
    _assert_requested_sites_granted(current_user, request.site_ids)

    subscription = await service.create_subscription(
        name=request.name,
        pattern=request.pattern,
        target_type=request.target_type,
        target_url=request.target_url,
        target_config=request.target_config,
        organization_id=org_scope_or_platform(current_user),
        site_ids=request.site_ids,
    )

    await session.commit()

    return SubscriptionResponse(
        id=subscription.id,
        name=subscription.name,
        pattern=subscription.pattern,
        target_type=subscription.target_type,
        target_url=subscription.target_url,
        target_config=subscription.target_config,
        organization_id=subscription.organization_id,
        site_ids=subscription.site_ids,
        is_active=subscription.is_active,
        last_triggered=subscription.last_triggered,
        trigger_count=subscription.trigger_count,
        created_at=subscription.created_at,
        updated_at=subscription.updated_at,
    )


@router.patch("/subscriptions/{subscription_id}", response_model=SubscriptionResponse)
async def update_subscription(
    subscription_id: UUID,
    request: SubscriptionUpdate,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("events:subscribe")),
) -> dict[str, Any]:
    """Update an event subscription."""
    service = EventService(session)

    updates = request.model_dump(exclude_unset=True)

    # block retargeting a subscription to sibling sites (the new
    # site_ids must all be granted) AND block clearing site_ids to null/[] (which
    # would promote it to an org-level sub that fans out sibling-site events to a
    # site-limited caller's webhook). Only enforce the clear-to-org-level rule
    # when the body actually carried a ``site_ids`` field — an omitted field
    # leaves the (already grant-constrained) stored scope untouched.
    _assert_requested_sites_granted(
        current_user,
        request.site_ids,
        site_ids_provided="site_ids" in updates,
    )

    subscription = await service.update_subscription(
        subscription_id,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_grant_for(current_user),
        **updates,
    )

    if not subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")

    await session.commit()

    return SubscriptionResponse(
        id=subscription.id,
        name=subscription.name,
        pattern=subscription.pattern,
        target_type=subscription.target_type,
        target_url=subscription.target_url,
        target_config=subscription.target_config,
        organization_id=subscription.organization_id,
        site_ids=subscription.site_ids,
        is_active=subscription.is_active,
        last_triggered=subscription.last_triggered,
        trigger_count=subscription.trigger_count,
        created_at=subscription.created_at,
        updated_at=subscription.updated_at,
    )


@router.delete("/subscriptions/{subscription_id}", response_model=MessageResponse)
async def delete_subscription(
    subscription_id: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: CurrentUser = Depends(require_permissions("events:subscribe")),
) -> dict[str, Any]:
    """Delete an event subscription."""
    service = EventService(session)

    deleted = await service.delete_subscription(
        subscription_id,
        organization_id=org_scope_or_platform(current_user),
        accessible_site_ids=_grant_for(current_user),
    )

    if not deleted:
        raise HTTPException(status_code=404, detail="Subscription not found")

    await session.commit()

    return MessageResponse(message="Subscription deleted successfully")


# ===========================================
# Single Event (catch-all — must be LAST)
# ===========================================


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: UUID,
    session: AsyncSession = Depends(get_logdb_session),  # EventRecord → LogDB
    current_user: CurrentUser = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Get a single event by ID."""
    service = EventService(session)
    event = await service.get_event_by_id(event_id)

    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Check organization access
    if event.organization_id and event.organization_id != current_user.organization_id:
        if not is_unscoped_superuser(current_user):
            raise HTTPException(status_code=403, detail="Access denied")

    # get_event_by_id filters by id only — a site-limited operator could
    # read a sibling-site event by guessing/enumerating its UUID. Enforce the
    # per-user site grant (no-op for super / org admin and NULL site_id =
    # org-level event). 404 shape, no existence oracle.
    assert_can_access_site(current_user, event.site_id, detail="Event not found")

    return event.to_dict()

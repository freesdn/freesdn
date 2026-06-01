# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Notification Endpoints
=====================================

Notification management, delivery, and provider configuration endpoints.
"""

import logging
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user
from app.core.dependencies import org_scope_or_platform
from app.db import get_session
from app.models import User
from app.services.notification import (
    NotificationCategory,
    NotificationChannel,
    NotificationService,
    NotificationSeverity,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# =============================================================================
# Schemas
# =============================================================================


class SendNotificationRequest(BaseModel):
    """Request to send a notification."""

    channel: NotificationChannel
    recipient: str
    title: str
    body: str
    body_html: str | None = None
    action_url: str | None = None
    action_text: str | None = None


class NotificationResponse(BaseModel):
    """Notification delivery response."""

    success: bool
    channel: str
    status: str
    message_id: str | None = None
    error: str | None = None


class InAppNotificationCreate(BaseModel):
    """Create in-app notification."""

    user_id: UUID | None = None
    title: str
    body: str
    category: NotificationCategory = NotificationCategory.SYSTEM
    severity: NotificationSeverity = NotificationSeverity.INFO
    action_url: str | None = None


class InAppNotificationResponse(BaseModel):
    """In-app notification response."""

    id: str
    title: str
    body: str
    category: str
    severity: str
    action_url: str | None = None
    read: bool
    dismissed: bool = False
    created_at: str


class InAppNotificationListResponse(BaseModel):
    """Paginated in-app notification list.

    NOTE: Previously this endpoint returned a bare ``list[...]`` but the
    frontend (``notificationApi.getInAppNotifications`` and
    ``TopBar``) expected ``{items, total, limit, offset}``. The mismatch
    meant ``notificationsData?.items`` was always ``undefined`` and the
    bell dropdown rendered empty even when notifications existed.

    ``unread_count`` is the global unread count, mirroring the bell-badge
    endpoint so the drawer doesn't need a second roundtrip.
    """

    items: list[InAppNotificationResponse]
    total: int
    limit: int
    offset: int
    unread_count: int = 0


class NotificationPreferencesUpdate(BaseModel):
    """Update notification preferences."""

    enabled_channels: list[NotificationChannel] | None = None
    quiet_hours_start: int | None = Field(None, ge=0, le=23)
    quiet_hours_end: int | None = Field(None, ge=0, le=23)
    category_settings: dict[str, dict[str, Any]] | None = None


class MuteCategoriesRequest(BaseModel):
    """Mute one or more notification categories.

    ``expires_at=null`` (or omitted) = permanent mute.
    A future ISO-8601 timestamp snoozes the category until that point.
    """

    categories: list[str] = Field(..., min_length=1, max_length=32)
    expires_at: datetime | None = None


class MuteCategoriesResponse(BaseModel):
    """Echo of the mute state after the update."""

    muted_categories: dict[str, dict[str, str | None]]


class ProviderConfig(BaseModel):
    """Notification provider configuration."""

    channel: NotificationChannel
    name: str
    config: dict[str, Any]
    is_enabled: bool = True


class ProviderTestRequest(BaseModel):
    """Test a notification provider."""

    channel: NotificationChannel
    recipient: str


# ── Provider schemas ─────────────────────────────────────────────────────

# Config blobs can carry SMTP server settings, Twilio account SIDs,
# Slack webhook URLs (encrypted), OAuth refresh tokens, etc. — 256 KiB
# is far past any legitimate per-provider config and rejects JSONB-
# stuffing attempts at the validation layer instead of after a global
# body cap.
_PROVIDER_CONFIG_MAX_BYTES = 256 * 1024


def _validate_provider_config_size(v: dict[str, Any] | None) -> dict[str, Any] | None:
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > _PROVIDER_CONFIG_MAX_BYTES:
        raise ValueError(f"config exceeds {_PROVIDER_CONFIG_MAX_BYTES} bytes (got {size})")
    return v


def _no_control_chars(name: str | None) -> str | None:
    """Reject CR/LF/control chars in display names.

    ``name`` isn't sent in email headers today, but allowing CRLF
    keeps the door open for header-injection in any future
    "From:"-style use; cheap to forbid up front.
    """
    if name is None:
        return name
    for ch in name:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ValueError("name must not contain control characters")
    return name


class ProviderCreateRequest(BaseModel):
    """Create a notification provider."""

    name: str = Field(..., max_length=120)
    provider_type: str = Field(..., max_length=40)
    config: dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool = True
    is_default: bool = False
    rate_limit_per_hour: int = Field(500, ge=0, le=100_000)
    rate_limit_per_day: int = Field(10_000, ge=0, le=1_000_000)

    @field_validator("name")
    @classmethod
    def _name_no_control(cls, v: str) -> str:
        return _no_control_chars(v) or v

    @field_validator("config")
    @classmethod
    def _config_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_provider_config_size(v) or v


class ProviderUpdateRequest(BaseModel):
    """Partial update for a notification provider."""

    name: str | None = Field(None, max_length=120)
    config: dict[str, Any] | None = None
    is_enabled: bool | None = None
    is_default: bool | None = None
    rate_limit_per_hour: int | None = Field(None, ge=0, le=100_000)
    rate_limit_per_day: int | None = Field(None, ge=0, le=1_000_000)

    @field_validator("name")
    @classmethod
    def _name_no_control(cls, v: str | None) -> str | None:
        return _no_control_chars(v)

    @field_validator("config")
    @classmethod
    def _config_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_provider_config_size(v)


class ProviderResponse(BaseModel):
    """Notification provider response."""

    model_config = {"from_attributes": True}

    id: str
    name: str
    provider_type: str
    channel: str
    is_enabled: bool
    is_default: bool
    is_verified: bool
    last_verified_at: str | None = None
    last_error: str | None = None
    rate_limit_per_hour: int
    rate_limit_per_day: int
    config_summary: dict[str, Any] = {}
    created_at: str
    updated_at: str


class ProviderTypeResponse(BaseModel):
    """Provider type definition."""

    type: str
    name: str
    channel: str
    icon: str = ""
    config_schema: dict[str, Any] = {}


class TestProviderResponse(BaseModel):
    """Result of a provider test."""

    success: bool
    message: str
    details: dict[str, Any] | None = None


# =============================================================================
# Helper to require admin role
# =============================================================================


def _require_admin(user: User) -> None:
    # Scope-aware: a scoped key narrowed below admin must not pass.
    from app.core.dependencies import is_unscoped_org_admin

    if not is_unscoped_org_admin(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )


def _provider_to_response(p: Any, service: NotificationService) -> ProviderResponse:
    """Convert a NotificationProviderRecord to ProviderResponse (DRY helper)."""
    return ProviderResponse(
        id=str(p.id),
        name=p.name,
        provider_type=p.provider_type,
        channel=p.channel,
        is_enabled=p.is_enabled,
        is_default=p.is_default,
        is_verified=p.is_verified,
        last_verified_at=p.last_verified_at.isoformat() if p.last_verified_at else None,
        last_error=p.last_error,
        rate_limit_per_hour=p.rate_limit_per_hour,
        rate_limit_per_day=p.rate_limit_per_day,
        config_summary=service._safe_config_summary(p.config),
        created_at=p.created_at.isoformat(),
        updated_at=p.updated_at.isoformat(),
    )


# =============================================================================
# Provider CRUD
# =============================================================================


@router.get("/providers", response_model=list[ProviderResponse])
async def list_providers(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    channel: str | None = Query(None),
    enabled_only: bool = Query(False),
) -> Any:
    """List all configured notification providers."""
    # gate to admin, matching every other provider operation
    # (create/update/delete/verify). The list discloses org notification
    # infrastructure (channels, health, rate limits) that a viewer/operator
    # should not enumerate; credentials are masked but the metadata is not.
    _require_admin(current_user)
    service = NotificationService(db=session)
    records = await service.list_providers(
        organization_id=org_scope_or_platform(current_user),
        channel=channel,
        enabled_only=enabled_only,
    )
    return [_provider_to_response(p, service) for p in records]


@router.get("/providers/types", response_model=list[ProviderTypeResponse])
async def get_provider_types(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Return all supported provider types with their config schemas."""
    types = NotificationService.get_provider_types()
    return [ProviderTypeResponse(**t) for t in types]


@router.post("/providers", response_model=ProviderResponse, status_code=status.HTTP_201_CREATED)
async def create_provider(
    data: ProviderCreateRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Create a new notification provider. Requires admin."""
    _require_admin(current_user)
    service = NotificationService(db=session)
    try:
        record = await service.create_provider(
            name=data.name,
            provider_type=data.provider_type,
            config=data.config,
            is_enabled=data.is_enabled,
            is_default=data.is_default,
            rate_limit_per_hour=data.rate_limit_per_hour,
            rate_limit_per_day=data.rate_limit_per_day,
            organization_id=org_scope_or_platform(current_user),
        )
    except ValueError as exc:
        logger.error("Invalid notification provider configuration: %s", exc, exc_info=True)
        raise HTTPException(status_code=422, detail="Invalid notification provider configuration")
    await session.commit()
    return _provider_to_response(record, service)


@router.get("/providers/{provider_id}", response_model=ProviderResponse)
async def get_provider(
    provider_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get a single notification provider by ID (org-scoped)."""
    service = NotificationService(db=session)
    record = await service.get_provider(
        provider_id, organization_id=org_scope_or_platform(current_user)
    )
    if not record:
        raise HTTPException(status_code=404, detail="Provider not found")
    return _provider_to_response(record, service)


@router.put("/providers/{provider_id}", response_model=ProviderResponse)
async def update_provider(
    provider_id: UUID,
    data: ProviderUpdateRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Update a notification provider. Requires admin."""
    _require_admin(current_user)
    service = NotificationService(db=session)
    updates = data.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    record = await service.update_provider(
        provider_id,
        organization_id=org_scope_or_platform(current_user),
        **updates,
    )
    if not record:
        raise HTTPException(status_code=404, detail="Provider not found")
    await session.commit()
    return _provider_to_response(record, service)


@router.delete("/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(
    provider_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Delete a notification provider. Requires admin."""
    _require_admin(current_user)
    service = NotificationService(db=session)
    deleted = await service.delete_provider(
        provider_id,
        organization_id=org_scope_or_platform(current_user),
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Provider not found")
    await session.commit()


@router.post("/providers/{provider_id}/verify", response_model=TestProviderResponse)
async def verify_stored_provider(
    provider_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Verify a stored provider's connectivity. Requires admin."""
    _require_admin(current_user)
    service = NotificationService(db=session)
    # GET/PUT/DELETE on the same resource return 404 for missing/foreign
    # providers; verify used to return 200 with ``success=false`` which
    # looked like a verification failure rather than a lookup failure.
    record = await service.get_provider(
        provider_id, organization_id=org_scope_or_platform(current_user)
    )
    if not record:
        raise HTTPException(status_code=404, detail="Provider not found")
    ok, msg = await service.verify_stored_provider(
        provider_id,
        organization_id=org_scope_or_platform(current_user),
    )
    await session.commit()
    return TestProviderResponse(success=ok, message=msg)


@router.post("/providers/{provider_id}/test", response_model=TestProviderResponse)
async def test_stored_provider(
    provider_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    test_email: str | None = Query(None),
) -> Any:
    """Send a test notification through a stored provider. Requires admin."""
    _require_admin(current_user)
    if not test_email:
        raise HTTPException(status_code=400, detail="test_email query param required")
    service = NotificationService(db=session)
    record = await service.get_provider(
        provider_id, organization_id=org_scope_or_platform(current_user)
    )
    if not record:
        raise HTTPException(status_code=404, detail="Provider not found")
    result = await service.test_stored_provider(
        provider_id,
        test_email,
        organization_id=org_scope_or_platform(current_user),
    )
    await session.commit()
    return TestProviderResponse(
        success=result.success,
        message="Test sent successfully" if result.success else (result.error or "Test failed"),
        details={"channel": result.channel.value, "status": result.status.value}
        if result.success
        else None,
    )


# =============================================================================
# Send Notifications
# =============================================================================


@router.post("/send", response_model=NotificationResponse)
async def send_notification(
    notification_data: SendNotificationRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """
    Send a notification through a specific channel.

    Requires admin privileges.
    """
    _require_admin(current_user)

    service = NotificationService(db=session)
    # Load the org's configured providers before sending — otherwise send() has no
    # provider registered for the channel and returns "No provider configured".
    await service.load_providers_from_db(organization_id=org_scope_or_platform(current_user))

    result = await service.send(
        channel=notification_data.channel,
        recipient=notification_data.recipient,
        title=notification_data.title,
        body=notification_data.body,
        body_html=notification_data.body_html,
        action_url=notification_data.action_url,
        action_text=notification_data.action_text,
        organization_id=org_scope_or_platform(current_user),
    )

    return NotificationResponse(
        success=result.success,
        channel=result.channel.value,
        status=result.status.value,
        message_id=result.message_id,
        error=result.error,
    )


@router.post("/send/template", response_model=NotificationResponse)
async def send_template_notification(
    channel: NotificationChannel,
    template_id: str,
    recipient: str,
    variables: dict[str, Any],
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Send a notification using a template."""
    _require_admin(current_user)

    service = NotificationService(db=session)
    # Load the org's configured providers before sending (see /send).
    await service.load_providers_from_db(organization_id=org_scope_or_platform(current_user))

    result = await service.send_template(
        template_id=template_id,
        channel=channel,
        recipient=recipient,
        variables=variables,
        organization_id=org_scope_or_platform(current_user),
    )

    return NotificationResponse(
        success=result.success,
        channel=result.channel.value,
        status=result.status.value,
        message_id=result.message_id,
        error=result.error,
    )


# =============================================================================
# In-App Notifications
# =============================================================================


@router.get("/in-app", response_model=InAppNotificationListResponse)
async def get_in_app_notifications(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    unread_only: bool = False,
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
    include_dismissed: bool = Query(
        False,
        description=(
            "False (default) = Active tab — undismissed items only. "
            "True = Archive tab — dismissed items only."
        ),
    ),
) -> Any:
    """Get in-app notifications for the current user.

    Returns a paginated envelope ``{items, total, limit, offset,
    unread_count}``. ``total`` reflects the count matching the current
    filter (Active vs Archive) so the FE can stop paging. ``unread_count``
    is always the global badge value.
    """
    service = NotificationService(db=session)

    envelope = await service.get_in_app_notifications(
        user_id=current_user.id,
        unread_only=unread_only,
        limit=limit,
        offset=offset,
        include_dismissed=include_dismissed,
    )

    items = [
        InAppNotificationResponse(
            id=n["id"],
            title=n["title"],
            body=n["body"],
            category=n["category"],
            severity=n["severity"],
            action_url=n.get("action_url"),
            read=n["read"],
            dismissed=n.get("dismissed", False),
            created_at=n["created_at"],
        )
        for n in envelope["items"]
    ]
    return InAppNotificationListResponse(
        items=items,
        total=envelope["total"],
        limit=envelope["limit"],
        offset=envelope["offset"],
        unread_count=envelope["unread_count"],
    )


@router.post("/in-app/{notification_id}/read", status_code=status.HTTP_204_NO_CONTENT)
async def mark_notification_read(
    notification_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Mark a notification as read."""
    service = NotificationService(db=session)
    await service.mark_read(notification_id, current_user.id)


@router.post("/in-app/read-all", status_code=status.HTTP_204_NO_CONTENT)
async def mark_all_notifications_read(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Mark all notifications as read."""
    service = NotificationService(db=session)
    await service.mark_all_read(current_user.id)


class UnreadCountResponse(BaseModel):
    """Unread notification count response."""

    total: int


class MarkNotificationsRequest(BaseModel):
    """Request to mark notifications."""

    # ``mark_notifications`` awaits one DB op per id, so an uncapped list is
    # an N-query amplification (DoS) vector for any authenticated user. Cap
    # the batch; the FE bell drawer marks at most one page (<=200) at a time.
    ids: list[UUID] = Field(..., min_length=1, max_length=200)
    action: str = Field(pattern="^(read|dismiss)$")


class MarkNotificationsResponse(BaseModel):
    """Response for marking notifications."""

    marked: int


@router.get("/in-app/unread-count", response_model=UnreadCountResponse)
async def get_unread_count(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get count of unread notifications for the current user."""
    service = NotificationService(db=session)
    count = await service.get_unread_count(current_user.id)
    return UnreadCountResponse(total=count)


@router.post("/in-app/mark", response_model=MarkNotificationsResponse)
async def mark_notifications(
    request: MarkNotificationsRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Mark multiple notifications as read or dismissed."""
    service = NotificationService(db=session)

    marked = 0
    if request.action == "read":
        for notification_id in request.ids:
            await service.mark_read(notification_id, current_user.id)
            marked += 1
    elif request.action == "dismiss":
        for notification_id in request.ids:
            await service.dismiss(notification_id, current_user.id)
            marked += 1

    return MarkNotificationsResponse(marked=marked)


@router.post("/in-app/mark-all-read", response_model=MarkNotificationsResponse)
async def mark_all_read(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Mark all notifications as read for the current user."""
    service = NotificationService(db=session)
    count = await service.mark_all_read(current_user.id)
    return MarkNotificationsResponse(marked=count)


# =============================================================================
# Preferences
# =============================================================================


@router.get("/preferences")
async def get_notification_preferences(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Get notification preferences for the current user."""
    service = NotificationService(db=session)
    prefs = await service._get_user_preferences(current_user.id)

    if prefs is None:
        # No preferences saved yet — return defaults (all channels enabled)
        return {
            "enabled_channels": [c.value for c in NotificationChannel],
            "quiet_hours": None,
            "category_settings": {},
        }

    quiet_hours = None
    if prefs.quiet_hours is not None:
        quiet_hours = {"start": prefs.quiet_hours[0], "end": prefs.quiet_hours[1]}

    return {
        "enabled_channels": [c.value for c in prefs.enabled_channels],
        "quiet_hours": quiet_hours,
        "category_settings": prefs.category_settings,
    }


@router.put("/preferences")
async def update_notification_preferences(
    preferences: NotificationPreferencesUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Update notification preferences."""
    service = NotificationService(db=session)

    quiet_hours = None
    if preferences.quiet_hours_start is not None and preferences.quiet_hours_end is not None:
        quiet_hours = (preferences.quiet_hours_start, preferences.quiet_hours_end)

    await service.update_preferences(
        user_id=current_user.id,
        enabled_channels=preferences.enabled_channels,
        category_settings=preferences.category_settings,
        quiet_hours=quiet_hours,
    )

    return {"status": "updated"}


@router.patch("/preferences/mute", response_model=MuteCategoriesResponse)
async def mute_notification_categories(
    payload: MuteCategoriesRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Mute (permanently) or snooze (until ``expires_at``) notification categories.

    The gate is consulted by ``NotificationService.send()``: matching
    categories return ``DeliveryStatus.SKIPPED`` rather than being
    delivered. Tracked in delivery analytics separately from SENT.
    """
    service = NotificationService(db=session)
    try:
        out = await service.mute_categories(
            user_id=current_user.id,
            categories=payload.categories,
            expires_at=payload.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await session.commit()
    return MuteCategoriesResponse(**out)


@router.delete(
    "/preferences/mute/{category}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def unmute_notification_category(
    category: str,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> None:
    """Unmute a single category. 404 if no mute entry exists."""
    service = NotificationService(db=session)
    removed = await service.unmute_category(user_id=current_user.id, category=category)
    if not removed:
        raise HTTPException(status_code=404, detail="Category was not muted")
    await session.commit()


# =============================================================================
# Provider Management (legacy in-memory test — kept for backward compat)
# =============================================================================


@router.post("/providers/channel-test", response_model=NotificationResponse)
async def test_notification_provider(
    test_data: ProviderTestRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> Any:
    """Test an in-memory notification provider by channel."""
    _require_admin(current_user)
    service = NotificationService(db=session)
    result = await service.test_provider(
        channel=test_data.channel,
        recipient=test_data.recipient,
    )
    return NotificationResponse(
        success=result.success,
        channel=result.channel.value,
        status=result.status.value,
        message_id=result.message_id,
        error=result.error,
    )

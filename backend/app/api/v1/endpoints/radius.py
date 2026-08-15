# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - RADIUS / 802.1X API Endpoints
===========================================

REST API for RADIUS server profiles, 802.1X port/SSID configuration,
and authentication event auditing.

Endpoints:
  RADIUS Profiles
  - GET    /radius/profiles              - List RADIUS server profiles
  - POST   /radius/profiles              - Create a RADIUS profile
  - PUT    /radius/profiles/{id}         - Update a RADIUS profile
  - DELETE /radius/profiles/{id}         - Soft-delete a RADIUS profile
  - POST   /radius/profiles/{id}/test    - Health-check a RADIUS profile

  802.1X Configs
  - GET    /radius/dot1x-configs         - List 802.1X configs
  - POST   /radius/dot1x-configs         - Create and push a config

  Auth Events
  - GET    /radius/auth-events           - Query auth events (paginated)
"""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user, get_session
from app.core.crypto import encrypt_credential
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.models import UserRole
from app.models.core import Controller, Site
from app.models.radius import Dot1xAuthEvent, Dot1xPortConfig, RadiusServerProfile
from app.modules.network.models import PortProfile, WifiNetwork
from app.services.radius import RadiusProfileService

logger = logging.getLogger(__name__)
router = APIRouter()


# =========================================================================
# Helpers
# =========================================================================


def _org_id(user: Any) -> Any:
    """Extract organization_id from the current user or raise 400."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _require_admin(user: Any) -> None:
    # Scope ceiling: a scoped API key must not satisfy this role-only admin gate
    # via its owner's raw role (RADIUS/802.1X is auth infrastructure).
    if getattr(user, "is_scoped", False):
        raise HTTPException(403, detail="Scoped API keys cannot satisfy role-based gates")
    if getattr(user, "role", None) not in (UserRole.ORG_ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(403, detail="Admin access required")


# =========================================================================
# Inline Pydantic Schemas
# =========================================================================

# --- RADIUS Profile ---


class RadiusProfileCreate(BaseModel):
    name: str = Field(..., max_length=255)
    host: str = Field(..., max_length=255)
    port: int = Field(1812, ge=1, le=65535)
    shared_secret: str = Field(..., min_length=1)
    auth_protocol: str = Field("pap", pattern=r"^(pap|mschapv2|eap-tls|eap-peap)$")
    timeout_seconds: int = Field(5, ge=1, le=60)
    retry_count: int = Field(3, ge=0, le=10)
    accounting_enabled: bool = False
    accounting_port: int = Field(1813, ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        import ipaddress

        v = v.strip()
        if not v:
            raise ValueError("Host cannot be empty")
        try:
            addr = ipaddress.ip_address(v)
            if addr.is_loopback or addr.is_link_local:
                raise ValueError("Cannot use loopback or link-local address")
            if addr.is_multicast:
                raise ValueError("Cannot use multicast address")
            if addr.is_unspecified:
                raise ValueError("Cannot use unspecified address")
        except ValueError as e:
            if (
                "loopback" in str(e)
                or "link-local" in str(e)
                or "multicast" in str(e)
                or "unspecified" in str(e)
            ):
                raise
            # It's a hostname, that's fine
        return v


class RadiusProfileUpdate(BaseModel):
    name: str | None = Field(None, max_length=255)
    host: str | None = Field(None, max_length=255)
    port: int | None = Field(None, ge=1, le=65535)
    shared_secret: str | None = Field(None, min_length=1)
    auth_protocol: str | None = Field(None, pattern=r"^(pap|mschapv2|eap-tls|eap-peap)$")
    timeout_seconds: int | None = Field(None, ge=1, le=60)
    retry_count: int | None = Field(None, ge=0, le=10)
    accounting_enabled: bool | None = None
    accounting_port: int | None = Field(None, ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str | None) -> str | None:
        if v is None:
            return v
        import ipaddress

        v = v.strip()
        if not v:
            raise ValueError("Host cannot be empty")
        try:
            addr = ipaddress.ip_address(v)
            if addr.is_loopback or addr.is_link_local:
                raise ValueError("Cannot use loopback or link-local address")
            if addr.is_multicast:
                raise ValueError("Cannot use multicast address")
            if addr.is_unspecified:
                raise ValueError("Cannot use unspecified address")
        except ValueError as e:
            if (
                "loopback" in str(e)
                or "link-local" in str(e)
                or "multicast" in str(e)
                or "unspecified" in str(e)
            ):
                raise
            # It's a hostname, that's fine
        return v


class RadiusProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    host: str
    port: int
    auth_protocol: str
    timeout_seconds: int
    retry_count: int
    accounting_enabled: bool
    accounting_port: int
    is_healthy: bool
    last_health_check: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


# --- 802.1X Config ---


class Dot1xConfigCreate(BaseModel):
    port_profile_id: UUID | None = None
    wifi_network_id: UUID | None = None
    controller_id: UUID
    radius_profile_id: UUID
    auth_mode: str = Field("port-based", pattern=r"^(port-based|mac-based|multi-host)$")
    guest_vlan_id: int | None = None
    dynamic_vlan: bool = False
    reauthentication_interval: int = Field(3600, ge=60, le=86400)


class Dot1xConfigResponse(BaseModel):
    id: str
    port_profile_id: str | None = None
    wifi_network_id: str | None = None
    controller_id: str
    radius_profile_id: str
    auth_mode: str
    guest_vlan_id: int | None = None
    dynamic_vlan: bool
    reauthentication_interval: int
    push_status: str
    pushed_at: str | None = None
    created_at: str | None = None


# --- Auth Event ---


class AuthEventResponse(BaseModel):
    id: str
    organization_id: str
    controller_id: str
    device_id: str | None = None
    client_mac: str
    username: str | None = None
    auth_result: str
    reject_reason: str | None = None
    assigned_vlan: int | None = None
    radius_profile_id: str | None = None
    timestamp: str


# =========================================================================
# Serialisation helpers
# =========================================================================


def _profile_to_response(p: RadiusServerProfile) -> RadiusProfileResponse:
    return RadiusProfileResponse(
        id=str(p.id),
        organization_id=str(p.organization_id),
        name=p.name,
        host=p.host,
        port=p.port,
        auth_protocol=p.auth_protocol,
        timeout_seconds=p.timeout_seconds,
        retry_count=p.retry_count,
        accounting_enabled=p.accounting_enabled,
        accounting_port=p.accounting_port,
        is_healthy=p.is_healthy,
        last_health_check=p.last_health_check.isoformat() if p.last_health_check else None,
        created_at=p.created_at.isoformat() if p.created_at else None,
        updated_at=p.updated_at.isoformat() if p.updated_at else None,
    )


def _config_to_response(c: Dot1xPortConfig) -> Dot1xConfigResponse:
    return Dot1xConfigResponse(
        id=str(c.id),
        port_profile_id=str(c.port_profile_id) if c.port_profile_id else None,
        wifi_network_id=str(c.wifi_network_id) if c.wifi_network_id else None,
        controller_id=str(c.controller_id),
        radius_profile_id=str(c.radius_profile_id),
        auth_mode=c.auth_mode,
        guest_vlan_id=c.guest_vlan_id,
        dynamic_vlan=c.dynamic_vlan,
        reauthentication_interval=c.reauthentication_interval,
        push_status=c.push_status,
        pushed_at=c.pushed_at.isoformat() if c.pushed_at else None,
        created_at=c.created_at.isoformat() if c.created_at else None,
    )


def _event_to_response(e: Dot1xAuthEvent) -> AuthEventResponse:
    return AuthEventResponse(
        id=str(e.id),
        organization_id=str(e.organization_id),
        controller_id=str(e.controller_id),
        device_id=str(e.device_id) if e.device_id else None,
        client_mac=e.client_mac,
        username=e.username,
        auth_result=e.auth_result,
        reject_reason=e.reject_reason,
        assigned_vlan=e.assigned_vlan,
        radius_profile_id=str(e.radius_profile_id) if e.radius_profile_id else None,
        timestamp=e.timestamp.isoformat(),
    )


# =========================================================================
# RADIUS Profile CRUD
# =========================================================================


@router.get("/profiles", response_model=list[RadiusProfileResponse])
async def list_radius_profiles(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """List all RADIUS server profiles for the user's organization."""
    org_id = _org_id(user)
    offset = (page - 1) * page_size
    result = await session.execute(
        select(RadiusServerProfile)
        .where(
            RadiusServerProfile.organization_id == org_id,
            RadiusServerProfile.deleted_at.is_(None),
        )
        .order_by(RadiusServerProfile.name)
        .offset(offset)
        .limit(page_size)
    )
    profiles = result.scalars().all()
    return [_profile_to_response(p) for p in profiles]


@router.post("/profiles", response_model=RadiusProfileResponse, status_code=201)
async def create_radius_profile(
    data: RadiusProfileCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Create a new RADIUS server profile."""
    _require_admin(user)
    org_id = _org_id(user)

    profile = RadiusServerProfile(
        organization_id=org_id,
        name=data.name,
        host=data.host,
        port=data.port,
        shared_secret_encrypted=encrypt_credential(data.shared_secret),
        auth_protocol=data.auth_protocol,
        timeout_seconds=data.timeout_seconds,
        retry_count=data.retry_count,
        accounting_enabled=data.accounting_enabled,
        accounting_port=data.accounting_port,
    )
    if hasattr(profile, "created_by"):
        profile.created_by = user.id

    session.add(profile)
    await session.flush()
    await session.refresh(profile)
    return _profile_to_response(profile)


@router.put("/profiles/{profile_id}", response_model=RadiusProfileResponse)
async def update_radius_profile(
    profile_id: UUID,
    data: RadiusProfileUpdate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Update an existing RADIUS server profile."""
    _require_admin(user)
    org_id = _org_id(user)
    result = await session.execute(
        select(RadiusServerProfile).where(
            RadiusServerProfile.id == profile_id,
            RadiusServerProfile.organization_id == org_id,
            RadiusServerProfile.deleted_at.is_(None),
        )
    )
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="RADIUS profile not found")

    update_data = data.model_dump(exclude_unset=True)

    # Map ``shared_secret`` input to the ``shared_secret_encrypted`` column
    if "shared_secret" in update_data:
        profile.shared_secret_encrypted = encrypt_credential(update_data.pop("shared_secret"))

    _ALLOWED_FIELDS = {
        "name",
        "host",
        "port",
        "auth_protocol",
        "timeout_seconds",
        "retry_count",
        "accounting_enabled",
        "accounting_port",
    }
    for key, value in update_data.items():
        if key in _ALLOWED_FIELDS:
            setattr(profile, key, value)

    if hasattr(profile, "updated_by"):
        profile.updated_by = user.id

    await session.flush()
    await session.refresh(profile)
    return _profile_to_response(profile)


@router.delete("/profiles/{profile_id}", status_code=204)
async def delete_radius_profile(
    profile_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    """Soft-delete a RADIUS server profile."""
    _require_admin(user)

    org_id = _org_id(user)
    result = await session.execute(
        select(RadiusServerProfile).where(
            RadiusServerProfile.id == profile_id,
            RadiusServerProfile.organization_id == org_id,
            RadiusServerProfile.deleted_at.is_(None),
        )
    )
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="RADIUS profile not found")

    profile.deleted_at = datetime.now(UTC)
    if hasattr(profile, "updated_by"):
        profile.updated_by = user.id

    await session.flush()
    return None


@router.post("/profiles/{profile_id}/test")
async def test_radius_profile(
    profile_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Run a TCP health check against a RADIUS server profile."""
    _require_admin(user)
    org_id = _org_id(user)

    # Verify ownership
    result = await session.execute(
        select(RadiusServerProfile).where(
            RadiusServerProfile.id == profile_id,
            RadiusServerProfile.organization_id == org_id,
            RadiusServerProfile.deleted_at.is_(None),
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="RADIUS profile not found")

    svc = RadiusProfileService(session)
    outcome = await svc.health_check(profile_id)
    await session.flush()
    return outcome


# =========================================================================
# 802.1X Configs
# =========================================================================


@router.get("/dot1x-configs", response_model=list[Dot1xConfigResponse])
async def list_dot1x_configs(
    controller_id: UUID | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """List 802.1X configs, optionally filtered by controller."""
    org_id = _org_id(user)

    query = (
        select(Dot1xPortConfig)
        .join(Controller, Dot1xPortConfig.controller_id == Controller.id)
        .where(
            Dot1xPortConfig.deleted_at.is_(None),
            Controller.site_id.in_(
                select(Site.id).where(Site.organization_id == org_id, Site.deleted_at.is_(None))
            ),
            # Per-user site grant: a site-limited operator must not see 802.1X
            # configs bound to a sibling-site controller (no-op for admins).
            site_scope_filter(user, Controller.site_id),
        )
    )
    if controller_id:
        query = query.where(Dot1xPortConfig.controller_id == controller_id)

    offset = (page - 1) * page_size
    query = query.order_by(Dot1xPortConfig.created_at.desc()).offset(offset).limit(page_size)
    result = await session.execute(query)
    configs = result.scalars().all()
    return [_config_to_response(c) for c in configs]


@router.post("/dot1x-configs", response_model=Dot1xConfigResponse, status_code=201)
async def create_dot1x_config(
    data: Dot1xConfigCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Create a new 802.1X config and push it to the controller."""
    _require_admin(user)
    org_id = _org_id(user)

    # Verify RADIUS profile exists and belongs to user's org
    rp_result = await session.execute(
        select(RadiusServerProfile).where(
            RadiusServerProfile.id == data.radius_profile_id,
            RadiusServerProfile.organization_id == org_id,
            RadiusServerProfile.deleted_at.is_(None),
        )
    )
    if not rp_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="RADIUS profile not found")

    # Verify controller belongs to user's org (via Site)
    ctrl_result = await session.execute(
        select(Controller)
        .join(Site, Controller.site_id == Site.id)
        .where(
            Controller.id == data.controller_id,
            Site.organization_id == org_id,
            Controller.deleted_at.is_(None),
        )
    )
    controller = ctrl_result.scalar_one_or_none()
    if not controller:
        raise HTTPException(status_code=404, detail="Controller not found")
    # Per-user site grant: a site-limited operator must not push an 802.1X config
    # to a controller in a sibling site (no-op for admins / None site).
    assert_can_access_site(user, controller.site_id, detail="Controller not found")

    # Verify port_profile_id belongs to user's org (via Site)
    if data.port_profile_id:
        pp_result = await session.execute(
            select(PortProfile)
            .join(Site, PortProfile.site_id == Site.id)
            .where(
                PortProfile.id == data.port_profile_id,
                Site.organization_id == org_id,
                PortProfile.deleted_at.is_(None),
            )
        )
        port_profile = pp_result.scalar_one_or_none()
        if not port_profile:
            raise HTTPException(status_code=404, detail="Port profile not found")
        assert_can_access_site(user, port_profile.site_id, detail="Port profile not found")

    # Verify wifi_network_id belongs to user's org (via Site)
    if data.wifi_network_id:
        wn_result = await session.execute(
            select(WifiNetwork)
            .join(Site, WifiNetwork.site_id == Site.id)
            .where(
                WifiNetwork.id == data.wifi_network_id,
                Site.organization_id == org_id,
                WifiNetwork.deleted_at.is_(None),
            )
        )
        wifi_network = wn_result.scalar_one_or_none()
        if not wifi_network:
            raise HTTPException(status_code=404, detail="WiFi network not found")
        assert_can_access_site(user, wifi_network.site_id, detail="WiFi network not found")

    config = Dot1xPortConfig(
        port_profile_id=data.port_profile_id,
        wifi_network_id=data.wifi_network_id,
        controller_id=data.controller_id,
        radius_profile_id=data.radius_profile_id,
        auth_mode=data.auth_mode,
        guest_vlan_id=data.guest_vlan_id,
        dynamic_vlan=data.dynamic_vlan,
        reauthentication_interval=data.reauthentication_interval,
    )
    if hasattr(config, "created_by"):
        config.created_by = user.id

    session.add(config)
    await session.flush()
    await session.refresh(config)

    # Attempt to push the config to the controller
    svc = RadiusProfileService(session)
    push_result = await svc.push_dot1x_config(config.id)
    await session.flush()
    await session.refresh(config)

    if not push_result.get("success"):
        logger.warning(
            "802.1X config %s created but push failed: %s",
            config.id,
            push_result.get("error"),
        )

    return _config_to_response(config)


# =========================================================================
# Auth Events (paginated)
# =========================================================================


@router.get("/auth-events")
async def list_auth_events(
    client_mac: str | None = Query(
        None, max_length=17, pattern=r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
    ),
    auth_result: str | None = Query(None, pattern=r"^(success|reject|timeout)$"),
    controller_id: UUID | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Query 802.1X auth events with pagination and optional filters."""
    org_id = _org_id(user)

    base_query = select(Dot1xAuthEvent).where(
        Dot1xAuthEvent.organization_id == org_id,
    )

    # Per-user site grant: a site-limited operator must not see auth events for
    # controllers in sibling sites. ``Dot1xAuthEvent`` carries no ``site_id`` of
    # its own, so scope through the owning ``Controller.site_id``. No-op for
    # super_admin / org_admin (the predicate renders as ``true()``).
    if getattr(user, "is_site_limited", False):
        base_query = base_query.join(
            Controller, Dot1xAuthEvent.controller_id == Controller.id
        ).where(site_scope_filter(user, Controller.site_id))

    if client_mac:
        base_query = base_query.where(Dot1xAuthEvent.client_mac == client_mac)
    if auth_result:
        base_query = base_query.where(Dot1xAuthEvent.auth_result == auth_result)
    if controller_id:
        base_query = base_query.where(Dot1xAuthEvent.controller_id == controller_id)

    # Total count
    count_query = select(func.count()).select_from(base_query.subquery())
    total = (await session.execute(count_query)).scalar() or 0

    # Paginated results
    offset = (page - 1) * page_size
    data_query = (
        base_query.order_by(Dot1xAuthEvent.timestamp.desc()).offset(offset).limit(page_size)
    )
    result = await session.execute(data_query)
    events = result.scalars().all()

    return {
        "items": [_event_to_response(e) for e in events],
        "total": total,
        "page": page,
        "page_size": page_size,
    }

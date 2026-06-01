# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VPN Orchestration API Endpoints
===============================================

CRUD for VPN tunnel templates and site-to-site tunnels,
including full-mesh provisioning.

Endpoints:
  Templates
  - GET    /vpn/templates          - List tunnel templates
  - POST   /vpn/templates          - Create a tunnel template

  Tunnels
  - GET    /vpn/tunnels            - List site-to-site tunnels
  - POST   /vpn/tunnels            - Create a single tunnel
  - POST   /vpn/tunnels/mesh       - Create full-mesh tunnels
  - DELETE /vpn/tunnels/{id}       - Tear down a tunnel
"""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db
from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.services.vpn_orchestration import VPNOrchestrationService

logger = logging.getLogger(__name__)

router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Inline Pydantic Schemas
# ─────────────────────────────────────────────────────────────────────────────


class VPNTunnelTemplateCreate(BaseModel):
    name: str = Field(..., max_length=255)
    vpn_type: str = Field(
        ...,
        max_length=20,
        description="ipsec, wireguard, openvpn",
        pattern=r"^(ipsec|wireguard|openvpn)$",
    )
    topology: str = Field(
        "point_to_point",
        max_length=20,
        description="hub_spoke, full_mesh, point_to_point",
        pattern=r"^(hub_spoke|full_mesh|point_to_point)$",
    )
    config_template: dict[str, Any] = Field(default_factory=dict)
    default_subnets: list[Any] = Field(default_factory=list)
    mtu: int | None = Field(default=None, ge=576, le=9000)
    mss_clamp: int | None = Field(default=None, ge=536, le=8960)

    @field_validator("config_template", mode="before")
    @classmethod
    def validate_config_size(cls, v: Any) -> Any:
        import json

        if v and len(json.dumps(v)) > 65536:
            raise ValueError("config_template too large (max 64KB)")
        return v

    @field_validator("default_subnets", mode="before")
    @classmethod
    def validate_subnets_size(cls, v: Any) -> Any:
        import json

        if v and len(json.dumps(v)) > 65536:
            raise ValueError("default_subnets too large (max 64KB)")
        return v


class VPNTunnelTemplateResponse(BaseModel):
    id: UUID
    organization_id: UUID
    name: str
    vpn_type: str
    topology: str
    config_template: dict[str, Any] = Field(default_factory=dict)
    default_subnets: list[Any] = Field(default_factory=list)
    mtu: int | None = None
    mss_clamp: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class VPNTunnelTemplateListResponse(BaseModel):
    templates: list[VPNTunnelTemplateResponse]
    total: int


class SiteToSiteTunnelCreate(BaseModel):
    template_id: UUID
    site_a_id: UUID
    site_b_id: UUID
    gateway_a_device_id: UUID | None = None
    gateway_b_device_id: UUID | None = None


class MeshTunnelCreate(BaseModel):
    template_id: UUID
    site_ids: list[UUID] = Field(..., min_length=2, max_length=20)


_SENSITIVE_CONFIG_KEYS = {"private_key", "preshared_key", "secret", "password", "key", "token"}


def _redact_sensitive(obj: Any) -> Any:
    """Recursively redact sensitive keys in dicts and lists."""
    if isinstance(obj, dict):
        return {
            k: ("***" if k in _SENSITIVE_CONFIG_KEYS else _redact_sensitive(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_sensitive(item) for item in obj]
    return obj


class SiteToSiteTunnelResponse(BaseModel):
    id: UUID
    organization_id: UUID
    template_id: UUID | None = None
    site_a_id: UUID
    site_b_id: UUID
    gateway_a_device_id: UUID | None = None
    gateway_b_device_id: UUID | None = None
    status: str = "pending"
    config_a: dict[str, Any] = Field(default_factory=dict)
    config_b: dict[str, Any] = Field(default_factory=dict)
    provisioned_at: datetime | None = None
    last_health_check: datetime | None = None
    error_message: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True

    def model_post_init(self, __context: Any) -> None:
        """Recursively strip sensitive keys from config JSONB before returning."""
        self.config_a = _redact_sensitive(self.config_a)
        self.config_b = _redact_sensitive(self.config_b)


class SiteToSiteTunnelListResponse(BaseModel):
    tunnels: list[SiteToSiteTunnelResponse]
    total: int


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _org_id(user: Any) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return UUID(str(oid))


def _assert_tunnel_sites(user: Any, *site_ids: Any, detail: str = "Tunnel not found") -> None:
    """A site-to-site tunnel spans two sites; a site-limited operator must hold a
    grant for BOTH endpoints. No-op for super_admin / org_admin. 404 (not 403) to
    avoid an existence oracle. Org membership is still checked separately."""
    for sid in site_ids:
        if sid is not None:
            assert_can_access_site(user, sid, detail=detail)


# ─────────────────────────────────────────────────────────────────────────────
# Templates
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/templates", response_model=VPNTunnelTemplateListResponse)
async def list_templates(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List VPN tunnel templates for the organisation."""
    org_id = _org_id(user)
    service = VPNOrchestrationService(db)
    templates, total = await service.list_templates(org_id, limit=limit, offset=offset)
    return VPNTunnelTemplateListResponse(
        templates=[VPNTunnelTemplateResponse.model_validate(t) for t in templates],
        total=total,
    )


@router.post(
    "/templates",
    response_model=VPNTunnelTemplateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_template(
    body: VPNTunnelTemplateCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Create a new VPN tunnel template."""
    org_id = _org_id(user)
    service = VPNOrchestrationService(db)
    template = await service.create_template(
        org_id,
        body.model_dump(),
        created_by=user.id,
    )
    await db.commit()
    return VPNTunnelTemplateResponse.model_validate(template)


# ─────────────────────────────────────────────────────────────────────────────
# Tunnels
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/tunnels", response_model=SiteToSiteTunnelListResponse)
async def list_tunnels(
    tunnel_status: str | None = Query(
        None, alias="status", pattern=r"^(pending|provisioning|active|error|disabled)$"
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """List site-to-site VPN tunnels."""
    org_id = _org_id(user)
    service = VPNOrchestrationService(db)
    tunnels, total = await service.list_tunnels(
        org_id,
        status=tunnel_status,
        limit=limit,
        offset=offset,
    )
    return SiteToSiteTunnelListResponse(
        tunnels=[SiteToSiteTunnelResponse.model_validate(t) for t in tunnels],
        total=total,
    )


@router.post(
    "/tunnels",
    response_model=SiteToSiteTunnelResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_tunnel(
    body: SiteToSiteTunnelCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Create a site-to-site VPN tunnel from a template."""
    org_id = _org_id(user)
    _assert_tunnel_sites(user, body.site_a_id, body.site_b_id, detail="Site not found")
    service = VPNOrchestrationService(db)
    try:
        tunnel = await service.create_tunnel(
            org_id,
            body.template_id,
            body.site_a_id,
            body.site_b_id,
            gateway_a_device_id=body.gateway_a_device_id,
            gateway_b_device_id=body.gateway_b_device_id,
            created_by=user.id,
        )
    except ValueError as exc:
        logger.error("VPN tunnel creation failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=400, detail="VPN tunnel creation failed")
    await db.commit()
    return SiteToSiteTunnelResponse.model_validate(tunnel)


@router.post(
    "/tunnels/mesh",
    response_model=list[SiteToSiteTunnelResponse],
    status_code=status.HTTP_201_CREATED,
)
async def create_mesh(
    body: MeshTunnelCreate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Create full-mesh VPN tunnels among the provided sites."""
    org_id = _org_id(user)
    _assert_tunnel_sites(user, *body.site_ids, detail="Site not found")
    service = VPNOrchestrationService(db)
    try:
        tunnels = await service.create_mesh(
            org_id,
            body.template_id,
            body.site_ids,
            created_by=user.id,
        )
    except ValueError as exc:
        logger.error("VPN mesh creation failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=400, detail="VPN mesh creation failed")
    await db.commit()
    return [SiteToSiteTunnelResponse.model_validate(t) for t in tunnels]


@router.delete("/tunnels/{tunnel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def teardown_tunnel(
    tunnel_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> None:
    """Tear down (delete) a site-to-site VPN tunnel."""
    from sqlalchemy import select

    from app.models.vpn import SiteToSiteTunnel

    org_id = _org_id(user)
    _t = (
        await db.execute(
            select(SiteToSiteTunnel).where(
                SiteToSiteTunnel.id == tunnel_id,
                SiteToSiteTunnel.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if not _t:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    _assert_tunnel_sites(user, _t.site_a_id, _t.site_b_id)
    service = VPNOrchestrationService(db)
    deleted = await service.teardown_tunnel(tunnel_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    await db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Tunnel Detail, Actions, and Health
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/tunnels/{tunnel_id}", response_model=SiteToSiteTunnelResponse)
async def get_tunnel(
    tunnel_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Get a single site-to-site tunnel with full detail."""
    from sqlalchemy import select

    from app.models.vpn import SiteToSiteTunnel

    org_id = _org_id(user)
    result = await db.execute(
        select(SiteToSiteTunnel).where(
            SiteToSiteTunnel.id == tunnel_id,
            SiteToSiteTunnel.organization_id == org_id,
        )
    )
    tunnel = result.scalar_one_or_none()
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    _assert_tunnel_sites(user, tunnel.site_a_id, tunnel.site_b_id)
    return SiteToSiteTunnelResponse.model_validate(tunnel)


class TunnelActionRequest(BaseModel):
    action: str = Field(..., pattern=r"^(enable|disable|reprovision)$")


class TunnelActionResponse(BaseModel):
    success: bool
    message: str
    tunnel_id: str
    new_status: str
    error_message: str | None = None


@router.post("/tunnels/{tunnel_id}/action", response_model=TunnelActionResponse)
async def tunnel_action(
    tunnel_id: UUID,
    body: TunnelActionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Perform an action on a site-to-site tunnel (enable/disable/reprovision)."""
    from sqlalchemy import select

    from app.models.vpn import SiteToSiteTunnel

    org_id = _org_id(user)
    result = await db.execute(
        select(SiteToSiteTunnel).where(
            SiteToSiteTunnel.id == tunnel_id,
            SiteToSiteTunnel.organization_id == org_id,
        )
    )
    tunnel = result.scalar_one_or_none()
    if not tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    _assert_tunnel_sites(user, tunnel.site_a_id, tunnel.site_b_id)

    action = body.action
    reprovision_failed = False

    if action == "enable":
        tunnel.status = "active"
        tunnel.error_message = None
    elif action == "disable":
        tunnel.status = "disabled"
    elif action == "reprovision":
        # Re-run provisioning via the orchestration service
        tunnel.status = "provisioning"
        tunnel.error_message = None
        tunnel.provisioned_at = None
        await db.flush()
        svc = VPNOrchestrationService(db)
        try:
            await svc._reprovision_tunnel(tunnel)
        except Exception as exc:
            # Persist the error state for the tunnel, but do NOT mask the
            # failure: log it with a traceback and report success=False so the
            # client knows the reprovision did not complete.
            logger.error("VPN tunnel %s reprovision failed: %s", tunnel_id, exc, exc_info=True)
            reprovision_failed = True
            tunnel.status = "error"
            tunnel.error_message = str(exc)[:500]

    await db.commit()
    success = not reprovision_failed
    message = f"Tunnel {action} failed" if reprovision_failed else f"Tunnel {action}d"
    return TunnelActionResponse(
        success=success,
        message=message,
        tunnel_id=str(tunnel_id),
        new_status=tunnel.status,
        error_message=tunnel.error_message if reprovision_failed else None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tunnel Health History
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/tunnels/{tunnel_id}/health-history")
async def get_tunnel_health_history(
    tunnel_id: UUID,
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("vpn:read")),
) -> Any:
    """Return time-series health data for a site-to-site tunnel."""
    from datetime import timedelta

    from sqlalchemy import select, text

    from app.models.vpn import SiteToSiteTunnel

    org_id = _org_id(user)
    result = await db.execute(
        select(SiteToSiteTunnel).where(
            SiteToSiteTunnel.id == tunnel_id,
            SiteToSiteTunnel.organization_id == org_id,
        )
    )
    _tunnel = result.scalar_one_or_none()
    if not _tunnel:
        raise HTTPException(status_code=404, detail="Tunnel not found")
    _assert_tunnel_sites(user, _tunnel.site_a_id, _tunnel.site_b_id)

    from datetime import datetime

    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    rows = await db.execute(
        text("""
            SELECT time, is_healthy, latency_ms, status, error_message, rx_bytes, tx_bytes, peer_count
            FROM vpn.vpn_health_checks
            WHERE tunnel_id = :tunnel_id AND time >= :cutoff
            ORDER BY time DESC
            LIMIT :limit
        """),
        {"tunnel_id": tunnel_id, "cutoff": cutoff, "limit": limit},
    )
    return [dict(r._mapping) for r in rows.fetchall()]


# ─────────────────────────────────────────────────────────────────────────────
# Template Update (MTU/MSS Tuning)
# ─────────────────────────────────────────────────────────────────────────────


class VPNTunnelTemplateUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    config_template: dict[str, Any] | None = None
    default_subnets: list[Any] | None = None
    mtu: int | None = Field(default=None, ge=576, le=9000)
    mss_clamp: int | None = Field(default=None, ge=536, le=8960)

    @field_validator("config_template", mode="before")
    @classmethod
    def validate_config_size(cls, v: Any) -> Any:
        import json

        if v and len(json.dumps(v)) > 65536:
            raise ValueError("config_template too large (max 64KB)")
        return v

    @field_validator("default_subnets", mode="before")
    @classmethod
    def validate_subnets_size(cls, v: Any) -> Any:
        import json

        if v and len(json.dumps(v)) > 65536:
            raise ValueError("default_subnets too large (max 64KB)")
        return v


@router.put("/templates/{template_id}", response_model=VPNTunnelTemplateResponse)
async def update_template(
    template_id: UUID,
    body: VPNTunnelTemplateUpdate,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("vpn:write")),
) -> Any:
    """Update a VPN tunnel template (name, config, MTU/MSS settings)."""
    from sqlalchemy import select

    from app.models.vpn import VPNTunnelTemplate

    org_id = _org_id(user)
    result = await db.execute(
        select(VPNTunnelTemplate).where(
            VPNTunnelTemplate.id == template_id,
            VPNTunnelTemplate.organization_id == org_id,
            VPNTunnelTemplate.deleted_at.is_(None),
        )
    )
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    updates = body.model_dump(exclude_none=True)
    for key, value in updates.items():
        setattr(template, key, value)

    await db.commit()
    await db.refresh(template)
    return VPNTunnelTemplateResponse.model_validate(template)

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - DPI / Traffic Analytics Endpoints
===============================================

REST endpoints for Deep Packet Inspection analytics:
- Application traffic summary and breakdown
- Per-app time-series trends
- Per-client application usage
- Custom classification rule management
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_active_user, get_session
from app.core.site_access import site_ids_for_request
from app.models import UserRole
from app.modules.collector.models import (
    ApplicationClassificationRule,
    FlowRecord,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _org_id(user: Any) -> Any:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _flow_site_scope(user: Any) -> Any | None:
    """Per-user site-grant predicate for ``FlowRecord``.

    ``FlowRecord`` carries no ``site_id`` of its own — its site dimension is the
    owning ``Device.site_id``. For a site-limited operator, restrict to flows
    whose ``device_id`` belongs to a granted site (fail-closed empty IN when the
    grant set is empty). Returns ``None`` (no extra filter) for super_admin /
    org_admin and grant-less users so the org-only scope is preserved.
    """
    site_ids = site_ids_for_request(user)
    if site_ids is None:
        return None
    from app.models.devices import Device

    granted_devices = select(Device.id).where(Device.site_id.in_(list(site_ids)))
    return FlowRecord.device_id.in_(granted_devices)


def _require_admin(user: Any) -> None:
    # Scope ceiling: a scoped API key must not satisfy this role-only gate via
    # its owner's raw role (matches firmware/ztp/radius; scope-ceiling class).
    if getattr(user, "is_scoped", False):
        raise HTTPException(403, detail="Scoped API keys cannot satisfy role-based gates")
    if getattr(user, "role", None) not in (UserRole.ORG_ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(403, detail="Admin access required")


# =========================================================================
# Schemas
# =========================================================================


class DPIRuleCreate(BaseModel):
    name: str = Field(..., max_length=100)
    app_category: str = Field(
        ...,
        pattern=r"^(web|streaming|conferencing|email|file_transfer|vpn_tunnel|dns|database|gaming|social|infrastructure|security|iot|voip|other)$",
    )
    protocol: int | None = Field(None, ge=0, le=255)
    port: int | None = Field(None, ge=1, le=65535)
    port_range_start: int | None = Field(None, ge=1, le=65535)
    port_range_end: int | None = Field(None, ge=1, le=65535)
    dest_ip_pattern: str | None = Field(None, max_length=255)
    priority: int = Field(100, ge=1, le=1000)
    enabled: bool = True

    @field_validator("dest_ip_pattern")
    @classmethod
    def validate_ip_pattern(cls, v: Any) -> Any:
        if v is not None:
            import ipaddress

            v = v.strip()
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError:
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    raise ValueError("dest_ip_pattern must be a valid IP address or CIDR notation")
        return v

    @model_validator(mode="after")
    def validate_port_range(self) -> "DPIRuleCreate":
        if self.port_range_start is not None and self.port_range_end is not None:
            if self.port_range_end < self.port_range_start:
                raise ValueError("port_range_end must be >= port_range_start")
            if (self.port_range_end - self.port_range_start + 1) > 1000:
                raise ValueError("Port range must not exceed 1000 ports")
        return self


class DPIRuleUpdate(BaseModel):
    name: str | None = Field(None, max_length=100)
    app_category: str | None = Field(
        None,
        pattern=r"^(web|streaming|conferencing|email|file_transfer|vpn_tunnel|dns|database|gaming|social|infrastructure|security|iot|voip|other)$",
    )
    protocol: int | None = Field(None, ge=0, le=255)
    port: int | None = Field(None, ge=1, le=65535)
    port_range_start: int | None = Field(None, ge=1, le=65535)
    port_range_end: int | None = Field(None, ge=1, le=65535)
    dest_ip_pattern: str | None = None
    priority: int | None = Field(None, ge=1, le=1000)
    enabled: bool | None = None

    @field_validator("dest_ip_pattern")
    @classmethod
    def validate_ip_pattern(cls, v: Any) -> Any:
        if v is not None:
            import ipaddress

            v = v.strip()
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError:
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    raise ValueError("dest_ip_pattern must be a valid IP address or CIDR notation")
        return v

    @model_validator(mode="after")
    def validate_port_range(self) -> "DPIRuleUpdate":
        if self.port_range_start is not None and self.port_range_end is not None:
            if self.port_range_end < self.port_range_start:
                raise ValueError("port_range_end must be >= port_range_start")
            if (self.port_range_end - self.port_range_start + 1) > 1000:
                raise ValueError("Port range must not exceed 1000 ports")
        return self


# =========================================================================
# Analytics Endpoints
# =========================================================================


@router.get("/summary")
async def dpi_summary(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Top applications by total bandwidth over the given time window."""
    org_id = _org_id(user)
    since = datetime.now(UTC) - timedelta(hours=hours)

    conditions = [
        FlowRecord.organization_id == org_id,
        FlowRecord.bucket_time >= since,
        FlowRecord.app_name.isnot(None),
    ]
    site_scope = _flow_site_scope(user)
    if site_scope is not None:
        conditions.append(site_scope)

    result = await session.execute(
        select(
            FlowRecord.app_name,
            FlowRecord.app_category,
            func.sum(FlowRecord.bytes_in + FlowRecord.bytes_out).label("total_bytes"),
            func.sum(FlowRecord.packets).label("total_packets"),
            func.count().label("flow_count"),
        )
        .where(*conditions)
        .group_by(FlowRecord.app_name, FlowRecord.app_category)
        .order_by(desc("total_bytes"))
        .limit(limit)
    )
    rows = result.all()

    return {
        "period_hours": hours,
        "items": [
            {
                "app_name": row.app_name,
                "app_category": row.app_category,
                "total_bytes": row.total_bytes,
                "total_packets": row.total_packets,
                "flow_count": row.flow_count,
            }
            for row in rows
        ],
    }


@router.get("/app-breakdown")
async def app_breakdown(
    hours: int = Query(24, ge=1, le=168),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Per-category bandwidth breakdown."""
    org_id = _org_id(user)
    since = datetime.now(UTC) - timedelta(hours=hours)

    conditions = [
        FlowRecord.organization_id == org_id,
        FlowRecord.bucket_time >= since,
        FlowRecord.app_category.isnot(None),
    ]
    site_scope = _flow_site_scope(user)
    if site_scope is not None:
        conditions.append(site_scope)

    result = await session.execute(
        select(
            FlowRecord.app_category,
            func.sum(FlowRecord.bytes_in + FlowRecord.bytes_out).label("total_bytes"),
            func.count(func.distinct(FlowRecord.app_name)).label("app_count"),
        )
        .where(*conditions)
        .group_by(FlowRecord.app_category)
        .order_by(desc("total_bytes"))
    )
    rows = result.all()

    # Also get total for percentage calculation
    total = sum(r.total_bytes or 0 for r in rows)

    return {
        "period_hours": hours,
        "total_bytes": total,
        "categories": [
            {
                "category": row.app_category,
                "total_bytes": row.total_bytes,
                "percentage": round((row.total_bytes / total * 100) if total else 0, 1),
                "app_count": row.app_count,
            }
            for row in rows
        ],
    }


@router.get("/app-trends")
async def app_trends(
    app: str = Query(..., description="Application name to track"),
    hours: int = Query(24, ge=1, le=168),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Time-series bandwidth for a specific application."""
    org_id = _org_id(user)
    since = datetime.now(UTC) - timedelta(hours=hours)

    conditions = [
        FlowRecord.organization_id == org_id,
        FlowRecord.bucket_time >= since,
        FlowRecord.app_name == app,
    ]
    site_scope = _flow_site_scope(user)
    if site_scope is not None:
        conditions.append(site_scope)

    # Truncate bucket_time to hour for time-series
    hour_trunc = func.date_trunc("hour", FlowRecord.bucket_time)
    result = await session.execute(
        select(
            hour_trunc.label("hour"),
            func.sum(FlowRecord.bytes_in + FlowRecord.bytes_out).label("total_bytes"),
            func.sum(FlowRecord.packets).label("total_packets"),
        )
        .where(*conditions)
        .group_by("hour")
        .order_by("hour")
    )
    rows = result.all()

    return {
        "app_name": app,
        "period_hours": hours,
        "data_points": [
            {
                "time": row.hour.isoformat() if row.hour else None,
                "total_bytes": row.total_bytes,
                "total_packets": row.total_packets,
            }
            for row in rows
        ],
    }


@router.get("/client/{device_id}")
async def client_dpi(
    device_id: UUID,
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Per-client (device) application usage."""
    org_id = _org_id(user)
    since = datetime.now(UTC) - timedelta(hours=hours)

    # Per-user site grant: a site-limited operator must not read DPI for a
    # device in a sibling site. ``FlowRecord`` has no ``site_id``; resolve the
    # device's owning site and assert (404 — no existence oracle). No-op for
    # super_admin / org_admin.
    from app.core.site_access import assert_can_access_site
    from app.models.core import Site
    from app.models.devices import Device

    dev_res = await session.execute(
        select(Device.site_id)
        .join(Site, Device.site_id == Site.id)
        .where(Device.id == device_id, Site.organization_id == org_id)
    )
    dev_site_id = dev_res.scalar_one_or_none()
    if dev_site_id is None:
        # Unknown / cross-org device id — fall through to org-scoped flow query,
        # which returns an empty series (no leak, no oracle change).
        pass
    else:
        assert_can_access_site(user, dev_site_id, detail="Device not found")

    result = await session.execute(
        select(
            FlowRecord.app_name,
            FlowRecord.app_category,
            func.sum(FlowRecord.bytes_in + FlowRecord.bytes_out).label("total_bytes"),
            func.sum(FlowRecord.packets).label("total_packets"),
        )
        .where(
            FlowRecord.organization_id == org_id,
            FlowRecord.device_id == device_id,
            FlowRecord.bucket_time >= since,
            FlowRecord.app_name.isnot(None),
        )
        .group_by(FlowRecord.app_name, FlowRecord.app_category)
        .order_by(desc("total_bytes"))
        .limit(limit)
    )
    rows = result.all()

    return {
        "device_id": str(device_id),
        "period_hours": hours,
        "items": [
            {
                "app_name": row.app_name,
                "app_category": row.app_category,
                "total_bytes": row.total_bytes,
                "total_packets": row.total_packets,
            }
            for row in rows
        ],
    }


# =========================================================================
# Classification Rules CRUD
# =========================================================================


@router.get("/rules")
async def list_rules(
    system_only: bool = False,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """List classification rules (system + org-specific)."""
    org_id = _org_id(user)

    query = select(ApplicationClassificationRule).where(
        ApplicationClassificationRule.enabled,
    )
    if system_only:
        query = query.where(ApplicationClassificationRule.is_system)
    else:
        query = query.where(
            (ApplicationClassificationRule.organization_id == org_id)
            | (ApplicationClassificationRule.is_system)
        )

    # Total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_query)).scalar() or 0

    offset = (page - 1) * page_size
    query = (
        query.order_by(ApplicationClassificationRule.priority.asc()).offset(offset).limit(page_size)
    )
    result = await session.execute(query)
    rules = result.scalars().all()

    return {
        "items": [_rule_to_dict(r) for r in rules],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/rules", status_code=201)
async def create_rule(
    data: DPIRuleCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Create a custom classification rule."""
    _require_admin(user)
    org_id = _org_id(user)

    rule = ApplicationClassificationRule(
        organization_id=org_id,
        is_system=False,
        **data.model_dump(exclude={"organization_id", "is_system"}),
    )
    session.add(rule)
    await session.flush()
    await session.refresh(rule)
    response = _rule_to_dict(rule)
    await session.commit()
    return response


@router.put("/rules/{rule_id}")
async def update_rule(
    rule_id: UUID,
    data: DPIRuleUpdate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> Any:
    """Update a custom classification rule."""
    _require_admin(user)
    org_id = _org_id(user)

    result = await session.execute(
        select(ApplicationClassificationRule).where(
            ApplicationClassificationRule.id == rule_id,
            ApplicationClassificationRule.organization_id == org_id,
            ApplicationClassificationRule.is_system.is_(False),
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found (only custom rules can be edited)")

    _ALLOWED_RULE_FIELDS = {
        "name",
        "app_category",
        "protocol",
        "port",
        "port_range_start",
        "port_range_end",
        "dest_ip_pattern",
        "priority",
        "enabled",
    }
    for field, value in data.model_dump(exclude_unset=True).items():
        if field in _ALLOWED_RULE_FIELDS:
            setattr(rule, field, value)
    await session.flush()
    await session.refresh(rule)
    response = _rule_to_dict(rule)
    await session.commit()
    return response


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    """Delete a custom classification rule."""
    _require_admin(user)
    org_id = _org_id(user)

    result = await session.execute(
        select(ApplicationClassificationRule).where(
            ApplicationClassificationRule.id == rule_id,
            ApplicationClassificationRule.organization_id == org_id,
            ApplicationClassificationRule.is_system.is_(False),
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found (system rules cannot be deleted)")

    await session.delete(rule)
    await session.flush()
    await session.commit()


# =========================================================================
# Helpers
# =========================================================================


def _rule_to_dict(r: ApplicationClassificationRule) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "name": r.name,
        "app_category": r.app_category,
        "protocol": r.protocol,
        "port": r.port,
        "port_range_start": r.port_range_start,
        "port_range_end": r.port_range_end,
        "dest_ip_pattern": r.dest_ip_pattern,
        "is_system": r.is_system,
        "priority": r.priority,
        "enabled": r.enabled,
        "organization_id": str(r.organization_id) if r.organization_id else None,
    }

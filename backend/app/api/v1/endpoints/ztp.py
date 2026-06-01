# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - ZTP & Provisioning Endpoints
==========================================

REST endpoints for Zero-Touch Provisioning:
- Auto-adoption rules
- MAC pre-registrations
- Adoption jobs
- Provisioning profiles
"""

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import get_current_active_user, get_session
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.models import UserRole
from app.models.ztp import (
    AdoptionJob,
    AdoptionJobStatus,
    AdoptionTrigger,
    AutoAdoptionRule,
    MACPreRegistration,
    ProvisioningProfile,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _org_id(user: Any) -> UUID:
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _require_admin(user: Any) -> None:
    # Scope ceiling: a scoped API key must not satisfy this role-only admin gate
    # via its owner's raw role.
    if getattr(user, "is_scoped", False):
        raise HTTPException(403, detail="Scoped API keys cannot satisfy role-based gates")
    if getattr(user, "role", None) not in (UserRole.ORG_ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(403, detail="Admin access required")


def _validate_site_grant(user: Any, site_id: UUID | None, *, detail: str = "Not found") -> None:
    """Per-user site-grant guard.

    No-op for super_admin / org_admin and for a ``None`` site_id; raises 404 for
    a site-limited user lacking the grant. Wraps the canonical
    ``assert_can_access_site`` so ZTP FK/site references are uniformly guarded.
    """
    assert_can_access_site(user, site_id, detail=detail)


def _nullable_site_scope(user: Any, site_id_column: Any) -> Any:
    """Site-grant predicate for a list query over a NULLABLE site column.

    For a site-limited caller, a row leaks only when its site dimension points
    at a sibling site; a NULL column is a genuinely org-wide row (no site
    targeted yet / matches any site) and stays visible. So the predicate is
    ``(col IS NULL) OR (col IN granted)``. ``site_scope_filter`` already fails
    closed (empty IN) for a grant-less site-limited user and returns ``true()``
    (no-op) for super_admin / org_admin / non-site-limited users — in which case
    this whole predicate collapses to a no-op.
    """
    base = site_scope_filter(user, site_id_column)
    if getattr(user, "is_site_limited", False):
        return or_(site_id_column.is_(None), base)
    return base


# =========================================================================
# Schemas
# =========================================================================


class AdoptionRuleCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = None
    priority: int = Field(100, ge=1, le=10000)
    enabled: bool = True
    match_device_type: str | None = None
    match_manufacturer: str | None = None
    match_model_pattern: str | None = Field(None, max_length=255)
    match_controller_id: UUID | None = None
    match_site_id: UUID | None = None
    target_site_id: UUID | None = None
    provisioning_profile_id: UUID | None = None
    auto_firmware_update: bool = False


class AdoptionRuleUpdate(BaseModel):
    name: str | None = Field(None, max_length=255)
    description: str | None = None
    priority: int | None = Field(None, ge=1, le=10000)
    enabled: bool | None = None
    match_device_type: str | None = None
    match_manufacturer: str | None = None
    match_model_pattern: str | None = Field(None, max_length=255)
    match_controller_id: UUID | None = None
    match_site_id: UUID | None = None
    target_site_id: UUID | None = None
    provisioning_profile_id: UUID | None = None
    auto_firmware_update: bool | None = None


class MACPreRegCreate(BaseModel):
    mac_address: str = Field(..., pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    device_name: str | None = None
    target_site_id: UUID | None = None
    provisioning_profile_id: UUID | None = None


class MACPreRegBulk(BaseModel):
    registrations: list[MACPreRegCreate] = Field(..., max_length=1000)


class ProfileCreate(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = None
    device_type: str
    manufacturer: str | None = None
    config_payload: dict = Field(default_factory=dict)
    config_template_id: UUID | None = None
    auto_firmware_update: bool = True
    target_firmware_version: str | None = None
    is_default: bool = False

    @field_validator("config_payload", mode="before")
    @classmethod
    def validate_config_size(cls, v: Any) -> dict[str, Any]:
        import json

        if v and len(json.dumps(v)) > 65536:
            raise ValueError("Config payload too large (max 64KB)")
        return v


class ProfileUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    device_type: str | None = None
    manufacturer: str | None = None
    config_payload: dict | None = None
    config_template_id: UUID | None = None
    auto_firmware_update: bool | None = None
    target_firmware_version: str | None = None
    is_default: bool | None = None

    @field_validator("config_payload", mode="before")
    @classmethod
    def validate_config_size(cls, v: Any) -> dict[str, Any]:
        import json

        if v and len(json.dumps(v)) > 65536:
            raise ValueError("Config payload too large (max 64KB)")
        return v


# =========================================================================
# Auto-Adoption Rules
# =========================================================================


@router.get("/rules")
async def list_rules(
    enabled: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """List auto-adoption rules ordered by priority."""
    org_id = _org_id(user)
    # Per-user site grant: a site-limited operator must not see a
    # rule whose match/target site dimension points at a sibling site. Both site
    # columns are nullable (NULL = org-wide, matches any site) so each is scoped
    # independently; no-op for super_admin / org_admin / non-site-limited users.
    query = (
        select(AutoAdoptionRule)
        .where(
            AutoAdoptionRule.organization_id == org_id,
            _nullable_site_scope(user, AutoAdoptionRule.match_site_id),
            _nullable_site_scope(user, AutoAdoptionRule.target_site_id),
        )
        .order_by(AutoAdoptionRule.priority.asc())
    )

    if enabled is not None:
        query = query.where(AutoAdoptionRule.enabled == enabled)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_q)).scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
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
    data: AdoptionRuleCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Create a new auto-adoption rule."""
    _require_admin(user)
    org_id = _org_id(user)

    # Validate FK references belong to this organization
    if data.provisioning_profile_id:
        prof_result = await session.execute(
            select(ProvisioningProfile).where(
                ProvisioningProfile.id == data.provisioning_profile_id,
                ProvisioningProfile.organization_id == org_id,
                ProvisioningProfile.deleted_at.is_(None),
            )
        )
        if not prof_result.scalar_one_or_none():
            raise HTTPException(404, detail="Provisioning profile not found")

    if data.target_site_id:
        from app.models.core import Site

        site_result = await session.execute(
            select(Site).where(
                Site.id == data.target_site_id,
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
            )
        )
        if not site_result.scalar_one_or_none():
            raise HTTPException(404, detail="Target site not found")
        _validate_site_grant(user, data.target_site_id, detail="Target site not found")

    if data.match_controller_id:
        from app.models.core import Controller

        ctrl_res = await session.execute(
            select(Controller)
            .join(Site, Controller.site_id == Site.id)
            .where(
                Controller.id == data.match_controller_id,
                Site.organization_id == org_id,
            )
        )
        if not ctrl_res.scalar_one_or_none():
            raise HTTPException(404, detail="Match controller not found")

    if data.match_site_id:
        ms_res = await session.execute(
            select(Site).where(
                Site.id == data.match_site_id,
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
            )
        )
        if not ms_res.scalar_one_or_none():
            raise HTTPException(404, detail="Match site not found")
        _validate_site_grant(user, data.match_site_id, detail="Match site not found")

    rule = AutoAdoptionRule(
        organization_id=org_id,
        **data.model_dump(),
    )
    session.add(rule)
    await session.commit()
    await session.refresh(rule)
    return _rule_to_dict(rule)


@router.put("/rules/{rule_id}")
async def update_rule(
    rule_id: UUID,
    data: AdoptionRuleUpdate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Update an auto-adoption rule."""
    _require_admin(user)
    org_id = _org_id(user)

    rule = await _get_rule(rule_id, org_id, session)

    updates = data.model_dump(exclude_unset=True)
    # Validate FK refs if provided
    if updates.get("target_site_id") or updates.get("provisioning_profile_id"):
        await _validate_fk_refs(
            updates.get("target_site_id"),
            updates.get("provisioning_profile_id"),
            org_id,
            session,
            user=user,
        )
    if updates.get("match_site_id"):
        from app.models.core import Site

        site_res = await session.execute(
            select(Site).where(
                Site.id == updates["match_site_id"],
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
            )
        )
        if not site_res.scalar_one_or_none():
            raise HTTPException(404, detail="Match site not found")
        _validate_site_grant(user, updates["match_site_id"], detail="Match site not found")
    if updates.get("match_controller_id"):
        from app.models.core import Controller
        from app.models.core import Site as SiteModel

        ctrl_res = await session.execute(
            select(Controller)
            .join(SiteModel, Controller.site_id == SiteModel.id)
            .where(
                Controller.id == updates["match_controller_id"],
                SiteModel.organization_id == org_id,
            )
        )
        if not ctrl_res.scalar_one_or_none():
            raise HTTPException(404, detail="Match controller not found")

    for field, value in updates.items():
        setattr(rule, field, value)

    await session.commit()
    await session.refresh(rule)
    return _rule_to_dict(rule)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    """Delete an auto-adoption rule."""
    _require_admin(user)
    org_id = _org_id(user)
    rule = await _get_rule(rule_id, org_id, session)
    await session.delete(rule)
    await session.commit()


# =========================================================================
# MAC Pre-Registrations
# =========================================================================


@router.get("/pre-registrations")
async def list_pre_registrations(
    adopted: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """List MAC pre-registrations."""
    org_id = _org_id(user)
    # Per-user site grant: a site-limited operator must not see a
    # pre-registration (MAC, device name, target site) bound to a sibling site.
    # target_site_id is nullable (NULL = no site yet) so it stays visible.
    query = (
        select(MACPreRegistration)
        .where(
            MACPreRegistration.organization_id == org_id,
            _nullable_site_scope(user, MACPreRegistration.target_site_id),
        )
        .order_by(MACPreRegistration.created_at.desc())
    )

    if adopted is not None:
        query = query.where(MACPreRegistration.adopted == adopted)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_q)).scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await session.execute(query)
    regs = result.scalars().all()

    return {
        "items": [_prereg_to_dict(r) for r in regs],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/pre-registrations", status_code=201)
async def create_pre_registration(
    data: MACPreRegCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Pre-register a MAC address for instant adoption."""
    _require_admin(user)
    org_id = _org_id(user)

    # Normalize MAC
    mac = data.mac_address.upper()

    # Check for duplicate within this organization
    existing = await session.execute(
        select(MACPreRegistration).where(
            MACPreRegistration.mac_address == mac,
            MACPreRegistration.organization_id == org_id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(409, detail="MAC address already registered")

    # Validate FK references belong to this organization
    await _validate_fk_refs(
        data.target_site_id, data.provisioning_profile_id, org_id, session, user=user
    )

    prereg = MACPreRegistration(
        organization_id=org_id,
        mac_address=mac,
        device_name=data.device_name,
        target_site_id=data.target_site_id,
        provisioning_profile_id=data.provisioning_profile_id,
    )
    session.add(prereg)
    await session.commit()
    await session.refresh(prereg)
    return _prereg_to_dict(prereg)


@router.post("/pre-registrations/bulk", status_code=201)
async def bulk_pre_register(
    data: MACPreRegBulk,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Bulk pre-register MAC addresses."""
    _require_admin(user)
    org_id = _org_id(user)

    # Validate FK references for all unique site/profile IDs in the batch
    all_site_ids = {r.target_site_id for r in data.registrations if r.target_site_id}
    all_profile_ids = {
        r.provisioning_profile_id for r in data.registrations if r.provisioning_profile_id
    }
    for sid in all_site_ids:
        await _validate_fk_refs(sid, None, org_id, session, user=user)
    for pid in all_profile_ids:
        await _validate_fk_refs(None, pid, org_id, session, user=user)

    # Batch query: fetch all existing MACs for this org in one query
    all_macs = [reg.mac_address.upper() for reg in data.registrations]
    existing_result = await session.execute(
        select(MACPreRegistration.mac_address).where(
            MACPreRegistration.mac_address.in_(all_macs),
            MACPreRegistration.organization_id == org_id,
        )
    )
    existing_macs = set(existing_result.scalars().all())

    created = 0
    skipped = 0
    for reg in data.registrations:
        mac = reg.mac_address.upper()
        if mac in existing_macs:
            skipped += 1
            continue

        prereg = MACPreRegistration(
            organization_id=org_id,
            mac_address=mac,
            device_name=reg.device_name,
            target_site_id=reg.target_site_id,
            provisioning_profile_id=reg.provisioning_profile_id,
        )
        session.add(prereg)
        existing_macs.add(mac)  # Prevent duplicates within the same batch
        created += 1

    await session.commit()
    return {"created": created, "skipped": skipped}


@router.delete("/pre-registrations/{prereg_id}", status_code=204)
async def delete_pre_registration(
    prereg_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    """Delete a MAC pre-registration."""
    _require_admin(user)
    org_id = _org_id(user)

    result = await session.execute(
        select(MACPreRegistration).where(
            MACPreRegistration.id == prereg_id,
            MACPreRegistration.organization_id == org_id,
        )
    )
    prereg = result.scalar_one_or_none()
    if not prereg:
        raise HTTPException(404, detail="Pre-registration not found")

    await session.delete(prereg)
    await session.commit()


# =========================================================================
# Adoption Jobs
# =========================================================================


@router.get("/jobs")
async def list_jobs(
    status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """List adoption jobs."""
    org_id = _org_id(user)
    query = (
        select(AdoptionJob)
        .where(
            AdoptionJob.organization_id == org_id,
        )
        .order_by(AdoptionJob.created_at.desc())
    )

    # Per-user site grant: an adoption job has no direct site
    # column — its site is the device's. A site-limited operator must not see
    # jobs (device name, status, error) for sibling-site devices, so restrict to
    # device_ids whose Device.site_id is granted. No-op for admins /
    # non-site-limited users (site_scope_filter returns true()).
    if getattr(user, "is_site_limited", False):
        from app.models.devices import Device

        granted_device_ids = (
            select(Device.id).where(site_scope_filter(user, Device.site_id)).scalar_subquery()
        )
        query = query.where(AdoptionJob.device_id.in_(granted_device_ids))

    if status:
        query = query.where(AdoptionJob.status == status)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_q)).scalar() or 0

    query = (
        query.options(selectinload(AdoptionJob.device))
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await session.execute(query)
    jobs = result.scalars().all()

    return {
        "items": [_job_to_dict(j) for j in jobs],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/jobs/{job_id}")
async def get_job(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Get adoption job detail with step history."""
    org_id = _org_id(user)
    result = await session.execute(
        select(AdoptionJob).where(
            AdoptionJob.id == job_id,
            AdoptionJob.organization_id == org_id,
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(404, detail="Adoption job not found")
    if job.device is not None:
        _validate_site_grant(user, job.device.site_id, detail="Adoption job not found")
    return _job_to_dict(job)


@router.post("/jobs/{job_id}/retry")
async def retry_job(
    job_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Retry a failed adoption job."""
    _require_admin(user)
    org_id = _org_id(user)

    result = await session.execute(
        select(AdoptionJob)
        .where(
            AdoptionJob.id == job_id,
            AdoptionJob.organization_id == org_id,
        )
        .with_for_update()
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(404, detail="Job not found")
    if job.status != AdoptionJobStatus.FAILED:
        raise HTTPException(400, detail="Can only retry failed jobs")
    if job.retry_count >= 5:
        raise HTTPException(400, detail="Maximum retry attempts reached")

    job.status = AdoptionJobStatus.PENDING
    job.retry_count += 1
    job.error_message = None
    job.started_at = datetime.now(UTC)
    job.completed_at = None
    await session.commit()

    try:
        from app.tasks.adoption import execute_adoption

        execute_adoption.delay(str(job.id))
    except Exception as e:
        logger.warning("Could not dispatch adoption retry task: %s", e)
        raise HTTPException(
            503, detail="Task queue unavailable; retry could not be scheduled"
        ) from e

    return {"status": "retrying", "job_id": str(job.id)}


@router.post("/adopt/{device_id}")
async def manual_adopt(
    device_id: UUID,
    profile_id: UUID | None = None,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Manually trigger adoption for a discovered device."""
    _require_admin(user)
    org_id = _org_id(user)

    from app.models.core import Site
    from app.models.devices import Device

    result = await session.execute(
        select(Device)
        .join(Site, Device.site_id == Site.id)
        .where(
            Device.id == device_id,
            Site.organization_id == org_id,
            Device.deleted_at.is_(None),
        )
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(404, detail="Device not found")
    _validate_site_grant(user, device.site_id, detail="Device not found")
    if device.is_adopted:
        raise HTTPException(400, detail="Device is already adopted")

    existing_job = await session.execute(
        select(AdoptionJob).where(
            AdoptionJob.device_id == device_id,
            AdoptionJob.organization_id == org_id,
            AdoptionJob.status.in_([AdoptionJobStatus.PENDING, AdoptionJobStatus.ADOPTING]),
        )
    )
    if existing_job.scalar_one_or_none():
        raise HTTPException(409, detail="Adoption already in progress for this device")

    # Fix 7: Validate profile_id belongs to this org
    if profile_id is not None:
        prof_result = await session.execute(
            select(ProvisioningProfile).where(
                ProvisioningProfile.id == profile_id,
                ProvisioningProfile.organization_id == org_id,
                ProvisioningProfile.deleted_at.is_(None),
            )
        )
        if not prof_result.scalar_one_or_none():
            raise HTTPException(404, detail="Provisioning profile not found")

    job = AdoptionJob(
        device_id=device.id,
        organization_id=org_id,
        status=AdoptionJobStatus.PENDING,
        current_step="validate",
        steps_completed=[],
        triggered_by=AdoptionTrigger.MANUAL,
        profile_id=profile_id,
        started_at=datetime.now(UTC),
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    try:
        from app.tasks.adoption import execute_adoption

        execute_adoption.delay(str(job.id))
    except Exception as e:
        logger.warning("Could not dispatch adoption task: %s", e)
        raise HTTPException(
            503, detail="Task queue unavailable; adoption could not be scheduled"
        ) from e

    return {"status": "started", "job_id": str(job.id)}


# =========================================================================
# Provisioning Profiles
# =========================================================================


@router.get("/profiles")
async def list_profiles(
    device_type: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """List provisioning profiles."""
    org_id = _org_id(user)
    query = (
        select(ProvisioningProfile)
        .where(
            ProvisioningProfile.organization_id == org_id,
            ProvisioningProfile.deleted_at.is_(None),
        )
        .order_by(ProvisioningProfile.name)
    )

    if device_type:
        query = query.where(ProvisioningProfile.device_type == device_type)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await session.execute(count_q)).scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await session.execute(query)
    profiles = result.scalars().all()

    return {
        "items": [_profile_to_dict(p) for p in profiles],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/profiles", status_code=201)
async def create_profile(
    data: ProfileCreate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Create a provisioning profile."""
    _require_admin(user)
    org_id = _org_id(user)

    if data.config_template_id:
        from app.models.enterprise import ConfigTemplate

        tpl_check = await session.execute(
            select(ConfigTemplate.id).where(
                ConfigTemplate.id == data.config_template_id,
                ConfigTemplate.organization_id == org_id,
            )
        )
        if not tpl_check.scalar_one_or_none():
            raise HTTPException(
                400, detail="Config template not found or does not belong to this organization"
            )

    profile = ProvisioningProfile(
        organization_id=org_id,
        **data.model_dump(),
    )
    session.add(profile)
    await session.commit()
    await session.refresh(profile)
    return _profile_to_dict(profile)


@router.put("/profiles/{profile_id}")
async def update_profile(
    profile_id: UUID,
    data: ProfileUpdate,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Update a provisioning profile."""
    _require_admin(user)
    org_id = _org_id(user)

    result = await session.execute(
        select(ProvisioningProfile).where(
            ProvisioningProfile.id == profile_id,
            ProvisioningProfile.organization_id == org_id,
            ProvisioningProfile.deleted_at.is_(None),
        )
    )
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(404, detail="Profile not found")

    if data.config_template_id:
        from app.models.enterprise import ConfigTemplate

        tpl_check = await session.execute(
            select(ConfigTemplate.id).where(
                ConfigTemplate.id == data.config_template_id,
                ConfigTemplate.organization_id == org_id,
            )
        )
        if not tpl_check.scalar_one_or_none():
            raise HTTPException(
                400, detail="Config template not found or does not belong to this organization"
            )

    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(profile, field, value)

    await session.commit()
    await session.refresh(profile)
    return _profile_to_dict(profile)


@router.delete("/profiles/{profile_id}", status_code=204)
async def delete_profile(
    profile_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> None:
    """Soft-delete a provisioning profile."""
    _require_admin(user)
    org_id = _org_id(user)

    result = await session.execute(
        select(ProvisioningProfile).where(
            ProvisioningProfile.id == profile_id,
            ProvisioningProfile.organization_id == org_id,
            ProvisioningProfile.deleted_at.is_(None),
        )
    )
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(404, detail="Profile not found")

    profile.deleted_at = datetime.now(UTC)
    await session.commit()


@router.post("/profiles/{profile_id}/apply/{device_id}")
async def apply_profile_to_device(
    profile_id: UUID,
    device_id: UUID,
    session: AsyncSession = Depends(get_session),
    user: Any = Depends(get_current_active_user),
) -> dict[str, Any]:
    """Apply a provisioning profile to an existing device."""
    _require_admin(user)
    org_id = _org_id(user)

    from app.models.core import Site
    from app.models.devices import Device
    from app.services.ztp import ProvisioningProfileService

    profile = await session.execute(
        select(ProvisioningProfile).where(
            ProvisioningProfile.id == profile_id,
            ProvisioningProfile.organization_id == org_id,
            ProvisioningProfile.deleted_at.is_(None),
        )
    )
    profile = profile.scalar_one_or_none()
    if not profile:
        raise HTTPException(404, detail="Profile not found")

    device = await session.execute(
        select(Device)
        .join(Site, Device.site_id == Site.id)
        .where(
            Device.id == device_id,
            Site.organization_id == org_id,
            Device.deleted_at.is_(None),
        )
    )
    device = device.scalar_one_or_none()
    if not device:
        raise HTTPException(404, detail="Device not found")
    # Per-user site grant: a site-limited operator must not apply a profile to a
    # device in a sibling site (no-op for super_admin / org_admin).
    _validate_site_grant(user, device.site_id, detail="Device not found")

    svc = ProvisioningProfileService(session)
    result = await svc.apply_profile(device, profile)
    await session.commit()

    if not result.get("success"):
        raise HTTPException(400, detail=result.get("error", "Failed to apply profile"))

    return result


# =========================================================================
# Helpers
# =========================================================================


async def _get_rule(rule_id: UUID, org_id: UUID, session: AsyncSession) -> AutoAdoptionRule:
    result = await session.execute(
        select(AutoAdoptionRule).where(
            AutoAdoptionRule.id == rule_id,
            AutoAdoptionRule.organization_id == org_id,
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Adoption rule not found")
    return rule


async def _validate_fk_refs(
    target_site_id: UUID | None,
    provisioning_profile_id: UUID | None,
    org_id: UUID,
    session: AsyncSession,
    user: Any = None,
) -> None:
    """Validate that target_site_id and provisioning_profile_id belong to the org.

    When ``user`` is provided, also enforces the per-user site grant on
    ``target_site_id`` so a site-limited caller cannot reference
    a sibling-site FK.
    """
    if target_site_id:
        from app.models.core import Site

        site_result = await session.execute(
            select(Site).where(
                Site.id == target_site_id,
                Site.organization_id == org_id,
                Site.deleted_at.is_(None),
            )
        )
        if not site_result.scalar_one_or_none():
            raise HTTPException(404, detail="Target site not found")
        if user is not None:
            _validate_site_grant(user, target_site_id, detail="Target site not found")

    if provisioning_profile_id:
        prof_result = await session.execute(
            select(ProvisioningProfile).where(
                ProvisioningProfile.id == provisioning_profile_id,
                ProvisioningProfile.organization_id == org_id,
                ProvisioningProfile.deleted_at.is_(None),
            )
        )
        if not prof_result.scalar_one_or_none():
            raise HTTPException(404, detail="Provisioning profile not found")


def _rule_to_dict(r: AutoAdoptionRule) -> dict:
    return {
        "id": str(r.id),
        "name": r.name,
        "description": r.description,
        "priority": r.priority,
        "enabled": r.enabled,
        "match_device_type": r.match_device_type,
        "match_manufacturer": r.match_manufacturer,
        "match_model_pattern": r.match_model_pattern,
        "match_controller_id": str(r.match_controller_id) if r.match_controller_id else None,
        "match_site_id": str(r.match_site_id) if r.match_site_id else None,
        "target_site_id": str(r.target_site_id) if r.target_site_id else None,
        "provisioning_profile_id": str(r.provisioning_profile_id)
        if r.provisioning_profile_id
        else None,
        "auto_firmware_update": r.auto_firmware_update,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }


def _prereg_to_dict(r: MACPreRegistration) -> dict:
    return {
        "id": str(r.id),
        "mac_address": r.mac_address,
        "device_name": r.device_name,
        "target_site_id": str(r.target_site_id) if r.target_site_id else None,
        "provisioning_profile_id": str(r.provisioning_profile_id)
        if r.provisioning_profile_id
        else None,
        "adopted": r.adopted,
        "adopted_at": r.adopted_at.isoformat() if r.adopted_at else None,
        "adopted_device_id": str(r.adopted_device_id) if r.adopted_device_id else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _job_to_dict(j: AdoptionJob) -> dict:
    return {
        "id": str(j.id),
        "device_id": str(j.device_id),
        "device_name": j.device.name if j.device else None,
        "status": j.status,
        "current_step": j.current_step,
        "steps_completed": j.steps_completed,
        "error_message": j.error_message,
        "retry_count": j.retry_count,
        "triggered_by": j.triggered_by,
        "rule_id": str(j.rule_id) if j.rule_id else None,
        "profile_id": str(j.profile_id) if j.profile_id else None,
        "started_at": j.started_at.isoformat() if j.started_at else None,
        "completed_at": j.completed_at.isoformat() if j.completed_at else None,
        "created_at": j.created_at.isoformat() if j.created_at else None,
    }


def _profile_to_dict(p: ProvisioningProfile) -> dict:
    return {
        "id": str(p.id),
        "name": p.name,
        "description": p.description,
        "device_type": p.device_type,
        "manufacturer": p.manufacturer,
        "config_payload": p.config_payload,
        "config_template_id": str(p.config_template_id) if p.config_template_id else None,
        "auto_firmware_update": p.auto_firmware_update,
        "target_firmware_version": p.target_firmware_version,
        "is_default": p.is_default,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }

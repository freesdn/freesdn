# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Module API Endpoints
==================================

API endpoints for managing modules:
- List available modules
- Enable/disable modules for organizations
- Manage module settings
- Get navigation and widgets
"""

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user, get_db
from app.core.dependencies import (
    is_unscoped_org_admin,
    is_unscoped_superuser,
    org_scope_or_platform,
)
from app.models.core import User
from app.modules.registry import module_registry
from app.modules.schemas import (
    FeatureFlagRead,
    FeatureFlagsResponse,
    FeatureFlagUpdate,
    ModuleEventRead,
    ModuleEventsResponse,
    ModuleListResponse,
    ModuleManifestResponse,
    ModuleStateResponse,
    NavigationResponse,
    OrgModuleDisable,
    OrgModuleEnable,
    OrgModuleListResponse,
    OrgModuleRead,
    OrgModuleSettingsUpdate,
    WidgetsResponse,
)
from app.modules.service import ModuleService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/modules", tags=["Modules"])


# ─── Helpers ──────────────────────────────────────────────────


def _verify_org_access(
    current_user: User,
    organization_id: UUID,
    *,
    require_admin: bool = False,
) -> None:
    """Ensure the user can access the given organization.

    Super-admins bypass all checks.
    Regular users must belong to the organization.
    If require_admin is True, the user must also be an org admin or super admin.
    """
    if is_unscoped_superuser(current_user):  # scope-aware
        return

    if current_user.organization_id != organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization",
        )

    if require_admin and not is_unscoped_org_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to manage modules",
        )


# ==========================================
# Module Discovery
# ==========================================


@router.get(
    "",
    response_model=ModuleListResponse,
    summary="List all available modules",
)
async def list_modules(
    current_user: Annotated[User, Depends(get_current_user)],
) -> ModuleListResponse:
    """
    Get a list of all available modules in the system.

    Returns manifests for all registered modules.
    """
    manifests = module_registry.get_all_manifests()

    return ModuleListResponse(
        modules=[ModuleManifestResponse(**m.to_dict()) for m in manifests],
        total=len(manifests),
    )


@router.get(
    "/states",
    response_model=list[ModuleStateResponse],
    summary="Get module states",
)
async def get_module_states(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[ModuleStateResponse]:
    """
    Get the current state of all modules.

    Shows loading status and any errors.
    """
    states = []
    for module in module_registry.modules.values():
        states.append(
            ModuleStateResponse(
                id=module.id,
                name=module.name,
                version=module.manifest.version,
                state=module.state,
                error=module.error,
            )
        )
    return states


@router.get(
    "/{module_id}",
    response_model=ModuleManifestResponse,
    summary="Get module details",
)
async def get_module(
    module_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> ModuleManifestResponse:
    """
    Get detailed information about a specific module.
    """
    try:
        manifest = module_registry.get_manifest(module_id)
        return ModuleManifestResponse(**manifest.to_dict())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Module '{module_id}' not found",
        )


# ==========================================
# Organization Module Management
# ==========================================


@router.get(
    "/org/{organization_id}",
    response_model=OrgModuleListResponse,
    summary="List modules for organization",
)
async def list_org_modules(
    organization_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    include_disabled: bool = Query(False, description="Include disabled modules"),
) -> OrgModuleListResponse:
    """
    Get all modules for an organization with their enablement status.
    """
    _verify_org_access(current_user, organization_id)

    service = ModuleService(db)
    org_modules = await service.get_org_modules(organization_id, include_disabled)

    # Build response with manifest info (skip modules no longer in registry)
    modules = []
    for om in org_modules:
        manifest = module_registry.get_module_or_none(om.module_id)
        if manifest is None:
            # Module was removed/merged — skip stale DB rows
            continue
        modules.append(
            OrgModuleRead(
                module_id=om.module_id,
                is_enabled=om.is_enabled,
                enabled_at=om.enabled_at,
                disabled_at=om.disabled_at,
                settings=om.settings,
                manifest=ModuleManifestResponse(**manifest.manifest.to_dict()),
            )
        )

    # Add available but not-enabled modules
    if include_disabled:
        enabled_ids = {m.module_id for m in modules}
        for module in module_registry.modules.values():
            if module.id not in enabled_ids:
                modules.append(
                    OrgModuleRead(
                        module_id=module.id,
                        is_enabled=False,
                        manifest=ModuleManifestResponse(**module.manifest.to_dict()),
                    )
                )

    return OrgModuleListResponse(modules=modules, total=len(modules))


@router.post(
    "/org/{organization_id}/enable",
    response_model=OrgModuleRead,
    summary="Enable a module",
)
async def enable_module(
    organization_id: UUID,
    data: OrgModuleEnable,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> OrgModuleRead:
    """
    Enable a module for an organization.

    Optionally provide initial settings.
    """
    _verify_org_access(current_user, organization_id, require_admin=True)

    service = ModuleService(db)

    try:
        org_module = await service.enable_module(
            organization_id=organization_id,
            module_id=data.module_id,
            settings=data.settings,
            user_id=current_user.id,
        )

        manifest = module_registry.get_module_or_none(data.module_id)

        return OrgModuleRead(
            module_id=org_module.module_id,
            is_enabled=org_module.is_enabled,
            enabled_at=org_module.enabled_at,
            disabled_at=org_module.disabled_at,
            settings=org_module.settings,
            manifest=ModuleManifestResponse(**manifest.manifest.to_dict()) if manifest else None,
        )

    except Exception as e:
        logger.error("Failed to enable module: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to enable module",
        )


@router.post(
    "/org/{organization_id}/disable",
    response_model=OrgModuleRead,
    summary="Disable a module",
)
async def disable_module(
    organization_id: UUID,
    data: OrgModuleDisable,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> OrgModuleRead:
    """
    Disable a module for an organization.

    Cannot disable core modules.
    """
    _verify_org_access(current_user, organization_id, require_admin=True)
    service = ModuleService(db)

    try:
        org_module = await service.disable_module(
            organization_id=organization_id,
            module_id=data.module_id,
            user_id=current_user.id,
        )

        if not org_module:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Module '{data.module_id}' not found for organization",
            )

        return OrgModuleRead(
            module_id=org_module.module_id,
            is_enabled=org_module.is_enabled,
            enabled_at=org_module.enabled_at,
            disabled_at=org_module.disabled_at,
            settings=org_module.settings,
        )

    except ValueError as e:
        logger.error("Failed to disable module: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to disable module",
        )


@router.put(
    "/org/{organization_id}/{module_id}/settings",
    response_model=OrgModuleRead,
    summary="Update module settings",
)
async def update_module_settings(
    organization_id: UUID,
    module_id: str,
    data: OrgModuleSettingsUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> OrgModuleRead:
    """
    Update settings for an enabled module.
    """
    _verify_org_access(current_user, organization_id, require_admin=True)

    service = ModuleService(db)

    try:
        org_module = await service.update_module_settings(
            organization_id=organization_id,
            module_id=module_id,
            settings=data.settings,
            user_id=current_user.id,
        )

        manifest = module_registry.get_module_or_none(module_id)

        return OrgModuleRead(
            module_id=org_module.module_id,
            is_enabled=org_module.is_enabled,
            enabled_at=org_module.enabled_at,
            disabled_at=org_module.disabled_at,
            settings=org_module.settings,
            manifest=ModuleManifestResponse(**manifest.manifest.to_dict()) if manifest else None,
        )

    except Exception as e:
        logger.error("Failed to update module settings: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update module settings",
        )


# ==========================================
# Navigation & Widgets
# ==========================================


@router.get(
    "/org/{organization_id}/navigation",
    response_model=NavigationResponse,
    summary="Get navigation items",
)
async def get_navigation(
    organization_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> NavigationResponse:
    """
    Get navigation items for enabled modules.

    Used by the frontend to build the sidebar navigation.
    """
    _verify_org_access(current_user, organization_id)

    # Ensure cache is populated
    service = ModuleService(db)
    await service.load_enabled_modules_to_cache(organization_id)

    items = module_registry.get_navigation_items(organization_id)
    return NavigationResponse(items=items)


@router.get(
    "/org/{organization_id}/widgets",
    response_model=WidgetsResponse,
    summary="Get dashboard widgets",
)
async def get_widgets(
    organization_id: UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> WidgetsResponse:
    """
    Get available dashboard widgets for enabled modules.

    Used by the frontend to populate the dashboard widget selector.
    """
    _verify_org_access(current_user, organization_id)

    # Ensure cache is populated
    service = ModuleService(db)
    await service.load_enabled_modules_to_cache(organization_id)

    widgets = module_registry.get_dashboard_widgets(organization_id)
    return WidgetsResponse(widgets=widgets)


# ==========================================
# Feature Flags
# ==========================================


@router.get(
    "/org/{organization_id}/{module_id}/features",
    response_model=FeatureFlagsResponse,
    summary="Get feature flags",
)
async def get_feature_flags(
    organization_id: UUID,
    module_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> FeatureFlagsResponse:
    """
    Get feature flags for a module.
    """
    _verify_org_access(current_user, organization_id)

    service = ModuleService(db)
    flags = await service.get_feature_flags(organization_id, module_id)

    return FeatureFlagsResponse(
        flags=[
            FeatureFlagRead(
                module_id=f.module_id,
                feature_key=f.feature_key,
                is_enabled=f.is_enabled,
                value=f.value,
            )
            for f in flags
        ]
    )


@router.put(
    "/org/{organization_id}/{module_id}/features/{feature_key}",
    response_model=FeatureFlagRead,
    summary="Set feature flag",
)
async def set_feature_flag(
    organization_id: UUID,
    module_id: str,
    feature_key: str,
    data: FeatureFlagUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> FeatureFlagRead:
    """
    Set a feature flag value for a module.
    """
    _verify_org_access(current_user, organization_id, require_admin=True)

    service = ModuleService(db)

    flag = await service.set_feature_flag(
        organization_id=organization_id,
        module_id=module_id,
        feature_key=feature_key,
        is_enabled=data.is_enabled,
        value=data.value,
    )

    return FeatureFlagRead(
        module_id=flag.module_id,
        feature_key=flag.feature_key,
        is_enabled=flag.is_enabled,
        value=flag.value,
    )


# ==========================================
# Module Events
# ==========================================


@router.get(
    "/events",
    response_model=ModuleEventsResponse,
    summary="Get module events",
)
async def get_module_events(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    organization_id: UUID | None = Query(None),
    module_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> ModuleEventsResponse:
    """
    Get module event history.

    Useful for auditing module changes.
    """
    # SECURITY: this endpoint lacked org scoping — a regular user
    # could omit organization_id (filter skipped → ALL orgs' events) or pass a
    # victim org's id, leaking cross-tenant module-config events (incl. actor +
    # old/new settings). Force the caller's own org; only super_admin may query
    # another org or all orgs. Mirrors every sibling endpoint's _verify_org_access.
    if is_unscoped_superuser(current_user):  # scope-aware
        effective_org = organization_id  # may be None → all orgs, by design
    else:
        if organization_id is not None:
            _verify_org_access(current_user, organization_id)
        # a scoped super_admin key (organization_id None) must NOT fall
        # through to all-orgs. org_scope_or_platform returns the caller's own org
        # and raises 403 for a scoped/no-org principal (fail closed).
        effective_org = org_scope_or_platform(current_user)

    service = ModuleService(db)
    events = await service.get_module_events(
        organization_id=effective_org,
        module_id=module_id,
        limit=limit,
        offset=offset,
    )

    return ModuleEventsResponse(
        events=[
            ModuleEventRead(
                id=str(e.id),
                organization_id=str(e.organization_id) if e.organization_id else None,
                module_id=e.module_id,
                event_type=e.event_type,
                timestamp=e.timestamp,
                user_id=str(e.user_id) if e.user_id else None,
                details=e.details,
                error_message=e.error_message,
            )
            for e in events
        ],
        total=len(events),
    )

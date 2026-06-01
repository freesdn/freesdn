# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Setup Wizard API
==============================

FastAPI routes for setup wizard.
All endpoints are public (no JWT required) but guarded by a
"setup incomplete" dependency so they cannot be re-run after first use.
"""

import logging
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status

logger = logging.getLogger(__name__)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import (
    CurrentUser,
    get_current_user_optional,
    is_unscoped_superuser,
)
from app.db.session import get_session
from app.models.core import User, UserRole
from app.setup.schemas import (
    AdminCreateRequest,
    AdminCreateResponse,
    ControllerAddRequest,
    ControllerAddResponse,
    ControllerTestResult,
    ControllerTypeInfo,
    DatabaseCheckResponse,
    ModuleOption,
    ModuleSelectionRequest,
    ModuleSelectionResponse,
    OrganizationCreateRequest,
    OrganizationCreateResponse,
    SampleDataRequest,
    SampleDataResponse,
    SetupCompleteRequest,
    SetupCompleteResponse,
    SetupStatus,
    WelcomeResponse,
)
from app.setup.service import SetupService

router = APIRouter(prefix="/setup", tags=["setup"])


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


async def get_setup_service(db: AsyncSession = Depends(get_session)) -> SetupService:
    return SetupService(db)


async def require_setup_incomplete(
    service: SetupService = Depends(get_setup_service),
) -> SetupService:
    """Gate setup endpoints: only allow if no super_admin exists.

    Setup is complete IFF at least one non-deleted ``super_admin`` user
    exists in the database. This is the correct invariant: a fresh
    install has no super_admin, and the first POST /setup/admin creates
    one.

    IMPORTANT: Do NOT use the ``Organization.settings``
    JSONB ``setup_completed`` flag as the authorization gate. That flag
    lives on a user-mutable row and can be wiped by pg_dump/restore,
    seed scripts, mid-flight failures, or row deletion — any of which
    would re-open the unauthenticated setup endpoint and allow a single
    request to create a new ``super_admin``. The super_admin existence
    check is enforced at the database level and cannot be bypassed this
    way.
    """
    count_result = await service.db.execute(
        select(func.count())
        .select_from(User)
        .where(
            User.role == UserRole.SUPER_ADMIN,
            User.deleted_at.is_(None),
        )
    )
    count = count_result.scalar() or 0
    if count > 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setup already complete. Login with existing credentials.",
        )
    return service


async def require_setup_authorized(
    service: SetupService = Depends(get_setup_service),
    current_user: CurrentUser | None = Depends(get_current_user_optional),
) -> SetupService:
    """Gate the POST-admin wizard steps (enable-modules, controllers, complete).

    These run AFTER the admin + org are created in one transaction, so
    ``require_setup_incomplete`` (which 403s the moment a super_admin exists)
    would wrongly block the rest of the SAME wizard run. Authorize instead by
    EITHER:
      - no super_admin exists yet (fresh install, anonymous wizard still safe), OR
      - the request is the authenticated super_admin who just ran the wizard
        (it logs in immediately after POST /setup/admin).

    Admin CREATION itself keeps the strict ``require_setup_incomplete`` gate, so
    an UNauthenticated request can never create a
    second super_admin once one exists. This dependency only authorizes
    NON-privilege-granting configuration steps for the real, just-created admin.
    """
    count = (
        await service.db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == UserRole.SUPER_ADMIN, User.deleted_at.is_(None))
        )
    ) or 0
    if count == 0:
        return service  # fresh install — the anonymous wizard may proceed
    if current_user is not None and is_unscoped_superuser(current_user):
        return service  # the just-created super_admin finishing setup
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Setup already complete. Log in as an administrator to change configuration.",
    )


# ===========================================================================
# Status  (always accessible — even after setup)
# ===========================================================================


@router.get("/status", response_model=SetupStatus, summary="Get setup status")
async def get_setup_status(
    service: SetupService = Depends(get_setup_service),
) -> SetupStatus:
    return await service.get_setup_status()


# ===========================================================================
# Restore branch — first-install "Restore from Backup" (UniFi/Home-Assistant model)
# ===========================================================================


@router.post(
    "/restore",
    summary="First-install restore: rebuild this instance from a .fsdnvault full backup",
)
async def restore_from_vault(
    file: UploadFile = File(...),
    passphrase: str = Form(...),
    org_name: str | None = Form(None),
    service: SetupService = Depends(require_setup_incomplete),
) -> dict[str, Any]:
    """Restore a fresh install from an uploaded secure (``.fsdnvault``) backup.

    Gated by ``require_setup_incomplete`` exactly like admin creation — only callable
    while no ``super_admin`` exists, so it can't be used to overwrite a live instance.
    The vault is decrypted with the operator passphrase (the salt rides in the file
    header — no origin DB row needed), the Organization is recreated with its original
    id, and every contributor is restored INCLUDING secrets (re-keyed onto this
    instance). The restored ``super_admin`` makes setup complete and the operator's
    old login works.
    """
    # Bound the upload (a config + secrets archive is small — tens of KB to a few MB).
    raw = await file.read(64 * 1024 * 1024 + 1)
    if len(raw) > 64 * 1024 * 1024:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "backup file too large")

    from app.services.backup import BackupService

    try:
        result = await BackupService(service.db).restore_fresh_instance_from_vault(
            raw, passphrase=passphrase, org_name=org_name
        )
        await service.db.commit()
    except ValueError as exc:
        await service.db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    except Exception:
        await service.db.rollback()
        logger.exception("first-install vault restore failed")
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, "restore failed — see server logs"
        )
    return {"success": True, **result}


# ===========================================================================
# Step 1: Welcome / System Requirements
# ===========================================================================


@router.get("/welcome", response_model=WelcomeResponse, summary="Check system requirements")
async def check_welcome(
    service: SetupService = Depends(require_setup_incomplete),
) -> WelcomeResponse:
    return await service.check_system_requirements()


# ===========================================================================
# Step 2: Database
# ===========================================================================


@router.get("/database", response_model=DatabaseCheckResponse, summary="Check database status")
async def check_database(
    service: SetupService = Depends(require_setup_incomplete),
) -> DatabaseCheckResponse:
    return await service.check_database()


@router.post("/database/migrate", summary="Run database migrations")
async def run_migrations(
    service: SetupService = Depends(require_setup_incomplete),
) -> dict[str, Any]:
    ok = await service.run_migrations()
    if not ok:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Migration failed")
    return {"success": True, "message": "Migrations applied successfully"}


# ===========================================================================
# Step 3: Admin User
# ===========================================================================


@router.post("/admin", response_model=AdminCreateResponse, summary="Create admin user")
async def create_admin(
    request: AdminCreateRequest,
    service: SetupService = Depends(require_setup_incomplete),
) -> AdminCreateResponse:
    resp = await service.create_admin_user(request)
    if not resp.success:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=resp.error)
    return resp


# ===========================================================================
# Step 4: Organization
# ===========================================================================


@router.post(
    "/organization",
    response_model=OrganizationCreateResponse,
    summary="Create organization",
)
async def create_organization(
    request: OrganizationCreateRequest,
    service: SetupService = Depends(require_setup_incomplete),
) -> OrganizationCreateResponse:
    resp = await service.create_organization(request)
    if not resp.success:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=resp.error)
    return resp


# ===========================================================================
# Step 5: Modules
# ===========================================================================


@router.get("/modules", response_model=list[ModuleOption], summary="Get available modules")
async def get_modules(
    service: SetupService = Depends(get_setup_service),
) -> list[ModuleOption]:
    # Read-only metadata (static list of module options) — safe to expose
    # without the incomplete-gate so the post-admin Modules step can load it.
    return service.get_available_modules()


@router.post("/modules", response_model=ModuleSelectionResponse, summary="Enable modules")
async def enable_modules(
    request: ModuleSelectionRequest,
    service: SetupService = Depends(require_setup_authorized),
) -> ModuleSelectionResponse:
    resp = await service.enable_modules(request)
    if not resp.success:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=resp.error)
    return resp


# ===========================================================================
# Step 6: Controllers
# ===========================================================================


@router.get(
    "/controllers/types",
    response_model=list[ControllerTypeInfo],
    summary="Get controller types",
)
async def get_controller_types(
    service: SetupService = Depends(get_setup_service),
) -> list[ControllerTypeInfo]:
    # Read-only metadata (static controller-type list).
    return service.get_available_controller_types()


@router.post(
    "/controllers/test",
    response_model=ControllerTestResult,
    summary="Test controller connection",
)
async def test_controller(
    request: ControllerAddRequest,
    service: SetupService = Depends(require_setup_authorized),
) -> ControllerTestResult:
    return await service.test_controller_connection(request)


@router.post(
    "/controllers",
    response_model=ControllerAddResponse,
    summary="Add controller",
)
async def add_controller(
    request: ControllerAddRequest,
    service: SetupService = Depends(require_setup_authorized),
) -> ControllerAddResponse:
    resp = await service.add_controller(request)
    if not resp.success:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=resp.error)
    return resp


# ===========================================================================
# Step 7: Complete
# ===========================================================================


@router.post(
    "/complete",
    response_model=SetupCompleteResponse,
    summary="Complete setup",
)
async def complete_setup(
    request: SetupCompleteRequest,
    http_request: Request,
    service: SetupService = Depends(require_setup_authorized),
) -> SetupCompleteResponse:
    # Guard against double-FINALIZATION (TOCTOU). NOTE: is_complete is true the
    # moment admin+org exist (mid-wizard), so it cannot be the guard here; use
    # the finalized flag, which is set ONLY by a successful complete_setup.
    if await service.is_finalized():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setup has already been finalized.",
        )
    # Extract client IP (honor X-Forwarded-For if present) and user agent
    # so complete_setup can write an audit log entry identifying the
    # anonymous actor who ran the one-shot setup wizard.
    forwarded = http_request.headers.get("x-forwarded-for")
    client_ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (http_request.client.host if http_request.client else None)
    )
    user_agent = http_request.headers.get("user-agent")
    resp = await service.complete_setup(
        request,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    if not resp.success:
        logger.error("Setup completion failed: %s", resp.error)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Setup completion failed")
    return resp


# ===========================================================================
# Sample Data  (can also be invoked independently)
# ===========================================================================


@router.post(
    "/sample-data",
    response_model=SampleDataResponse,
    summary="Install sample / demo data",
)
async def install_sample_data_endpoint(
    request: SampleDataRequest,
    service: SetupService = Depends(require_setup_authorized),
) -> SampleDataResponse:
    """Install realistic sample data so users can explore the UI."""
    try:
        from app.setup.sample_data import install_sample_data

        result = await install_sample_data(
            service.db,
            request.organization_id,
            request.site_id,
        )
        await service.db.commit()
        return result
    except Exception as exc:
        await service.db.rollback()
        logger.error("Sample data installation failed: %s", exc, exc_info=True)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Sample data installation failed"
        )

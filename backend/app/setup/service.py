# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Setup Wizard Service
==================================

Business logic for setup wizard operations.
Fully ORM-based and **stateless** — each request is self-contained.
IDs flow through the frontend store, not server-side state.
"""

import importlib.metadata
import logging
import os
import re
import shutil
import sys
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.models.core import (
    Controller,
    ControllerStatus,
    Organization,
    Site,
    User,
    UserRole,
)
from app.modules.models import OrganizationModule
from app.setup.schemas import (
    AdminCreateRequest,
    AdminCreateResponse,
    ControllerAddRequest,
    ControllerAddResponse,
    ControllerTestResult,
    ControllerTypeInfo,
    DatabaseCheckResponse,
    DockerService,
    ModuleOption,
    ModuleSelectionRequest,
    ModuleSelectionResponse,
    OrganizationCreateRequest,
    OrganizationCreateResponse,
    SetupCompleteRequest,
    SetupCompleteResponse,
    SetupStatus,
    SetupStep,
    SetupSummary,
    StackInfo,
    SystemRequirement,
    WelcomeResponse,
)

logger = logging.getLogger(__name__)

# fixed key for the first-run bootstrap advisory lock (arbitrary
# constant within signed bigint; "SETU" mnemonic).
_SETUP_BOOTSTRAP_LOCK_KEY = 0x53455455


class SetupService:
    """
    Setup wizard service — stateless, ORM-based.

    Every method receives all the context it needs via its parameters.
    No ``_setup_state`` dict; the frontend passes IDs between steps.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # =========================================================================
    # Setup Status
    # =========================================================================

    async def get_setup_status(self) -> SetupStatus:
        """Check whether this instance is already set up.

        Setup is considered complete IFF at least one non-deleted
        ``super_admin`` user exists in the database. This is the only
        correct invariant — ``Organization.settings['setup_completed']``
        lives on a user-mutable row and can be wiped by pg_dump/restore,
        seed scripts, mid-flight failures, or row deletion; using it as
        the authorization gate allows unauthenticated super_admin
        takeover.

        The JSONB flag is still read below (``_setup_completed_at``) as
        a UX hint only — to render the "wizard completed at" timestamp
        in the UI — and MUST NOT be used to authorize setup endpoints.
        """
        try:
            super_admin_count = (
                await self.db.scalar(
                    select(func.count())
                    .select_from(User)
                    .where(
                        User.role == UserRole.SUPER_ADMIN,
                        User.deleted_at.is_(None),
                    )
                )
            ) or 0
            user_count = (await self.db.scalar(select(func.count()).select_from(User))) or 0
            org = (await self.db.execute(select(Organization).limit(1))).scalar_one_or_none()

            # Build steps_completed from actual database state — do
            # NOT lie. Previous version returned a hard-coded list
            # claiming organization/modules were complete even when
            # those rows didn't exist; that confused the wizard into
            # showing "Setup already complete. Login with existing
            # credentials." on the Org step right after a successful
            # Admin step (when no org row had actually been written).
            completed: list[SetupStep] = [
                SetupStep.WELCOME,
                SetupStep.DATABASE,
            ]
            current = SetupStep.ADMIN
            if user_count > 0:
                completed.append(SetupStep.ADMIN)
                current = SetupStep.ORGANIZATION
            if org is not None:
                completed.append(SetupStep.ORGANIZATION)
                current = SetupStep.MODULES

            # Fully complete IFF super_admin AND org both exist. A
            # super_admin alone (orphaned, organization_id=NULL) is
            # NOT a usable system — every device-add flow needs an
            # org to scope to.
            is_complete = super_admin_count > 0 and org is not None
            if is_complete:
                completed.extend(
                    [
                        SetupStep.MODULES,
                        SetupStep.COMPLETE,
                    ]
                )
                return SetupStatus(
                    is_complete=True,
                    current_step=SetupStep.COMPLETE,
                    steps_completed=completed,
                    message="FreeSDN is already configured.",
                )

            return SetupStatus(
                is_complete=False,
                current_step=current,
                steps_completed=completed,
            )

        except Exception as exc:
            logger.debug("Setup status check (tables may not exist): %s", exc)
            # Roll back the failed transaction so the session is
            # re-usable by subsequent queries (e.g. SELECT version()).
            await self.db.rollback()

        return SetupStatus(
            is_complete=False,
            current_step=SetupStep.NOT_STARTED,
            steps_completed=[],
        )

    async def is_finalized(self) -> bool:
        """True once a successful ``complete_setup`` has set the
        ``setup_completed`` flag on the organization.

        Used ONLY as the double-finalization (TOCTOU) guard inside
        ``POST /setup/complete`` — NOT as an authorization gate. Authorization
        for the post-admin steps is the authenticated super_admin
        (``require_setup_authorized``); admin creation stays gated on
        super_admin-existence.
        """
        try:
            org = (await self.db.execute(select(Organization).limit(1))).scalar_one_or_none()
            return bool(org and (org.settings or {}).get("setup_completed"))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("is_finalized check failed: %s", exc)
            await self.db.rollback()
            return False

    # =========================================================================
    # Step 1: Welcome / System Requirements
    # =========================================================================

    async def check_system_requirements(self) -> WelcomeResponse:
        """Verify that the host meets minimum requirements."""
        requirements: list[SystemRequirement] = []

        # Python
        py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        py_ok = sys.version_info >= (3, 12)
        requirements.append(
            SystemRequirement(
                name="Python",
                required="3.12+",
                actual=py,
                passed=py_ok,
                message=None if py_ok else "Python 3.12 or higher is required",
            )
        )

        # PostgreSQL
        try:
            # Ensure we start with a clean transaction state — prior
            # queries (e.g. setup-status table checks) may have failed
            # on a fresh DB where tables don't exist yet.
            await self.db.rollback()
            result = await self.db.execute(text("SELECT version()"))
            pg_full = result.scalar() or ""
            is_pg = "PostgreSQL" in pg_full
            pg_ver = pg_full.split()[1] if is_pg else "Not connected"
            pg_ok = False
            if is_pg:
                try:
                    pg_major = int(pg_ver.split(".")[0])
                    pg_ok = pg_major >= 16
                except (ValueError, IndexError):
                    pass
            requirements.append(
                SystemRequirement(
                    name="PostgreSQL",
                    required="16+",
                    actual=pg_ver,
                    passed=pg_ok,
                    message=None if pg_ok else "PostgreSQL 16 or higher is required",
                )
            )
        except Exception:
            logger.exception("PostgreSQL requirement check failed")
            requirements.append(
                SystemRequirement(
                    name="PostgreSQL",
                    required="16+",
                    actual="Connection failed",
                    passed=False,
                    message="Database connection failed — see server logs for details",
                )
            )

        # Redis
        redis_ok = False
        redis_ver = "Not configured"
        try:
            from app.core.config import settings
            from app.core.redis_client import get_async_redis

            if settings.REDIS_URL:
                r = get_async_redis()
                info = await r.info("server")
                redis_ver = info.get("redis_version", "Connected")
                try:
                    redis_major = int(redis_ver.split(".")[0])
                    redis_ok = redis_major >= 7
                except (ValueError, IndexError):
                    redis_ok = True  # allow if version can't be parsed
                await r.aclose()
        except (ConnectionError, TimeoutError, OSError, ImportError):
            redis_ver = "Connection failed"
        requirements.append(
            SystemRequirement(
                name="Redis",
                required="7+",
                actual=redis_ver,
                passed=redis_ok,
            )
        )

        # Disk space
        try:
            disk = shutil.disk_usage("/")
            free_gb = disk.free / (1024**3)
        except OSError:
            # Windows fallback
            try:
                disk = shutil.disk_usage("C:\\")
                free_gb = disk.free / (1024**3)
            except OSError:
                free_gb = 0.0
        disk_ok = free_gb >= 1.0
        requirements.append(
            SystemRequirement(
                name="Disk Space",
                required="1 GB free",
                actual=f"{free_gb:.1f} GB free",
                passed=disk_ok,
            )
        )

        all_met = all(r.passed for r in requirements)

        # Gather runtime stack versions
        stack_packages = [
            ("FastAPI", "fastapi", "backend"),
            ("Pydantic", "pydantic", "backend"),
            ("SQLAlchemy", "sqlalchemy", "backend"),
            ("Uvicorn", "uvicorn", "backend"),
            ("Celery", "celery", "backend"),
            ("Alembic", "alembic", "backend"),
            ("Redis (client)", "redis", "backend"),
            ("HTTPX", "httpx", "backend"),
            ("Jinja2", "jinja2", "backend"),
        ]
        stack_info = []
        for display_name, pkg, category in stack_packages:
            try:
                ver = importlib.metadata.version(pkg)
            except importlib.metadata.PackageNotFoundError:
                ver = "not installed"
            stack_info.append(StackInfo(name=display_name, version=ver, category=category))

        # Probe Docker services reachability
        docker_services = await self._probe_docker_services()

        return WelcomeResponse(
            app_name=settings.APP_NAME,
            app_version=settings.APP_VERSION,
            environment=settings.ENVIRONMENT,
            requirements=requirements,
            all_requirements_met=all_met,
            can_proceed=all_met,
            stack_info=stack_info,
            docker_services=docker_services,
        )

    # =========================================================================
    # Step 2: Database
    # =========================================================================

    async def check_database(self) -> DatabaseCheckResponse:
        """Verify database connection and migration status."""
        try:
            # Clear any stale transaction state before checking.
            await self.db.rollback()
            result = await self.db.execute(text("SELECT version()"))
            version_str = result.scalar() or ""

            # TimescaleDB on main database
            timescale = False
            ts_version = None
            ts_location = None
            try:
                ts = await self.db.execute(
                    text("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'")
                )
                v = ts.scalar()
                if v:
                    timescale = True
                    ts_version = v
                    ts_location = "main"
            except SQLAlchemyError:
                pass

            # Check logdb (separate TimescaleDB container)
            logdb_connected = False
            logdb_url = os.environ.get("LOGDB_URL")
            if logdb_url:
                logdb_engine = None
                try:
                    from sqlalchemy.ext.asyncio import create_async_engine

                    logdb_engine = create_async_engine(logdb_url, pool_pre_ping=True)
                    async with logdb_engine.connect() as conn:
                        logdb_connected = True
                        ts = await conn.execute(
                            text(
                                "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'"
                            )
                        )
                        v = ts.scalar()
                        if v:
                            timescale = True
                            ts_version = v
                            ts_location = "logdb"
                except (SQLAlchemyError, ConnectionError, OSError):
                    pass
                finally:
                    if logdb_engine is not None:
                        await logdb_engine.dispose()

            # Alembic - compare current revision against head
            schema_current = False
            migrations_applied = 0
            migrations_pending = 0
            try:
                m = await self.db.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
                current_rev = m.scalar()

                if current_rev:
                    from alembic.config import Config as AlembicConfig
                    from alembic.script import ScriptDirectory

                    cfg = AlembicConfig("alembic.ini")
                    script = ScriptDirectory.from_config(cfg)
                    head_rev = script.get_current_head()

                    schema_current = current_rev == head_rev

                    # Count total migration scripts
                    all_revs = list(script.walk_revisions())
                    migrations_applied = len(all_revs)

                    if not schema_current and head_rev:
                        pending = 0
                        for _rev in script.walk_revisions(head_rev, current_rev):
                            pending += 1
                        migrations_pending = max(0, pending - 1)
                        migrations_applied = max(0, migrations_applied - migrations_pending)
            except (SQLAlchemyError, ImportError, FileNotFoundError, OSError):
                pass

            return DatabaseCheckResponse(
                connected=True,
                database_type="postgresql",
                database_version=version_str,
                timescale_enabled=timescale,
                timescale_version=ts_version,
                timescale_location=ts_location,
                logdb_connected=logdb_connected,
                schema_current=schema_current,
                migrations_applied=migrations_applied,
                migrations_pending=migrations_pending,
            )
        except Exception:
            logger.exception("Database check failed")
            return DatabaseCheckResponse(
                connected=False,
                error="Database check failed — see server logs for details",
            )

    async def run_migrations(self) -> bool:
        """Apply pending Alembic migrations (run in thread to avoid blocking)."""
        try:
            import asyncio

            from alembic.config import Config

            from alembic import command

            def _run() -> None:
                cfg = Config("alembic.ini")
                command.upgrade(cfg, "head")

            await asyncio.to_thread(_run)
            return True
        except Exception as exc:
            logger.error("Migration failed: %s", exc)
            return False

    # =========================================================================
    # Step 3: Admin User
    # =========================================================================

    async def create_admin_user(self, request: AdminCreateRequest) -> AdminCreateResponse:
        """Create the initial super-admin user via ORM.

        When ``request.organization_name`` is provided, also creates
        the first organization + default site + user→org link in the
        SAME transaction. This is the supported atomic-setup path —
        without it, the gate (``require_setup_incomplete``) closes the
        moment this method commits, and any follow-up
        ``/setup/organization`` request is rejected with 403, leaving
        the admin orphaned (``organization_id=NULL``) and unable to
        create sites or devices.

        The org-bundle fields are optional only for backward compat;
        the v2.6.0+ frontend always sends them.
        """
        try:
            # SECURITY: serialize the bootstrap. require_setup_
            # incomplete does an UNLOCKED super_admin-count check, so two
            # concurrent /setup/admin requests (with different emails) could both
            # pass the gate and each create a super_admin. Take a transaction-
            # scoped advisory lock (held until COMMIT) and re-check the count
            # under it — the second request blocks, then sees count>0 and bails.
            await self.db.execute(
                text("SELECT pg_advisory_xact_lock(:k)"), {"k": _SETUP_BOOTSTRAP_LOCK_KEY}
            )
            super_admin_count = await self.db.scalar(
                select(func.count(User.id)).where(
                    User.role == UserRole.SUPER_ADMIN,
                    User.deleted_at.is_(None),
                )
            )
            if super_admin_count:
                return AdminCreateResponse(
                    success=False,
                    error="Setup has already been completed",
                )

            # Check for existing user
            existing = await self.db.execute(
                select(User).where(
                    (User.email == request.email) | (User.username == request.username)
                )
            )
            if existing.scalar_one_or_none():
                return AdminCreateResponse(
                    success=False,
                    error="A user with this email or username already exists",
                )

            full_name = f"{request.first_name} {request.last_name}".strip() or request.username

            # Atomic-org creation when requested
            org: Organization | None = None
            site: Site | None = None
            if request.organization_name:
                org_slug = request.organization_slug or self._generate_slug(
                    request.organization_name
                )
                # Slug must be unique — bail early if collision so we
                # don't half-create state.
                slug_exists = await self.db.execute(
                    select(Organization).where(Organization.slug == org_slug)
                )
                if slug_exists.scalar_one_or_none():
                    return AdminCreateResponse(
                        success=False,
                        error=f"organization slug {org_slug!r} already exists",
                    )
                org = Organization(
                    id=uuid4(),
                    name=request.organization_name,
                    slug=org_slug,
                    description="Created during FreeSDN setup",
                    contact_email=None,
                    is_active=True,
                    settings={
                        "timezone": request.organization_timezone,
                        "locale": request.organization_locale,
                    },
                )
                self.db.add(org)
                await self.db.flush()
                site = Site(
                    id=uuid4(),
                    organization_id=org.id,
                    name="Main Site",
                    slug="main",
                    description="Default site created during setup",
                    timezone=request.organization_timezone,
                    is_active=True,
                )
                self.db.add(site)
                await self.db.flush()

            user = User(
                id=uuid4(),
                email=request.email,
                username=request.username,
                full_name=full_name,
                hashed_password=get_password_hash(request.password),
                role=UserRole.SUPER_ADMIN,
                is_active=True,
                is_verified=True,
                organization_id=org.id if org else None,
                preferences={"theme": "dark", "notifications": True},
            )
            self.db.add(user)
            await self.db.flush()

            # log user_id only (setup wizard is bootstrap context
            # but the JSON log stream should never carry raw emails).
            logger.info(
                "Setup wizard: created admin user (org=%s)",
                str(org.id) if org else "none",
                extra={"user_id": str(user.id)},
            )

            return AdminCreateResponse(
                success=True,
                user_id=user.id,
                email=user.email,
                username=user.username,
                organization_id=org.id if org else None,
                organization_slug=org.slug if org else None,
                default_site_id=site.id if site else None,
            )
        except Exception:
            logger.exception("Failed to create admin user")
            await self.db.rollback()
            return AdminCreateResponse(
                success=False,
                error="Installation error — see server logs for details",
            )

    # =========================================================================
    # Step 4: Organization
    # =========================================================================

    async def create_organization(
        self,
        request: OrganizationCreateRequest,
    ) -> OrganizationCreateResponse:
        """Create the first organization + default site.

        Also links the admin user (``request.admin_id``) to the org.
        """
        try:
            slug = request.slug or self._generate_slug(request.name)

            # Check uniqueness
            existing = await self.db.execute(select(Organization).where(Organization.slug == slug))
            if existing.scalar_one_or_none():
                return OrganizationCreateResponse(
                    success=False,
                    error="An organization with this slug already exists",
                )

            org = Organization(
                id=uuid4(),
                name=request.name,
                slug=slug,
                description="Created during FreeSDN setup",
                contact_email=None,
                is_active=True,
                settings={
                    "timezone": request.timezone,
                    "locale": request.locale,
                },
            )
            self.db.add(org)
            await self.db.flush()

            # Create a default site
            site = Site(
                id=uuid4(),
                organization_id=org.id,
                name="Main Site",
                slug="main",
                description="Default site created during setup",
                timezone=request.timezone,
                time_format=request.time_format,
                date_format=request.date_format,
                is_active=True,
            )
            self.db.add(site)
            await self.db.flush()

            # Link admin user → organization
            if request.admin_id:
                admin = await self.db.get(User, request.admin_id)
                if admin:
                    admin.organization_id = org.id
                    await self.db.flush()
                else:
                    logger.warning(
                        "Setup wizard: admin_id %s not found — org created but admin not linked",
                        request.admin_id,
                    )

            logger.info(
                "Setup wizard: created org '%s' (id=%s) with site '%s' (id=%s)",
                org.name,
                org.id,
                site.name,
                site.id,
            )

            return OrganizationCreateResponse(
                success=True,
                organization_id=org.id,
                site_id=site.id,
                name=org.name,
                slug=org.slug,
            )
        except Exception:
            logger.exception("Failed to create organization")
            await self.db.rollback()
            return OrganizationCreateResponse(
                success=False,
                error="Installation error — see server logs for details",
            )

    # =========================================================================
    # Step 5: Modules
    # =========================================================================

    def get_available_modules(self) -> list[ModuleOption]:
        """Return the module catalogue — synced with module manifests."""
        return [
            # ── Core ──
            ModuleOption(
                id="network",
                name="Network Management",
                description="VLANs, WiFi, PoE, switches, and access points",
                category="Core",
                recommended=True,
            ),
            # ── Security ──
            ModuleOption(
                id="cameras",
                name="Video Surveillance",
                description="IP camera management, live streaming, and recording playback",
                category="Security",
            ),
            ModuleOption(
                id="access_control",
                name="Access Control",
                description="Physical access control, door management, and credentials",
                category="Security",
            ),
            ModuleOption(
                id="firewall",
                name="Firewall",
                description="Firewall rules, NAT, VPN, IDS/IPS, and gateway orchestration",
                category="Security",
                requires=["network"],
            ),
            # ── Communications ──
            ModuleOption(
                id="voip",
                name="VoIP & Telephony",
                description="IP phone fleet management, PBX integration, and call management",
                category="Communications",
            ),
            # ── Monitoring ──
            ModuleOption(
                id="collector",
                name="Observability",
                description="SNMP traps, Syslog, and NetFlow collection with log aggregation",
                category="Monitoring",
            ),
            # ── Operations ──
            ModuleOption(
                id="backup",
                name="Backup & Restore",
                description="Backup and restore device configurations and system state",
                category="Operations",
                recommended=True,
            ),
            ModuleOption(
                id="ai",
                name="AI Assistant",
                description="AI-powered network assistant with multi-provider LLM support",
                category="Operations",
                recommended=True,
            ),
            ModuleOption(
                id="hypervisor",
                name="Hypervisor",
                description="Proxmox VE hypervisor and virtual machine management",
                category="Operations",
            ),
        ]

    async def enable_modules(
        self,
        request: ModuleSelectionRequest,
    ) -> ModuleSelectionResponse:
        """Persist enabled modules for the organization."""
        try:
            now = datetime.now(UTC)

            for module_id in request.enabled_modules:
                # Upsert via ORM
                existing = await self.db.execute(
                    select(OrganizationModule).where(
                        OrganizationModule.organization_id == request.organization_id,
                        OrganizationModule.module_id == module_id,
                    )
                )
                om = existing.scalar_one_or_none()
                if om:
                    om.is_enabled = True
                    om.enabled_at = now
                else:
                    om = OrganizationModule(
                        id=uuid4(),
                        organization_id=request.organization_id,
                        module_id=module_id,
                        is_enabled=True,
                        enabled_at=now,
                        settings={},
                    )
                    self.db.add(om)

            await self.db.flush()
            logger.info(
                "Setup wizard: enabled modules %s for org %s",
                request.enabled_modules,
                request.organization_id,
            )

            return ModuleSelectionResponse(
                success=True,
                enabled_modules=request.enabled_modules,
            )
        except Exception:
            logger.exception("Failed to enable modules")
            await self.db.rollback()
            return ModuleSelectionResponse(
                success=False,
                error="Installation error — see server logs for details",
            )

    # =========================================================================
    # Step 6: Controllers
    # =========================================================================

    def get_available_controller_types(self) -> list[ControllerTypeInfo]:
        """Return available adapter types from the registry."""
        types: list[ControllerTypeInfo] = []
        try:
            from app.adapters.registry import adapter_registry

            for manifest in adapter_registry.list_manifests():
                types.append(
                    ControllerTypeInfo(
                        adapter_id=manifest.id,
                        name=manifest.name,
                        vendor=manifest.vendor,
                        description=manifest.description,
                        requires_controller=manifest.supports_controller,
                    )
                )
        except Exception as exc:
            logger.warning("Could not load adapter manifests: %s", exc)

        # Always provide at least a manual entry
        if not types:
            types.append(
                ControllerTypeInfo(
                    adapter_id="omada",
                    name="TP-Link Omada",
                    vendor="TP-Link",
                    description="Omada SDN controller",
                    requires_controller=True,
                )
            )
        return types

    async def test_controller_connection(
        self,
        request: ControllerAddRequest,
    ) -> ControllerTestResult:
        """Test connectivity to a controller before saving."""
        # SSRF guard: the pre-setup window is reachable unauthenticated (before
        # the first super_admin exists), so block loopback / link-local / cloud
        # metadata targets. allow_private=True keeps on-prem RFC1918 reachable.
        from app.core.security_utils import resolve_and_pin_host

        try:
            # ALWAYS resolve+validate (rejects a host that
            # resolves to loopback/link-local/metadata) on this UNAUTHENTICATED
            # first-boot path, and ALWAYS connect to the pinned IP literal — even with
            # verify_ssl=true. The earlier "keep the hostname when verify_ssl so the
            # cert check defeats a rebind" reasoning held ONLY for the single TLS
            # channel; multi-subchannel adapters (e.g. FreePBX AMI:5038 / ARI:8088)
            # open NON-TLS subchannels that re-resolve the hostname at connect time,
            # so the cert defense never covers them and a low-TTL rebind reaches
            # loopback/metadata/internal. A pre-setup reachability probe never needs
            # SNI/cert-hostname matching, so pinning the IP for every subchannel is
            # the correct, complete fix.
            pinned = resolve_and_pin_host(request.host, allow_private=True)
            host_for_connect = pinned
        except ValueError:
            return ControllerTestResult(
                success=False,
                adapter_id=request.adapter_id,
                host=request.host,
                error="Target host is not permitted (blocked loopback/link-local/metadata address)",
            )
        try:
            from app.adapters.registry import adapter_registry

            adapter = adapter_registry.create_adapter(
                adapter_id=request.adapter_id,
                host=host_for_connect,
                username=request.username,
                password=request.password,
                verify_ssl=request.verify_ssl,
                site_id=None,
            )

            async with adapter:
                result = await adapter.test_connection()
                if result.success:
                    devices = await adapter.discover_devices()
                    return ControllerTestResult(
                        success=True,
                        adapter_id=request.adapter_id,
                        host=request.host,
                        message="Connection successful",
                        devices_found=len(devices),
                    )
                return ControllerTestResult(
                    success=False,
                    adapter_id=request.adapter_id,
                    host=request.host,
                    error=result.error,
                )
        except Exception:
            logger.exception("Controller connection test failed")
            return ControllerTestResult(
                success=False,
                adapter_id=request.adapter_id,
                host=request.host,
                error="Connection test failed — see server logs for details",
            )

    async def add_controller(
        self,
        request: ControllerAddRequest,
    ) -> ControllerAddResponse:
        """Save a controller to the database via ORM."""
        try:
            if not request.site_id:
                return ControllerAddResponse(
                    success=False,
                    error="site_id is required when adding a controller",
                )

            from app.core.security_utils import resolve_and_pin_host

            try:
                # resolve+validate (rejects rebind-unsafe hosts). The
                # saved-controller connect path re-pins via _pin_controller_host,
                # so the stored display hostname is fine to persist.
                resolve_and_pin_host(request.host, allow_private=True)
            except ValueError:
                return ControllerAddResponse(
                    success=False,
                    error="Target host is not permitted (blocked loopback/link-local/metadata address)",
                )

            # Build config JSONB payload
            config: dict[str, Any] = {}
            if request.username:
                config["username"] = request.username
            if request.password:
                from app.core.crypto import encrypt_credential

                config["password"] = encrypt_credential(request.password)
            if request.connection_mode:
                config["connection_mode"] = request.connection_mode
            if request.client_id:
                config["client_id"] = request.client_id
            if request.client_secret:
                from app.core.crypto import encrypt_credential

                # Encrypt at rest, matching the canonical controllers API
                # (controllers.py create/update). The model getter auto-decrypts
                # only when is_encrypted, so reads stay correct.
                config["client_secret"] = encrypt_credential(request.client_secret)
            if request.omada_id:
                config["omada_id"] = request.omada_id
            if request.cloud_region:
                config["cloud_region"] = request.cloud_region
            if request.site_mappings:
                config["site_mappings"] = request.site_mappings

            controller = Controller(
                id=uuid4(),
                site_id=request.site_id,
                name=request.name,
                controller_type=request.adapter_id,
                host=request.host,
                port=request.port,
                use_ssl=True,
                verify_ssl=request.verify_ssl,
                status=ControllerStatus.DISCONNECTED,
                config=config,
                is_active=True,
                sync_enabled=True,
                sync_interval_seconds=300,
            )
            self.db.add(controller)
            await self.db.flush()

            logger.info(
                "Setup wizard: added controller '%s' (id=%s)", controller.name, controller.id
            )

            # Optionally test
            test_result = ControllerTestResult(
                success=True,
                adapter_id=request.adapter_id,
                host=request.host,
                message="Controller saved",
            )

            return ControllerAddResponse(
                success=True,
                controller_id=controller.id,
                test_result=test_result,
            )
        except Exception:
            logger.exception("Failed to add controller")
            await self.db.rollback()
            return ControllerAddResponse(
                success=False,
                error="Installation error — see server logs for details",
            )

    # =========================================================================
    # Step 7: Complete
    # =========================================================================

    async def complete_setup(
        self,
        request: SetupCompleteRequest,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> SetupCompleteResponse:
        """Finalize setup. Optionally install sample data.

        ``client_ip`` and ``user_agent`` are captured from the HTTP
        request in the endpoint layer and recorded in the audit log so
        that the (necessarily anonymous) actor who ran the one-shot
        setup wizard is identified for forensic review.
        """
        try:
            # Install sample data if requested
            sample_result = None
            if request.install_sample_data and request.organization_id and request.site_id:
                from app.setup.sample_data import install_sample_data

                sample_result = await install_sample_data(
                    self.db, request.organization_id, request.site_id
                )
                logger.info("Setup wizard: sample data installed")

            # Mark setup as complete in Organization settings.
            # NOTE: This flag is a UX hint only (used to display a
            # "wizard completed at" timestamp in the UI). It is NOT the
            # authorization gate — that is handled by checking for the
            # existence of a super_admin user (see
            # ``require_setup_incomplete``). Do not rely on this flag
            # for access control.
            completed_at = datetime.now(UTC)
            org = await self.db.execute(select(Organization).limit(1))
            org_row = org.scalar_one_or_none()
            if org_row:
                org_settings = dict(org_row.settings or {})
                org_settings["setup_completed"] = True  # UX hint only
                org_settings["setup_completed_at"] = completed_at.isoformat()
                org_row.settings = org_settings
                await self.db.flush()

            # Gather summary from the DB
            admin = await self.db.execute(
                select(User).where(User.role == UserRole.SUPER_ADMIN).limit(1)
            )
            admin_user = admin.scalar_one_or_none()

            org = await self.db.execute(select(Organization).limit(1))
            org_row = org.scalar_one_or_none()

            modules = await self.db.execute(
                select(OrganizationModule.module_id).where(
                    OrganizationModule.is_enabled == True  # noqa: E712
                )
            )
            enabled = [r[0] for r in modules.fetchall()]

            controllers = await self.db.execute(select(func.count()).select_from(Controller))
            ctrl_count = controllers.scalar() or 0

            summary = SetupSummary(
                admin_email=admin_user.email if admin_user else "",
                organization_name=org_row.name if org_row else "",
                enabled_modules=enabled,
                controllers_added=ctrl_count,
                total_devices=0,
            )

            # Audit log: record that an anonymous actor completed the
            # one-shot setup wizard. This is a security-sensitive event
            # — it created a super_admin — so we capture IP, user
            # agent, and the email of the created admin for forensics.
            try:
                from app.models.security_audit import AuditLogRecord

                audit_entry = AuditLogRecord(
                    id=uuid4(),
                    timestamp=completed_at,
                    action="SETUP_COMPLETE",
                    resource_type="setup_wizard",
                    resource_id=str(org_row.id) if org_row else None,
                    resource_name=org_row.name if org_row else None,
                    actor_id=str(admin_user.id) if admin_user else None,
                    actor_type="anonymous",
                    actor_name="setup-wizard",
                    actor_email=admin_user.email if admin_user else None,
                    organization_id=org_row.id if org_row else None,
                    site_id=None,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    status="success",
                    response_code=200,
                    new_state={
                        "admin_email": admin_user.email if admin_user else None,
                        "organization_name": org_row.name if org_row else None,
                        "enabled_modules": enabled,
                        "controllers_added": ctrl_count,
                    },
                    tags=["setup", "security", "super_admin_created"],
                    extra_metadata={
                        "note": (
                            "Anonymous one-shot setup wizard: created "
                            "initial super_admin. Subsequent attempts "
                            "are blocked by require_setup_incomplete."
                        ),
                    },
                )
                self.db.add(audit_entry)
                await self.db.flush()
            except Exception:
                # Audit failure must not break setup completion, but
                # log loudly — this is a security-relevant event.
                logger.exception("Setup wizard: failed to write SETUP_COMPLETE audit log")

            await self.db.commit()
            logger.info(
                "Setup wizard completed successfully (admin=%s, ip=%s)",
                admin_user.email if admin_user else "?",
                client_ip or "?",
            )

            return SetupCompleteResponse(
                success=True,
                summary=summary,
                sample_data=sample_result,
                login_url="/login",
            )
        except Exception:
            logger.exception("Failed to complete setup")
            await self.db.rollback()
            return SetupCompleteResponse(
                success=False,
                error="Installation error — see server logs for details",
            )

    # =========================================================================
    # Helpers
    # =========================================================================

    async def _probe_docker_services(self) -> list[DockerService]:
        """Probe Docker Compose services for reachability via TCP."""
        import asyncio
        import socket

        # Each service maps to one or more (host, port) candidates; the first
        # reachable candidate wins. The frontend is the Caddy "edge" container
        # in prod (static build on port 80) and the Vite "frontend" dev server
        # in --dev (port 5173) — probe both so a prod install does not report
        # the frontend (which is serving this very page) as "unreachable".
        services_to_check: list[tuple[str, list[tuple[str, int | None]]]] = [
            ("PostgreSQL", [("postgres", 5432)]),
            ("TimescaleDB (LogDB)", [("logdb", 5432)]),
            ("Redis", [("redis", 6379)]),
            ("API", [("api", 8000)]),
            ("Celery Worker", [("worker", None)]),
            ("Celery Beat", [("scheduler", None)]),
            ("Flower", [("flower", 5555)]),
            ("Frontend", [("edge", 80), ("frontend", 5173)]),
        ]

        results: list[DockerService] = []

        for display_name, candidates in services_to_check:
            reachable = False
            host, port = candidates[0]
            for cand_host, cand_port in candidates:
                if cand_port is not None:
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(cand_host, cand_port),
                            timeout=2.0,
                        )
                        reachable = True
                        host, port = cand_host, cand_port
                        writer.close()
                        await writer.wait_closed()
                        break
                    except (TimeoutError, OSError):
                        continue
                else:
                    # No exposed port — fall back to a DNS-resolution check.
                    try:
                        socket.getaddrinfo(cand_host, None)
                        reachable = True
                        host, port = cand_host, cand_port
                        break
                    except socket.gaierror:
                        continue

            results.append(
                DockerService(
                    name=display_name,
                    host=f"{host}:{port}" if port else host,
                    reachable=reachable,
                    version=None,
                )
            )

        return results

    @staticmethod
    def _generate_slug(name: str) -> str:
        """Generate a URL-safe slug from a name."""
        slug = name.lower()
        slug = re.sub(r"[^a-z0-9\s-]", "", slug)
        slug = re.sub(r"[\s_]+", "-", slug)
        slug = re.sub(r"-+", "-", slug)
        return slug.strip("-")[:50]

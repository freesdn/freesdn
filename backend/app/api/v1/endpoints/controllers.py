# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Controller CRUD Endpoints
=======================================

Full CRUD operations for controllers with:
- Permission-based access control
- Connection testing
- Sync management
"""

import logging
import time
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status

logger = logging.getLogger(__name__)
from sqlalchemy import func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.core.dependencies import (
    CurrentUser,
    is_unscoped_superuser,
    require_permissions,
)
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.core.tenancy import tenant_filter
from app.db import get_session
from app.models import Controller, ControllerStatus, Device, DeviceStatus, Site
from app.schemas import (
    ControllerCreate,
    ControllerProbe,
    ControllerResponse,
    ControllerUpdate,
    ControllerWithStats,
    PaginatedResponse,
)
from app.schemas.core import _validate_site_mappings

router = APIRouter()


# =====================================================================
# Shared helpers
# =====================================================================


def _controller_device_filter(controller_id: UUID, current_user: CurrentUser) -> Any:
    """Shared predicate bounding a controller's devices to the caller's grant.

    ``Device.controller_id`` and ``Device.site_id`` are INDEPENDENT
    columns and a controller's ``site_mappings`` let one controller span devices
    in sibling sites of the same org. The controller access gate only validates
    the controller's PRIMARY ``site_id`` — it does NOT bound the device set. So
    every controller device aggregate must additionally scope by the caller's
    per-user site grant. ``site_scope_filter`` is ``true()`` (no-op) for
    super_admin / org_admin / grant-less users and ``Device.site_id IN(grants)``
    for a site-limited caller (never ``in_(None)``), so this is admin-safe.
    """
    from sqlalchemy import and_

    return and_(
        Device.controller_id == controller_id,
        Device.deleted_at.is_(None),
        site_scope_filter(current_user, Device.site_id),
    )


def _decrypt_if_needed(value: str | None) -> str:
    """Return plaintext value for encrypted controller secrets."""
    if not value:
        return ""
    if not is_encrypted(value):
        return value
    try:
        return decrypt_credential(value)
    except ValueError as exc:
        # Previously this silently returned the ciphertext, which then
        # became "the password" — yielding a confusing 401 from the
        # controller. Surface a clear error instead so the operator
        # knows the credential is corrupted (e.g. after a key rotation)
        # and needs to be re-entered.
        raise HTTPException(
            500,
            detail="controller credential could not be decrypted (key rotated?)",
        ) from exc


def _local_controller_public_host(host: str | None, connection_mode: str | None) -> str | None:
    """F1: a LOCAL-mode controller stores admin credentials (password /
    client_secret / token_secret) that every later test/sync/op replays to its
    ``host``. If an operator points the host at a PUBLIC address, that stored
    secret egresses there. This returns the resolved public IP when ``host`` is a
    public address (so the WRITE path can gate it behind an explicit confirmation),
    or ``None`` when it is private/on-prem or the controller is cloud-mode (cloud
    legitimately reaches the vendor endpoint, gated separately by
    cloud_region/omada_id). We enforce at the host-SETTING point (create/update)
    rather than at every read so the 28 shared controller operations are not
    constrained; the host is vetted once when it is chosen. ``validate_target_host``
    already rejected loopback/link-local/metadata before this runs.
    """
    if (connection_mode or "").lower() == "cloud":
        return None
    from app.core.security_utils import is_private_ip, resolve_and_pin_host

    try:
        pinned = resolve_and_pin_host(host or "", allow_private=True)
    except ValueError:
        # unresolved / blocked host — validate_target_host surfaces that separately
        return None
    return None if is_private_ip(pinned) else pinned


def _scope_freesdn_sites_list(current_user: CurrentUser, sites: list[Any]) -> list[Any]:
    """Filter a list of org Site rows down to the caller's granted sites.

    the controller site-mapping dropdown ("freesdn_sites")
    returned every site in the org. A site-limited user could thus enumerate
    sibling-site names/ids. No-op for super_admin / org_admin (not
    site-limited); site-limited users see only their granted sites.
    """
    if not getattr(current_user, "is_site_limited", False):
        return sites
    granted = current_user.accessible_site_ids or set()
    return [s for s in sites if s.id in granted]


def _scope_site_mappings(
    current_user: CurrentUser, mappings: dict[str, str] | None
) -> dict[str, str]:
    """Filter controller ``site_mappings`` down to grant-accessible targets.

    ``get_controller_remote_sites`` already grant-checks the parent
    controller and scopes the ``freesdn_sites`` dropdown, but returned the
    saved ``current_mappings`` UNCHANGED. Each mapping value is a FreeSDN site
    UUID — a sibling target site. A site-limited operator could therefore read
    the names/ids of sibling target sites via the READ path even though the
    WRITE path (PUT /site-mappings) already validates them. Drop any mapping
    whose target site is outside the caller's grant. No-op for non-site-limited
    (super_admin / org_admin) callers.
    """
    if not mappings:
        return mappings or {}
    if not getattr(current_user, "is_site_limited", False):
        return mappings
    granted = {str(sid) for sid in (current_user.accessible_site_ids or set())}
    return {k: v for k, v in mappings.items() if str(v) in granted}


async def _assert_mapping_targets_accessible(
    session: AsyncSession,
    mappings: dict[str, str] | None,
    org_id: UUID,
    current_user: CurrentUser,
) -> None:
    """Validate that every site_mappings TARGET site is in-org AND granted.

    (site-grant)a controller's ``site_mappings`` bind upstream
    controller-side site IDs to FreeSDN site UUIDs. The parent controller's
    own site is grant-checked everywhere, but the *mapped target* sites are
    sibling sites that were only validated against ``organization_id`` (PUT
    /site-mappings) or not validated at all (POST / PATCH). A site-limited
    operator granted only the controller's site could therefore bind upstream
    sites to — and route synced inventory/config into — sibling sites they
    cannot otherwise access.

    Enforces, for each distinct target UUID:
    - it parses as a UUID and exists in ``org_id`` (else 400, mirrors the
      pre-existing PUT validation shape), and
    - the caller's per-user grant allows it (``assert_can_access_site`` → 404,
      no existence oracle; no-op for super_admin / org_admin / grant-less).
    """
    if not mappings:
        return

    raw_targets = list(set(mappings.values()))
    parsed: dict[str, UUID] = {}
    invalid: list[str] = []
    for raw in raw_targets:
        try:
            parsed[raw] = UUID(str(raw))
        except (ValueError, AttributeError, TypeError):
            invalid.append(raw)
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid FreeSdn site id(s): {', '.join(invalid)}",
        )

    sites_result = await session.execute(
        select(Site.id).where(
            Site.id.in_(list(parsed.values())),
            Site.organization_id == org_id,
            Site.deleted_at.is_(None),
        )
    )
    found_ids = set(sites_result.scalars().all())
    missing = [raw for raw, sid in parsed.items() if sid not in found_ids]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"FreeSdn site(s) not found: {', '.join(missing)}",
        )

    # Per-user site grant: a site-limited caller may only map into sites they
    # can access. 404 (not 403) keeps the no-existence-oracle convention.
    for site_uuid in parsed.values():
        assert_can_access_site(
            current_user,
            site_uuid,
            detail="FreeSdn site not found",
        )


def _as_uuid(value: Any) -> UUID | None:
    """Best-effort UUID coercion; None for malformed values."""
    try:
        return UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


async def _get_controller_and_adapter(
    controller_id: UUID,
    session: AsyncSession,
    current_user: CurrentUser,
) -> Any:
    """Load a controller, check access, and create an adapter for it."""
    from app.adapters.registry import adapter_registry
    from app.services.adapter_base import GatewayServiceBase

    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()
    if not controller:
        raise HTTPException(status_code=404, detail="Controller not found")

    if not is_unscoped_superuser(current_user):
        if (
            not controller.site
            or controller.site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            raise HTTPException(status_code=403, detail="Access denied to this controller")

    # Belt-and-suspenders SSRF gate: reject controller hosts that
    # target the FreeSDN host's loopback or cloud metadata endpoints
    # (matches the central GatewayServiceBase enforcement).
    GatewayServiceBase._validate_controller_host(controller.host or "")

    kwargs: dict[str, Any] = {
        "port": controller.port,
        "use_ssl": controller.use_ssl,
        "verify_ssl": controller.verify_ssl,
        "mode": controller.connection_mode,
    }
    if controller.connection_mode == "cloud":
        kwargs.update(
            {
                "client_id": controller.client_id or "",
                "client_secret": _decrypt_if_needed(controller.client_secret),
                "omada_id": controller.omada_id or "",
                "cloud_region": controller.cloud_region or "",
            }
        )

    # Proxmox API token auth
    if controller.type.lower() == "proxmox":
        token_id = (controller.config or {}).get("token_id", "")
        if token_id:
            kwargs["token_id"] = token_id
            kwargs["token_secret"] = _decrypt_if_needed(
                (controller.config or {}).get("token_secret")
            )
        kwargs["realm"] = (controller.config or {}).get("realm", "pam")

    # TrueNAS authenticates with an API key (Bearer). The generic onboarding
    # form has no api_key field, so the operator enters their (ideally
    # read-only) API key in the password field; map it to the adapter's
    # api_key kwarg here.
    if controller.type.lower() == "truenas":
        kwargs["api_key"] = _decrypt_if_needed(controller.password)

    adapter = adapter_registry.create_adapter(
        adapter_id=controller.type.lower(),
        host=controller.host,
        username=controller.username or "",
        password=_decrypt_if_needed(controller.password),
        **kwargs,
    )

    # the Omada adapter defaults its active site to the FIRST
    # discovered upstream site (_ensure_site_id -> sites[0]). For a site-limited
    # caller a controller's site_mappings can expose UPSTREAM sites bound to
    # sibling FreeSDN sites they were NOT granted — even though they legitimately
    # reached the controller via its primary site. Pin the adapter to a single
    # grant-bounded upstream site, or REJECT when it cannot be proven scoped.
    # No-op for super_admin / org_admin / grant-less callers (whole-org access).
    if getattr(current_user, "is_site_limited", False) and hasattr(adapter, "set_active_site"):
        mappings = controller.site_mappings or {}
        granted = current_user.accessible_site_ids or set()
        reachable = [
            omada_sid
            for omada_sid, freesdn_uuid in mappings.items()
            if _as_uuid(freesdn_uuid) in granted
        ]
        if len(reachable) == 1:
            adapter.set_active_site(reachable[0])
        else:
            # exactly-one granted upstream site is the only case we can
            # pin. Zero reachable — including EMPTY site_mappings, where the Omada
            # adapter would otherwise default to the FIRST discovered upstream
            # site that cannot be proven to match this caller's grant — or more
            # than one (ambiguous) means the live aggregate cannot be confined to
            # a single granted site, so refuse it.
            raise HTTPException(
                status_code=403,
                detail=(
                    "This controller's live data cannot be confined to your "
                    "granted site; an operator must map the controller's sites"
                ),
            )
    return controller, adapter


# Error codes an adapter uses to signal "this operation isn't supported by
# this vendor" (vs. a genuine communication failure). The BaseAdapter
# ``__getattr__`` stub returns ``AdapterResult.fail(error_code="NOT_SUPPORTED")``
# for any unimplemented ``get_*``/``update_*``/... method, so a missing
# adapter method surfaces here rather than as an AttributeError.
_UNSUPPORTED_ERROR_CODES = frozenset({"NOT_SUPPORTED", "NOT_IMPLEMENTED"})


# FSDN-AUDIT: these direct controller config-write endpoints push live state
# (RADIUS shared secrets, 802.1X, hotspot/captive-portal, site radio, vouchers,
# backups) on a non-staged path, so they don't get the staging service's
# durable AuditLogRecord. Emit a dedicated security-channel audit line on every
# such mutation so the write is attributable. The payload is NEVER logged
# verbatim (shared secrets must not land in logs) — only the actor, controller,
# and the operation name are recorded.
_config_write_audit_log = logging.getLogger("freesdn.security.controller_write")


def _audit_config_write(operation: str, controller_id: UUID, current_user: CurrentUser) -> None:
    """Record an attributable security-audit line for a live config write.

    Deliberately logs no request body / secret material — just who did what to
    which controller — so the trail is safe to retain.
    """
    _config_write_audit_log.warning(
        "CONTROLLER_CONFIG_WRITE op=%s controller=%s actor=%s",
        operation,
        controller_id,
        getattr(getattr(current_user, "user", None), "email", "?"),
    )


def _raise_for_adapter_result(result: Any, controller_type: str) -> None:
    """Raise the right HTTP error for a failed adapter result.

    NOT_SUPPORTED keeps the controller-typed 501 message; every other failure
    delegates to the central error_code->HTTP mapper so callers get finer,
    correct codes (404 not-found, 504 timeout, 429 rate-limit, 403 read-only/
    policy, 400 validation) instead of a flat 502.

    Does nothing when the result indicates success; callers extract the
    value as before.
    """
    if getattr(result, "success", True):
        return
    if getattr(result, "error_code", None) in _UNSUPPORTED_ERROR_CODES:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller_type} controller",
        )
    from app.core.adapter_result import raise_for_adapter_result

    raise_for_adapter_result(result)


# ===========================================
# List Controllers
# ===========================================


@router.get("/", response_model=PaginatedResponse[ControllerResponse])
async def list_controllers(
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
    controller_type: str | None = None,
    status: str | None = None,
    is_active: bool | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
) -> Any:
    """
    List controllers with filtering and pagination.

    Filters:
    - site_id: Filter by site
    - controller_type: Filter by type (omada, unifi, etc.)
    - status: Filter by connection status
    - is_active: Filter by active status
    """
    # ── Subqueries for device counts ──────────────────────────────────
    # per-controller device counts must be bounded by the caller's
    # site grant — a controller can carry devices in sibling sites. The filter
    # is true() (no-op) for admins, Device.site_id IN(grants) otherwise.
    _dev_scope = site_scope_filter(current_user, Device.site_id)
    device_total_sq = (
        select(
            Device.controller_id,
            func.count(Device.id).label("device_count"),
        )
        .where(Device.deleted_at.is_(None), _dev_scope)
        .group_by(Device.controller_id)
        .subquery()
    )
    device_online_sq = (
        select(
            Device.controller_id,
            func.count(Device.id).label("online_device_count"),
        )
        .where(
            Device.deleted_at.is_(None),
            Device.status == DeviceStatus.ONLINE,
            _dev_scope,
        )
        .group_by(Device.controller_id)
        .subquery()
    )

    # Build base query with device counts
    query = (
        select(
            Controller,
            func.coalesce(device_total_sq.c.device_count, literal(0)).label("device_count"),
            func.coalesce(device_online_sq.c.online_device_count, literal(0)).label(
                "online_device_count"
            ),
        )
        .outerjoin(device_total_sq, device_total_sq.c.controller_id == Controller.id)
        .outerjoin(device_online_sq, device_online_sq.c.controller_id == Controller.id)
        .where(Controller.deleted_at.is_(None))
    )

    # Apply tenant scoping (org via Site + per-user site grant) in one call.
    # tenant_filter emits `site_id IN (sites in org)` AND the site grant for
    # via-site Controller; equivalent to the prior Site-join + site_scope_filter.
    query = query.where(tenant_filter(Controller, current_user))

    # Apply filters
    if site_id:
        query = query.where(Controller.site_id == site_id)

    if controller_type:
        query = query.where(Controller.controller_type == controller_type)

    if status:
        query = query.where(Controller.status == status)

    if is_active is not None:
        query = query.where(Controller.is_active == is_active)

    # Get total count (from a stripped subquery without device columns)
    count_base = select(Controller.id).where(Controller.deleted_at.is_(None))
    count_base = count_base.where(tenant_filter(Controller, current_user))
    if site_id:
        count_base = count_base.where(Controller.site_id == site_id)
    if controller_type:
        count_base = count_base.where(Controller.controller_type == controller_type)
    if status:
        count_base = count_base.where(Controller.status == status)
    if is_active is not None:
        count_base = count_base.where(Controller.is_active == is_active)
    total = await session.scalar(select(func.count()).select_from(count_base.subquery())) or 0

    # Apply pagination
    query = query.offset((page - 1) * per_page).limit(per_page)
    query = query.order_by(Controller.name)

    rows = (await session.execute(query)).all()

    # Build response items with device counts attached
    items = []
    for controller, dev_count, online_count in rows:
        resp = ControllerResponse.model_validate(controller, from_attributes=True)
        resp.device_count = dev_count
        resp.online_device_count = online_count
        items.append(resp)

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page,
    )


# ===========================================
# Get Single Controller
# ===========================================


@router.get("/{controller_id}", response_model=ControllerWithStats)
async def get_controller(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a single controller by ID with stats."""
    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Controller not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if (
            not controller.site
            or controller.site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this controller",
            )

    # Compute device counts from the devices table (grant-scoped)
    _dev_filter = _controller_device_filter(controller_id, current_user)
    dev_count = await session.scalar(select(func.count(Device.id)).where(_dev_filter)) or 0
    online_count = (
        await session.scalar(
            select(func.count(Device.id)).where(
                _dev_filter,
                Device.status == DeviceStatus.ONLINE,
            )
        )
        or 0
    )

    return ControllerWithStats(
        **controller.__dict__,
        device_count=dev_count,
        online_device_count=online_count,
    )


# ===========================================
# Create Controller
# ===========================================


@router.post("/", response_model=ControllerResponse, status_code=status.HTTP_201_CREATED)
async def create_controller(
    controller_data: ControllerCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:create"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    background_tasks: BackgroundTasks = None,  # type: ignore[assignment]
    confirm_public_host: bool = Query(
        False,
        description=(
            "Acknowledge that this controller's host is a PUBLIC address and its "
            "stored credentials may be sent there (local-mode controllers)."
        ),
    ),
) -> Any:
    """
    Create a new controller.

    The controller will be created with credentials stored securely.
    Initial connection test is performed automatically.
    """
    # Verify site exists and user has access
    site_result = await session.execute(
        select(Site).where(Site.id == controller_data.site_id, Site.deleted_at.is_(None))
    )
    site = site_result.scalar_one_or_none()

    if not site:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Site not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user) and (
        site.organization_id != current_user.organization_id
        or not current_user.can_access_site(site.id)  # site grant
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this site",
        )

    # validate any site_mappings TARGET sites are in-org AND granted to
    # the caller, BEFORE persisting — otherwise a site-limited operator could
    # bind upstream sites to sibling sites they cannot access.
    await _assert_mapping_targets_accessible(
        session,
        controller_data.site_mappings,
        site.organization_id,
        current_user,
    )

    # SSRF protection: validate controller host
    from app.core.security_utils import validate_target_host

    try:
        validate_target_host(controller_data.host)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid controller host: {e}",
        )

    # F1: a local-mode controller's stored credentials are replayed to its host on
    # every later test/sync/op. Allow a PUBLIC host (e.g. a remote-site controller
    # reachable over the internet) only with an explicit confirmation, and audit it.
    # Private/on-prem and cloud-mode controllers are unaffected (no friction).
    _public_ip = _local_controller_public_host(
        controller_data.host, controller_data.connection_mode
    )
    if _public_ip and not confirm_public_host:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This controller's host resolves to a PUBLIC address; its stored "
                "credentials would be sent there. Resubmit with confirm_public_host=true "
                "to allow a public-internet controller."
            ),
        )
    if _public_ip:
        logger.warning(
            "AUDIT: controller %r created with stored-credential egress to PUBLIC "
            "host %s (confirmed by %s)",
            controller_data.name,
            _public_ip,
            getattr(current_user.user, "email", "?"),
        )

    # Atomic tier-quota check (SELECT FOR UPDATE on org row, close TOCTOU).
    # Controllers are counted via Site join inside the service.
    from app.services.organization import OrganizationService

    org_svc = OrganizationService(session)
    await org_svc._check_quota(site.organization_id, "controllers")

    # Create controller
    controller = Controller(
        site_id=controller_data.site_id,
        name=controller_data.name,
        description=controller_data.description,
        controller_type=controller_data.controller_type,
        host=controller_data.host,
        port=controller_data.port,
        use_ssl=controller_data.use_ssl,
        verify_ssl=controller_data.verify_ssl,
        config=controller_data.config,
        sync_enabled=controller_data.sync_enabled,
        sync_interval_seconds=controller_data.sync_interval_seconds,
        status=ControllerStatus.UNKNOWN,
    )

    # Store credentials and mode-specific config in JSONB config column
    config = {**controller.config}
    config["connection_mode"] = controller_data.connection_mode or "local"

    # Store site mappings if provided
    if controller_data.site_mappings:
        config["site_mappings"] = controller_data.site_mappings

    if controller_data.connection_mode == "cloud":
        # Cloud mode: OAuth2 credentials
        config["client_id"] = controller_data.client_id
        config["client_secret"] = (
            encrypt_credential(controller_data.client_secret)
            if controller_data.client_secret
            else None
        )
        config["omada_id"] = controller_data.omada_id
        config["cloud_region"] = controller_data.cloud_region
    elif controller_data.controller_type == "proxmox":
        # Proxmox: API token auth OR username/password
        if controller_data.config.get("token_id"):
            config["token_id"] = controller_data.config["token_id"]
            config["token_secret"] = (
                encrypt_credential(controller_data.config["token_secret"])
                if controller_data.config.get("token_secret")
                else None
            )
        if controller_data.username:
            config["username"] = controller_data.username
            config["password"] = (
                encrypt_credential(controller_data.password) if controller_data.password else None
            )
        config["realm"] = controller_data.config.get("realm", "pam")
    else:
        # Local mode: username/password
        config["username"] = controller_data.username
        config["password"] = (
            encrypt_credential(controller_data.password) if controller_data.password else None
        )

    controller.config = config

    session.add(controller)
    await session.commit()
    await session.refresh(controller)

    # Schedule an initial connection test in the background so the create
    # response returns immediately while the controller is being probed.
    async def _initial_connection_test(controller_id: UUID) -> None:
        from app.adapters.registry import adapter_registry
        from app.db import async_session_factory

        async with async_session_factory() as bg_session:
            stmt = select(Controller).where(
                Controller.id == controller_id,
                Controller.deleted_at.is_(None),
            )
            row = await bg_session.execute(stmt)
            ctrl = row.scalar_one_or_none()
            if not ctrl:
                return

            mode = (ctrl.config or {}).get("connection_mode", "local")
            kwargs: dict[str, Any] = {
                "port": ctrl.port,
                "use_ssl": ctrl.use_ssl,
                "verify_ssl": ctrl.verify_ssl,
                "mode": mode,
            }
            if mode == "cloud":
                kwargs.update(
                    client_id=(ctrl.config or {}).get("client_id", ""),
                    client_secret=_decrypt_if_needed((ctrl.config or {}).get("client_secret")),
                    omada_id=(ctrl.config or {}).get("omada_id", ""),
                    cloud_region=(ctrl.config or {}).get("cloud_region", ""),
                )

            # Proxmox API token auth
            if ctrl.controller_type == "proxmox":
                token_id = (ctrl.config or {}).get("token_id", "")
                if token_id:
                    kwargs["token_id"] = token_id
                    kwargs["token_secret"] = _decrypt_if_needed(
                        (ctrl.config or {}).get("token_secret")
                    )
                kwargs["realm"] = (ctrl.config or {}).get("realm", "pam")

            # TrueNAS API-key (Bearer): operator enters the key in the password
            # field; map it to the adapter's api_key kwarg.
            if ctrl.controller_type == "truenas":
                kwargs["api_key"] = _decrypt_if_needed((ctrl.config or {}).get("password"))

            try:
                adapter = adapter_registry.create_adapter(
                    adapter_id=ctrl.controller_type.lower(),
                    host=ctrl.host,
                    username=_decrypt_if_needed((ctrl.config or {}).get("username")),
                    password=_decrypt_if_needed((ctrl.config or {}).get("password")),
                    **kwargs,
                )
                async with adapter:
                    test_result = await adapter.test_connection()

                success = bool(getattr(test_result, "success", False))
                ctrl.status = (
                    ControllerStatus.CONNECTED if success else ControllerStatus.DISCONNECTED
                )
                ctrl.last_error = (
                    None
                    if success
                    else (getattr(test_result, "error", None) or "Connection test failed")
                )
                logger.info(
                    "Initial connection test for controller %s: %s",
                    controller_id,
                    "success" if success else ctrl.last_error,
                )
            except Exception as exc:
                ctrl.status = ControllerStatus.ERROR
                # Strip URL fragments before persist — see /test handler.
                import re as _re

                ctrl.last_error = _re.sub(r"https?://\S+", "<redacted-url>", str(exc))[:500]
                success = False
                logger.warning(
                    "Initial connection test failed for controller %s: %s",
                    controller_id,
                    exc,
                )
            await bg_session.commit()

            # On successful connection, trigger immediate device discovery
            if success:
                from app.tasks.discovery import discover_devices_for_controller

                discover_devices_for_controller.apply_async(
                    args=[str(controller_id)],
                    countdown=3,
                    queue="discovery",
                )

    if background_tasks is not None:
        background_tasks.add_task(_initial_connection_test, controller.id)
    else:
        # Fallback: run inline if BackgroundTasks not injected (e.g. tests).
        # add_done_callback so any uncaught exception in the connect-test
        # task surfaces in logs rather than being silently swallowed
        # (orphan-task hygiene).
        import asyncio

        def _on_done(task: asyncio.Task[Any]) -> None:
            if task.cancelled():
                return
            exc = task.exception()
            if exc is not None:
                logger.warning(
                    "Initial connection test orphan task failed: %s",
                    exc,
                )

        _t = asyncio.ensure_future(_initial_connection_test(controller.id))
        _t.add_done_callback(_on_done)

    return controller


# ===========================================
# Update Controller
# ===========================================


@router.patch("/{controller_id}", response_model=ControllerResponse)
async def update_controller(
    controller_id: UUID,
    controller_data: ControllerUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    confirm_public_host: bool = Query(
        False,
        description=(
            "Acknowledge that this controller's host is a PUBLIC address and its "
            "stored credentials may be sent there (local-mode controllers)."
        ),
    ),
) -> Any:
    """Update an existing controller."""
    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Controller not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if (
            not controller.site
            or controller.site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this controller",
            )

    # Update fields
    update_data = controller_data.model_dump(exclude_unset=True)

    # Separate cloud/config fields from direct model columns.
    # ``username`` and ``password`` live in JSONB ``config`` (local-mode
    # creds); previously they weren't in ``config_keys`` so PATCH
    # silently dropped them and credentials were immutable post-creation.
    config_keys = {
        "connection_mode",
        "client_id",
        "client_secret",
        "omada_id",
        "cloud_region",
        "site_mappings",
        "username",
        "password",
    }
    config_updates = {k: v for k, v in update_data.items() if k in config_keys}
    model_updates = {k: v for k, v in update_data.items() if k not in config_keys}

    # if this PATCH sets site_mappings, validate every TARGET site is
    # in-org AND granted to the caller before it reaches the DB. The parent
    # controller's own site is already grant-checked above; mapped sibling
    # sites were previously merged in unchecked.
    if "site_mappings" in config_updates and controller.site is not None:
        await _assert_mapping_targets_accessible(
            session,
            config_updates["site_mappings"],
            controller.site.organization_id,
            current_user,
        )

    # SECURITY: validate host against SSRF before updating
    if "host" in model_updates and model_updates["host"]:
        from app.core.security_utils import validate_target_host

        try:
            validate_target_host(model_updates["host"])
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid host: {e}",
            )

        # F1: changing a local-mode controller's host to a PUBLIC address would
        # silently re-point its STORED credentials there. Require an explicit
        # confirmation + audit it. The mode is the incoming one if being changed,
        # else the controller's existing mode.
        _new_mode = config_updates.get("connection_mode") or controller.connection_mode
        _public_ip = _local_controller_public_host(model_updates["host"], _new_mode)
        if _public_ip and not confirm_public_host:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Changing this controller's host to a PUBLIC address would send its "
                    "stored credentials there. Resubmit with confirm_public_host=true "
                    "to allow a public-internet controller."
                ),
            )
        if _public_ip:
            logger.warning(
                "AUDIT: controller %s host changed to PUBLIC %s with stored-credential "
                "egress (confirmed by %s)",
                controller.id,
                _public_ip,
                getattr(current_user.user, "email", "?"),
            )

    # SECURITY: whitelist of safe model fields to prevent mass assignment
    # (blocks overwriting id, deleted_at, site_id, raw config, etc.)
    _SAFE_MODEL_FIELDS = {
        "name",
        "description",
        "host",
        "port",
        "use_ssl",
        "verify_ssl",
        "sync_enabled",
        "sync_interval_seconds",
        "is_active",
    }
    for field, value in model_updates.items():
        if field not in _SAFE_MODEL_FIELDS:
            continue
        setattr(controller, field, value)

    # Merge cloud + local-credential fields into config JSONB.
    # Sensitive values are re-encrypted on each write. Empty-string
    # ``password=""`` is treated as "no change requested" rather than
    # "clear the secret" so a UI form that defaults to "" doesn't wipe
    # the stored credential on every save.
    if config_updates:
        if "client_secret" in config_updates and config_updates["client_secret"]:
            config_updates["client_secret"] = encrypt_credential(config_updates["client_secret"])
        elif "client_secret" in config_updates and not config_updates["client_secret"]:
            config_updates.pop("client_secret")
        if "password" in config_updates and config_updates["password"]:
            config_updates["password"] = encrypt_credential(config_updates["password"])
        elif "password" in config_updates and not config_updates["password"]:
            config_updates.pop("password")
        merged = {**(controller.config or {}), **config_updates}
        controller.config = merged

    await session.commit()
    await session.refresh(controller)

    # Pool eviction: any cached adapter for this controller may now be
    # pointing at stale host / port / credentials. Mark unhealthy so the
    # cleanup loop swaps in a fresh adapter on the next request.
    try:
        from app.adapters.pool import adapter_pool

        adapter_pool.invalidate_controller(str(controller_id))
    except Exception:
        pass

    return controller


# ===========================================
# Delete Controller
# ===========================================


@router.delete("/{controller_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_controller(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:delete"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """
    Soft-delete a controller.

    Associated devices will also be deleted.
    """
    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Controller not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if (
            not controller.site
            or controller.site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this controller",
            )

    # Soft-delete associated devices so they don't become orphans
    now = datetime.now(UTC)
    device_result = await session.execute(
        select(Device).where(
            Device.controller_id == controller_id,
            Device.deleted_at.is_(None),
        )
    )
    for device in device_result.scalars().all():
        device.deleted_at = now

    # Soft delete the controller
    controller.deleted_at = now
    await session.commit()

    # Pool eviction: mark every shared adapter for this controller as
    # unhealthy so the cleanup loop closes the underlying httpx client.
    # Prevents future requests from hitting a stale cached client that
    # points at a deleted-row's credentials.
    try:
        from app.adapters.pool import adapter_pool

        adapter_pool.invalidate_controller(str(controller_id))
    except Exception:
        pass

    return None


# ===========================================
# Controller Actions
# ===========================================


def _build_error_hint(exc: Exception, mode: str | None = "local") -> str:
    """Return an actionable error message based on the exception type."""
    from app.adapters.exceptions import (
        AdapterAuthenticationError,
        AdapterConnectionError,
    )
    from app.adapters.omada.exceptions import (
        OmadaAuthError,
        OmadaConnectionError,
        OmadaTimeoutError,
    )

    if isinstance(exc, (AdapterAuthenticationError, OmadaAuthError)):
        if mode == "cloud":
            return (
                "Authentication failed with the cloud API. "
                "Verify your Client ID, Client Secret, and Omada Controller ID are correct."
            )
        return (
            "Authentication failed. "
            "Verify your username and password are correct and the account has admin privileges."
        )
    if isinstance(exc, (AdapterConnectionError, OmadaConnectionError)):
        if mode == "cloud":
            return (
                "Cannot reach the cloud endpoint. "
                "Check the cloud region and ensure outbound HTTPS (port 443) is not blocked."
            )
        return (
            "Cannot reach the controller. "
            "Verify the host address, port, and that the controller is running. "
            "If using HTTPS with a self-signed certificate, disable 'Verify SSL'."
        )
    if isinstance(exc, OmadaTimeoutError):
        return "Connection timed out. The controller may be overloaded or unreachable."

    # Proxmox-specific errors
    from app.adapters.proxmox.client import ProxmoxApiError

    if isinstance(exc, ProxmoxApiError):
        status_code = getattr(exc, "status_code", None)
        if status_code == 401:
            return (
                "Proxmox authentication failed. "
                "If using API Token, verify the Token ID (user@realm!token-name) and Token Secret. "
                "If using username/password, check credentials and realm (pam/pve)."
            )
        if status_code == 403:
            return (
                "Proxmox access denied. "
                "The user or API token lacks the required privileges. "
                "Ensure PVEAuditor or higher role is assigned."
            )
        return f"Proxmox API error ({status_code}): {exc}"

    logger.error("Unexpected controller error: %s", exc)
    return "An unexpected error occurred. Check server logs for details."


@router.post("/{controller_id}/test")
async def test_controller_connection(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """
    Test the connection to a controller.

    Returns connection status and any error messages.
    """
    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Controller not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if (
            not controller.site
            or controller.site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this controller",
            )

    from app.adapters.registry import adapter_registry

    kwargs: dict[str, Any] = {
        "port": controller.port,
        "use_ssl": controller.use_ssl,
        "verify_ssl": controller.verify_ssl,
        "mode": controller.connection_mode,
    }
    if controller.connection_mode == "cloud":
        kwargs.update(
            {
                "client_id": controller.client_id or "",
                "client_secret": _decrypt_if_needed(controller.client_secret),
                "omada_id": controller.omada_id or "",
                "cloud_region": controller.cloud_region or "",
            }
        )

    # Proxmox API token auth
    if controller.type.lower() == "proxmox":
        token_id = (controller.config or {}).get("token_id", "")
        if token_id:
            kwargs["token_id"] = token_id
            kwargs["token_secret"] = _decrypt_if_needed(
                (controller.config or {}).get("token_secret")
            )
        kwargs["realm"] = (controller.config or {}).get("realm", "pam")

    try:
        adapter = adapter_registry.create_adapter(
            adapter_id=controller.type.lower(),
            host=controller.host,
            username=controller.username or "",
            password=_decrypt_if_needed(controller.password),
            **kwargs,
        )
        t0 = time.monotonic()
        async with adapter:
            test_result = await adapter.test_connection()
        latency_ms = round((time.monotonic() - t0) * 1000)

        success = bool(getattr(test_result, "success", False))
        controller.status = ControllerStatus.CONNECTED if success else ControllerStatus.DISCONNECTED
        controller.last_error = (
            None
            if success
            else (getattr(test_result, "error", None) or getattr(test_result, "message", None))
        )
        await session.commit()

        # Build details from adapter test result data
        result_data = getattr(test_result, "data", None) or {}
        details = {
            "latency_ms": latency_ms,
            "controller_version": result_data.get("controller_version")
            or result_data.get("version"),
            "controller_name": result_data.get("controller_name") or controller.name,
            "mode": result_data.get("mode") or controller.connection_mode,
        }

        return {
            "success": success,
            "message": getattr(test_result, "message", None)
            or ("Connection successful" if success else "Connection failed"),
            "controller_id": str(controller_id),
            "status": controller.status,
            "error": getattr(test_result, "error", None),
            "details": details,
        }
    except Exception as exc:
        controller.status = ControllerStatus.DISCONNECTED
        # ``str(exc)`` from httpx / asyncpg / adapter layers often
        # embeds the full controller URL plus auth fragments. Strip
        # URLs and cap length before persisting to ``last_error``
        # since it surfaces in ``/stats`` and the FE detail view.
        import re as _re

        controller.last_error = _re.sub(r"https?://\S+", "<redacted-url>", str(exc))[:500]
        await session.commit()

        # Provide actionable error hints
        error_hint = _build_error_hint(exc, controller.connection_mode)

        return {
            "success": False,
            "message": "Connection test failed",
            "controller_id": str(controller_id),
            "status": controller.status,
            "error": error_hint,
            "details": {
                "controller_name": controller.name,
                "mode": controller.connection_mode,
            },
        }


@router.post("/{controller_id}/sync")
async def sync_controller(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """
    Trigger a manual sync for a controller.

    This will fetch all devices and update the database.
    Tries Celery first; falls back to a FastAPI background task.
    """
    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Controller not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if (
            not controller.site
            or controller.site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this controller",
            )

    # Update status to syncing
    controller.status = ControllerStatus.SYNCING
    await session.commit()

    # Controller types whose DEVICES are materialized by a module's
    # DeviceSource (not the generic discovery path). For these, a manual
    # sync must also kick the module device-sync so the device appears
    # on demand instead of waiting for the 15-min periodic safety-net.
    # proxmox → hypervisor module (ProxmoxNode → Device with IP).
    _MODULE_OWNED_CONTROLLER_MODULE = {"proxmox": "hypervisor"}
    owning_module = _MODULE_OWNED_CONTROLLER_MODULE.get(
        str(getattr(controller.controller_type, "value", controller.controller_type)),
    )

    # Try Celery first, fall back to in-process background task
    task_id: str | None = None
    try:
        from app.tasks.discovery import discover_devices_for_controller

        result_obj = discover_devices_for_controller.delay(str(controller_id))
        task_id = result_obj.id
        # Materialize module-owned devices (e.g. Proxmox nodes) on demand.
        if owning_module:
            try:
                from app.tasks.sync import sync_module_incremental

                sync_module_incremental.delay(owning_module)
            except Exception:
                logger.debug("Could not enqueue module sync for %s", owning_module)
    except Exception:
        # Celery unavailable — run inline via FastAPI BackgroundTasks
        from app.tasks.discovery import _discover_devices_for_controller

        async def _run_discovery() -> None:
            await _discover_devices_for_controller(str(controller_id))
            if owning_module:
                from app.tasks.sync import _sync_module_incremental

                await _sync_module_incremental(owning_module)

        # Pass the coroutine FUNCTION (not a pre-created coroutine wrapped in
        # ensure_future): Starlette awaits an async background func directly on
        # the event loop after the response. The old
        # `add_task(asyncio.ensure_future, _run_discovery())` ran ensure_future
        # in a worker THREAD with no event loop → RuntimeError, so the fallback
        # discovery silently never ran.
        background_tasks.add_task(_run_discovery)

    return {
        "success": True,
        "message": "Sync started",
        "controller_id": str(controller_id),
        **({"task_id": task_id} if task_id else {}),
    }


# ===========================================
# Controller Stats
# ===========================================


@router.get("/{controller_id}/stats")
async def get_controller_stats(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Get detailed statistics for a controller."""
    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Controller not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if (
            not controller.site
            or controller.site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this controller",
            )

    # Compute real stats from the devices table (grant-scoped)
    _dev_filter = _controller_device_filter(controller_id, current_user)
    dev_count = await session.scalar(select(func.count(Device.id)).where(_dev_filter)) or 0
    online_count = (
        await session.scalar(
            select(func.count(Device.id)).where(
                _dev_filter,
                Device.status == DeviceStatus.ONLINE,
            )
        )
        or 0
    )
    return {
        "controller_id": str(controller_id),
        "device_count": dev_count,
        "online_device_count": online_count,
        "offline_device_count": dev_count - online_count,
        "last_sync": controller.last_sync.isoformat() if controller.last_sync else None,
        "status": controller.status,
        "uptime_percent": 0.0,
    }


# ===========================================
# Controller Metadata (aggregated device data)
# ===========================================


@router.get("/{controller_id}/capabilities")
async def get_controller_capabilities(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Return the adapter manifest's advertised capabilities.

    Used by the frontend to hide tabs/buttons for features the
    backing adapter doesn't support. The shape is a flat list of
    capability codes plus the per-device-type breakdown so the UI
    can scope (e.g. show "WIDS/WIPS" only when the access_point
    device type advertises ``wifi.wids_wips``).
    """
    from app.adapters.registry import get_adapter_registry

    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()
    if not controller:
        raise HTTPException(status_code=404, detail="Controller not found")
    if not is_unscoped_superuser(current_user) and (
        not controller.site
        or controller.site.organization_id != current_user.organization_id
        or not current_user.can_access_site(controller.site_id)
    ):
        raise HTTPException(status_code=403, detail="Access denied")

    registry = get_adapter_registry()
    if not registry.has_adapter(controller.controller_type):
        return {
            "controller_id": controller_id,
            "adapter_id": controller.controller_type,
            "capabilities": [],
            "by_device_type": {},
        }
    manifest = registry.get_manifest(controller.controller_type)

    # Flatten all caps into a single set so the UI can do
    # ``capabilities.includes("wifi.wids_wips")`` without descending
    # device types.
    flat: set[str] = set()
    by_device_type: dict[str, list[str]] = {}
    for dtype, dtcap in (manifest.device_types or {}).items():
        codes = [str(c) for c in (dtcap.capabilities or [])]
        by_device_type[dtype] = codes
        flat.update(codes)

    return {
        "controller_id": controller_id,
        "adapter_id": manifest.id,
        "adapter_name": manifest.name,
        "vendor": manifest.vendor,
        "version": manifest.version,
        "supported_versions": list(manifest.supported_versions or []),
        "capabilities": sorted(flat),
        "by_device_type": by_device_type,
        "auth_methods": list(manifest.auth_methods or []),
        "supports_bulk_operations": bool(manifest.supports_bulk_operations),
    }


@router.get("/{controller_id}/metadata")
async def get_controller_metadata(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """
    Get enriched controller metadata: device breakdown, PoE budget,
    firmware status, controller health, client count, quick device list.
    """
    from app.models.devices import DeviceClient, DeviceType

    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(status_code=404, detail="Controller not found")

    if not is_unscoped_superuser(current_user):
        if (
            not controller.site
            or controller.site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            raise HTTPException(status_code=403, detail="Access denied")

    # Device counts by type (grant-scoped — bounds the whole metadata
    # aggregate, since type_counts / client_count / PoE / firmware / quick-list
    # all derive from this device set).
    devices_result = await session.execute(
        select(Device).where(_controller_device_filter(controller_id, current_user))
    )
    devices = devices_result.scalars().all()

    total = len(devices)
    online = sum(1 for d in devices if d.status == DeviceStatus.ONLINE)
    type_counts: dict[str, int] = {}
    for d in devices:
        dt = d.device_type or "unknown"
        type_counts[dt] = type_counts.get(dt, 0) + 1

    # Client count (via DeviceClient records, fallback to device_metadata)
    device_ids = [d.id for d in devices]
    client_count = 0
    if device_ids:
        client_count = (
            await session.scalar(
                select(func.count(DeviceClient.id)).where(
                    DeviceClient.device_id.in_(device_ids),
                    DeviceClient.is_online.is_(True),
                )
            )
            or 0
        )
    # Fallback: sum client_count from device_metadata (set by Omada clientNum)
    if not client_count:
        client_count = sum((d.device_metadata or {}).get("client_count", 0) or 0 for d in devices)

    # PoE budget aggregate from device_metadata
    poe_budget_total = 0.0
    poe_consumed_total = 0.0
    poe_switches = 0
    for d in devices:
        meta = d.device_metadata or {}
        budget = meta.get("poe_budget_watts") or meta.get("poeTotalPower")
        if budget:
            poe_budget_total += float(budget)
            consumed = (
                meta.get("poe_consumed_watts")
                or meta.get("poeConsumedPower")
                or meta.get("poeConsumption")
                or 0
            )
            poe_consumed_total += float(consumed)
            poe_switches += 1

    # Firmware status
    fw_up_to_date = 0
    fw_needs_upgrade = 0
    fw_devices = []
    for d in devices:
        meta = d.device_metadata or {}
        fw = meta.get("firmware", {})
        if fw:
            needs = fw.get("needs_upgrade", False)
            if needs:
                fw_needs_upgrade += 1
            else:
                fw_up_to_date += 1
            fw_devices.append(
                {
                    "mac": d.mac_address,
                    "name": d.name,
                    "current": fw.get("current_version") or meta.get("firmware_version"),
                    "latest": fw.get("latest_version"),
                    "needs_upgrade": needs,
                }
            )

    # Quick device list (max 50)
    device_list = []
    for d in devices[:50]:
        meta = d.device_metadata or {}
        device_list.append(
            {
                "id": str(d.id),
                "name": d.name,
                "type": d.device_type,
                "status": d.status,
                "mac": d.mac_address,
                "ip": d.ip_address,
                "model": d.model,
                "firmware_version": meta.get("firmware_version"),
                "cpu_usage": meta.get("cpu_usage"),
                "memory_usage": meta.get("memory_usage"),
                "uptime": meta.get("uptime"),
                "poe_budget_watts": meta.get("poe_budget_watts") or meta.get("poeTotalPower"),
                "poe_consumed_watts": meta.get("poe_consumed_watts")
                or meta.get("poeConsumedPower"),
                "radios": meta.get("radios"),
                "clients": meta.get("clients"),
            }
        )

    config = controller.config or {}

    return {
        "controller_id": str(controller_id),
        "controller_name": controller.name,
        "controller_type": controller.controller_type,
        "status": controller.status,
        "runtime_status": config.get("runtime_status", {}),
        "device_counts": {
            "total": total,
            "online": online,
            "offline": total - online,
            "switches": type_counts.get(DeviceType.SWITCH, 0),
            "access_points": type_counts.get(DeviceType.ACCESS_POINT, 0),
            "gateways": type_counts.get(DeviceType.GATEWAY, 0)
            + type_counts.get(DeviceType.ROUTER, 0),
        },
        "client_count": client_count,
        "poe_budget": {
            "total_budget_watts": round(poe_budget_total, 1),
            "total_consumed_watts": round(poe_consumed_total, 1),
            "total_remaining_watts": round(poe_budget_total - poe_consumed_total, 1),
            "switches_with_poe": poe_switches,
        },
        "firmware": {
            "total_devices": len(fw_devices),
            "up_to_date": fw_up_to_date,
            "needs_upgrade": fw_needs_upgrade,
            "devices": fw_devices,
        },
        "sync": {
            "last_sync": controller.last_sync.isoformat() if controller.last_sync else None,
            "last_sync_duration_seconds": config.get("last_sync_duration_seconds"),
            "last_error": controller.last_error,
            "error_history": config.get("error_history", []),
        },
        # a site-limited caller must not see the full
        # {upstream_site: sibling_freesdn_uuid} map (it leaks sibling target site
        # UUIDs). Scope it the same way the remote-sites path does.
        "site_mappings": _scope_site_mappings(current_user, config.get("site_mappings", {})),
        "devices": device_list,
    }


# ===========================================
# Remote Sites (live fetch from controller)
# ===========================================


@router.get("/{controller_id}/remote-sites")
async def get_controller_remote_sites(
    controller_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """
    Fetch sites directly from the remote controller.

    Connects to the controller and returns its site list so the user
    can map them to FreeSdn sites.  Also returns any existing mappings.
    """
    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Controller not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if (
            not controller.site
            or controller.site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this controller",
            )

    # Build adapter kwargs
    from app.adapters.registry import adapter_registry

    kwargs: dict[str, Any] = {
        "port": controller.port,
        "use_ssl": controller.use_ssl,
        "verify_ssl": controller.verify_ssl,
    }
    if controller.connection_mode == "cloud":
        kwargs.update(
            {
                "mode": "cloud",
                "client_id": controller.client_id,
                "client_secret": _decrypt_if_needed(controller.client_secret),
                "omada_id": controller.omada_id,
                "cloud_region": controller.cloud_region,
            }
        )
    else:
        kwargs["mode"] = "local"

    try:
        adapter = adapter_registry.create_adapter(
            adapter_id=controller.type.lower(),
            host=controller.host,
            username=controller.username or "",
            password=_decrypt_if_needed(controller.password),
            **kwargs,
        )
        async with adapter:
            remote_sites = await adapter.get_sites()
    except Exception as e:
        # Don't leak raw controller-side exception text (httpx/asyncpg/adapter
        # layers embed full controller URLs + auth fragments) into the API
        # response. Log the full detail server-side; return an actionable hint
        # built from the exception TYPE only (mirrors _build_error_hint and the
        # URL-strip done in the /test handlers).
        logger.error(
            "get_controller_remote_sites: failed to fetch sites from controller %s: %s",
            controller_id,
            e,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Failed to fetch sites from controller '{controller.name}'. "
                f"{_build_error_hint(e, controller.connection_mode)}"
            ),
        )

    # Get internal FreeSdn sites for the user's org (for binding dropdown)
    if not controller.site:
        raise HTTPException(status_code=400, detail="Controller has no site assigned")
    org_id = controller.site.organization_id
    sites_result = await session.execute(
        select(Site)
        .where(
            Site.organization_id == org_id,
            Site.deleted_at.is_(None),
        )
        .order_by(Site.name)
    )
    # site-limited users only see their granted sites
    scoped = _scope_freesdn_sites_list(current_user, list(sites_result.scalars().all()))
    freesdn_sites = [{"id": str(s.id), "name": s.name} for s in scoped]

    return {
        "controller_id": str(controller_id),
        "remote_sites": remote_sites,
        "freesdn_sites": freesdn_sites,
        # scope existing mappings to the caller's granted target sites
        # so a site-limited operator can't enumerate sibling target sites via
        # the READ path (the WRITE path already validates targets).
        "current_mappings": _scope_site_mappings(current_user, controller.site_mappings),
    }


# ===========================================
# Site Mappings (persist bindings)
# ===========================================


@router.put("/{controller_id}/site-mappings")
async def update_controller_site_mappings(
    controller_id: UUID,
    mappings: dict[str, str],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """
    Save Omada-site → FreeSdn-site mappings for a controller.

    Body: ``{ "omada_site_id": "freesdn_site_uuid", ... }``
    """
    # Bare ``dict[str, str]`` body bypasses pydantic's per-field caps;
    # reuse the same validator the create/update schemas already apply
    # so 10 000-char keys / 5 000-entry payloads can't reach the DB.
    try:
        mappings = _validate_site_mappings(mappings) or {}
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    result = await session.execute(
        select(Controller)
        .options(selectinload(Controller.site))
        .where(Controller.id == controller_id, Controller.deleted_at.is_(None))
    )
    controller = result.scalar_one_or_none()

    if not controller:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Controller not found",
        )

    # Check organization access
    if not is_unscoped_superuser(current_user):
        if (
            not controller.site
            or controller.site.organization_id != current_user.organization_id
            or not current_user.can_access_site(controller.site_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this controller",
            )

    # Validate that all target FreeSdn site UUIDs exist in the same org AND
    # are granted to the caller: the parent controller's own site is
    # grant-checked above, but the mapped TARGET sites are sibling sites that
    # were previously validated only against organization_id — a site-limited
    # operator could bind upstream sites into siblings they cannot access.
    if not controller.site:
        raise HTTPException(status_code=400, detail="Controller has no site assigned")
    org_id = controller.site.organization_id
    await _assert_mapping_targets_accessible(session, mappings, org_id, current_user)

    # Persist in config JSONB
    controller.site_mappings = mappings
    await session.commit()
    await session.refresh(controller)

    return {
        "success": True,
        "controller_id": str(controller_id),
        "site_mappings": controller.site_mappings,
    }


# ===========================================
# Probe Remote Sites (pre-creation, no saved controller)
# ===========================================


@router.post("/probe-remote-sites")
async def probe_remote_sites(
    probe_data: ControllerProbe,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:create"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """
    Probe a controller for its sites before the controller is saved.

    Used during the Add Controller flow so the user can set up
    site mappings *before* committing the controller record.

    Body mirrors ControllerCreate fields needed to connect.
    """
    from app.adapters.registry import adapter_registry

    adapter_id = (probe_data.controller_type or probe_data.adapter_id or "").lower()
    if not adapter_id:
        raise HTTPException(status_code=400, detail="controller_type or adapter_id required")

    host = probe_data.host
    username = probe_data.username
    password = probe_data.password
    mode = probe_data.connection_mode

    kwargs: dict[str, Any] = {
        "port": probe_data.port,
        "use_ssl": probe_data.use_ssl,
        "verify_ssl": probe_data.verify_ssl,
        "mode": mode,
    }

    if mode == "cloud":
        kwargs["client_id"] = probe_data.client_id or ""
        kwargs["client_secret"] = probe_data.client_secret or ""
        kwargs["omada_id"] = probe_data.omada_id or ""
        kwargs["cloud_region"] = probe_data.cloud_region or ""
        if not host or host == "cloud":
            region = kwargs.get("cloud_region", "use1")
            host = f"{region}-omada-northbound.tplinkcloud.com"

    # Proxmox API token auth
    if adapter_id == "proxmox":
        if getattr(probe_data, "token_id", None):
            kwargs["token_id"] = probe_data.token_id
            kwargs["token_secret"] = getattr(probe_data, "token_secret", "") or ""
        if getattr(probe_data, "realm", None):
            kwargs["realm"] = probe_data.realm

    # TrueNAS authenticates with an API key (WS API_KEY_PLAIN). The generic
    # probe form has no api_key field, so the operator enters the key in the
    # password field; map it to the adapter's api_key kwarg (mirrors
    # _get_controller_and_adapter so the pre-save test matches the saved path).
    if adapter_id == "truenas":
        kwargs["api_key"] = password

    # SSRF protection: validate host before connecting
    from app.core.security_utils import validate_target_host

    try:
        validate_target_host(host)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        adapter = adapter_registry.create_adapter(
            adapter_id=adapter_id,
            host=host,
            username=username,
            password=password,
            **kwargs,
        )
    except Exception as e:
        logger.error("Failed to create adapter for '%s': %s", adapter_id, e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to create adapter. Verify that the controller type is supported.",
        )

    try:
        async with adapter:
            remote_sites = await adapter.get_sites()
    except Exception as e:
        # Build a diagnostic message based on the exception type
        from app.adapters.exceptions import (
            AdapterAuthenticationError,
            AdapterConnectionError,
        )
        from app.adapters.omada.exceptions import (
            OmadaAuthError,
            OmadaConnectionError,
            OmadaTimeoutError,
        )

        logger.error("Controller connection test failed: %s", e, exc_info=True)

        if isinstance(e, (AdapterAuthenticationError, OmadaAuthError)):
            if mode == "cloud":
                hint = (
                    "Authentication failed with the Omada Cloud API. "
                    "Please verify: (1) Client ID and Client Secret are correct and belong to an active OpenAPI application, "
                    "(2) The Omada Controller ID (omadacId) matches your cloud controller, "
                    "(3) The selected cloud region matches your controller's region. "
                    "You can find these in Omada Settings, Platform Integration, OpenAPI."
                )
            else:
                hint = (
                    "Authentication failed with the local Omada controller. "
                    "Please verify your username and password are correct. "
                    "Ensure the account has admin privileges (viewer accounts cannot access the API)."
                )
        elif isinstance(e, (AdapterConnectionError, OmadaConnectionError)):
            if mode == "cloud":
                hint = (
                    "Cannot reach the cloud endpoint. "
                    "Verify the cloud region is correct. "
                    "Also ensure outbound HTTPS (port 443) is not blocked by your firewall."
                )
            else:
                hint = (
                    "Cannot reach the Omada controller. "
                    "Verify the host address and port are correct and the controller is running. "
                    "If using HTTPS with a self-signed certificate, make sure 'Verify SSL' is disabled."
                )
        elif isinstance(e, OmadaTimeoutError):
            hint = (
                "The connection request timed out. "
                "The controller may be overloaded or unreachable. "
                "Check network connectivity and try again."
            )
        else:
            hint = "An unexpected error occurred. Check the backend logs for full details."

        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=hint,
        )

    # Also return org's FreeSdn sites for binding
    org_id = current_user.organization_id
    sites_result = await session.execute(
        select(Site)
        .where(
            Site.organization_id == org_id,
            Site.deleted_at.is_(None),
        )
        .order_by(Site.name)
    )
    # site-limited users only see their granted sites
    scoped = _scope_freesdn_sites_list(current_user, list(sites_result.scalars().all()))
    freesdn_sites = [{"id": str(s.id), "name": s.name} for s in scoped]

    return {
        "remote_sites": remote_sites,
        "freesdn_sites": freesdn_sites,
    }


# ===========================================
# Test Connection (pre-creation)
# ===========================================


@router.post("/test-connection")
async def test_connection_precreation(
    probe_data: ControllerProbe,
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:create"))],
) -> dict[str, Any]:
    """
    Test connectivity to a controller before saving it.

    Used from the Add Controller modal so the user can verify
    credentials and reachability without committing a record.
    Returns detailed results including latency and controller info.
    """
    from app.adapters.registry import adapter_registry

    adapter_id = (probe_data.controller_type or "").lower()
    if not adapter_id:
        raise HTTPException(status_code=400, detail="controller_type is required")

    host = probe_data.host
    username = probe_data.username
    password = probe_data.password
    mode = probe_data.connection_mode

    kwargs: dict[str, Any] = {
        "port": probe_data.port,
        "use_ssl": probe_data.use_ssl,
        "verify_ssl": probe_data.verify_ssl,
        "mode": mode,
    }

    if mode == "cloud":
        kwargs["client_id"] = probe_data.client_id or ""
        kwargs["client_secret"] = probe_data.client_secret or ""
        kwargs["omada_id"] = probe_data.omada_id or ""
        kwargs["cloud_region"] = probe_data.cloud_region or ""
        if not host or host == "cloud":
            region = kwargs.get("cloud_region", "use1")
            host = f"{region}-omada-northbound.tplinkcloud.com"

    # Proxmox API token auth
    if adapter_id == "proxmox":
        if getattr(probe_data, "token_id", None):
            kwargs["token_id"] = probe_data.token_id
            kwargs["token_secret"] = getattr(probe_data, "token_secret", "") or ""
        if getattr(probe_data, "realm", None):
            kwargs["realm"] = probe_data.realm

    # TrueNAS authenticates with an API key (WS API_KEY_PLAIN). The generic
    # probe form has no api_key field, so the operator enters the key in the
    # password field; map it to the adapter's api_key kwarg (mirrors
    # _get_controller_and_adapter so the pre-save test matches the saved path).
    if adapter_id == "truenas":
        kwargs["api_key"] = password

    # SSRF protection: validate host before connecting
    from app.core.security_utils import validate_target_host

    try:
        validate_target_host(host)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        adapter = adapter_registry.create_adapter(
            adapter_id=adapter_id,
            host=host,
            username=username,
            password=password,
            **kwargs,
        )
    except Exception as e:
        logger.error("Failed to create adapter for '%s': %s", adapter_id, e, exc_info=True)
        return {
            "success": False,
            "message": "Failed to create adapter. Verify that the controller type is supported.",
            "error": _build_error_hint(e, mode),
            "details": {"mode": mode},
        }

    try:
        t0 = time.monotonic()
        async with adapter:
            test_result = await adapter.test_connection()
        latency_ms = round((time.monotonic() - t0) * 1000)

        success = bool(getattr(test_result, "success", False))
        result_data = getattr(test_result, "data", None) or {}

        details = {
            "latency_ms": latency_ms,
            "controller_version": result_data.get("controller_version")
            or result_data.get("version"),
            "controller_name": result_data.get("controller_name"),
            "mode": result_data.get("mode") or mode,
        }

        return {
            "success": success,
            "message": getattr(test_result, "message", None)
            or ("Connection successful" if success else "Connection failed"),
            "error": getattr(test_result, "error", None),
            "details": details,
        }
    except Exception as exc:
        logger.error("Pre-creation connection test failed: %s", exc, exc_info=True)
        error_hint = _build_error_hint(exc, mode)
        return {
            "success": False,
            "message": "Connection test failed",
            "error": error_hint,
            "details": {"mode": mode},
        }


# ===========================================
# Hotspot & Captive Portal
# ===========================================


@router.get("/{controller_id}/hotspot")
async def get_hotspot_config(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> dict[str, Any]:
    """Get the hotspot configuration for this controller."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_hotspot_config()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or {}
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_hotspot_config error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.put("/{controller_id}/hotspot")
async def update_hotspot_config(
    controller_id: UUID,
    config: dict[str, Any],
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
) -> dict[str, Any]:
    """Update the hotspot configuration."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    _audit_config_write("hotspot.update", controller_id, current_user)
    try:
        async with adapter:
            result = await adapter.update_hotspot_config(config)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("update_hotspot_config error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.get("/{controller_id}/captive-portal")
async def get_captive_portal_config(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> dict[str, Any]:
    """Get the captive portal configuration."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_captive_portal_config()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or {}
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_captive_portal_config error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.put("/{controller_id}/captive-portal")
async def update_captive_portal_config(
    controller_id: UUID,
    config: dict[str, Any],
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
) -> dict[str, Any]:
    """Update the captive portal configuration."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    _audit_config_write("captive_portal.update", controller_id, current_user)
    try:
        async with adapter:
            result = await adapter.update_captive_portal_config(config)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("update_captive_portal_config error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.get("/{controller_id}/hotspot/vouchers")
async def get_vouchers(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> list[dict[str, Any]]:
    """List all hotspot vouchers."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_vouchers()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or []
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_vouchers error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


from pydantic import BaseModel as _BaseModel
from pydantic import Field as _Field


class RadiusServerIn(_BaseModel):
    ip: str = _Field(..., max_length=255)
    port: int = _Field(1812, ge=1, le=65535)
    secret: str = _Field("", max_length=255)


class RadiusConfigUpdate(_BaseModel):
    auth_server: RadiusServerIn | None = None
    auth_server_secondary: RadiusServerIn | None = None
    acct_server: RadiusServerIn | None = None
    acct_server_secondary: RadiusServerIn | None = None
    auth_port: int = _Field(1812, ge=1, le=65535)
    acct_port: int = _Field(1813, ge=1, le=65535)
    interim_interval: int = _Field(600, ge=60, le=86400)
    nas_id: str = _Field("", max_length=255)


class VoucherCreateIn(_BaseModel):
    quantity: int = 1
    duration_hours: int = 24
    speed_limit_down: int | None = None
    speed_limit_up: int | None = None
    data_limit_mb: int | None = None
    note: str | None = None


@router.post("/{controller_id}/hotspot/vouchers", status_code=status.HTTP_201_CREATED)
async def create_vouchers(
    controller_id: UUID,
    data: VoucherCreateIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
) -> dict[str, Any]:
    """Create hotspot vouchers."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    _audit_config_write("hotspot.vouchers.create", controller_id, current_user)
    try:
        async with adapter:
            result = await adapter.create_vouchers(data.model_dump(exclude_none=True))
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("create_vouchers error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.delete("/{controller_id}/hotspot/vouchers/{voucher_id}")
async def delete_voucher(
    controller_id: UUID,
    voucher_id: str,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
) -> dict[str, Any]:
    """Delete a hotspot voucher."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    _audit_config_write("hotspot.vouchers.delete", controller_id, current_user)
    try:
        async with adapter:
            result = await adapter.delete_voucher(voucher_id)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("delete_voucher error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


# ===========================================
# 802.1X / Network Authentication
# ===========================================


@router.get("/{controller_id}/dot1x")
async def get_dot1x_config(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> dict[str, Any]:
    """Get the 802.1X authentication configuration."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_dot1x_config()
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_dot1x_config error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.put("/{controller_id}/dot1x")
async def update_dot1x_config(
    controller_id: UUID,
    config: dict[str, Any],
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
) -> dict[str, Any]:
    """Update the 802.1X authentication configuration."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    _audit_config_write("dot1x.update", controller_id, current_user)
    try:
        async with adapter:
            result = await adapter.update_dot1x_config(config)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("update_dot1x_config error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.get("/{controller_id}/dot1x/events")
async def get_dot1x_auth_events(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """Get recent 802.1X authentication events."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_dot1x_auth_events(limit=limit)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or []
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_dot1x_auth_events error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


# ===========================================
# RADIUS Server Management
# ===========================================


@router.get("/{controller_id}/dot1x/radius")
async def get_radius_servers(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> dict[str, Any]:
    """Get RADIUS server configuration (primary + secondary servers, ports, shared secrets)."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            config = await adapter.get_dot1x_config()
        raw = getattr(config, "value", config) or {}
        full = raw if isinstance(raw, dict) else {}
        # Extract RADIUS-specific fields from the dot1x config
        return {
            "auth_server": full.get("authServer") or full.get("primaryServer") or {},
            "auth_server_secondary": full.get("authServerSecondary")
            or full.get("secondaryServer")
            or {},
            "acct_server": full.get("acctServer") or full.get("accountingServer") or {},
            "acct_server_secondary": full.get("acctServerSecondary") or {},
            "auth_port": int(full.get("authPort") or 1812),
            "acct_port": int(full.get("acctPort") or 1813),
            "interim_interval": int(full.get("interimInterval") or 600),
            "nas_id": str(full.get("nasId") or full.get("nasIdentifier") or ""),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_radius_servers error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.put("/{controller_id}/dot1x/radius")
async def update_radius_servers(
    controller_id: UUID,
    config: RadiusConfigUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
) -> dict[str, Any]:
    """Update RADIUS server configuration (primary/secondary auth + accounting servers)."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    # RADIUS shared secrets are pushed live here; record an attributable audit
    # line (without the secret material itself).
    _audit_config_write("dot1x.radius.update", controller_id, current_user)
    try:
        payload = config.model_dump(exclude_none=True)
        async with adapter:
            result = await adapter.update_dot1x_config(payload)
        if not getattr(result, "success", True):
            logger.warning("RADIUS config update failed: %s", getattr(result, "message", "unknown"))
            raise HTTPException(502, detail="Failed to update RADIUS configuration")
        return getattr(result, "value", result) or {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("update_radius_servers error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.get("/{controller_id}/dot1x/stats")
async def get_dot1x_stats(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    limit: int = Query(200, ge=1, le=300),
) -> dict[str, Any]:
    """Get 802.1X authentication statistics summary (success/failure counts, recent events)."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            events = await adapter.get_dot1x_auth_events(limit=limit)
        event_list = getattr(events, "value", events) or []
        # Compute stats from events
        success_count = sum(
            1 for e in event_list if e.get("auth_result") in ("success", "Success", "ACCEPT")
        )
        failure_count = sum(
            1
            for e in event_list
            if e.get("auth_result") in ("failure", "Failure", "REJECT", "reject")
        )
        unique_clients = len({e.get("client_mac") for e in event_list if e.get("client_mac")})
        unique_users = len({e.get("username") for e in event_list if e.get("username")})
        return {
            "total_events": len(event_list),
            "success_count": success_count,
            "failure_count": failure_count,
            "unique_clients": unique_clients,
            "unique_users": unique_users,
            "success_rate": round(success_count / max(len(event_list), 1) * 100, 1),
            "recent_events": event_list[:10],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_dot1x_stats error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


# ===========================================
# WiFi Radio Settings & Rogue AP Detection
# ===========================================


@router.get("/{controller_id}/wifi/radio-settings")
async def get_site_radio_settings(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> dict[str, Any]:
    """Get site-wide WiFi radio settings (channel plan, TX power, DFS, band steering)."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_site_radio_settings()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or {}
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_site_radio_settings error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.put("/{controller_id}/wifi/radio-settings")
async def update_site_radio_settings(
    controller_id: UUID,
    config: dict[str, Any],
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
) -> dict[str, Any]:
    """Update site-wide WiFi radio settings.

    The adapter applies settings per band (2g/5g/6g). Site-wide toggles such as
    fast-roaming (802.11r/k/v) are not band-specific, so the band defaults to
    ``2g`` when the caller does not specify one. The ``band`` key is consumed
    here and not forwarded as part of the radio config payload.
    """
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    _audit_config_write("wifi.radio_settings.update", controller_id, current_user)
    band = str(config.pop("band", "2g"))
    try:
        async with adapter:
            result = await adapter.update_site_radio_settings(band, config)
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or {"success": True}
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("update_site_radio_settings error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.get("/{controller_id}/wifi/channel-utilization")
async def get_channel_utilization(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> list[dict[str, Any]]:
    """Get WiFi channel utilization data per AP/band."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_channel_utilization()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or []
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_channel_utilization error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.get("/{controller_id}/wifi/rogue-aps")
async def get_rogue_aps(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> list[dict[str, Any]]:
    """Detect and list rogue access points."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_rogue_aps()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or []
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_rogue_aps error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


# ===========================================
# Batch Operations
# ===========================================


class BatchDevicesIn(_BaseModel):
    device_macs: list[str]


# Catastrophic batch ops: separate audit-log channel so SRE can spot
# fleet-wide reboots/firmware pushes immediately. The canonical path
# is the staging service (see ``AdapterStagingService``); these direct
# endpoints are kept for legacy callers and gated to ``site_admin+``.
# TODO(staging-batch): route these through staging.stage_change with
# feature="bulk.device.reboot" / "firmware.upgrade.batch" so the
# catastrophic-feature prefix gate at apply-time is the single
# enforcement point.
_batch_audit_log = logging.getLogger("freesdn.security.batch_op")


@router.post("/{controller_id}/batch/reboot")
async def batch_reboot(
    controller_id: UUID,
    data: BatchDevicesIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
    confirm: bool = Query(False, description="Must be true — rebooting a fleet disrupts the site."),
) -> dict[str, Any]:
    """Reboot multiple devices managed by this controller."""
    # FSDN-DW-BULK-REBOOT: a fleet reboot is a site-wide outage; require explicit
    # confirmation (the staged bulk.device.reboot path is catastrophic-classified).
    if not confirm:
        raise HTTPException(
            400, detail="Bulk reboot disrupts the fleet; pass confirm=true to proceed."
        )
    if not current_user.has_min_role("site_admin"):
        raise HTTPException(403, detail="batch reboot requires site_admin role or higher")
    _batch_audit_log.warning(
        "BATCH_REBOOT initiated controller=%s actor=%s devices=%d",
        controller_id,
        getattr(current_user.user, "email", "?"),
        len(data.device_macs),
    )
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.batch_reboot(data.device_macs)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {
            "success": True,
            "devices": len(data.device_macs),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("batch_reboot error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.post("/{controller_id}/batch/firmware-upgrade")
async def batch_firmware_upgrade(
    controller_id: UUID,
    data: BatchDevicesIn,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("firmware:upgrade"))],
    confirm: bool = Query(False, description="Must be true — a bad fleet flash can brick devices."),
) -> dict[str, Any]:
    """Upgrade firmware on multiple devices.

    Gated on the dedicated ``firmware:upgrade`` permission (super_admin-only in
    DEFAULT_ROLE_PERMISSIONS — org/site_admin are deliberately excluded because a
    bad fleet flash can brick devices). This matches the modern firmware paths
    (adapter_omada_firmware / enterprise bulk-op). ``require_permissions`` is
    scope-aware, so a deliberately-narrowed API key without ``firmware:upgrade``
    in its scopes is also refused — closing the legacy ``controller:update`` gap
    where any site_admin/org_admin (who hold ``controller:*``) could batch-flash.
    """
    # an irreversible fleet flash must require an explicit
    # confirmation, matching the controllers batch/reboot sibling gate.
    if not confirm:
        raise HTTPException(
            status_code=409,
            detail="Batch firmware flash can brick devices. Re-issue with confirm=true.",
        )
    _batch_audit_log.warning(
        "BATCH_FIRMWARE_UPGRADE initiated controller=%s actor=%s devices=%d",
        controller_id,
        getattr(current_user.user, "email", "?"),
        len(data.device_macs),
    )
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.batch_firmware_upgrade(data.device_macs)
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {
            "success": True,
            "devices": len(data.device_macs),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("batch_firmware_upgrade error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.post("/{controller_id}/batch/firmware-check")
async def batch_firmware_check(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> dict[str, Any]:
    """Check for available firmware updates across all devices."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.batch_firmware_check()
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("batch_firmware_check error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


# ===========================================
# Firmware Management
# ===========================================


@router.get("/{controller_id}/firmware")
async def get_firmware_list(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> list[dict[str, Any]]:
    """Get available firmware versions for devices on this controller."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_firmware_list()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or []
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_firmware_list error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.get("/{controller_id}/firmware/overview")
async def get_firmware_overview(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> dict[str, Any]:
    """Get firmware overview: device counts per version, update availability."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_firmware_overview()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or {}
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_firmware_overview error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.get("/{controller_id}/firmware/history")
async def get_firmware_upgrade_log(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> list[dict[str, Any]]:
    """Get firmware upgrade history log."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_firmware_upgrade_log()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or []
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_firmware_upgrade_log error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


# ===========================================
# Controller System Operations
# ===========================================


@router.get("/{controller_id}/health")
async def get_controller_health(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> dict[str, Any]:
    """Get controller health and status information."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_controller_status()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or {}
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_controller_status error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.get("/{controller_id}/logs")
async def get_controller_logs(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """Get controller system logs."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_controller_logs(limit=limit)
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or []
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_controller_logs error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.post("/{controller_id}/backup")
async def create_controller_backup(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:update"))],
) -> dict[str, Any]:
    """Trigger a controller configuration backup."""
    _, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    _audit_config_write("backup.create", controller_id, current_user)
    try:
        async with adapter:
            result = await adapter.create_controller_backup()
        if not getattr(result, "success", True):
            raise HTTPException(502, detail=getattr(result, "message", "Adapter error"))
        return getattr(result, "value", result) or {"success": True}
    except HTTPException:
        raise
    except Exception as e:
        logger.error("create_controller_backup error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


@router.get("/{controller_id}/topology")
async def get_controller_topology(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> dict[str, Any]:
    """Get network topology data from the controller."""
    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)
    try:
        async with adapter:
            result = await adapter.get_topology_data()
        _raise_for_adapter_result(result, controller.type)
        return getattr(result, "value", result) or {}
    except HTTPException:
        raise
    except (AttributeError, NotImplementedError):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"Operation not supported by {controller.type} controller",
        )
    except Exception as e:
        logger.error("get_topology_data error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Controller communication error")


# ===========================================
# Storage (TrueNAS) — live read-only inventory
# ===========================================


def _pool_redundancy(topology: dict[str, Any]) -> dict[str, Any]:
    """Derive a human redundancy summary from a pool's data vdevs.

    Reports the data vdev type (RAIDZ1/2/3, MIRROR, STRIPE), how many
    data vdevs there are, and the width of the first one. ZFS fault
    tolerance is per-vdev, so the type is what matters for "can I lose a
    disk".
    """
    data = (topology or {}).get("data") or []
    if not data:
        return {"type": "UNKNOWN", "vdevs": 0, "width": 0}
    first = data[0]
    vtype = str(first.get("type") or "STRIPE").upper()
    if vtype in ("DISK", ""):
        vtype = "STRIPE"
    width = len(first.get("children") or []) or 1
    return {"type": vtype, "vdevs": len(data), "width": width}


def _scrub_summary(scan: dict[str, Any]) -> dict[str, Any] | None:
    """Flatten a pool ``scan`` object into a scrub summary."""
    if not scan:
        return None
    end = scan.get("end_time")
    end_ms = end.get("$date") if isinstance(end, dict) else end
    return {
        "function": scan.get("function"),
        "state": scan.get("state"),
        "errors": scan.get("errors"),
        "percentage": scan.get("percentage"),
        "finished_at_ms": int(end_ms) if isinstance(end_ms, (int, float)) else None,
    }


def _disk_topology_map(pools: list[Any]) -> dict[str, dict[str, Any]]:
    """Map device-name → {pool, vdev, vdev_type, status, errors} from the
    pools' vdev trees, so the disk inventory can show membership + ZFS
    error counters that ``disk.query`` alone doesn't carry."""
    out: dict[str, dict[str, Any]] = {}
    for p in pools:
        topo = getattr(p, "topology", None) or {}
        for grp in ("data", "special", "dedup", "log", "cache", "spare"):
            for vd in topo.get(grp) or []:
                vdtype = str(vd.get("type") or "").upper()
                leaves = vd.get("children") or [vd]
                for leaf in leaves:
                    dname = leaf.get("disk")
                    if not dname:
                        continue
                    stats = leaf.get("stats") or {}
                    out[str(dname)] = {
                        "pool": p.name,
                        "vdev": grp,
                        "vdev_type": vdtype or "DISK",
                        "status": leaf.get("status"),
                        "read_errors": stats.get("read_errors"),
                        "write_errors": stats.get("write_errors"),
                        "checksum_errors": stats.get("checksum_errors"),
                    }
    return out


@router.get("/{controller_id}/storage")
async def get_controller_storage(
    controller_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("controller:read"))],
) -> dict[str, Any]:
    """Live read-only storage inventory for a TrueNAS appliance.

    Aggregates system identity, ZFS pool health + capacity, physical
    disks, and datasets into a single response so the Storage page can
    render the appliance in one round-trip (each adapter connect is a
    full WS handshake + auth, so we fetch everything under one session).

    Read-only: no writes are issued. Auth/connection failures from the
    appliance surface as 502 with the adapter's message (e.g. a revoked
    API key) so the operator can act, rather than masking it.
    """
    from app.adapters.exceptions import (
        AdapterAuthenticationError,
        AdapterConnectionError,
    )

    controller, adapter = await _get_controller_and_adapter(controller_id, session, current_user)

    if controller.type.lower() != "truenas":
        raise HTTPException(
            status_code=400,
            detail=f"Storage inventory is only available for TrueNAS controllers (got '{controller.type}')",
        )

    try:
        async with adapter:
            info = await adapter.get_system_info_model()
            pools = await adapter.get_pools()
            disks = await adapter.get_disks()
            datasets = await adapter.get_datasets()
            snapshots = await adapter.get_snapshots()
            alerts = await adapter.get_alerts()
            disk_temps = await adapter.get_disk_temperatures()
            services = await adapter.get_services()
            data_protection = await adapter.get_data_protection()
    except AdapterAuthenticationError as exc:
        # Upstream (TrueNAS) rejected us — NOT the FreeSDN session. 502 so
        # the FE doesn't log the user out; detail carries the actionable hint.
        raise HTTPException(502, detail=f"TrueNAS authentication failed: {exc}")
    except AdapterConnectionError as exc:
        raise HTTPException(502, detail=f"TrueNAS unreachable: {exc}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_controller_storage error: %s", e, exc_info=True)
        raise HTTPException(502, detail="Storage controller communication error")

    # Pool-health rollup: FAULTED/OFFLINE -> error, DEGRADED -> warning.
    # A CRITICAL active alert also drives the appliance to error so the
    # hot-disk case (pool still ONLINE) doesn't read as "healthy".
    worst = "ok"
    for p in pools:
        st = (p.status or "").upper()
        if st in ("FAULTED", "OFFLINE", "REMOVED"):
            worst = "error"
            break
        if st in ("DEGRADED", "UNAVAIL"):
            worst = "warning"
    alert_levels = {str(a.get("level") or "").upper() for a in alerts}
    if worst != "error" and ("CRITICAL" in alert_levels or "ALERT" in alert_levels):
        worst = "error"
    elif worst == "ok" and ("WARNING" in alert_levels or "ERROR" in alert_levels):
        worst = "warning"

    disk_map = _disk_topology_map(pools)

    return {
        "controller_id": str(controller.id),
        "name": controller.name,
        "host": controller.host,
        "transport": getattr(adapter, "_transport", None),
        "system": {
            "version": info.version,
            "hostname": info.hostname,
            "product": info.system_product,
            "serial": info.system_serial,
            "physmem": info.physmem,
            "uptime_seconds": info.uptime_seconds,
            "timezone": info.timezone,
        },
        "health": {
            "status": worst,
            "pool_count": len(pools),
            "alert_count": len(alerts),
            "critical_alert_count": sum(
                1 for a in alerts if str(a.get("level") or "").upper() in ("CRITICAL", "ALERT")
            ),
        },
        "alerts": alerts,
        "services": services,
        "data_protection": data_protection,
        "pools": [
            {
                "name": p.name,
                "status": p.status,
                "healthy": p.healthy,
                "size": p.usage.size,
                "allocated": p.usage.allocated,
                "free": p.usage.free,
                "fragmentation": p.usage.fragmentation,
                "usage_percent": (
                    round(p.usage.allocated / p.usage.size * 100, 1) if p.usage.size else 0.0
                ),
                "is_decrypted": p.is_decrypted,
                "redundancy": _pool_redundancy(p.topology),
                "scrub": _scrub_summary(p.scan),
            }
            for p in pools
        ],
        "disks": [
            {
                "name": d.name,
                "type": d.type,
                "model": d.model,
                "serial": d.serial,
                "size": d.size,
                # Resolve pool membership + ZFS status/errors from topology
                # (disk.query reports pool=None), and temperature from the
                # SMART feed.
                "pool": (disk_map.get(d.name, {}).get("pool")) or d.pool,
                "vdev_type": disk_map.get(d.name, {}).get("vdev_type"),
                "zfs_status": disk_map.get(d.name, {}).get("status"),
                "read_errors": disk_map.get(d.name, {}).get("read_errors"),
                "write_errors": disk_map.get(d.name, {}).get("write_errors"),
                "checksum_errors": disk_map.get(d.name, {}).get("checksum_errors"),
                "temperature_c": disk_temps.get(d.name),
                "transfermode": d.transfermode,
            }
            for d in disks
        ],
        "datasets": [
            {
                "id": d.id,
                "name": d.name,
                "pool": d.pool,
                "type": d.type,
                "mountpoint": d.mountpoint,
                "encrypted": d.encrypted,
                "locked": d.locked,
                "used_bytes": d.usage.used_bytes,
                "available_bytes": d.usage.available_bytes,
                "quota_bytes": d.usage.quota_bytes,
            }
            for d in datasets
        ],
        "snapshot_count": len(snapshots),
    }

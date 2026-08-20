# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VoIP Module API Endpoints
=======================================

REST API endpoints for VoIP management — GDMS-style fleet operations.

Sub-routers (clear domain separation):
  phones_router      /phones        — Phone CRUD + lifecycle operations
  discovery_router   /discovery     — Network discovery scans
  templates_router   /templates     — Config template management
  provisioning_router /provisioning — Phone config serving (no auth)
  fleet_router       /fleet         — Fleet dashboard & bulk operations
  firmware_router    /firmware      — Firmware tracking & compliance
  pbx_router         /pbx           — PBX system management
  extensions_router  /extensions    — Extension listing (cross-PBX)
  ring_groups_router /ring-groups   — Ring group management
  call_logs_router   /call-logs     — CDR search & stats
  voicemails_router  /voicemails    — Voicemail management
"""

import logging
import re
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, require_min_role, require_permissions
from app.core.redaction import redact_list, redact_secrets
from app.db import get_session
from app.modules.voip.schemas import (
    BulkConnectRequest,
    BulkConnectResponse,
    BulkFirmwareRequest,
    BulkOperationRequest,
    BulkProvisionRequest,
    ConfigTemplateCreate,
    ConfigTemplateUpdate,
    DiscoveryScanRequest,
    ExtensionCreate,
    ExtensionUpdate,
    FirmwareTrackCreate,
    HangupCallRequest,
    OriginateCallRequest,
    PBXCreate,
    PBXTestConnection,
    PBXUpdate,
    PhoneConnectionTestRequest,
    PhoneConnectionTestResult,
    PhoneCreate,
    PhoneOnboardRequest,
    PhoneProvisionRequest,
    PhoneUpdate,
    QueueMemberRequest,
    RingGroupCreate,
    TransferCallRequest,
    VoicemailUpdate,
)
from app.modules.voip.service import (
    CrossTenantError,
    DiscoveryScanNotFoundError,
    PBXNotFoundError,
    PhoneNotFoundError,
    VoicemailNotFoundError,
    VoIPError,
    VoIPService,
    _sanitize_pbx_settings,
)

# ---------------------------------------------------------------------------
# Sub-routers — each maps to a clear domain concept
# ---------------------------------------------------------------------------
phones_router = APIRouter(prefix="/phones", tags=["VoIP — Phones"])
discovery_router = APIRouter(prefix="/discovery", tags=["VoIP — Discovery"])
templates_router = APIRouter(prefix="/templates", tags=["VoIP — Templates"])
provisioning_router = APIRouter(prefix="/provisioning", tags=["VoIP — Provisioning"])
fleet_router = APIRouter(prefix="/fleet", tags=["VoIP — Fleet"])
firmware_router = APIRouter(prefix="/firmware", tags=["VoIP — Firmware"])
pbx_router = APIRouter(prefix="/pbx", tags=["VoIP — PBX"])
extensions_router = APIRouter(prefix="/extensions", tags=["VoIP — Extensions"])
ring_groups_router = APIRouter(prefix="/ring-groups", tags=["VoIP — Ring Groups"])
call_logs_router = APIRouter(prefix="/call-logs", tags=["VoIP — Call Logs"])
voicemails_router = APIRouter(prefix="/voicemails", tags=["VoIP — Voicemails"])

# MAC address validation pattern (12 hex chars, various separators)
_MAC_RE = re.compile(r"^[0-9a-fA-F]{12}$|^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


def get_voip_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> VoIPService:
    """Unauthenticated VoIP service — used only by the provisioning endpoint.

    Every other endpoint should use :func:`get_scoped_voip_service` which
    binds the organization context at construction time. Leaving the
    unauthenticated factory in place lets the provisioning endpoint use
    the same service class without sneakily exposing org-agnostic
    operations elsewhere.
    """
    return VoIPService(db=session)


def _org_id(user) -> UUID:
    """Extract organization_id from user or raise 400."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(status_code=400, detail="Organization context required")
    return oid


def get_scoped_voip_service(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
) -> VoIPService:
    """Per-request VoIP service with organization context bound at construction.

    Replaces the previous ``_set_org`` pattern which mutated the
    service instance's ``organization_id`` attribute after the fact —
    a brittle approach that risked races if a future caller forgot
    to call it or called it twice with mismatched orgs. With this
    factory the org_id is set ONCE in the constructor and the
    service object can never be reused across users.
    """
    return VoIPService(
        db=session,
        organization_id=_org_id(current_user),
        accessible_site_ids=(
            current_user.accessible_site_ids if current_user.is_site_limited else None
        ),
    )


# Legacy alias preserved for endpoints we haven't refactored yet —
# keep behaviour identical but route through the same explicit
# construction path so the org binding is
# always synchronous and per-request.
def _set_org(service: VoIPService, user) -> VoIPService:
    """DEPRECATED: prefer :func:`get_scoped_voip_service`. Kept for transitional callers."""
    service.organization_id = _org_id(user)
    # bind per-user site grant alongside org.
    service.accessible_site_ids = (
        user.accessible_site_ids if getattr(user, "is_site_limited", False) else None
    )
    return service


# ---------------------------------------------------------------------------
# Helper — persist connection-test data to a Phone ORM object
# ---------------------------------------------------------------------------
import contextlib
from datetime import UTC

from sqlalchemy.orm.attributes import flag_modified as _flag_modified


async def _persist_connection_result(
    phone,
    result: dict,
    ip: str,
    session: AsyncSession,
    *,
    commit: bool = True,
) -> None:
    """Write connection-test results to dedicated columns + settings JSONB.

    Separated so the same logic works for single and bulk connect flows.
    """
    # Dedicated columns — always overwrite with latest values
    if result.get("mac_address"):
        phone.mac_address = result["mac_address"]
    if result.get("vendor"):
        phone.vendor = result["vendor"]
    if result.get("model"):
        phone.model = result["model"]
    if result.get("firmware_version"):
        phone.firmware_version = result["firmware_version"]
    if result.get("sip_registered") is not None:
        phone.sip_registered = bool(result["sip_registered"])
    if result.get("sip_registrar"):
        phone.sip_server = result["sip_registrar"]

    # Network columns
    net = result.get("network_info", {})
    if net.get("vlan_id"):
        with contextlib.suppress(ValueError, TypeError):
            phone.vlan_id = int(net["vlan_id"])
    if net.get("subnet_mask"):
        ip_addr = result.get("ip_address", ip)
        mask = net["subnet_mask"]
        prefix = sum(bin(int(o)).count("1") for o in mask.split(".")) if "." in mask else 24
        phone.subnet = f"{ip_addr}/{prefix}"

    # Status & timestamps
    phone.status = "online"
    phone.last_seen = datetime.now(UTC)

    # ── Merge into settings JSONB (preserve credentials etc.) ───
    settings = phone.settings or {}

    if result.get("sip_accounts"):
        settings["sip_accounts"] = result["sip_accounts"]
    if result.get("sip_account"):
        settings["sip_user_id"] = result["sip_account"]
    if result.get("sip_registrar"):
        settings["sip_registrar"] = result["sip_registrar"]
    if net:
        settings["network_info"] = net

    raw = result.get("raw_data", {})
    if raw.get("_phone_status"):
        settings["phone_status"] = raw["_phone_status"]
    if raw.get("_line_status"):
        settings["line_status"] = raw["_line_status"]
    if raw.get("_registered_accounts"):
        settings["registered_accounts"] = raw["_registered_accounts"]
    if raw.get("_dhcp_vendor_id"):
        settings["dhcp_vendor_id"] = raw["_dhcp_vendor_id"]

    if result.get("config_items"):
        settings["config_items"] = result["config_items"]
    if result.get("lockout_status"):
        settings["lockout_status"] = result["lockout_status"]
    if result.get("authenticated"):
        settings["authenticated"] = True
        settings["last_authenticated_at"] = datetime.now(UTC).isoformat()

    phone.settings = settings
    _flag_modified(phone, "settings")

    if commit:
        await session.commit()
        await session.refresh(phone)


# =============================================================================
# Phone Endpoints (CRUD + fleet lifecycle)
# =============================================================================


@phones_router.get("/")
async def list_phones(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    site_id: UUID | None = None,
    pbx_id: UUID | None = None,
    # Cap to keep DB filter clauses bounded; ``search`` reaches a
    # LIKE pattern in the service layer.
    status: str | None = Query(None, max_length=32),
    lifecycle_state: str | None = Query(None, max_length=32),
    vendor: str | None = Query(None, max_length=64),
    config_template_id: UUID | None = None,
    search: str | None = Query(None, max_length=256),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List all phones with advanced fleet filters."""
    _set_org(service, current_user)
    phones, total = await service.list_phones(
        site_id=site_id,
        pbx_id=pbx_id,
        status=status,
        lifecycle_state=lifecycle_state,
        vendor=vendor,
        config_template_id=config_template_id,
        search=search,
        limit=limit,
        offset=offset,
    )

    # Batch-fetch the joined PBX + extension info so the UI can render
    # the "Extension" column without N+1 detail-fetches. Two queries
    # total regardless of how many phones came back. Both queries are
    # already scoped by the service through ``_set_org`` —
    # :meth:`VoIPService.get_pbx_systems_by_ids` and
    # :meth:`get_extensions_by_ids` re-apply the org filter defensively.
    pbx_ids = {p.pbx_id for p in phones if p.pbx_id}
    ext_ids = {p.extension_id for p in phones if p.extension_id}
    pbx_map: dict = await service.get_pbx_systems_by_ids(pbx_ids) if pbx_ids else {}
    ext_map: dict = await service.get_extensions_by_ids(ext_ids) if ext_ids else {}

    items = []
    for p in phones:
        row = _sanitize_phone_response(p)
        ext = ext_map.get(p.extension_id) if p.extension_id else None
        pbx = pbx_map.get(p.pbx_id) if p.pbx_id else None
        if ext is not None:
            row["extension"] = ext.extension_number
            row["extension_display"] = ext.display_name
        if pbx is not None:
            row["pbx_system_id"] = str(pbx.id)
            row["pbx_system_name"] = pbx.name
        # ``sip_user`` was previously stuffed into settings — surface it
        # at the top level so the FE column doesn't have to dig.
        sip_user = (p.settings or {}).get("sip_user_id") if p.settings else None
        if sip_user:
            row["sip_user"] = sip_user
        items.append(row)

    return {"items": items, "total": total}


@phones_router.get("/stats")
async def get_phone_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    site_id: UUID | None = None,
):
    """Get phone statistics."""
    _set_org(service, current_user)
    return await service.get_phone_stats(site_id=site_id)


@phones_router.get("/{phone_id}")
async def get_phone(
    phone_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Get a phone by ID."""
    _set_org(service, current_user)
    try:
        phone = await service.get_phone(phone_id)
    except PhoneNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Phone not found",
        )
    row = _sanitize_phone_response(phone)

    # Enrich with the same joined fields the list endpoint returns so
    # the PhoneDetailPage shows the bound extension + PBX name in the
    # Push-SIP-Config dialog and elsewhere.
    if phone.extension_id:
        ext_map = await service.get_extensions_by_ids({phone.extension_id})
        ext = ext_map.get(phone.extension_id)
        if ext is not None:
            row["extension"] = ext.extension_number
            row["extension_display"] = ext.display_name
    if phone.pbx_id:
        pbx_map = await service.get_pbx_systems_by_ids({phone.pbx_id})
        pbx = pbx_map.get(phone.pbx_id)
        if pbx is not None:
            row["pbx_system_id"] = str(pbx.id)
            row["pbx_system_name"] = pbx.name
    sip_user = (phone.settings or {}).get("sip_user_id") if phone.settings else None
    if sip_user:
        row["sip_user"] = sip_user
    return row


@phones_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_phone(
    phone_data: PhoneCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Create a new phone."""
    _set_org(service, current_user)
    payload = phone_data.model_dump()
    # Resolve site_id when the FE didn't send one. The Add Phone
    # modal doesn't expose a Site picker yet (the camera modal does
    # but the phone modal doesn't), so we infer here from the org's
    # first / only site. Future: read X-Selected-Site header or
    # add a Site picker to the modal.
    if payload.get("site_id") is None:
        if current_user.organization_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=("no site_id supplied and user is not attached to an organization"),
            )
        from sqlalchemy import select

        from app.core.site_access import site_scope_filter
        from app.models.core import Site as SiteModel

        # when auto-selecting the org's first site, a site-limited
        # caller must land on a GRANTED site, not whatever the org's oldest
        # site happens to be. site_scope_filter is a no-op for super/org admin
        # and grant-less users, and AND-s the per-user grant for site-limited
        # callers (mirrors create_template above).
        site_row = (
            await service.db.execute(
                select(SiteModel.id)
                .where(
                    SiteModel.organization_id == current_user.organization_id,
                    SiteModel.deleted_at.is_(None),
                    site_scope_filter(current_user, SiteModel.id),
                )
                .order_by(SiteModel.created_at.asc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if site_row is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="no site available — create a site first",
            )
        payload["site_id"] = site_row
    else:
        # a client-supplied site_id is also validated against the
        # per-user grant up front (404 — no existence oracle). create_phone()'s
        # _assert_site_in_org now folds the grant too (defence in depth), but
        # checking here keeps the 404 shape consistent with create_template.
        from app.core.site_access import assert_can_access_site

        assert_can_access_site(current_user, payload["site_id"], detail="Site not found")
    try:
        phone = await service.create_phone(payload)
    except CrossTenantError:
        # a supplied site_id/pbx_id/extension_id/config_template_id
        # referenced a row outside the caller's org. 404 (not 403) avoids
        # leaking the existence of foreign rows.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Referenced site, PBX, extension, or template not found",
        )
    from app.services.device_sync import trigger_device_registry_sync

    trigger_device_registry_sync("voip")
    return phone


@phones_router.patch("/{phone_id}")
async def update_phone(
    phone_id: UUID,
    phone_data: PhoneUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Update a phone."""
    _set_org(service, current_user)
    try:
        result = await service.update_phone(phone_id, phone_data.model_dump(exclude_unset=True))
        from app.services.device_sync import trigger_device_registry_sync

        trigger_device_registry_sync("voip")
        return result
    except PhoneNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Phone not found",
        )


@phones_router.delete("/{phone_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_phone(
    phone_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Delete a phone."""
    _set_org(service, current_user)
    try:
        from app.services.device_sync import DeviceSyncService

        await DeviceSyncService.remove_device(
            service.db,
            external_id_prefix="voip_phone",
            source_id=phone_id,
        )
        await service.delete_phone(phone_id)
    except PhoneNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Phone not found",
        )


# -- Phone Lifecycle (GDMS-style) --


@phones_router.post("/{phone_id}/onboard")
async def onboard_phone(
    phone_id: UUID,
    data: PhoneOnboardRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Onboard a discovered phone into managed state."""
    _set_org(service, current_user)
    try:
        return await service.onboard_phone(
            phone_id=phone_id,
            name=data.name,
            pbx_id=data.pbx_id,
            extension_id=data.extension_id,
            config_template_id=data.config_template_id,
            location=data.location,
            tags=data.tags,
        )
    except PhoneNotFoundError:
        raise HTTPException(status_code=404, detail="Phone not found")
    except CrossTenantError:
        # assigned pbx/extension/template belongs to another org.
        raise HTTPException(
            status_code=404, detail="Referenced PBX, extension, or template not found"
        )
    except VoIPError as exc:
        logger.error("Phone onboarding failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=409, detail="Phone onboarding failed")


class PhoneMigrateRequest(BaseModel):
    """Body for POST /phones/{phone_id}/migrate.

    Was a bare ``dict`` which bypassed pydantic per-field validation.
    """

    target_site_id: UUID
    follow_links: bool = False
    dry_run: bool = False


@phones_router.post("/{phone_id}/migrate")
async def migrate_phone_to_site(
    phone_id: UUID,
    data: PhoneMigrateRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Move a phone from one site to another.

    With ``follow_links=true`` the service tries to find a PBX at the
    target site with the same ``ip_address`` and rebinds the phone's
    extension if a matching number exists. Otherwise (default), all
    site-scoped links are cleared — run /voip/phones/auto-link after
    migration to bind to the new site's PBX.

    Idempotent: migrating a phone that's already at the target site
    is a no-op.
    """
    from app.core.site_access import assert_can_access_site
    from app.services.device_migration import (
        DeviceMigrationError,
        DeviceMigrationService,
    )

    # DeviceMigrationService scopes by organization_id ONLY (no
    # per-user site grant), so a site-limited operator could migrate a phone
    # OUT OF a sibling (non-granted) site or INTO one. Enforce the grant on
    # both ends here, before delegating:
    #   1. Resolve the source phone through the grant-aware VoIPService.get_phone
    #      — raises 404 when the phone lives in a non-granted site.
    #   2. Assert the target_site_id is within the per-user grant (404 — no
    #      existence oracle). Both checks no-op for super/org admin and
    #      grant-less callers.
    scoped = VoIPService(
        db=session,
        organization_id=_org_id(current_user),
        accessible_site_ids=(
            current_user.accessible_site_ids if current_user.is_site_limited else None
        ),
    )
    try:
        await scoped.get_phone(phone_id)
    except PhoneNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Phone not found")
    assert_can_access_site(current_user, data.target_site_id, detail="Site not found")

    svc = DeviceMigrationService(
        db=session,
        organization_id=_org_id(current_user),
    )
    try:
        return await svc.migrate_phone(
            phone_id=phone_id,
            target_site_id=data.target_site_id,
            actor_id=current_user.id,
            follow_links=data.follow_links,
            dry_run=data.dry_run,
        )
    except DeviceMigrationError as exc:
        # Strip URLs from upstream-adapter exception text before
        # surfacing — httpx errors often embed the full PBX URL
        # incl. auth fragments.
        import re as _re

        safe = _re.sub(r"https?://\S+", "<redacted-url>", str(exc))[:500]
        raise HTTPException(status_code=400, detail=safe)


@phones_router.post("/{phone_id}/reboot")
async def reboot_phone_endpoint(
    phone_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Reboot a single phone via its vendor adapter.

    Returns immediately (202 semantics) after dispatching the call.
    The phone drops its HTTP socket as part of the reboot, so the
    adapter treats a closed connection mid-response as success.
    """
    _set_org(service, current_user)
    try:
        return await service.reboot_phone(phone_id)
    except PhoneNotFoundError:
        raise HTTPException(status_code=404, detail="Phone not found")
    except VoIPError as exc:
        import re as _re

        safe = _re.sub(r"https?://\S+", "<redacted-url>", str(exc))[:500]
        raise HTTPException(status_code=400, detail=safe)


@phones_router.post("/{phone_id}/factory-reset")
async def factory_reset_phone_endpoint(
    phone_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    confirm: bool = False,
):
    """Factory-reset a single phone. Destructive — wipes all config."""
    # factory reset wipes ALL phone config + de-registers SIP
    # (re-onboard required) — require an explicit confirm, matching the
    # destructive-op confirmation gate used by bulk reboot / NVR reboot /
    # hypervisor destructive ops.
    if not confirm:
        raise HTTPException(
            status_code=409,
            detail=(
                "Factory reset wipes ALL phone configuration and de-registers SIP; "
                "resubmit with ?confirm=true to proceed."
            ),
        )
    _set_org(service, current_user)
    try:
        return await service.factory_reset_phone(phone_id)
    except PhoneNotFoundError:
        raise HTTPException(status_code=404, detail="Phone not found")
    except VoIPError as exc:
        import re as _re

        safe = _re.sub(r"https?://\S+", "<redacted-url>", str(exc))[:500]
        raise HTTPException(status_code=400, detail=safe)


@phones_router.get("/{phone_id}/live-status")
async def get_phone_live_status(
    phone_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Cheap live-state probe — what's the phone doing RIGHT NOW.

    Returns ``{phone_state, line_status, lockout, ts}`` in ~150-300 ms
    by hitting the GS api-get_phone_status + api-get_line_status
    endpoints over the already-saved admin session. Designed to be
    polled at 5 s intervals from the FE for a real-time line indicator
    without hammering the slower full status path.
    """
    _set_org(service, current_user)
    try:
        return await service.get_phone_live_status(phone_id)
    except PhoneNotFoundError:
        raise HTTPException(status_code=404, detail="Phone not found")
    except VoIPError as exc:
        import re as _re

        safe = _re.sub(r"https?://\S+", "<redacted-url>", str(exc))[:500]
        raise HTTPException(status_code=400, detail=safe)


class PushSipConfigRequest(BaseModel):
    """Body for POST /phones/{phone_id}/push-sip-config.

    Was a bare ``dict`` which bypassed pydantic per-field validation.
    The SIP secret is bounded to a sane upper limit (Grandstream /
    Yealink accept up to ~63 chars per spec; 256 leaves headroom for
    operator extensions). account_index gated to common phone-account
    range (most desk phones have 1-6 accounts; cap at 16).
    """

    sip_password: str = Field(..., min_length=1, max_length=256)
    account_index: int = Field(default=1, ge=1, le=16)
    dry_run: bool = False


@phones_router.post("/{phone_id}/push-sip-config")
async def push_sip_config_to_phone(
    phone_id: UUID,
    data: PushSipConfigRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Push the bound FreePBX extension's SIP credentials down to the phone.

    The SIP password is required because FreeSDN deliberately doesn't
    cache SIP secrets — the FreePBX adapter redacts them on the read
    path. With ``dry_run=true`` you get back the plan (with the
    password redacted) without writing anything to the phone.
    """
    _set_org(service, current_user)
    try:
        return await service.push_sip_config_to_phone(
            phone_id=phone_id,
            sip_password=data.sip_password,
            account_index=data.account_index,
            dry_run=data.dry_run,
        )
    except PhoneNotFoundError:
        raise HTTPException(status_code=404, detail="Phone not found")
    except VoIPError as exc:
        # Surface the message — it's an operator-facing config error,
        # not a server fault. URL-redact before surfacing since some
        # error paths include the PBX URL with embedded credentials.
        import re as _re

        safe = _re.sub(r"https?://\S+", "<redacted-url>", str(exc))[:500]
        raise HTTPException(status_code=400, detail=safe)


@phones_router.post("/auto-link")
async def auto_link_phones(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    site_id: UUID | None = None,
    onboard: bool = False,
):
    """Auto-link discovered phones to FreePBX extensions.

    Matches each phone's reported ``sip_registrar`` host against the
    PBX's ``ip_address``, then matches the phone's ``sip_user_id``
    against ``extension_number`` on that PBX. Idempotent — re-running
    is safe (already-linked phones are skipped).

    Pass ``onboard=true`` to also promote successfully-linked phones
    from ``discovered`` → ``onboarding`` (queues them for the
    provisioning task).

    Returns a per-phone summary so the UI can render which phones
    landed where and why any didn't.
    """
    _set_org(service, current_user)
    return await service.auto_link_phones_to_pbx(
        site_id=site_id,
        onboard=onboard,
    )


@phones_router.post("/{phone_id}/decommission")
async def decommission_phone(
    phone_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Decommission a phone — remove from active management."""
    _set_org(service, current_user)
    try:
        return await service.decommission_phone(phone_id)
    except PhoneNotFoundError:
        raise HTTPException(status_code=404, detail="Phone not found")


@phones_router.post("/{phone_id}/maintenance")
async def toggle_maintenance(
    phone_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    enabled: bool = True,
):
    """Toggle maintenance mode on a phone."""
    _set_org(service, current_user)
    try:
        return await service.set_maintenance_mode(phone_id, enabled)
    except PhoneNotFoundError:
        raise HTTPException(status_code=404, detail="Phone not found")


@phones_router.post("/{phone_id}/provision")
async def provision_phone(
    phone_id: UUID,
    data: PhoneProvisionRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Generate and push provisioning config for a phone."""
    from app.modules.voip.provisioning import ProvisioningError, ProvisioningService

    prov = ProvisioningService(session, organization_id=_org_id(current_user))
    outcome = "failed"
    try:
        result = await prov.generate_phone_config(phone_id, write_file=True, force=data.force)
        outcome = "ok"
        # ``reboot_after`` defaults to True because a phone does not apply a
        # freshly written config until it re-provisions. Best-effort: the
        # config IS written by this point, so a phone that refuses the reboot
        # must not turn a successful provision into an error -- report it
        # instead, so the operator knows to power-cycle.
        if data.reboot_after:
            svc = VoIPService(db=session)
            _set_org(svc, current_user)
            try:
                await svc.reboot_phone(phone_id)
                result["rebooted"] = True
            except (PhoneNotFoundError, VoIPError) as exc:
                logger.warning("Provision succeeded but reboot failed for %s: %s", phone_id, exc)
                result["rebooted"] = False
                result["reboot_error"] = "Phone did not accept the reboot"
        else:
            result["rebooted"] = False
        return result
    except ProvisioningError as exc:
        logger.error("Phone provisioning failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=400, detail="Provisioning failed")
    finally:
        # Phone provisioning rewrites the SIP/web/admin creds on a
        # phone. Automation rules typically want to track provisioning
        # events for compliance + asset-management workflows.
        from app.modules.voip.events import record_phone_action

        await record_phone_action(
            "provision",
            phone_id=phone_id,
            adapter_id="grandstream",  # only adapter with provisioning today
            organization_id=current_user.organization_id,
            outcome=outcome,
        )


@phones_router.get("/{phone_id}/config-preview")
async def preview_phone_config(
    phone_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Preview the generated provisioning config XML for a phone."""
    from app.modules.voip.provisioning import ProvisioningError, ProvisioningService

    prov = ProvisioningService(session, organization_id=_org_id(current_user))
    try:
        xml = await prov.generate_config_preview(phone_id)
        return Response(content=xml, media_type="application/xml")
    except ProvisioningError as exc:
        logger.error("Config preview failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=400, detail="Config preview failed")


# =============================================================================
# Phone Connection Test & Credentials
# =============================================================================


@phones_router.post("/{phone_id}/test-connection", response_model=PhoneConnectionTestResult)
async def test_phone_connection(
    phone_id: UUID,
    data: PhoneConnectionTestRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Test connectivity and login to a phone.

    Probes the phone's web interface, attempts login with provided credentials,
    and retrieves device info (MAC, model, firmware, SIP registration).
    Optionally saves credentials on successful authentication.
    """
    from app.modules.voip.discovery import test_phone_connection as _test_conn

    # FSDN-SG (VoIP site-grant sibling): bind the per-user site grant, not just
    # org. get_phone()/save_phone_credentials skip the grant filter when
    # accessible_site_ids is unset, which would let a site-limited caller probe
    # or write a SIBLING-site phone. _set_org binds both org and grant.
    svc = _set_org(VoIPService(db=session), current_user)
    try:
        phone = await svc.get_phone(phone_id)
    except PhoneNotFoundError:
        raise HTTPException(status_code=404, detail="Phone not found")

    ip = data.ip_address or getattr(phone, "ip_address", None)
    if not ip:
        raise HTTPException(status_code=400, detail="No IP address available")

    result = await _test_conn(
        ip=ip,
        username=data.username,
        password=data.password,
    )

    # Save credentials if requested and auth succeeded
    if data.save_credentials and result.get("authenticated"):
        await svc.save_phone_credentials(
            phone_id=phone_id,
            username=data.username,
            password=data.password,
        )

    # Persist all discovered data to the phone record
    try:
        await _persist_connection_result(phone, result, ip, session)
    except Exception as persist_err:
        logger.warning(
            "Failed to persist connection result for phone %s: %s", phone_id, persist_err
        )

    return PhoneConnectionTestResult(**result)


@phones_router.post("/test-connection", response_model=PhoneConnectionTestResult)
async def test_phone_connection_adhoc(
    data: PhoneConnectionTestRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
):
    """Test connectivity to a phone by IP (without a phone record)."""
    from app.modules.voip.discovery import test_phone_connection as _test_conn

    if not data.ip_address:
        raise HTTPException(status_code=400, detail="ip_address is required")

    result = await _test_conn(
        ip=data.ip_address,
        username=data.username,
        password=data.password,
    )
    return PhoneConnectionTestResult(**result)


@phones_router.put("/{phone_id}/credentials")
async def save_phone_credentials(
    phone_id: UUID,
    data: PhoneConnectionTestRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Save login credentials for a phone."""
    # FSDN-SG (VoIP site-grant sibling): bind the per-user site grant, not just
    # org. get_phone()/save_phone_credentials skip the grant filter when
    # accessible_site_ids is unset, which would let a site-limited caller probe
    # or write a SIBLING-site phone. _set_org binds both org and grant.
    svc = _set_org(VoIPService(db=session), current_user)
    try:
        await svc.get_phone(phone_id)
    except PhoneNotFoundError:
        raise HTTPException(status_code=404, detail="Phone not found")

    await svc.save_phone_credentials(
        phone_id=phone_id,
        username=data.username,
        password=data.password,
    )
    return {"status": "saved"}


# =============================================================================
# Discovery Endpoints
# =============================================================================


@discovery_router.post("/scan", status_code=status.HTTP_202_ACCEPTED)
async def trigger_discovery_scan(
    data: DiscoveryScanRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Trigger a network discovery scan for VoIP devices.

    The scan runs asynchronously via Celery. Returns the scan ID
    for status polling.
    """
    _set_org(service, current_user)

    from app.modules.voip.models import ScanStatus

    # Resolve the scan's site, enforcing the caller's per-user site grant.
    site_id = data.site_id
    if site_id is not None:
        # FSDN-SG-003: a client-supplied site_id must be validated against the
        # caller's per-user grant up front (404 — no existence oracle), mirroring
        # create_phone / create_template. Without this a site-limited caller
        # could queue a LIVE network scan + phone writes against a sibling site
        # they were never granted. No-op for super/org admins and grant-less users.
        from app.core.site_access import assert_can_access_site

        assert_can_access_site(current_user, site_id, detail="Site not found")
    else:
        # FSDN-SG-003: auto-select must land on a GRANTED site, not whatever the
        # org's oldest site happens to be. site_scope_filter AND-s the per-user
        # grant for site-limited callers (no-op for super/org admins).
        from sqlalchemy import select as _select

        from app.core.site_access import site_scope_filter
        from app.models.core import Site as SiteModel

        site_id = (
            await session.execute(
                _select(SiteModel.id)
                .where(
                    SiteModel.organization_id == current_user.organization_id,
                    SiteModel.deleted_at.is_(None),
                    site_scope_filter(current_user, SiteModel.id),
                )
                .order_by(SiteModel.created_at.asc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if site_id is None:
            raise HTTPException(
                status_code=422,
                detail="No site found for your organization. Create a site first.",
            )

    scan = await service.create_discovery_scan(
        {
            "site_id": site_id,
            "scan_type": data.scan_type,
            "subnet": data.subnet,
            "port_range": data.port_range,
            "status": ScanStatus.PENDING.value,
            "metadata_json": {
                "auto_onboard": data.auto_onboard,
                "config_template_id": str(data.config_template_id)
                if data.config_template_id
                else None,
                "triggered_by": str(current_user.id),
                "has_credentials": data.credentials is not None,
            },
        }
    )

    # Dispatch Celery task — pass credentials transiently (not persisted)
    from app.modules.voip.tasks import run_discovery_scan_task

    creds_dict = None
    if data.credentials:
        from app.core.crypto import encrypt_credential

        creds_dict = {
            "username": data.credentials.username,
            "password": encrypt_credential(data.credentials.password),
        }
    run_discovery_scan_task.delay(str(scan.id), creds_dict)

    return {
        "scan_id": str(scan.id),
        "status": "pending",
        "message": f"Discovery scan queued for {data.subnet or 'auto-detect'}",
    }


@discovery_router.get("/scans")
async def list_discovery_scans(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    site_id: UUID | None = None,
    scan_status: str | None = Query(None, max_length=32),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List discovery scan history."""
    _set_org(service, current_user)
    scans, total = await service.list_discovery_scans(
        site_id=site_id,
        status=scan_status,
        limit=limit,
        offset=offset,
    )
    return {"items": scans, "total": total}


@discovery_router.get("/scans/{scan_id}")
async def get_discovery_scan(
    scan_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Get a discovery scan by ID with results."""
    _set_org(service, current_user)
    try:
        return await service.get_discovery_scan(scan_id)
    except DiscoveryScanNotFoundError:
        raise HTTPException(status_code=404, detail="Discovery scan not found")


@discovery_router.get("/scans/{scan_id}/status")
async def get_discovery_scan_status(
    scan_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Lightweight polling endpoint for live scan progress.

    Uses a column-select query that skips the heavy results JSONB —
    only fetches id, status, devices_found, started_at, completed_at,
    metadata_json, and error_message.
    """
    _set_org(service, current_user)
    try:
        scan = await service.get_discovery_scan_status(scan_id)
    except DiscoveryScanNotFoundError:
        raise HTTPException(status_code=404, detail="Discovery scan not found")

    meta = scan.get("metadata_json") or {}
    progress = meta.get("progress", {})

    return {
        "scan_id": str(scan_id),
        "status": scan.get("status", "unknown"),
        "devices_found": scan.get("devices_found", 0) or 0,
        "started_at": str(scan["started_at"]) if scan.get("started_at") else None,
        "completed_at": str(scan["completed_at"]) if scan.get("completed_at") else None,
        "error_message": scan.get("error_message"),
        "progress": {
            "phase": progress.get("phase", "unknown"),
            "percent": progress.get("percent", 0),
            "message": progress.get("message", ""),
            "devices_found": progress.get("devices_found", 0),
            "log": progress.get("log", [])[-20:],
            "devices": progress.get("devices", []),
        },
    }


@discovery_router.post("/scans/{scan_id}/cancel")
async def cancel_discovery_scan(
    scan_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Cancel a running or pending discovery scan."""
    _set_org(service, current_user)
    try:
        result = await service.cancel_discovery_scan(scan_id)
    except DiscoveryScanNotFoundError:
        raise HTTPException(status_code=404, detail="Discovery scan not found")
    except ValueError as e:
        logger.error("Cannot cancel scan %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=409, detail="Cannot cancel scan in current state")

    # Best-effort Celery task revocation
    try:
        from app.core.celery_app import celery_app

        celery_app.control.revoke(str(scan_id), terminate=True, signal="SIGTERM")
    except Exception:
        pass  # Task may have already finished

    return {"scan_id": str(scan_id), "status": "cancelled", "message": result}


@discovery_router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_discovery_scan(
    scan_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Delete a completed/failed/cancelled discovery scan."""
    _set_org(service, current_user)
    try:
        await service.delete_discovery_scan(scan_id)
    except DiscoveryScanNotFoundError:
        raise HTTPException(status_code=404, detail="Discovery scan not found")
    except ValueError as e:
        logger.error("Cannot delete scan %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=409, detail="Cannot delete scan in current state")


# =============================================================================
# Config Template Endpoints
# =============================================================================


@templates_router.get("/")
async def list_templates(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: UUID | None = None,
    vendor: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List configuration templates."""
    from app.modules.voip.provisioning import ProvisioningService
    from app.modules.voip.schemas import ConfigTemplateResponse

    prov = ProvisioningService(session, organization_id=_org_id(current_user))
    templates, total = await prov.list_templates(
        site_id=site_id, vendor=vendor, limit=limit, offset=offset
    )

    # Populate the "Phones" column the list table renders (was always 0).
    # One GROUP BY query for every template on the page — no N+1.
    counts = await prov.get_template_phone_counts([t.id for t in templates])
    items = []
    for tpl in templates:
        row = ConfigTemplateResponse.model_validate(tpl).model_dump(mode="json")
        # The FE reads ``phones_count`` (the schema's ``phone_count`` stays
        # for back-compat); surface both so neither contract drifts.
        n = counts.get(tpl.id, 0)
        row["phone_count"] = n
        row["phones_count"] = n
        items.append(row)
    return {"items": items, "total": total}


@templates_router.get("/{template_id}")
async def get_template(
    template_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Get a configuration template by ID."""
    from app.modules.voip.provisioning import ProvisioningError, ProvisioningService

    prov = ProvisioningService(session, organization_id=_org_id(current_user))
    try:
        return await prov.get_template(template_id)
    except ProvisioningError:
        raise HTTPException(status_code=404, detail="Template not found")


@templates_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_template(
    data: ConfigTemplateCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Create a new configuration template."""
    from app.modules.voip.provisioning import ProvisioningError, ProvisioningService

    payload = data.model_dump()
    # the create dialog has no site picker, so site_id was
    # always absent → required-field 422. Resolve it from the org's first
    # site when not supplied (mirrors create_phone above).
    supplied_site_id = payload.get("site_id")
    if supplied_site_id is not None:
        # site_id is client-controlled. A site-limited caller must
        # not be able to plant a template into a sibling site of the same org.
        # Validate the supplied grant up front (404 — no existence oracle).
        from app.core.site_access import assert_can_access_site

        assert_can_access_site(current_user, supplied_site_id, detail="Site not found")
    else:
        if current_user.organization_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="no site_id supplied and user is not attached to an organization",
            )
        from sqlalchemy import select

        from app.core.site_access import site_scope_filter
        from app.models.core import Site as SiteModel

        # when auto-selecting the org's first site, a site-limited
        # caller must land on a GRANTED site, not whatever the org's oldest
        # site happens to be. site_scope_filter is a no-op for super/org admin
        # and grant-less users, and AND-s the per-user grant for site-limited.
        site_row = (
            await session.execute(
                select(SiteModel.id)
                .where(
                    SiteModel.organization_id == current_user.organization_id,
                    SiteModel.deleted_at.is_(None),
                    site_scope_filter(current_user, SiteModel.id),
                )
                .order_by(SiteModel.created_at.asc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if site_row is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="no site available — create a site first",
            )
        payload["site_id"] = site_row

    prov = ProvisioningService(session, organization_id=_org_id(current_user))
    try:
        return await prov.create_template(payload)
    except ProvisioningError:
        # Service-level site validation rejected the resolved site (outside the
        # caller's org or per-user grant). 404 — no existence oracle.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")


@templates_router.patch("/{template_id}")
async def update_template(
    template_id: UUID,
    data: ConfigTemplateUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Update a configuration template."""
    from app.modules.voip.provisioning import ProvisioningError, ProvisioningService

    prov = ProvisioningService(session, organization_id=_org_id(current_user))
    try:
        return await prov.update_template(template_id, data.model_dump(exclude_unset=True))
    except ProvisioningError:
        raise HTTPException(status_code=404, detail="Template not found")


@templates_router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_template(
    template_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Delete a configuration template."""
    from app.modules.voip.provisioning import ProvisioningError, ProvisioningService

    prov = ProvisioningService(session, organization_id=_org_id(current_user))
    try:
        await prov.delete_template(template_id)
    except ProvisioningError:
        raise HTTPException(status_code=404, detail="Template not found")


# =============================================================================
# Provisioning Config Endpoint (Phone pulls config here — no auth)
# =============================================================================


@provisioning_router.get("/cfg{mac_address}.xml")
async def serve_phone_config(
    mac_address: str,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """HTTP provisioning endpoint — phones request their config here.

    Grandstream phones will request: ``GET /voip/provisioning/cfg{MAC}.xml``

    SECURITY: this endpoint was previously unauthenticated and
    returned config for ANY MAC. Anyone who knew or guessed a MAC could
    pull SIP credentials (P34) and admin web passwords (P2) for any
    tenant. We now require BOTH:

      1. The MAC must resolve to a known Phone row — the tenant is
         derived from that row's site, NEVER from request input.
      2. The source IP must be inside one of the site's configured
         subnets, OR the URL must carry a valid HMAC signature
         (``?sig=<hex>``) generated from the same MAC + the server's
         encryption key.

    Returns 404 on any failure so an attacker can't distinguish
    "MAC doesn't exist" from "MAC exists but you're not authorised".
    """
    from app.modules.voip.provisioning import ProvisioningService
    from app.modules.voip.provisioning_auth import resolve_provisioning_request

    ctx = await resolve_provisioning_request(request, session, mac_address)
    if ctx is None:
        # Generic 404 — never leak whether the MAC exists
        raise HTTPException(status_code=404, detail="No config for this device")

    # Bind the tenant context to the provisioning service so any
    # downstream queries are org-scoped.
    prov = ProvisioningService(session, organization_id=ctx.organization_id)
    result = await prov.get_config_for_mac(ctx.mac)

    if result is None:
        raise HTTPException(status_code=404, detail="No config for this device")

    xml_content, content_type = result
    return Response(content=xml_content, media_type=content_type)


# =============================================================================
# Fleet Dashboard & Bulk Operations
# =============================================================================


@fleet_router.get("/dashboard")
async def get_fleet_dashboard(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    site_id: UUID | None = None,
):
    """Get comprehensive fleet dashboard metrics (GDMS-style)."""
    _set_org(service, current_user)
    return await service.get_fleet_dashboard(site_id=site_id)


@fleet_router.post("/bulk/reboot")
async def bulk_reboot_phones(
    data: BulkOperationRequest,
    current_user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    session: Annotated[AsyncSession, Depends(get_session)],
    confirm: bool = Query(
        False, description="Must be true — rebooting phones disrupts active calls."
    ),
):
    """Bulk reboot multiple phones.

    Requires the ``site_admin`` role minimum (reboots take phones
    offline and disrupt active calls) AND an explicit confirm=true
    (FSDN-DW-BULK-REBOOT).

    G-H5 fix: every phone ID is validated against the caller's
    organization in ONE query. If even one phone doesn't belong to
    the caller's org the WHOLE request is rejected — partial bulk
    operations across orgs are an enumeration primitive that the
    previous per-iteration check made invisible.
    """
    if not confirm:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Bulk reboot disrupts active calls; pass confirm=true to proceed.",
        )

    from sqlalchemy import select

    from app.modules.voip.models import Phone
    from app.modules.voip.tasks import reboot_phone

    _set_org(service, current_user)
    # Verify org context is present (raises 400 if not). We don't
    # use the return value directly — the org filter is applied via
    # ``service._sites_for_org()`` below.
    _org_id(current_user)

    # Resolve every phone ID through the org-scoped service in one
    # query. Any ID that doesn't belong to this org is silently NOT
    # returned by the query — so if the count mismatches we know the
    # caller is probing other tenants' IDs.
    result = await session.execute(
        select(Phone.id).where(
            Phone.id.in_(data.phone_ids),
            Phone.site_id.in_(select(service._sites_for_org().c.id)),
            Phone.deleted_at.is_(None),
        )
    )
    valid_ids = {row.id for row in result.all()}

    if len(valid_ids) != len(data.phone_ids):
        # Refuse the whole batch — no partial success when org boundary
        # is being probed.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="One or more phone IDs are not in your organization",
        )

    succeeded = 0
    failed = 0
    errors = []

    from app.core.events import EventPriority
    from app.modules.voip.events import record_phone_action

    for phone_id in data.phone_ids:
        try:
            reboot_phone.delay(str(phone_id))
            succeeded += 1
            await record_phone_action(
                "reboot",
                phone_id=phone_id,
                adapter_id="grandstream",
                organization_id=current_user.organization_id,
                outcome="ok",
                priority=EventPriority.HIGH,
                bulk=True,
            )
        except Exception as exc:
            failed += 1
            errors.append(
                {"phone_id": str(phone_id), "error": f"Task dispatch failed ({type(exc).__name__})"}
            )
            await record_phone_action(
                "reboot",
                phone_id=phone_id,
                adapter_id="grandstream",
                organization_id=current_user.organization_id,
                outcome="failed",
                priority=EventPriority.HIGH,
                bulk=True,
                error=type(exc).__name__,
            )

    return {
        "operation": "bulk_reboot",
        "total": len(data.phone_ids),
        "succeeded": succeeded,
        "failed": failed,
        "skipped": 0,
        "errors": errors,
    }


@fleet_router.post("/bulk/provision")
async def bulk_provision_phones(
    data: BulkProvisionRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Bulk generate provisioning configs for multiple phones."""
    from app.modules.voip.provisioning import ProvisioningService

    prov = ProvisioningService(session, organization_id=_org_id(current_user))
    result = await prov.bulk_generate_configs(phone_ids=data.phone_ids)

    return {
        "operation": "bulk_provision",
        "total": result["total"],
        "succeeded": result["generated"],
        "failed": result["errors"],
        "skipped": result["total"] - result["generated"] - result["errors"],
        "errors": result.get("error_details", []),
    }


@fleet_router.post("/bulk/firmware")
async def bulk_firmware_upgrade(
    data: BulkFirmwareRequest,
    current_user: Annotated[CurrentUser, Depends(require_min_role("site_admin"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Schedule bulk firmware upgrade for multiple phones.

    Requires the ``site_admin`` role — firmware operations are
    irreversible and brick-the-fleet risky.
    """
    _set_org(service, current_user)
    result = await service.bulk_update_firmware(
        phone_ids=data.phone_ids,
        target_version=data.target_version,
        schedule_at=data.schedule_at,
    )
    return {
        "operation": "bulk_firmware",
        **result,
    }


@fleet_router.post("/bulk/connect", response_model=BulkConnectResponse)
async def bulk_connect_phones(
    data: BulkConnectRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """Bulk connect — set credentials and fully connect selected phones.

    For each phone:
      1. Look up stored IP
      2. Run full connection test (probe + login + fetch config)
      3. Save credentials on successful authentication
      4. Persist all discovered data (SIP, network, firmware, etc.)

    Returns per-phone results so the UI can show which succeeded/failed.
    """
    from app.modules.voip.discovery import test_phone_connection as _test_conn

    # FSDN-SG (VoIP site-grant sibling): bind the per-user site grant, not just
    # org. get_phone()/save_phone_credentials skip the grant filter when
    # accessible_site_ids is unset, which would let a site-limited caller probe
    # or write a SIBLING-site phone. _set_org binds both org and grant.
    svc = _set_org(VoIPService(db=session), current_user)
    succeeded = 0
    failed = 0
    skipped = 0
    errors: list[dict[str, str]] = []
    results: list[dict[str, Any]] = []

    for phone_id in data.phone_ids:
        try:
            phone = await svc.get_phone(phone_id)
        except PhoneNotFoundError:
            skipped += 1
            errors.append({"phone_id": str(phone_id), "error": "Phone not found"})
            continue

        ip = getattr(phone, "ip_address", None)
        if not ip:
            skipped += 1
            errors.append({"phone_id": str(phone_id), "error": "No IP address"})
            results.append(
                {
                    "phone_id": str(phone_id),
                    "name": getattr(phone, "name", None)
                    or getattr(phone, "mac_address", str(phone_id)),
                    "status": "skipped",
                    "error": "No IP address",
                }
            )
            continue

        try:
            result = await _test_conn(
                ip=ip,
                username=data.username,
                password=data.password,
            )

            # Save credentials on successful auth
            if result.get("authenticated"):
                await svc.save_phone_credentials(
                    phone_id=phone_id,
                    username=data.username,
                    password=data.password,
                )

            # Persist all discovered data
            await _persist_connection_result(phone, result, ip, session)
            succeeded += 1
            results.append(
                {
                    "phone_id": str(phone_id),
                    "name": getattr(phone, "name", None)
                    or getattr(phone, "mac_address", str(phone_id)),
                    "ip_address": ip,
                    "status": result.get("status", "unknown"),
                    "authenticated": result.get("authenticated", False),
                    "model": result.get("model"),
                    "firmware_version": result.get("firmware_version"),
                    "sip_registered": result.get("sip_registered", False),
                    "sip_account": result.get("sip_account"),
                }
            )
        except Exception as exc:
            failed += 1
            errors.append(
                {"phone_id": str(phone_id), "error": f"Connection failed ({type(exc).__name__})"}
            )
            results.append(
                {
                    "phone_id": str(phone_id),
                    "name": getattr(phone, "name", None)
                    or getattr(phone, "mac_address", str(phone_id)),
                    "ip_address": ip,
                    "status": "error",
                    "error": f"Connection failed ({type(exc).__name__})",
                }
            )

    return BulkConnectResponse(
        operation="bulk_connect",
        total=len(data.phone_ids),
        succeeded=succeeded,
        failed=failed,
        skipped=skipped,
        errors=errors,
        results=results,
    )


# =============================================================================
# Firmware Endpoints
# =============================================================================


@firmware_router.get("/")
async def list_firmware_tracks(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    site_id: UUID | None = None,
    vendor: str | None = None,
    model: str | None = Query(None, max_length=100),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List registered firmware versions."""
    _set_org(service, current_user)
    return {
        "items": await service.list_firmware_tracks(
            site_id=site_id,
            vendor=vendor,
            model=model,
            limit=limit,
            offset=offset,
        )
    }


@firmware_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_firmware_track(
    data: FirmwareTrackCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Register a firmware version for tracking."""
    _set_org(service, current_user)
    return await service.create_firmware_track(data.model_dump())


@firmware_router.get("/compliance")
async def get_firmware_compliance(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    site_id: UUID | None = None,
):
    """Get firmware compliance report across the fleet."""
    _set_org(service, current_user)
    return await service.get_firmware_compliance(site_id=site_id)


# =============================================================================
# PBX Endpoints
# =============================================================================


def _sanitize_pbx_response(pbx: Any) -> dict:
    """Convert PBX ORM object to dict with credentials stripped + redacted.

    Belt-and-braces: ``_sanitize_pbx_settings`` removes the known-bad
    keys, ``redact_secrets`` then walks the resulting dict for any other
    sensitive field names. The combination means a future field rename
    that adds a new credential key (eg ``proxy_password``) gets caught
    by the redaction even if we forget to add it to
    ``_SENSITIVE_SETTINGS_KEYS``.

    We also explicitly DROP the new ``*_password_enc`` columns from
    the output — Fernet tokens are themselves sensitive (they're a
    valid input to ``decrypt_credential`` for anyone with the key).
    """
    from sqlalchemy.inspection import inspect as sa_inspect

    try:
        state = sa_inspect(pbx)
        data = {c.key: getattr(pbx, c.key) for c in state.mapper.column_attrs}
    except Exception:
        data = pbx if isinstance(pbx, dict) else pbx.__dict__.copy()
        data.pop("_sa_instance_state", None)
    if "settings" in data:
        data["settings"] = _sanitize_pbx_settings(data.get("settings"))
    # Strip encrypted-column ciphertext from API response — never returned.
    # api_client_secret_enc (OAuth client secret, Fernet-encrypted at
    # service.py:1922/1941) was omitted from this loop → leak.
    for col in (
        "ami_secret_enc",
        "ari_password_enc",
        "web_password_enc",
        "api_client_secret_enc",
    ):
        data.pop(col, None)
    # Final pass through the shared redactor.
    return redact_secrets(data)


def _sanitize_phone_response(phone: Any) -> Any:
    """Strip encrypted columns + apply shared redaction to a Phone object."""
    from sqlalchemy.inspection import inspect as sa_inspect

    try:
        state = sa_inspect(phone)
        data = {c.key: getattr(phone, c.key) for c in state.mapper.column_attrs}
    except Exception:
        data = phone if isinstance(phone, dict) else phone.__dict__.copy()
        data.pop("_sa_instance_state", None)
    for col in ("sip_password_enc", "admin_password_enc", "xml_password_enc"):
        data.pop(col, None)
    return redact_secrets(data)


@pbx_router.get("/")
async def list_pbx_systems(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    site_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List all PBX systems."""
    _set_org(service, current_user)
    pbx_list, total = await service.list_pbx_systems(
        site_id=site_id,
        limit=limit,
        offset=offset,
    )
    items = [_sanitize_pbx_response(p) for p in pbx_list]
    # Populate the extension-count column the list table renders (was always 0).
    counts = await service.extension_counts([p.id for p in pbx_list])
    for item, p in zip(items, pbx_list, strict=True):
        item["extension_count"] = counts.get(p.id, 0)
    return {"items": items, "total": total}


@pbx_router.get("/{pbx_id}")
async def get_pbx(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Get a PBX by ID."""
    _set_org(service, current_user)
    try:
        pbx = await service.get_pbx(pbx_id)
        return _sanitize_pbx_response(pbx)
    except PBXNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PBX not found",
        )


@pbx_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_pbx(
    pbx_data: PBXCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Create a new PBX connection."""
    _set_org(service, current_user)
    try:
        return await service.create_pbx(pbx_data.model_dump())
    except CrossTenantError:
        # supplied site_id is outside the caller's org or per-user
        # site grant. 404 (not 403) avoids leaking the existence of a foreign
        # site.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Site not found",
        )


@pbx_router.patch("/{pbx_id}")
async def update_pbx(
    pbx_id: UUID,
    pbx_data: PBXUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Update a PBX connection."""
    _set_org(service, current_user)
    try:
        return await service.update_pbx(pbx_id, pbx_data.model_dump(exclude_unset=True))
    except PBXNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PBX not found",
        )


@pbx_router.delete("/{pbx_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_pbx(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Delete a PBX connection."""
    _set_org(service, current_user)
    try:
        await service.delete_pbx(pbx_id)
    except PBXNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PBX not found",
        )


@pbx_router.post("/test-connection")
async def test_pbx_connection(
    test_data: PBXTestConnection,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Test connectivity to a PBX system."""
    _set_org(service, current_user)
    return await service.test_pbx_connection(
        pbx_type=test_data.pbx_type,
        ip_address=test_data.ip_address,
        api_port=test_data.api_port,
        api_username=test_data.api_username,
        api_password=test_data.api_password,
        api_key=test_data.api_key,
        verify_ssl=test_data.verify_ssl,
        api_client_id=test_data.api_client_id,
        api_client_secret=test_data.api_client_secret,
    )


@pbx_router.post("/{pbx_id}/sync", status_code=status.HTTP_202_ACCEPTED)
async def sync_pbx(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Trigger a background PBX sync.

    Returns ``202 Accepted`` immediately with a ``task_id`` instead
    of blocking 30+ seconds while the adapter fetches 23 vendor
    endpoints. Operators watch progress through the ``pbx.sync.*``
    WebSocket event taxonomy:

        pbx.sync.started     — task picked up by Celery worker
        pbx.sync.progress    — per-stage update (connecting, extensions,
                               ring_groups, live_data, persisting, done)
        pbx.sync.completed   — final summary with per-resource counts
        pbx.sync.failed      — adapter-level failure

    Frontend filters by ``adapter_id == "pbx:<pbx_id>"`` and renders
    an interactive progress bar with live extension/trunk/ring-group
    counts as they stream in.

    The canonical pattern. Same shape applies to any
    long-running adapter operation that previously blocked the
    request thread.
    """
    _set_org(service, current_user)
    try:
        # Verify the PBX exists + is in the caller's org before
        # dispatching the task — fail-fast 404 here is better than
        # a Celery task that does nothing.
        pbx = await service.get_pbx(pbx_id)
    except PBXNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PBX not found",
        )

    from app.modules.voip.tasks import sync_pbx_full

    task = sync_pbx_full.delay(
        str(pbx_id),
        organization_id=str(current_user.organization_id),
        actor_id=str(current_user.id),
    )
    return {
        "task_id": task.id,
        "status": "queued",
        "pbx_id": str(pbx_id),
        "pbx_name": pbx.name,
        "message": (
            f"Sync queued for {pbx.name}. Watch live progress through "
            "the pbx.sync.* WebSocket events filtered by "
            f"adapter_id='pbx:{pbx_id}'."
        ),
    }


# -- PBX-scoped extensions --


@pbx_router.get("/{pbx_id}/extensions")
async def list_extensions(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List extensions for a PBX."""
    _set_org(service, current_user)
    extensions, total = await service.list_extensions(
        pbx_id=pbx_id,
        limit=limit,
        offset=offset,
    )

    # Batch-fetch any phones bound to these extensions so the FE can
    # render the bound device inline (IP, MAC, status) — one query
    # regardless of how many extensions came back.
    ext_ids = {e.id for e in extensions}
    phones_by_ext: dict = {}
    if ext_ids:
        bound_phones = await service.get_phones_by_extension_ids(ext_ids)
        for ph in bound_phones:
            phones_by_ext.setdefault(ph.extension_id, []).append(ph)

    # Flatten settings: merge synced_data into top-level settings dict
    # so the frontend can access s.tech, s.sipname, etc. directly.
    def _flatten_ext(ext):
        d = {
            "id": str(ext.id),
            "pbx_id": str(ext.pbx_id),
            "extension_number": ext.extension_number,
            "display_name": ext.display_name,
            "caller_id_name": ext.caller_id_name,
            "caller_id_number": ext.caller_id_number,
            "voicemail_enabled": ext.voicemail_enabled,
            "voicemail_pin": "****" if ext.voicemail_pin else None,
            "is_active": ext.is_active,
            "created_at": ext.created_at.isoformat() if ext.created_at else None,
            "updated_at": ext.updated_at.isoformat() if ext.updated_at else None,
        }
        raw_settings = dict(ext.settings or {})
        # If old nesting exists, flatten it
        if "synced_data" in raw_settings:
            synced = raw_settings.pop("synced_data")
            if isinstance(synced, dict):
                raw_settings.update(synced)
        # FreePBX sync can stuff SIP secrets (secret/auth_password/
        # sip_secret) into Extension.settings; redact before returning. Mirrors
        # the PBX/phone sanitizers which both end in redact_secrets().
        d["settings"] = redact_secrets(raw_settings)
        # Bound phone(s) — most extensions have 0 or 1, but defensively
        # support N (e.g. a hot-desk extension with multiple devices).
        bound = phones_by_ext.get(ext.id, [])
        d["bound_phones"] = [
            {
                "id": str(p.id),
                "name": p.name,
                "ip_address": p.ip_address,
                "mac_address": p.mac_address,
                "vendor": p.vendor,
                "model": p.model,
                "firmware_version": p.firmware_version,
                "status": p.status,
                "sip_registered": p.sip_registered,
                "lifecycle_state": p.lifecycle_state,
            }
            for p in bound
        ]
        return d

    return {"items": [_flatten_ext(e) for e in extensions], "total": total}


# -- PBX enterprise endpoints (adapter-backed) --


@pbx_router.post("/{pbx_id}/connect")
async def connect_pbx(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Full connection test for a saved PBX using the real adapter."""
    _set_org(service, current_user)
    try:
        return await service.connect_pbx(pbx_id)
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/dashboard")
async def get_pbx_dashboard(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Get comprehensive PBX dashboard with DB + live adapter data."""
    _set_org(service, current_user)
    try:
        return await service.get_pbx_dashboard(pbx_id)
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")


@pbx_router.get("/{pbx_id}/system-info")
async def get_pbx_system_info(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Get real-time PBX system information via adapter."""
    _set_org(service, current_user)
    try:
        return await service.get_pbx_system_info(pbx_id)
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/trunks")
async def list_pbx_trunks(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List SIP trunks from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_trunks(pbx_id)
        # PJSIP trunks have ``secret`` / ``auth_password`` fields that
        # the FreePBX REST scraper extracts as plaintext. redact_list
        # masks them before they reach the wire.
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/trunks/{trunk_id}")
async def get_pbx_trunk_detail(
    pbx_id: UUID,
    trunk_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Get detailed information about a single SIP trunk."""
    _set_org(service, current_user)
    try:
        return redact_secrets(await service.get_trunk_detail(pbx_id, trunk_id))
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("Trunk detail retrieval failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trunk not found")


# FreePBX exposes NO API to create/update/delete trunks (the GraphQL schema
# has no addTrunk/updateTrunk; only removeSipStationKeyAndDeleteTrunk). These
# endpoints previously reached the adapter directly — bypassing the staged
# dual-gate, apply-time RBAC, and the audit log — and always 502'd at the
# transport. They now return 501 up front: honest, and no request reaches the
# adapter or DB. Trunks are read-only via the API; manage them in FreePBX.
_TRUNK_WRITE_UNSUPPORTED = (
    "Trunk {op} is not supported: FreePBX exposes no API to write trunks. "
    "Manage trunks in the FreePBX admin UI."
)


@pbx_router.post("/{pbx_id}/trunks", status_code=status.HTTP_201_CREATED)
async def create_pbx_trunk(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))] = None,
):
    """Trunk creation is unsupported by the FreePBX API (501)."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=_TRUNK_WRITE_UNSUPPORTED.format(op="creation"),
    )


@pbx_router.patch("/{pbx_id}/trunks/{trunk_id}")
async def update_pbx_trunk(
    pbx_id: UUID,
    trunk_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))] = None,
):
    """Trunk update is unsupported by the FreePBX API (501)."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=_TRUNK_WRITE_UNSUPPORTED.format(op="update"),
    )


@pbx_router.delete("/{pbx_id}/trunks/{trunk_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_pbx_trunk(
    pbx_id: UUID,
    trunk_id: str,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))] = None,
):
    """Trunk deletion is unsupported by the FreePBX API (501)."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=_TRUNK_WRITE_UNSUPPORTED.format(op="deletion"),
    )


@pbx_router.get("/{pbx_id}/queues")
async def list_pbx_queues(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List call queues from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_queues(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/ivrs")
async def list_pbx_ivrs(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List IVR menus from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_ivrs(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/dids")
async def list_pbx_dids(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List DIDs / Inbound Routes from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_dids(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/active-calls")
async def get_pbx_active_calls(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view_calls"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Get active calls from the PBX in real-time."""
    _set_org(service, current_user)
    try:
        items = await service.get_pbx_active_calls(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/voicemail-boxes")
async def list_pbx_voicemail_boxes(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List voicemail boxes from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_voicemail_boxes(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


# ── Rich PBX data endpoints ─────────────────────────────────


@pbx_router.get("/{pbx_id}/config")
async def get_pbx_full_config(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Comprehensive PBX configuration snapshot — all synced data in one call."""
    _set_org(service, current_user)
    try:
        # Full config contains every synced_cache list — push through
        # the shared redactor so any new vendor-specific secret field
        # is automatically masked.
        return redact_secrets(await service.get_pbx_full_config(pbx_id))
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/outbound-routes")
async def list_pbx_outbound_routes(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List outbound routes from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_outbound_routes(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/followme")
async def list_pbx_followme(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List Follow-Me entries from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_followme(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/announcements")
async def list_pbx_announcements(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List announcements from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_announcements(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/paging")
async def list_pbx_paging_groups(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List paging / intercom groups from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_paging_groups(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/daynight")
async def list_pbx_daynight(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List day/night call-flow controls from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_daynight(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/blacklist")
async def list_pbx_blacklist(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List blacklisted numbers from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_blacklist(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/certificates")
async def list_pbx_certificates(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List SSL/TLS certificates from the PBX."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_certificates(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/admin-users")
async def list_pbx_admin_users(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """List FreePBX admin (AMP) users."""
    _set_org(service, current_user)
    try:
        items = await service.list_pbx_admin_users(pbx_id)
        return {"items": redact_list(items), "total": len(items)}
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.get("/{pbx_id}/ring-groups")
async def list_pbx_ring_groups(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List ring groups for a specific PBX."""
    _set_org(service, current_user)
    groups, total = await service.list_ring_groups(
        pbx_id=pbx_id,
        limit=limit,
        offset=offset,
    )
    return {"items": groups, "total": total}


@pbx_router.get("/{pbx_id}/call-logs")
async def search_pbx_call_logs(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view_calls"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    # Call log filters reach the DB LIKE/EQ predicates — cap to keep
    # query patterns bounded.
    src: str | None = Query(None, max_length=64),
    dst: str | None = Query(None, max_length=64),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Search call logs from the PBX (live CDR via adapter)."""
    _set_org(service, current_user)
    try:
        items = await service.search_pbx_call_logs(
            pbx_id,
            start_date=start_date,
            end_date=end_date,
            src=src,
            dst=dst,
            limit=limit,
            offset=offset,
        )
        # ``total`` used to be ``len(items)`` -- the size of the page, not the
        # size of the result set, so the UI saw one page and every "next"
        # returned the same rows. The upstream CDR API exposes no count, so
        # report the honest lower bound plus an explicit ``has_more``.
        page = redact_list(items)
        return {
            "items": page,
            "total": offset + len(page),
            "has_more": len(page) == limit,
            "offset": offset,
            "limit": limit,
        }
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


# -- PBX Extension CRUD (adapter-backed) --


@pbx_router.get("/{pbx_id}/extensions/{ext_number}")
async def get_pbx_extension_detail(
    pbx_id: UUID,
    ext_number: Annotated[str, Path(min_length=1, max_length=20, pattern=r"^\d+$")],
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Get detailed information about a single extension."""
    _set_org(service, current_user)
    try:
        return await service.get_extension_detail(pbx_id, ext_number)
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("Extension detail retrieval failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Extension not found")


@pbx_router.post("/{pbx_id}/extensions", status_code=status.HTTP_201_CREATED)
async def create_pbx_extension(
    pbx_id: UUID,
    ext_data: ExtensionCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Create a new extension on the PBX."""
    _set_org(service, current_user)
    try:
        return await service.create_pbx_extension(pbx_id, ext_data.model_dump())
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.patch("/{pbx_id}/extensions/{ext_number}")
async def update_pbx_extension(
    pbx_id: UUID,
    ext_number: Annotated[str, Path(min_length=1, max_length=20, pattern=r"^\d+$")],
    ext_data: ExtensionUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Update an extension on the PBX."""
    _set_org(service, current_user)
    try:
        return await service.update_pbx_extension(
            pbx_id,
            ext_number,
            ext_data.model_dump(exclude_unset=True),
        )
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.delete("/{pbx_id}/extensions/{ext_number}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_pbx_extension(
    pbx_id: UUID,
    ext_number: Annotated[str, Path(min_length=1, max_length=20, pattern=r"^\d+$")],
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Delete an extension from the PBX."""
    _set_org(service, current_user)
    try:
        await service.delete_pbx_extension(pbx_id, ext_number)
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


# -- PBX Call Control --


@pbx_router.post("/{pbx_id}/call/originate")
async def originate_call(
    pbx_id: UUID,
    data: OriginateCallRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Originate an outbound call via the PBX."""
    _set_org(service, current_user)
    outcome = "failed"
    try:
        result = await service.originate_call(
            pbx_id,
            data.extension,
            data.destination,
            caller_id=data.caller_id,
            context=data.context,
        )
        outcome = "ok"
        return result
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )
    finally:
        # Platform-citizen event — originate is the highest-leverage
        # PBX write because compliance / call-recording / fraud-watch
        # rules typically need to trigger on it. NORMAL priority;
        # bump via automation if needed.
        from app.modules.voip.events import record_pbx_action

        await record_pbx_action(
            "originate_call",
            pbx_id=pbx_id,
            adapter_id="freepbx",
            organization_id=current_user.organization_id,
            outcome=outcome,
            extension=data.extension,
            destination=data.destination,
        )


@pbx_router.post("/{pbx_id}/call/hangup")
async def hangup_call(
    pbx_id: UUID,
    data: HangupCallRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Hang up an active call on the PBX."""
    _set_org(service, current_user)
    try:
        return await service.hangup_call(pbx_id, data.channel)
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.post("/{pbx_id}/call/transfer")
async def transfer_call(
    pbx_id: UUID,
    data: TransferCallRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Transfer an active call to another extension."""
    _set_org(service, current_user)
    try:
        return await service.transfer_call(
            pbx_id,
            data.channel,
            data.destination,
            data.context,
        )
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


# -- PBX System Operations --


@pbx_router.post("/{pbx_id}/reload")
async def reload_pbx_config(
    pbx_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Apply pending PBX configuration changes."""
    _set_org(service, current_user)
    outcome = "failed"
    try:
        result = await service.reload_pbx_config(pbx_id)
        outcome = "ok"
        return result
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )
    finally:
        # Catastrophic-ish — reload drops every active call mid-frame
        # on FreePBX for a few hundred ms. HIGH priority so noisy
        # rules can filter on it.
        from app.core.events import EventPriority
        from app.modules.voip.events import record_pbx_action

        await record_pbx_action(
            "reload",
            pbx_id=pbx_id,
            adapter_id="freepbx",
            organization_id=current_user.organization_id,
            outcome=outcome,
            priority=EventPriority.HIGH,
        )


@pbx_router.post("/{pbx_id}/queue/add-member")
async def queue_add_member(
    pbx_id: UUID,
    data: QueueMemberRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Add a member to a call queue."""
    _set_org(service, current_user)
    try:
        return await service.queue_add_member(
            pbx_id,
            data.queue_name,
            data.interface,
            data.member_name or "",
        )
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@pbx_router.post("/{pbx_id}/queue/remove-member")
async def queue_remove_member(
    pbx_id: UUID,
    data: QueueMemberRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Remove a member from a call queue."""
    _set_org(service, current_user)
    try:
        return await service.queue_remove_member(pbx_id, data.queue_name, data.interface)
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("VoIP gateway error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


# =============================================================================
# Extensions (cross-PBX)
# =============================================================================


@extensions_router.get("/")
async def list_all_extensions(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    site_id: UUID | None = Query(None, description="Scope to extensions whose PBX is at this site"),
):
    """List all extensions across all PBX systems.

    ``site_id`` scopes the list to extensions whose PBX lives at the
    given site. Extensions are PBX-scoped in the data model — the
    filter joins through voip.pbx to translate site → PBX → extension.
    """
    _set_org(service, current_user)
    extensions, total = await service.list_all_extensions(
        limit=limit,
        offset=offset,
        site_id=site_id,
    )
    # redact FreePBX SIP secrets in Extension.settings + mask voicemail_pin
    # before returning to a voip.view (viewer) caller — parity with the
    # list_extensions sibling (_flatten_ext /). Detach FIRST: get_session()
    # auto-commits, so mutating an attached row would persist the redaction over
    # the real stored secret. redact_secrets recurses into the nested synced_data
    # blob, so the response shape is preserved.
    for ext in extensions:
        service.db.expunge(ext)
        ext.settings = redact_secrets(dict(ext.settings or {}))
        if ext.voicemail_pin:
            ext.voicemail_pin = "****"
    return {"items": extensions, "total": total}


# =============================================================================
# Ring Group Endpoints
# =============================================================================


@ring_groups_router.get("/")
async def list_ring_groups(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    pbx_id: UUID | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    site_id: UUID | None = Query(None),
):
    """List ring groups."""
    _set_org(service, current_user)
    groups, total = await service.list_ring_groups(
        pbx_id=pbx_id,
        limit=limit,
        offset=offset,
        site_id=site_id,
    )
    return {"items": groups, "total": total}


@ring_groups_router.post("/", status_code=status.HTTP_201_CREATED)
async def create_ring_group(
    data: RingGroupCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_extensions"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Create a ring group on a PBX.

    ``pbx_id`` is resolved through the org-scoped ``get_pbx`` inside the
    service, so a caller can only target a PBX in their own organization.
    """
    _set_org(service, current_user)
    try:
        return await service.create_ring_group(data.model_dump())
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        logger.error("Ring group create failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


@ring_groups_router.delete("/{ring_group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ring_group(
    ring_group_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_extensions"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Delete a ring group.

    The service looks the row up org-scoped (via the PBX→site→org join)
    before touching the PBX, so cross-org deletes 404 rather than leak.
    """
    _set_org(service, current_user)
    try:
        await service.delete_ring_group(ring_group_id)
    except PBXNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PBX not found")
    except VoIPError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Ring group not found"
            )
        logger.error("Ring group delete failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="PBX communication error"
        )


# =============================================================================
# Call Log Endpoints
# =============================================================================


@call_logs_router.get("/")
async def search_call_logs(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view_calls"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    pbx_id: UUID | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    direction: str | None = Query(None, max_length=16),
    call_status: str | None = Query(None, max_length=32),
    caller: str | None = Query(None, max_length=64),
    callee: str | None = Query(None, max_length=64),
    limit: int = Query(100, ge=1, le=1000),
    site_id: UUID | None = Query(None),
):
    """Search call logs."""
    _set_org(service, current_user)
    logs, total = await service.search_call_logs(
        pbx_id=pbx_id,
        start_time=start_time,
        end_time=end_time,
        direction=direction,
        status=call_status,
        caller=caller,
        callee=callee,
        limit=limit,
        site_id=site_id,
    )

    # Enrich each CDR row with its PBX's human name so the FE "PBX"
    # column isn't always '-'. One batched, org-scoped query for all
    # distinct PBX IDs on the page (mirrors the phones list endpoint).
    pbx_ids = {log.pbx_id for log in logs if log.pbx_id}
    pbx_map: dict = await service.get_pbx_systems_by_ids(pbx_ids) if pbx_ids else {}

    items = []
    for log in logs:
        row = {c.key: getattr(log, c.key) for c in log.__mapper__.column_attrs}
        pbx = pbx_map.get(log.pbx_id) if log.pbx_id else None
        if pbx is not None:
            row["pbx_system_id"] = str(pbx.id)
            row["pbx_system_name"] = pbx.name
        items.append(row)

    return {"items": items, "total": total}


@call_logs_router.get("/stats")
async def get_call_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view_calls"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    pbx_id: UUID | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    site_id: UUID | None = Query(None),
):
    """Get call statistics."""
    _set_org(service, current_user)
    return await service.get_call_stats(
        pbx_id=pbx_id,
        start_time=start_time,
        end_time=end_time,
        site_id=site_id,
    )


# =============================================================================
# Voicemail Endpoints
# =============================================================================


@voicemails_router.get("/")
async def list_voicemails(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    extension_number: str | None = Query(None, max_length=32),
    folder: str | None = Query(None, max_length=32),
    is_read: bool | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    site_id: UUID | None = Query(None),
):
    """List voicemail messages."""
    _set_org(service, current_user)
    messages, total = await service.list_voicemails(
        extension_number=extension_number,
        folder=folder,
        is_read=is_read,
        limit=limit,
        offset=offset,
        site_id=site_id,
    )
    return {"items": messages, "total": total}


@voicemails_router.get("/stats")
async def get_voicemail_stats(
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
    extension_number: str | None = Query(None, max_length=32),
    site_id: UUID | None = Query(None),
):
    """Get voicemail statistics."""
    _set_org(service, current_user)
    return await service.get_voicemail_stats(extension_number=extension_number, site_id=site_id)


@voicemails_router.get("/{vm_id}")
async def get_voicemail(
    vm_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Get a voicemail message by ID."""
    _set_org(service, current_user)
    try:
        return await service.get_voicemail(vm_id)
    except VoicemailNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Voicemail not found",
        )


@voicemails_router.patch("/{vm_id}")
async def update_voicemail(
    vm_id: UUID,
    data: VoicemailUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Update a voicemail (mark read, move folder)."""
    _set_org(service, current_user)
    try:
        return await service.update_voicemail(vm_id, data.model_dump(exclude_unset=True))
    except VoicemailNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Voicemail not found",
        )


@voicemails_router.post("/{vm_id}/mark-read")
async def mark_voicemail_read(
    vm_id: UUID,
    # State mutation requires manage_phones, not just view. Was an
    # asymmetry — POST /mark-read accepted voip.view while the
    # parallel PATCH /{vm_id} (line 2557) and DELETE require
    # voip.manage_phones.
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Mark a voicemail as read."""
    _set_org(service, current_user)
    try:
        return await service.mark_voicemail_read(vm_id)
    except VoicemailNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Voicemail not found",
        )


@voicemails_router.delete("/{vm_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_voicemail(
    vm_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.manage_phones"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Delete a voicemail message."""
    _set_org(service, current_user)
    try:
        await service.delete_voicemail(vm_id)
    except VoicemailNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Voicemail not found",
        )


@voicemails_router.get("/{vm_id}/download")
async def download_voicemail(
    vm_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("voip.view"))],
    service: Annotated[VoIPService, Depends(get_voip_service)],
):
    """Voicemail audio download — NOT YET AVAILABLE.

    ``VoicemailMessage.file_path`` holds the recording's spool path on
    the *remote PBX* host (e.g. ``/var/spool/asterisk/voicemail/.../msg0000.wav``).
    FreeSDN runs as a separate service and has no filesystem access to
    that path, and no FreePBX/Asterisk adapter method exposes the
    recording bytes over its API (the REST/AJAX client explicitly
    returns nothing for voicemail; ARI only serves call recordings, not
    mailbox messages). So there is currently NO safe, read-only way to
    retrieve the audio.

    This previously returned ``file_path`` as if it were downloadable,
    which let the UI hand the user a dead server-side path. We now fail
    honestly with 501 rather than leak the spool path. The org-scoped
    lookup is still performed first so this can't be used to probe
    whether a voicemail ID exists in another tenant (404 wins over 501).

    To implement real downloads later: add a read-only adapter method to
    fetch the recording bytes (e.g. AMI ``VoicemailRefresh`` + a sound
    file fetch, or an out-of-band SCP/agent on the PBX), then stream them
    here with the correct ``audio/wav`` media type. Until then the FE
    keeps the Download button disabled with an explanatory tooltip.
    """
    _set_org(service, current_user)
    try:
        # Resolve (and org-scope) the row so a cross-tenant ID still 404s.
        await service.get_voicemail(vm_id)
    except VoicemailNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Voicemail not found",
        )
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "Voicemail audio retrieval is not available — the recording is "
            "stored only on the PBX and is not reachable through the adapter."
        ),
    )

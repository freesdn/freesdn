# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Credentials Endpoints
====================================

CRUD + test for stored credentials.
"""

import logging
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_credential, encrypt_credential, is_encrypted
from app.core.dependencies import (
    CurrentUser,
    is_unscoped_superuser,
    require_permissions,
)
from app.core.site_access import assert_can_access_site, site_scope_filter
from app.db import get_session
from app.models import Credential, Device
from app.models.core import Site
from app.schemas.core import MessageResponse
from app.schemas.credentials import (
    CredentialCreate,
    CredentialResponse,
    CredentialTestRequest,
    CredentialTestResponse,
    CredentialUpdate,
)

# Fields that may be set on PATCH/PUT. Anything not in this set is
# silently ignored to prevent mass-assignment of internal columns
# (``organization_id``, ``created_by``, ``last_used``,
# ``last_test_result``, etc.). Secret fields get encrypted via
# ``_SECRET_FIELD_MAP`` first.
_UPDATABLE_FIELDS = frozenset(
    {
        "name",
        "description",
        "credential_type",
        "scope",
        "vendor",
        "site_id",
        "username",
        "is_default",
        "options",
    }
)

# Input-field → DB-column mapping for fields that need encryption
# before persistence. Previously this missed ``ssh_private_key`` and
# ``certificate``, so SSH keys went to the DB in plaintext.
_SECRET_FIELD_MAP = {
    "password": "encrypted_password",
    "api_key": "api_key",
    "token": "token",
    "snmp_community": "snmp_community",
    "ssh_private_key": "ssh_private_key",
    "certificate": "certificate",
}


async def _verify_site_in_org(
    session: AsyncSession,
    site_id: UUID | None,
    organization_id: UUID,
    current_user: CurrentUser,
) -> None:
    """404 if ``site_id`` is set but the caller may not attach to it.

    Two gates, both 404 (no existence oracle):

    1. Org ownership — previously POST/PUT happily attached a
       credential to a ``site_id`` belonging to another org (the FK to
       ``core.sites`` is satisfied because the table is global, but
       ``Credential.site`` resolution would then return a foreign-org
       Site object).
    2. Per-user site grant — a site-limited operator
       (granted Site A only) must not be able to bind a credential to a
       sibling Site B in the same org. ``assert_can_access_site`` is a
       no-op for super_admin / org_admin / grant-less users and for a
       ``None`` site_id (org-level credential).
    """
    if site_id is None:
        return
    result = await session.execute(
        select(Site.id).where(
            Site.id == site_id,
            Site.organization_id == organization_id,
            Site.deleted_at.is_(None),
        )
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Site not found")
    # Enforce the per-user site grant on the referenced site.
    assert_can_access_site(current_user, site_id, detail="Site not found")


async def _demote_other_defaults(
    session: AsyncSession,
    *,
    organization_id: UUID,
    scope: Any,
    vendor: str | None,
    keep_id: UUID | None = None,
) -> None:
    """Unset ``is_default`` on siblings in the same (org, scope, vendor).

    Without this two credentials could both be ``is_default=True`` in
    the same scope and downstream lookups (``.where(is_default=True)
    .limit(1)``) would return nondeterministic results.
    """
    clauses = [
        Credential.organization_id == organization_id,
        Credential.scope == scope,
        Credential.is_default.is_(True),
        Credential.deleted_at.is_(None),
    ]
    if vendor is not None:
        clauses.append(Credential.vendor == vendor)
    else:
        clauses.append(Credential.vendor.is_(None))
    if keep_id is not None:
        clauses.append(Credential.id != keep_id)
    await session.execute(sa_update(Credential).where(*clauses).values(is_default=False))


logger = logging.getLogger(__name__)
router = APIRouter()


# ===========================================
# Credential CRUD
# ===========================================


@router.get("/", response_model=list[CredentialResponse])
async def list_credentials(
    current_user: Annotated[CurrentUser, Depends(require_permissions("settings:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    scope: str | None = None,
    vendor: str | None = None,
    credential_type: str | None = None,
    site_id: UUID | None = None,
) -> Any:
    """List all credentials for the current organization."""
    query = select(Credential).where(
        Credential.deleted_at.is_(None),
        Credential.is_active.is_(True),
    )

    if not is_unscoped_superuser(current_user):
        query = query.where(Credential.organization_id == current_user.organization_id)

    # Per-user site grant: a site-limited operator only
    # sees credentials bound to a granted site (or org-level rows with
    # ``site_id IS NULL`` — global/vendor credentials are not
    # site-bound and remain visible). No-op for super_admin /
    # org_admin / grant-less users. Site-level credentials in sibling
    # sites are filtered out even though they share the org.
    query = query.where(
        or_(
            Credential.site_id.is_(None),
            site_scope_filter(current_user, Credential.site_id),
        )
    )

    if scope:
        query = query.where(Credential.scope == scope)
    if vendor:
        query = query.where(Credential.vendor == vendor)
    if credential_type:
        query = query.where(Credential.credential_type == credential_type)
    if site_id:
        query = query.where(Credential.site_id == site_id)

    query = query.order_by(Credential.name)
    result = await session.execute(query)
    credentials = result.scalars().all()

    # Batch device counts in a single query (avoids N+1)
    cred_ids = [c.id for c in credentials]
    device_counts: dict[UUID, int] = {}
    if cred_ids:
        counts_result = await session.execute(
            select(Device.credential_id, func.count(Device.id))
            .where(Device.credential_id.in_(cred_ids), Device.deleted_at.is_(None))
            .group_by(Device.credential_id)
        )
        device_counts = {row[0]: row[1] for row in counts_result.all()}

    responses = []
    for cred in credentials:
        resp = CredentialResponse.model_validate(cred)
        resp.devices_count = device_counts.get(cred.id, 0)
        responses.append(resp)

    return responses


@router.post("/", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
async def create_credential(
    data: CredentialCreate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("settings:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Create a new credential."""
    await _verify_site_in_org(session, data.site_id, current_user.organization_id, current_user)
    if data.is_default:
        await _demote_other_defaults(
            session,
            organization_id=current_user.organization_id,
            scope=data.scope,
            vendor=data.vendor,
        )
    credential = Credential(
        organization_id=current_user.organization_id,
        name=data.name,
        description=data.description,
        credential_type=data.credential_type,
        scope=data.scope,
        vendor=data.vendor,
        site_id=data.site_id,
        username=data.username,
        # All secret fields go through ``encrypt_credential`` —
        # previously ``ssh_private_key`` and ``certificate`` were
        # silently dropped (not in the create assignment), leaving
        # SSH-key credentials non-functional at the vendor layer.
        encrypted_password=encrypt_credential(data.password) if data.password else None,
        api_key=encrypt_credential(data.api_key) if data.api_key else None,
        token=encrypt_credential(data.token) if data.token else None,
        snmp_community=encrypt_credential(data.snmp_community) if data.snmp_community else None,
        ssh_private_key=encrypt_credential(data.ssh_private_key) if data.ssh_private_key else None,
        certificate=encrypt_credential(data.certificate) if data.certificate else None,
        is_default=data.is_default,
        options=data.options,
    )

    session.add(credential)
    await session.commit()
    await session.refresh(credential)

    return CredentialResponse.model_validate(credential)


@router.get("/{credential_id}", response_model=CredentialResponse)
async def get_credential(
    credential_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("settings:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Get a specific credential."""
    query = select(Credential).where(
        Credential.id == credential_id,
        Credential.deleted_at.is_(None),
    )
    if not is_unscoped_superuser(current_user):
        query = query.where(Credential.organization_id == current_user.organization_id)

    result = await session.execute(query)
    credential = result.scalar_one_or_none()
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Per-user site grant: a site-limited operator cannot read a
    # credential bound to a sibling site. Org-level (site_id IS NULL)
    # credentials remain readable.
    assert_can_access_site(current_user, credential.site_id, detail="Credential not found")

    return CredentialResponse.model_validate(credential)


@router.put("/{credential_id}", response_model=CredentialResponse)
async def update_credential(
    credential_id: UUID,
    data: CredentialUpdate,
    current_user: Annotated[CurrentUser, Depends(require_permissions("settings:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Update a credential."""
    query = select(Credential).where(
        Credential.id == credential_id,
        Credential.deleted_at.is_(None),
    )
    if not is_unscoped_superuser(current_user):
        query = query.where(Credential.organization_id == current_user.organization_id)

    result = await session.execute(query)
    credential = result.scalar_one_or_none()
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Per-user site grant: a site-limited operator cannot modify a
    # credential bound to a sibling site (gate the EXISTING binding).
    assert_can_access_site(current_user, credential.site_id, detail="Credential not found")

    update_data = data.model_dump(exclude_unset=True)

    # Validate ``site_id`` belongs to caller's org AND that the caller
    # holds a grant for it (same gate as create) BEFORE any field
    # assignment — prevents re-homing a credential into a sibling site.
    if "site_id" in update_data and update_data["site_id"] is not None:
        await _verify_site_in_org(
            session,
            update_data["site_id"],
            current_user.organization_id,
            current_user,
        )

    # Encrypt secret-field inputs, then map to their model columns.
    for input_field, model_field in _SECRET_FIELD_MAP.items():
        if input_field in update_data:
            value = update_data.pop(input_field)
            update_data[model_field] = encrypt_credential(value) if value else None

    # If this PUT promotes the row to default, demote any siblings
    # in the same (org, scope, vendor) first. Scope/vendor on the
    # current row may have been changed in the same PUT so use the
    # incoming values when present.
    if update_data.get("is_default") is True:
        await _demote_other_defaults(
            session,
            organization_id=current_user.organization_id,
            scope=update_data.get("scope", credential.scope),
            vendor=update_data.get("vendor", credential.vendor),
            keep_id=credential.id,
        )

    # Explicit allowlist of FE-writable fields. Previously the loop
    # was ``if hasattr(credential, key)`` which let any model column
    # through — including internal counters
    # (``last_used``/``last_test_result``) and audit columns.
    allowed = _UPDATABLE_FIELDS | set(_SECRET_FIELD_MAP.values())
    for key, value in update_data.items():
        if key in allowed:
            setattr(credential, key, value)

    await session.commit()
    await session.refresh(credential)

    return CredentialResponse.model_validate(credential)


@router.delete("/{credential_id}", response_model=MessageResponse)
async def delete_credential(
    credential_id: UUID,
    current_user: Annotated[CurrentUser, Depends(require_permissions("settings:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Soft-delete a credential."""
    query = select(Credential).where(
        Credential.id == credential_id,
        Credential.deleted_at.is_(None),
    )
    if not is_unscoped_superuser(current_user):
        query = query.where(Credential.organization_id == current_user.organization_id)

    result = await session.execute(query)
    credential = result.scalar_one_or_none()
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Per-user site grant: a site-limited operator cannot delete a
    # credential bound to a sibling site.
    assert_can_access_site(current_user, credential.site_id, detail="Credential not found")

    credential.deleted_at = datetime.now(UTC)
    await session.commit()

    return MessageResponse(message="Credential deleted")


@router.post("/{credential_id}/test", response_model=CredentialTestResponse)
async def test_credential(
    credential_id: UUID,
    data: CredentialTestRequest,
    current_user: Annotated[CurrentUser, Depends(require_permissions("settings:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Any:
    """Test a credential against a target device."""
    query = select(Credential).where(
        Credential.id == credential_id,
        Credential.deleted_at.is_(None),
    )
    if not is_unscoped_superuser(current_user):
        query = query.where(Credential.organization_id == current_user.organization_id)

    result = await session.execute(query)
    credential = result.scalar_one_or_none()
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Per-user site grant: a site-limited operator cannot test (and
    # thereby exercise the decrypted secret of) a credential bound to a
    # sibling site.
    assert_can_access_site(current_user, credential.site_id, detail="Credential not found")

    # /L1 (residual hardening): testing a stored credential sends its
    # plaintext to the target, so make every test DETECTABLE — log actor +
    # credential + requested destination.
    logger.warning(
        "AUDIT stored-credential test: actor=%s credential_id=%s requested_target=%s",
        getattr(current_user, "id", None),
        credential_id,
        data.target_ip,
    )

    import httpx

    from app.core.security_utils import resolve_and_pin_host, validate_target_host

    target_ip = data.target_ip
    port = data.port or 443

    # SECURITY: Validate target IP to prevent SSRF against loopback/metadata.
    # RFC1918 is intentionally allowed — credential tests probe LAN devices.
    try:
        validate_target_host(target_ip, allow_private=True)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target: {e}",
        )

    # TOCTOU / DNS-rebind pin — resolve and validate ONCE, then build
    # the connection URL from the returned IP literal so httpx never performs a
    # second DNS lookup that could be poisoned (loopback/link-local/metadata).
    # RFC1918 is still reachable (allow_private=True); only loopback /
    # link-local / metadata addresses are rejected at pin time.
    try:
        pinned_host = resolve_and_pin_host(target_ip, allow_private=True)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target: {e}",
        )

    # this endpoint always sends a STORED credential's plaintext, so the
    # destination must be a private/on-prem device — never a caller-chosen public
    # host (stored-secret egress). Mirrors the discovery /test-credentials fix.
    from app.core.security_utils import is_private_ip

    if not is_private_ip(pinned_host):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A stored credential may only be tested against a private/on-prem address.",
        )

    username = credential.username or ""
    password = credential.encrypted_password or ""
    if password and is_encrypted(password):
        password = decrypt_credential(password)

    # Bump last_used at test-start (mirrors how driver runs use it
    # to age out stale creds). Result outcome is recorded after the
    # HTTP call so we don't pollute it on transport-level failures.
    credential.last_used = datetime.now(UTC)

    # SECURITY: HTTPS only. The previous loop fell through to HTTP
    # on any HTTPS ConnectError/ReadTimeout — basic-auth then sent
    # the decrypted username + password in CLEARTEXT over a plain
    # HTTP socket. Operators that genuinely need to probe an HTTP-
    # only management interface must opt in with
    # ``allow_plaintext_http: true``.
    schemes: list[str] = ["https"]
    if data.allow_plaintext_http:
        schemes.append("http")

    last_err_kind: str | None = None
    for scheme in schemes:
        verify_ssl = data.verify_ssl if scheme == "https" else True
        try:
            # Build URL from the pinned IP literal so httpx connects to a fixed
            # address — no second DNS lookup, no rebind window.
            url = f"{scheme}://{pinned_host}:{port}/"
            async with httpx.AsyncClient(verify=verify_ssl, timeout=10) as client:
                resp = await client.get(
                    url,
                    auth=(username, password) if username else None,
                    follow_redirects=False,
                )
            if resp.status_code < 500:
                credential.last_test_result = "success"
                await session.commit()
                return CredentialTestResponse(
                    success=True,
                    message=f"Connected successfully via {scheme.upper()} (HTTP {resp.status_code})",
                    device_info={
                        "status_code": resp.status_code,
                        "scheme": scheme,
                        "verify_ssl": data.verify_ssl if scheme == "https" else None,
                    },
                )
        except (httpx.ConnectError, httpx.ReadTimeout):
            last_err_kind = "connect"
            continue
        except Exception as e:
            # Generic error type only — do NOT echo ``str(e)``. httpx
            # exception strings embed the full URL + sometimes proxy
            # chains + cert subjects. Log the detail server-side.
            logger.warning("Credential test failed for %s: %s", credential.id, e, exc_info=True)
            last_err_kind = type(e).__name__
            break

    credential.last_test_result = "failed"
    await session.commit()
    return CredentialTestResponse(
        success=False,
        message=(
            "Test failed (no response from target)" if last_err_kind == "connect" else "Test failed"
        ),
    )

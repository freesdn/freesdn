# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Credentials Endpoints
====================================

CRUD + test for stored credentials.
"""

import hashlib
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
    # Visibility alone does not authorize a write under a read-only site grant.
    if not current_user.has_site_permission("settings:write", site_id):
        raise HTTPException(status_code=403, detail="Write permission required for this site")


async def _serialize_credential_writes(session: AsyncSession, organization_id: UUID) -> None:
    """Serialize management-API credential writes through commit or rollback.

    Empty default groups have no row to lock. A namespaced PostgreSQL
    transaction advisory lock also covers two simultaneous inserts. Locks are
    scoped to the owning organization, so unrelated organizations can proceed.
    This does not enforce uniqueness for raw SQL or independently run restores.
    """
    digest = hashlib.sha256(f"freesdn:credential-management:{organization_id}".encode()).digest()
    key = int.from_bytes(digest[:8], byteorder="big", signed=True)
    await session.execute(select(func.pg_advisory_xact_lock(key)))


async def _reload_credential_for_write(session: AsyncSession, credential: Credential) -> Credential:
    """Reload the binding after serialization; a preceding writer may move it."""
    owner = credential.organization_id
    credential_id = credential.id
    await _serialize_credential_writes(session, owner)
    result = await session.execute(
        select(Credential)
        .where(
            Credential.id == credential_id,
            Credential.organization_id == owner,
            Credential.deleted_at.is_(None),
        )
        .execution_options(populate_existing=True)
    )
    current: Credential | None = result.scalar_one_or_none()
    if current is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    return current


async def _demote_other_defaults(
    session: AsyncSession,
    *,
    organization_id: UUID,
    site_id: UUID | None,
    scope: Any,
    vendor: str | None,
    keep_id: UUID | None = None,
) -> None:
    """Demote live defaults only in the exact (org, site, scope, vendor) group.

    A NULL site denotes the org-level group, not all sites. This operation
    requires its management-API caller to hold the organization transaction
    lock. It does not repair duplicates outside the promoted group.
    """
    clauses = [
        Credential.organization_id == organization_id,
        Credential.site_id == site_id if site_id is not None else Credential.site_id.is_(None),
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
        device_counts = {row[0]: row[1] for row in counts_result.all() if row[0] is not None}

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
    organization_id = current_user.organization_id
    if organization_id is None:
        raise HTTPException(status_code=403, detail="Organization context required")
    await _serialize_credential_writes(session, organization_id)
    await _verify_site_in_org(session, data.site_id, organization_id, current_user)
    if data.is_default:
        await _demote_other_defaults(
            session,
            organization_id=organization_id,
            site_id=data.site_id,
            scope=data.scope,
            vendor=data.vendor,
        )
    credential = Credential(
        organization_id=organization_id,
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
    # Visibility alone does not authorize a write under a read-only site grant.
    if credential.site_id is not None and not current_user.has_site_permission(
        "settings:write", credential.site_id
    ):
        raise HTTPException(status_code=403, detail="Write permission required for this site")

    credential = await _reload_credential_for_write(session, credential)
    assert_can_access_site(current_user, credential.site_id, detail="Credential not found")
    if credential.site_id is not None and not current_user.has_site_permission(
        "settings:write", credential.site_id
    ):
        raise HTTPException(status_code=403, detail="Write permission required for this site")

    update_data = data.model_dump(exclude_unset=True)

    # Validate ``site_id`` belongs to the credential's org AND that the caller
    # holds a grant for it (same gate as create) BEFORE any field
    # assignment — prevents re-homing a credential into a sibling site.
    if "site_id" in update_data and update_data["site_id"] is not None:
        await _verify_site_in_org(
            session,
            update_data["site_id"],
            credential.organization_id,
            current_user,
        )

    # Encrypt secret-field inputs, then map to their model columns.
    for input_field, model_field in _SECRET_FIELD_MAP.items():
        if input_field in update_data:
            value = update_data.pop(input_field)
            update_data[model_field] = encrypt_credential(value) if value else None

    # A default moved to another group must replace that group's default even
    # when the caller omits is_default. Metadata-only edits do not repair or
    # demote other rows; explicit false leaves destination defaults untouched.
    group_changed = any(
        field in update_data and update_data[field] != getattr(credential, field)
        for field in ("site_id", "scope", "vendor")
    )
    if update_data.get("is_default", credential.is_default) is True and (
        update_data.get("is_default") is True or group_changed
    ):
        await _demote_other_defaults(
            session,
            organization_id=credential.organization_id,
            site_id=update_data.get("site_id", credential.site_id),
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
    # Visibility alone does not authorize a write under a read-only site grant.
    if credential.site_id is not None and not current_user.has_site_permission(
        "settings:write", credential.site_id
    ):
        raise HTTPException(status_code=403, detail="Write permission required for this site")

    credential = await _reload_credential_for_write(session, credential)
    assert_can_access_site(current_user, credential.site_id, detail="Credential not found")
    if credential.site_id is not None and not current_user.has_site_permission(
        "settings:write", credential.site_id
    ):
        raise HTTPException(status_code=403, detail="Write permission required for this site")

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
    """Check HTTP connectivity without claiming credential authentication."""
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
    # Visibility alone does not authorize a write under a read-only site grant.
    if credential.site_id is not None and not current_user.has_site_permission(
        "settings:write", credential.site_id
    ):
        raise HTTPException(status_code=403, detail="Write permission required for this site")

    # /L1 (residual hardening): testing a stored credential sends its
    # plaintext to the target, so make every test DETECTABLE — log actor +
    # credential + requested destination.
    logger.warning(
        "AUDIT stored-credential test: actor=%s credential_id=%s requested_target=%s",
        getattr(current_user, "id", None),
        credential_id,
        data.target_ip,
    )

    import asyncio
    import ipaddress

    import httpx

    from app.core.security_utils import resolve_and_pin_host, validate_target_host

    target_ip = data.target_ip
    if target_ip.startswith("[") and target_ip.endswith("]"):
        try:
            target_ip = str(ipaddress.IPv6Address(target_ip[1:-1]))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid target: bracketed targets must be IPv6 literals.",
            ) from None
    try:
        target_address = ipaddress.ip_address(target_ip)
    except ValueError:
        pass  # Hostnames retain their original identity for Host/SNI below.
    else:
        if isinstance(target_address, ipaddress.IPv6Address):
            target_address = target_address.ipv4_mapped or target_address
        # Apply every existing target check to the canonical address, including
        # the embedded IPv4 of mapped literals; never bypass metadata checks.
        target_ip = str(target_address)
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

    # One elapsed transport budget covers HTTPS and any explicitly enabled
    # plaintext fallback. Per-read timeouts alone allow a peer to drip data
    # indefinitely. DNS validation and database commits are separate work.
    deadline = asyncio.get_running_loop().time() + 10
    last_err_kind: str | None = None
    for scheme in schemes:
        verify_ssl = data.verify_ssl if scheme == "https" else True
        try:
            async with asyncio.timeout_at(deadline):
                # Build URL from the pinned IP literal so httpx connects to a
                # fixed address without a second, rebindable DNS lookup.
                url_host = f"[{pinned_host}]" if ":" in pinned_host else pinned_host
                url = f"{scheme}://{url_host}:{port}/"
                request_options: dict[str, Any] = {}
                if target_ip != pinned_host:
                    # The socket remains pinned to the validated IP. Retain the
                    # requested hostname for virtual-host routing and certificate
                    # identity, including SNI when verification is opted out.
                    original_url = httpx.URL(scheme=scheme, host=target_ip, port=port)
                    request_options["headers"] = {"Host": original_url.netloc.decode("ascii")}
                    if scheme == "https":
                        request_options["extensions"] = {"sni_hostname": original_url.host}
                # Retain CA configuration while excluding ambient proxies.
                verify_context = httpx.create_ssl_context(verify=verify_ssl, trust_env=True)
                async with httpx.AsyncClient(
                    verify=verify_context, timeout=10, trust_env=False
                ) as client:
                    async with client.stream(
                        "GET",
                        url,
                        auth=(username, password) if username else None,
                        follow_redirects=False,
                        **request_options,
                    ) as response:
                        # This check needs only the status. Never download or
                        # decompress an arbitrary device response body.
                        status_code = response.status_code
            # A generic HTTP endpoint can answer without authenticating the
            # supplied credential. Only report an HTTP connectivity outcome.
            # Receiving an error or redirect is final: do not retry plaintext
            # after a completed HTTPS response, even when fallback is enabled.
            reachable = 200 <= status_code < 300
            credential.last_test_result = "reachable" if reachable else "failed"
            await session.commit()
            return CredentialTestResponse(
                success=reachable,
                message=(
                    f"HTTP connectivity check returned HTTP {status_code} "
                    f"via {scheme.upper()}; authentication was not verified."
                ),
                device_info={
                    "status_code": status_code,
                    "scheme": scheme,
                    "verify_ssl": data.verify_ssl if scheme == "https" else None,
                    "check_kind": "http_connectivity",
                    "authentication_verified": False,
                },
            )
        except TimeoutError:
            last_err_kind = "deadline"
            break
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
            "Test failed (transport time budget exceeded)"
            if last_err_kind == "deadline"
            else "Test failed (no response from target)"
            if last_err_kind == "connect"
            else "Test failed"
        ),
    )

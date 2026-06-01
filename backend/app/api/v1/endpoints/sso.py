# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SSO API Endpoints
=================================

Endpoints for SSO provider management and OIDC/SAML/LDAP auth flows.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import require_roles
from app.db import get_session
from app.models.core import Organization, User, UserRole
from app.models.sso import SSOProtocol
from app.schemas.sso import (
    LDAPAuthRequest,
    SSOAuthorizeRequest,
    SSOAuthorizeResponse,
    SSOCallbackRequest,
    SSOCallbackResponse,
    SSOProviderCreate,
    SSOProviderPublic,
    SSOProviderResponse,
    SSOProviderUpdate,
    SSOTestConnectionResponse,
)
from app.services.sso import (
    SSOAuthError,
    SSOCallbackError,
    SSOConfigError,
    SSONotSupportedError,
    SSOService,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _org_id(user: User) -> Any:
    """Extract the organisation ID from the authenticated user's token."""
    oid = getattr(user, "organization_id", None)
    if not oid:
        raise HTTPException(400, detail="Organization context required")
    return oid


def _require_saml_certificate(protocol: Any, saml_certificate: str | None) -> None:
    """
    Reject SAML provider create/update that lacks a signing
    certificate. Unsigned SAML assertions are forgeable (attacker could
    claim NameID=super_admin@target.com), so the field is mandatory.
    """
    if protocol != SSOProtocol.SAML:
        return
    if not saml_certificate or not str(saml_certificate).strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=(
                "saml_certificate is required for SAML providers. "
                "Unsigned SAML assertions are not accepted."
            ),
        )


# Role hierarchy from most-privileged (index 0) to least. Used to bound a
# provider's JIT ``default_role`` to roles at or below the creating admin's
# own tier.
_ROLE_TIER: dict[str, int] = {
    UserRole.SUPER_ADMIN.value: 0,
    UserRole.ORG_ADMIN.value: 1,
    UserRole.SITE_ADMIN.value: 2,
    UserRole.OPERATOR.value: 3,
    UserRole.VIEWER.value: 4,
}


def _validate_default_role(default_role: Any, current_user: User) -> None:
    """
    Bound the SSO provider's JIT ``default_role`` so an admin cannot
    configure a provider that auto-provisions accounts above the admin's own
    privilege tier.

    Without this gate ``default_role`` is a free-string field, so an org_admin
    could set ``default_role="super_admin"``; ``_map_role()`` then returns that
    value verbatim when no role_mapping group matches, and JIT provisioning
    mints a real super_admin user — a privilege escalation that bypasses the
    deliberate "never auto-grant super_admin via SSO" filter already applied to
    the group-claim path in ``SSOService._map_role``.

    ``None`` means "unchanged" (PATCH) or "use the schema default" and is
    allowed; an empty/whitespace value is treated as unset.
    """
    if default_role is None:
        return
    role_str = str(default_role).strip()
    if not role_str:
        return
    if role_str not in _ROLE_TIER:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid default_role: {role_str!r}",
        )
    # super_admin is never a valid JIT default_role, mirroring the group-claim
    # filter in SSOService._map_role ("Never auto-grant super_admin via SSO").
    if role_str == UserRole.SUPER_ADMIN.value:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="default_role=super_admin is not permitted for SSO providers.",
        )
    caller_role = str(getattr(current_user, "role", "") or "")
    caller_tier = _ROLE_TIER.get(caller_role)
    # An admin may only set a default_role at or below their own tier. If the
    # caller's role is unrecognised, fall back to the most-restrictive tier.
    if caller_tier is None:
        caller_tier = max(_ROLE_TIER.values())
    if _ROLE_TIER[role_str] < caller_tier:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="default_role exceeds your privilege tier.",
        )


def _validate_role_mapping(role_mapping: Any, current_user: User) -> None:
    """
    (symmetry)cap the provider's group->role ``role_mapping`` the same
    way ``default_role`` is capped. ``_map_role`` already refuses to grant
    super_admin from a group claim, but it does NOT tier-check the other roles,
    and ``_validate_default_role`` only guards ``default_role`` — so without this
    an admin could map an IdP group to a role ABOVE their own tier (a privilege
    escalation the moment provider management is ever delegated below org_admin).
    Reject super_admin targets and any target above the caller's tier.

    ``None`` (PATCH-unchanged) is allowed.
    """
    if not role_mapping:
        return
    if not isinstance(role_mapping, dict):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="role_mapping must be an object of {role: [groups]}.",
        )
    caller_role = str(getattr(current_user, "role", "") or "")
    caller_tier = _ROLE_TIER.get(caller_role)
    if caller_tier is None:
        caller_tier = max(_ROLE_TIER.values())
    for target_role in role_mapping:
        role_str = str(target_role).strip()
        if not role_str:
            continue
        if role_str not in _ROLE_TIER:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role in role_mapping: {role_str!r}",
            )
        if role_str == UserRole.SUPER_ADMIN.value:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail="role_mapping may not grant super_admin via SSO.",
            )
        if _ROLE_TIER[role_str] < caller_tier:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"role_mapping grants '{role_str}', which exceeds your privilege tier.",
            )


# =============================================================================
# Public endpoints (login page – no auth required)
# =============================================================================


@router.get(
    "/providers/public",
    response_model=list[SSOProviderPublic],
    summary="List active SSO providers for login page",
)
async def list_public_providers(
    organization_slug: str | None = Query(None),
    db: AsyncSession = Depends(get_session),
) -> list[SSOProviderPublic]:
    """Return minimal SSO provider info for rendering login-page buttons."""
    svc = SSOService(db)
    # require an organization slug for public provider
    # discovery. Without it, the endpoint would return every active tenant's
    # SSO provider metadata to an anonymous caller (cross-tenant enumeration).
    if not organization_slug:
        return []
    organization_id = None
    if organization_slug:
        org_result = await db.execute(
            select(Organization.id).where(
                Organization.slug == organization_slug,
                Organization.deleted_at.is_(None),
                Organization.is_active.is_(True),
            )
        )
        organization_id = org_result.scalar_one_or_none()
        if organization_id is None:
            return []

    providers = await svc.list_providers(
        organization_id=organization_id,
        active_only=True,
    )
    return [SSOProviderPublic.model_validate(p) for p in providers]


# =============================================================================
# OIDC Flow
# =============================================================================


@router.post(
    "/oidc/authorize",
    response_model=SSOAuthorizeResponse,
    summary="Initiate OIDC login",
)
async def oidc_authorize(
    body: SSOAuthorizeRequest,
    db: AsyncSession = Depends(get_session),
) -> SSOAuthorizeResponse:
    """Start an OIDC authorization-code flow. Returns the redirect URL."""
    svc = SSOService(db)
    provider = await svc.get_provider_by_slug(body.provider_slug)
    if not provider or provider.protocol != SSOProtocol.OIDC:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "OIDC provider not found")
    if provider.status.value != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "SSO provider is not active")

    try:
        result = await svc.oidc_authorize(provider, redirect_uri=body.redirect_uri)
        await db.commit()
        return result
    except SSOConfigError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


@router.post(
    "/oidc/callback",
    response_model=SSOCallbackResponse,
    summary="OIDC callback",
)
async def oidc_callback(
    body: SSOCallbackRequest,
    response: Response,
    db: AsyncSession = Depends(get_session),
) -> SSOCallbackResponse:
    """Exchange the OIDC authorization code for FreeSDN tokens."""
    if not body.code:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing authorization code")

    svc = SSOService(db)
    try:
        result = await svc.oidc_callback(state=body.state, code=body.code)
        await db.commit()
        # if local MFA is required, do NOT set auth cookies —
        # the client must complete the TOTP challenge via /auth/login/mfa.
        if result.require_mfa:
            return result
        # Set httpOnly cookies for browser clients
        from app.core.cookies import set_auth_cookies

        if result.access_token and result.refresh_token:
            set_auth_cookies(response, result.access_token, result.refresh_token)
            # cookies are the browser auth channel — do NOT also
            # echo the raw bearer/refresh tokens in the JSON body (observable by
            # page JS / logging / extensions, defeating httpOnly). Browser
            # clients check `authenticated`.
            result.access_token = None
            result.refresh_token = None
            # signal success without echoing raw tokens.
            # Browser clients check `authenticated` instead of `access_token`.
            result.authenticated = True
        return result
    except SSOCallbackError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except SSOAuthError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))
    except SSOConfigError as e:
        logger.error("SSO configuration error: %s", e, exc_info=True)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "SSO configuration error")


# =============================================================================
# SAML Flow
# =============================================================================


@router.post(
    "/saml/login",
    response_model=SSOAuthorizeResponse,
    summary="Initiate SAML login",
)
async def saml_login(
    body: SSOAuthorizeRequest,
    db: AsyncSession = Depends(get_session),
) -> SSOAuthorizeResponse:
    """Start a SAML auth flow. Returns the IdP redirect URL."""
    svc = SSOService(db)
    provider = await svc.get_provider_by_slug(body.provider_slug)
    if not provider or provider.protocol != SSOProtocol.SAML:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SAML provider not found")
    if provider.status.value != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "SSO provider is not active")

    try:
        result = await svc.saml_login(provider, redirect_uri=body.redirect_uri)
        await db.commit()
        return result
    except SSOConfigError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


@router.post(
    "/saml/callback",
    response_model=SSOCallbackResponse,
    summary="SAML ACS callback",
)
async def saml_callback(
    body: SSOCallbackRequest,
    response: Response,
    db: AsyncSession = Depends(get_session),
) -> SSOCallbackResponse:
    """Process a SAML Response and issue FreeSDN tokens."""
    if not body.saml_response:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing SAML response")

    svc = SSOService(db)
    try:
        result = await svc.saml_callback(state=body.state, saml_response_b64=body.saml_response)
        await db.commit()
        # if local MFA is required, do NOT set auth cookies —
        # the client must complete the TOTP challenge via /auth/login/mfa.
        if result.require_mfa:
            return result
        # Set httpOnly cookies for browser clients
        from app.core.cookies import set_auth_cookies

        if result.access_token and result.refresh_token:
            set_auth_cookies(response, result.access_token, result.refresh_token)
            # cookies are the browser auth channel — do NOT also
            # echo the raw bearer/refresh tokens in the JSON body (observable by
            # page JS / logging / extensions, defeating httpOnly). Browser
            # clients check `authenticated`.
            result.access_token = None
            result.refresh_token = None
            # signal success without echoing raw tokens.
            result.authenticated = True
        return result
    except SSONotSupportedError as e:
        # SAML acceptance path is disabled until a reference-
        # validating verifier replaces the XSW-vulnerable validate_sign()+re-parse.
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, str(e))
    except SSOCallbackError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except SSOAuthError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))


# =============================================================================
# LDAP Flow
# =============================================================================


@router.post(
    "/ldap/authenticate",
    response_model=SSOCallbackResponse,
    summary="Authenticate via LDAP",
)
async def ldap_authenticate(
    body: LDAPAuthRequest,
    response: Response,
    db: AsyncSession = Depends(get_session),
) -> SSOCallbackResponse:
    """Authenticate with username/password against an LDAP directory."""
    svc = SSOService(db)
    provider = await svc.get_provider_by_slug(body.provider_slug)
    if not provider or provider.protocol != SSOProtocol.LDAP:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "LDAP provider not found")
    if provider.status.value != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "SSO provider is not active")

    try:
        result = await svc.ldap_authenticate(provider, body.username, body.password)
        await db.commit()
        # if local MFA is required, do NOT set auth cookies —
        # the client must complete the TOTP challenge via /auth/login/mfa.
        if result.require_mfa:
            return result
        # Set httpOnly cookies for browser clients
        from app.core.cookies import set_auth_cookies

        if result.access_token and result.refresh_token:
            set_auth_cookies(response, result.access_token, result.refresh_token)
            # cookies are the browser auth channel — do NOT also
            # echo the raw bearer/refresh tokens in the JSON body (observable by
            # page JS / logging / extensions, defeating httpOnly). Browser
            # clients check `authenticated`.
            result.access_token = None
            result.refresh_token = None
            # signal success without echoing raw tokens.
            result.authenticated = True
        return result
    except SSOAuthError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))
    except SSOConfigError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


# =============================================================================
# Provider Management (admin-only)
# =============================================================================


@router.get(
    "/providers",
    response_model=list[SSOProviderResponse],
    summary="List SSO providers",
)
async def list_providers(
    protocol: str | None = Query(None),
    db: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_roles([UserRole.SUPER_ADMIN, UserRole.ORG_ADMIN])),
) -> list[SSOProviderResponse]:
    """List all SSO providers (admin only)."""
    org_id = _org_id(current_user)
    svc = SSOService(db)
    proto = SSOProtocol(protocol) if protocol else None
    providers = await svc.list_providers(organization_id=org_id, protocol=proto)
    return [SSOProviderResponse.model_validate(p) for p in providers]


@router.get(
    "/providers/{provider_id}",
    response_model=SSOProviderResponse,
    summary="Get SSO provider details",
)
async def get_provider(
    provider_id: UUID,
    db: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_roles([UserRole.SUPER_ADMIN, UserRole.ORG_ADMIN])),
) -> SSOProviderResponse:
    """Get details of a specific SSO provider."""
    org_id = _org_id(current_user)
    svc = SSOService(db)
    provider = await svc.get_provider(provider_id)
    if not provider or provider.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO provider not found")
    return SSOProviderResponse.model_validate(provider)


@router.post(
    "/providers",
    response_model=SSOProviderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create SSO provider",
)
async def create_provider(
    body: SSOProviderCreate,
    db: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_roles([UserRole.SUPER_ADMIN, UserRole.ORG_ADMIN])),
) -> SSOProviderResponse:
    """Create a new SSO provider configuration."""
    org_id = _org_id(current_user)
    body.organization_id = org_id
    _require_saml_certificate(
        getattr(body, "protocol", None),
        getattr(body, "saml_certificate", None),
    )
    _validate_default_role(getattr(body, "default_role", None), current_user)
    _validate_role_mapping(getattr(body, "role_mapping", None), current_user)
    svc = SSOService(db)
    provider = await svc.create_provider(body, created_by=current_user.id)
    await db.commit()
    return SSOProviderResponse.model_validate(provider)


@router.patch(
    "/providers/{provider_id}",
    response_model=SSOProviderResponse,
    summary="Update SSO provider",
)
async def update_provider(
    provider_id: UUID,
    body: SSOProviderUpdate,
    db: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_roles([UserRole.SUPER_ADMIN, UserRole.ORG_ADMIN])),
) -> SSOProviderResponse:
    """Update an existing SSO provider."""
    org_id = _org_id(current_user)
    svc = SSOService(db)
    existing = await svc.get_provider(provider_id)
    if not existing or existing.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO provider not found")
    # enforce signing-certificate requirement at update time.
    # Protocol may come from the patch body or remain unchanged on existing.
    effective_protocol = getattr(body, "protocol", None) or existing.protocol
    # If the patch provides saml_certificate use that, else fall back to
    # whatever is already persisted on the provider row.
    patched_cert = getattr(body, "saml_certificate", None)
    effective_cert = patched_cert if patched_cert is not None else existing.saml_certificate
    _require_saml_certificate(effective_protocol, effective_cert)
    # a PATCH that changes default_role must stay within the caller's
    # tier (None = unchanged, skipped inside the helper).
    _validate_default_role(getattr(body, "default_role", None), current_user)
    _validate_role_mapping(getattr(body, "role_mapping", None), current_user)
    provider = await svc.update_provider(provider_id, body, updated_by=current_user.id)
    if not provider:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO provider not found")
    await db.commit()
    return SSOProviderResponse.model_validate(provider)


@router.delete(
    "/providers/{provider_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Delete SSO provider",
)
async def delete_provider(
    provider_id: UUID,
    db: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_roles([UserRole.SUPER_ADMIN, UserRole.ORG_ADMIN])),
) -> None:
    """Soft-delete an SSO provider."""
    org_id = _org_id(current_user)
    svc = SSOService(db)
    existing = await svc.get_provider(provider_id)
    if not existing or existing.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO provider not found")
    deleted = await svc.delete_provider(provider_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO provider not found")
    await db.commit()


@router.post(
    "/providers/{provider_id}/test",
    response_model=SSOTestConnectionResponse,
    summary="Test SSO provider connectivity",
)
async def test_provider_connection(
    provider_id: UUID,
    db: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_roles([UserRole.SUPER_ADMIN, UserRole.ORG_ADMIN])),
) -> SSOTestConnectionResponse:
    """Test connectivity to the identity provider."""
    org_id = _org_id(current_user)
    svc = SSOService(db)
    provider = await svc.get_provider(provider_id)
    if not provider or provider.organization_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO provider not found")
    return await svc.test_connection(provider)

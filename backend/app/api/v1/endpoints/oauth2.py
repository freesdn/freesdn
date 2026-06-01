# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - OAuth2 Authorization Server
==========================================

Implements OAuth2 Authorization Code flow with PKCE (RFC 7636).
Also supports Client Credentials grant for machine-to-machine access.

Endpoints:
  GET/POST /oauth2/authorize  — Authorization endpoint (consent)
  POST     /oauth2/token      — Token endpoint (code exchange, refresh)
  POST     /oauth2/revoke     — Token revocation (RFC 7009)
  GET      /oauth2/apps       — List registered apps
  POST     /oauth2/apps       — Register new app
  GET      /oauth2/apps/{id}  — Get app
  PUT      /oauth2/apps/{id}  — Update app
  DELETE   /oauth2/apps/{id}  — Delete app
  POST     /oauth2/apps/{id}/rotate-secret — Rotate client secret
"""

import base64
import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import urlparse
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_active_user
from app.db import get_session
from app.models.core import User
from app.models.oauth2 import OAuth2App, OAuth2AuthorizationCode, OAuth2Token

logger = logging.getLogger(__name__)

router = APIRouter()

# Token lifetimes
ACCESS_TOKEN_TTL = timedelta(hours=1)
REFRESH_TOKEN_TTL = timedelta(days=30)
AUTH_CODE_TTL = timedelta(minutes=10)


# =============================================================================
# Helpers
# =============================================================================


def _generate_client_credentials() -> tuple[str, str, str, str]:
    """Generate client_id, client_secret, secret_hash, secret_prefix."""
    client_id = secrets.token_urlsafe(32)  # 43 chars
    client_secret = f"fsd_cs_{secrets.token_hex(32)}"  # 72 chars
    secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
    secret_prefix = client_secret[:12]
    return client_id, client_secret, secret_hash, secret_prefix


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _generate_token() -> str:
    return secrets.token_urlsafe(48)


def _normalize_scopes(scopes: list[str]) -> list[str]:
    """Deduplicate scopes while preserving order."""
    return list(dict.fromkeys(scope for scope in scopes if scope))


def _validate_owned_scopes(current_user: CurrentUser, scopes: list[str]) -> list[str]:
    """Ensure a user cannot register scopes beyond their own permissions."""
    normalized_scopes = _normalize_scopes(scopes)
    if normalized_scopes and not current_user.has_permission("*"):
        unauthorized_scopes = [
            scope
            for scope in normalized_scopes
            if scope == "*" or not current_user.has_permission(scope)
        ]
        if unauthorized_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot grant OAuth2 app scopes beyond your own permissions",
            )
    return normalized_scopes


def _validate_requested_scopes(requested_scopes: list[str], allowed_scopes: list[str]) -> list[str]:
    """Ensure a token request only asks for scopes registered on the app."""
    normalized_requested = _normalize_scopes(requested_scopes)
    allowed_scope_set = set(allowed_scopes)
    if any(scope not in allowed_scope_set for scope in normalized_requested):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Requested scopes exceed the app's registered scopes",
        )
    return normalized_requested


def _verify_pkce(code_challenge: str, code_verifier: str, method: str = "S256") -> bool:
    """Verify PKCE code_verifier against stored code_challenge (S256 only)."""
    if method != "S256":
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


async def _get_app_or_404(
    session: AsyncSession,
    app_id: UUID,
    user_id: UUID | None = None,
) -> OAuth2App:
    q = select(OAuth2App).where(OAuth2App.id == app_id, OAuth2App.is_active == True)  # noqa: E712
    if user_id:
        q = q.where(OAuth2App.user_id == user_id)
    result = await session.execute(q)
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2 app not found")
    return app


# =============================================================================
# Schemas
# =============================================================================

# restrict OAuth2 redirect_uris to safe URL schemes. An unvalidated
# list allowed org_admins to register javascript:, data:, or attacker-domain
# URIs and turn /authorize into an open redirect / token-stealing gadget.
BLOCKED_REDIRECT_SCHEMES = {
    "javascript",
    "data",
    "file",
    "vbscript",
    "about",
    "blob",
}
MAX_REDIRECT_URIS = 10
MAX_REDIRECT_URI_LENGTH = 2048
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _validate_single_redirect_uri(uri: str) -> None:
    """Raise ValueError if ``uri`` is not a safe OAuth2 redirect target.

    Used both by the AppCreate/AppUpdate pydantic validators AND as
    defense-in-depth at /authorize time (in case a stored URI slipped
    through from before this validator existed).
    """
    if not isinstance(uri, str) or not uri.strip():
        raise ValueError("redirect_uri must be a non-empty string")
    if len(uri) > MAX_REDIRECT_URI_LENGTH:
        raise ValueError(f"redirect_uri too long (max {MAX_REDIRECT_URI_LENGTH} chars)")

    try:
        parsed = urlparse(uri)
    except Exception as e:
        raise ValueError(f"invalid redirect_uri: {uri}") from e

    scheme = (parsed.scheme or "").lower()
    if scheme in BLOCKED_REDIRECT_SCHEMES:
        raise ValueError(f"redirect_uri scheme {scheme!r} is blocked")

    # Must be an absolute URL with scheme + host.
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"redirect_uri must be an absolute URL: {uri}")

    if scheme == "http":
        host = (parsed.hostname or "").lower()
        # http:// is only allowed for loopback addresses (local dev).
        if host not in LOCAL_HOSTS:
            raise ValueError(f"http:// is only allowed for localhost. Use https:// for {uri}")
    elif scheme != "https":
        raise ValueError(f"redirect_uri must use https:// (got {scheme}://)")

    # RFC 6749 requires exact match — no wildcards.
    if "*" in uri:
        raise ValueError(f"wildcards not allowed in redirect_uri: {uri}")


def _validate_redirect_uri_list(v: list[str]) -> list[str]:
    if not v:
        raise ValueError("at least one redirect_uri is required")
    if len(v) > MAX_REDIRECT_URIS:
        raise ValueError(f"too many redirect URIs (max {MAX_REDIRECT_URIS})")
    for uri in v:
        _validate_single_redirect_uri(uri)
    return v


class AppCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    # 10 redirect URIs / 64 scopes / 8 grants per app is generous —
    # most real apps need 1-3 redirects + a handful of scopes.
    redirect_uris: list[str] = Field(default_factory=list, max_length=10)
    scopes: list[str] = Field(default_factory=list, max_length=64)
    grant_types: list[str] = Field(
        default_factory=lambda: ["authorization_code", "refresh_token"],
        max_length=8,
    )
    is_confidential: bool = True
    logo_url: str | None = Field(None, max_length=2048)
    homepage_url: str | None = Field(None, max_length=2048)

    @field_validator("redirect_uris")
    @classmethod
    def _check_redirect_uris(cls, v: list[str]) -> list[str]:
        return _validate_redirect_uri_list(v)


class AppUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    redirect_uris: list[str] | None = Field(None, max_length=10)
    scopes: list[str] | None = Field(None, max_length=64)
    logo_url: str | None = Field(None, max_length=2048)
    homepage_url: str | None = Field(None, max_length=2048)

    @field_validator("redirect_uris")
    @classmethod
    def _check_redirect_uris(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        return _validate_redirect_uri_list(v)


class AppResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    client_id: str
    client_secret_prefix: str
    redirect_uris: list[str]
    scopes: list[str]
    grant_types: list[str]
    is_active: bool
    is_confidential: bool
    logo_url: str | None
    homepage_url: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class AppCreated(AppResponse):
    """Includes the plaintext client_secret — only shown once."""

    client_secret: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = int(ACCESS_TOKEN_TTL.total_seconds())
    refresh_token: str | None = None
    scope: str = ""


# =============================================================================
# App Management Endpoints
# =============================================================================


@router.get("/apps", response_model=list[AppResponse])
async def list_apps(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[OAuth2App]:
    """List all OAuth2 apps registered by the current user."""
    result = await session.execute(
        select(OAuth2App)
        .where(OAuth2App.user_id == current_user.id, OAuth2App.is_active == True)  # noqa: E712
        .order_by(OAuth2App.created_at.desc())
    )
    return result.scalars().all()


@router.post("/apps", response_model=AppCreated, status_code=status.HTTP_201_CREATED)
async def register_app(
    body: AppCreate,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AppCreated:
    """
    Register a new OAuth2 application.

    **The client_secret is only returned once — store it securely.**
    """
    client_id, client_secret, secret_hash, secret_prefix = _generate_client_credentials()
    app_scopes = _validate_owned_scopes(current_user, body.scopes)

    app = OAuth2App(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        name=body.name,
        description=body.description,
        client_id=client_id,
        client_secret_hash=secret_hash,
        client_secret_prefix=secret_prefix,
        redirect_uris=body.redirect_uris,
        scopes=app_scopes,
        grant_types=body.grant_types,
        is_confidential=body.is_confidential,
        logo_url=body.logo_url,
        homepage_url=body.homepage_url,
    )
    session.add(app)
    await session.commit()
    await session.refresh(app)

    return AppCreated(
        id=app.id,
        name=app.name,
        description=app.description,
        client_id=app.client_id,
        client_secret=client_secret,  # Only time shown!
        client_secret_prefix=app.client_secret_prefix,
        redirect_uris=app.redirect_uris,
        scopes=app.scopes,
        grant_types=app.grant_types,
        is_active=app.is_active,
        is_confidential=app.is_confidential,
        logo_url=app.logo_url,
        homepage_url=app.homepage_url,
        created_at=app.created_at,
    )


@router.get("/apps/{app_id}", response_model=AppResponse)
async def get_app(
    app_id: UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OAuth2App:
    """Get a specific OAuth2 app (must be owner)."""
    return await _get_app_or_404(session, app_id, user_id=current_user.id)


@router.put("/apps/{app_id}", response_model=AppResponse)
async def update_app(
    app_id: UUID,
    body: AppUpdate,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OAuth2App:
    """Update an OAuth2 app."""
    app = await _get_app_or_404(session, app_id, user_id=current_user.id)
    update_data = body.model_dump(exclude_unset=True)
    if "scopes" in update_data:
        update_data["scopes"] = _validate_owned_scopes(current_user, update_data["scopes"])
    for field, value in update_data.items():
        setattr(app, field, value)
    await session.commit()
    await session.refresh(app)
    return app


@router.delete("/apps/{app_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_app(
    app_id: UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Delete (soft-deactivate) an OAuth2 app. Revokes all issued tokens."""
    app = await _get_app_or_404(session, app_id, user_id=current_user.id)
    # Soft-delete by deactivating; cascade revoke tokens
    app.is_active = False
    result = await session.execute(
        select(OAuth2Token).where(OAuth2Token.app_id == app_id, OAuth2Token.revoked == False)  # noqa: E712
    )
    for token in result.scalars().all():
        token.revoked = True
    await session.commit()


@router.post("/apps/{app_id}/rotate-secret", response_model=AppCreated)
async def rotate_secret(
    app_id: UUID,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AppCreated:
    """
    Rotate the client secret for an app.

    **All existing tokens issued for this app remain valid until they expire.**
    The new client_secret is only shown once.
    """
    app = await _get_app_or_404(session, app_id, user_id=current_user.id)
    _, client_secret, secret_hash, secret_prefix = _generate_client_credentials()
    app.client_secret_hash = secret_hash
    app.client_secret_prefix = secret_prefix
    await session.commit()
    await session.refresh(app)

    return AppCreated(
        id=app.id,
        name=app.name,
        description=app.description,
        client_id=app.client_id,
        client_secret=client_secret,
        client_secret_prefix=app.client_secret_prefix,
        redirect_uris=app.redirect_uris,
        scopes=app.scopes,
        grant_types=app.grant_types,
        is_active=app.is_active,
        is_confidential=app.is_confidential,
        logo_url=app.logo_url,
        homepage_url=app.homepage_url,
        created_at=app.created_at,
    )


# =============================================================================
# Authorization Endpoint
# =============================================================================


class AuthorizeRequest(BaseModel):
    """Body for POST /oauth2/authorize (user approves consent)."""

    client_id: str
    redirect_uri: str
    scope: str = ""
    state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    approved: bool = True


@router.get("/authorize")
async def authorize_get(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    response_type: str = Query(...),
    scope: str = Query(""),
    state: str | None = Query(None),
    code_challenge: str | None = Query(None),
    code_challenge_method: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """
    Authorization endpoint — GET phase.

    Returns app metadata for the frontend consent page to display.
    The frontend renders the consent form and POSTs back to this endpoint.
    """
    if response_type != "code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only response_type=code is supported",
        )
    result = await session.execute(
        select(OAuth2App).where(OAuth2App.client_id == client_id, OAuth2App.is_active == True)  # noqa: E712
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown client_id",
        )
    if redirect_uri not in app.redirect_uris:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="redirect_uri not registered for this app",
        )
    # defense-in-depth. Even though the URI is registered, an
    # older row may pre-date the validator. Re-check scheme/format before
    # handing the browser a redirect.
    try:
        _validate_single_redirect_uri(redirect_uri)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"redirect_uri rejected: {e}",
        ) from None

    # Public clients (no client_secret) MUST use PKCE — RFC 7636.
    # Without PKCE, authorization code interception on a public client
    # lets an attacker redeem the code.
    if not app.is_confidential:
        if not code_challenge:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=("code_challenge required for public clients (PKCE, RFC 7636)"),
            )
        # reject 'plain' — in plain mode code_challenge == code_verifier
        # so an attacker who intercepts the auth code gets the verifier for free.
        # Only S256 (SHA-256) provides real protection against code interception.
        method = code_challenge_method or "S256"
        if method != "S256":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="code_challenge_method must be S256 (plain is insecure)",
            )

    requested_scopes = [s for s in scope.split() if s]
    return {
        "app": {
            "name": app.name,
            "description": app.description,
            "logo_url": app.logo_url,
            "homepage_url": app.homepage_url,
        },
        "requested_scopes": requested_scopes,
        "state": state,
    }


@router.post("/authorize")
async def authorize_post(
    body: AuthorizeRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """
    Authorization endpoint — POST phase (user grants or denies consent).

    Returns {code, state} on approval; raises 403 on denial.
    """
    result = await session.execute(
        select(OAuth2App).where(
            OAuth2App.client_id == body.client_id,
            OAuth2App.is_active == True,  # noqa: E712
        )
    )
    app = result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown client_id")

    if body.redirect_uri not in app.redirect_uris:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="redirect_uri not registered",
        )
    # defense-in-depth re-validation (see authorize_get above).
    try:
        _validate_single_redirect_uri(body.redirect_uri)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"redirect_uri rejected: {e}",
        ) from None

    # Public clients MUST use PKCE when issuing a code.
    if not app.is_confidential:
        if not body.code_challenge:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=("code_challenge required for public clients (PKCE, RFC 7636)"),
            )
        # reject 'plain' — only S256 offers real protection.
        method = body.code_challenge_method or "S256"
        if method != "S256":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="code_challenge_method must be S256 (plain is insecure)",
            )

    requested_scopes = _validate_requested_scopes(
        [s for s in body.scope.split() if s],
        list(app.scopes),
    )
    if requested_scopes and not current_user.has_permission("*"):
        unauthorized_scopes = [
            scope for scope in requested_scopes if not current_user.has_permission(scope)
        ]
        if unauthorized_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot authorize scopes beyond your own permissions",
            )

    if not body.approved:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User denied authorization",
        )

    code = secrets.token_urlsafe(48)
    auth_code = OAuth2AuthorizationCode(
        code=code,
        app_id=app.id,
        user_id=current_user.id,
        redirect_uri=body.redirect_uri,
        scopes=requested_scopes,
        code_challenge=body.code_challenge,
        code_challenge_method=body.code_challenge_method,
        expires_at=datetime.now(UTC) + AUTH_CODE_TTL,
    )
    session.add(auth_code)
    await session.commit()

    return {"code": code, "state": body.state}


# =============================================================================
# Token Endpoint
# =============================================================================


@router.post("/token", response_model=TokenResponse)
async def token(
    grant_type: str = Form(...),
    # authorization_code grant
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    code_verifier: str | None = Form(None),
    # client_credentials grant
    scope: str | None = Form(None),
    # refresh_token grant
    refresh_token: str | None = Form(None),
    # Client authentication (confidential apps)
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """
    Token endpoint.

    Supported grant_types:
    - `authorization_code` — Exchange auth code + PKCE verifier for tokens
    - `refresh_token`      — Exchange refresh token for new access token
    - `client_credentials` — Machine-to-machine (no user)
    """
    # DISABLED: this server mints opaque Bearer tokens that NO resource
    # server validates — get_current_user_optional / _get_authenticated_user accept
    # only signed JWTs (Bearer/cookie) and X-API-Key, never these opaque tokens. So
    # the full code-exchange dance previously handed integrators a token that
    # authorized nothing. Return 501 rather than silently issue useless tokens; the
    # implementation below is left intact so a future commit can wire up the
    # resource-server side (validate token_version/revocation/expiry/scope-ceiling
    # at read time) and re-enable. Until then, use the JWT login flow or API keys.
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "The OAuth2 token endpoint is not yet active — issued tokens are not "
            "accepted by any resource server. Use the JWT login flow or an API key."
        ),
    )

    # ── Authenticate client ──────────────────────────────────────────────────
    app: OAuth2App | None = None
    if client_id:
        result = await session.execute(
            select(OAuth2App).where(
                OAuth2App.client_id == client_id,
                OAuth2App.is_active == True,  # noqa: E712
            )
        )
        app = result.scalar_one_or_none()

    if grant_type not in ("authorization_code", "refresh_token", "client_credentials"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported grant_type: {grant_type}",
        )

    # ── authorization_code grant ─────────────────────────────────────────────
    if grant_type == "authorization_code":
        if not code:
            raise HTTPException(status_code=400, detail="code is required")

        # Lock the row to prevent concurrent code exchange (race condition)
        result = await session.execute(
            select(OAuth2AuthorizationCode)
            .where(
                OAuth2AuthorizationCode.code == code,
                OAuth2AuthorizationCode.used == False,  # noqa: E712
            )
            .with_for_update()
        )
        auth_code = result.scalar_one_or_none()
        if not auth_code:
            raise HTTPException(status_code=400, detail="Invalid or already-used code")
        if auth_code.expires_at < datetime.now(UTC):
            raise HTTPException(status_code=400, detail="Authorization code expired")
        if redirect_uri and auth_code.redirect_uri != redirect_uri:
            raise HTTPException(status_code=400, detail="redirect_uri mismatch")

        # Resolve the app that issued this code (authoritative)
        code_app_result = await session.execute(
            select(OAuth2App).where(
                OAuth2App.id == auth_code.app_id,
                OAuth2App.is_active == True,  # noqa: E712
            )
        )
        code_app = code_app_result.scalar_one_or_none()
        if code_app is None:
            raise HTTPException(status_code=400, detail="invalid_client")

        # enforce grant_types whitelist. Previously only the
        # client_credentials branch verified this, so an app registered with
        # e.g. ["refresh_token"] could still redeem auth codes.
        if "authorization_code" not in (code_app.grant_types or []):
            raise HTTPException(
                status_code=400,
                detail="grant_type 'authorization_code' not allowed for this app",
            )

        # Enforce client authentication for confidential apps.
        # NOTE: derive from the code's app, not the (optional) client_id form
        # field, so a confidential client can't skip auth by omitting client_id.
        if code_app.is_confidential:
            if not client_secret:
                raise HTTPException(status_code=401, detail="Client authentication required")
            secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
            if not secrets.compare_digest(secret_hash, code_app.client_secret_hash):
                raise HTTPException(status_code=401, detail="Invalid client credentials")
            if client_id and client_id != code_app.client_id:
                raise HTTPException(status_code=401, detail="Invalid client credentials")
        else:
            # Public client: client_id (if sent) must match the code's app,
            # and PKCE must be present (enforced below).
            if client_id and client_id != code_app.client_id:
                raise HTTPException(status_code=401, detail="invalid_client")
            if not auth_code.code_challenge:
                raise HTTPException(
                    status_code=400,
                    detail="PKCE required for public clients",
                )

        # PKCE verification
        if auth_code.code_challenge:
            if not code_verifier:
                raise HTTPException(status_code=400, detail="code_verifier required")
            if not _verify_pkce(
                auth_code.code_challenge, code_verifier, auth_code.code_challenge_method or "S256"
            ):
                raise HTTPException(status_code=400, detail="PKCE verification failed")

        # Mark code as used
        auth_code.used = True
        user_id = auth_code.user_id
        app_id = auth_code.app_id
        token_scopes = auth_code.scopes

    # ── refresh_token grant ──────────────────────────────────────────────────
    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status_code=400, detail="refresh_token is required")
        rt_hash = _hash_token(refresh_token)
        result = await session.execute(
            select(OAuth2Token).where(
                OAuth2Token.refresh_token_hash == rt_hash,
                OAuth2Token.revoked == False,  # noqa: E712
            )
        )
        old_token = result.scalar_one_or_none()
        if not old_token:
            raise HTTPException(status_code=400, detail="Invalid refresh token")

        # Authenticate the client for confidential apps on refresh
        # (RFC 6749 §6). Previously a stolen refresh token alone was enough
        # to mint new access tokens for a confidential app.
        refresh_app_result = await session.execute(
            select(OAuth2App).where(
                OAuth2App.id == old_token.app_id,
                OAuth2App.is_active == True,  # noqa: E712
            )
        )
        refresh_app = refresh_app_result.scalar_one_or_none()
        if refresh_app is None:
            raise HTTPException(status_code=400, detail="invalid_client")

        if refresh_app.is_confidential:
            if not client_secret:
                raise HTTPException(
                    status_code=401,
                    detail="client_authentication_required",
                )
            provided_hash = hashlib.sha256(client_secret.encode()).hexdigest()
            if not secrets.compare_digest(provided_hash, refresh_app.client_secret_hash):
                raise HTTPException(status_code=401, detail="invalid_client")
            # Also ensure client_id (if sent) matches the token's app
            if client_id and client_id != refresh_app.client_id:
                raise HTTPException(status_code=401, detail="invalid_client")

        # Check user.token_version hasn't been bumped
        # (logout-everywhere / password change / reset).
        user_result = await session.execute(select(User).where(User.id == old_token.user_id))
        refresh_user = user_result.scalar_one_or_none()
        if (
            refresh_user is None
            or not refresh_user.is_active
            or getattr(refresh_user, "deleted_at", None) is not None
        ):
            raise HTTPException(status_code=401, detail="user_invalid")

        token_ver_at_issue = getattr(old_token, "user_token_version_at_issue", 0) or 0
        current_user_tv = getattr(refresh_user, "token_version", 0) or 0
        if current_user_tv != token_ver_at_issue:
            # Credentials rotated since this refresh token was issued —
            # revoke it and deny.
            old_token.revoked = True
            await session.commit()
            raise HTTPException(status_code=401, detail="token_revoked")

        # Revoke old token (token rotation)
        old_token.revoked = True
        user_id = old_token.user_id
        app_id = old_token.app_id
        token_scopes = old_token.scopes

    # ── client_credentials grant ─────────────────────────────────────────────
    else:  # client_credentials
        if not app or not client_secret:
            raise HTTPException(status_code=401, detail="Client authentication required")
        secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
        if not secrets.compare_digest(secret_hash, app.client_secret_hash):
            raise HTTPException(status_code=401, detail="Invalid client credentials")
        if "client_credentials" not in app.grant_types:
            raise HTTPException(status_code=400, detail="grant_type not allowed for this app")
        # No user for client_credentials — issue token on behalf of the app owner
        user_id = app.user_id
        app_id = app.id
        requested_scopes = [s for s in (scope or "").split() if s]
        token_scopes = (
            _validate_requested_scopes(requested_scopes, list(app.scopes))
            if requested_scopes
            else list(app.scopes)
        )

    # ── Issue tokens ─────────────────────────────────────────────────────────
    now = datetime.now(UTC)
    at_raw = _generate_token()
    rt_raw = _generate_token() if grant_type != "client_credentials" else None

    # Snapshot the user's token_version at mint time so that a
    # subsequent "logout everywhere" / password change invalidates every
    # OAuth2 token we issued.
    minting_user_tv = 0
    if user_id is not None:
        mint_user_result = await session.execute(
            select(User.token_version).where(User.id == user_id)
        )
        minting_user_tv = mint_user_result.scalar_one_or_none() or 0

    token_record = OAuth2Token(
        app_id=app_id,
        user_id=user_id,
        access_token_hash=_hash_token(at_raw),
        refresh_token_hash=_hash_token(rt_raw) if rt_raw else None,
        scopes=token_scopes,
        expires_at=now + ACCESS_TOKEN_TTL,
        user_token_version_at_issue=minting_user_tv,
    )
    session.add(token_record)
    await session.commit()

    return TokenResponse(
        access_token=at_raw,
        token_type="Bearer",
        expires_in=int(ACCESS_TOKEN_TTL.total_seconds()),
        refresh_token=rt_raw,
        scope=" ".join(token_scopes),
    )


# =============================================================================
# Token Revocation (RFC 7009)
# =============================================================================


@router.post("/revoke", status_code=status.HTTP_200_OK)
async def revoke(
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """
    Revoke an access or refresh token (RFC 7009).

    Always returns 200 regardless of whether the token existed.
    """
    token_hash = _hash_token(token)

    # Try access token first
    result = await session.execute(
        select(OAuth2Token).where(OAuth2Token.access_token_hash == token_hash)
    )
    record = result.scalar_one_or_none()

    if not record:
        # Try as refresh token
        result = await session.execute(
            select(OAuth2Token).where(OAuth2Token.refresh_token_hash == token_hash)
        )
        record = result.scalar_one_or_none()

    if record and not record.revoked:
        record.revoked = True
        await session.commit()

    return {"revoked": True}

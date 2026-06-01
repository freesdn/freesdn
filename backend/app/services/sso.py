# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SSO Service
============================

Handles OIDC, SAML 2.0, and LDAP authentication flows, including
Just-In-Time (JIT) user provisioning and attribute/role mapping.
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, create_refresh_token
from app.core.security_utils import (
    decrypt_field,
    encrypt_field,
    safe_http_request,
    validate_target_host,
)
from app.models.core import User, UserRole
from app.models.sso import SSOProtocol, SSOProvider, SSOProviderStatus, SSOSession
from app.schemas.sso import (
    SSOAuthorizeResponse,
    SSOCallbackResponse,
    SSOProviderCreate,
    SSOProviderUpdate,
    SSOTestConnectionResponse,
    SSOUserInfo,
)

logger = logging.getLogger(__name__)

# How long SSO sessions (state) live before expiry
SSO_SESSION_TTL = timedelta(minutes=10)

# Default access token expiry (seconds)
ACCESS_TOKEN_TTL_SECONDS = 1800


# ---------------------------------------------------------------------------
# Timing-safe dummy hash
# ---------------------------------------------------------------------------
# LDAP SSO previously failed fast when the user was not found, leaking a
# username-enumeration side channel via response timing.  Mirror the pattern
# used in ``app.api.v1.endpoints.auth``: on the "user not found"
# branch we run a verify() against a pre-computed Argon2id hash so the
# response time matches the "user exists, wrong password" branch.
#
# Computed lazily on first use (not at import time) so we don't incur a
# ~300 ms startup tax and to avoid circular-import hazards with
# ``app.core.security``.
_DUMMY_PASSWORD_HASH: str | None = None


def _get_dummy_hash() -> str:
    """Return a cached Argon2id hash for timing-safe SSO failure branches."""
    global _DUMMY_PASSWORD_HASH
    if _DUMMY_PASSWORD_HASH is None:
        # Use the public helper (the pwd_context global was removed in
        # the passlib → argon2-cffi migration).
        from app.core.security import get_password_hash

        _DUMMY_PASSWORD_HASH = get_password_hash("this-is-a-dummy-password-not-a-real-credential")
    return _DUMMY_PASSWORD_HASH


def _dummy_verify(plain_password: str) -> None:
    """Waste CPU verifying against the dummy hash.

    Keeps the "user not found" timing indistinguishable from a real LDAP
    bind + Argon2id verify.  Result is intentionally discarded.
    """
    from app.core.security import verify_password

    # verify_password swallows exceptions and returns bool; discard.
    verify_password(plain_password, _get_dummy_hash())


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SSOError(Exception):
    """Base SSO error."""


class SSOProviderNotFoundError(SSOError):
    """Requested SSO provider does not exist or is inactive."""


class SSOConfigError(SSOError):
    """SSO provider is misconfigured."""


class SSOCallbackError(SSOError):
    """Callback validation failure (e.g. bad state, expired session)."""


class SSOAuthError(SSOError):
    """Remote IdP denied authentication."""


class SSONotSupportedError(SSOError):
    """A flow is intentionally disabled because its verifier is not safe to use yet."""


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class SSOService:
    """Manages SSO provider lifecycle and authentication flows."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # =====================================================================
    # Provider CRUD
    # =====================================================================

    async def list_providers(
        self,
        organization_id: UUID | None = None,
        protocol: SSOProtocol | None = None,
        active_only: bool = False,
    ) -> list[SSOProvider]:
        """List SSO providers with optional filters."""
        stmt = select(SSOProvider).where(SSOProvider.deleted_at.is_(None))
        if organization_id:
            stmt = stmt.where(SSOProvider.organization_id == organization_id)
        if protocol:
            stmt = stmt.where(SSOProvider.protocol == protocol)
        if active_only:
            stmt = stmt.where(SSOProvider.status == SSOProviderStatus.ACTIVE)
        stmt = stmt.order_by(SSOProvider.display_order)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_provider(self, provider_id: UUID) -> SSOProvider | None:
        """Get a single SSO provider by ID."""
        stmt = select(SSOProvider).where(
            SSOProvider.id == provider_id, SSOProvider.deleted_at.is_(None)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_provider_by_slug(self, slug: str) -> SSOProvider | None:
        """Get a single SSO provider by slug."""
        stmt = select(SSOProvider).where(SSOProvider.slug == slug, SSOProvider.deleted_at.is_(None))
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def create_provider(
        self, data: SSOProviderCreate, created_by: UUID | None = None
    ) -> SSOProvider:
        """Create a new SSO provider."""
        provider = SSOProvider(
            id=uuid4(),
            organization_id=data.organization_id,
            name=data.name,
            slug=data.slug,
            description=data.description,
            protocol=SSOProtocol(data.protocol),
            status=SSOProviderStatus(data.status),
            icon_url=data.icon_url,
            display_order=data.display_order,
            # OIDC
            oidc_issuer=data.oidc_issuer,
            oidc_client_id=data.oidc_client_id,
            oidc_client_secret=encrypt_field(data.oidc_client_secret)
            if data.oidc_client_secret
            else data.oidc_client_secret,
            oidc_scopes=data.oidc_scopes,
            oidc_discovery_url=data.oidc_discovery_url,
            # SAML
            saml_entity_id=data.saml_entity_id,
            saml_sso_url=data.saml_sso_url,
            saml_slo_url=data.saml_slo_url,
            saml_certificate=data.saml_certificate,
            saml_signing_key=encrypt_field(data.saml_signing_key)
            if data.saml_signing_key
            else data.saml_signing_key,
            saml_name_id_format=data.saml_name_id_format,
            # LDAP
            ldap_url=data.ldap_url,
            ldap_bind_dn=data.ldap_bind_dn,
            ldap_bind_password=encrypt_field(data.ldap_bind_password)
            if data.ldap_bind_password
            else data.ldap_bind_password,
            ldap_base_dn=data.ldap_base_dn,
            ldap_user_search_filter=data.ldap_user_search_filter,
            ldap_group_search_filter=data.ldap_group_search_filter,
            ldap_use_tls=data.ldap_use_tls,
            ldap_tls_ca_cert=data.ldap_tls_ca_cert,
            # Mappings
            attribute_mapping=data.attribute_mapping,
            role_mapping=data.role_mapping,
            jit_provisioning=data.jit_provisioning,
            default_role=data.default_role,
            extra_settings=data.extra_settings,
            created_by=created_by,
            updated_by=created_by,
        )
        self.db.add(provider)
        await self.db.flush()
        return provider

    async def update_provider(
        self,
        provider_id: UUID,
        data: SSOProviderUpdate,
        updated_by: UUID | None = None,
    ) -> SSOProvider | None:
        """Update an existing SSO provider."""
        provider = await self.get_provider(provider_id)
        if not provider:
            return None

        _ENCRYPTED_FIELDS = {"oidc_client_secret", "saml_signing_key", "ldap_bind_password"}
        update_data = data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            if key in _ENCRYPTED_FIELDS and value:
                value = encrypt_field(value)
            setattr(provider, key, value)
        provider.updated_by = updated_by
        await self.db.flush()
        return provider

    async def delete_provider(self, provider_id: UUID) -> bool:
        """Soft-delete an SSO provider."""
        provider = await self.get_provider(provider_id)
        if not provider:
            return False
        provider.deleted_at = datetime.now(UTC)
        await self.db.flush()
        return True

    # =====================================================================
    # OIDC Flow
    # =====================================================================

    async def oidc_authorize(
        self, provider: SSOProvider, redirect_uri: str | None = None
    ) -> SSOAuthorizeResponse:
        """Build the OIDC authorization URL and persist a state token."""
        if provider.protocol != SSOProtocol.OIDC:
            raise SSOConfigError("Provider is not an OIDC provider")
        if not provider.oidc_client_id:
            raise SSOConfigError("OIDC client_id is not configured")

        # Resolve endpoints via OIDC discovery. Standard providers publish a
        # discovery doc at {issuer}/.well-known/openid-configuration, so derive
        # it from the issuer when not set explicitly — this makes a provider
        # configured with just issuer + client_id + secret work out of the box
        # (Keycloak/Okta/Azure/Google/Authentik) instead of failing against the
        # non-standard {issuer}/authorize guess below.
        authorization_endpoint = None
        discovery_url = self._effective_discovery_url(provider)
        if discovery_url:
            endpoints = await self._oidc_discover(
                discovery_url, allow_hosts=self._trusted_idp_hosts(provider)
            )
            authorization_endpoint = endpoints.get("authorization_endpoint")
        if not authorization_endpoint and provider.oidc_issuer:
            authorization_endpoint = f"{provider.oidc_issuer.rstrip('/')}/authorize"

        if not authorization_endpoint:
            raise SSOConfigError("Cannot determine OIDC authorization endpoint")

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        # Persist SSO session
        sso_session = SSOSession(
            id=uuid4(),
            provider_id=provider.id,
            state=state,
            nonce=nonce,
            redirect_uri=redirect_uri,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + SSO_SESSION_TTL,
        )
        self.db.add(sso_session)
        await self.db.flush()

        # Build authorize URL with proper URL encoding
        from urllib.parse import urlencode

        params = {
            "client_id": provider.oidc_client_id,
            "response_type": "code",
            "scope": provider.oidc_scopes or "openid profile email",
            "state": state,
            "nonce": nonce,
        }
        if redirect_uri:
            # default-deny validation of redirect_uri.
            # An empty/missing allowlist must NOT accept any URI —
            # otherwise an attacker-supplied redirect_uri can intercept
            # the authorization code and take over the account.
            self._validate_redirect_uri(provider, redirect_uri)
            params["redirect_uri"] = redirect_uri

        authorize_url = f"{authorization_endpoint}?{urlencode(params)}"

        return SSOAuthorizeResponse(authorize_url=authorize_url, state=state)

    async def oidc_callback(self, state: str, code: str) -> SSOCallbackResponse:
        """Exchange OIDC authorization code for tokens, create/update user."""
        session = await self._validate_sso_session(state)
        provider = await self.get_provider(session.provider_id)
        if not provider:
            raise SSOProviderNotFoundError("SSO provider not found")

        # Discover token endpoint (derive discovery from issuer when not set)
        token_endpoint = None
        userinfo_endpoint = None
        discovery_url = self._effective_discovery_url(provider)
        if discovery_url:
            endpoints = await self._oidc_discover(
                discovery_url, allow_hosts=self._trusted_idp_hosts(provider)
            )
            token_endpoint = endpoints.get("token_endpoint")
            userinfo_endpoint = endpoints.get("userinfo_endpoint")
        if not token_endpoint and provider.oidc_issuer:
            token_endpoint = f"{provider.oidc_issuer.rstrip('/')}/oauth/token"
            userinfo_endpoint = f"{provider.oidc_issuer.rstrip('/')}/userinfo"

        if not token_endpoint:
            raise SSOConfigError("Cannot determine OIDC token endpoint")

        # DNS-rebinding-safe token exchange
        try:
            token_resp = await safe_http_request(
                "POST",
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": provider.oidc_client_id,
                    "client_secret": decrypt_field(provider.oidc_client_secret)
                    if provider.oidc_client_secret
                    else "",
                    "redirect_uri": session.redirect_uri or "",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15.0,
                allow_hosts=self._trusted_idp_hosts(provider),
            )
        except ValueError as e:
            raise SSOConfigError(f"Token endpoint blocked (SSRF): {e}")
        if token_resp.status_code != 200:
            raise SSOAuthError(f"Token exchange failed: {token_resp.status_code} {token_resp.text}")

        token_data = token_resp.json()
        id_token = token_data.get("id_token")
        access_token_ext = token_data.get("access_token")

        claims: dict[str, Any] = {}

        # ------------------------------------------------------------------
        # ALWAYS verify the id_token when present, regardless of
        # whether we also hit the userinfo endpoint.  The id_token is the
        # only place that carries the nonce we minted at authorize time,
        # so skipping verification here re-opens the replay window.
        # ------------------------------------------------------------------
        id_token_claims: dict[str, Any] = {}
        if id_token:
            try:
                import jwt as pyjwt
                from jwt.api_jwk import PyJWKSet

                # Try to get JWKS from discovery for signature verification
                jwks_uri = None
                discovery_url = self._effective_discovery_url(provider)
                if discovery_url:
                    endpoints = await self._oidc_discover(
                        discovery_url, allow_hosts=self._trusted_idp_hosts(provider)
                    )
                    jwks_uri = endpoints.get("jwks_uri")

                if not jwks_uri:
                    raise ValueError(
                        "JWKS URI unavailable — refusing to accept unverified id_token"
                    )

                # DNS-rebinding-safe JWKS fetch.  We avoid
                # PyJWKClient because it performs its own unconstrained HTTP
                # request and would re-introduce the DNS-rebinding hole.
                jwks_response = await safe_http_request(
                    "GET", jwks_uri, timeout=10.0, allow_hosts=self._trusted_idp_hosts(provider)
                )
                if jwks_response.status_code != 200:
                    raise ValueError(f"JWKS endpoint returned HTTP {jwks_response.status_code}")
                jwk_set = PyJWKSet.from_dict(jwks_response.json())

                token_header = pyjwt.get_unverified_header(id_token)
                signing_key_obj = None
                for candidate in jwk_set.keys:
                    if candidate.key_id == token_header.get("kid"):
                        signing_key_obj = candidate
                        break
                if signing_key_obj is None:
                    raise SSOCallbackError("No matching JWKS key for id_token kid")

                # Build the required-claims set.  We always enforce the
                # standard OIDC core claims; issuer and nonce are added
                # when the provider/session configured them.
                required_claims: list[str] = ["exp", "iat", "aud"]
                if provider.oidc_issuer:
                    required_claims.append("iss")
                if session.nonce:
                    required_claims.append("nonce")

                decode_kwargs: dict[str, Any] = {
                    "algorithms": [
                        "RS256",
                        "RS384",
                        "RS512",
                        "ES256",
                        "ES384",
                        "ES512",
                    ],
                    "audience": provider.oidc_client_id,
                    "options": {"require": required_claims},
                }
                if provider.oidc_issuer:
                    decode_kwargs["issuer"] = provider.oidc_issuer

                id_token_claims = pyjwt.decode(
                    id_token,
                    signing_key_obj.key,
                    **decode_kwargs,
                )
            except Exception as e:
                logger.error("OIDC id_token signature verification failed: %s", e)
                raise SSOAuthError(
                    "Failed to verify OIDC id_token signature. "
                    "Ensure the IdP's JWKS endpoint is reachable and the token is valid."
                )

            # nonce replay defense — bind the id_token's nonce
            # to the nonce we generated at authorize time and stored in
            # the SSO session.  The jwt.decode require-list above already
            # enforces presence; this check binds the *value* to this flow.
            if session.nonce:
                token_nonce = id_token_claims.get("nonce")
                if not token_nonce or token_nonce != session.nonce:
                    raise SSOAuthError(
                        "Invalid or missing nonce in id_token — possible replay attack"
                    )

            claims = dict(id_token_claims)

        # Userinfo endpoint enrichment (does NOT carry nonce).  We merge
        # userinfo into the id_token claims so attribute mapping has the
        # full picture, but we do not trust userinfo as the sole source of
        # identity when an id_token was also supplied.
        if userinfo_endpoint and access_token_ext:
            # DNS-rebinding-safe userinfo fetch
            try:
                ui_resp = await safe_http_request(
                    "GET",
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token_ext}"},
                    timeout=10.0,
                    allow_hosts=self._trusted_idp_hosts(provider),
                )
                if ui_resp.status_code == 200:
                    ui_claims = ui_resp.json()
                    if isinstance(ui_claims, dict):
                        # id_token claims win over userinfo for any overlap:
                        # the signed token is the authoritative source.
                        merged = dict(ui_claims)
                        merged.update(claims)
                        claims = merged
            except ValueError as e:
                logger.warning("Userinfo endpoint blocked (SSRF): %s", e)

        if not claims:
            raise SSOAuthError("Failed to obtain user claims from IdP")

        # Map claims → user attributes
        user_attrs = self._map_attributes(provider, claims)
        user = await self._provision_or_update_user(provider, user_attrs, claims)

        # Complete SSO session
        session.user_id = user.id
        session.external_id = claims.get("sub") or claims.get("email")
        session.completed_at = datetime.now(UTC)
        session.idp_response = claims

        # Issue FreeSDN tokens
        return await self._issue_tokens(user, provider)

    def _effective_discovery_url(self, provider: SSOProvider) -> str | None:
        """The OIDC discovery URL to use: the explicit one, else the standard
        ``{issuer}/.well-known/openid-configuration`` derived from the issuer.

        Standard OIDC providers (Keycloak, Okta, Azure AD, Google, Authentik,
        Auth0, …) all publish discovery at that well-known path, so deriving it
        from the issuer lets a provider configured with just issuer + client_id
        + secret work out of the box — instead of failing against the
        non-standard ``{issuer}/authorize`` / ``{issuer}/oauth/token`` guesses.
        Mirrors the resolution the ``test`` endpoint already uses.
        """
        if provider.oidc_discovery_url:
            return provider.oidc_discovery_url
        if provider.oidc_issuer:
            return f"{provider.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"
        return None

    def _trusted_idp_hosts(self, provider: SSOProvider) -> frozenset[str]:
        """Admin-configured IdP hostnames allowed to bypass the private-IP SSRF
        block, so SSO works against an on-prem / internal IdP (Keycloak, ADFS) on
        a private address — a common enterprise topology. Only the OIDC issuer /
        discovery and SAML endpoint hosts the admin explicitly configured are
        trusted; the cloud-metadata block is NEVER bypassed, and DNS pinning + TLS
        verification still apply to every request.
        """
        from urllib.parse import urlparse

        hosts: set[str] = set()
        for raw in (
            provider.oidc_issuer,
            provider.oidc_discovery_url,
            provider.saml_sso_url,
            provider.saml_slo_url,
        ):
            if raw:
                host = urlparse(raw).hostname
                if host:
                    hosts.add(host)
        return frozenset(hosts)

    async def _oidc_discover(
        self, discovery_url: str, *, allow_hosts: frozenset[str] = frozenset()
    ) -> dict[str, Any]:
        """Fetch OIDC discovery document."""
        try:
            # DNS-rebinding-safe discovery fetch
            resp = await safe_http_request(
                "GET", discovery_url, timeout=10.0, allow_hosts=allow_hosts
            )
            if resp.status_code == 200:
                return dict(resp.json())
        except ValueError as e:
            logger.warning("OIDC discovery URL blocked (SSRF): %s", e)
        except Exception as e:
            logger.warning("OIDC discovery failed for %s: %s", discovery_url, e)
        return {}

    # =====================================================================
    # SAML Flow
    # =====================================================================

    async def saml_login(
        self, provider: SSOProvider, redirect_uri: str | None = None
    ) -> SSOAuthorizeResponse:
        """Generate SAML AuthnRequest redirect."""
        if provider.protocol != SSOProtocol.SAML:
            raise SSOConfigError("Provider is not a SAML provider")
        if not provider.saml_sso_url:
            raise SSOConfigError("SAML SSO URL is not configured")

        # default-deny validation of redirect_uri before
        # persisting it in the SSOSession (RelayState would otherwise
        # carry an attacker-controlled URL all the way to the callback).
        if redirect_uri:
            self._validate_redirect_uri(provider, redirect_uri)

        state = secrets.token_urlsafe(32)

        sso_session = SSOSession(
            id=uuid4(),
            provider_id=provider.id,
            state=state,
            redirect_uri=redirect_uri,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + SSO_SESSION_TTL,
        )
        self.db.add(sso_session)
        await self.db.flush()

        # Build minimal SAML AuthnRequest URL with RelayState
        # Full XML generation requires python3-saml / pysaml2 — here we provide
        # the redirect skeleton that integrators can extend.
        authorize_url = f"{provider.saml_sso_url}?RelayState={state}"

        return SSOAuthorizeResponse(authorize_url=authorize_url, state=state)

    async def saml_callback(self, state: str, saml_response_b64: str) -> SSOCallbackResponse:
        """Process SAML Response, extract assertions, provision user."""
        # SECURITY: the SAML acceptance path below verifies the
        # signature with the python3-saml LOW-LEVEL primitive
        # OneLogin_Saml2_Utils.validate_sign(raw_xml, cert) and then consumes
        # identity by INDEPENDENTLY re-parsing the same raw XML with ElementTree
        # (_parse_saml_attributes: .//NameID / .//Attribute, first match
        # anywhere). validate_sign() does not bind the signed element to the
        # consumed element, enforce a single-assertion constraint, or check
        # Conditions/Audience/Recipient/InResponseTo — the textbook XML
        # Signature Wrapping (XSW) setup: a holder of ANY one validly-signed
        # IdP assertion can wrap a forged unsigned one that ElementTree picks
        # up first while validate_sign() still returns True, escalating to
        # org_admin via SSO role mapping. Until a reference-validating verifier
        # (OneLogin_Saml2_Response.is_valid() driven from persisted SP settings
        # + a stored AuthnRequest ID) is wired in, REFUSE to issue tokens
        # through this path — mirrors the OAuth2 /token 501 posture. SAML is
        # non-functional by default (python3-saml is not a declared dependency)
        # so no working deployment regresses.
        raise SSONotSupportedError(
            "SAML SSO is temporarily disabled: the assertion verifier does not "
            "yet validate the signed-element binding (XML Signature Wrapping), "
            "assertion Conditions, AudienceRestriction, or InResponseTo. "
            "Re-enable once a reference-validating verifier is wired in."
        )
        session = await self._validate_sso_session(state)
        provider = await self.get_provider(session.provider_id)
        if not provider:
            raise SSOProviderNotFoundError("SSO provider not found")

        # Decode SAML response
        import base64

        try:
            raw_xml = base64.b64decode(saml_response_b64).decode("utf-8")
        except Exception as e:
            raise SSOCallbackError(f"Invalid SAML response: {e}")

        # MANDATORY signing-certificate check. If the provider was
        # created without a certificate, REFUSE to proceed. Previously a
        # missing cert silently skipped signature verification, allowing
        # forged assertions (NameID=super_admin@target.com).
        if not provider.saml_certificate or not provider.saml_certificate.strip():
            raise SSOConfigError(
                "SAML provider is misconfigured: signing certificate is required. "
                "Refusing to accept unsigned SAML assertions."
            )

        # Signature verification is now mandatory and always runs.
        try:
            from onelogin.saml2.utils import OneLogin_Saml2_Utils
        except ImportError:
            raise SSOCallbackError(
                "SAML signature verification requires python3-saml. "
                "Install it to enable SAML authentication."
            ) from None

        if not OneLogin_Saml2_Utils.validate_sign(raw_xml, provider.saml_certificate):
            raise SSOCallbackError("SAML response signature verification failed")
        logger.info("SAML response signature verified successfully")

        # Parse minimal attributes from assertion
        claims = self._parse_saml_attributes(raw_xml)

        user_attrs = self._map_attributes(provider, claims)
        user = await self._provision_or_update_user(provider, user_attrs, claims)

        session.user_id = user.id
        session.external_id = claims.get("NameID") or claims.get("email")
        session.completed_at = datetime.now(UTC)
        session.idp_response = {"saml_attributes": claims}

        return await self._issue_tokens(user, provider)

    @staticmethod
    def _parse_saml_attributes(xml_str: str) -> dict[str, Any]:
        """Best-effort extraction of SAML assertion attributes."""
        import xml.etree.ElementTree as ET

        ns = {
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        }
        attrs: dict[str, Any] = {}
        try:
            # CPython's xml.etree.ElementTree does not resolve external entities
            # by default, but we use defusedxml where available for defense-in-depth
            try:
                import defusedxml.ElementTree as SafeET

                root = SafeET.fromstring(xml_str)
            except ImportError:
                root = ET.fromstring(xml_str)
            # NameID
            name_id = root.find(".//saml:NameID", ns)
            if name_id is not None and name_id.text:
                attrs["NameID"] = name_id.text

            # Attributes
            for attr in root.findall(".//saml:Attribute", ns):
                name = attr.get("Name", "")
                values = [v.text for v in attr.findall("saml:AttributeValue", ns) if v.text]
                if values:
                    attrs[name] = values[0] if len(values) == 1 else values
        except ET.ParseError as e:
            logger.warning("SAML XML parse error: %s", e)

        return attrs

    # =====================================================================
    # LDAP Flow
    # =====================================================================

    async def ldap_authenticate(
        self, provider: SSOProvider, username: str, password: str
    ) -> SSOCallbackResponse:
        """Authenticate via LDAP bind."""
        if provider.protocol != SSOProtocol.LDAP:
            raise SSOConfigError("Provider is not an LDAP provider")
        if not provider.ldap_url or not provider.ldap_base_dn:
            raise SSOConfigError("LDAP URL or base DN not configured")

        # SSRF validation for LDAP host
        from urllib.parse import urlparse as _urlparse

        _ldap_host = _urlparse(provider.ldap_url).hostname
        if _ldap_host:
            try:
                validate_target_host(_ldap_host)
            except ValueError as e:
                raise SSOConfigError(f"LDAP host blocked (SSRF): {e}")

        try:
            import ssl

            import ldap3
            from ldap3 import (
                ALL,
                AUTO_BIND_NO_TLS,
                AUTO_BIND_TLS_BEFORE_BIND,
                Connection,
                Server,
                Tls,
            )
        except ImportError:
            raise SSOConfigError("ldap3 package is not installed. Run: pip install ldap3")

        # Connect to LDAP
        tls_config = None
        if provider.ldap_use_tls:
            tls_config = Tls(validate=ssl.CERT_REQUIRED)
            if provider.ldap_tls_ca_cert:
                # Pass the CA PEM directly via ca_certs_data. The old path wrote it
                # to a NamedTemporaryFile(delete=False) that ldap3 read by path but
                # nothing ever unlinked — leaking one .pem per LDAP auth/test.
                tls_config = Tls(
                    validate=ssl.CERT_REQUIRED,
                    ca_certs_data=provider.ldap_tls_ca_cert,
                )

        server = Server(
            provider.ldap_url,
            use_ssl=provider.ldap_url.startswith("ldaps://"),
            tls=tls_config,
            get_info=ALL,
        )
        # when TLS is requested over a plaintext ldap:// URL, do
        # StartTLS BEFORE sending any credential (fail closed if it can't
        # negotiate). ldaps:// is already TLS via use_ssl above; plain ldap://
        # with TLS not requested stays as-is.
        _auto_bind = (
            AUTO_BIND_TLS_BEFORE_BIND
            if (provider.ldap_use_tls and not provider.ldap_url.startswith("ldaps://"))
            else AUTO_BIND_NO_TLS
        )

        # Build search filter from template (with LDAP injection prevention)
        from app.core.security_utils import escape_ldap_filter

        safe_username = escape_ldap_filter(username)
        search_filter = (
            provider.ldap_user_search_filter or "(&(objectClass=user)(sAMAccountName={username}))"
        ).replace("{username}", safe_username)

        # First bind with service account to search
        bind_dn = provider.ldap_bind_dn
        bind_pw = (
            decrypt_field(provider.ldap_bind_password)
            if provider.ldap_bind_password
            else provider.ldap_bind_password
        )

        try:
            conn = Connection(
                server,
                user=bind_dn,
                password=bind_pw,
                auto_bind=_auto_bind,
                read_only=True,
            )
        except Exception as e:
            raise SSOAuthError(f"LDAP service bind failed: {e}")

        # Search for user
        conn.search(
            provider.ldap_base_dn,
            search_filter,
            attributes=ldap3.ALL_ATTRIBUTES,
        )

        if not conn.entries:
            conn.unbind()
            # normalize timing with the "user exists, wrong
            # password" branch so attackers cannot enumerate valid
            # usernames by measuring response latency.  The dummy verify
            # burns ~300 ms of Argon2id work, matching the cost of a
            # real LDAP bind + downstream processing.
            _dummy_verify(password)
            raise SSOAuthError("Invalid LDAP credentials")

        user_entry = conn.entries[0]
        user_dn = user_entry.entry_dn
        conn.unbind()

        # Bind as the user to verify password.  On failure we use the
        # same generic error message as the user-not-found path above so
        # the response is indistinguishable to the caller.
        try:
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=_auto_bind)
            user_conn.unbind()
        except Exception:
            raise SSOAuthError("Invalid LDAP credentials")

        # Build claims from LDAP attributes
        claims: dict[str, Any] = {"dn": user_dn}
        for attr_name in user_entry.entry_attributes:
            val = user_entry[attr_name].value
            if isinstance(val, list) and len(val) == 1:
                val = val[0]
            claims[attr_name] = str(val) if val else None

        user_attrs = self._map_attributes(provider, claims)
        user = await self._provision_or_update_user(provider, user_attrs, claims)

        return await self._issue_tokens(user, provider)

    # =====================================================================
    # Attribute & Role Mapping
    # =====================================================================

    def _map_attributes(self, provider: SSOProvider, claims: dict[str, Any]) -> dict[str, Any]:
        """Map IdP claims to FreeSDN user fields using the provider's attribute_mapping."""
        mapping = provider.attribute_mapping or {}
        attrs: dict[str, Any] = {}

        for freesdn_field, idp_claim in mapping.items():
            value = claims.get(idp_claim)
            if value is not None:
                attrs[freesdn_field] = str(value)

        # Ensure email is always present
        if "email" not in attrs:
            # Try common claim names
            for key in ("email", "mail", "Email", "emailAddress", "NameID"):
                if key in claims:
                    attrs["email"] = str(claims[key])
                    break

        return attrs

    def _map_role(self, provider: SSOProvider, claims: dict[str, Any]) -> str:
        """Determine FreeSDN role from IdP groups/roles via role_mapping."""
        role_mapping = provider.role_mapping or {}
        if not role_mapping:
            return provider.default_role or "viewer"

        # Check claims for group membership
        groups: list[str] = []
        for key in ("groups", "roles", "memberOf", "group"):
            val = claims.get(key)
            if isinstance(val, list):
                groups.extend(str(g) for g in val)
            elif val:
                groups.append(str(val))

        # First match wins (ordered by role hierarchy)
        # Never auto-grant super_admin via SSO — must be assigned manually
        role_priority = ["org_admin", "site_admin", "operator", "viewer"]
        for role in role_priority:
            mapped_groups = role_mapping.get(role, [])
            if isinstance(mapped_groups, str):
                mapped_groups = [mapped_groups]
            for group in mapped_groups:
                if group in groups:
                    return role

        return provider.default_role or "viewer"

    # =====================================================================
    # JIT User Provisioning
    # =====================================================================

    async def _provision_or_update_user(
        self,
        provider: SSOProvider,
        user_attrs: dict[str, Any],
        raw_claims: dict[str, Any],
    ) -> User:
        """Find existing user by email/external_id or create via JIT provisioning."""
        email = user_attrs.get("email")
        if not email:
            raise SSOAuthError("No email claim in IdP response")

        # Try to find existing user — SCOPED to the provider's own organization.
        # SECURITY (cross-tenant account takeover): an SSO provider is org-scoped
        # and its IdP config (issuer/JWKS/cert/LDAP) is fully controlled by the
        # org_admin who created it. The signature checks only prove the assertion
        # was signed by THAT org's configured key — they do NOT bind the asserted
        # email to the org. Without the organization_id filter, a malicious
        # org_admin could sign an assertion for victim@other-org.com and this
        # lookup would return the foreign-org user, then _issue_tokens() would
        # mint a real FreeSDN JWT carrying the victim's org + role (up to
        # super_admin). User.email is globally unique, so the match is
        # deterministic. Pin the lookup to provider.organization_id (NOT NULL).
        stmt = select(User).where(
            User.email == email,
            User.organization_id == provider.organization_id,
            User.deleted_at.is_(None),
        )
        result = await self.db.execute(stmt)
        user = result.scalar_one_or_none()

        # Defense in depth: if the email matches a user in a DIFFERENT org (the
        # org-scoped query above already excludes them, but a future refactor
        # could widen it), refuse rather than fall through to JIT-create a
        # duplicate-email row.
        if user is None:
            foreign = await self.db.execute(
                select(User.id).where(
                    User.email == email,
                    User.organization_id != provider.organization_id,
                    User.deleted_at.is_(None),
                )
            )
            if foreign.scalar_one_or_none() is not None:
                logger.warning(
                    "SSO login blocked: email belongs to a different organization",
                    extra={
                        "sso_provider": provider.protocol.value,
                        "provider_id": str(provider.id),
                    },
                )
                raise SSOAuthError("User does not belong to this SSO provider's organization")

        if user:
            # Update SSO-related fields
            user.auth_provider = provider.protocol.value
            user.external_id = (
                raw_claims.get("sub") or raw_claims.get("NameID") or raw_claims.get("dn")
            )
            user.sso_provider_id = provider.id
            user.last_login = datetime.now(UTC)
            if user_attrs.get("full_name"):
                user.full_name = user_attrs["full_name"]
            await self.db.flush()
            return user

        # JIT provisioning
        if not provider.jit_provisioning:
            raise SSOAuthError("User does not exist and JIT provisioning is disabled")

        role_str = self._map_role(provider, raw_claims)
        # Validate against UserRole enum
        try:
            role = UserRole(role_str)
        except ValueError:
            role = UserRole.VIEWER

        user = User(
            id=uuid4(),
            email=email,
            username=user_attrs.get("username") or email.split("@")[0],
            full_name=user_attrs.get("full_name"),
            hashed_password="!SSO_MANAGED",  # SSO users don't have local passwords
            role=role,
            organization_id=provider.organization_id,
            auth_provider=provider.protocol.value,
            external_id=(raw_claims.get("sub") or raw_claims.get("NameID") or raw_claims.get("dn")),
            sso_provider_id=provider.id,
            is_active=True,
            is_verified=True,  # IdP-authenticated users are pre-verified
            last_login=datetime.now(UTC),
            language="en",
            preferences={},
        )
        self.db.add(user)
        await self.db.flush()
        # log user_id + provider, not email.
        logger.info(
            "JIT provisioned user",
            extra={
                "user_id": str(user.id),
                "sso_provider": provider.protocol.value,
            },
        )
        return user

    # =====================================================================
    # Token Issuance
    # =====================================================================

    async def _issue_tokens(
        self, user: User, provider: SSOProvider | None = None
    ) -> SSOCallbackResponse:
        """Issue FreeSDN JWT tokens for an authenticated SSO user.

        SECURITY: If the user has local MFA (TOTP) enabled we
        do NOT mint a full access+refresh token pair just because the
        user made it through the IdP flow. Instead we return a short
        lived ``mfa_pending`` token that the caller must exchange via
        ``POST /auth/login/mfa``. Otherwise an attacker who compromises
        an IdP password (or an LDAP password, which is the LDAP path's
        only factor) bypasses the user's second factor.

        Opt-out: an SSO provider may set ``extra_settings.trust_idp_mfa``
        to ``true`` to declare that the upstream IdP is already
        enforcing MFA, in which case we skip the local TOTP gate.
        """
        token_version = getattr(user, "token_version", 0) or 0

        # ------------------------------------------------------------------
        # local MFA gate
        # ------------------------------------------------------------------
        if getattr(user, "mfa_enabled", False) and getattr(user, "mfa_secret", None):
            trust_idp_mfa = False
            if provider is not None:
                extra = getattr(provider, "extra_settings", None) or {}
                trust_idp_mfa = bool(extra.get("trust_idp_mfa", False))

            if not trust_idp_mfa:
                logger.info(
                    "SSO login for user %s requires local MFA; issuing mfa_pending token",
                    user.id,
                )
                mfa_token = create_access_token(
                    subject=str(user.id),
                    expires_delta=timedelta(minutes=5),
                    extra_claims={"type": "mfa_pending", "aud": "freesdn-mfa"},
                    token_version=token_version,
                )
                return SSOCallbackResponse(
                    access_token=None,
                    refresh_token=None,
                    token_type="bearer",
                    expires_in=None,
                    user=None,
                    require_mfa=True,
                    mfa_token=mfa_token,
                )

        # ------------------------------------------------------------------
        # Normal path: issue full access + refresh tokens
        # ------------------------------------------------------------------
        role = user.role if isinstance(user.role, str) else user.role.value
        access_token = create_access_token(
            subject=str(user.id),
            extra_claims={
                "role": role,
                "org_id": str(user.organization_id) if user.organization_id else None,
            },
            token_version=token_version,
        )
        refresh_token = create_refresh_token(
            subject=str(user.id),
            token_version=token_version,
        )

        # record a per-device UserSession so this initial SSO
        # session is individually revocable (DELETE /auth/sessions/{id}) — the
        # password-login path does this, but the SSO path previously didn't, so
        # an SSO refresh token wasn't tracked until its first rotation and a
        # targeted revoke couldn't kill it. Bookkeeping must never break login.
        try:
            from app.core.security import decode_token
            from app.models.core import UserSession

            _acc = await decode_token(access_token) or {}
            _ref = await decode_token(refresh_token) or {}
            _now = datetime.now(UTC)
            self.db.add(
                UserSession(
                    user_id=user.id,
                    refresh_jti=_ref.get("jti"),
                    access_jti=_acc.get("jti"),
                    created_at=_now,
                    last_used_at=_now,
                    is_revoked=False,
                )
            )
            await self.db.flush()
        except Exception:
            logger.warning("SSO UserSession bookkeeping failed", exc_info=True)

        auth_provider_name = user.auth_provider or (
            provider.protocol.value if provider is not None else "local"
        )
        return SSOCallbackResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            user=SSOUserInfo(
                id=user.id,
                email=user.email,
                username=user.username,
                full_name=user.full_name,
                role=role,
                organization_id=user.organization_id,
                auth_provider=auth_provider_name,
            ),
            require_mfa=False,
            mfa_token=None,
        )

    # =====================================================================
    # Session Helpers
    # =====================================================================

    @staticmethod
    def _validate_redirect_uri(provider: SSOProvider, redirect_uri: str) -> None:
        """Enforce default-deny on SSO redirect_uri.

        An empty or missing ``extra_settings.allowed_redirect_uris``
        MUST NOT accept arbitrary URIs — the only implicit allow is
        the application's own ``PUBLIC_BASE_URL + /auth/callback``.
        Raises ``SSOConfigError`` if ``redirect_uri`` is not allowed.
        """
        allowed_uris = list((provider.extra_settings or {}).get("allowed_redirect_uris", []) or [])

        # Always implicitly allow the application's own callback URL.
        from app.core.config import settings

        base = settings.PUBLIC_BASE_URL.rstrip("/")
        # The canonical FE route is /auth/sso/callback (SSOCallbackPage); the
        # bare /auth/callback is kept for backward-compat. Both are implicitly
        # allowed so a stock install's SSO login isn't dead-on-arrival.
        default_callback = f"{base}/auth/sso/callback"
        for implicit in (default_callback, f"{base}/auth/callback"):
            if implicit not in allowed_uris:
                allowed_uris.append(implicit)

        if redirect_uri not in allowed_uris:
            raise SSOConfigError(
                f"redirect_uri {redirect_uri!r} not in allowed_redirect_uris. "
                f"Add it to the SSO provider's extra_settings.allowed_redirect_uris "
                f"or use the default {default_callback!r}."
            )

    async def _validate_sso_session(self, state: str) -> SSOSession:
        """Validate and atomically claim an SSO session by state token.

        Two parallel callbacks with the same ``state`` used to
        both read ``completed_at = None``, both pass the check, and race
        to redeem the authorization code / SAML response twice.  We now
        acquire a row-level lock via ``SELECT ... FOR UPDATE`` and mark
        the session as completed *before* returning, so the second
        caller either sees ``completed_at is not None`` or blocks on the
        lock and then sees the same.
        """
        stmt = select(SSOSession).where(SSOSession.state == state).with_for_update()
        result = await self.db.execute(stmt)
        session = result.scalar_one_or_none()

        if not session:
            raise SSOCallbackError("Invalid SSO state token")
        if session.completed_at is not None:
            raise SSOCallbackError("SSO session already completed")
        if session.expires_at < datetime.now(UTC):
            raise SSOCallbackError("SSO session expired")

        # Claim the session now, inside the still-open transaction, so
        # any concurrent caller waiting on the row lock will observe
        # completed_at != None after we flush.  Callers (oidc_callback /
        # saml_callback) still set completed_at again on success — this
        # first write is the race-safe gate.
        session.completed_at = datetime.now(UTC)
        await self.db.flush()

        return session

    # =====================================================================
    # Test Connectivity
    # =====================================================================

    async def test_connection(self, provider: SSOProvider) -> SSOTestConnectionResponse:
        """Test connectivity to the configured IdP."""
        try:
            if provider.protocol == SSOProtocol.OIDC:
                return await self._test_oidc(provider)
            elif provider.protocol == SSOProtocol.SAML:
                return await self._test_saml(provider)
            elif provider.protocol == SSOProtocol.LDAP:
                return await self._test_ldap(provider)
            else:
                return SSOTestConnectionResponse(
                    success=False, message=f"Unknown protocol: {provider.protocol}"
                )
        except Exception as e:
            return SSOTestConnectionResponse(success=False, message=str(e))

    async def _test_oidc(self, provider: SSOProvider) -> SSOTestConnectionResponse:
        url = self._effective_discovery_url(provider)
        if not url:
            return SSOTestConnectionResponse(
                success=False, message="No OIDC discovery URL or issuer configured"
            )
        try:
            # DNS-rebinding-safe fetch. Pass the admin-configured IdP
            # host(s) as allow_hosts so "Test Connection" matches the live login
            # flow — an on-prem IdP on a private IP must report reachable, not
            # falsely SSRF-blocked.
            resp = await safe_http_request(
                "GET", url, timeout=10.0, allow_hosts=self._trusted_idp_hosts(provider)
            )
        except ValueError as e:
            return SSOTestConnectionResponse(success=False, message=f"OIDC URL blocked (SSRF): {e}")
        if resp.status_code == 200:
            data = resp.json()
            return SSOTestConnectionResponse(
                success=True,
                message="OIDC discovery successful",
                details={
                    "issuer": data.get("issuer"),
                    "authorization_endpoint": data.get("authorization_endpoint"),
                    "token_endpoint": data.get("token_endpoint"),
                },
            )
        return SSOTestConnectionResponse(
            success=False, message=f"OIDC discovery returned {resp.status_code}"
        )

    async def _test_saml(self, provider: SSOProvider) -> SSOTestConnectionResponse:
        if not provider.saml_sso_url:
            return SSOTestConnectionResponse(success=False, message="No SAML SSO URL configured")
        try:
            # DNS-rebinding-safe HEAD probe (allow_hosts mirrors the
            # login flow so an internal SAML IdP reports reachable).
            resp = await safe_http_request(
                "HEAD",
                provider.saml_sso_url,
                timeout=10.0,
                allow_hosts=self._trusted_idp_hosts(provider),
            )
        except ValueError as e:
            return SSOTestConnectionResponse(success=False, message=f"SAML URL blocked (SSRF): {e}")
        reachable = resp.status_code < 500
        return SSOTestConnectionResponse(
            success=reachable,
            message="SAML endpoint reachable"
            if reachable
            else f"SAML endpoint returned {resp.status_code}",
            details={"sso_url": provider.saml_sso_url},
        )

    async def _test_ldap(self, provider: SSOProvider) -> SSOTestConnectionResponse:
        if not provider.ldap_url:
            return SSOTestConnectionResponse(success=False, message="No LDAP URL configured")
        # SSRF validation for LDAP host
        from urllib.parse import urlparse as _urlparse

        _ldap_host = _urlparse(provider.ldap_url).hostname
        if _ldap_host:
            try:
                validate_target_host(_ldap_host)
            except ValueError as e:
                return SSOTestConnectionResponse(
                    success=False, message=f"LDAP host blocked (SSRF): {e}"
                )
        try:
            import ssl

            from ldap3 import (
                ALL,
                AUTO_BIND_NO_TLS,
                AUTO_BIND_TLS_BEFORE_BIND,
                Connection,
                Server,
                Tls,
            )
        except ImportError:
            return SSOTestConnectionResponse(
                success=False,
                message="ldap3 package not installed",
            )

        tls_config = None
        if provider.ldap_use_tls:
            tls_config = Tls(validate=ssl.CERT_REQUIRED)

        server = Server(
            provider.ldap_url,
            use_ssl=provider.ldap_url.startswith("ldaps://"),
            tls=tls_config,
            get_info=ALL,
        )
        # when TLS is requested over a plaintext ldap:// URL, do
        # StartTLS BEFORE sending any credential (fail closed if it can't
        # negotiate). ldaps:// is already TLS via use_ssl above; plain ldap://
        # with TLS not requested stays as-is.
        _auto_bind = (
            AUTO_BIND_TLS_BEFORE_BIND
            if (provider.ldap_use_tls and not provider.ldap_url.startswith("ldaps://"))
            else AUTO_BIND_NO_TLS
        )
        try:
            conn = Connection(
                server,
                user=provider.ldap_bind_dn,
                password=decrypt_field(provider.ldap_bind_password)
                if provider.ldap_bind_password
                else provider.ldap_bind_password,
                auto_bind=_auto_bind,
                read_only=True,
            )
            info = str(server.info) if server.info else "Connected"
            conn.unbind()
            return SSOTestConnectionResponse(
                success=True,
                message="LDAP bind successful",
                details={"server_info": info[:500]},
            )
        except Exception as e:
            return SSOTestConnectionResponse(
                success=False,
                message=f"LDAP bind failed: {e}",
            )

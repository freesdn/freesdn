# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SSO Schemas
============================

Pydantic schemas for SSO provider management and auth flows.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


def _require_http_url(v: str | None) -> str | None:
    """Reject a non-http(s) or host-less IdP URL at config time.

    The OIDC issuer/discovery and SAML endpoint hosts are trusted for the
    private-IP SSRF bypass during login, so a typo'd or non-URL value must fail
    here rather than silently widen the allow-list or get stored as junk.
    """
    if not v:
        return v
    from urllib.parse import urlparse

    parsed = urlparse(v)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("must be an http(s):// URL with a hostname")
    return v


# ---------------------------------------------------------------------------
# Provider CRUD Schemas
# ---------------------------------------------------------------------------


class SSOProviderBase(BaseModel):
    """Shared fields for SSO provider create/update."""

    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    description: str | None = None
    protocol: str = Field(..., pattern=r"^(oidc|saml|ldap)$")
    status: str = Field(default="inactive", pattern=r"^(active|inactive|testing)$")

    icon_url: str | None = None
    display_order: int = 0

    # OIDC
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_scopes: str | None = "openid profile email"
    oidc_discovery_url: str | None = None

    # SAML
    saml_entity_id: str | None = None
    saml_sso_url: str | None = None
    saml_slo_url: str | None = None
    saml_certificate: str | None = None
    saml_signing_key: str | None = None
    saml_name_id_format: str | None = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # LDAP
    ldap_url: str | None = None
    ldap_bind_dn: str | None = None
    ldap_bind_password: str | None = None
    ldap_base_dn: str | None = None
    ldap_user_search_filter: str | None = "(&(objectClass=user)(sAMAccountName={username}))"
    ldap_group_search_filter: str | None = None
    ldap_use_tls: bool = True
    ldap_tls_ca_cert: str | None = None

    # Mappings
    attribute_mapping: dict[str, str] = Field(
        default_factory=lambda: {
            "email": "email",
            "username": "preferred_username",
            "full_name": "name",
        }
    )
    role_mapping: dict[str, str] = Field(default_factory=dict)

    # JIT
    jit_provisioning: bool = True
    default_role: str = "viewer"

    extra_settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("oidc_issuer", "oidc_discovery_url", "saml_sso_url", "saml_slo_url")
    @classmethod
    def _validate_idp_urls(cls, v: str | None) -> str | None:
        return _require_http_url(v)


class SSOProviderCreate(SSOProviderBase):
    """Create a new SSO provider."""

    organization_id: UUID

    @field_validator("protocol")
    @classmethod
    def validate_required_fields(cls, v: str, info: Any) -> str:
        """Ensure protocol-specific required fields are present."""
        # Validation is deferred to service layer for richer error messages
        return v


class SSOProviderUpdate(BaseModel):
    """Update an existing SSO provider (all fields optional)."""

    name: str | None = None
    description: str | None = None
    status: str | None = Field(default=None, pattern=r"^(active|inactive|testing)$")
    icon_url: str | None = None
    display_order: int | None = None

    # OIDC
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_scopes: str | None = None
    oidc_discovery_url: str | None = None

    # SAML
    saml_entity_id: str | None = None
    saml_sso_url: str | None = None
    saml_slo_url: str | None = None
    saml_certificate: str | None = None
    saml_signing_key: str | None = None
    saml_name_id_format: str | None = None

    # LDAP
    ldap_url: str | None = None
    ldap_bind_dn: str | None = None
    ldap_bind_password: str | None = None
    ldap_base_dn: str | None = None
    ldap_user_search_filter: str | None = None
    ldap_group_search_filter: str | None = None
    ldap_use_tls: bool | None = None
    ldap_tls_ca_cert: str | None = None

    # Mappings
    attribute_mapping: dict[str, str] | None = None
    role_mapping: dict[str, str] | None = None

    # JIT
    jit_provisioning: bool | None = None
    default_role: str | None = None

    extra_settings: dict[str, Any] | None = None

    @field_validator("oidc_issuer", "oidc_discovery_url", "saml_sso_url", "saml_slo_url")
    @classmethod
    def _validate_idp_urls(cls, v: str | None) -> str | None:
        return _require_http_url(v)


class SSOProviderResponse(BaseModel):
    """Public SSO provider response (secrets masked)."""

    id: UUID
    organization_id: UUID
    name: str
    slug: str
    description: str | None
    protocol: str
    status: str
    icon_url: str | None
    display_order: int

    # OIDC (no client_secret)
    oidc_issuer: str | None
    oidc_client_id: str | None
    oidc_scopes: str | None
    oidc_discovery_url: str | None

    # SAML (no signing_key)
    saml_entity_id: str | None
    saml_sso_url: str | None
    saml_slo_url: str | None
    saml_name_id_format: str | None

    # LDAP (no bind_password)
    ldap_url: str | None
    ldap_bind_dn: str | None
    ldap_base_dn: str | None
    ldap_user_search_filter: str | None
    ldap_group_search_filter: str | None
    ldap_use_tls: bool | None

    # Mappings
    attribute_mapping: dict[str, str]
    role_mapping: dict[str, str]

    # JIT
    jit_provisioning: bool
    default_role: str

    # Timestamps
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SSOProviderPublic(BaseModel):
    """Minimal info shown on the login page for SSO buttons."""

    id: UUID
    name: str
    slug: str
    protocol: str
    icon_url: str | None
    display_order: int

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Auth-flow Schemas
# ---------------------------------------------------------------------------


class SSOAuthorizeRequest(BaseModel):
    """Initiate an SSO login flow."""

    # Slug matches the regex on ``SSOProviderBase.slug`` (``[a-z0-9-]``)
    # and the same length cap so a bogus slug rejects at the schema
    # layer instead of at the DB lookup. ``redirect_uri`` was unbounded;
    # IdP callback URIs are typically <500 chars but cap at 2048 to
    # accommodate query-string-heavy callbacks while rejecting DoS.
    provider_slug: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    redirect_uri: str | None = Field(None, max_length=2048)


class SSOAuthorizeResponse(BaseModel):
    """Redirect URL for the user to authenticate with the IdP."""

    authorize_url: str
    state: str


class SSOCallbackRequest(BaseModel):
    """Callback from OIDC / SAML IdP."""

    # ``state`` is a server-generated nonce (CSRF token); 256 chars is
    # generous. ``code`` is an OIDC authorization code (vendor-defined
    # max but rarely >1024). ``saml_response`` is a base64-encoded
    # XML blob — real SAML assertions can be 30-50 KB so cap at
    # 64 KiB; over that is almost certainly an attack.
    state: str = Field(..., min_length=1, max_length=256)
    code: str | None = Field(None, max_length=2048)
    saml_response: str | None = Field(None, max_length=65536)


class SSOCallbackResponse(BaseModel):
    """Response from a successful SSO callback.

    When the local user has MFA enabled and the SSO provider does NOT
    opt in to ``trust_idp_mfa``, this response instead
    carries an MFA challenge: ``require_mfa=True`` with a short-lived
    ``mfa_token`` that the caller must exchange via
    ``POST /auth/login/mfa`` to obtain a full session.  In that case
    ``access_token`` / ``refresh_token`` / ``user`` are ``None``.

    SECURITY: raw tokens are delivered via httpOnly
    cookies only.  ``access_token`` / ``refresh_token`` remain in this
    schema for backward compatibility with non-browser callers but are
    NOT returned by the server when the SSO callback also sets cookies.
    Browser clients MUST check ``authenticated: true`` as the success
    signal instead of testing for the presence of ``access_token``.
    """

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None
    user: SSOUserInfo | None = None
    # non-token success signal for browser SSO callbacks.
    # Set to True when cookies have been written and the session is ready.
    # Browsers MUST use this field (not access_token) as the presence guard.
    authenticated: bool = False
    # MFA challenge fields (set when local MFA is required)
    require_mfa: bool = False
    mfa_token: str | None = None


class SSOUserInfo(BaseModel):
    """User info extracted from IdP."""

    id: UUID
    email: str
    username: str
    full_name: str | None
    role: str
    organization_id: UUID | None
    auth_provider: str


class LDAPAuthRequest(BaseModel):
    """Direct LDAP auth (username/password)."""

    provider_slug: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    # LDAP usernames can include a full DN (e.g.
    # ``CN=admin,OU=People,DC=corp,DC=local``) so 1024 chars is the
    # right ceiling. Password capped to avoid Argon2-shape DoS on
    # any future hashing path.
    username: str = Field(..., min_length=1, max_length=1024)
    password: str = Field(..., min_length=1, max_length=1024)


class SSOTestConnectionRequest(BaseModel):
    """Test IdP connectivity."""

    provider_id: UUID


class SSOTestConnectionResponse(BaseModel):
    """Test result."""

    success: bool
    message: str
    details: dict[str, Any] | None = None

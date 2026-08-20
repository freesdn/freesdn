# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Core Pydantic Schemas
===================================

Request/Response schemas for authentication and core entities.
"""

from datetime import datetime
from typing import Any, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.core.security import validate_password as _validate_password
from app.models.core import ControllerStatus, ControllerType, UserRole

# Type variable for generic pagination
T = TypeVar("T")


# ===========================================
# Base Schemas
# ===========================================


class BaseSchema(BaseModel):
    """Base schema with common configuration."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
    )


class TimestampSchema(BaseSchema):
    """Schema with timestamp fields."""

    created_at: datetime
    updated_at: datetime


class MessageResponse(BaseSchema):
    """Simple message response."""

    message: str
    success: bool = True
    details: dict[str, Any] | None = None


# ===========================================
# Authentication Schemas
# ===========================================


class TokenResponse(BaseSchema):
    """JWT token response — used by OAuth2 /auth/token and agent/API-key flows."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Token expiration in seconds")


class BrowserAuthResponse(BaseSchema):
    """Slim auth response for browser cookie-based endpoints.

    The browser already receives access + refresh tokens via httpOnly cookies
    set in the ``Set-Cookie`` response header.  Echoing the raw token values
    in the JSON body is unnecessary and exposes them to JavaScript (XSS risk).
    This schema intentionally omits ``access_token`` and ``refresh_token`` so
    the JSON body carries no bearer-usable secrets.
    """

    token_type: str = "bearer"
    expires_in: int = Field(description="Access token lifetime in seconds")


class TokenPayload(BaseSchema):
    """Decoded JWT token payload."""

    sub: str
    exp: datetime
    iat: datetime
    type: str


class LoginRequest(BaseSchema):
    """User login request.

    Accepts either an email address or a username in the 'login' field.
    Industry standard for self-hosted network management platforms.
    """

    login: str = Field(min_length=1, max_length=254, description="Email address or username")
    password: str = Field(min_length=1, max_length=256)
    remember_me: bool = Field(
        default=False,
        description=(
            "Opt into a longer-lived session ('remember me'). When true the "
            "refresh token + cookies use the extended remember-me window."
        ),
    )


class RefreshTokenRequest(BaseSchema):
    """Token refresh request.

    ``refresh_token`` is OPTIONAL because the endpoint documents itself as
    accepting "refresh token from JSON body OR httpOnly cookie" -- a browser
    has the cookie and has nothing to put in the body.

    It used to be required, and that made the whole refresh path unusable from
    the SPA. The axios interceptor posts ``{}`` (client.ts) and the auth store
    posts ``{}`` (authStore.ts), which is a PRESENT body that failed
    validation, so every refresh returned 422. The interceptor treats that as
    a failed refresh, clears auth state and drops the user on the login screen.

    Net effect: the access token lives 3600s, and at expiry the very mechanism
    meant to renew the session silently ended it instead. Sessions could never
    outlive one token lifetime. Found by driving the live UI -- the suite never
    posts an empty body, and ``curl`` with no body at all returns 200, so both
    of the obvious checks pass.
    """

    refresh_token: str | None = None


class PasswordChangeRequest(BaseSchema):
    """Password change request."""

    current_password: str
    new_password: str = Field(min_length=8, max_length=256)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)


class PasswordResetRequestSchema(BaseSchema):
    """Request a password reset link."""

    email: EmailStr


class PasswordResetConfirmSchema(BaseSchema):
    """Consume a password-reset token and set new password."""

    token: str
    new_password: str = Field(min_length=8, max_length=256)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)


class RegisterRequest(BaseSchema):
    """Self-registration request."""

    email: EmailStr
    password: str = Field(min_length=8, max_length=256)
    first_name: str = Field(default="", max_length=100)
    last_name: str = Field(default="", max_length=100)
    # ``organization_name`` was unbounded — only field on the
    # self-registration schema without a cap; a 100 MB string was
    # passed through to the User row.
    organization_name: str | None = Field(None, max_length=255)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)


class MfaSetupRequest(BaseSchema):
    """Optional body for POST /auth/mfa/setup.

       Fresh enrollment (MFA not yet enabled) needs no body. Re-enrolling on an
       account that ALREADY has MFA enabled requires step-up re-authentication
    — supply the account password here. The whole body is
       optional so the fresh-enrollment flow is unchanged.
    """

    password: str | None = None


class MfaSetupResponse(BaseSchema):
    """MFA setup response with secret and QR URI."""

    secret: str
    uri: str
    backup_codes: list[str]


class MfaEnableRequest(BaseSchema):
    """Confirm MFA setup with a TOTP code."""

    code: str = Field(min_length=6, max_length=6)


class MfaDisableRequest(BaseSchema):
    """Disable MFA (requires password confirmation)."""

    password: str = Field(min_length=1)


class MfaLoginRequest(BaseSchema):
    """Complete MFA verification during login."""

    # JWT mfa_pending tokens are ~300-500 bytes; cap at 2048 to
    # reject obviously-malformed submissions before JWT parsing.
    mfa_token: str = Field(min_length=20, max_length=2048)
    code: str = Field(min_length=6, max_length=8)  # 6 for TOTP, 8 for backup


class ProfileUpdateRequest(BaseSchema):
    """Update current user's profile."""

    full_name: str | None = Field(None, max_length=255)
    username: str | None = Field(None, min_length=3, max_length=100)
    language: str | None = Field(None, min_length=2, max_length=10)


# ───────────────────────────────────────────────────────────────────────
# Per-device session management
# ───────────────────────────────────────────────────────────────────────
# Returned by GET /auth/sessions. Never includes the raw refresh-token
# or JTI — only metadata the user needs to identify and revoke a device.


class SessionInfo(BaseSchema):
    """A single authenticated session for the current user."""

    id: UUID
    user_agent: str | None = None
    ip_address: str | None = None
    created_at: datetime | None = None
    last_seen_at: datetime | None = None
    revoked_at: datetime | None = None
    is_revoked: bool = False


class SessionListResponse(BaseSchema):
    """Response body for GET /auth/sessions."""

    sessions: list[SessionInfo]


# ===========================================
# User Schemas
# ===========================================


class UserBase(BaseSchema):
    """Base user schema."""

    email: EmailStr
    username: str = Field(min_length=3, max_length=100)
    # ``full_name`` was unbounded — only field on the user schema
    # without a cap. A 100 MB ``full_name`` was previously accepted
    # all the way to the DB.
    full_name: str | None = Field(None, max_length=255)


class UserCreate(UserBase):
    """User creation schema."""

    password: str = Field(min_length=8, max_length=256)
    role: UserRole = UserRole.VIEWER
    organization_id: UUID | None = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password(v)


class UserUpdate(BaseSchema):
    """User update schema."""

    email: EmailStr | None = None
    username: str | None = Field(None, min_length=3, max_length=100)
    # Mirror UserBase / DB column (``core.users.full_name`` is
    # VARCHAR(255)). Previously unbounded — a 10 KB ``full_name``
    # reached the DB and bubbled
    # ``psycopg.errors.StringDataRightTruncation`` → 500 (the existing
    # IntegrityError handler doesn't catch DataError).
    full_name: str | None = Field(None, max_length=255)
    role: UserRole | None = None
    is_active: bool | None = None
    language: str | None = Field(
        None, min_length=2, max_length=10, description="ISO language code (e.g., 'en', 'fr', 'zh')"
    )


class UserResponse(UserBase, TimestampSchema):
    """User response schema."""

    id: UUID
    role: UserRole
    organization_id: UUID | None
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    last_login: datetime | None
    language: str = "en"
    permissions: list[str] = Field(default_factory=list)
    is_superuser: bool = False
    is_org_admin: bool = False


class UserWithOrg(UserResponse):
    """User response with organization info."""

    organization: "OrganizationResponse | None" = None


# ===========================================
# Organization Schemas
# ===========================================


def _validate_org_settings_size(v: dict[str, Any] | None) -> dict[str, Any] | None:
    """Cap ``settings`` JSONB at 32 KiB; previously unbounded.

    Without this an org_admin could persist a 1 MB ``settings`` blob
    that re-deserialized on every dashboard load.
    """
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > 32 * 1024:
        raise ValueError(f"settings exceeds 32768 bytes (got {size})")
    return v


class OrganizationBase(BaseSchema):
    """Base organization schema."""

    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    description: str | None = Field(None, max_length=2000)
    contact_email: EmailStr | None = None
    # E.164 max is 15 digits; 32 chars covers formatted variants
    # (``+1 (555) 555-1234``) without leaving a DoS-shaped field
    # unbounded.
    contact_phone: str | None = Field(None, max_length=32)


class OrganizationCreate(OrganizationBase):
    """Organization creation schema."""

    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("settings")
    @classmethod
    def _settings_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_org_settings_size(v) or v


class OrganizationUpdate(BaseSchema):
    """Organization update schema."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    contact_email: EmailStr | None = None
    contact_phone: str | None = Field(None, max_length=32)
    settings: dict[str, Any] | None = None
    is_active: bool | None = None

    @field_validator("settings")
    @classmethod
    def _settings_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_org_settings_size(v)


class OrganizationResponse(OrganizationBase, TimestampSchema):
    """Organization response schema."""

    id: UUID
    is_active: bool
    settings: dict[str, Any]


class OrganizationWithStats(OrganizationResponse):
    """Organization with statistics."""

    site_count: int = 0
    user_count: int = 0
    device_count: int = 0


# ===========================================
# Site Schemas
# ===========================================

# Supported time formats
TIME_FORMATS = ["12h", "24h"]

# Common date formats
DATE_FORMATS = [
    "YYYY-MM-DD",  # ISO 8601 (2024-12-31)
    "DD/MM/YYYY",  # European (31/12/2024)
    "MM/DD/YYYY",  # US (12/31/2024)
    "DD-MM-YYYY",  # Alternative European (31-12-2024)
    "DD.MM.YYYY",  # German/Swiss (31.12.2024)
    "YYYY/MM/DD",  # Japanese (2024/12/31)
]


def assert_safe_site_cidr(network: Any) -> None:
    """Reject CIDRs that are unsafe as a Site.subnet.

    Site.subnets is a trust boundary: VoIP provisioning grants an unauthenticated,
    secret-bearing config to any client whose source IP falls in a site subnet
    (before HMAC). A default-route / special-use / overly-broad-public CIDR would
    therefore turn that into public MAC-only access. Provisioning subnets are LAN
    ranges, so we reject anything broader/unsafe than that.
    """
    if network.prefixlen == 0:
        raise ValueError("default-route CIDR (0.0.0.0/0 or ::/0) is not allowed as a site subnet")
    if (
        network.is_multicast
        or network.is_loopback
        or network.is_link_local
        or network.is_unspecified
        or network.is_reserved
    ):
        raise ValueError("special-use CIDR is not allowed as a site subnet")
    # A public (non-private) block must be tight; broad public ranges would match
    # arbitrary internet clients.
    if not network.is_private and network.prefixlen < (24 if network.version == 4 else 64):
        raise ValueError("overly broad public CIDR is not allowed as a site subnet")


def is_safe_site_cidr(network: Any) -> bool:
    """Boolean form of :func:`assert_safe_site_cidr` (for fail-closed read paths)."""
    try:
        assert_safe_site_cidr(network)
        return True
    except ValueError:
        return False


class SiteSubnet(BaseSchema):
    """A subnet definition for a site."""

    cidr: str = Field(max_length=43, description="CIDR notation, e.g. 192.168.1.0/24")
    name: str = Field(default="", max_length=100, description="Friendly name, e.g. 'Management'")
    vlan_id: int | None = Field(None, ge=1, le=4094, description="Optional VLAN tag")
    description: str = Field(default="", max_length=500)

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        import ipaddress

        try:
            network = ipaddress.ip_network(v.strip(), strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: {v}")
        assert_safe_site_cidr(network)  # reject dangerous/overbroad subnets
        return str(network)  # normalized form


def _validate_time_format(v: str | None) -> str | None:
    if v is None:
        return v
    if v not in TIME_FORMATS:
        raise ValueError(f"time_format must be one of {TIME_FORMATS}")
    return v


def _validate_date_format(v: str | None) -> str | None:
    if v is None:
        return v
    if v not in DATE_FORMATS:
        raise ValueError(f"date_format must be one of {DATE_FORMATS}")
    return v


def _validate_site_settings_size(v: dict[str, Any] | None) -> dict[str, Any] | None:
    """Cap site.settings JSONB at 32 KiB; previously unbounded.

    A 200-key x 200-byte settings blob (~40 KB) was accepted into
    ``core.sites.settings`` and re-deserialized on every dashboard
    request.
    """
    if v is None:
        return v
    import json as _json

    size = len(_json.dumps(v, default=str).encode("utf-8"))
    if size > 32 * 1024:
        raise ValueError(f"settings exceeds 32768 bytes (got {size})")
    return v


class SiteBase(BaseSchema):
    """Base site schema."""

    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    # DB columns: description TEXT, address TEXT, city/country
    # String(100). Capping ``description``/``address`` at 2000 prevents
    # bloat without restricting legitimate use; ``city``/``country``
    # are mirrored to the DB column width so the schema rejects before
    # psycopg StringDataRightTruncation → 500.
    description: str | None = Field(None, max_length=2000)
    address: str | None = Field(None, max_length=500)
    city: str | None = Field(None, max_length=100)
    country: str | None = Field(None, max_length=100)
    timezone: str = Field(
        default="UTC",
        max_length=64,
        description="IANA timezone (e.g., 'America/New_York', 'Europe/London')",
    )
    time_format: str = Field(default="24h", description="Time format: '12h' or '24h'")
    date_format: str = Field(default="YYYY-MM-DD", description="Date format pattern")
    subnets: list[SiteSubnet] = Field(
        default_factory=list, max_length=200, description="Site network subnets (max 200)"
    )
    gateway_ip: str | None = Field(None, max_length=45, description="Site gateway IP address")

    @field_validator("time_format")
    @classmethod
    def _tf(cls, v: str) -> str:
        return _validate_time_format(v) or v

    @field_validator("date_format")
    @classmethod
    def _df(cls, v: str) -> str:
        return _validate_date_format(v) or v

    @field_validator("gateway_ip")
    @classmethod
    def validate_gateway_ip(cls, v: str | None) -> str | None:
        if v is None or v.strip() == "":
            return None
        import ipaddress

        try:
            addr = ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return str(addr)


class SiteCreate(SiteBase):
    """Site creation schema.

    ``organization_id`` is optional — when omitted, the endpoint
    infers it from the authenticated user's ``user.organization_id``
    (the common case for non-super_admin operators). Super_admins
    can still pass an explicit ``organization_id`` to create a site
    in another tenant.

    Without this relaxation, the frontend's Sites > Create Site
    dialog 422s because it doesn't (and shouldn't) require the
    operator to type their own org UUID — that's a server-side
    contextual concern.
    """

    organization_id: UUID | None = None
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("settings")
    @classmethod
    def _settings_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_site_settings_size(v) or v


class SiteUpdate(BaseSchema):
    """Site update schema."""

    name: str | None = Field(None, min_length=1, max_length=255)
    # Cap to match SiteBase (and the DB columns) so a 10 KB
    # description / 500-char city doesn't slip past pydantic into
    # psycopg StringDataRightTruncation.
    description: str | None = Field(None, max_length=2000)
    address: str | None = Field(None, max_length=500)
    city: str | None = Field(None, max_length=100)
    country: str | None = Field(None, max_length=100)
    timezone: str | None = Field(
        None, max_length=64, description="IANA timezone (e.g., 'America/New_York')"
    )
    time_format: str | None = Field(None, description="Time format: '12h' or '24h'")
    date_format: str | None = Field(None, description="Date format pattern")
    settings: dict[str, Any] | None = None
    is_active: bool | None = None
    subnets: list[SiteSubnet] | None = Field(None, max_length=200)
    gateway_ip: str | None = Field(None, max_length=45)

    @field_validator("time_format")
    @classmethod
    def _tf(cls, v: str | None) -> str | None:
        return _validate_time_format(v)

    @field_validator("date_format")
    @classmethod
    def _df(cls, v: str | None) -> str | None:
        return _validate_date_format(v)

    @field_validator("settings")
    @classmethod
    def _settings_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_site_settings_size(v)

    @field_validator("gateway_ip")
    @classmethod
    def validate_gateway_ip(cls, v: str | None) -> str | None:
        if v is None or v.strip() == "":
            return None
        import ipaddress

        try:
            addr = ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return str(addr)


class SiteResponse(SiteBase, TimestampSchema):
    """Site response schema."""

    id: UUID
    organization_id: UUID
    is_active: bool
    settings: dict[str, Any]
    time_format: str = "24h"
    date_format: str = "YYYY-MM-DD"
    subnets: list[SiteSubnet] = Field(default_factory=list)
    gateway_ip: str | None = None


class SiteWithStats(SiteResponse):
    """Site with statistics."""

    controller_count: int = 0
    device_count: int = 0
    online_device_count: int = 0


# ===========================================
# User Site Access Schemas
# ===========================================

_ACCESS_LEVEL_ALLOWED = {"admin", "full", "write", "read"}


def _validate_access_level(v: str | None) -> str | None:
    """Allowlist for ``UserSiteAccess.access_level``.

    Downstream ``has_site_permission`` already fails-secure on unknown
    values, but the column previously accepted any string ("hacker_god",
    10 KB blobs) and persisted it. That bloats the JSONB-adjacent column
    and risks a future ``access_level == "X"`` comparison honoring
    garbage. Enforce the allowlist + None at the schema layer.
    """
    if v is None:
        return v
    if v.lower() not in _ACCESS_LEVEL_ALLOWED:
        raise ValueError("access_level must be one of: admin, full, write, read (or null)")
    return v.lower()


class UserSiteAccessCreate(BaseSchema):
    """Grant a user access to a site."""

    user_id: UUID
    site_id: UUID
    access_level: str | None = Field(
        None,
        description="Optional access level override: 'admin', 'full', 'write', 'read'. NULL inherits global role.",
        max_length=16,
    )

    @field_validator("access_level")
    @classmethod
    def _check_access_level(cls, v: str | None) -> str | None:
        return _validate_access_level(v)


class UserSiteAccessResponse(TimestampSchema):
    """User site access response."""

    id: UUID
    user_id: UUID
    site_id: UUID
    access_level: str | None = None


class UserSiteAccessBulk(BaseSchema):
    """Bulk-assign sites to a user."""

    user_id: UUID
    # A user reasonably manages dozens-not-thousands of sites; 500 is
    # safely above any realistic case and keeps the IN(...) build bounded.
    site_ids: list[UUID] = Field(..., max_length=500)
    access_level: str | None = Field(None, max_length=16)

    @field_validator("access_level")
    @classmethod
    def _check_access_level(cls, v: str | None) -> str | None:
        return _validate_access_level(v)


# ===========================================
# Organization Dashboard Schema
# ===========================================


class OrganizationDashboard(OrganizationResponse):
    """Rich organisation dashboard payload."""

    site_count: int = 0
    user_count: int = 0
    controller_count: int = 0
    device_count: int = 0
    online_device_count: int = 0
    recent_sites: list[SiteWithStats] = Field(default_factory=list)


# ===========================================
# Controller Schemas
# ===========================================


def _validate_controller_config(v: dict[str, Any] | None) -> dict[str, Any] | None:
    """Cap controller ``config`` JSONB (256 keys / 8 KB / 64 KB total).

    The endpoint stores creds + adapter-specific knobs (token_id /
    token_secret / realm / site_mappings, …) in this column. Previously
    unbounded — a single create with {200 keys × 500 bytes} (~100 KB)
    persisted. Bounds match the storage_locations cap shape.
    """
    if v is None:
        return v
    if len(v) > 256:
        raise ValueError("config must contain at most 256 keys")
    import json as _json

    for key, val in v.items():
        if not isinstance(key, str) or len(key) > 128:
            raise ValueError("config keys must be strings of <= 128 chars")
        if isinstance(val, str) and len(val) > 8192:
            raise ValueError(f"config['{key}'] exceeds 8192 chars")
    total = len(_json.dumps(v, default=str).encode("utf-8"))
    if total > 64 * 1024:
        raise ValueError(f"config exceeds 65536 bytes (got {total})")
    return v


def _validate_site_mappings(v: dict[str, str] | None) -> dict[str, str] | None:
    """Cap site_mappings dict (200 entries, keys/values <= 64 chars).

    Values are FreeSDN site UUIDs — 36 chars at most. Keys are
    upstream controller-side IDs (Omada site IDs, etc.) which are
    typically 24-32 char hex strings. 200 entries is well above any
    realistic multi-site Omada deployment.
    """
    if v is None:
        return v
    if len(v) > 200:
        raise ValueError("site_mappings must contain at most 200 entries")
    for key, val in v.items():
        if not isinstance(key, str) or len(key) > 64:
            raise ValueError("site_mappings keys must be strings of <= 64 chars")
        if not isinstance(val, str) or len(val) > 64:
            raise ValueError("site_mappings values must be strings of <= 64 chars")
    return v


class ControllerBase(BaseSchema):
    """Base controller schema."""

    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    controller_type: ControllerType
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65535)
    use_ssl: bool = True
    verify_ssl: bool = False


class ControllerCreate(ControllerBase):
    """Controller creation schema."""

    site_id: UUID
    # Local-mode credentials. Caps match the credentials endpoint
    # baseline (username ≤512, password ≤16384 covers PEM-key-shaped
    # secrets used by some vendors).
    username: str | None = Field(None, max_length=512)
    password: str | None = Field(None, max_length=16384)
    config: dict[str, Any] = Field(default_factory=dict)
    sync_enabled: bool = True
    sync_interval_seconds: int = Field(default=300, ge=60, le=86400)

    # Site mappings: {omada_site_id: freesdn_site_uuid}
    site_mappings: dict[str, str] = Field(
        default_factory=dict,
        description="Map controller-side site IDs to FreeSdn site UUIDs",
    )

    @field_validator("config")
    @classmethod
    def _cap_config(cls, v: dict[str, Any]) -> dict[str, Any]:
        return _validate_controller_config(v) or {}

    @field_validator("site_mappings")
    @classmethod
    def _cap_mappings(cls, v: dict[str, str]) -> dict[str, str]:
        return _validate_site_mappings(v) or {}

    # Cloud mode fields (Omada Cloud / OpenAPI)
    connection_mode: str = Field(default="local", description="Connection mode: 'local' or 'cloud'")
    client_id: str | None = Field(None, description="OAuth2 client ID for cloud mode")
    client_secret: str | None = Field(None, description="OAuth2 client secret for cloud mode")
    omada_id: str | None = Field(None, description="Omada controller ID (omadacId) for cloud mode")
    cloud_region: str | None = Field(None, description="Cloud region: use1, euw1, aps1")

    @model_validator(mode="after")
    def validate_mode_fields(self) -> "ControllerCreate":
        """Validate required fields based on connection mode."""
        if self.connection_mode == "cloud":
            missing = []
            if not self.client_id:
                missing.append("client_id")
            if not self.client_secret:
                missing.append("client_secret")
            if not self.omada_id:
                missing.append("omada_id")
            if not self.cloud_region:
                missing.append("cloud_region")
            if missing:
                raise ValueError(f"Cloud mode requires: {', '.join(missing)}")
            # Auto-populate host for cloud mode if not provided
            if not self.host or self.host == "cloud":
                region = self.cloud_region or "use1"
                self.host = f"{region}-omada-northbound.tplinkcloud.com"
        elif self.controller_type == "proxmox":
            # Proxmox supports API token auth (token_id + token_secret in config)
            # OR username/password — at least one auth method required
            has_token = bool(self.config.get("token_id")) and bool(self.config.get("token_secret"))
            has_credentials = bool(self.username) and bool(self.password)
            if not has_token and not has_credentials:
                raise ValueError(
                    "Proxmox requires either API token (token_id + token_secret) "
                    "or username + password"
                )
        else:
            # Local mode requires username/password
            if not self.username:
                raise ValueError("Local mode requires username")
            if not self.password:
                raise ValueError("Local mode requires password")
        return self


class ControllerUpdate(BaseSchema):
    """Controller update schema."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    # ``host`` was unbounded on PATCH (only POST capped it) — could
    # bypass the schema-layer DoS guard. Mirrored from ``ControllerBase``.
    host: str | None = Field(None, min_length=1, max_length=255)
    port: int | None = Field(None, ge=1, le=65535)
    use_ssl: bool | None = None
    verify_ssl: bool | None = None
    sync_enabled: bool | None = None
    sync_interval_seconds: int | None = Field(None, ge=60, le=86400)
    is_active: bool | None = None
    # Local-mode credentials — previously absent from the update
    # schema, which meant the only way to rotate a leaked controller
    # password was to delete + re-create the controller (losing all
    # device-binding history). The endpoint persists these to the
    # JSONB ``config`` column with encryption.
    username: str | None = Field(None, max_length=512)
    password: str | None = Field(None, max_length=16384)

    # Site mappings
    site_mappings: dict[str, str] | None = Field(
        None,
        description="Map controller-side site IDs to FreeSdn site UUIDs",
    )

    @field_validator("site_mappings")
    @classmethod
    def _cap_mappings(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        return _validate_site_mappings(v)

    # Cloud mode updatable fields
    connection_mode: str | None = Field(None, pattern=r"^(local|cloud)$")
    client_id: str | None = Field(None, max_length=255)
    client_secret: str | None = Field(None, max_length=500)
    omada_id: str | None = Field(None, max_length=255)
    cloud_region: str | None = Field(None, max_length=50)


class ControllerProbe(BaseSchema):
    """Schema for probe-remote-sites and test-connection endpoints."""

    controller_type: str | None = Field(None, max_length=50)
    adapter_id: str | None = Field(None, max_length=50)
    host: str = Field("", max_length=255)
    port: int = Field(443, ge=1, le=65535)
    username: str = Field("", max_length=255)
    password: str = Field("", max_length=500)
    use_ssl: bool = True
    verify_ssl: bool = False
    connection_mode: str = Field("local", pattern=r"^(local|cloud)$")
    # Cloud mode fields
    client_id: str | None = Field(None, max_length=255)
    client_secret: str | None = Field(None, max_length=500)
    omada_id: str | None = Field(None, max_length=255)
    cloud_region: str | None = Field(None, max_length=50)
    # Proxmox API token fields
    token_id: str | None = Field(
        None, max_length=255, description="Proxmox API token ID (e.g. user@pam!tokenname)"
    )
    token_secret: str | None = Field(None, max_length=500, description="Proxmox API token secret")
    realm: str | None = Field(
        None, max_length=50, description="Proxmox auth realm (pam, pve, ldap, ad)"
    )


class ControllerResponse(ControllerBase, TimestampSchema):
    """Controller response schema."""

    id: UUID
    site_id: UUID
    status: ControllerStatus
    last_sync: datetime | None
    last_error: str | None
    config: dict[str, Any]
    sync_enabled: bool
    sync_interval_seconds: int
    is_active: bool
    connection_mode: str = "local"
    site_mappings: dict[str, str] = Field(default_factory=dict)
    device_count: int = 0
    online_device_count: int = 0

    _SENSITIVE_CONFIG_KEYS = frozenset(
        {
            "password",
            "secret",
            "client_secret",
            "api_key",
            "token",
            "private_key",
            "credential",
            "auth_token",
        }
    )

    @model_validator(mode="after")
    def _redact_config_secrets(self) -> "ControllerResponse":
        """Strip sensitive credential values from config before serialization."""
        if self.config:
            redacted = {}
            for k, v in self.config.items():
                if any(s in k.lower() for s in self._SENSITIVE_CONFIG_KEYS):
                    redacted[k] = "***REDACTED***" if v else v
                else:
                    redacted[k] = v
            self.config = redacted
        return self


class ControllerWithStats(ControllerResponse):
    """Controller with statistics (alias kept for backward compat)."""

    pass


# ===========================================
# Pagination Schemas
# ===========================================


class PaginationParams(BaseSchema):
    """Pagination query parameters."""

    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page


class PaginatedResponse[T](BaseSchema):
    """Paginated response wrapper."""

    items: list[T]
    total: int
    page: int
    per_page: int
    pages: int

    @classmethod
    def create(
        cls,
        items: list[T],
        total: int,
        page: int,
        per_page: int,
    ) -> "PaginatedResponse[T]":
        pages = (total + per_page - 1) // per_page
        return cls(
            items=items,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages,
        )


# Update forward references
UserWithOrg.model_rebuild()

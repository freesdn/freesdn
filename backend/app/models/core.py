# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Core Domain Models
================================

User, Organization, Site, and Controller models.
These form the foundation of the multi-tenant architecture.
"""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.devices import Device
    from app.models.enterprise import SiteGroup
    from app.models.sso import SSOProvider
    from app.modules.models import OrganizationModule


class CredentialType(StrEnum):
    """Credential authentication type."""

    BASIC_AUTH = "basic_auth"
    USERNAME_PASSWORD = "username_password"
    API_KEY = "api_key"
    TOKEN = "token"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    SNMP_COMMUNITY = "snmp_community"


class CredentialScope(StrEnum):
    """Credential applicability scope."""

    GLOBAL = "global"
    VENDOR = "vendor"
    SITE = "site"
    DEVICE = "device"


class UserRole(StrEnum):
    """User role enumeration."""

    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin"
    SITE_ADMIN = "site_admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class ControllerType(StrEnum):
    """Controller type enumeration."""

    OMADA = "omada"
    UNIFI = "unifi"
    MERAKI = "meraki"
    OPNSENSE = "opnsense"
    PFSENSE = "pfsense"
    MIKROTIK = "mikrotik"
    OPENWRT = "openwrt"
    HIKVISION = "hikvision"
    AXIS = "axis"
    FREEPBX = "freepbx"
    GRANDSTREAM = "grandstream"
    PROXMOX = "proxmox"
    TRUENAS = "truenas"
    GENERIC_ONVIF = "generic_onvif"
    GENERIC_SNMP = "generic_snmp"


class ControllerStatus(StrEnum):
    """Controller connection status."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    SYNCING = "syncing"
    UNKNOWN = "unknown"
    UNREACHABLE = "unreachable"


# ===========================================
# Organization Model
# ===========================================


class Organization(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Organization - Top-level tenant in the system.

    Organizations contain sites and users.
    """

    __tablename__ = "organizations"
    __table_args__ = (
        # Partial unique: a slug is unique only among LIVE orgs, so it can be
        # reused after its org is soft-deleted (mirrors uq_devices_mac_alive).
        Index(
            "ix_organizations_slug",
            "slug",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        {"schema": "core"},
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Uniqueness enforced by the partial index above (live rows only).
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Contact Info
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    contact_phone: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Settings
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    sites: Mapped[list["Site"]] = relationship(
        "Site",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    users: Mapped[list["User"]] = relationship(
        "User",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    modules: Mapped[list["OrganizationModule"]] = relationship(
        "OrganizationModule",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    sso_providers: Mapped[list["SSOProvider"]] = relationship(  # noqa: F821
        "SSOProvider",
        back_populates="organization",
        cascade="all, delete-orphan",
    )


# ===========================================
# Site Model
# ===========================================


class Site(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Site - Physical or logical location within an organization.

    Sites contain controllers and devices.
    """

    __tablename__ = "sites"
    __table_args__ = (
        Index("ix_sites_organization_id", "organization_id"),
        # Partial-unique (deleted_at IS NULL) so a slug frees up after a Site is
        # soft-deleted — matching Organization.slug / User.email / Device.external_id.
        # Without this, a soft-deleted Site permanently blocks reusing its slug.
        Index(
            "ix_sites_slug",
            "organization_id",
            "slug",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        {"schema": "core"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Location
    address: Mapped[str | None] = mapped_column(Text, nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    country: Mapped[str | None] = mapped_column(String(100), nullable=True)
    timezone: Mapped[str] = mapped_column(String(50), default="UTC", nullable=False)

    # Time/Date Format Settings
    time_format: Mapped[str] = mapped_column(
        String(10), default="24h", nullable=False
    )  # "12h" or "24h"
    date_format: Mapped[str] = mapped_column(
        String(20), default="YYYY-MM-DD", nullable=False
    )  # ISO format

    # Site Group (for template inheritance hierarchy)
    site_group_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.site_groups.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Network Topology
    subnets: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
    )  # [{"cidr": "192.168.1.0/24", "name": "Management", "vlan_id": 1}, ...]
    gateway_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Settings
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="sites",
    )
    site_group: Mapped["SiteGroup | None"] = relationship(
        "SiteGroup",
        back_populates="sites",
        foreign_keys=[site_group_id],
    )
    controllers: Mapped[list["Controller"]] = relationship(
        "Controller",
        back_populates="site",
        cascade="all, delete-orphan",
    )
    devices: Mapped[list["Device"]] = relationship(
        "Device",
        back_populates="site",
        cascade="all, delete-orphan",
    )


# ===========================================
# Controller Model
# ===========================================


class Controller(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Controller - External system that manages devices.

    Examples: Omada Controller, UniFi Controller, HikVision NVR.
    """

    __tablename__ = "controllers"
    __table_args__ = (
        Index("ix_controllers_site_id", "site_id"),
        Index("ix_controllers_type", "controller_type"),
        {"schema": "core"},
    )

    # Foreign Keys
    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Basic Info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    controller_type: Mapped[ControllerType] = mapped_column(String(50), nullable=False)

    # Connection Details
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(nullable=False)
    use_ssl: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Credentials (encrypted reference - actual credentials in vault)
    credential_id: Mapped[UUID | None] = mapped_column(nullable=True)

    # Status
    status: Mapped[ControllerStatus] = mapped_column(
        String(20),
        default=ControllerStatus.UNKNOWN,
        nullable=False,
    )
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Configuration
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Auto-sync settings
    sync_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sync_interval_seconds: Mapped[int] = mapped_column(default=300, nullable=False)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    site: Mapped["Site"] = relationship(
        "Site",
        back_populates="controllers",
    )
    devices: Mapped[list["Device"]] = relationship(
        "Device",
        back_populates="controller",
        cascade="all, delete-orphan",
    )

    # Convenience properties for backward compatibility with task code
    @property
    def type(self) -> str:
        """Alias for controller_type."""
        return self.controller_type

    @property
    def is_enabled(self) -> bool:
        """Alias for is_active."""
        return self.is_active

    @property
    def username(self) -> str | None:
        """Get username from config JSONB."""
        return self.config.get("username") if self.config else None

    @property
    def password(self) -> str | None:
        """Get password from config JSONB (auto-decrypts if encrypted)."""
        raw = self.config.get("password") if self.config else None
        if raw:
            from app.core.crypto import decrypt_credential, is_encrypted

            if is_encrypted(raw):
                return decrypt_credential(raw)
        return raw

    @property
    def connection_mode(self) -> str:
        """Get connection mode from config JSONB (local or cloud)."""
        return self.config.get("connection_mode", "local") if self.config else "local"

    @property
    def client_id(self) -> str | None:
        """Get OAuth2 client ID for cloud mode."""
        return self.config.get("client_id") if self.config else None

    @property
    def client_secret(self) -> str | None:
        """Get OAuth2 client secret for cloud mode (auto-decrypts if encrypted)."""
        raw = self.config.get("client_secret") if self.config else None
        if raw:
            from app.core.crypto import decrypt_credential, is_encrypted

            if is_encrypted(raw):
                return decrypt_credential(raw)
        return raw

    @property
    def omada_id(self) -> str | None:
        """Get Omada controller ID for cloud mode."""
        return self.config.get("omada_id") if self.config else None

    @property
    def cloud_region(self) -> str | None:
        """Get cloud region for cloud mode."""
        return self.config.get("cloud_region") if self.config else None

    @property
    def site_mappings(self) -> dict[str, str]:
        """Get Omada-site-ID → FreeSdn-site-UUID mappings from config JSONB."""
        return self.config.get("site_mappings", {}) if self.config else {}

    @site_mappings.setter
    def site_mappings(self, value: dict[str, str]) -> None:
        """Set site mappings in config JSONB."""
        if self.config is None:
            self.config = {}
        updated = {**self.config, "site_mappings": value}
        self.config = updated


# ===========================================
# User Model
# ===========================================


class User(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    User - System user account.

    Users belong to an organization and have role-based permissions.
    """

    __tablename__ = "users"
    __table_args__ = (
        # Partial unique: email/username are unique only among LIVE users, so the
        # identifiers can be re-onboarded after a user is soft-deleted.
        Index("ix_users_email", "email", unique=True, postgresql_where=text("deleted_at IS NULL")),
        Index(
            "ix_users_username",
            "username",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_users_organization_id", "organization_id"),
        {"schema": "core"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=True,  # Null for super admins
    )

    # Basic Info — uniqueness enforced by the partial indexes above (live rows only).
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Authentication
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    # Role & Permissions
    role: Mapped[UserRole] = mapped_column(
        String(20),
        default=UserRole.VIEWER,
        nullable=False,
    )

    # MFA
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mfa_backup_codes: Mapped[str | None] = mapped_column(Text, nullable=True)  # encrypted JSON list
    # a TOTP secret generated by /mfa/setup but not yet confirmed
    # lives here (staged), so an abandoned re-enroll never clobbers the live
    # secret on an already-enabled account. Promoted to mfa_secret on enable.
    mfa_pending_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mfa_pending_backup_codes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # most-recently-consumed TOTP timestep — blocks same-window
    # replay of an observed code (RFC 6238 §5.2).
    mfa_last_totp_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Login tracking
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Session versioning – incremented on logout-all / password change / password reset.
    # Tokens minted with an older version are rejected, providing instant global revocation.
    token_version: Mapped[int] = mapped_column(default=0, nullable=False, server_default="0")

    # Language/Locale Preferences
    language: Mapped[str] = mapped_column(
        String(10), default="en", nullable=False
    )  # ISO language code

    # SSO / External Auth
    auth_provider: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )  # "local", "oidc", "saml", "ldap" – NULL means local
    external_id: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )  # Subject / DN from external IdP
    sso_provider_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sso_providers.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Preferences
    preferences: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Relationships
    organization: Mapped["Organization | None"] = relationship(
        "Organization",
        back_populates="users",
    )
    sessions: Mapped[list["UserSession"]] = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    site_access: Mapped[list["UserSiteAccess"]] = relationship(
        "UserSiteAccess",
        back_populates="user",
        cascade="all, delete-orphan",
    )


# ===========================================
# User ↔ Site Access (junction table)
# ===========================================


class UserSiteAccess(Base, UUIDMixin, AuditMixin):
    """
    Junction table granting a user access to specific sites.

    When no rows exist for a user, behaviour depends on their role:
      • super_admin / org_admin → implicit access to every site in their org.
      • site_admin / operator / viewer → NO site access (deny-by-default).

    ``access_level`` lets you further restrict what the user can do inside
    the site without changing their global role:
      • "admin"   – full CRUD within the site
      • "write"   – read + limited create/update
      • "read"    – read-only
    Default is ``None`` which inherits the user's global role permissions.
    """

    __tablename__ = "user_site_access"
    __table_args__ = (
        Index(
            "ix_user_site_access_user_site",
            "user_id",
            "site_id",
            unique=True,
        ),
        Index("ix_user_site_access_site_id", "site_id"),
        {"schema": "core"},
    )

    # Foreign Keys
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Optional fine-grained access level within the site
    access_level: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )  # "admin", "write", "read" – or NULL = inherit from role

    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="site_access",
    )
    site: Mapped["Site"] = relationship("Site")


# ===========================================
# User Session Model
# ===========================================


class UserSession(Base, UUIDMixin):
    """
    UserSession - Per-device authenticated session.

    One row per "place the user is signed in from" (a browser, a phone
    app, etc.). Keyed on the refresh-token JTI so token rotation can
    update the row in place without leaving zombie sessions behind.

    Per-device revocation:
      • ``/auth/logout``               → set ``revoked_at`` for THIS session
      • ``/auth/logout-all``           → revoke all sessions AND bump
                                         ``User.token_version`` (legacy
                                         "kill everything" behaviour)
      • ``/auth/sessions/{id}`` DELETE → admin-style revoke a specific one

    The auth dependency checks ``access_jti`` on every authenticated
    request — a revoked session immediately stops authorising calls even
    though the access-token JWT is still otherwise valid.
    """

    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("ix_user_sessions_user_id", "user_id"),
        Index("ix_user_sessions_refresh_token", "refresh_token_hash"),
        Index("ix_user_sessions_refresh_jti", "refresh_jti", unique=True),
        Index("ix_user_sessions_access_jti", "access_jti"),
        {"schema": "core"},
    )

    # Foreign Keys
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Session Info
    # Legacy: refresh-token hash stored from previous schema. Kept for
    # backward compatibility — new code keys off ``refresh_jti``.
    refresh_token_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Refresh-token JTI — used to look up + rotate this specific session.
    refresh_jti: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Access-token JTI currently bound to this session. Replaced on every
    # refresh, used by the auth dependency to detect revocation faster.
    access_jti: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Device Info
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Timestamps. All TIMESTAMPTZ to match the timezone-aware datetimes
    # the auth service emits (utcnow with tzinfo). Without timezone=True,
    # SQLAlchemy emits "TIMESTAMP WITHOUT TIME ZONE" casts client-side,
    # which asyncpg rejects when given an aware datetime. Verified via
    # live login attempt: would 500 with "can't subtract offset-naive
    # and offset-aware datetimes".
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Per-device revoke timestamp. NULL == active.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Status (legacy mirror of revoked_at — kept so existing maintenance
    # task that queries ``is_revoked`` keeps working).
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="sessions",
    )


# ===========================================
# Credential Model
# ===========================================


class Credential(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Credential - Stored credentials for device/controller authentication.

    Credentials are reusable and can be scoped to a vendor, site, or device.
    Passwords and secrets are stored encrypted (via Fernet in production).
    """

    __tablename__ = "credentials"
    __table_args__ = (
        Index("ix_credentials_organization_id", "organization_id"),
        Index("ix_credentials_credential_type", "credential_type"),
        Index("ix_credentials_scope", "scope"),
        {"schema": "core"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.sites.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Identity
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Type & Scope
    credential_type: Mapped[CredentialType] = mapped_column(String(30), nullable=False)
    scope: Mapped[CredentialScope] = mapped_column(
        String(20),
        default=CredentialScope.GLOBAL,
        nullable=False,
    )
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Auth data (encrypted in production)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    encrypted_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    token: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssh_private_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    certificate: Mapped[str | None] = mapped_column(Text, nullable=True)

    # SNMP
    snmp_community: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Extended options
    options: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Status
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_test_result: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )  # success, failed

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization")
    site: Mapped["Site | None"] = relationship("Site")

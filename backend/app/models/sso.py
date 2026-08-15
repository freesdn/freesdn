# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SSO / Identity Provider Models
===============================================

Models for OIDC, SAML 2.0, and LDAP identity provider configurations.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Organization


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SSOProtocol(enum.StrEnum):
    """Supported SSO protocols."""

    OIDC = "oidc"
    SAML = "saml"
    LDAP = "ldap"


class SSOProviderStatus(enum.StrEnum):
    """SSO provider lifecycle status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    TESTING = "testing"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SSOProvider(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    Organisation-scoped identity-provider configuration.

    Stores connection parameters for OIDC, SAML 2.0, and LDAP providers.
    Each organisation may have multiple providers (e.g. Azure AD + LDAP).
    """

    __tablename__ = "sso_providers"
    __table_args__ = (
        Index("ix_sso_providers_org_id", "organization_id"),
        Index("ix_sso_providers_protocol", "protocol"),
        Index("ix_sso_providers_slug", "slug", unique=True),
        {"schema": "core"},
    )

    # Foreign keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Descriptive
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    protocol: Mapped[SSOProtocol] = mapped_column(
        SAEnum(SSOProtocol, name="sso_protocol", create_constraint=False),
        nullable=False,
    )
    status: Mapped[SSOProviderStatus] = mapped_column(
        SAEnum(SSOProviderStatus, name="sso_provider_status", create_constraint=False),
        default=SSOProviderStatus.INACTIVE,
        nullable=False,
    )

    # Display / UX
    icon_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    display_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # === OIDC Settings ===
    oidc_issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    oidc_client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    oidc_client_secret: Mapped[str | None] = mapped_column(String(512), nullable=True)
    oidc_scopes: Mapped[str | None] = mapped_column(
        String(500), default="openid profile email", nullable=True
    )
    oidc_discovery_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # === SAML Settings ===
    saml_entity_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    saml_sso_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    saml_slo_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    saml_certificate: Mapped[str | None] = mapped_column(Text, nullable=True)
    saml_signing_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    saml_name_id_format: Mapped[str | None] = mapped_column(
        String(255),
        default="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        nullable=True,
    )

    # === LDAP Settings ===
    ldap_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ldap_bind_dn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ldap_bind_password: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ldap_base_dn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ldap_user_search_filter: Mapped[str | None] = mapped_column(
        String(512),
        default="(&(objectClass=user)(sAMAccountName={username}))",
        nullable=True,
    )
    ldap_group_search_filter: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ldap_use_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ldap_tls_ca_cert: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Attribute mapping  – maps IdP claims / attributes → FreeSDN user fields
    attribute_mapping: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=lambda: {
            "email": "email",
            "username": "preferred_username",
            "full_name": "name",
        },
        nullable=False,
    )

    # Role mapping  – maps IdP groups / roles → FreeSDN UserRole
    role_mapping: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    # JIT Provisioning
    jit_provisioning: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    default_role: Mapped[str] = mapped_column(String(20), default="viewer", nullable=False)

    # Extra settings (future-proof)
    extra_settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Relationships
    organization: Mapped[Organization] = relationship(  # noqa: F821
        back_populates="sso_providers", lazy="selectin"
    )
    sessions: Mapped[list[SSOSession]] = relationship(
        back_populates="provider", cascade="all, delete-orphan", lazy="noload"
    )


class SSOSession(Base, UUIDMixin):
    """
    Tracks individual SSO authentication exchanges.

    Used for SAML relay-state correlation, OIDC state/nonce validation,
    and post-logout back-channel callbacks.
    """

    __tablename__ = "sso_sessions"
    __table_args__ = (
        Index("ix_sso_sessions_state", "state", unique=True),
        Index("ix_sso_sessions_user_id", "user_id"),
        {"schema": "core"},
    )

    provider_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sso_providers.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # OIDC state + nonce / SAML relay state
    state: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    nonce: Mapped[str | None] = mapped_column(String(255), nullable=True)
    redirect_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # External IdP subject identifier
    external_id: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default="now()",
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Raw IdP response for audit
    idp_response: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Relationships
    provider: Mapped[SSOProvider] = relationship(back_populates="sessions")

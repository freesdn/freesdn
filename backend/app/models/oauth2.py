# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - OAuth2 Models
============================

SQLAlchemy models for OAuth2 Authorization Server:
- OAuth2App    : Registered third-party application
- OAuth2AuthorizationCode : Short-lived PKCE authorization code
- OAuth2Token  : Issued access / refresh token pair
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin


class OAuth2App(Base, UUIDMixin, AuditMixin):
    """
    A registered OAuth2 client application.

    Third-party developers register their app to receive a client_id
    and client_secret and to declare their allowed redirect URIs and
    requested scopes.
    """

    __tablename__ = "oauth2_apps"
    __table_args__ = (
        Index("ix_oauth2_apps_client_id", "client_id"),
        Index("ix_oauth2_apps_user_id", "user_id"),
        {"schema": "core"},
    )

    # Owner
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL"),
        nullable=True,
    )

    # App identity
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Credentials
    client_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    client_secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    client_secret_prefix: Mapped[str] = mapped_column(String(12), nullable=False)

    # OAuth2 configuration
    redirect_uris: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    grant_types: Mapped[list[str]] = mapped_column(
        JSONB,
        default=lambda: ["authorization_code", "refresh_token"],
        nullable=False,
    )

    # Status & type
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_confidential: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Branding (optional)
    logo_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    homepage_url: Mapped[str | None] = mapped_column(String(512), nullable=True)


class OAuth2AuthorizationCode(Base, UUIDMixin):
    """
    Short-lived authorization code issued after user consent.

    Exchanged for an access token via POST /oauth2/token.
    Supports PKCE (Proof Key for Code Exchange) via code_challenge.
    """

    __tablename__ = "oauth2_authorization_codes"
    __table_args__ = (
        Index("ix_oauth2_codes_code", "code"),
        Index("ix_oauth2_codes_app_user", "app_id", "user_id"),
        {"schema": "core"},
    )

    code: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    app_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.oauth2_apps.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    redirect_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)

    # PKCE fields (RFC 7636)
    code_challenge: Mapped[str | None] = mapped_column(String(128), nullable=True)
    code_challenge_method: Mapped[str | None] = mapped_column(String(10), nullable=True)  # "S256"

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class OAuth2Token(Base, UUIDMixin):
    """
    Issued OAuth2 access/refresh token pair.

    Access tokens expire quickly (1 hour default).
    Refresh tokens last longer (30 days default).
    Neither value is stored — only SHA-256 hashes.
    """

    __tablename__ = "oauth2_tokens"
    __table_args__ = (
        Index("ix_oauth2_tokens_access", "access_token_hash"),
        Index("ix_oauth2_tokens_refresh", "refresh_token_hash"),
        Index("ix_oauth2_tokens_app_user", "app_id", "user_id"),
        {"schema": "core"},
    )

    app_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.oauth2_apps.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.users.id", ondelete="CASCADE"),
        nullable=False,
    )

    access_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    refresh_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # OAuth2 token_version binding.
    # Snapshot of User.token_version at the time this token was minted.
    # If current user.token_version differs, the token is considered revoked
    # (matches how first-party JWT sessions are invalidated by password
    # reset / "logout everywhere").
    user_token_version_at_issue: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

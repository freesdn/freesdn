# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Plugin Marketplace Models
=========================================

Database models for the plugin marketplace catalog: plugins, versions, reviews.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin


class MarketplacePlugin(Base, UUIDMixin, AuditMixin):
    """A plugin listed in the FreeSDN marketplace catalog."""

    __tablename__ = "marketplace_plugins"
    __table_args__ = ({"schema": "core"},)

    plugin_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    short_description: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)  # Markdown

    author_name: Mapped[str] = mapped_column(String(200))
    author_url: Mapped[str | None] = mapped_column(String(512))

    category: Mapped[str] = mapped_column(String(50), index=True)
    # Categories: monitoring | security | automation | integration | analytics | device | reporting

    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    latest_version: Mapped[str] = mapped_column(String(20))
    min_core_version: Mapped[str] = mapped_column(String(20))

    icon_url: Mapped[str | None] = mapped_column(String(512))
    banner_url: Mapped[str | None] = mapped_column(String(512))
    screenshots: Mapped[list[str]] = mapped_column(JSONB, default=list)

    download_url: Mapped[str] = mapped_column(String(512))
    checksum_sha256: Mapped[str] = mapped_column(String(64))
    package_size: Mapped[int | None] = mapped_column(Integer)

    download_count: Mapped[int] = mapped_column(Integer, default=0)
    rating: Mapped[float] = mapped_column(Float, default=0.0)
    rating_count: Mapped[int] = mapped_column(Integer, default=0)

    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_featured: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="published")
    # Status: draft | published | suspended | deprecated

    def __repr__(self) -> str:
        return f"<MarketplacePlugin {self.slug}@{self.latest_version}>"


class MarketplacePluginVersion(Base, UUIDMixin):
    """A specific version of a marketplace plugin."""

    __tablename__ = "marketplace_plugin_versions"
    __table_args__ = ({"schema": "core"},)

    marketplace_plugin_id: Mapped[UUID] = mapped_column(index=True)
    version: Mapped[str] = mapped_column(String(20))
    changelog: Mapped[str | None] = mapped_column(Text)
    download_url: Mapped[str] = mapped_column(String(512))
    checksum_sha256: Mapped[str] = mapped_column(String(64))
    min_core_version: Mapped[str] = mapped_column(String(20))
    released_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<MarketplacePluginVersion {self.marketplace_plugin_id}@{self.version}>"


class PluginReview(Base, UUIDMixin, AuditMixin):
    """User review of a marketplace plugin."""

    __tablename__ = "plugin_reviews"
    # One review per user per plugin. This is the authoritative guard the
    # create-review endpoint relies on: its IntegrityError->409 arm only fires
    # when this DB constraint catches the loser of a concurrent insert (the
    # best-effort SELECT pre-check races on its own). Built from ORM metadata by
    # both alembic 001_initial (create_all) and the dev/test create_all path.
    __table_args__ = (
        UniqueConstraint("marketplace_plugin_id", "user_id", name="uq_plugin_review_user_plugin"),
        {"schema": "core"},
    )

    marketplace_plugin_id: Mapped[UUID] = mapped_column(index=True)
    user_id: Mapped[UUID] = mapped_column(index=True)
    rating: Mapped[int] = mapped_column(Integer)  # 1-5 stars
    title: Mapped[str | None] = mapped_column(String(200))
    body: Mapped[str | None] = mapped_column(Text)

    def __repr__(self) -> str:
        return f"<PluginReview {self.marketplace_plugin_id} by {self.user_id}>"

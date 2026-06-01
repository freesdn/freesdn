# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Plugin System Models
====================================

Database models for installed plugins and per-org plugin settings/state.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin


class InstalledPlugin(Base, UUIDMixin, AuditMixin):
    """Tracks plugins that have been installed on this FreeSDN instance."""

    __tablename__ = "installed_plugins"
    __table_args__ = ({"schema": "core"},)

    plugin_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(20))
    description: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(200))
    license: Mapped[str | None] = mapped_column(String(50))
    homepage: Mapped[str | None] = mapped_column(String(512))

    installed_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"), nullable=True
    )
    installed_from: Mapped[str | None] = mapped_column(String(512))
    plugin_dir: Mapped[str] = mapped_column(String(512))

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(20), default="installed")
    # Status: "installed" | "disabled" | "error" | "uninstalled"

    # Cached copy of the parsed plugin.yaml for offline display
    manifest_cache: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    def __repr__(self) -> str:
        return f"<InstalledPlugin {self.plugin_id}@{self.version}>"


class PluginSetting(Base, UUIDMixin):
    """Per-organisation key/value settings for a plugin."""

    __tablename__ = "plugin_settings"
    __table_args__ = (
        Index(
            "ix_plugin_settings_lookup",
            "plugin_id",
            "organization_id",
            "key",
            unique=True,
        ),
        {"schema": "core"},
    )

    plugin_id: Mapped[str] = mapped_column(String(100), index=True)
    organization_id: Mapped[UUID] = mapped_column(index=True)
    key: Mapped[str] = mapped_column(String(200))
    value: Mapped[Any] = mapped_column(JSONB)

    def __repr__(self) -> str:
        return f"<PluginSetting {self.plugin_id}/{self.key}>"


class PluginOrganizationState(Base, UUIDMixin, AuditMixin):
    """Organization-scoped plugin activation overrides.

    Rows are optional. Absence means "inherit the globally installed plugin
    state". A row with ``is_enabled=False`` disables the plugin for that
    organization without affecting other organizations or the global install.
    """

    __tablename__ = "plugin_organization_states"
    __table_args__ = (
        Index(
            "ix_plugin_org_states_lookup",
            "plugin_id",
            "organization_id",
            unique=True,
        ),
        {"schema": "core"},
    )

    plugin_id: Mapped[str] = mapped_column(String(100), index=True)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        index=True,
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    def __repr__(self) -> str:
        return (
            f"<PluginOrganizationState {self.plugin_id}/{self.organization_id} "
            f"enabled={self.is_enabled}>"
        )

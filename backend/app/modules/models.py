# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Module Database Models
====================================

Database models for storing module state and settings.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import AuditMixin, Base, UUIDMixin

if TYPE_CHECKING:
    from app.models.core import Organization


class OrganizationModule(Base, UUIDMixin, AuditMixin):
    """
    Tracks which modules are enabled for each organization.

    This is the source of truth for module enablement.
    The module registry caches this data in memory.
    """

    __tablename__ = "organization_modules"
    __table_args__ = (
        UniqueConstraint("organization_id", "module_id", name="uq_org_module"),
        Index("ix_org_modules_org_id", "organization_id"),
        Index("ix_org_modules_module_id", "module_id"),
        {"schema": "core"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Module identification
    module_id: Mapped[str] = mapped_column(String(100), nullable=False)

    # State
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Settings (module-specific configuration)
    settings: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Relationships
    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="modules",
    )

    def __repr__(self) -> str:
        return f"<OrganizationModule(org={self.organization_id}, module={self.module_id}, enabled={self.is_enabled})>"


class ModuleEvent(Base, UUIDMixin):
    """
    Audit log for module-related events.

    Tracks:
    - Module enabled/disabled
    - Settings changes
    - Errors
    """

    __tablename__ = "module_events"
    __table_args__ = (
        Index("ix_module_events_org_id", "organization_id"),
        Index("ix_module_events_module_id", "module_id"),
        Index("ix_module_events_timestamp", "timestamp"),
        {"schema": "core"},
    )

    # Context
    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    module_id: Mapped[str] = mapped_column(String(100), nullable=False)

    # Event details
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Event types: enabled, disabled, settings_changed, error, loaded, unloaded

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Actor
    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Details
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class ModuleFeatureFlag(Base, UUIDMixin, AuditMixin):
    """
    Feature flags for modules.

    Allows granular control over module features per organization.
    """

    __tablename__ = "module_feature_flags"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "module_id", "feature_key", name="uq_org_module_feature"
        ),
        Index("ix_feature_flags_org_module", "organization_id", "module_id"),
        {"schema": "core"},
    )

    # Foreign Keys
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Feature identification
    module_id: Mapped[str] = mapped_column(String(100), nullable=False)
    feature_key: Mapped[str] = mapped_column(String(100), nullable=False)

    # State
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Optional value (for non-boolean flags)
    value: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

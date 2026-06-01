# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Custom Role Model
===============================

Org-scoped, DB-backed custom RBAC roles. These augment the built-in system
roles (defined in ``app.core.dependencies.ROLE_HIERARCHY`` /
``DEFAULT_ROLE_PERMISSIONS``): an organization can define additional named
permission bundles without code changes.

System roles remain code-defined (``is_system`` rows are synthesized in the
roles endpoint, never stored here). Only custom roles live in this table.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, SoftDeleteMixin, UUIDMixin


class CustomRole(Base, UUIDMixin, AuditMixin, SoftDeleteMixin):
    """
    A custom, organization-scoped RBAC role.

    Uniquely identified within an org by ``slug``. The ``permissions`` JSONB
    column holds the same permission vocabulary used by the built-in roles
    (e.g. ``"device:read"``, ``"network:*"``).
    """

    __tablename__ = "custom_roles"
    __table_args__ = (
        # A slug is unique per org (ignoring soft-deleted rows).
        Index(
            "uq_custom_roles_org_slug",
            "organization_id",
            "slug",
            unique=True,
            postgresql_where="deleted_at IS NULL",
        ),
        Index("ix_custom_roles_org", "organization_id"),
        {"schema": "core"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Identity
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Permission bundle (same vocabulary as DEFAULT_ROLE_PERMISSIONS)
    permissions: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)

    # Privilege level (mirrors ROLE_HIERARCHY semantics; UI clamps 1-100).
    level: Mapped[int] = mapped_column(Integer, default=50, nullable=False)

    # Whether this is the org's default role for new users.
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Always False for stored rows — system roles are code-defined and never
    # persisted. Kept for response-shape parity with the system-role rows.
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "name": self.name,
            "slug": self.slug,
            "description": self.description or "",
            "permissions": list(self.permissions or []),
            "level": self.level,
            "is_system": False,
            "is_default": self.is_default,
        }

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Topology Models
===============================

Extends the network.topology_links with saved layout positions
and computed graph data for the topology map visualization.
"""

from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    Float,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import AuditMixin, Base, UUIDMixin

if TYPE_CHECKING:
    pass


class TopologyLayout(Base, UUIDMixin, AuditMixin):
    """
    Persisted layout positions for topology map visualization.

    Each user can have their own saved layout per site.
    When no user-specific layout exists, the auto-layout engine is used.
    """

    __tablename__ = "topology_layouts"
    __table_args__ = (
        UniqueConstraint("site_id", "user_id", name="uq_topology_layout_site_user"),
        Index("ix_topology_layouts_site", "site_id"),
        {"schema": "network"},
    )

    site_id: Mapped[UUID] = mapped_column(
        ForeignKey("core.sites.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("core.users.id", ondelete="SET NULL"),
        nullable=True,
    )  # NULL = default org-wide layout

    name: Mapped[str] = mapped_column(String(255), nullable=False, default="Default")

    # Positions: { "device_uuid": {"x": 100, "y": 200, "pinned": true}, ... }
    positions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # Viewport state
    zoom: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    center_x: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    center_y: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Filters that were active when layout was saved
    filters: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

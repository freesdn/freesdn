# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Topology Schemas
================================

Pydantic request/response models for:
  - Topology graph data (nodes + edges)
  - Layout persistence
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

# ==========================================================================
# Graph Data
# ==========================================================================


class TopologyNode(BaseModel):
    """A node in the topology graph (device or gateway)."""

    id: UUID
    label: str
    device_type: str
    status: str
    ip_address: str | None = None
    mac_address: str | None = None
    model: str | None = None
    site_id: UUID | None = None
    site_name: str | None = None
    health_score: float | None = None
    health_status: str | None = None
    # Position (from saved layout or auto-computed)
    x: float | None = None
    y: float | None = None
    pinned: bool = False
    # Grouping
    layer: str | None = None  # "core", "distribution", "access", "edge"
    metadata: dict[str, Any] = Field(default_factory=dict)


class TopologyEdge(BaseModel):
    """An edge in the topology graph (link between devices)."""

    id: UUID
    source_id: UUID
    target_id: UUID
    source_port: str | None = None
    target_port: str | None = None
    speed: str | None = None
    status: str
    link_type: str
    discovered_via: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TopologyGraphResponse(BaseModel):
    """Complete topology graph for a site or organization."""

    nodes: list[TopologyNode]
    edges: list[TopologyEdge]
    site_id: UUID | None = None
    generated_at: datetime
    stats: TopologyStats


class TopologyStats(BaseModel):
    total_nodes: int
    total_edges: int
    nodes_by_type: dict[str, int]
    nodes_by_status: dict[str, int]
    links_by_status: dict[str, int]
    orphan_count: int  # Devices with no edges


# ==========================================================================
# Layout Persistence
# ==========================================================================


class LayoutPositionItem(BaseModel):
    x: float
    y: float
    pinned: bool = False


class TopologyLayoutSave(BaseModel):
    """Save layout positions for a topology view."""

    name: str = Field("Default", min_length=1, max_length=255)
    # positions: device_id → position. Capped at 2000 entries — anything
    # over that is almost certainly garbage or an attack; a real site
    # with 2000 devices shouldn't be on one topology view anyway.
    # Previously a 10_000-node payload (~500 KB) was happily 201ed,
    # storing JSONB bloat on every save.
    positions: dict[str, LayoutPositionItem] = Field(..., max_length=2000)
    zoom: float = Field(1.0, ge=0.1, le=10.0)
    # center coordinates aren't strictly bounded by ReactFlow but
    # we cap to a sane viewport range so a typo / attack can't write
    # ``center_x = 1e308`` and break the FE when re-fetched.
    center_x: float = Field(0.0, ge=-100_000, le=100_000)
    center_y: float = Field(0.0, ge=-100_000, le=100_000)
    filters: dict[str, Any] | None = None

    @field_validator("filters")
    @classmethod
    def _filters_size_cap(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return v
        import json as _json

        size = len(_json.dumps(v, default=str).encode("utf-8"))
        if size > 16 * 1024:
            raise ValueError(f"filters exceeds 16384 bytes (got {size})")
        return v


class TopologyLayoutResponse(BaseModel):
    id: UUID
    site_id: UUID
    user_id: UUID | None
    name: str
    positions: dict[str, Any]
    zoom: float
    center_x: float
    center_y: float
    filters: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Topology Service
================================

Builds L2/L3 topology graph from devices and topology links.
Supports layout persistence and auto-layout computation.
"""

import asyncio
import logging
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.core import Site
from app.models.devices import Device
from app.models.enterprise import DeviceHealth
from app.models.topology import TopologyLayout
from app.modules.network.models import TopologyLink

logger = logging.getLogger("freesdn.enterprise.topology")


class TopologyService:
    """Builds topology graph data and manages layout persistence."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Graph Building
    # ------------------------------------------------------------------

    MAX_TOPOLOGY_NODES = 500  # Prevent loading unbounded devices into memory

    async def get_topology_graph(
        self,
        organization_id: UUID,
        site_id: UUID | None = None,
        user_id: UUID | None = None,
        include_health: bool = True,
        accessible_site_ids: set[UUID] | None = None,
    ) -> dict[str, Any]:
        """
        Build a complete topology graph with nodes and edges.

        Capped at MAX_TOPOLOGY_NODES to prevent OOM on large deployments.
        Optionally overlays saved layout positions and health data.
        """
        now = datetime.now(UTC)

        # 1. Load devices (capped to prevent OOM at scale)
        devices_stmt = (
            select(Device)
            .join(Site, Device.site_id == Site.id)
            .where(
                Site.organization_id == organization_id,
                Site.deleted_at.is_(None),
                Device.deleted_at.is_(None),
            )
        )
        if site_id:
            devices_stmt = devices_stmt.where(Device.site_id == site_id)
        # site-limited callers see only granted-site devices.
        if accessible_site_ids is not None:
            devices_stmt = devices_stmt.where(Device.site_id.in_(accessible_site_ids))
        devices_stmt = devices_stmt.limit(self.MAX_TOPOLOGY_NODES)

        devices_result = await self.db.execute(devices_stmt)
        devices = list(devices_result.scalars().all())
        device_ids = {d.id for d in devices}

        # Resolve site names for the loaded devices in a single query (no N+1).
        site_name_map: dict[UUID, str] = {}
        device_site_ids = {d.site_id for d in devices if d.site_id is not None}
        if device_site_ids:
            site_names_result = await self.db.execute(
                select(Site.id, Site.name).where(Site.id.in_(device_site_ids))
            )
            site_name_map = dict(site_names_result.all())

        # 2. Load topology links
        links_stmt = select(TopologyLink).where(
            TopologyLink.source_device_id.in_(device_ids)
            | TopologyLink.target_device_id.in_(device_ids)
        )
        links_result = await self.db.execute(links_stmt)
        links = list(links_result.scalars().all())

        # Filter links to ensure both endpoints belong to org-scoped devices
        device_id_set = device_ids
        links = [
            l
            for l in links
            if l.source_device_id in device_id_set and l.target_device_id in device_id_set
        ]

        # 3. Load health data if requested
        health_map: dict[UUID, dict[str, Any]] = {}
        if include_health:
            health_stmt = select(DeviceHealth).where(DeviceHealth.device_id.in_(device_ids))
            health_result = await self.db.execute(health_stmt)
            for h in health_result.scalars().all():
                health_map[h.device_id] = {
                    "score": h.health_score,
                    "status": h.health_status,
                }

        # 4. Load saved layout
        positions: dict[str, dict[str, Any]] = {}
        if site_id:
            layout = await self._get_layout(site_id, user_id)
            if layout:
                positions = layout.positions or {}

        # 5. Build nodes
        nodes = []
        connected_device_ids = set()
        for link in links:
            connected_device_ids.add(link.source_device_id)
            connected_device_ids.add(link.target_device_id)

        for device in devices:
            device_health = health_map.get(device.id, {})
            pos = positions.get(str(device.id), {})

            node = {
                "id": device.id,
                "label": device.name or device.hostname or str(device.id)[:8],
                "device_type": device.device_type or "unknown",
                "status": device.status or "unknown",
                "ip_address": device.ip_address,
                "mac_address": device.mac_address,
                "model": device.model,
                "site_id": device.site_id,
                "site_name": site_name_map.get(device.site_id),
                "health_score": device_health.get("score"),
                "health_status": device_health.get("status"),
                "x": pos.get("x"),
                "y": pos.get("y"),
                "pinned": pos.get("pinned", False),
                "layer": self._infer_layer(device),
                "metadata": {
                    "firmware_version": getattr(device, "firmware_version", None),
                    "serial_number": getattr(device, "serial_number", None),
                },
            }
            nodes.append(node)

        # 6. Build edges
        edges = []
        for link in links:
            edges.append(
                {
                    "id": link.id,
                    "source_id": link.source_device_id,
                    "target_id": link.target_device_id,
                    "source_port": link.source_port,
                    "target_port": link.target_port,
                    "speed": link.speed,
                    "status": link.status,
                    "link_type": link.link_type,
                    "discovered_via": link.discovered_via,
                    "metadata": link.link_metadata or {},
                }
            )

        # 7. Compute stats
        orphan_count = sum(1 for d in devices if d.id not in connected_device_ids)
        nodes_by_type = defaultdict(int)
        nodes_by_status = defaultdict(int)
        links_by_status = defaultdict(int)

        for node in nodes:
            nodes_by_type[node["device_type"]] += 1
            nodes_by_status[node["status"]] += 1
        for edge in edges:
            links_by_status[edge["status"]] += 1

        stats = {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes_by_type": dict(nodes_by_type),
            "nodes_by_status": dict(nodes_by_status),
            "links_by_status": dict(links_by_status),
            "orphan_count": orphan_count,
        }

        # 8. Auto-layout nodes that don't have saved positions
        if not positions:
            await self._auto_layout(nodes, edges)

        truncated = len(devices) >= self.MAX_TOPOLOGY_NODES

        return {
            "nodes": nodes,
            "edges": edges,
            "site_id": site_id,
            "generated_at": now,
            "stats": stats,
            "truncated": truncated,
            "max_nodes": self.MAX_TOPOLOGY_NODES if truncated else None,
        }

    # ------------------------------------------------------------------
    # Layout Persistence
    # ------------------------------------------------------------------

    async def save_layout(
        self,
        site_id: UUID,
        user_id: UUID | None,
        data: dict[str, Any],
    ) -> TopologyLayout:
        """Save or update a topology layout for a site."""
        layout = await self._get_layout(site_id, user_id)

        ALLOWED_LAYOUT_FIELDS = {"positions", "zoom", "center_x", "center_y", "algorithm", "name"}
        if layout:
            for key, value in data.items():
                if key in ALLOWED_LAYOUT_FIELDS and value is not None:
                    setattr(layout, key, value)
        else:
            # Filter through allowed fields to prevent mass assignment
            filtered_data = {
                k: v for k, v in data.items() if k in ALLOWED_LAYOUT_FIELDS and v is not None
            }
            # Convert positions if they're Pydantic models
            positions = filtered_data.get("positions", {})
            if positions:
                filtered_data["positions"] = {
                    k: v.model_dump() if hasattr(v, "model_dump") else v
                    for k, v in positions.items()
                }
            layout = TopologyLayout(
                site_id=site_id,
                user_id=user_id,
                **filtered_data,
            )
            self.db.add(layout)

        await self.db.flush()
        # ``onupdate=func.now()`` evicts ``updated_at`` post-UPDATE without
        # refreshing it. With async sessions this means the next attribute
        # access tries a sync DB IO → MissingGreenlet at response-
        # serialization time. Explicit refresh loads the new server
        # timestamp into the Python object so FastAPI can serialize it.
        await self.db.refresh(layout)
        return layout

    async def get_layout(self, site_id: UUID, user_id: UUID | None = None) -> TopologyLayout | None:
        return await self._get_layout(site_id, user_id)

    async def delete_layout(self, site_id: UUID, user_id: UUID | None = None) -> bool:
        layout = await self._get_layout(site_id, user_id)
        if not layout:
            return False
        await self.db.delete(layout)
        await self.db.flush()
        return True

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    async def _get_layout(self, site_id: UUID, user_id: UUID | None) -> TopologyLayout | None:
        """Get layout for site + user, falling back to site-default."""
        if user_id:
            result = await self.db.execute(
                select(TopologyLayout).where(
                    TopologyLayout.site_id == site_id,
                    TopologyLayout.user_id == user_id,
                )
            )
            layout = result.scalar_one_or_none()
            if layout:
                return layout

        # Fall back to site default (user_id = NULL)
        result = await self.db.execute(
            select(TopologyLayout).where(
                TopologyLayout.site_id == site_id,
                TopologyLayout.user_id.is_(None),
            )
        )
        return result.scalar_one_or_none()

    def _infer_layer(self, device: Device) -> str:
        """Infer network layer from device type for visualization grouping."""
        dtype = (device.device_type or "").lower()
        if "router" in dtype or "gateway" in dtype or "firewall" in dtype:
            return "core"
        elif (
            "switch" in dtype and ("core" in dtype or "distribution" in dtype) or "switch" in dtype
        ):
            return "distribution"
        elif "ap" in dtype or "access_point" in dtype or "wireless" in dtype:
            return "access"
        else:
            return "edge"

    async def _auto_layout(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        algorithm: str = "auto",
    ) -> None:
        """
        Compute positions for nodes using TopologyLayoutEngine.

        The layout computation is CPU-bound and is offloaded to a thread
        via ``asyncio.to_thread()`` to avoid blocking the event loop.

        Args:
            algorithm: "hierarchical", "force_directed", or "auto" (default).
        """
        from app.services.topology_layout import TopologyLayoutEngine

        # Build links in the format expected by TopologyLayoutEngine
        layout_nodes = [
            {"id": str(n["id"]), "device_type": n.get("device_type", "")} for n in nodes
        ]
        layout_links = [
            {"source": str(e["source_id"]), "target": str(e["target_id"])} for e in edges
        ]

        def _compute_layout():
            if algorithm == "hierarchical":
                return TopologyLayoutEngine.hierarchical_layout(layout_nodes, layout_links)
            elif algorithm == "force_directed":
                return TopologyLayoutEngine.force_directed_layout(layout_nodes, layout_links)
            else:
                return TopologyLayoutEngine.auto_select(layout_nodes, layout_links)

        positions = await asyncio.to_thread(_compute_layout)

        # Apply positions to nodes that don't already have saved positions
        for node in nodes:
            pos = positions.get(str(node["id"]), {})
            if node.get("x") is None:
                node["x"] = pos.get("x", 0)
            if node.get("y") is None:
                node["y"] = pos.get("y", 0)

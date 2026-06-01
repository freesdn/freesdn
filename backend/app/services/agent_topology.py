# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Service for upserting LLDP/CDP topology edges from the agent.

Pairs with ``devices.topology_edges`` (migration 022) and the WS
``topology_update`` handler registered in
``services/remote_agent.py``. Single chokepoint for both the WS
ingestion path and any future REST push so the dedup + merge
semantics are identical.

This is SEPARATE from ``services/topology.py`` — that file builds
graphs from the existing ``topology_links`` table (controller-derived
edges). This file is for AGENT-observed L2 edges (LLDP/CDP/etc.).

Edge identity (for dedup): the partial unique index on
``(site_id, local_interface, neighbor_chassis_id, neighbor_port_id)``
treats those four as the primary key. Re-observations from the same
chassis on the same agent interface to the same neighbor port just
advance ``last_seen`` and refresh any TLV fields that have new values.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.devices import TopologyEdge

logger = logging.getLogger(__name__)


# Fields where "latest non-empty observation wins" — chassis/port
# subtypes can change rarely (e.g., switch firmware upgrade), and the
# description/system_name/capabilities fields are often only sent in
# one direction so we update when we get one.
_REPLACE_IF_PRESENT = (
    "neighbor_chassis_subtype",
    "neighbor_port_subtype",
    "neighbor_port_description",
    "neighbor_system_name",
    "neighbor_system_description",
    "neighbor_capabilities",
    "neighbor_mgmt_address",
    "vlan_id",
)


async def upsert_topology_edge(
    session: AsyncSession,
    *,
    site_id: UUID,
    organization_id: UUID,
    discovered_by_agent_id: UUID | None,
    protocol: str = "lldp",
    local_interface: str,
    neighbor_chassis_id: str,
    neighbor_port_id: str,
    neighbor_chassis_subtype: str | None = None,
    neighbor_port_subtype: str | None = None,
    neighbor_port_description: str | None = None,
    neighbor_system_name: str | None = None,
    neighbor_system_description: str | None = None,
    neighbor_capabilities: list[str] | None = None,
    neighbor_mgmt_address: str | None = None,
    vlan_id: int | None = None,
) -> TopologyEdge:
    """Upsert one observed edge. Caller commits."""
    result = await session.execute(
        select(TopologyEdge).where(
            and_(
                TopologyEdge.site_id == site_id,
                TopologyEdge.local_interface == local_interface,
                TopologyEdge.neighbor_chassis_id == neighbor_chassis_id,
                TopologyEdge.neighbor_port_id == neighbor_port_id,
                TopologyEdge.deleted_at.is_(None),
            )
        )
    )
    existing = result.scalar_one_or_none()
    now = datetime.now(UTC)

    if existing is None:
        edge = TopologyEdge(
            site_id=site_id,
            organization_id=organization_id,
            discovered_by_agent_id=discovered_by_agent_id,
            protocol=protocol,
            local_interface=local_interface,
            neighbor_chassis_id=neighbor_chassis_id,
            neighbor_chassis_subtype=neighbor_chassis_subtype,
            neighbor_port_id=neighbor_port_id,
            neighbor_port_subtype=neighbor_port_subtype,
            neighbor_port_description=neighbor_port_description,
            neighbor_system_name=neighbor_system_name,
            neighbor_system_description=neighbor_system_description,
            neighbor_capabilities=neighbor_capabilities,
            neighbor_mgmt_address=neighbor_mgmt_address,
            vlan_id=vlan_id,
            first_seen=now,
            last_seen=now,
        )
        session.add(edge)
        await session.flush()
        return edge

    new_values = {
        "neighbor_chassis_subtype": neighbor_chassis_subtype,
        "neighbor_port_subtype": neighbor_port_subtype,
        "neighbor_port_description": neighbor_port_description,
        "neighbor_system_name": neighbor_system_name,
        "neighbor_system_description": neighbor_system_description,
        "neighbor_capabilities": neighbor_capabilities,
        "neighbor_mgmt_address": neighbor_mgmt_address,
        "vlan_id": vlan_id,
    }
    for field in _REPLACE_IF_PRESENT:
        val = new_values.get(field)
        if val is not None and val != "":
            setattr(existing, field, val)

    if discovered_by_agent_id is not None:
        existing.discovered_by_agent_id = discovered_by_agent_id

    existing.last_seen = now
    existing.updated_at = now
    await session.flush()
    return existing


async def upsert_topology_edges_batch(
    session: AsyncSession,
    *,
    site_id: UUID,
    organization_id: UUID,
    edges: list[dict[str, Any]],
    discovered_by_agent_id: UUID | None = None,
) -> tuple[int, int]:
    """Batch-upsert observed edges with a SINGLE existing-row query.

        Replaces the N+1 pattern where the REST batch endpoint did one
        "does it exist?" SELECT per edge AND ``upsert_topology_edge`` did
        another SELECT per edge — up to 2×N round trips for an N-edge batch
    . Here we load every existing edge that matches the
        batch's identity tuples in one query, then create/merge in memory
        and flush once.

        ``edges`` items use the same field names as ``upsert_topology_edge``
        kwargs. Returns ``(created, updated)``.
    """
    from sqlalchemy import tuple_ as _tuple

    now = datetime.now(UTC)

    # Identity tuples for the whole batch (dedup within the batch too).
    keys = {
        (
            e["local_interface"],
            e["neighbor_chassis_id"],
            e["neighbor_port_id"],
        )
        for e in edges
    }
    existing_map: dict[tuple[str, str, str], TopologyEdge] = {}
    if keys:
        rows = (
            (
                await session.execute(
                    select(TopologyEdge).where(
                        TopologyEdge.site_id == site_id,
                        TopologyEdge.deleted_at.is_(None),
                        _tuple(
                            TopologyEdge.local_interface,
                            TopologyEdge.neighbor_chassis_id,
                            TopologyEdge.neighbor_port_id,
                        ).in_(list(keys)),
                    )
                )
            )
            .scalars()
            .all()
        )
        for r in rows:
            existing_map[(r.local_interface, r.neighbor_chassis_id, r.neighbor_port_id)] = r

    created = 0
    updated = 0
    for e in edges:
        key = (
            e["local_interface"],
            e["neighbor_chassis_id"],
            e["neighbor_port_id"],
        )
        existing = existing_map.get(key)
        if existing is None:
            edge = TopologyEdge(
                site_id=site_id,
                organization_id=organization_id,
                discovered_by_agent_id=discovered_by_agent_id,
                protocol=e.get("protocol", "lldp"),
                local_interface=e["local_interface"],
                neighbor_chassis_id=e["neighbor_chassis_id"],
                neighbor_chassis_subtype=e.get("neighbor_chassis_subtype"),
                neighbor_port_id=e["neighbor_port_id"],
                neighbor_port_subtype=e.get("neighbor_port_subtype"),
                neighbor_port_description=e.get("neighbor_port_description"),
                neighbor_system_name=e.get("neighbor_system_name"),
                neighbor_system_description=e.get("neighbor_system_description"),
                neighbor_capabilities=e.get("neighbor_capabilities"),
                neighbor_mgmt_address=e.get("neighbor_mgmt_address"),
                vlan_id=e.get("vlan_id"),
                first_seen=now,
                last_seen=now,
            )
            session.add(edge)
            # Track within-batch so a duplicate tuple in the same payload
            # merges onto the row we just created instead of inserting twice.
            existing_map[key] = edge
            created += 1
        else:
            for field in _REPLACE_IF_PRESENT:
                val = e.get(field)
                if val is not None and val != "":
                    setattr(existing, field, val)
            if discovered_by_agent_id is not None:
                existing.discovered_by_agent_id = discovered_by_agent_id
            existing.last_seen = now
            existing.updated_at = now
            updated += 1

    await session.flush()
    return created, updated


def normalize_lldp_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Map an agent ``topology_update`` payload onto upsert kwargs.

    Returns the upsert kwargs dict, or None if the payload lacks the
    minimum required fields (chassis + port).
    """
    neighbor = payload.get("neighbor") or {}
    chassis = neighbor.get("chassis_id")
    port = neighbor.get("port_id")
    if not chassis or not port:
        return None

    return {
        "protocol": (payload.get("discovered_via") or "lldp").lower(),
        "local_interface": (payload.get("local_interface") or "unknown")[:64],
        "neighbor_chassis_id": str(chassis)[:64],
        "neighbor_chassis_subtype": neighbor.get("chassis_id_subtype"),
        "neighbor_port_id": str(port)[:64],
        "neighbor_port_subtype": neighbor.get("port_id_subtype"),
        "neighbor_port_description": (neighbor.get("port_description") or None),
        "neighbor_system_name": (neighbor.get("system_name") or None),
        "neighbor_system_description": (neighbor.get("system_description") or None),
        "neighbor_capabilities": neighbor.get("capabilities"),
        "neighbor_mgmt_address": neighbor.get("mgmt_address"),
        "vlan_id": neighbor.get("vlan_id"),
    }

# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Topology API Endpoints
======================================

L2/L3 topology graph building and layout persistence.
"""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db
from app.core.dependencies import CurrentUser, require_permissions
from app.core.site_access import assert_can_access_site
from app.models.core import Site
from app.schemas.topology import (
    TopologyGraphResponse,
    TopologyLayoutResponse,
    TopologyLayoutSave,
)
from app.services.topology import TopologyService

router = APIRouter()


# ==========================================================================
# Topology Graph
# ==========================================================================


@router.get("/graph", response_model=TopologyGraphResponse)
async def get_topology_graph(
    site_id: UUID | None = None,
    include_health: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """
    Get the topology graph for a site or the entire organization.

    Returns nodes (devices) and edges (links) with optional health overlay
    and saved layout positions.
    """
    # SECURITY: foreign site_id used to return 200 with
    # an empty {nodes:[], edges:[]} payload — not a tenant leak (the
    # downstream service filters by org_id) but operators couldn't tell
    # whether they had no devices on that site or had typed/pasted the
    # wrong UUID. Match the Health endpoint pattern: 404 if the site is
    # not owned by the caller's org.
    if site_id is not None:
        check = await db.execute(
            select(Site.id).where(
                Site.id == site_id,
                Site.organization_id == user.organization_id,
                Site.deleted_at.is_(None),
            )
        )
        if check.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Site not found")
        # site-limited callers can't request a non-granted site.
        assert_can_access_site(user, site_id, detail="Site not found")

    service = TopologyService(db)
    graph = await service.get_topology_graph(
        organization_id=user.organization_id,
        site_id=site_id,
        user_id=user.id,
        include_health=include_health,
        accessible_site_ids=(user.accessible_site_ids if user.is_site_limited else None),
    )
    return graph


# ==========================================================================
# Layout Persistence
# ==========================================================================


@router.get("/layout/{site_id}", response_model=TopologyLayoutResponse | None)
async def get_topology_layout(
    site_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """Get saved topology layout for a site."""
    site_check = await db.execute(
        select(Site).where(
            Site.id == site_id,
            Site.organization_id == user.organization_id,
            Site.deleted_at.is_(None),
        )
    )
    if not site_check.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Site not found")
    assert_can_access_site(user, site_id, detail="Site not found")
    service = TopologyService(db)
    layout = await service.get_layout(site_id, user_id=user.id)
    if not layout:
        return None
    return layout


@router.put("/layout/{site_id}", response_model=TopologyLayoutResponse)
async def save_topology_layout(
    site_id: UUID,
    body: TopologyLayoutSave,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:write")),
) -> Any:
    """Save or update topology layout positions for a site."""
    site_check = await db.execute(
        select(Site).where(
            Site.id == site_id,
            Site.organization_id == user.organization_id,
            Site.deleted_at.is_(None),
        )
    )
    if not site_check.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Site not found")
    assert_can_access_site(user, site_id, detail="Site not found")
    service = TopologyService(db)
    layout = await service.save_layout(
        site_id=site_id,
        user_id=user.id,
        data=body.model_dump(),
    )
    await db.commit()
    return layout


@router.post("/auto-layout/{site_id}")
async def auto_layout(
    site_id: UUID,
    algorithm: str = Query("auto", pattern="^(auto|hierarchical|force_directed)$"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:read")),
) -> Any:
    """
    Compute auto-layout positions for a site's topology.

    Accepts `algorithm`: "auto" (default), "hierarchical", or "force_directed".
    Returns the topology graph with freshly computed positions (does not save).
    """
    # Mirror the graph + layout endpoints — verify site ownership BEFORE
    # the algorithm runs so foreign site_id returns 404 rather than a
    # 200 with empty graph.
    check = await db.execute(
        select(Site.id).where(
            Site.id == site_id,
            Site.organization_id == user.organization_id,
            Site.deleted_at.is_(None),
        )
    )
    if check.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Site not found")

    # site-limited callers can't request non-granted sites
    assert_can_access_site(user, site_id, detail="Site not found")

    service = TopologyService(db)
    graph = await service.get_topology_graph(
        organization_id=user.organization_id,
        site_id=site_id,
        user_id=user.id,
        include_health=True,
    )
    # Re-compute layout with the selected algorithm. ``_auto_layout`` is
    # a coroutine — calling it without ``await`` silently dropped the
    # computation (RuntimeWarning in logs) and returned the auto-selected
    # layout from ``get_topology_graph`` regardless of the algorithm
    # requested.
    #
    # ``_auto_layout`` only fills nodes whose x/y is None (to
    # preserve user-saved positions on the normal graph path), but
    # ``get_topology_graph`` already populated every node's position — so the
    # requested algorithm was discarded and the selector was a no-op. This
    # endpoint explicitly does NOT persist, so clear positions first to force a
    # clean recompute for the chosen algorithm.
    for node in graph["nodes"]:
        node["x"] = None
        node["y"] = None
    await service._auto_layout(graph["nodes"], graph["edges"], algorithm=algorithm)
    return graph


@router.delete("/layout/{site_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_topology_layout(
    site_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_permissions("device:write")),
) -> None:
    """Delete saved topology layout for a site."""
    site_check = await db.execute(
        select(Site).where(
            Site.id == site_id,
            Site.organization_id == user.organization_id,
            Site.deleted_at.is_(None),
        )
    )
    if not site_check.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Site not found")
    assert_can_access_site(user, site_id, detail="Site not found")
    service = TopologyService(db)
    deleted = await service.delete_layout(site_id, user_id=user.id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Layout not found")
    await db.commit()

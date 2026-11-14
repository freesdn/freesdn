# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A disabled module stops polling.

When an organization switches a module off in Settings > Modules, that
module's periodic tasks skip the organization's devices: the Firewall module's
gateway sync, health poll and drift checks, the Cameras module's NVR health
poll and alert ingest, the Hypervisor and Storage monitors, the Network
module's Omada monitor and the VoIP phone health check. ``voip.sync_all_cdr``
already did this; every other poller kept contacting the devices of a module
the operator had turned off.

Same rule as the route gate (``app/modules/enablement.py``): only an EXPLICIT
``is_enabled=False`` row counts as disabled. A missing row is not, because no
module declares ``is_core`` and organizations created through the API have no
rows at all; treating "no row" as off would stop all polling for them.

One query per sweep, not one per device.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def orgs_with_module_disabled(
    session: AsyncSession, module_id: str, organization_ids: Iterable[Any]
) -> set[UUID]:
    """The subset of ``organization_ids`` that explicitly disabled ``module_id``."""
    from app.modules.models import OrganizationModule

    wanted = {_as_uuid(org) for org in organization_ids if org is not None}
    wanted.discard(None)
    if not wanted:
        return set()
    rows = await session.execute(
        select(OrganizationModule.organization_id).where(
            OrganizationModule.module_id == module_id,
            OrganizationModule.organization_id.in_(wanted),
            OrganizationModule.is_enabled.is_(False),
        )
    )
    return {row[0] for row in rows.all()}


def module_not_disabled(org_column: Any, module_id: str) -> Any:
    """A WHERE clause: the row's organization has not explicitly disabled
    ``module_id``. For pollers that select their targets in one query."""
    from sqlalchemy import exists

    from app.modules.models import OrganizationModule

    return ~exists(
        select(OrganizationModule.id).where(
            OrganizationModule.organization_id == org_column,
            OrganizationModule.module_id == module_id,
            OrganizationModule.is_enabled.is_(False),
        )
    )


def _as_uuid(value: Any) -> UUID | None:
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None

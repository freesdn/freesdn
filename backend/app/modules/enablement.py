# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Make the Settings > Modules toggle actually close a module's endpoints.

Until this existed, disabling a module hid its navigation and nothing else.
``ModuleRegistry.require_enabled`` was written for the job and never called by
anything, and ``ModuleLoader.register_routes`` mounted every discovered module's
router unconditionally, so every route of a "disabled" module stayed callable
with valid credentials. ``ModuleGuard.tsx`` told developers the opposite in a
comment -- "The backend enforces real module access, so this optimistic render
is UX-only" -- which is how the gap survived.

WHAT THIS REFUSES, AND WHY IT IS DELIBERATELY NARROW
----------------------------------------------------
Only an EXPLICIT ``is_enabled=False`` row refuses. A missing row does not.

That asymmetry is the whole safety argument. ``ModuleService.is_module_enabled``
treats a missing row as disabled, and no module declares ``is_core``, so a gate
built on "enabled means a row saying True" would 403 the entire product for any
organization whose rows were never written -- one created through the API, or
one that skipped the wizard's module step. Enforcing an operator's explicit
"off" is the feature people expect from a toggle; refusing everything an
operator never explicitly switched on is a lockout.

Tightening this to deny-by-default is a reasonable future step, but it needs a
backfill migration that writes rows for existing organizations first. Doing it
here, without one, would brick live deployments on upgrade.

AUTHENTICATION IS NOT IMPOSED
-----------------------------
The caller is resolved OPTIONALLY. This dependency decides enablement and
nothing else: if a module route is public, it stays public, and if it requires
auth, its own dependency still says so. A gate that silently added
authentication to every module route would be changing a second thing under
cover of the first.

A principal with no organization (a scoped token, a setup-time caller) is not
refused here either. Which organization such a caller acts for is a question
other layers already answer, and inventing an answer in a routing gate is how
guards start disagreeing with each other.

VENDOR ROUTERS A MODULE OWNS
----------------------------
Proxmox, FreePBX, TrueNAS, OPNsense and pfSense have their own routers on the
core API router (``/api/v1/gateway-proxmox-vm/...`` and so on) next to their
module's router. Those carry the same gate, keyed by router prefix in
``MODULE_OWNED_ROUTER_PREFIXES``; ``tests/modules/test_module_enablement_gate.py``
fails if one of them is mounted without it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from uuid import UUID

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# app.core.dependencies, app.db.session and app.modules.models are imported
# INSIDE the functions below, not here. ModuleLoader imports this file at
# module scope, and app.core.dependencies imports app.models, which imports
# app.modules.ai.models, which re-enters app.modules -> loader -> this file.
# Importing at module scope therefore fails with a partially initialised
# app.core.dependencies. Both functions run long after imports have settled:
# module_enabled_dependency() is called from register_routes() and from the
# core API router's include_router (app/api/v1/__init__.py), both of which run
# after every endpoint module, and so app.core.dependencies, has been imported.

__all__ = [
    "MODULE_OWNED_ROUTER_PREFIXES",
    "ModuleDisabledError",
    "is_module_explicitly_disabled",
    "module_enabled_dependency",
    "module_owner_for_router_prefix",
]

#: ``type`` of the error envelope a disabled module's route answers with, so a
#: client can tell "this module is switched off" from "you lack a permission"
#: (both are 403) without parsing the sentence.
MODULE_DISABLED_ERROR_TYPE = "module_disabled"

#: Vendor routers mounted on the core API router (``app/api/v1/__init__.py``)
#: rather than on a module router, keyed by router prefix, mapped to the module
#: that owns them. They belong to exactly one module each: Proxmox is the
#: hypervisor module's backend, FreePBX the VoIP module's, TrueNAS the storage
#: module's, OPNsense and pfSense the firewall module's. Before this map existed
#: the module gate covered only ``/api/v1/{module_id}/...``, so disabling the
#: hypervisor module left every Proxmox stage and read route callable.
#:
#: Deliberately NOT listed: Omada, UniFi, MikroTik and OpenWrt. Each of those
#: is a switch, access point and router at once and serves the network module
#: as much as the firewall module, so there is no single owner to enforce.
#: Matching is on a router's prefix, exactly or followed by ``-``.
MODULE_OWNED_ROUTER_PREFIXES: dict[str, str] = {
    "/gateway-proxmox": "hypervisor",
    "/gateway-freepbx": "voip",
    "/gateway-storage": "storage",
    "/gateway-opnsense": "firewall",
    "/gateway-pfsense": "firewall",
}


def module_owner_for_router_prefix(prefix: str | None) -> str | None:
    """The module that owns a core-mounted vendor router, or None."""
    if not prefix:
        return None
    for family, module_id in MODULE_OWNED_ROUTER_PREFIXES.items():
        if prefix == family or prefix.startswith(family + "-"):
            return module_id
    return None


class ModuleDisabledError(HTTPException):
    """A request reached a route of a module this organization switched off.

    An ``HTTPException`` so it behaves as a plain 403 anywhere, and its own
    class so ``app.core.middleware`` can give it an envelope with
    ``type: "module_disabled"`` and the ``module_id``.
    """

    error_type = MODULE_DISABLED_ERROR_TYPE

    def __init__(self, module_id: str) -> None:
        self.module_id = module_id
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"The '{module_id}' module is disabled for this organization. "
                "An administrator can re-enable it in Settings > Modules."
            ),
        )


async def is_module_explicitly_disabled(
    session: AsyncSession,
    organization_id: UUID,
    module_id: str,
) -> bool:
    """True only when a row exists for this pair and says ``is_enabled=False``.

    Read authoritatively from the database rather than from
    ``ModuleRegistry._enabled_cache``. That cache is a per-process dict, so with
    more than one worker an operator who disables a module updates one worker's
    view and leaves the others serving the module. For a gate, stale-permissive
    is the wrong direction to fail.
    """
    from app.modules.models import OrganizationModule

    result = await session.execute(
        select(OrganizationModule.is_enabled).where(
            OrganizationModule.organization_id == organization_id,
            OrganizationModule.module_id == module_id,
        )
    )
    enabled = result.scalar_one_or_none()
    return enabled is False


def module_enabled_dependency(module_id: str) -> Callable[..., Awaitable[None]]:
    """Build the router-level dependency that enforces ``module_id``.

    Applied by :meth:`ModuleLoader.register_routes` to every module router, and
    by the core API router (``app/api/v1/__init__.py``) to every vendor router
    listed in :data:`MODULE_OWNED_ROUTER_PREFIXES`, so the gate cannot be
    forgotten on a new endpoint the way a per-route check would be.

    What stays reachable while a module is disabled: everything under
    ``/api/v1/modules/`` (the list, states, per-module health and the enable and
    disable calls), which the UI needs to show a module as disabled and to turn
    it back on. That router is not a module router and is never gated.
    """

    from app.core.dependencies import CurrentUser, get_current_user_optional
    from app.db.session import get_session

    async def _enforce(
        user: CurrentUser | None = Depends(get_current_user_optional),
        session: AsyncSession = Depends(get_session),
    ) -> None:
        if user is None or user.organization_id is None:
            return
        if await is_module_explicitly_disabled(session, user.organization_id, module_id):
            raise ModuleDisabledError(module_id)

    _enforce.__name__ = f"require_{module_id}_enabled"
    return _enforce

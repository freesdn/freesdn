# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Shared staging-pipeline FastAPI guards.

WP-08: the staged-write apply endpoint enforces a minimum *role* on top of the
permission gate for catastrophic features (VM destroy, node shutdown, RouterOS
reboot, backup restore, cert upload, …) so they can't be applied by a low-tier
operator. ``enforce_catastrophic_stage_role`` duplicates that role gate at stage
time to close the "queue-poison" window (a low-tier operator plants a
catastrophic change that a higher-tier operator later applies from the queue).

It is meant to be attached router-wide via ``include_router(dependencies=[...])``
on EVERY adapter router whose stage endpoint can accept a catastrophic feature.

COVERAGE (keep this list honest — an overstated docstring hides real gaps):
the dependency is currently wired only on the 12 Proxmox stage routers in
``app/api/v1/__init__.py``. The Omada bulk/system and OPNsense/pfSense system
stage routers can ALSO accept catastrophic features (``bulk.device.factory_reset
/reboot/forget``, ``system.controller_factory_reset``, ``system.backup.restore``,
``opnsense.system.firmware_update``/``config_restore``/``backup_restore``, …) but
do NOT yet have this dependency attached, so their stage POSTs are gated by the
write permission alone — the queue-poison window stays open for those vendors.
Wiring this dependency onto those routers is the remaining fix and lives in
``app/api/v1/__init__.py`` (the router-aggregation site), not here.
"""

from typing import Annotated

from fastapi import Depends, HTTPException

from app.core.dependencies import CurrentUser, get_current_active_user


async def enforce_catastrophic_stage_role(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
    feature: str | None = None,
) -> None:
    """Stage-time catastrophic-role gate, mirroring the apply-time gate.

    Applied router-wide (via ``include_router(dependencies=[...])``), so it also
    runs on the read routes in the same router — there ``feature`` is absent
    (None) and the check is a NO-OP. On a stage POST, ``feature`` is the path
    param; if it maps to a catastrophic feature the caller must hold the required
    minimum role (e.g. ``site_admin``) in addition to the write permission the
    endpoint itself already checks.
    """
    if not feature:
        return
    # Local import avoids a module-load cycle (the apply-role map lives in the
    # omada-vpn endpoint module, which imports plenty of services).
    from app.api.v1.endpoints.adapter_omada_vpn import _required_apply_role

    required = _required_apply_role(feature)
    if required and not current_user.has_min_role(required):
        raise HTTPException(
            status_code=403,
            detail=(
                f"feature {feature!r} is catastrophic and requires minimum role "
                f"{required!r} to stage"
            ),
        )

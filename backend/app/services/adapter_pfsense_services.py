# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense Services service
============================================

Read-and-stage for pfSense system services (start / stop / restart).
Mirrors ``adapter_opnsense_services.py``: reads run live, writes are
STAGED in ``core.adapter_pending_changes``, and the applier passes
``force=True`` so the pfSense client's universal ``ADAPTER_READ_ONLY``
gate lets the write through.

Supported features::

    pfsense.services.start     create   (target_id = service name)
    pfsense.services.stop      create   (target_id = service name)
    pfsense.services.restart   create   (target_id = service name)

The pfSense API targets a service by name — there is no UUID — so the
``target_id`` on the staged change carries the service name (``unbound``,
``dhcpd``, ``openvpn``, ...). The endpoint validates that name with
:func:`app.adapters.validation.validate_id` before it ever flows into
the URL path.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.validation import validate_id
from app.services.adapter_base import GatewayServiceBase

# (feature, operation) → bound client method name. Same dispatch shape
# Omada / OPNsense use.
_APPLY: dict[tuple[str, str], str] = {
    ("pfsense.services.start", "create"): "start_service",
    ("pfsense.services.stop", "create"): "stop_service",
    ("pfsense.services.restart", "create"): "restart_service",
}


class GatewayPfsenseServicesService(GatewayServiceBase):
    """Live reads + staged start/stop/restart for pfSense services."""

    SUPPORTED_CONTROLLER_TYPE = "pfsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_services(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_services()
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Each call passes ``force=True`` to the pfSense client. Outside
        the applier, the client's ``ADAPTER_READ_ONLY`` gate refuses
        every write — this is the sanctioned exit.
        """

        async def _apply(c: Any) -> Any:
            # Fast-fail BEFORE building a network client.
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            # start/stop/restart are one-shot ops — gate operation here.
            if (
                c.feature
                in (
                    "pfsense.services.start",
                    "pfsense.services.stop",
                    "pfsense.services.restart",
                )
                and c.operation != "create"
            ):
                raise HTTPException(
                    400,
                    detail=(f"{c.feature} only supports operation=create (one-shot)"),
                )

            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            target_id = c.target_id  # service name

            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"pfSense adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            # All three operations target a service by name. Refuse if
            # the staged change forgot to set ``target_id`` — without it
            # we would POST to ``/start//`` which is a 404 at best and
            # surprising behaviour at worst.
            if not target_id:
                raise HTTPException(
                    400,
                    detail=(f"feature={c.feature!r} requires target_id (service name)"),
                )
            # Re-validate the staged service name before it interpolates
            # into the URL path. The endpoint already runs
            # ``validate_id`` at stage-time, but DB-stored values must
            # not be trusted — an attacker with DB write access (or a
            # bug that bypasses staging validation) cannot smuggle a
            # path-traversal payload here.
            validate_id(target_id, label="service_name")
            return await method(target_id, force=True)

        return _apply

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Services service
=============================================

Read-and-stage for OPNsense system services (start / stop / restart).
Mirrors ``adapter_opnsense_firewall.py``: reads run live, writes are
STAGED in ``core.adapter_pending_changes`` (the table is vendor-agnostic
despite its historical name), and the applier passes ``force=True`` so
the OPNsense client's universal ``ADAPTER_READ_ONLY`` gate lets the
write through.

Supported features::

    opnsense.services.start     create   (target_id = service name)
    opnsense.services.stop      create   (target_id = service name)
    opnsense.services.restart   create   (target_id = service name)

The OPNsense API targets a service by name — there is no UUID — so the
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
# Omada / OPNsense-firewall use.
_APPLY: dict[tuple[str, str], str] = {
    ("opnsense.services.start", "create"): "start_service",
    ("opnsense.services.stop", "create"): "stop_service",
    ("opnsense.services.restart", "create"): "restart_service",
}


class GatewayOpnsenseServicesService(GatewayServiceBase):
    """Live reads + staged start/stop/restart for OPNsense services."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_services(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_services()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Each call passes ``force=True`` to the OPNsense client. Outside
        the applier, the client's ``ADAPTER_READ_ONLY`` gate refuses
        every write — this is the sanctioned exit.
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            try:
                target_id = c.target_id  # service name

                method_name = _APPLY.get((c.feature, c.operation))
                if method_name is None:
                    raise HTTPException(
                        400,
                        detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                    )
                method = getattr(client, method_name, None)
                if method is None:
                    raise HTTPException(
                        501,
                        detail=(
                            f"OPNsense adapter has no method {method_name!r}; "
                            "missing implementation"
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
                # re-validate the service name at apply-time.
                # Stage-time validation can be bypassed by inserting a
                # row directly; this is the last-resort path-segment
                # gate before the OPNsense client.
                validate_id(str(target_id), label="service_name")
                return await method(target_id, force=True)
            finally:
                await client.close()  # Item 14

        return _apply

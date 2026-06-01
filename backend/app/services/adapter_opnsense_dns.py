# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense DNS service
========================================

Read-and-stage for OPNsense Unbound DNS host overrides (per-FQDN A/AAAA
overrides) and domain overrides (forward whole zones to a different
resolver). Mirrors ``adapter_opnsense_firewall.py``: live reads,
staged writes, shared apply dispatcher.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the shared dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    opnsense.dns.host_override     create | delete   (Unbound host A/AAAA)
    opnsense.dns.domain_override   create | delete   (Unbound zone forward)
    opnsense.dns.apply             create  (reconfigure Unbound)

The applier passes ``force=True`` to the OPNsense client so the write
actually reaches the controller — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.validation import validate_id
from app.services.adapter_base import GatewayServiceBase

# (feature, operation) → bound client method name.
#
# Note: only ``create`` and ``delete`` are wired for host/domain
# overrides. The OPNsense client does expose update verbs
# (``update_dns_override``, ``update_dns_domain_override``) but the
# UI surface for DNS in the v2.6.0 frontend is create/delete only —
# add ``update`` here when the UI catches up.
_APPLY: dict[tuple[str, str], str] = {
    ("opnsense.dns.host_override", "create"): "add_dns_override",
    ("opnsense.dns.host_override", "delete"): "delete_dns_override",
    ("opnsense.dns.domain_override", "create"): "add_dns_domain_override",
    ("opnsense.dns.domain_override", "delete"): "delete_dns_domain_override",
    ("opnsense.dns.apply", "create"): "apply_dns_changes",
}


class GatewayOpnsenseDnsService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense Unbound DNS config."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_host_overrides(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            overrides = await client.get_dns_overrides()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": overrides,
            "fetched_at": datetime.now(UTC),
        }

    async def list_domain_overrides(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            overrides = await client.get_dns_domain_overrides()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": overrides,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` to the OPNsense client so it
        satisfies the client-layer read-only check — that gate is
        the bottom-of-stack safety; this applier is the top of the
        sanctioned write path.
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            try:
                payload = c.payload or {}
                target_id = c.target_id

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

                # Dispatch by feature/operation. Each call gets force=True
                # so the read-only gate lets the write through — the
                # operator already passed force=true at the apply
                # endpoint, which is the high-level dual-gate.
                if c.feature in (
                    "opnsense.dns.host_override",
                    "opnsense.dns.domain_override",
                ):
                    if c.operation == "create":
                        return await method(payload, force=True)
                    if c.operation == "delete":
                        if not target_id:
                            raise HTTPException(
                                400,
                                detail=(f"delete on {c.feature} requires target_id"),
                            )
                        # Defense-in-depth: re-validate at apply time.
                        validate_id(str(target_id), label="target_id")
                        return await method(target_id, force=True)
                if c.feature == "opnsense.dns.apply":
                    # No payload, no target — just commit.
                    return await method(force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                await client.close()  # Item 14

        return _apply

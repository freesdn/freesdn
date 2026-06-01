# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense NAT service
=======================================

Read-and-stage for pfSense destination NAT (port forward) rules. The
pfSense client also exposes outbound NAT and 1-to-1 NAT for *reads*,
but only port-forward CRUD methods exist on the client today. Source
NAT and 1-to-1 writes are read-only here until the client grows the
write methods — the rest of the wiring is identical to OPNsense / Omada.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    pfsense.nat.port_forward     create | delete    (target_id = rule_id)

The applier passes ``force=True`` to the pfSense client so the write
actually reaches the firewall — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# (feature, operation) → bound client method name. The applier
# uses this to dispatch — same pattern Omada / OPNsense use.
#
# Update is intentionally absent: the pfSense client does not expose
# ``update_port_forward``. Operators can delete + re-create until the
# adapter grows the verb.
_APPLY: dict[tuple[str, str], str] = {
    ("pfsense.nat.port_forward", "create"): "add_port_forward",
    ("pfsense.nat.port_forward", "delete"): "delete_port_forward",
}


class GatewayPfsenseNatService(GatewayServiceBase):
    """Live reads + staged writes for pfSense NAT config."""

    SUPPORTED_CONTROLLER_TYPE = "pfsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_outbound_rules(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        rules = await client.get_nat_rules()
        return {
            "controller_id": controller_id,
            "items": ([redact_secrets(r) for r in rules] if isinstance(rules, list) else rules),
            "fetched_at": datetime.now(UTC),
        }

    async def list_port_forwards(
        self, controller_id: UUID, organization_id: UUID
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        rules = await client.get_port_forwards()
        return {
            "controller_id": controller_id,
            "items": ([redact_secrets(r) for r in rules] if isinstance(rules, list) else rules),
            "fetched_at": datetime.now(UTC),
        }

    async def list_one_to_one(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        rules = await client.get_nat_1to1()
        return {
            "controller_id": controller_id,
            "items": rules,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` to the pfSense client so it
        satisfies the client-layer read-only check — that gate
        is the bottom-of-stack safety; this applier is the top of the
        sanctioned write path.
        """

        async def _apply(c: Any) -> Any:
            # Fast-fail BEFORE building a network client.
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )

            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            payload = c.payload or {}
            target_id = c.target_id

            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"pfSense adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            if c.feature == "pfsense.nat.port_forward":
                if c.operation == "create":
                    return await method(payload, force=True)
                if c.operation == "delete":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(
                                "delete on pfsense.nat.port_forward requires target_id (rule id)"
                            ),
                        )
                    # pfSense uses int rule IDs; the staging layer
                    # carries it as a string. The client's path-safety
                    # regex would reject a non-numeric value.
                    try:
                        rule_id = int(target_id)
                    except (TypeError, ValueError) as exc:
                        raise HTTPException(
                            400,
                            detail=("pfsense.nat.port_forward target_id must be a numeric rule id"),
                        ) from exc
                    return await method(rule_id, force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

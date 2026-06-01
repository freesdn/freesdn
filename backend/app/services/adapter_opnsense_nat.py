# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense NAT service
========================================

Read-and-stage for OPNsense source NAT (outbound NAT) and destination
NAT (port forward) rules. Mirrors the shape of
``adapter_opnsense_firewall.py`` so the same Pending Changes UX works
for NAT. The contract:

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (the table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    opnsense.nat.source_rule           create | update | delete
    opnsense.nat.source_apply          create  (commit staged source NAT)
    opnsense.nat.port_forward          create | update | delete
    opnsense.nat.port_forward_apply    create  (commit staged port forwards)

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
from app.services.adapter_redaction import redact_secrets

# (feature, operation) → bound client method name. The applier
# uses this to dispatch — same pattern Omada/firewall services use.
_APPLY: dict[tuple[str, str], str] = {
    # Source NAT (outbound NAT).
    ("opnsense.nat.source_rule", "create"): "add_source_nat_rule",
    ("opnsense.nat.source_rule", "update"): "update_source_nat_rule",
    ("opnsense.nat.source_rule", "delete"): "delete_source_nat_rule",
    ("opnsense.nat.source_apply", "create"): "apply_source_nat_changes",
    # Destination NAT (port forwards).
    ("opnsense.nat.port_forward", "create"): "add_port_forward_rule",
    ("opnsense.nat.port_forward", "update"): "update_port_forward_rule",
    ("opnsense.nat.port_forward", "delete"): "delete_port_forward_rule",
    ("opnsense.nat.port_forward_apply", "create"): "apply_port_forward_changes",
}


class GatewayOpnsenseNatService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense NAT config."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_source_rules(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            rules = await client.get_nat_rules()
        finally:
            await client.close()  # Item 14
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
        try:
            rules = await client.get_port_forward_rules()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": ([redact_secrets(r) for r in rules] if isinstance(rules, list) else rules),
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
                    "opnsense.nat.source_rule",
                    "opnsense.nat.port_forward",
                ):
                    if c.operation == "create":
                        return await method(payload, force=True)
                    if c.operation == "update":
                        if not target_id:
                            raise HTTPException(
                                400,
                                detail=(f"update on {c.feature} requires target_id"),
                            )
                        # Defense-in-depth: re-validate at apply time.
                        validate_id(str(target_id), label="target_id")
                        return await method(target_id, payload, force=True)
                    if c.operation == "delete":
                        if not target_id:
                            raise HTTPException(
                                400,
                                detail=(f"delete on {c.feature} requires target_id"),
                            )
                        validate_id(str(target_id), label="target_id")
                        return await method(target_id, force=True)
                if c.feature in (
                    "opnsense.nat.source_apply",
                    "opnsense.nat.port_forward_apply",
                ):
                    # No payload, no target — just commit.
                    return await method(force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                await client.close()  # Item 14

        return _apply

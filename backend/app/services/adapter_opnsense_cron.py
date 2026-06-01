# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Cron service
==========================================

Read-and-stage for OPNsense scheduled jobs (cron). Mirrors the shape
of ``adapter_opnsense_firewall.py`` so the same Pending Changes UX
applies to the firewall's task scheduler.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    opnsense.cron.job        create | update | delete
    opnsense.cron.apply      create  (commit staged config to crond)

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
_APPLY: dict[tuple[str, str], str] = {
    ("opnsense.cron.job", "create"): "add_cron_job",
    ("opnsense.cron.job", "update"): "update_cron_job",
    ("opnsense.cron.job", "delete"): "delete_cron_job",
    ("opnsense.cron.apply", "create"): "apply_cron_changes",
}


class GatewayOpnsenseCronService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense cron jobs."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_jobs(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        # close the httpx pool deterministically; without
        # this every read leaked an open session for the lifetime of
        # the request.
        try:
            items = await client.get_cron_jobs()
        finally:
            await client.close()
        return {
            "controller_id": controller_id,
            "items": items,
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

                # Dispatch by feature/operation. Each call gets force=True.
                if c.feature == "opnsense.cron.job":
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
                if c.feature == "opnsense.cron.apply":
                    # No payload, no target — just commit.
                    return await method(force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                # close the httpx pool even when the apply
                # raises, so the controller session does not leak.
                await client.close()

        return _apply

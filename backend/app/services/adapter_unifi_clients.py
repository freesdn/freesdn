# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway UniFi Clients service
========================================

Live reads + staged writes for UniFi client (station / connected
device) management. Mirrors the shape of the MikroTik per-domain
services so the same Pending Changes drawer + apply dispatcher
serves both vendors.

- Reads run live against the UniFi controller.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    unifi.clients.block        update  target_id=mac
    unifi.clients.unblock      update  target_id=mac
    unifi.clients.forget       delete  target_id=mac

Each stage carries ``payload.site`` so the apply path can reach the
right UniFi site without re-querying. UniFi controllers are inserted
into ``core.controllers`` directly, so the polymorphic resolver hits
the fast path on the Controller table (no auto-pair shim needed).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets
from app.services.adapter_unifi_common import enforce_unifi_site_grant

# (feature, operation) → bound UniFi adapter method name. The applier
# reads this to dispatch by shape — same pattern as the MikroTik
# per-domain services so the dispatcher is uniform across vendors.
_APPLY: dict[tuple[str, str], str] = {
    ("unifi.clients.block", "update"): "block_client",
    ("unifi.clients.unblock", "update"): "unblock_client",
    # reconnect kicks the client so it re-associates — disruptive but
    # RECOVERABLE (the client just reconnects), so operation=update (not a
    # catastrophic delete) and it needs no confirmation. Same (site, mac,
    # force=True) shape as block/unblock, so the generic applier handles it.
    ("unifi.clients.reconnect", "update"): "reconnect_client",
    # forget is destructive (drops historical state); operation=delete
    # so the FE renders it with the red "delete" badge in the drawer.
    ("unifi.clients.forget", "delete"): "forget_client",
}

# Catastrophic-op confirmation for UniFi clients (``unifi.clients.forget`` and
# any delete) is enforced CENTRALLY in ``adapter_unifi_preflight.enforce_unifi_preflight``,
# which now sits on the shared ``AdapterStagingService.apply_change`` chokepoint
# for every ``unifi.*`` feature. This service used to carry its own in-place
# forget gate (added before the central UniFi preflight existed), but that gate
# read the RAW staged payload and so could not see the operator's apply-time
# ``confirmed`` sign-off (made in the Pending-Changes drawer, where the diff is
# reviewed). The central gate honours apply-time confirmation, so the local one
# was removed to keep a single source of truth — no per-applier gate to drift.


class GatewayUniFiClientsService(GatewayServiceBase):
    """Live reads + staged writes for UniFi clients."""

    SUPPORTED_CONTROLLER_TYPE = "unifi"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_clients(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site: str,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        enforce_unifi_site_grant(ctrl, site)
        client = await self._get_adapter(ctrl)
        items = await client.list_clients(site)
        # Client rows occasionally include x_passphrase fields when a
        # voucher-bound or guest client retains its credential blob.
        return {
            "controller_id": controller_id,
            "site": site,
            "items": ([redact_secrets(c) for c in items] if isinstance(items, list) else items),
            "fetched_at": datetime.now(UTC),
        }

    async def get_one(
        self,
        controller_id: UUID,
        organization_id: UUID,
        site: str,
        mac: str,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any] | None:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id,
            organization_id,
            is_superuser=is_superuser,
        )
        enforce_unifi_site_grant(ctrl, site)
        client = await self._get_adapter(ctrl)
        return await client.get_client(site, mac)

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(
                c.controller_id,
                c.organization_id,
            )
            client = await self._get_adapter(ctrl)
            payload = c.payload or {}
            site = payload.get("site")
            mac = c.target_id

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
                    detail=(f"UniFi adapter has no method {method_name!r}; missing implementation"),
                )

            # block / unblock / forget all need (site, mac, force=True).
            # site comes from the staged payload (operator picks the
            # site at stage time; UniFi can host multiple sites under
            # one controller); mac comes from target_id (the row ID).
            if not site:
                raise HTTPException(
                    400,
                    detail=(f"feature {c.feature!r} requires payload.site"),
                )
            if not mac:
                raise HTTPException(
                    400,
                    detail=(f"feature {c.feature!r} requires a target_id (client MAC)"),
                )

            # NB: the catastrophic-op confirmation gate (forget / any delete) is
            # enforced centrally in ``enforce_unifi_preflight`` at the shared
            # ``apply_change`` chokepoint BEFORE this applier runs — see the module
            # comment above. It honours the operator's apply-time ``confirmed``
            # sign-off, which this in-applier path (raw payload only) could not.
            return await method(site, mac, force=True)

        return _apply

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense Diagnostics service
===============================================

Pure read service + direct probe helpers. Like
``adapter_opnsense_diagnostics.py``, this module has NO ``_APPLY`` map
and no ``build_applier``: every operation is either a live read
(arp / logs) or a non-mutating diagnostic probe (ping / traceroute /
dns_lookup).

The probe operations are write-shaped (``POST`` to the controller) but
non-mutating — the pfSense client's universal ``ADAPTER_READ_ONLY``
gate would block them by default, so the probe helpers below pass
``force=True`` to the underlying client. The endpoint layer gates each
probe behind ``firewall:write`` so a reader can't probe arbitrary hosts
from the operator's network.

We still extend ``GatewayServiceBase`` to inherit controller resolution,
credential decryption, and tenant-scoping plumbing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase


class GatewayPfsenseDiagnosticsService(GatewayServiceBase):
    """Live reads + direct probes for pfSense diagnostics."""

    SUPPORTED_CONTROLLER_TYPE = "pfsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def get_arp_table(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        items = await client.get_arp_table()
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def get_logs(
        self,
        controller_id: UUID,
        organization_id: UUID,
        category: str,
        count: int,
    ) -> dict[str, Any]:
        """Fetch recent log entries.

        ``category`` is one of ``system`` or ``firewall`` — the only
        log streams the pfSense client currently exposes. Anything
        else gets a 400 from the endpoint before we land here, but we
        re-validate defensively.
        """
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        if category == "system":
            items = await client.get_system_log(count)
        elif category == "firewall":
            items = await client.get_firewall_log(count)
        else:
            raise HTTPException(
                400,
                detail=(f"unknown log category={category!r}; expected 'system' or 'firewall'"),
            )
        return {
            "controller_id": controller_id,
            "category": category,
            "count": count,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    # ── Direct probe helpers (NOT staged) ────────────────────────────
    #
    # These three POST to the controller but do not change config — they
    # trigger a one-shot probe and return its output. Endpoint layer
    # gates them behind ``firewall:write``. Each passes ``force=True``
    # to bypass the client's universal read-only gate; without that the
    # probe would be refused at the bottom of the stack.

    async def ping(
        self,
        controller_id: UUID,
        organization_id: UUID,
        host: str,
        count: int,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        item = await client.run_ping(host, count, force=True)
        return {
            "controller_id": controller_id,
            "host": host,
            "count": count,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def traceroute(
        self, controller_id: UUID, organization_id: UUID, host: str
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        item = await client.run_traceroute(host, force=True)
        return {
            "controller_id": controller_id,
            "host": host,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def dns_lookup(
        self, controller_id: UUID, organization_id: UUID, hostname: str
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        item = await client.run_dns_lookup(hostname, force=True)
        return {
            "controller_id": controller_id,
            "hostname": hostname,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

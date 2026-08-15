# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Diagnostics service
================================================

Pure read service + direct probe helpers. Unlike
``adapter_opnsense_firewall.py`` and ``adapter_opnsense_system.py``,
this module has NO ``_APPLY`` map and no ``build_applier``: every
operation is either a live read (logs / traffic / arp / ndp) or a
non-mutating diagnostic probe (ping / traceroute / dns-lookup).

The probe operations are write-shaped (``POST`` to the controller) but
non-mutating — the OPNsense client's universal ``ADAPTER_READ_ONLY``
gate would block them by default, so the probe helpers below pass
``force=True`` to the underlying client. The endpoint layer gates
each probe behind ``firewall:write`` so a reader can't probe arbitrary
hosts from the operator's network.

We still extend ``GatewayServiceBase`` to inherit the controller
resolution, credential decryption, and tenant-scoping plumbing.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.adapters.validation import validate_id  # noqa: F401  # kept for callers
from app.services.adapter_base import GatewayServiceBase

# Item 20 + 24 — hostnames can legitimately reach 253 chars (RFC 1035),
# but ``validate_id`` caps at 64. Use a hostname/IP-shaped regex with
# the wider bound. The pattern accepts: ASCII alphanumerics, ``.``,
# ``-``, ``_`` (lenient for legacy hostnames), ``:`` (IPv6 colons), and
# brackets are stripped before matching. Anything else (slashes,
# whitespace, quotes, control bytes, dot-dot) is rejected.
_DIAG_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,253}$")


def _validate_diag_host(host: str) -> str:
    """Reject diagnostic targets that are not a valid hostname / IP.

    Used by ``ping`` / ``traceroute`` / ``dns_lookup``. Raises an
    HTTP 400 (via ``HTTPException``) so the operator sees a clean
    error rather than the generic ``validate_id`` "invalid X format"
    message — diagnostics callers think in hostnames, not opaque IDs.
    """
    from fastapi import HTTPException

    if not host or ".." in host or not _DIAG_HOST_RE.match(host):
        raise HTTPException(
            400,
            detail="invalid diagnostic host (must be a valid hostname or IP)",
        )
    return host


class GatewayOpnsenseDiagnosticsService(GatewayServiceBase):
    """Live reads + direct probes for OPNsense diagnostics."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def get_logs(
        self,
        controller_id: UUID,
        organization_id: UUID,
        category: str,
        count: int,
    ) -> dict[str, Any]:
        """Fetch recent log entries.

        ``category`` is one of ``system`` or ``firewall`` — the only
        log streams the OPNsense client currently exposes. Anything
        else gets a 400 from the endpoint before we land here, but we
        re-validate defensively.
        """
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            if category == "system":
                items = await client.get_system_log(count)
            elif category == "firewall":
                items = await client.get_firewall_log(count)
            else:
                # Defensive: the endpoint should already reject this.
                from fastapi import HTTPException

                raise HTTPException(
                    400,
                    detail=(f"unknown log category={category!r}; expected 'system' or 'firewall'"),
                )
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "category": category,
            "count": count,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def get_traffic_stats(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            item = await client.get_traffic_stats()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def get_arp_table(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_arp_table()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": items,
            "fetched_at": datetime.now(UTC),
        }

    async def get_ndp_table(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            items = await client.get_ndp_table()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
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
        try:
            # validate the host argument before it lands in
            # the controller-side ping body. ``host`` is validated by
            # the adapter as well, but defending at the service layer
            # closes the gap for any caller that goes around the
            # endpoint (Celery jobs, future internal callers).
            _validate_diag_host(host)
            item = await client.ping(host, count, force=True)
        finally:
            await client.close()  # Item 14
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
        try:
            # same validation as ping.
            _validate_diag_host(host)
            item = await client.traceroute(host, force=True)
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "host": host,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

    async def dns_lookup(
        self, controller_id: UUID, organization_id: UUID, hostname: str
    ) -> dict[str, Any]:
        """DNS reverse lookup. The OPNsense client uses GET for this
        endpoint, so ``force`` is unnecessary — but we keep the same
        endpoint-permission shape (``firewall:write``) as ping /
        traceroute so a reader can't probe arbitrary hostnames."""
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            # Same defensive validation as ping/traceroute. The endpoint
            # already runs ``validate_id`` on the hostname (capped at 64
            # chars) so this is a belt-and-suspenders check for service
            # callers that bypass the endpoint.
            _validate_diag_host(hostname)
            item = await client.dns_lookup(hostname)
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "hostname": hostname,
            "item": item,
            "fetched_at": datetime.now(UTC),
        }

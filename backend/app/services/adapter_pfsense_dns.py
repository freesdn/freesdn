# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense DNS service
=======================================

Read-and-stage for pfSense Unbound DNS host overrides. Mirrors
``adapter_opnsense_dns.py``: live reads, staged writes, shared apply
dispatcher.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes``.
- Apply uses the shared dispatcher in ``gateway_vpn.apply_change`` and
  the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    pfsense.dns.override   create | delete   (Unbound host A/AAAA override)
    pfsense.dns.apply      create  (reconfigure Unbound)

The applier passes ``force=True`` to the pfSense client so the write
actually reaches the firewall — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.

The pfSense client method names are ``add_dns_host_override`` /
``delete_dns_host_override`` even though the FreeSDN-side feature key
is the more generic ``pfsense.dns.override`` — the indirection lives in
the ``_APPLY`` map below.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase

# Allowlist of keys accepted on a ``pfsense.dns.override`` create
# payload. Anything outside this set is rejected at the applier so a
# corrupt staging row cannot smuggle arbitrary JSON into the pfSense
# Unbound-host endpoint. Mirrors the OPNsense pattern of validating
# at the bottom of the staging stack rather than trusting upstream.
#
# Widened to cover the full set the pfSense Unbound host_override
# endpoint accepts: ``enable`` toggles the entry, ``apply_immediately``
# triggers an inline reload, and ``mx``/``mxprio`` set MX-record
# fields when the operator wants to override an MX in addition to
# A/AAAA. Without these, legitimate operator payloads were rejected
# at the applier with a confusing 400.
_DNS_OVERRIDE_KEYS: frozenset[str] = frozenset(
    {
        "host",
        "domain",
        "ip",
        "descr",
        "aliases",
        "enable",
        "apply_immediately",
        "mx",
        "mxprio",
    }
)

# (feature, operation) → bound client method name.
_APPLY: dict[tuple[str, str], str] = {
    ("pfsense.dns.override", "create"): "add_dns_host_override",
    ("pfsense.dns.override", "delete"): "delete_dns_host_override",
    ("pfsense.dns.apply", "create"): "apply_dns_changes",
}


class GatewayPfsenseDnsService(GatewayServiceBase):
    """Live reads + staged writes for pfSense Unbound DNS config."""

    SUPPORTED_CONTROLLER_TYPE = "pfsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_overrides(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        overrides = await client.get_dns_host_overrides()
        return {
            "controller_id": controller_id,
            "items": overrides,
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` to the pfSense client so it
        satisfies the client-layer read-only check.
        """

        async def _apply(c: Any) -> Any:
            # Fast-fail BEFORE building a network client.
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )
            # ``apply`` is a one-shot commit — gate operation here so
            # accidental ``update``/``delete`` surfaces a 400 instead
            # of silently running as create.
            if c.feature == "pfsense.dns.apply" and c.operation != "create":
                raise HTTPException(
                    400,
                    detail=("pfsense.dns.apply only supports operation=create"),
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

            if c.feature == "pfsense.dns.override":
                if c.operation == "create":
                    # Reject any key outside the allowlist — pfSense
                    # Unbound expects exactly these fields, and an
                    # unexpected key in the staging payload is more
                    # likely an injection attempt than a legitimate
                    # vendor extension.
                    if not isinstance(payload, dict):
                        raise HTTPException(
                            400,
                            detail=("pfsense.dns.override create payload must be an object"),
                        )
                    extras = set(payload.keys()) - _DNS_OVERRIDE_KEYS
                    if extras:
                        raise HTTPException(
                            400,
                            detail=(
                                "pfsense.dns.override payload contains "
                                f"unsupported keys: {sorted(extras)!r} "
                                f"(allowed: {sorted(_DNS_OVERRIDE_KEYS)!r})"
                            ),
                        )
                    return await method(payload, force=True)
                if c.operation == "delete":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(
                                "delete on pfsense.dns.override requires target_id (override id)"
                            ),
                        )
                    try:
                        host_id = int(target_id)
                    except (TypeError, ValueError) as exc:
                        raise HTTPException(
                            400,
                            detail=("pfsense.dns.override target_id must be a numeric override id"),
                        ) from exc
                    return await method(host_id, force=True)
            if c.feature == "pfsense.dns.apply":
                # No payload, no target — just commit.
                return await method(force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

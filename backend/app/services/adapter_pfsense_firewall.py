# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway pfSense Firewall service
============================================

Read-and-stage for pfSense firewall rules and aliases. Mirrors the
shape of ``adapter_opnsense_firewall.py`` so the same Pending Changes
UX works for pfSense alongside OPNsense / Omada. The contract:

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    pfsense.firewall.rule       create | update | delete
    pfsense.firewall.alias      create | update | delete
    pfsense.firewall.apply      create  (commit staged config)

The applier passes ``force=True`` to the pfSense client so the write
actually reaches the firewall — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.core.adapter_result import raise_for_adapter_result
from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# (feature, operation) → bound client method name. The applier
# uses this to dispatch — same pattern Omada / OPNsense services use.
_APPLY: dict[tuple[str, str], str] = {
    # pfSense low-level client uses ``add_*`` for create.
    ("pfsense.firewall.rule", "create"): "add_firewall_rule",
    ("pfsense.firewall.rule", "update"): "update_firewall_rule",
    ("pfsense.firewall.rule", "delete"): "delete_firewall_rule",
    ("pfsense.firewall.alias", "create"): "add_alias",
    ("pfsense.firewall.alias", "update"): "update_alias",
    ("pfsense.firewall.alias", "delete"): "delete_alias",
    # ``apply`` commits the staged pfSense config (filter+aliases) to
    # the running pf ruleset. Without this the rule/alias edits sit
    # unapplied on the controller. Exposed as a feature so the operator
    # decides when the active ruleset switches.
    ("pfsense.firewall.apply", "create"): "apply_firewall_changes",
}


class GatewayPfsenseFirewallService(GatewayServiceBase):
    """Live reads + staged writes for pfSense firewall config."""

    SUPPORTED_CONTROLLER_TYPE = "pfsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_rules(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        rules = await client.get_firewall_rules()
        return {
            "controller_id": controller_id,
            "items": ([redact_secrets(r) for r in rules] if isinstance(rules, list) else rules),
            "fetched_at": datetime.now(UTC),
        }

    async def list_aliases(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        aliases = await client.get_aliases()
        return {
            "controller_id": controller_id,
            "items": (
                [redact_secrets(a) for a in aliases] if isinstance(aliases, list) else aliases
            ),
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` to the pfSense client so it
        satisfies the client-layer read-only check — that gate
        is the bottom-of-stack safety; this applier is the top of the
        sanctioned write path. The dispatcher
        (``gateway_vpn.apply_change``) is what actually opens the
        gate via ``AdapterStagingService.apply_change``'s dual-gate
        check.
        """

        async def _apply(c: Any) -> Any:
            # Fast-fail on unknown feature/operation BEFORE building
            # the network client. A typo'd feature shouldn't open a
            # TCP session to the controller.
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )

            # ``apply`` is a one-shot commit — gate operation here so
            # accidental ``update``/``delete`` on the apply feature
            # surfaces a 400 instead of dispatching as a no-op.
            if c.feature == "pfsense.firewall.apply" and c.operation != "create":
                raise HTTPException(
                    400,
                    detail=(
                        "pfsense.firewall.apply only supports operation=create (one-shot commit)"
                    ),
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

            # Dispatch by feature/operation. Each call gets force=True
            # so the read-only gate lets the write through — the
            # operator already passed force=true at the apply
            # endpoint, which is the high-level dual-gate.
            if c.feature == "pfsense.firewall.rule":
                if c.operation == "create":
                    result = await method(payload, force=True)
                    # Auto-apply: a created rule is invisible until the
                    # filter ruleset is committed. Operators expect a
                    # single staged change to take effect after apply,
                    # not require a second ``firewall.apply`` change.
                    # A failed write must NOT commit the ruleset or be marked
                    # "applied" by the staging framework (which only checks for a
                    # raised exception, not result.success) — raise on failure.
                    raise_for_adapter_result(result)
                    await client.apply_firewall_changes(force=True)
                    return result
                # pfSense firewall rules are addressed by INTEGER id.
                # The staging table carries ``target_id`` as a string;
                # mirror the NAT/DHCP/DNS appliers and cast here so a
                # malformed value (alpha, ``"1; DELETE"``, …) is
                # caught at the FreeSDN edge with a clear 400, not at
                # the controller as an opaque API error.
                if c.operation in ("update", "delete"):
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(
                                f"{c.operation} on pfsense.firewall.rule "
                                "requires target_id (rule id)"
                            ),
                        )
                    try:
                        rule_id = int(target_id)
                    except (TypeError, ValueError) as exc:
                        raise HTTPException(
                            400,
                            detail=("pfsense.firewall.rule target_id must be a numeric rule id"),
                        ) from exc
                    if c.operation == "update":
                        result = await method(rule_id, payload, force=True)
                    else:
                        result = await method(rule_id, force=True)
                    # A failed write must NOT commit the ruleset or be marked
                    # "applied" by the staging framework (which only checks for a
                    # raised exception, not result.success) — raise on failure.
                    raise_for_adapter_result(result)
                    await client.apply_firewall_changes(force=True)
                    return result
            if c.feature == "pfsense.firewall.alias":
                if c.operation == "create":
                    result = await method(payload, force=True)
                    # Apply: alias must commit before subsequent rule
                    # writes can reference it.
                    # A failed write must NOT commit the ruleset or be marked
                    # "applied" by the staging framework (which only checks for a
                    # raised exception, not result.success) — raise on failure.
                    raise_for_adapter_result(result)
                    await client.apply_firewall_changes(force=True)
                    return result
                if c.operation in ("update", "delete"):
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail=(
                                f"{c.operation} on pfsense.firewall.alias "
                                "requires target_id (alias name)"
                            ),
                        )
                    if c.operation == "update":
                        result = await method(target_id, payload, force=True)
                    else:
                        result = await method(target_id, force=True)
                    # A failed write must NOT commit the ruleset or be marked
                    # "applied" by the staging framework (which only checks for a
                    # raised exception, not result.success) — raise on failure.
                    raise_for_adapter_result(result)
                    await client.apply_firewall_changes(force=True)
                    return result
            if c.feature == "pfsense.firewall.apply":
                # No payload, no target — just commit.
                return await method(force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

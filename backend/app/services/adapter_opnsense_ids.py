# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense IDS/IPS (Suricata) service
=======================================================

Read-and-stage for OPNsense Suricata IDS/IPS settings, rules, and
alerts. Mirrors the shape of ``adapter_opnsense_firewall.py`` so the
same Pending Changes UX works for Suricata.

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    opnsense.ids.settings        update           (full settings blob)
    opnsense.ids.rule_enable     create           (target_id = rule SID)
    opnsense.ids.rule_disable    create           (target_id = rule SID)
    opnsense.ids.alert_drop      create           (truncate alert log)
    opnsense.ids.apply           create           (commit staged config)

The applier passes ``force=True`` to the OPNsense client so the write
actually reaches the controller — every write outside the applier is
refused at the client layer by the ``ADAPTER_READ_ONLY`` gate.

Notes on shape:
- The OPNsense Suricata API exposes ``toggleRule/{sid}/{0|1}`` rather
  than separate enable/disable verbs and has no per-rule ``setRule``.
  We expose enable/disable as two distinct features so the audit log
  records intent clearly. ``opnsense.ids.rule`` (free-form update) is
  intentionally omitted — the controller does not support it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.adapters.validation import validate_id
from app.services.adapter_base import GatewayServiceBase

# (feature, operation) → bound client method name. The applier
# uses this to dispatch — same pattern other OPNsense services use.
# rule_enable / rule_disable both resolve to ``toggle_ids_rule`` but
# the applier picks the right ``enabled`` boolean based on the feature.
_APPLY: dict[tuple[str, str], str] = {
    ("opnsense.ids.settings", "update"): "update_ids_settings",
    ("opnsense.ids.rule_enable", "create"): "toggle_ids_rule",
    ("opnsense.ids.rule_disable", "create"): "toggle_ids_rule",
    ("opnsense.ids.alert_drop", "create"): "drop_ids_alert_log",
    ("opnsense.ids.apply", "create"): "apply_ids_changes",
}


class GatewayOpnsenseIdsService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense Suricata config."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def get_settings(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            settings = await client.get_ids_settings()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "settings": settings,
            "fetched_at": datetime.now(UTC),
        }

    async def list_rules(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            rules = await client.get_ids_rules()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": rules,
            "fetched_at": datetime.now(UTC),
        }

    async def list_alerts(self, controller_id: UUID, organization_id: UUID) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
        client = await self._get_client(ctrl)
        try:
            alerts = await client.get_ids_alerts()
        finally:
            await client.close()  # Item 14
        return {
            "controller_id": controller_id,
            "items": alerts,
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
                if c.feature == "opnsense.ids.settings":
                    # Settings update takes the full payload as the body.
                    return await method(payload, force=True)
                if c.feature == "opnsense.ids.rule_enable":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail="opnsense.ids.rule_enable requires target_id (rule SID)",
                        )
                    # re-validate the SID at apply-time. The
                    # endpoint validates at stage-time, but a malicious
                    # apply could craft a row with a tampered SID.
                    validate_id(str(target_id), label="ids_sid")
                    return await method(target_id, True, force=True)
                if c.feature == "opnsense.ids.rule_disable":
                    if not target_id:
                        raise HTTPException(
                            400,
                            detail="opnsense.ids.rule_disable requires target_id (rule SID)",
                        )
                    # same re-validation as rule_enable.
                    validate_id(str(target_id), label="ids_sid")
                    return await method(target_id, False, force=True)
                if c.feature == "opnsense.ids.alert_drop":
                    # No payload, no target — just drop the log.
                    return await method(force=True)
                if c.feature == "opnsense.ids.apply":
                    # No payload, no target — just commit.
                    return await method(force=True)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                await client.close()  # Item 14

        return _apply

# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OpenWrt Firewall service
===========================================

Read-and-stage for OpenWrt firewall + port-forward + source-NAT writes.
Mirrors the pfSense/MikroTik per-domain pattern so the same Pending
Changes drawer works for OpenWrt alongside the other vendors. Contract:

- Reads run live (already exposed by ``adapter_openwrt`` umbrella).
- Writes are STAGED in ``adapter_pending_changes`` (vendor-agnostic
  table — name is historical).
- Apply uses the shared ``/gateway-vpn/changes/{id}/apply`` dispatcher
  which routes ``openwrt.firewall.*`` features into this service's
  ``build_applier``.

Supported features::

    openwrt.firewall.rule           create | update | delete
    openwrt.firewall.port_forward   create | update | delete
    openwrt.firewall.source_nat     create | update | delete

OpenWrt's adapter does *not* have a separate ``force=True`` read-only
gate at the client layer — the read-only check lives in
``AdapterStagingService.apply_change`` (the dispatcher's dual-gate).
So unlike pfSense we don't need to thread ``force`` through every call.

The adapter already commits + restarts the firewall service after each
write (``uci_commit firewall; /etc/init.d/firewall reload``), so there
is no separate ``openwrt.firewall.apply`` feature — each staged change
is self-applying once the dispatcher invokes it.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase

# (feature, operation) → bound adapter method name. Applier dispatches
# through this table — same pattern used by the pfSense/Omada services.
_APPLY: dict[tuple[str, str], str] = {
    ("openwrt.firewall.rule", "create"): "create_firewall_rule",
    ("openwrt.firewall.rule", "update"): "update_firewall_rule",
    ("openwrt.firewall.rule", "delete"): "delete_firewall_rule",
    ("openwrt.firewall.port_forward", "create"): "create_port_forward",
    ("openwrt.firewall.port_forward", "update"): "update_port_forward",
    ("openwrt.firewall.port_forward", "delete"): "delete_port_forward",
    ("openwrt.firewall.source_nat", "create"): "create_source_nat_rule",
    ("openwrt.firewall.source_nat", "update"): "update_source_nat_rule",
    ("openwrt.firewall.source_nat", "delete"): "delete_source_nat_rule",
}

# (feature) → (list-method name, key in returned data dict). Used by
# the applier to verify ``target_id`` actually exists on the resolved
# controller BEFORE invoking update/delete. Closes the IDOR:
# without this, ``target_id`` is opaque FE input that flows
# straight to the adapter — an operator who guesses or enumerates a
# UCI section name belonging to another controller can update/delete
# it because the firewall:write check alone doesn't bind the target
# to any specific controller.
_LIST_FOR_VERIFY: dict[str, tuple[str, str]] = {
    "openwrt.firewall.rule": ("get_firewall_rules", "rules"),
    "openwrt.firewall.port_forward": ("get_port_forwards", "port_forwards"),
    "openwrt.firewall.source_nat": ("get_source_nat_rules", "rules"),
}


async def _verify_target_owned(
    client: Any,
    feature: str,
    target_id: str,
) -> str:
    """Verify ``target_id`` lives on this controller AND return its
    resolved UCI section name.

    Two responsibilities in one fetch — the verify call has to fetch
    the live list anyway, so returning the matched ``uci_name`` lets
    the adapter skip its own redundant ``uci_get_all``. Saves one
    full-tree fetch per write — meaningful for
    bulk operations.

    Raises 404 if the target isn't found. Raises 502 if we can't
    fetch the live list — we'd rather fail closed than dispatch a
    write whose target we couldn't verify.
    """
    pair = _LIST_FOR_VERIFY.get(feature)
    if pair is None:
        raise HTTPException(
            501,
            detail=(
                f"no verify-list mapping for feature={feature!r}; "
                "refuse write until target ownership can be checked"
            ),
        )
    list_method_name, items_key = pair
    list_method = getattr(client, list_method_name, None)
    if list_method is None:
        raise HTTPException(
            501,
            detail=(
                f"OpenWrt adapter missing {list_method_name!r} — cannot verify target ownership"
            ),
        )
    result = await list_method()
    if getattr(result, "success", True) is False:
        raise HTTPException(
            502,
            detail=(
                f"could not fetch live {feature} list to verify "
                f"target_id={target_id!r}: "
                f"{getattr(result, 'error', 'unknown error')}"
            ),
        )
    data = getattr(result, "data", None) or {}
    items = data.get(items_key, []) if isinstance(data, dict) else []
    target_str = str(target_id)
    for item in items:
        if not isinstance(item, dict):
            continue
        if str(item.get("id")) == target_str or str(item.get("uci_name")) == target_str:
            uci_name = item.get("uci_name")
            if not isinstance(uci_name, str) or not uci_name:
                # Item matched but has no uci_name — shouldn't happen
                # for normal UCI sections; fail closed.
                raise HTTPException(
                    500,
                    detail=(f"target {target_id!r} matched but is missing a uci_name field"),
                )
            return uci_name
    # 404 not 403 — we don't want to leak "exists on another
    # controller" by varying the code.
    raise HTTPException(
        404,
        detail=(f"target_id={target_id!r} not found on this controller for feature={feature!r}"),
    )


def _unwrap(result: Any) -> dict[str, Any]:
    """Coerce an AdapterResult into a plain dict, raising on failure."""
    if result is None:
        raise HTTPException(502, detail="adapter returned no result")
    if getattr(result, "success", True) is False:
        raise HTTPException(
            502,
            detail=getattr(result, "error", None) or "adapter call failed",
        )
    return {
        "success": True,
        "message": getattr(result, "message", None),
        "data": getattr(result, "data", None),
    }


class GatewayOpenWrtFirewallService(GatewayServiceBase):
    """Staged-write surface for OpenWrt firewall + NAT."""

    SUPPORTED_CONTROLLER_TYPE = "openwrt"

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        The apply path's dual-gate (``ADAPTER_READ_ONLY=false`` AND
        ``force=true`` at the apply endpoint) has already authorised
        the write by the time this runs. Each adapter call commits +
        reloads the firewall service on the OpenWrt box on success.
        """

        async def _apply(c: Any) -> Any:
            method_name = _APPLY.get((c.feature, c.operation))
            if method_name is None:
                raise HTTPException(
                    400,
                    detail=(f"no applier for feature={c.feature!r} operation={c.operation!r}"),
                )

            # update/delete require an addressable target.
            if c.operation in ("update", "delete") and not c.target_id:
                raise HTTPException(
                    400,
                    detail=(
                        f"{c.operation} on {c.feature} requires target_id "
                        "(UCI section name or stable UUID)"
                    ),
                )

            ctrl = await self._resolve_controller_or_gateway(
                c.controller_id,
                c.organization_id,
            )
            client = await self._get_adapter(ctrl)
            method = getattr(client, method_name, None)
            if method is None:
                raise HTTPException(
                    501,
                    detail=(
                        f"OpenWrt adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            payload = c.payload or {}
            if c.operation == "create":
                result = await method(payload)
            elif c.operation == "update":
                # Verify the target lives on this controller AND
                # capture its resolved UCI section name so the adapter
                # can skip its own redundant ``uci_get_all`` lookup.
                uci_name = await _verify_target_owned(
                    client,
                    c.feature,
                    c.target_id,
                )
                result = await method(
                    c.target_id,
                    payload,
                    uci_name=uci_name,
                )
            else:  # delete
                uci_name = await _verify_target_owned(
                    client,
                    c.feature,
                    c.target_id,
                )
                # ``delete_firewall_rule`` uses ``resolved_uci_name``
                # (single positional `uci_name` arg is already the
                # input); the other deletes take ``uci_name=`` kwarg.
                if c.feature == "openwrt.firewall.rule":
                    result = await method(
                        c.target_id,
                        resolved_uci_name=uci_name,
                    )
                else:
                    result = await method(c.target_id, uci_name=uci_name)
            return _unwrap(result)

        return _apply

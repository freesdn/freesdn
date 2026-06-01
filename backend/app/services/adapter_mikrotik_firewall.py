# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway MikroTik Firewall service
=============================================

Read-and-stage for RouterOS firewall configuration: the three classic
chains (filter / NAT / mangle) plus address lists. Mirrors the shape
of ``adapter_opnsense_firewall.py`` so the same Pending Changes UX
works for MikroTik alongside OPNsense / pfSense / Omada. The contract
for every vendor is identical:

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

A managed MikroTik may be carrying PRODUCTION traffic, so this service
is the ONLY sanctioned write path. Every other entry point (raw client.post,
ad-hoc scripts, accidental code) is refused at the client layer by
the universal ``ADAPTER_READ_ONLY`` gate. The applier passes
``force=True`` because the operator already cleared the high-level
``force=true`` gate on the apply endpoint.

Supported features::

    mikrotik.firewall.filter_rule    create | update | delete
    mikrotik.firewall.filter_toggle  create  (target_id=rule id, payload {enabled: bool})
    mikrotik.firewall.nat_rule       create | update | delete
    mikrotik.firewall.mangle_rule    create | update | delete
    mikrotik.firewall.address_list   create | delete
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# (feature, operation) → bound MikroTik client method name. The
# applier looks up the method here and dispatches by feature shape.
# Only what the underlying client actually exposes is wired in;
# missing methods would raise 501 at apply time.
_APPLY: dict[tuple[str, str], str] = {
    # Filter chain — full CRUD.
    ("mikrotik.firewall.filter_rule", "create"): "add_firewall_filter_rule",
    ("mikrotik.firewall.filter_rule", "update"): "update_firewall_filter_rule",
    ("mikrotik.firewall.filter_rule", "delete"): "delete_firewall_filter_rule",
    # Filter toggle — special op that flips ``disabled``. ``create`` is
    # the only op shape (target_id=rule id, payload={"enabled": bool}).
    # The applier inspects the payload to pick enable vs disable.
    ("mikrotik.firewall.filter_toggle", "create"): "enable_firewall_filter_rule",
    # Filter reorder — emits a sequence of /ip/firewall/filter/move
    # calls to reposition the ordered ID list.
    ("mikrotik.firewall.filter_reorder", "update"): "move_firewall_filter_rule",
    # NAT chain — full CRUD.
    ("mikrotik.firewall.nat_rule", "create"): "add_firewall_nat_rule",
    ("mikrotik.firewall.nat_rule", "update"): "update_firewall_nat_rule",
    ("mikrotik.firewall.nat_rule", "delete"): "delete_firewall_nat_rule",
    # Mangle chain — full CRUD.
    ("mikrotik.firewall.mangle_rule", "create"): "add_firewall_mangle_rule",
    ("mikrotik.firewall.mangle_rule", "update"): "update_firewall_mangle_rule",
    ("mikrotik.firewall.mangle_rule", "delete"): "delete_firewall_mangle_rule",
    # Address lists — RouterOS analogue of OPNsense aliases. The
    # adapter exposes add+delete only (no native update; entries are
    # immutable on RouterOS — operators delete+re-add).
    ("mikrotik.firewall.address_list", "create"): "add_firewall_address_list",
    ("mikrotik.firewall.address_list", "delete"): "delete_firewall_address_list",
}

# (feature) → list-method name on the client. Used by the IDOR guard
# below to fetch the live items for a feature and verify ``target_id``
# is in the set BEFORE we let an update/delete dispatch into the
# adapter. RouterOS PATCH /ip/firewall/filter/{id} accepts ANY ``.id``
# value — if an operator can guess or enumerate an id from another
# tenant's box, they could update/delete it. The org check at
# ``_resolve_controller_or_gateway`` already binds the request to the
# operator's controller; this guard binds ``target_id`` to that
# controller's actual config.
_LIST_FOR_VERIFY: dict[str, str] = {
    "mikrotik.firewall.filter_rule": "get_firewall_filter_rules",
    "mikrotik.firewall.filter_toggle": "get_firewall_filter_rules",
    "mikrotik.firewall.filter_reorder": "get_firewall_filter_rules",
    "mikrotik.firewall.nat_rule": "get_firewall_nat_rules",
    "mikrotik.firewall.mangle_rule": "get_firewall_mangle_rules",
    "mikrotik.firewall.address_list": "get_firewall_address_lists",
}


async def _verify_target_owned(
    client: Any,
    feature: str,
    target_id: str,
) -> None:
    """Verify ``target_id`` (RouterOS ``.id``) actually lives on this
    controller. Closes the IDOR — without this,
    ``target_id`` is opaque FE input that the applier interpolates
    straight into a RouterOS REST URL.

    Raises 404 if not found (matches RouterOS's own behaviour for a
    missing id), 502 if we couldn't fetch the live list to verify.
    """
    list_method_name = _LIST_FOR_VERIFY.get(feature)
    if list_method_name is None:
        raise HTTPException(
            501,
            detail=(
                f"no verify-list mapping for feature={feature!r}; "
                "refuse write until target ownership can be checked"
            ),
        )
    list_method = getattr(client, list_method_name, None)
    if list_method is None:
        raise HTTPException(
            501,
            detail=(
                f"MikroTik adapter missing {list_method_name!r} — cannot verify target ownership"
            ),
        )
    try:
        items = await list_method()
    except Exception as exc:
        raise HTTPException(
            502,
            detail=(
                f"could not fetch live {feature} list to verify target_id={target_id!r}: {exc}"
            ),
        ) from exc
    if not isinstance(items, list):
        raise HTTPException(
            502,
            detail=(
                f"unexpected response shape from {list_method_name!r} "
                f"while verifying target_id={target_id!r}"
            ),
        )
    target_str = str(target_id)
    found = any(
        isinstance(item, dict) and str(item.get(".id") or item.get("id")) == target_str
        for item in items
    )
    if not found:
        raise HTTPException(
            404,
            detail=(
                f"target_id={target_id!r} not found on this controller for feature={feature!r}"
            ),
        )


class GatewayMikrotikFirewallService(GatewayServiceBase):
    """Live reads + staged writes for RouterOS firewall config."""

    SUPPORTED_CONTROLLER_TYPE = "mikrotik"

    # ── Live reads ───────────────────────────────────────────────────

    # Defensive redaction on every read response: rule comments
    # routinely contain operator notes with credentials, ticket
    # references, or temporary passwords ("temp pass: hunter2 — DEL
    # ON FRIDAY"). The shared redactor masks anything matching the
    # sensitive-key allowlist and is harmless on rule rows that
    # don't contain such fields.

    async def list_filter_rules(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        items = await client.get_firewall_filter_rules()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_nat_rules(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        items = await client.get_firewall_nat_rules()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_mangle_rules(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        items = await client.get_firewall_mangle_rules()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    async def list_address_lists(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        is_superuser: bool = False,
    ) -> dict[str, Any]:
        ctrl = await self._resolve_controller_or_gateway(
            controller_id, organization_id, is_superuser=is_superuser
        )
        client = await self._get_client(ctrl)
        items = await client.get_firewall_address_lists()
        return {
            "controller_id": controller_id,
            "items": [redact_secrets(i) for i in items],
            "fetched_at": datetime.now(UTC),
        }

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` so the client-layer
        read-only gate lets the write through. The dispatcher
        (``gateway_vpn.apply_change``) opens the high-level gate via
        ``AdapterStagingService.apply_change``'s dual-gate check; this
        applier is what actually translates the staged record into
        adapter calls.
        """

        async def _apply(c: Any) -> Any:
            ctrl = await self._resolve_controller_or_gateway(c.controller_id, c.organization_id)
            client = await self._get_client(ctrl)
            payload = c.payload or {}
            target_id = c.target_id

            # ``filter_reorder`` is the special case where one staged
            # change emits *many* adapter calls. RouterOS /move takes
            # ``numbers`` (rule id) + ``destination`` (rule id to land
            # before); we walk the operator-supplied ordered list and
            # land each rule before the next, then explicitly move
            # the last entry to the end of the chain (no destination).
            if c.feature == "mikrotik.firewall.filter_reorder":
                if c.operation != "update":
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} only supports the 'update' "
                            f"operation (got {c.operation!r})"
                        ),
                    )
                order = payload.get("order")
                if not isinstance(order, list) or not order:
                    raise HTTPException(
                        400,
                        detail=(
                            f"{c.feature!r} payload requires a non-empty 'order' array of rule IDs"
                        ),
                    )
                if not all(isinstance(item, str) and item for item in order):
                    raise HTTPException(
                        400,
                        detail=(f"{c.feature!r} 'order' must contain only non-empty string IDs"),
                    )
                # Resolve the move method locally — the generic
                # ``method = getattr(client, ...)`` lookup below the
                # special-cased branches has not run yet at this
                # point in the dispatch.
                move = getattr(client, "move_firewall_filter_rule", None)
                if move is None:
                    raise HTTPException(
                        501,
                        detail=(
                            "MikroTik adapter has no method "
                            "'move_firewall_filter_rule'; missing "
                            "implementation"
                        ),
                    )
                # Issue the move calls sequentially. After each move
                # the chain renumbers; using the operator-supplied IDs
                # rather than positions sidesteps that. The last
                # entry has no ``destination`` → moves to end.
                # IDOR guard: every rid in ``order`` must live on this
                # controller before we issue any /move. One bad rid
                # would otherwise interpolate into a RouterOS URL on
                # the controller the operator selected — but ``order``
                # is FE-supplied and unvalidated until now.
                for rid in order:
                    await _verify_target_owned(
                        client,
                        "mikrotik.firewall.filter_reorder",
                        rid,
                    )
                results: list[Any] = []
                for idx, rid in enumerate(order):
                    if idx < len(order) - 1:
                        next_rid = order[idx + 1]
                        results.append(await move(rid, next_rid, force=True))
                    else:
                        # Last rule — drop ``destination`` so RouterOS
                        # places it at the chain tail.
                        results.append(await move(rid, None, force=True))
                return {"moved": len(results), "results": results}

            # ``filter_toggle`` is the one feature where the method
            # depends on the payload — pick enable vs disable up front
            # so the rest of the dispatcher can stay shape-uniform.
            if c.feature == "mikrotik.firewall.filter_toggle":
                if c.operation != "create":
                    raise HTTPException(
                        400,
                        detail=(
                            "filter_toggle only supports operation='create' "
                            "(payload {enabled: bool})"
                        ),
                    )
                if not target_id:
                    raise HTTPException(
                        400,
                        detail="filter_toggle requires target_id (rule id)",
                    )
                enabled = bool(payload.get("enabled", False))
                method_name = (
                    "enable_firewall_filter_rule" if enabled else "disable_firewall_filter_rule"
                )
                method = getattr(client, method_name, None)
                if method is None:
                    raise HTTPException(
                        501,
                        detail=(
                            f"MikroTik adapter has no method {method_name!r}; "
                            "missing implementation"
                        ),
                    )
                # IDOR guard before we let target_id reach the URL bus.
                await _verify_target_owned(client, c.feature, target_id)
                return await method(target_id, force=True)

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
                        f"MikroTik adapter has no method {method_name!r}; missing implementation"
                    ),
                )

            # Universal target_id guard — RouterOS PATCH/DELETE on a
            # missing id would interpolate ``None`` into the URL path.
            if c.operation in ("update", "delete") and not target_id:
                raise HTTPException(
                    400,
                    detail=(f"feature {c.feature!r} requires a target_id for {c.operation!r}"),
                )

            # Filter / NAT / mangle rules share the same CRUD shape:
            # create takes the rule dict, update takes (id, dict),
            # delete takes id.
            if c.feature in (
                "mikrotik.firewall.filter_rule",
                "mikrotik.firewall.nat_rule",
                "mikrotik.firewall.mangle_rule",
            ):
                if c.operation == "create":
                    return await method(payload, force=True)
                # IDOR guard for update/delete — verify the rule lives
                # on this controller before we interpolate the id into
                # a RouterOS REST URL.
                await _verify_target_owned(client, c.feature, target_id)
                if c.operation == "update":
                    return await method(target_id, payload, force=True)
                if c.operation == "delete":
                    return await method(target_id, force=True)
            # Address-list entries: create takes (list_name, address,
            # **kw); delete takes the entry id.
            if c.feature == "mikrotik.firewall.address_list":
                if c.operation == "create":
                    list_name = payload.get("list") or payload.get("list_name")
                    address = payload.get("address")
                    if not list_name or not address:
                        raise HTTPException(
                            400,
                            detail=("address_list create requires payload {list, address}"),
                        )
                    # Drop ``force`` from the spread — applier
                    # already passes force=True explicitly; a
                    # collision would raise TypeError.
                    extra = {
                        k: v
                        for k, v in payload.items()
                        if k not in {"list", "list_name", "address", "force"}
                    }
                    return await method(list_name, address, force=True, **extra)
                if c.operation == "delete":
                    # IDOR guard — RouterOS address_list /delete
                    # accepts any .id; verify it belongs to this box.
                    await _verify_target_owned(
                        client,
                        c.feature,
                        target_id,
                    )
                    return await method(target_id, force=True)
            raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")

        return _apply

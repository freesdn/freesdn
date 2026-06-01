# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Gateway OPNsense Firewall service
=============================================

Read-and-stage for OPNsense firewall rules and aliases. Mirrors the
shape of ``gateway_firewall.py`` (Omada) so the same Pending Changes
UX works for both vendors. The contract for both:

- Reads run live against the controller.
- Writes are STAGED in ``core.adapter_pending_changes`` (table is
  vendor-agnostic despite the historical name).
- Apply uses the existing dispatcher in ``gateway_vpn.apply_change``
  and the dual-gate (``ADAPTER_READ_ONLY=false`` AND ``force=true``).

Supported features::

    opnsense.firewall.rule       create | update | delete
    opnsense.firewall.alias      create | update | delete
    opnsense.firewall.apply      create  (commit staged config)

The applier passes ``force=True`` to the OPNsense client so the
write actually reaches the controller — every write outside the
applier is refused at the client layer by the
``ADAPTER_READ_ONLY`` gate.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import HTTPException

from app.services.adapter_base import GatewayServiceBase
from app.services.adapter_redaction import redact_secrets

# In-memory TTL cache for live reads. Firewall rule/alias listings
# are called from the UI on every page-render and the OPNsense
# ``searchRule`` endpoint is one of the slowest in the API
# (it iterates over the entire pf table on the box). A 10-second
# cache keyed by ``(controller_id, method)`` collapses that to one
# fetch per page-load even when 6 panels mount in parallel.
#
# The cache is invalidated whenever a ``firewall.apply`` runs (the
# applier closure clears the keys for that controller) so a fresh
# write is always visible immediately after apply, not after the
# TTL expires.
_TTL = 10.0
_LIST_CACHE: dict[str, tuple[float, Any]] = {}


def _cache_key(controller_id: UUID, method: str) -> str:
    return f"{controller_id}:{method}"


def _cache_get(controller_id: UUID, method: str) -> Any | None:
    entry = _LIST_CACHE.get(_cache_key(controller_id, method))
    if entry is None:
        return None
    expires_at, value = entry
    if expires_at < time.monotonic():
        # Expired — drop the stale entry so the cache doesn't grow
        # unbounded over the process lifetime.
        _LIST_CACHE.pop(_cache_key(controller_id, method), None)
        return None
    return value


def _cache_put(controller_id: UUID, method: str, value: Any) -> None:
    _LIST_CACHE[_cache_key(controller_id, method)] = (
        time.monotonic() + _TTL,
        value,
    )


def _cache_invalidate(controller_id: UUID) -> None:
    """Drop every cached entry for ``controller_id``.

    Called from the applier closure after a successful
    ``firewall.apply`` so the next read sees the freshly-applied
    ruleset, not the pre-apply snapshot.
    """
    prefix = f"{controller_id}:"
    stale = [k for k in _LIST_CACHE if k.startswith(prefix)]
    for k in stale:
        _LIST_CACHE.pop(k, None)


def _paginate(payload: dict[str, Any], *, limit: int, offset: int) -> dict[str, Any]:
    """Slice ``payload['items']`` to a window and surface counts.

    Returns a NEW dict so the cached payload stays intact for the
    next caller. The shape mirrors the un-paginated response with
    extra ``total``/``limit``/``offset`` fields for the UI.
    """
    items = payload.get("items") or []
    if not isinstance(items, list):
        # Some OPNsense endpoints return a dict keyed by uuid; punt
        # on slicing that shape to avoid silently dropping records.
        return payload
    total = len(items)
    sliced = items[offset : offset + limit]
    return {
        **payload,
        "items": sliced,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# (feature, operation) → bound client method name. The applier
# uses this to dispatch — same pattern Omada services use.
_APPLY: dict[tuple[str, str], str] = {
    # OPNsense low-level client uses ``add_*`` for create.
    ("opnsense.firewall.rule", "create"): "add_firewall_rule",
    ("opnsense.firewall.rule", "update"): "update_firewall_rule",
    ("opnsense.firewall.rule", "delete"): "delete_firewall_rule",
    ("opnsense.firewall.alias", "create"): "add_alias",
    ("opnsense.firewall.alias", "update"): "update_alias",
    ("opnsense.firewall.alias", "delete"): "delete_alias",
    # ``apply`` commits the staged OPNsense config (filter+aliases)
    # to the running pf ruleset. Without this the rule/alias edits
    # sit unapplied on the controller. Exposed as a feature so the
    # operator decides when the active ruleset switches.
    ("opnsense.firewall.apply", "create"): "apply_firewall_changes",
}


class GatewayOpnsenseFirewallService(GatewayServiceBase):
    """Live reads + staged writes for OPNsense firewall config."""

    SUPPORTED_CONTROLLER_TYPE = "opnsense"

    # ── Live reads ───────────────────────────────────────────────────

    async def list_rules(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> dict[str, Any]:
        # Serve from the 10s TTL cache when available; the OPNsense
        # ``searchRule`` endpoint is expensive on large rule sets.
        # Cache the FULL result, slice per-call so the cache stays
        # warm across paginated UI scrolls.
        cached = _cache_get(controller_id, "list_rules")
        if cached is None:
            ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
            client = await self._get_client(ctrl)
            # deterministically close the httpx session.
            try:
                rules = await client.get_firewall_rules()
            finally:
                await client.close()
            cached = {
                "controller_id": controller_id,
                "items": ([redact_secrets(r) for r in rules] if isinstance(rules, list) else rules),
                "fetched_at": datetime.now(UTC),
            }
            _cache_put(controller_id, "list_rules", cached)
        return _paginate(cached, limit=limit, offset=offset)

    async def list_aliases(
        self,
        controller_id: UUID,
        organization_id: UUID,
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> dict[str, Any]:
        cached = _cache_get(controller_id, "list_aliases")
        if cached is None:
            ctrl = await self._resolve_controller_or_gateway(controller_id, organization_id)
            client = await self._get_client(ctrl)
            try:
                aliases = await client.get_aliases()
            finally:
                await client.close()
            cached = {
                "controller_id": controller_id,
                "items": (
                    [redact_secrets(a) for a in aliases] if isinstance(aliases, list) else aliases
                ),
                "fetched_at": datetime.now(UTC),
            }
            _cache_put(controller_id, "list_aliases", cached)
        return _paginate(cached, limit=limit, offset=offset)

    # ── Apply path ───────────────────────────────────────────────────

    def build_applier(self, change: Any) -> Any:
        """Return an awaitable that pushes ``change`` to the controller.

        Every call passes ``force=True`` to the OPNsense client so it
        satisfies the client-layer read-only check — that gate
        is the bottom-of-stack safety; this applier is the top of the
        sanctioned write path. The dispatcher
        (``gateway_vpn.apply_change``) is what actually opens the
        gate via ``AdapterStagingService.apply_change``'s dual-gate
        check.
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
                #
                # target_id is REQUIRED for update/delete; without it
                # the OPNsense client would interpolate ``None`` into
                # the URL path. — pfSense
                # already enforced this, OPNsense didn't.
                if (
                    c.operation in ("update", "delete")
                    and c.feature
                    in (
                        "opnsense.firewall.rule",
                        "opnsense.firewall.alias",
                    )
                    and not target_id
                ):
                    raise HTTPException(
                        400,
                        detail=(f"{c.operation} on {c.feature} requires target_id"),
                    )
                if c.feature == "opnsense.firewall.rule":
                    if c.operation == "create":
                        return await method(payload, force=True)
                    if c.operation == "update":
                        return await method(target_id, payload, force=True)
                    if c.operation == "delete":
                        return await method(target_id, force=True)
                if c.feature == "opnsense.firewall.alias":
                    if c.operation == "create":
                        return await method(payload, force=True)
                    if c.operation == "update":
                        return await method(target_id, payload, force=True)
                    if c.operation == "delete":
                        return await method(target_id, force=True)
                if c.feature == "opnsense.firewall.apply":
                    # No payload, no target — just commit. Drop every
                    # cached rule/alias listing for this controller so
                    # the next read sees the freshly-applied ruleset.
                    try:
                        return await method(force=True)
                    finally:
                        _cache_invalidate(c.controller_id)
                raise HTTPException(400, detail=f"unhandled feature={c.feature!r}")
            finally:
                # close the httpx pool deterministically.
                await client.close()

        return _apply

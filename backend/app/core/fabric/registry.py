# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN Fabric — the unified, tier-tagged Operation/Event registry.

The registry is the single discovery point for "what can each app do (Operations)
and emit (Events)" across the platform. It collapses the four previously-separate
"services" surfaces into one catalog:

  * **native** operations/events — declared by in-tree modules via the new
    ``BaseModule.get_operations()`` / ``get_emitted_events()`` hooks (discovered
    with no central registration, exactly like ``get_backup_contributor()``).
  * **plugin** operations/events — declared by external apps through the existing
    ``PluginAutomationBridge`` (already namespaced ``plugin.{id}.*``,
    permission-declared, MAX_*-limited); projected here tagged ``tier=plugin``.
  * a read-only **projection of the AI tool registry** so the catalog shows the
    AI assistant's tools as part of the same unified surface (the convergence
    target; not yet rewired in this phase).

Phase-0 contract: discovery is **on-demand and side-effect-free** — calling the
registry never mutates module/plugin/AI state, so it cannot change current
behavior. Imports of the module registry / plugin bridge / AI registry are
**lazy** (inside the methods) to keep this module import-safe even though
``app.modules.base`` is imported very early in the boot sequence.
"""

from __future__ import annotations

import logging
from typing import Any

from app.core.fabric.operations import EventSpec, Operation, OperationTier

logger = logging.getLogger(__name__)

# Sentinel: lets ``compatible_targets(event=...)`` accept a caller-supplied event
# (possibly ``None`` for an unknown event) WITHOUT re-discovering it, while still
# defaulting to an internal lookup when the caller passes nothing.
_UNSET: Any = object()

# Discovery is cheap (in-memory module/plugin walks) but NOT free: rebuilding the
# whole catalog — reconstructing every frozen Operation/EventSpec with its
# __post_init__ regex validation — on every get_operation() call is wasteful on
# the hot path (the negotiator calls get_operation per step, per firing). A tiny
# TTL cache collapses that to one rebuild per window; a newly started/stopped
# plugin becomes visible within the TTL (an acceptable bound vs the per-call cost).
_CATALOG_TTL_SECONDS = 3.0


class FabricRegistry:
    """Discovers Fabric operations + events across native modules and plugins.

    Discovery is re-run from the live module/plugin registries behind a short TTL
    cache (so the catalog reflects a plugin start/stop within ~3s) — keeping the
    hot dispatch path (per-step get_operation) from rebuilding the whole catalog
    every call. ``_native()``/``_plugin()`` are synchronous (no awaits), so the
    cache read-or-rebuild is atomic within the event loop (no lock needed).
    """

    def __init__(self) -> None:
        self._cache_at = 0.0
        self._cache_ops: dict[str, Operation] | None = None
        self._cache_events: dict[str, EventSpec] | None = None

    def invalidate(self) -> None:
        """Drop the discovery cache so the next query re-discovers immediately.

        Call after a plugin/module start/stop to surface the change at once rather
        than waiting out the TTL (and used by tests that swap the module/plugin set).
        """
        self._cache_ops = None
        self._cache_events = None
        self._cache_at = 0.0

    def _discover(self) -> tuple[dict[str, Operation], dict[str, EventSpec]]:
        """Merged native+plugin catalog, cached for ``_CATALOG_TTL_SECONDS``."""
        import time

        now = time.monotonic()
        if self._cache_ops is not None and (now - self._cache_at) < _CATALOG_TTL_SECONDS:
            return self._cache_ops, self._cache_events or {}
        native_ops, native_events = self._native()
        plugin_ops, plugin_events = self._plugin()
        # Native ids never collide with plugin ids (reserved 'plugin.' prefix).
        ops = {**native_ops, **plugin_ops}
        events = {**native_events, **plugin_events}
        self._cache_ops, self._cache_events, self._cache_at = ops, events, now
        return ops, events

    # ── Native (in-tree modules) ──────────────────────────────────────────

    def _native(self) -> tuple[dict[str, Operation], dict[str, EventSpec]]:
        ops: dict[str, Operation] = {}
        events: dict[str, EventSpec] = {}

        # Fabric's own built-in sink operations + platform event sources
        # (always available).
        try:
            from app.core.fabric.builtin_ops import builtin_events, builtin_operations

            for op in builtin_operations():
                ops[op.id] = op
            for ev in builtin_events():
                events[ev.event_type] = ev
        except Exception:
            logger.exception("Fabric: failed loading built-in operations/events")

        try:
            from app.modules.registry import module_registry
        except Exception as exc:  # pragma: no cover - module system absent
            logger.debug("Fabric: module registry unavailable: %s", exc)
            return ops, events

        for module in module_registry.modules.values():
            mod_id = getattr(module, "id", "?")
            try:
                for op in module.get_operations() or []:
                    if op.tier is not OperationTier.NATIVE:
                        logger.warning(
                            "Fabric: module %s declared non-native operation %s; skipping",
                            mod_id,
                            op.id,
                        )
                        continue
                    ops[op.id] = op
                for ev in module.get_emitted_events() or []:
                    if ev.tier is not OperationTier.NATIVE:
                        logger.warning(
                            "Fabric: module %s declared non-native event %s; skipping",
                            mod_id,
                            ev.event_type,
                        )
                        continue
                    events[ev.event_type] = ev
            except Exception:
                # A buggy module must never break the whole catalog.
                logger.exception("Fabric: failed reading operations from module %s", mod_id)
        return ops, events

    # ── Plugin (external apps, via the bridge) ────────────────────────────

    def _plugin(self) -> tuple[dict[str, Operation], dict[str, EventSpec]]:
        ops: dict[str, Operation] = {}
        events: dict[str, EventSpec] = {}
        try:
            from app.plugins.bridges import automation_bridge
        except Exception as exc:  # pragma: no cover
            logger.debug("Fabric: plugin bridge unavailable: %s", exc)
            return ops, events

        for act in automation_bridge.get_plugin_actions():
            try:
                op = Operation(
                    id=str(act["type"]),  # already 'plugin.{id}.{action}'
                    title=str(act.get("short_type") or act["type"]),
                    description=str(act.get("description") or ""),
                    input_schema=dict(act.get("params_schema") or {}),
                    tier=OperationTier.PLUGIN,
                    provider_id=str(act.get("plugin_id") or ""),
                )
                ops[op.id] = op
            except Exception:
                logger.exception("Fabric: bad plugin action %s", act.get("type"))

        for trg in automation_bridge.get_plugin_triggers():
            try:
                ev = EventSpec(
                    event_type=str(trg["type"]),  # 'plugin.{id}.{trigger}'
                    title=str(trg.get("short_type") or trg["type"]),
                    description=str(trg.get("description") or ""),
                    payload_schema=dict(trg.get("schema") or {}),
                    tier=OperationTier.PLUGIN,
                    provider_id=str(trg.get("plugin_id") or ""),
                )
                events[ev.event_type] = ev
            except Exception:
                logger.exception("Fabric: bad plugin trigger %s", trg.get("type"))
        return ops, events

    # ── AI tool projection (read-only convergence view) ───────────────────

    def projected_ai_tools(self) -> list[dict[str, Any]]:
        """Project the AI tool registry as lightweight catalog entries.

        Shows the AI assistant's callable tools as part of the unified Fabric
        surface (the convergence target). Read-only: it does NOT touch or rewire
        the AI tool system in this phase. Tier is inferred from the existing
        ``plugin_{id}_`` prefix the AI bridge enforces.
        """
        out: list[dict[str, Any]] = []
        try:
            from app.modules.ai.tools import TOOL_REGISTRY
        except Exception as exc:  # pragma: no cover
            logger.debug("Fabric: AI tool registry unavailable: %s", exc)
            return out
        for tool in TOOL_REGISTRY.values():
            is_plugin = str(getattr(tool, "name", "")).startswith("plugin_")
            out.append(
                {
                    "name": getattr(tool, "name", ""),
                    "description": getattr(tool, "description", ""),
                    "permission": getattr(tool, "permission", None),
                    "tier": (OperationTier.PLUGIN if is_plugin else OperationTier.NATIVE).value,
                }
            )
        return out

    # ── Public API ────────────────────────────────────────────────────────

    def list_operations(self) -> list[Operation]:
        ops, _ = self._discover()
        return list(ops.values())

    def list_events(self) -> list[EventSpec]:
        _, events = self._discover()
        return list(events.values())

    def get_operation(self, op_id: str) -> Operation | None:
        # O(1) dict lookup on the cached catalog (was a full re-discovery + scan).
        return self._discover()[0].get(op_id)

    def get_event(self, event_type: str) -> EventSpec | None:
        return self._discover()[1].get(event_type)

    def compatible_targets(
        self, event_type: str, *, event: EventSpec | None = _UNSET
    ) -> list[Operation]:
        """Operations that can serve as a target step for ``event_type``.

        The Negotiator's matchmaking surface, used by the builder UI to suggest
        which operations a given source event can drive. An operation is a
        compatible target when :func:`media_compatible` holds between the event's
        ``produces`` media-types and the operation's ``accepts`` — i.e. a
        data-only operation fits any event, while an artifact-consuming operation
        fits only an event that produces a media-type it accepts.

        Pass ``event=`` when the caller already resolved the :class:`EventSpec`
        (e.g. the suggest endpoint) to skip a redundant catalog walk.

        This is a *capability* check only; the per-author permission gate is
        applied separately (the suggest endpoint annotates ``allowed`` so the UI
        can disable operations the author may not invoke).
        """
        from app.core.fabric.operations import media_compatible

        ev = self.get_event(event_type) if event is _UNSET else event
        produced = ev.produces if ev else ()
        return [op for op in self.list_operations() if media_compatible(produced, op.accepts)]

    def catalog(self) -> dict[str, Any]:
        """Full catalog payload for ``GET /fabric/catalog``."""
        operations = self.list_operations()
        events = self.list_events()
        ai_tools = self.projected_ai_tools()
        return {
            "operations": [op.to_catalog_dict() for op in operations],
            "events": [ev.to_catalog_dict() for ev in events],
            "ai_tools": ai_tools,
            "counts": {
                "operations": len(operations),
                "events": len(events),
                "ai_tools": len(ai_tools),
                "native_operations": sum(1 for o in operations if o.tier is OperationTier.NATIVE),
                "plugin_operations": sum(1 for o in operations if o.tier is OperationTier.PLUGIN),
            },
        }


# Module-level singleton (stateless discovery facade).
fabric_registry = FabricRegistry()

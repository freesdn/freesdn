# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Plugin Bridges
==============================

Bridges that connect plugins to the automation engine and AI tool system.

- ``PluginAutomationBridge``: Lets plugins register custom triggers and actions
- ``PluginAIBridge``: Lets plugins register AI tools

These are singletons created at module level, imported by sdk.py and loader.py.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

#: Maximum registrations per plugin (prevents resource exhaustion)
MAX_TRIGGERS_PER_PLUGIN = 50
MAX_ACTIONS_PER_PLUGIN = 50
MAX_TOOLS_PER_PLUGIN = 20
# Cap a plugin AI-tool's SUCCESS-path return (the error path is already bounded).
# Symmetry with the Fabric executor's bounded plugin output — a plugin must not be
# able to push an unbounded blob back through the AI tool channel.
_MAX_TOOL_RESULT_BYTES = 256 * 1024

# SECURITY (PS-11): permission assigned to a plugin AI tool that declares NONE.
# No role grants this string (it is not in any role's permission set), so
# has_permission() returns True only for super_admin (implicit-grant) — i.e. an
# undeclared plugin tool is super_admin-only rather than ungated-for-everyone.
_UNDECLARED_PLUGIN_TOOL_PERMISSION = "plugin:undeclared_ai_tool"

#: Allowed pattern for trigger/action type names
_TYPE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,98}[a-z0-9]$")


class PluginAutomationBridge:
    """
    Allows plugins to register custom triggers and actions with the
    automation engine.

    Triggers are registered as event patterns that the automation engine
    listens for. Actions are registered as handler functions that execute
    when a rule fires.
    """

    def __init__(self) -> None:
        # plugin_id -> list of registered trigger type strings
        self._plugin_triggers: dict[str, list[dict[str, Any]]] = {}
        # plugin_id -> list of registered action type strings
        self._plugin_actions: dict[str, list[dict[str, Any]]] = {}

    def register_plugin_trigger(
        self,
        plugin_id: str,
        trigger_type: str,
        description: str,
        schema: dict[str, Any],
    ) -> None:
        """
        Register a plugin event type as an automation trigger.

        The trigger fires when the plugin emits an event matching
        ``plugin.{plugin_id}.{trigger_type}``.
        """
        if not _TYPE_NAME_PATTERN.match(trigger_type):
            raise ValueError(f"Invalid trigger_type: '{trigger_type}'")

        existing = self._plugin_triggers.get(plugin_id, [])
        if len(existing) >= MAX_TRIGGERS_PER_PLUGIN:
            raise ValueError(
                f"Plugin {plugin_id} exceeded max triggers ({MAX_TRIGGERS_PER_PLUGIN})"
            )

        full_type = f"plugin.{plugin_id}.{trigger_type}"

        if plugin_id not in self._plugin_triggers:
            self._plugin_triggers[plugin_id] = []
        elif any(trigger["type"] == full_type for trigger in self._plugin_triggers[plugin_id]):
            logger.debug("Plugin %s trigger already registered: %s", plugin_id, full_type)
            return

        self._plugin_triggers[plugin_id].append(
            {
                "type": full_type,
                "short_type": trigger_type,
                "description": description[:500],
                "schema": schema,
                "plugin_id": plugin_id,
            }
        )
        logger.info("Plugin %s registered trigger: %s", plugin_id, full_type)

    def register_plugin_action(
        self,
        plugin_id: str,
        action_type: str,
        handler: Callable[..., Any],
        description: str,
        params_schema: dict[str, Any],
    ) -> None:
        """
        Register a plugin function as an automation action.

        When an automation rule uses this action type, the handler
        is called with the action params and execution context.
        """
        if not _TYPE_NAME_PATTERN.match(action_type):
            raise ValueError(f"Invalid action_type: '{action_type}'")

        existing = self._plugin_actions.get(plugin_id, [])
        if len(existing) >= MAX_ACTIONS_PER_PLUGIN:
            raise ValueError(f"Plugin {plugin_id} exceeded max actions ({MAX_ACTIONS_PER_PLUGIN})")

        full_type = f"plugin.{plugin_id}.{action_type}"

        if plugin_id not in self._plugin_actions:
            self._plugin_actions[plugin_id] = []
        elif any(action["type"] == full_type for action in self._plugin_actions[plugin_id]):
            logger.debug("Plugin %s action already registered: %s", plugin_id, full_type)
            return

        self._plugin_actions[plugin_id].append(
            {
                "type": full_type,
                "short_type": action_type,
                "description": description[:500],
                "params_schema": params_schema,
                "handler": handler,
                "plugin_id": plugin_id,
            }
        )

        # Register the handler with the automation engine if available
        try:
            from app.services.automation import automation_engine

            if hasattr(automation_engine, "_action_handlers"):
                # Only register if no other plugin owns this key
                if full_type not in automation_engine._action_handlers:
                    automation_engine._action_handlers[full_type] = handler  # type: ignore[index]
                else:
                    logger.warning(
                        "Action handler '%s' already registered, skipping for plugin %s",
                        full_type,
                        plugin_id,
                    )
        except Exception as exc:
            logger.debug("Could not register action handler with engine: %s", exc)

        logger.info("Plugin %s registered action: %s", plugin_id, full_type)

    def unregister_plugin(self, plugin_id: str) -> None:
        """Remove all triggers and actions for a plugin."""
        # Clean up triggers
        self._plugin_triggers.pop(plugin_id, None)

        # Clean up actions and their engine registrations
        actions = self._plugin_actions.pop(plugin_id, [])
        for action in actions:
            try:
                from app.services.automation import automation_engine

                if hasattr(automation_engine, "_action_handlers"):
                    automation_engine._action_handlers.pop(action["type"], None)
            except (ImportError, AttributeError, KeyError):
                pass

        if actions:
            logger.info("Unregistered %d actions for plugin %s", len(actions), plugin_id)

    def get_plugin_triggers(self, plugin_id: str | None = None) -> list[dict[str, Any]]:
        """Get registered triggers for a plugin, or all plugins."""
        if plugin_id:
            return list(self._plugin_triggers.get(plugin_id, []))
        return [t for triggers in self._plugin_triggers.values() for t in triggers]

    def get_plugin_actions(self, plugin_id: str | None = None) -> list[dict[str, Any]]:
        """Get registered actions for a plugin, or all plugins."""
        if plugin_id:
            return list(self._plugin_actions.get(plugin_id, []))
        result = []
        for actions in self._plugin_actions.values():
            for a in actions:
                result.append({k: v for k, v in a.items() if k != "handler"})
        return result


class PluginAIBridge:
    """
    Allows plugins to register tools that the AI assistant can call.

    Tools are prefixed with ``plugin_{plugin_id}_`` to avoid name collisions
    with built-in tools.
    """

    def __init__(self) -> None:
        # plugin_id -> list of registered tool names
        self._plugin_tools: dict[str, list[str]] = {}

    def register_plugin_tool(self, plugin_id: str, tool: Any) -> None:
        """
        Register a plugin tool with the AI tool registry.

        The tool name is auto-prefixed with ``plugin_{plugin_id}_``.
        """
        from app.modules.ai.tools import TOOL_REGISTRY, AITool, register_tool

        existing = self._plugin_tools.get(plugin_id, [])
        if len(existing) >= MAX_TOOLS_PER_PLUGIN:
            raise ValueError(f"Plugin {plugin_id} exceeded max AI tools ({MAX_TOOLS_PER_PLUGIN})")

        prefixed_name = f"plugin_{plugin_id}_{tool.name}"

        # Prevent overwriting built-in tools
        if prefixed_name in TOOL_REGISTRY:
            logger.warning(
                "AI tool '%s' already registered, skipping for plugin %s",
                prefixed_name,
                plugin_id,
            )
            return

        # SECURITY (PS-11): a plugin-registered AI tool MUST be gated by a
        # permission. _execute_tool (modules/ai/service.py) SKIPS the RBAC check
        # when ``tool.permission`` is falsy, and a plugin tool's handler runs with
        # the calling user's RAW user+db (it is NOT SDK-org-scoped), so an
        # undeclared permission = an ungated privileged action invocable by ANY
        # chat user. Fail closed: coerce a missing permission to a sentinel that
        # no role grants, so an undeclared tool is super_admin-only until the
        # author declares a real permission in plugin.yaml.
        effective_permission = tool.permission or _UNDECLARED_PLUGIN_TOOL_PERMISSION
        if not tool.permission:
            logger.warning(
                "Plugin %s registered AI tool '%s' with NO permission; gating it "
                "super_admin-only (%s). Declare a permission in plugin.yaml to "
                "make it usable by the intended roles.",
                plugin_id,
                tool.name,
                _UNDECLARED_PLUGIN_TOOL_PERMISSION,
            )

        # Wrap the handler to add error sanitization
        original_handler = tool.handler

        async def wrapped_handler(**kwargs: Any) -> dict[str, Any]:
            try:
                result: dict[str, Any] = await original_handler(**kwargs)
            except Exception:
                logger.exception("Plugin tool %s failed", prefixed_name)
                return {"error": f"Plugin tool {prefixed_name} encountered an internal error"}
            # Bound the success-path return so a plugin can't emit an unbounded blob.
            try:
                import json as _json

                if len(_json.dumps(result, default=str)) > _MAX_TOOL_RESULT_BYTES:
                    logger.warning("Plugin tool %s result exceeded cap; dropped", prefixed_name)
                    return {"error": "Plugin tool result too large", "truncated": True}
            except (TypeError, ValueError):
                return {"error": "Plugin tool returned a non-serializable result"}
            return result

        register_tool(
            AITool(
                name=prefixed_name,
                description=f"[Plugin: {plugin_id}] {tool.description}"[:500],
                parameters=tool.parameters,
                handler=wrapped_handler,
                permission=effective_permission,
            )
        )

        if plugin_id not in self._plugin_tools:
            self._plugin_tools[plugin_id] = []
        self._plugin_tools[plugin_id].append(prefixed_name)

        logger.info("Plugin %s registered AI tool: %s", plugin_id, prefixed_name)

    def unregister_plugin_tools(self, plugin_id: str) -> None:
        """Remove all AI tools for a plugin."""
        from app.modules.ai.tools import TOOL_REGISTRY

        tool_names = self._plugin_tools.pop(plugin_id, [])
        for name in tool_names:
            TOOL_REGISTRY.pop(name, None)

        if tool_names:
            logger.info("Unregistered %d AI tools for plugin %s", len(tool_names), plugin_id)

    def get_plugin_tools(self, plugin_id: str | None = None) -> list[str]:
        """Get registered tool names for a plugin, or all plugins."""
        if plugin_id:
            return list(self._plugin_tools.get(plugin_id, []))
        return [name for names in self._plugin_tools.values() for name in names]


# Module-level singletons
automation_bridge = PluginAutomationBridge()
ai_bridge = PluginAIBridge()

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - AI Tool Registry
================================

Central registry for function-calling tools available to LLM providers.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# Tool registry — populated by tool modules at import time
TOOL_REGISTRY: dict[str, "AITool"] = {}


@dataclass
class AITool:
    """Definition of a tool the LLM can call."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema
    handler: Callable[..., Any]  # async (user, db, **kwargs) -> dict
    permission: str | None = None  # FreeSDN permission required to execute


def register_tool(tool: AITool) -> None:
    """Register a tool in the global registry."""
    TOOL_REGISTRY[tool.name] = tool


def get_tool_definitions() -> list[dict[str, Any]]:
    """Return tool definitions formatted for LLM API (OpenAI/Anthropic compatible)."""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            },
        }
        for t in TOOL_REGISTRY.values()
    ]


def get_anthropic_tool_definitions() -> list[dict[str, Any]]:
    """Return tool definitions in Anthropic format."""
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.parameters,
        }
        for t in TOOL_REGISTRY.values()
    ]


# Import tool modules to auto-register their tools
def load_tools() -> None:
    """Trigger import of all tool modules so they register themselves."""
    from app.modules.ai.tools import diagnostics, network  # noqa: F401

    # Extended tools (graceful import — these depend on optional modules)
    try:
        from app.modules.ai.tools import automation as _a  # noqa: F401
    except Exception:
        pass
    try:
        from app.modules.ai.tools import collector as _c  # noqa: F401
    except Exception:
        pass

# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - AI Tools: Automation
====================================

AI tools for managing and querying automation rules.
"""

from __future__ import annotations

from typing import Any

from app.modules.ai.tools import AITool, register_tool


async def _list_automation_rules(
    user, db, status: str | None = None, limit: int = 20, **kwargs
) -> dict[str, Any]:
    """List automation rules for the user's organization."""
    from sqlalchemy import select

    try:
        from app.models.automation import AutomationRuleRecord
    except ImportError:
        return {"error": "Automation model not available", "rules": []}

    # REQUIRE organization_id to prevent cross-tenant data leakage
    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required", "rules": []}

    q = select(AutomationRuleRecord).where(
        AutomationRuleRecord.organization_id == user.organization_id
    )
    if status:
        q = q.where(AutomationRuleRecord.status == status)
    q = q.limit(max(1, min(limit, 100)))

    result = await db.execute(q)
    rules = result.scalars().all()
    return {
        "rules": [
            {
                "id": str(r.id),
                "name": getattr(r, "name", ""),
                "status": getattr(r, "status", ""),
                "trigger_type": getattr(r, "trigger_type", ""),
                "trigger_count": getattr(r, "trigger_count", 0),
                "last_triggered": str(getattr(r, "last_triggered", ""))
                if getattr(r, "last_triggered", None)
                else None,
            }
            for r in rules
        ],
        "total": len(rules),
    }


async def _get_execution_history(
    user, db, rule_id: str | None = None, limit: int = 20, **kwargs
) -> dict[str, Any]:
    """Get automation execution history."""
    from sqlalchemy import select

    try:
        from app.models.automation import AutomationExecutionRecord
    except ImportError:
        return {"error": "Execution record model not available", "executions": []}

    # REQUIRE organization_id to prevent cross-tenant data leakage
    if not getattr(user, "organization_id", None):
        return {"error": "Organization context required", "executions": []}

    q = select(AutomationExecutionRecord).where(
        AutomationExecutionRecord.organization_id == user.organization_id
    )
    if rule_id:
        from uuid import UUID

        try:
            q = q.where(AutomationExecutionRecord.rule_id == UUID(rule_id))
        except ValueError:
            return {"error": f"Invalid rule_id: {rule_id}"}
    q = q.order_by(AutomationExecutionRecord.triggered_at.desc()).limit(min(limit, 50))

    result = await db.execute(q)
    execs = result.scalars().all()
    return {
        "executions": [
            {
                "id": str(e.id),
                "rule_id": str(getattr(e, "rule_id", "")),
                "success": getattr(e, "success", False),
                "started_at": str(getattr(e, "triggered_at", "")),
                "actions_executed": getattr(e, "actions_executed", 0),
            }
            for e in execs
        ],
        "total": len(execs),
    }


# Register tools
register_tool(
    AITool(
        name="list_automation_rules",
        description="List automation rules with optional status filter. Returns rule name, status, trigger type, and execution count.",
        parameters={
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Filter by rule status: active, paused, disabled, error",
                    "enum": ["active", "paused", "disabled", "error"],
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of rules to return (default 20)",
                    "default": 20,
                },
            },
        },
        handler=_list_automation_rules,
        permission="automation.rules.read",
    )
)

register_tool(
    AITool(
        name="get_execution_history",
        description="Get automation rule execution history. Shows recent executions with status and timing.",
        parameters={
            "type": "object",
            "properties": {
                "rule_id": {
                    "type": "string",
                    "description": "Filter by specific rule ID (UUID)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of executions to return (default 20)",
                    "default": 20,
                },
            },
        },
        handler=_get_execution_history,
        permission="automation.rules.read",
    )
)

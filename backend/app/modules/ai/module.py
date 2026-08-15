# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - AI Module
========================

AI-powered network assistant with multi-provider LLM support.
Supports OpenAI, Anthropic, and Ollama for network Q&A, diagnostics,
and autonomous tool calling against the FreeSDN data layer.
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter

from app.modules.base import BaseModule
from app.modules.manifest import (
    ModuleCategory,
    ModuleManifest,
    ModuleNavItem,
    ModulePermission,
)

logger = logging.getLogger(__name__)


class AIModule(BaseModule):
    """
    AI Assistant Module for FreeSDN.

    Provides an agentic LLM interface that can query network state,
    run diagnostics, and provide recommendations using multi-provider
    support (OpenAI, Anthropic, Ollama).
    """

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        return ModuleManifest(
            id="ai",
            name="AI Assistant",
            version="1.0.0",
            description="AI-powered network assistant with multi-provider LLM support",
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category=ModuleCategory.SYSTEM,
            icon="Brain",
            color="#8B5CF6",
            is_beta=True,
            capabilities=[],
            permissions=[
                ModulePermission(
                    code="ai.chat",
                    name="Use AI Chat",
                    description="Send messages to the AI assistant",
                    resource="ai",
                    action="execute",
                ),
                ModulePermission(
                    code="ai.admin",
                    name="AI Admin",
                    description="Configure AI providers and settings",
                    resource="ai",
                    action="update",
                ),
            ],
            nav_items=[
                ModuleNavItem(
                    path="/ai",
                    label="AI Assistant",
                    icon="Brain",
                    order=90,
                    permission="ai.chat",
                ),
            ],
            api_prefix="/ai",
        )

    @property
    def manifest(self) -> ModuleManifest:
        return self.get_manifest()

    def get_router(self) -> APIRouter:
        from app.modules.ai.api import router

        return router

    def get_models(self) -> list[type]:
        from app.modules.ai.models import AIConversation, AIMessage, AIProviderConfig, LLMCallLog

        return [AIConversation, AIMessage, AIProviderConfig, LLMCallLog]

    def __init__(self) -> None:
        super().__init__()
        logger.info("AIModule initialized")

    def get_emitted_events(self):  # type: ignore[no-untyped-def]
        """Fabric event source: AI spend crossed its budget threshold
        (governance.py) — wireable to fabric.notify for cost alerting.

        (AI *tools* are already projected read-only into the catalog by
        FabricRegistry.projected_ai_tools(); they are NOT re-declared here.)
        """
        from app.core.fabric.operations import EventSpec, OperationTier

        return [
            EventSpec(
                event_type="ai.budget.warning",
                title="AI budget warning",
                description="AI usage crossed a configured budget threshold.",
                payload_schema={
                    "type": "object",
                    "properties": {
                        "organization_id": {"type": "string"},
                        "used": {"type": "number"},
                        "budget": {"type": "number"},
                        "percentage": {"type": "number"},
                    },
                },
                tier=OperationTier.NATIVE,
                provider_id="ai",
            ),
        ]

    async def on_load(self) -> None:
        logger.info("AI module v%s loading...", self.manifest.version)
        # Load and register all AI tools
        from app.modules.ai.tools import load_tools

        load_tools()
        # NOTE: the Fabric→AI-tool bridge runs LATER, in the boot wiring
        # (app.core.fabric.runtime.wire_and_start), NOT here — modules load
        # alphabetically, so at this point the op-providing modules
        # (cameras/firewall/hypervisor/network/storage/voip) haven't loaded yet
        # and the catalog would be near-empty. Running it once after all modules
        # are loaded captures the full native catalog.
        await super().on_load()

    async def on_start(self, organization_id: UUID, db: Any = None) -> None:
        logger.info("AI module starting for org %s...", organization_id)
        await super().on_start(organization_id, db)

    async def on_stop(self, organization_id: UUID, db: Any = None) -> None:
        logger.info("AI module stopping for org %s...", organization_id)
        await super().on_stop(organization_id, db)

    async def health_check(self) -> dict[str, Any]:
        from app.modules.ai.tools import TOOL_REGISTRY

        return {
            "status": "healthy",
            "module": self.manifest.id,
            "version": self.manifest.version,
            "state": self.state.value,
            "checks": {
                "tools_loaded": len(TOOL_REGISTRY) > 0,
                "tool_count": len(TOOL_REGISTRY),
            },
        }

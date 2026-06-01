# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Collector Module
================================

SNMP trap, Syslog, and NetFlow collector module.
Receives passive network monitoring data via UDP and stores it for
search, correlation, and automation triggers.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter

from app.modules.base import BaseModule, ModuleCapability
from app.modules.manifest import (
    ModuleCategory,
    ModuleManifest,
    ModuleNavItem,
    ModulePermission,
)

logger = logging.getLogger(__name__)


class CollectorModule(BaseModule):
    """
    Network Collector Module for FreeSDN.

    Runs asyncio UDP listeners for SNMP traps, syslog (RFC 3164/5424),
    and NetFlow v5/v9.  Data is persisted and exposed via REST endpoints.
    """

    @classmethod
    def get_manifest(cls) -> ModuleManifest:
        return ModuleManifest(
            id="collector",
            name="Observability",
            version="1.0.0",
            # 🟡 honest: syslog ingest verified live E2E via the dedicated
            # `collector` compose service (app/modules/collector/run.py); SNMP-trap
            # and NetFlow share the same receiver+store path (unit-tested).
            is_beta=True,
            description=(
                "SNMP traps, Syslog, and NetFlow collection with log aggregation "
                "and traffic analytics"
            ),
            author="FreeSDN Team",
            license="AGPL-3.0-only",
            category=ModuleCategory.SYSTEM,
            icon="Radio",
            color="#F59E0B",
            capabilities=[ModuleCapability.TRAFFIC_ANALYTICS],
            permissions=[
                ModulePermission(
                    code="collector.logs.read",
                    name="View Logs",
                    description="Search and view collected syslog and SNMP logs",
                    resource="collector",
                    action="read",
                ),
                ModulePermission(
                    code="collector.flows.read",
                    name="View Flows",
                    description="View NetFlow traffic records",
                    resource="collector",
                    action="read",
                ),
                ModulePermission(
                    code="collector.config",
                    name="Configure Collector",
                    description="Enable/disable collector services and set ports",
                    resource="collector",
                    action="update",
                ),
            ],
            nav_items=[
                ModuleNavItem(
                    path="/collector",
                    label="Observability",
                    icon="Radio",
                    order=85,
                    permission="collector.logs.read",
                ),
                ModuleNavItem(
                    path="/collector/logs",
                    label="Log Explorer",
                    icon="ScrollText",
                    order=86,
                    permission="collector.logs.read",
                ),
            ],
            api_prefix="/collector",
        )

    @property
    def manifest(self) -> ModuleManifest:
        return self.get_manifest()

    def get_router(self) -> APIRouter:
        from app.modules.collector.api import router

        return router

    def get_models(self) -> list[type]:
        from app.modules.collector.models import CollectorConfig, CollectorLog, FlowRecord

        return [CollectorLog, FlowRecord, CollectorConfig]

    def __init__(self) -> None:
        super().__init__()
        logger.info("CollectorModule initialized")

    async def on_load(self) -> None:
        logger.info("Collector module v%s loading...", self.manifest.version)
        await super().on_load()

    async def on_start(self, organization_id: UUID, db: Any = None) -> None:
        """Start collector services for the given org using its saved config."""
        logger.info("Collector module starting for org %s...", organization_id)
        try:
            from sqlalchemy import select

            from app.modules.collector.models import CollectorConfig

            # NOTE(C1): Use get_collector_manager() so the lazy singleton
            # is constructed with the real AsyncSessionLocal session
            # factory — without this, every receiver's persistence
            # branch was dead code (session_factory was None).
            from app.modules.collector.services.manager import (
                get_collector_manager,
            )

            if db is not None:
                result = await db.execute(
                    select(CollectorConfig).where(
                        CollectorConfig.organization_id == organization_id
                    )
                )
                config = result.scalar_one_or_none()
                if config:
                    manager = get_collector_manager()
                    await manager.start(config)
                    logger.info(f"Collector services started for org {organization_id}")
        except Exception as exc:
            logger.warning(f"Could not start collector services for org {organization_id}: {exc}")
        await super().on_start(organization_id, db)

    async def on_stop(self, organization_id: UUID, db: Any = None) -> None:
        logger.info("Collector module stopping for org %s...", organization_id)
        try:
            from app.modules.collector.services.manager import get_collector_manager

            await get_collector_manager().stop()
        except Exception as exc:
            logger.warning("Error stopping collector services: %s", exc)
        await super().on_stop(organization_id, db)

    async def health_check(self) -> dict[str, Any]:
        from app.modules.collector.services.manager import get_collector_manager

        svc_status = get_collector_manager().status()
        any_running = any(v["running"] for v in svc_status.values())
        return {
            "status": "healthy",
            "module": self.manifest.id,
            "version": self.manifest.version,
            "state": self.state.value,
            "checks": {
                "services": svc_status,
                "any_service_running": any_running,
            },
        }

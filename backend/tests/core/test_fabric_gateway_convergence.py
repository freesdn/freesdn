# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Fabric orchestration convergence: the network Distribution Engine folded into
the Fabric orchestration plane as a first-class EVENT SOURCE.

The convergence is deliberately at the event/orchestration plane, NOT a merge of
the two saga/write engines: distribution keeps its own tiered apply + compensation
plan (writes still ride each vendor adapter's ADAPTER_READ_ONLY/force gate), and
merely surfaces its outcome as a Fabric trigger. So an operator can wire a
downstream Fabric action (notify / snapshot / log) to a completed or failed VLAN
distribution — observability only, no new write authority, no change to the
staged-write sign-off path.

These tests pin: (1) the gateway module contributes the lifecycle events,
(2) the Fabric registry discovers them in the catalog, (3) DistributionService
publishes the right org-scoped event for success/failure and never raises.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest


def _gateway_module():
    # get_emitted_events()/get_operations() don't touch instance state, so a
    # __new__ instance is a sufficient (and import-cheap) stand-in.
    from app.modules.gateway.module import GatewayModule

    return GatewayModule.__new__(GatewayModule)


class TestGatewayEmittedEvents:
    def test_declares_distribution_lifecycle_events(self):
        from app.core.fabric.operations import OperationTier

        evs = _gateway_module().get_emitted_events()
        by_type = {e.event_type: e for e in evs}
        assert "gateway.distribution.completed" in by_type
        assert "gateway.distribution.failed" in by_type
        for e in evs:
            assert e.tier is OperationTier.NATIVE
            assert e.provider_id == "gateway"
            props = e.payload_schema.get("properties", {})
            # the negotiator maps these — org/site must be advertised
            assert "organization_id" in props and "site_id" in props


class TestRegistryDiscovery:
    def test_catalog_includes_gateway_distribution_events(self, monkeypatch):
        from app.core.fabric.registry import fabric_registry
        from app.modules.registry import module_registry
        from app.plugins import bridges

        # `modules` is a read-only property over `_modules`; patch the store.
        monkeypatch.setattr(
            module_registry, "_modules", {"gateway": _gateway_module()}, raising=False
        )
        monkeypatch.setattr(bridges.automation_bridge, "get_plugin_actions", lambda: [])
        monkeypatch.setattr(bridges.automation_bridge, "get_plugin_triggers", lambda: [])
        fabric_registry.invalidate()
        try:
            types = {e.event_type for e in fabric_registry.list_events()}
            assert "gateway.distribution.completed" in types
            assert "gateway.distribution.failed" in types
        finally:
            fabric_registry.invalidate()  # don't leak the patched catalog to other tests


class TestPublishLifecycle:
    def _service(self):
        from app.modules.gateway.services.distribution_service import DistributionService

        return DistributionService(db=MagicMock())

    def _record(self, status, *, rollback=None, results=None, org=None):
        return SimpleNamespace(
            id=uuid4(),
            organization_id=org or uuid4(),
            site_id=uuid4(),
            resource_type="vlan",
            resource_id=uuid4(),
            action="create",
            status=status,
            step_results=(
                results if results is not None else [{"status": "success"}, {"status": "success"}]
            ),
            rollback_plan=rollback,
        )

    @pytest.mark.asyncio
    async def test_completed_publishes_completed_event(self, monkeypatch):
        import app.modules.gateway.services.distribution_service as mod
        from app.modules.gateway.models import DistributionStatus

        published = []
        bus = MagicMock()
        bus.publish = AsyncMock(side_effect=lambda ev: published.append(ev))
        monkeypatch.setattr(mod, "get_event_bus", lambda: bus)

        org = uuid4()
        await self._service()._publish_lifecycle(
            self._record(DistributionStatus.COMPLETED, org=org)
        )

        assert len(published) == 1
        ev = published[0]
        assert ev.event_type == "gateway.distribution.completed"
        assert ev.source == "gateway"
        assert ev.organization_id == str(org)  # org-scoped for the fail-closed router
        assert ev.payload["steps_succeeded"] == 2
        assert ev.payload["rollback_required"] is False

    @pytest.mark.asyncio
    async def test_failed_publishes_failed_event_with_rollback_flag(self, monkeypatch):
        import app.modules.gateway.services.distribution_service as mod
        from app.modules.gateway.models import DistributionStatus

        published = []
        bus = MagicMock()
        bus.publish = AsyncMock(side_effect=lambda ev: published.append(ev))
        monkeypatch.setattr(mod, "get_event_bus", lambda: bus)

        await self._service()._publish_lifecycle(
            self._record(
                DistributionStatus.FAILED,
                rollback={"steps": [{"action": "delete_vlan"}]},
                results=[{"status": "success"}, {"status": "failed"}],
            )
        )

        assert published[0].event_type == "gateway.distribution.failed"
        assert published[0].payload["rollback_required"] is True
        assert published[0].payload["steps_succeeded"] == 1

    @pytest.mark.asyncio
    async def test_publish_is_fire_and_forget(self, monkeypatch):
        """A telemetry failure must never fail or roll back the distribution."""
        import app.modules.gateway.services.distribution_service as mod
        from app.modules.gateway.models import DistributionStatus

        bus = MagicMock()
        bus.publish = AsyncMock(side_effect=RuntimeError("bus down"))
        monkeypatch.setattr(mod, "get_event_bus", lambda: bus)

        # must NOT raise
        await self._service()._publish_lifecycle(self._record(DistributionStatus.COMPLETED))

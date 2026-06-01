# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""End-to-end proof that LIVE firewall events drive cross-system automation:

    firewall.event.wan_down  →  (action receives gateway context)

The firewall health poller publishes ``firewall.event.*`` on real OPNsense state
transitions (WAN up/down, new critical IDS signature, reachability). This wires
one of those advertised triggers to a Connection through the REAL Negotiator and
proves it fires and threads the trigger payload — so it fails if the catalog and
the firing namespace ever diverge, the headline "any app → any app" promise for
the firewall source.
"""
from __future__ import annotations

import uuid

import pytest

from app.core.fabric.artifact_broker import ArtifactBroker
from app.core.fabric.execution import OperationResult
from app.core.fabric.executor import OperationExecutor
from app.core.fabric.negotiator import Connection, ConnectionStep, Negotiator
from app.core.fabric.operations import Operation, OperationTier

ORG = uuid.uuid4()


class _Event:
    def __init__(self, event_type, payload, organization_id):
        self.event_type = event_type
        self.payload = payload
        self.organization_id = organization_id
        self.id = str(uuid.uuid4())


class _FakeRegistry:
    def __init__(self, ops):
        self._ops = {o.id: o for o in ops}

    def get_operation(self, op_id):
        return self._ops.get(op_id)


class _FakeSession:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, *a):
        return False


def test_firewall_transition_events_are_advertised() -> None:
    from app.modules.firewall.module import FirewallModule

    advertised = {e.event_type for e in FirewallModule().get_emitted_events()}
    # Every transition the poller can fire must be an advertised trigger.
    for et in (
        "firewall.event.wan_down",
        "firewall.event.wan_up",
        "firewall.event.ids_critical",
        "firewall.event.gateway_unreachable",
        "firewall.event.gateway_online",
    ):
        assert et in advertised


@pytest.mark.asyncio
async def test_wan_down_drives_a_connection(tmp_path) -> None:
    from app.modules.firewall.module import FirewallModule

    advertised = {e.event_type for e in FirewallModule().get_emitted_events()}
    assert "firewall.event.wan_down" in advertised

    received: dict = {}

    async def _notify(ctx):
        received["gateway_id"] = ctx.params.get("gateway_id")
        received["gateway_name"] = ctx.params.get("gateway_name")
        return OperationResult.ok(output={"notified": True})

    notify_op = Operation(
        id="test.notify",
        title="notify",
        handler=_notify,
        tier=OperationTier.NATIVE,
        provider_id="test",
    )

    async def _allow(actor_id, permission, org_id):
        return True

    executor = OperationExecutor(artifact_broker=ArtifactBroker(base_dir=tmp_path))
    neg = Negotiator(
        registry=_FakeRegistry([notify_op]),
        executor=executor,
        permission_checker=_allow,
        session_factory=lambda: _FakeSession(),
    )
    gw_id = str(uuid.uuid4())
    neg.add_connection(
        Connection(
            id="fw-wan-down-vertical",
            organization_id=ORG,
            name="wan_down → notify",
            source_event="firewall.event.wan_down",
            steps=[
                ConnectionStep(
                    "test.notify",
                    params={
                        "gateway_id": "{{trigger.gateway_id}}",
                        "gateway_name": "{{trigger.gateway_name}}",
                    },
                ),
            ],
            actor_id=uuid.uuid4(),
        )
    )

    runs = await neg.handle_event(
        _Event(
            "firewall.event.wan_down",
            {"gateway_id": gw_id, "gateway_name": "OpnSenseX", "gateway": "WAN_GW", "status": "down"},
            ORG,
        )
    )

    assert len(runs) == 1
    run = runs[0]
    assert run["success"] is True, run
    # Templating threaded the live trigger payload into the action.
    assert received["gateway_id"] == gw_id
    assert received["gateway_name"] == "OpnSenseX"


@pytest.mark.asyncio
async def test_unrelated_event_does_not_fire_firewall_connection(tmp_path) -> None:
    async def _notify(ctx):
        return OperationResult.ok(output={})

    notify_op = Operation(
        id="test.notify", title="notify", handler=_notify,
        tier=OperationTier.NATIVE, provider_id="test",
    )

    async def _allow(actor_id, permission, org_id):
        return True

    neg = Negotiator(
        registry=_FakeRegistry([notify_op]),
        executor=OperationExecutor(artifact_broker=ArtifactBroker(base_dir=tmp_path)),
        permission_checker=_allow,
        session_factory=lambda: _FakeSession(),
    )
    neg.add_connection(
        Connection(
            id="fw-wan-down-vertical",
            organization_id=ORG,
            name="wan_down → notify",
            source_event="firewall.event.wan_down",
            steps=[ConnectionStep("test.notify", params={})],
            actor_id=uuid.uuid4(),
        )
    )
    # A different event must not trigger the wan_down connection.
    runs = await neg.handle_event(_Event("firewall.event.wan_up", {}, ORG))
    assert runs == []

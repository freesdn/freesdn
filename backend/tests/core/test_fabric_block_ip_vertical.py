# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Cross-vendor Fabric vertical — automated threat response:

    firewall.event.ids_critical  →  firewall.block_ip (STAGED)  →  notify

An OPNsense IDS-critical alert (carrying the attacker's source IP) drives, through
the REAL Negotiator, a staged OPNsense block rule for that IP plus a notification.
Proves the headline "any app → any app" promise AND the safety contract: a write
operation triggered by an (untrusted) event is only ever STAGED into Pending
Changes — the negotiator NEVER force-applies a device write. The real
``firewall.block_ip`` Operation the module advertises is used; only the DB
stage_change + the org-ownership guard are stubbed (no DB, no device).
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

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
        return object()  # non-None so the write path proceeds

    async def __aexit__(self, *a):
        return False


@pytest.mark.asyncio
async def test_ids_critical_stages_block_ip_and_notifies(tmp_path, monkeypatch) -> None:
    from app.modules.firewall.module import FirewallModule

    # The trigger must be a real advertised firewall event.
    advertised = {e.event_type for e in FirewallModule().get_emitted_events()}
    assert "firewall.event.ids_critical" in advertised

    # The action must be the real advertised write-op (staged, not applied).
    block_op = next(o for o in FirewallModule().get_operations() if o.id == "firewall.block_ip")
    assert block_op.write is True and block_op.feature == "opnsense.firewall.rule"

    # Org-ownership guard on the write plane → allow (real check needs a DB).
    monkeypatch.setattr(
        "app.core.fabric.executor._controller_in_org", AsyncMock(return_value=True)
    )

    # Capture what the Fabric STAGES (instead of hitting the DB).
    staged: dict = {}

    async def _fake_stage(self, **kw):
        staged.update(kw)
        return SimpleNamespace(id=uuid.uuid4())

    monkeypatch.setattr(
        "app.services.adapter_staging.AdapterStagingService.stage_change", _fake_stage
    )

    notified: dict = {}

    async def _notify(ctx):
        notified.update(ctx.params)
        return OperationResult.ok(output={"notified": True})

    notify_op = Operation(
        id="test.notify", title="notify", handler=_notify,
        tier=OperationTier.NATIVE, provider_id="test",
    )

    async def _allow(actor_id, permission, org_id):
        return True

    neg = Negotiator(
        registry=_FakeRegistry([block_op, notify_op]),
        executor=OperationExecutor(artifact_broker=ArtifactBroker(base_dir=tmp_path)),
        permission_checker=_allow,
        session_factory=lambda: _FakeSession(),
    )
    gateway_id = str(uuid.uuid4())
    attacker_ip = "203.0.113.66"
    neg.add_connection(
        Connection(
            id="ids-autoblock",
            organization_id=ORG,
            name="IDS-critical → block source IP → notify",
            source_event="firewall.event.ids_critical",
            steps=[
                ConnectionStep(
                    "firewall.block_ip",
                    params={
                        "controller_id": "{{trigger.gateway_id}}",
                        "source_net": "{{trigger.source_ip}}",
                        "action": "block",
                        "interface": "wan",
                        "description": "FreeSDN auto-block (IDS critical)",
                    },
                ),
                ConnectionStep(
                    "test.notify",
                    params={"gateway": "{{trigger.gateway_name}}", "blocked": "{{trigger.source_ip}}"},
                ),
            ],
            actor_id=uuid.uuid4(),
        )
    )

    runs = await neg.handle_event(
        _Event(
            "firewall.event.ids_critical",
            {
                "gateway_id": gateway_id,
                "gateway_name": "OpnSenseX",
                "source_ip": attacker_ip,
                "new_signatures": ["2100498"],
            },
            ORG,
        )
    )

    assert len(runs) == 1
    run = runs[0]
    assert run["success"] is True, run

    # Step 0: the Fabric STAGED an opnsense.firewall.rule with the attacker IP —
    # and only staged it (operator sign-off applies; never force-applied here).
    assert staged["feature"] == "opnsense.firewall.rule"
    assert staged["operation"] == "create"
    assert str(staged["controller_id"]) == gateway_id
    assert staged["payload"]["source_net"] == attacker_ip
    assert staged["payload"]["action"] == "block"
    assert "controller_id" not in staged["payload"]  # routing key stripped
    step0 = run["steps"][0]
    assert step0["operation_id"] == "firewall.block_ip" and step0["success"]

    # Step 1: the threat context threaded into the notify sink via templating.
    assert notified["gateway"] == "OpnSenseX"
    assert notified["blocked"] == attacker_ip

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""VoIP/FreePBX as a first-class Fabric participant.

Locks the operation + event contract that makes the FreePBX integration
drivable by — and a trigger source for — cross-system automations:

* Read ops (handler, immediate): phone live status, PBX active calls, extensions.
* Live-action op (handler, immediate): originate a call.
* Staged config-write op (write=True, feature=pbx.*): create an inbound route,
  routed through the AdapterStagingService dual-gate (never auto-applied).

These are pure declaration tests (no DB / no live PBX). The end-to-end
"invoke -> stages a change through the real pipeline" path is exercised live
against the dev stack separately.
"""
from __future__ import annotations

from app.modules.voip.module import VoIPModule


def _ops():
    return {o.id: o for o in VoIPModule().get_operations()}


def test_voip_declares_expected_fabric_operations():
    ops = _ops()
    assert {
        "voip.phone.live_status",
        "voip.pbx.active_calls",
        "voip.pbx.list_extensions",
        "voip.pbx.originate_call",
        "voip.pbx.inbound_route_create",
    } <= set(ops)


def test_read_and_action_ops_are_handler_backed_immediate():
    ops = _ops()
    for oid in ("voip.pbx.active_calls", "voip.pbx.list_extensions", "voip.pbx.originate_call"):
        op = ops[oid]
        assert op.write is False, f"{oid} should execute immediately (not staged)"
        assert op.handler is not None, f"{oid} needs a handler"
        assert op.feature is None
        assert op.permission  # every op declares an RBAC gate


def test_originate_is_a_gated_live_action():
    op = _ops()["voip.pbx.originate_call"]
    # Real-time action: fires immediately from an automation, gated by the
    # manage-phones permission (negotiator enforces it against the author).
    assert op.permission == "voip.manage_phones"
    assert op.write is False and op.handler is not None
    assert "destination" in op.input_schema["properties"]


def test_inbound_route_create_is_a_staged_write_through_the_pipeline():
    op = _ops()["voip.pbx.inbound_route_create"]
    # write=True forces it through AdapterStagingService; the feature must match
    # the dispatcher key so the staged change routes to the FreePBX applier.
    assert op.write is True
    assert op.feature == "pbx.inbound_route.create"
    assert op.permission == "voip.manage_phones"
    assert op.handler is None  # staged writes have no direct handler
    # the executor reads the PBX id from `controller_id`
    assert "controller_id" in op.input_schema["properties"]


def test_write_op_feature_matches_apply_dispatch_and_permission():
    """The op's feature + permission must agree with the apply-time dispatcher
    and permission map, or a staged Fabric write would 400/403 at sign-off."""
    from app.api.v1.endpoints.adapter_omada_vpn import (
        _required_apply_permission,
        _service_for_feature,
    )
    from app.services.adapter_freepbx_inbound_routes import FreePBXInboundRoutesService

    op = _ops()["voip.pbx.inbound_route_create"]
    svc = _service_for_feature(op.feature, session=None)
    assert isinstance(svc, FreePBXInboundRoutesService)
    assert _required_apply_permission(op.feature) == op.permission


def test_voip_emits_trigger_events():
    """Result-events that can drive cross-system automations today."""
    events = {e.event_type for e in VoIPModule().get_emitted_events()}
    assert {"pbx.originate_call.ok", "pbx.reload.ok", "pbx.sync.completed"} <= events

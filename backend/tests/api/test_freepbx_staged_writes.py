# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the FreePBX staged-write vertical (Phase 1: extensions).

Two layers, both fast + offline:

* **Adapter gate** — ``FreePBXAdapter.{create,update,delete}_extension`` must
  enforce the read-only + force dual-gate before any transport call.
* **Service applier** — ``FreePBXExtensionsService.build_applier`` must map
  ``(feature, operation)`` to the right adapter method WITH ``force=True``
  (it only runs inside ``apply_change`` after the env-lock gate has passed),
  and surface a failed ``AdapterResult`` as a 502. ``stage_change`` must
  reject features outside the ``pbx.extension.*`` allowlist.

No DB or network: the applier's controller/client resolution is monkeypatched
to a recording fake adapter.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.adapters.base import AdapterResult
from app.adapters.freepbx.adapter import FreePBXAdapter
from app.services.adapter_freepbx_extensions import FreePBXExtensionsService

# ── Adapter dual-gate ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_adapter_extension_writes_blocked_in_read_only_without_force():
    """read-only + force=False ⇒ refused before any transport call."""
    adapter = FreePBXAdapter(host="pbx.example.test", username="admin", password="x", read_only=True)
    for coro in (
        adapter.create_extension("100", {"name": "X"}, force=False),
        adapter.update_extension("100", {"name": "X"}, force=False),
        adapter.delete_extension("100", force=False),
    ):
        res = await coro
        assert res.success is False
        assert "read-only" in (res.error or "").lower()


@pytest.mark.asyncio
async def test_adapter_extension_writes_pass_gate_with_force():
    """read-only + force=True ⇒ gate passes; the NEXT check (REST API
    availability) is what stops it, proving the gate is not the blocker."""
    adapter = FreePBXAdapter(host="pbx.example.test", username="admin", password="x", read_only=True)
    res = await adapter.update_extension("100", {"name": "X"}, force=True)
    assert res.success is False
    # Past the read-only gate now — fails on transport availability instead.
    assert "read-only" not in (res.error or "").lower()
    assert "REST API" in (res.error or "")


# ── Service applier dispatch ────────────────────────────────────────────


class _RecordingAdapter:
    """Stands in for a connected FreePBXAdapter; records write calls."""

    def __init__(self, *, fail: bool = False):
        self.calls: list[tuple] = []
        self._fail = fail

    async def create_extension(self, ext_number, data, *, force=False):
        self.calls.append(("create", ext_number, data, force))
        return self._result("created")

    async def update_extension(self, ext_number, data, *, force=False):
        self.calls.append(("update", ext_number, data, force))
        return self._result("updated")

    async def delete_extension(self, ext_number, *, force=False):
        self.calls.append(("delete", ext_number, force))
        return self._result("deleted")

    def _result(self, msg):
        if self._fail:
            return AdapterResult.fail(error="freepbx rejected the change")
        return AdapterResult.ok(data={"ok": True}, message=msg)


def _service_with_fake_adapter(fake: _RecordingAdapter) -> FreePBXExtensionsService:
    svc = FreePBXExtensionsService(db=None)  # db unused on the applier path

    async def _fake_get_controller(controller_id, organization_id):
        return SimpleNamespace(id=controller_id, controller_type="freepbx")

    async def _fake_get_client(controller):
        return fake

    svc._get_controller = _fake_get_controller  # type: ignore[assignment]
    svc._get_client = _fake_get_client  # type: ignore[assignment]
    return svc


def _change(feature: str, *, target_id=None, payload=None):
    return SimpleNamespace(
        feature=feature,
        operation=feature.rsplit(".", 1)[-1],
        payload=payload or {},
        target_id=target_id,
        controller_id="11111111-1111-1111-1111-111111111111",
        organization_id="22222222-2222-2222-2222-222222222222",
    )


@pytest.mark.asyncio
async def test_applier_update_calls_adapter_with_force():
    fake = _RecordingAdapter()
    svc = _service_with_fake_adapter(fake)
    applier = svc.build_applier(_change("pbx.extension.update", target_id="100", payload={"name": "New"}))
    await applier(_change("pbx.extension.update", target_id="100", payload={"name": "New"}))
    assert fake.calls == [("update", "100", {"name": "New"}, True)]


@pytest.mark.asyncio
async def test_applier_create_and_delete_pass_force():
    fake = _RecordingAdapter()
    svc = _service_with_fake_adapter(fake)
    await svc.build_applier(_change("pbx.extension.create", target_id="200", payload={"name": "C"}))(
        _change("pbx.extension.create", target_id="200", payload={"name": "C"})
    )
    await svc.build_applier(_change("pbx.extension.delete", target_id="200"))(
        _change("pbx.extension.delete", target_id="200")
    )
    ops = [c[0] for c in fake.calls]
    assert ops == ["create", "delete"]
    assert all(c[-1] is True for c in fake.calls)  # force=True on every write


@pytest.mark.asyncio
async def test_applier_surfaces_failure_as_502():
    fake = _RecordingAdapter(fail=True)
    svc = _service_with_fake_adapter(fake)
    applier = svc.build_applier(_change("pbx.extension.update", target_id="100"))
    with pytest.raises(HTTPException) as ei:
        await applier(_change("pbx.extension.update", target_id="100"))
    assert ei.value.status_code == 502


@pytest.mark.asyncio
async def test_stage_change_rejects_non_extension_feature():
    svc = FreePBXExtensionsService(db=None)
    with pytest.raises(HTTPException) as ei:
        await svc.stage_change(
            feature="pbx.trunk.delete",
            operation="delete",
            payload={},
            controller_id="11111111-1111-1111-1111-111111111111",
            organization_id="22222222-2222-2222-2222-222222222222",
            target_id="9",
        )
    assert ei.value.status_code == 400


# ── Fan-out: every feature's applier passes force=True ──────────────────


class _GenericRecorder:
    """Records every async method call (name, args, kwargs)."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __getattr__(self, name: str):
        async def _rec(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return AdapterResult.ok(data={"ok": True})

        return _rec


def _const_async(val):
    async def _f(*a, **k):
        return val

    return _f


# (module, class, feature, expected adapter method, target_id)
_FANOUT = [
    ("app.services.adapter_freepbx_trunks", "FreePBXTrunksService",
     "pbx.trunk.update", "update_trunk", "t1"),
    ("app.services.adapter_freepbx_ring_groups", "FreePBXRingGroupsService",
     "pbx.ring_group.update", "update_ring_group", "600"),
    ("app.services.adapter_freepbx_queues", "FreePBXQueuesService",
     "pbx.queue.update", "update_queue", "700"),
    ("app.services.adapter_freepbx_ivr", "FreePBXIVRService",
     "pbx.ivr.update", "update_ivr", "1"),
    ("app.services.adapter_freepbx_inbound_routes", "FreePBXInboundRoutesService",
     "pbx.inbound_route.update", "update_did", "5"),
]


@pytest.mark.parametrize("module,cls_name,feature,method,target", _FANOUT)
@pytest.mark.asyncio
async def test_fanout_applier_passes_force(module, cls_name, feature, method, target):
    """Each feature's build_applier dispatches update -> the right adapter
    method with force=True (the env-lock half of the dual-gate is already
    cleared by apply_change before the applier runs)."""
    import importlib

    service_cls = getattr(importlib.import_module(module), cls_name)
    rec = _GenericRecorder()
    svc = service_cls(db=None)
    svc._get_controller = _const_async(SimpleNamespace(id=target, controller_type="freepbx"))
    svc._get_client = _const_async(rec)

    change = _change(feature, target_id=target, payload={"x": 1})
    await svc.build_applier(change)(change)

    assert rec.calls, "applier made no adapter call"
    name, args, kwargs = rec.calls[-1]
    assert name == method, f"{cls_name} called {name}, expected {method}"
    assert kwargs.get("force") is True, f"{cls_name}.{name} not called with force=True"


@pytest.mark.parametrize("module,cls_name,feature,method,target", _FANOUT)
@pytest.mark.asyncio
async def test_fanout_stage_rejects_foreign_feature(module, cls_name, feature, method, target):
    """Each service's stage_change rejects a feature outside its allowlist."""
    import importlib

    service_cls = getattr(importlib.import_module(module), cls_name)
    svc = service_cls(db=None)
    with pytest.raises(HTTPException) as ei:
        await svc.stage_change(
            feature="pbx.extension.delete",  # foreign to every non-extension svc
            operation="delete",
            payload={},
            controller_id="11111111-1111-1111-1111-111111111111",
            organization_id="22222222-2222-2222-2222-222222222222",
            target_id="9",
        )
    assert ei.value.status_code == 400


# ── Every config-write adapter method honours the read-only + force gate ──

# (adapter method name, positional args excluding force)
_GATED_WRITE_METHODS = [
    ("create_extension", ("100", {})),
    ("update_extension", ("100", {})),
    ("delete_extension", ("100",)),
    ("create_trunk", ({},)),
    ("update_trunk", ("1", {})),
    ("delete_trunk", ("1",)),
    ("create_ring_group", ({},)),
    ("update_ring_group", ("600", {})),
    ("delete_ring_group", ("600",)),
    ("create_queue", ({},)),
    ("update_queue", ("700", {})),
    ("delete_queue", ("700",)),
    ("create_ivr", ({},)),
    ("update_ivr", ("1", {})),
    ("delete_ivr", ("1",)),
    ("create_did", ({},)),
    ("update_did", ("5", {})),
    ("delete_did", ("5",)),
    # Live AMI queue-member writes — must honour the same read-only gate.
    ("queue_add_member", ("700", "SIP/100")),
    ("queue_remove_member", ("700", "SIP/100")),
    ("queue_pause_member", ("700", "SIP/100")),
]


@pytest.mark.parametrize("method,args", _GATED_WRITE_METHODS)
@pytest.mark.asyncio
async def test_every_config_write_is_dual_gated(method, args):
    """Every FreePBX config-write adapter method refuses in read-only mode
    without force, and passes the gate (failing later on transport) with
    force=True. Locks in the Phase-2 gating across all 6 features."""
    adapter = FreePBXAdapter(host="pbx.example.test", username="admin", password="x", read_only=True)

    blocked = await getattr(adapter, method)(*args, force=False)
    assert blocked.success is False
    assert "read-only" in (blocked.error or "").lower(), f"{method} not gated"

    passed = await getattr(adapter, method)(*args, force=True)
    assert passed.success is False  # no live transport in the test
    assert "read-only" not in (passed.error or "").lower(), f"{method} gate not bypassable by force"


# ── Inbound-route (DID) composite-id reconstruction ──────────────────────
#
# FreePBX keys an inbound route by (extension, cidnum) and exposes it as the
# single id "{extension}/{cidnum}". That "/" is rejected by the shared
# staging id-validator (slashes are banned because some vendors interpolate
# target_id into a URL path). So the UI/API stage the slash-free extension as
# target_id and carry cidnum in the payload; the applier rebuilds the
# composite. These tests lock in that contract — a live verification against
# pbx.example.test first surfaced the validator rejecting "9995550199/".

from app.services.adapter_freepbx_inbound_routes import (  # noqa: E402
    FreePBXInboundRoutesService,
)


@pytest.mark.parametrize(
    "target,cidnum,expected",
    [
        ("9995550199", "", "9995550199/"),
        ("9995550199", None, "9995550199/"),
        ("15551234", "8005551212", "15551234/8005551212"),
        ("9995550199/", "ignored", "9995550199/"),  # already composite -> pass through
    ],
)
def test_inbound_route_id_reconstruction(target, cidnum, expected):
    assert FreePBXInboundRoutesService._route_id(target, cidnum) == expected


def test_inbound_route_raw_id_rejected_by_staging_validator():
    """Documents WHY reconstruction exists: the raw FreePBX 'ext/cid' id is
    rejected by the shared staging id-validator, so it can never be the
    target_id — the slash-free extension is staged instead."""
    from app.adapters.validation import validate_id

    with pytest.raises(HTTPException) as ei:
        validate_id("9995550199/", label="target_id")
    assert ei.value.status_code == 400
    assert validate_id("9995550199", label="target_id") == "9995550199"


@pytest.mark.asyncio
async def test_inbound_route_delete_rebuilds_composite_id():
    """Delete applier rebuilds 'ext/' from a slash-free target + empty cid."""
    rec = _GenericRecorder()
    svc = FreePBXInboundRoutesService(db=None)
    svc._get_controller = _const_async(SimpleNamespace(id="x", controller_type="freepbx"))
    svc._get_client = _const_async(rec)

    change = _change("pbx.inbound_route.delete", target_id="9995550199", payload={"cidnum": ""})
    await svc.build_applier(change)(change)

    name, args, kwargs = rec.calls[-1]
    assert name == "delete_did"
    assert args == ("9995550199/",)
    assert kwargs.get("force") is True


@pytest.mark.asyncio
async def test_inbound_route_delete_rebuilds_composite_with_cidnum():
    """Delete applier joins extension + cidnum into 'ext/cid'."""
    rec = _GenericRecorder()
    svc = FreePBXInboundRoutesService(db=None)
    svc._get_controller = _const_async(SimpleNamespace(id="x", controller_type="freepbx"))
    svc._get_client = _const_async(rec)

    change = _change(
        "pbx.inbound_route.delete", target_id="15551234", payload={"cidnum": "8005551212"}
    )
    await svc.build_applier(change)(change)

    name, args, kwargs = rec.calls[-1]
    assert name == "delete_did"
    assert args == ("15551234/8005551212",)
    assert kwargs.get("force") is True

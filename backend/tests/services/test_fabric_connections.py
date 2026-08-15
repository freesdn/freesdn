# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for FabricConnectionService spec validation + engine mapping.

Focus is the security-critical authoring gate: a Connection can only be created
if its author holds the RBAC permission each step Operation declares, mirroring
the engine's runtime gate (plugin/write ops with no declared permission are
refused outright). Validation is DB-free, so these run as fast unit tests.
"""
from __future__ import annotations

import uuid

import pytest

from app.core.fabric.operations import Operation, OperationTier
from app.models.fabric import Connection
from app.services.fabric_connections import (
    ConnectionPermissionError,
    ConnectionValidationError,
    FabricConnectionService,
)


class _FakeUser:
    def __init__(self, perms: list[str]) -> None:
        self._perms = set(perms)
        self.id = uuid.uuid4()

    def has_permission(self, p: str) -> bool:
        return p in self._perms


def _svc() -> FabricConnectionService:
    return FabricConnectionService(db=None)  # type: ignore[arg-type]  # _validate_spec is DB-free


def _patch_ops(monkeypatch, ops: dict[str, Operation]) -> None:
    from app.core.fabric.registry import fabric_registry

    monkeypatch.setattr(fabric_registry, "get_operation", lambda oid: ops.get(oid))


class TestValidateSpec:
    def test_unknown_operation_rejected(self, monkeypatch) -> None:
        _patch_ops(monkeypatch, {})
        with pytest.raises(ConnectionValidationError):
            _svc()._validate_spec(
                source_event="a.b", steps=[{"operation_id": "nope"}],
                conditions=None, current_user=_FakeUser([]),
            )

    def test_empty_steps_and_bad_params(self, monkeypatch) -> None:
        op = Operation(id="x.read", title="r", tier=OperationTier.NATIVE, provider_id="x")
        _patch_ops(monkeypatch, {op.id: op})
        with pytest.raises(ConnectionValidationError):
            _svc()._validate_spec(source_event="a.b", steps=[], conditions=None, current_user=_FakeUser([]))
        with pytest.raises(ConnectionValidationError):
            _svc()._validate_spec(
                source_event="a.b", steps=[{"operation_id": "x.read", "params": "nope"}],
                conditions=None, current_user=_FakeUser([]),
            )

    def test_permission_required_enforced(self, monkeypatch) -> None:
        op = Operation(id="storage.dataset.create", title="c", write=True, feature="storage.dataset",
                       permission="storage.write", tier=OperationTier.NATIVE, provider_id="storage")
        _patch_ops(monkeypatch, {op.id: op})
        # author lacks the permission → refused
        with pytest.raises(ConnectionPermissionError):
            _svc()._validate_spec(
                source_event="a.b", steps=[{"operation_id": op.id, "params": {}}],
                conditions=None, current_user=_FakeUser([]),
            )
        # author holds it → ok
        _svc()._validate_spec(
            source_event="a.b", steps=[{"operation_id": op.id, "params": {}}],
            conditions=None, current_user=_FakeUser(["storage.write"]),
        )

    def test_native_sink_no_permission_allowed(self, monkeypatch) -> None:
        op = Operation(id="fabric.notify", title="n", tier=OperationTier.NATIVE, provider_id="fabric")
        _patch_ops(monkeypatch, {op.id: op})
        # native, non-write, permission=None → safe sink, allowed for any author
        _svc()._validate_spec(
            source_event="a.b", steps=[{"operation_id": op.id}], conditions=None, current_user=_FakeUser([]),
        )

    def test_plugin_without_permission_refused(self, monkeypatch) -> None:
        op = Operation(id="plugin.acme.x", title="x", tier=OperationTier.PLUGIN, provider_id="acme")
        _patch_ops(monkeypatch, {op.id: op})
        # plugin op with no declared permission can never run → refused at authoring
        with pytest.raises(ConnectionPermissionError):
            _svc()._validate_spec(
                source_event="a.b", steps=[{"operation_id": op.id}], conditions=None, current_user=_FakeUser([]),
            )

    def test_bad_conditions_rejected(self, monkeypatch) -> None:
        op = Operation(id="x.read", title="r", tier=OperationTier.NATIVE, provider_id="x")
        _patch_ops(monkeypatch, {op.id: op})
        # deeply-nested condition tree beyond the ConditionGroup depth cap
        bad = {"logic": "and", "conditions": []}
        node = bad
        for _ in range(15):
            child = {"logic": "and", "conditions": []}
            node["conditions"].append(child)
            node = child
        with pytest.raises(ValueError):  # ConditionGroup.from_dict raises on excess depth
            _svc()._validate_spec(
                source_event="a.b", steps=[{"operation_id": "x.read"}], conditions=bad, current_user=_FakeUser([]),
            )


class TestEngineMapping:
    def test_to_engine_connection(self) -> None:
        c = Connection(
            organization_id=uuid.uuid4(), name="cam->store", source_event="cameras.event.motion",
            steps=[{"operation_id": "cameras.snapshot", "params": {"camera_id": "{{trigger.camera_id}}"},
                    "continue_on_error": False}],
            enabled=True, conditions=None, cooldown_seconds=30,
        )
        c.id = uuid.uuid4()
        c.created_by = uuid.uuid4()
        ec = FabricConnectionService.to_engine_connection(c)
        assert ec.cooldown_seconds == 30  # cooldown threaded into the engine (loop guard)
        assert ec.id == str(c.id)
        assert ec.organization_id == c.organization_id
        assert ec.source_event == "cameras.event.motion"
        assert ec.actor_id == c.created_by  # author identity carried for the runtime gate
        assert len(ec.steps) == 1
        assert ec.steps[0].operation_id == "cameras.snapshot"
        assert ec.steps[0].continue_on_error is False

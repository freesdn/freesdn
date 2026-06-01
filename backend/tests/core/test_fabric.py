# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the FreeSDN Fabric Phase-0 catalog (operation/event types +
the tier-tagged FabricRegistry discovery).

The registry is a stateless discovery facade over the live module registry,
plugin bridge, and AI tool registry, with lazy imports. We exercise:
- Operation/EventSpec validation + tier/namespace rules,
- native discovery from modules,
- plugin projection (tier=plugin) from the bridge,
- per-module fault isolation (a buggy module never breaks the catalog),
- AI-tool projection + the catalog() shape/counts.
"""
from __future__ import annotations

import pytest

from app.core.fabric.operations import EventSpec, Operation, OperationTier


@pytest.fixture(autouse=True)
def _reset_fabric_catalog_cache():
    """The singleton registry now caches discovery for a few seconds; clear it
    around each test so per-test module/plugin monkeypatches take effect."""
    from app.core.fabric.registry import fabric_registry

    fabric_registry.invalidate()
    yield
    fabric_registry.invalidate()

# ---------------------------------------------------------------------------
# Operation / EventSpec validation
# ---------------------------------------------------------------------------


class TestOperationValidation:
    def test_valid_native_operation(self) -> None:
        op = Operation(
            id="storage.pool.read",
            title="Read pools",
            produces=("application/json",),
            permission="storage.read",
            tier=OperationTier.NATIVE,
            provider_id="storage",
        )
        assert op.id == "storage.pool.read"
        assert op.write is False
        d = op.to_catalog_dict()
        assert d["tier"] == "native" and d["produces"] == ["application/json"]
        assert "handler" not in d  # catalog never leaks the callable

    def test_invalid_id_rejected(self) -> None:
        for bad in ("nodot", "Has.Caps", "trailing.", ".leading", "a..b"):
            with pytest.raises(ValueError):
                Operation(id=bad, title="x")

    def test_write_requires_feature_and_permission(self) -> None:
        with pytest.raises(ValueError):  # missing feature
            Operation(id="storage.dataset.create", title="x", write=True, permission="storage.write")
        with pytest.raises(ValueError):  # missing permission (would run ungated)
            Operation(id="storage.dataset.create", title="x", write=True, feature="storage.dataset")
        op = Operation(id="storage.dataset.create", title="x", write=True,
                       feature="storage.dataset", permission="storage.write")
        assert op.feature == "storage.dataset" and op.permission == "storage.write"

    def test_tier_namespace_rules(self) -> None:
        # native must NOT use the reserved plugin. namespace
        with pytest.raises(ValueError):
            Operation(id="plugin.acme.sync", title="x", tier=OperationTier.NATIVE)
        # plugin MUST be namespaced plugin.*
        with pytest.raises(ValueError):
            Operation(id="acme.sync", title="x", tier=OperationTier.PLUGIN)
        # hyphenated plugin id is allowed
        op = Operation(id="plugin.acme-monitoring.sync", title="x", tier=OperationTier.PLUGIN,
                       provider_id="acme-monitoring")
        assert op.id == "plugin.acme-monitoring.sync"

    def test_event_spec_validation(self) -> None:
        ev = EventSpec(event_type="cameras.event.motion", title="Motion",
                       produces=("image/jpeg",), provider_id="cameras")
        assert ev.to_catalog_dict()["produces"] == ["image/jpeg"]
        with pytest.raises(ValueError):
            EventSpec(event_type="plugin.x.evt", title="x", tier=OperationTier.NATIVE)


# ---------------------------------------------------------------------------
# Registry discovery (native + plugin + fault isolation + AI projection)
# ---------------------------------------------------------------------------


class _FakeModule:
    def __init__(self, mod_id: str, ops=None, events=None, raises: bool = False) -> None:
        self.id = mod_id
        self._ops = ops or []
        self._events = events or []
        self._raises = raises

    def get_operations(self):
        if self._raises:
            raise RuntimeError("boom")
        return self._ops

    def get_emitted_events(self):
        return self._events


def _patch_modules(monkeypatch, modules: dict) -> None:
    from app.modules.registry import module_registry

    monkeypatch.setattr(module_registry, "_modules", modules, raising=False)


def _patch_plugin_bridge(monkeypatch, actions=None, triggers=None) -> None:
    from app.plugins.bridges import automation_bridge

    monkeypatch.setattr(automation_bridge, "get_plugin_actions", lambda: actions or [])
    monkeypatch.setattr(automation_bridge, "get_plugin_triggers", lambda: triggers or [])


def _patch_ai_tools(monkeypatch, tools: dict) -> None:
    import app.modules.ai.tools as ai_tools

    monkeypatch.setattr(ai_tools, "TOOL_REGISTRY", tools, raising=False)


class TestRegistryDiscovery:
    def test_native_discovery(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.core.fabric.registry import fabric_registry

        op = Operation(id="storage.pool.read", title="pools", tier=OperationTier.NATIVE, provider_id="storage")
        ev = EventSpec(event_type="storage.pool.degraded", title="degraded", provider_id="storage")
        _patch_modules(monkeypatch, {"storage": _FakeModule("storage", [op], [ev])})
        _patch_plugin_bridge(monkeypatch)

        ops = fabric_registry.list_operations()
        events = fabric_registry.list_events()
        assert any(o.id == "storage.pool.read" and o.tier is OperationTier.NATIVE for o in ops)
        assert any(e.event_type == "storage.pool.degraded" for e in events)

    def test_plugin_projection_is_tier_plugin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.core.fabric.registry import fabric_registry

        _patch_modules(monkeypatch, {})
        _patch_plugin_bridge(
            monkeypatch,
            actions=[{
                "type": "plugin.acme.sync", "short_type": "sync",
                "description": "Sync", "params_schema": {"type": "object"},
                "plugin_id": "acme",
            }],
            triggers=[{
                "type": "plugin.acme.threshold", "short_type": "threshold",
                "description": "Threshold", "schema": {}, "plugin_id": "acme",
            }],
        )
        ops = fabric_registry.list_operations()
        events = fabric_registry.list_events()
        plugin_op = next(o for o in ops if o.id == "plugin.acme.sync")
        assert plugin_op.tier is OperationTier.PLUGIN and plugin_op.provider_id == "acme"
        assert any(e.event_type == "plugin.acme.threshold" and e.tier is OperationTier.PLUGIN for e in events)

    def test_buggy_module_does_not_break_catalog(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.core.fabric.registry import fabric_registry

        good = Operation(id="net.vlan.read", title="vlans", provider_id="network")
        _patch_modules(monkeypatch, {
            "bad": _FakeModule("bad", raises=True),
            "network": _FakeModule("network", [good]),
        })
        _patch_plugin_bridge(monkeypatch)
        ids = {o.id for o in fabric_registry.list_operations()}
        assert "net.vlan.read" in ids  # the good module still surfaces

    def test_catalog_shape_and_counts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.core.fabric.registry import fabric_registry
        from app.modules.ai.tools import AITool

        nat = Operation(id="storage.pool.read", title="pools", provider_id="storage")
        _patch_modules(monkeypatch, {"storage": _FakeModule("storage", [nat])})
        _patch_plugin_bridge(monkeypatch, actions=[{
            "type": "plugin.acme.sync", "short_type": "sync", "description": "",
            "params_schema": {}, "plugin_id": "acme",
        }])
        _patch_ai_tools(monkeypatch, {
            "list_devices": AITool(name="list_devices", description="d", parameters={}, handler=lambda: None),
            "plugin_acme_foo": AITool(name="plugin_acme_foo", description="p", parameters={}, handler=lambda: None),
        })

        cat = fabric_registry.catalog()
        assert set(cat) >= {"operations", "events", "ai_tools", "counts"}
        ids = {o["id"] for o in cat["operations"]}
        # the fake native op + the built-in fabric.* sinks are all native
        assert "storage.pool.read" in ids and "fabric.notify" in ids
        assert cat["counts"]["plugin_operations"] == 1
        assert cat["counts"]["native_operations"] >= 1
        tiers = {t["name"]: t["tier"] for t in cat["ai_tools"]}
        assert tiers["list_devices"] == "native" and tiers["plugin_acme_foo"] == "plugin"


# ---------------------------------------------------------------------------
# Real reference module declares its ops/events
# ---------------------------------------------------------------------------


class TestCamerasReferenceDeclarations:
    def test_cameras_module_declares_fabric_ops_and_events(self) -> None:
        from app.modules.cameras.module import CamerasModule

        mod = CamerasModule()
        ops = mod.get_operations()
        events = mod.get_emitted_events()
        # snapshot op now has a real handler (executable, not declaration-only)
        snap = next(o for o in ops if o.id == "cameras.snapshot")
        assert "image/jpeg" in snap.produces and snap.handler is not None
        assert all(o.tier is OperationTier.NATIVE for o in ops)
        types = {e.event_type for e in events}
        # The smart-detection alerts are now advertised as canonical
        # ``camera.alert.*`` triggers (matching what _dispatch_alerts publishes),
        # plus the status transitions.
        assert types >= {
            "camera.alert.line_cross", "camera.alert.intrusion",
            "camera.alert.tamper", "camera.alert.face",
            "camera.status.online", "camera.status.offline",
        }
        # The old declarations advertised events that NEVER fired — they must be gone.
        assert "cameras.event.motion" not in types
        assert "cameras.event.person" not in types
        # Every advertised alert trigger can carry a snapshot for the
        # alert→snapshot→store/notify vertical.
        for e in events:
            if e.event_type.startswith("camera.alert."):
                assert "image/jpeg" in e.produces


# ---------------------------------------------------------------------------
# P2 — platform event sources + real-app write targets
# ---------------------------------------------------------------------------


class TestPlatformEventSources:
    def test_builtin_events_expose_change_stream(self) -> None:
        from app.core.fabric.builtin_ops import builtin_events

        evs = {e.event_type: e for e in builtin_events()}
        assert {"controller.change.applied", "controller.change.staged",
                "controller.change.failed",
                "device.status.changed", "device.discovered", "device.updated"} <= set(evs)
        for e in evs.values():
            assert e.tier is OperationTier.NATIVE and e.provider_id == "fabric"
        # the staged-change stream carries the cross-app vendor discriminator
        assert "vendor" in evs["controller.change.applied"].payload_schema.get("properties", {})
        # the device stream carries device_id + status transition data
        assert "device_id" in evs["device.status.changed"].payload_schema.get("properties", {})

    def test_registry_catalog_includes_change_stream(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.core.fabric.registry import fabric_registry

        _patch_modules(monkeypatch, {})
        _patch_plugin_bridge(monkeypatch)
        types = {e.event_type for e in fabric_registry.list_events()}
        assert "controller.change.applied" in types  # always-available source


class TestHypervisorWriteTargets:
    def test_hypervisor_declares_staged_vm_write_ops(self) -> None:
        from app.modules.hypervisor.module import HypervisorModule

        ops = {o.id: o for o in HypervisorModule().get_operations()}
        assert {"hypervisor.vm.snapshot", "hypervisor.vm.start", "hypervisor.vm.stop",
                "hypervisor.vm.shutdown", "hypervisor.vm.reboot",
                # expanded surface: full VM lifecycle + node maintenance as ops
                "hypervisor.vm.suspend", "hypervisor.vm.resume",
                "hypervisor.vm.migrate", "hypervisor.vm.clone",
                "hypervisor.node.reboot", "hypervisor.node.shutdown"} <= set(ops)
        for o in ops.values():
            # device writes: must route through staging (feature) + be permissioned
            assert o.write is True and o.feature and o.permission
            assert o.tier is OperationTier.NATIVE and o.handler is None  # STAGE-only
        # each maps 1:1 to a real applier feature so it actually applies on sign-off
        assert ops["hypervisor.vm.snapshot"].feature == "proxmox.snapshot.create"
        assert ops["hypervisor.vm.start"].feature == "proxmox.vm.start"
        assert ops["hypervisor.vm.reboot"].feature == "proxmox.vm.reboot"
        assert ops["hypervisor.vm.start"].permission == "hypervisor.manage_vms"
        # expanded ops map to their real applier features
        assert ops["hypervisor.vm.migrate"].feature == "proxmox.vm.migrate"
        assert ops["hypervisor.vm.clone"].feature == "proxmox.vm.clone"
        assert ops["hypervisor.vm.suspend"].feature == "proxmox.vm.suspend"
        assert ops["hypervisor.node.reboot"].feature == "proxmox.node.reboot"
        # node maintenance is gated by the dedicated manage_nodes permission
        assert ops["hypervisor.node.reboot"].permission == "hypervisor.manage_nodes"
        assert ops["hypervisor.node.shutdown"].permission == "hypervisor.manage_nodes"
        # migrate needs an explicit target node in its input schema
        assert "target_node" in ops["hypervisor.vm.migrate"].input_schema["properties"]


class TestStorageParticipant:
    def test_storage_module_declares_health_read_and_blob_write(self) -> None:
        from app.core.fabric.operations import MEDIA_BLOB
        from app.modules.storage.module import StorageModule

        ops = {o.id: o for o in StorageModule().get_operations()}
        assert set(ops) == {"storage.health", "storage.store_blob"}
        health = ops["storage.health"]
        assert health.write is False and health.handler is not None
        assert health.permission == "storage.view"
        blob = ops["storage.store_blob"]
        assert blob.write is True and blob.handler is None  # STAGE-only
        assert blob.feature == "storage.store_blob" and blob.permission == "storage.write"
        assert "image/jpeg" in blob.accepts and MEDIA_BLOB in blob.accepts

    def test_storage_module_declares_health_transition_events(self) -> None:
        from app.modules.storage.module import StorageModule

        evs = {e.event_type for e in StorageModule().get_emitted_events()}
        assert {"storage.pool.degraded", "storage.pool.healthy", "storage.capacity.warning",
                "storage.alert.critical", "storage.appliance.unreachable",
                "storage.appliance.online"} <= evs

    def test_dispatcher_routes_store_blob_to_truenas(self) -> None:
        from app.api.v1.endpoints.adapter_omada_vpn import _service_for_feature
        from app.services.adapter_truenas_storage import GatewayTrueNASStorageService

        svc = _service_for_feature("storage.store_blob", None)  # type: ignore[arg-type]
        assert isinstance(svc, GatewayTrueNASStorageService)
        svc2 = _service_for_feature("truenas.storage.store_blob", None)  # type: ignore[arg-type]
        assert isinstance(svc2, GatewayTrueNASStorageService)

    def test_dispatcher_rejects_unknown_truenas_subdomain(self) -> None:
        from fastapi import HTTPException

        from app.api.v1.endpoints.adapter_omada_vpn import _service_for_feature

        with pytest.raises(HTTPException):
            _service_for_feature("truenas.bogus.thing", None)  # type: ignore[arg-type]


class TestModuleMeshSources:
    """Every module declares its REAL emitted bus events as Fabric sources, so
    any module's activity can trigger a cross-app Connection."""

    def test_modules_declare_real_event_sources(self) -> None:
        from app.modules.access_control.module import AccessControlModule
        from app.modules.ai.module import AIModule
        from app.modules.backup.module import BackupModule
        from app.modules.firewall.module import FirewallModule
        from app.modules.network.module import NetworkModule
        from app.modules.voip.module import VoIPModule

        cases = {
            NetworkModule: {"network.vlan.created", "network.wifi.created", "network.wifi.deleted"},
            VoIPModule: {"pbx.sync.failed", "phone.provision.failed", "pbx.originate_call.ok"},
            FirewallModule: {"gateway.sync.completed", "gateway.brain.offline"},
            BackupModule: {"backup.validation.failed"},
            AIModule: {"ai.budget.warning"},
            AccessControlModule: {"access.door.forced", "access.door.granted", "access.door.alarm"},
        }
        for cls, expected in cases.items():
            evs = cls().get_emitted_events()
            ids = {e.event_type for e in evs}
            assert expected <= ids, f"{cls.__name__} missing {expected - ids}"
            assert all(e.tier is OperationTier.NATIVE and e.provider_id for e in evs)

    def test_modules_declare_read_op_handlers(self) -> None:
        # mid-chain read targets — each must have a real handler + permission
        from app.modules.firewall.module import FirewallModule
        from app.modules.network.module import NetworkModule
        from app.modules.voip.module import VoIPModule

        expected = {
            FirewallModule: "firewall.search_alerts",
            NetworkModule: "network.client.list",
            VoIPModule: "voip.phone.live_status",
        }
        for cls, op_id in expected.items():
            ops = {o.id: o for o in cls().get_operations()}
            assert op_id in ops, f"{cls.__name__} missing {op_id}"
            op = ops[op_id]
            assert op.write is False and op.handler is not None and op.permission
            assert op.tier is OperationTier.NATIVE

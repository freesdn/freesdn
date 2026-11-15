# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Each adapter gets the device identifier IT expects.

``tasks/sync.py`` called ``adapter.get_device_status(device.mac_address)`` for
every device of every controller. Proxmox wants a node name and a hypervisor
node's Device row (written by the hypervisor module) has no MAC, so every
status cycle on the 2026-11 soak requested ``/nodes/None/status`` and got a 500.
The same sync called ``.get()`` on the ``AdapterResult`` that OPNsense, pfSense,
MikroTik and OpenWrt return, so their status poll raised AttributeError every
minute.

``adapter_device_id`` (app/services/adapter_factory.py) resolves the identifier
from an explicit per-adapter table. Gates here: every registered adapter is in
that table, and no device read in app/ passes ``.mac_address`` /
``.external_id`` straight to an adapter.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

import app.tasks.sync as sync_mod
from app.adapters.base import AdapterResult
from app.models.core import Controller, Organization, Site
from app.models.devices import Device
from app.services import adapter_factory
from app.services.adapter_factory import DEVICE_ID_KIND, adapter_device_id

APP_ROOT = Path(__file__).resolve().parents[2] / "app"
_DEVICE_READS = {"get_device_status", "get_device_config", "get_device_metrics", "get_device_info"}


# ---------------------------------------------------------------------------
# The resolver and its gates
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "ctype,device,expected",
    [
        ("proxmox", SimpleNamespace(name="pve-a", mac_address=None, serial_number=None), "pve-a"),
        ("omada", SimpleNamespace(name="AP", mac_address="AA:BB:CC:00:00:01"), "AA:BB:CC:00:00:01"),
        ("omada", SimpleNamespace(name="AP", mac_address=None, serial_number="SN1"), "SN1"),
        ("unifi", SimpleNamespace(name="AP", mac_address=None, serial_number=None), None),
        ("opnsense", SimpleNamespace(name="fw", mac_address=None, serial_number=None), ""),
        (
            "truenas",
            SimpleNamespace(name="nas", mac_address="TO BE FILLED BY O"),
            "TO BE FILLED BY O",
        ),
    ],
)
def test_resolver_answers_in_each_adapters_vocabulary(ctype, device, expected):
    assert adapter_device_id(device, ctype) == expected


def test_every_registered_adapter_declares_what_its_device_id_means():
    from app.adapters.registry import adapter_registry  # discovers on import

    registered = set(adapter_registry.list_adapters())
    assert registered, "no adapters registered"
    missing = sorted(registered - set(DEVICE_ID_KIND))
    assert not missing, f"add these adapters to adapter_factory.DEVICE_ID_KIND: {missing}"
    assert set(DEVICE_ID_KIND.values()) <= {"mac", "node_name", "ignored"}


def _raw_identifier_reads(source: str, rel: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _DEVICE_READS
            and node.args
            and isinstance(node.args[0], ast.Attribute)
            and node.args[0].attr in {"mac_address", "external_id"}
        ):
            found.append(f"{rel}:{node.lineno}: {node.func.attr}(<x>.{node.args[0].attr})")
    return found


def test_no_device_read_passes_a_raw_mac_or_external_id_to_an_adapter():
    """Use adapter_device_id(device, controller_type) instead."""
    found = []
    for path in sorted(APP_ROOT.rglob("*.py")):
        if path.relative_to(APP_ROOT).parts[0] == "adapters":
            continue  # an adapter calling its own client speaks its own vocabulary
        rel = path.relative_to(APP_ROOT.parent).as_posix()
        found += _raw_identifier_reads(path.read_text(encoding="utf-8"), rel)
    assert found == []


def test_ratchet_flags_the_soak_regression():
    """The exact line from tasks/sync.py before this fix."""
    planted = (
        "async def f(adapter, device):\n"
        "    return await adapter.get_device_status(device.mac_address)\n"
    )
    assert _raw_identifier_reads(planted, "sync.py") == [
        "sync.py:2: get_device_status(<x>.mac_address)"
    ]


# ---------------------------------------------------------------------------
# The sync, end to end on real PostgreSQL
# ---------------------------------------------------------------------------
class _FakeAdapter:
    def __init__(self, answer):
        self.answer = answer
        self.asked: list = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_device_status(self, device_id):
        self.asked.append(device_id)
        return self.answer


async def _device(db_session, ctype, **dev_kw):
    suffix = uuid4().hex[:8]
    org = Organization(name="Id Org", slug=f"id-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="Id Site", slug=f"id-site-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name=f"{ctype} {suffix}",
        controller_type=ctype,
        host="192.0.2.20",  # TEST-NET-1; nothing is contacted
        port=8006,
        site_id=site.id,
        is_active=True,
        sync_enabled=True,
        config={"username": "u", "password": "not-a-real-secret"},
    )
    db_session.add(ctrl)
    await db_session.flush()
    dev = Device(site_id=site.id, controller_id=ctrl.id, status="unknown", **dev_kw)
    db_session.add(dev)
    await db_session.flush()
    return ctrl, dev


def _wire(monkeypatch, db_session, fake):
    monkeypatch.setattr(adapter_factory, "get_adapter", lambda *_a, **_k: fake)
    monkeypatch.setattr(sync_mod, "build_adapter_for_controller", lambda *_a: fake)

    class _Ctx:
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(sync_mod, "AsyncSessionLocal", lambda: _Ctx())
    monkeypatch.setattr(db_session, "commit", db_session.flush)

    async def _noop(*a, **k):
        return None

    monkeypatch.setattr(sync_mod, "publish_device_event", _noop)


async def test_status_sync_asks_proxmox_for_the_node_by_name(db_session, monkeypatch):
    _ctrl, node = await _device(
        db_session, "proxmox", name="pve-a", device_type="server", mac_address=None
    )
    fake = _FakeAdapter({"uptime": 120, "cpu": 0.1})
    _wire(monkeypatch, db_session, fake)

    out = await sync_mod._sync_device_status(str(node.id))

    assert fake.asked == ["pve-a"]
    assert out["success"] is True
    assert node.uptime_seconds == 120


async def test_batch_status_sync_asks_proxmox_for_the_node_by_name(db_session, monkeypatch):
    ctrl, node = await _device(
        db_session, "proxmox", name="pve-b", device_type="server", mac_address=None
    )
    fake = _FakeAdapter({"uptime": 60})
    _wire(monkeypatch, db_session, fake)

    await sync_mod._sync_all_device_statuses()

    assert "pve-b" in fake.asked
    assert None not in fake.asked


async def test_status_sync_reads_an_adapter_result(db_session, monkeypatch):
    """OPNsense/pfSense/MikroTik/OpenWrt answer with an AdapterResult, not a dict."""
    _ctrl, fw = await _device(
        db_session, "opnsense", name="fw", device_type="firewall", mac_address=None
    )
    fake = _FakeAdapter(AdapterResult.ok(data={"system": {}, "interfaces": [], "gateways": []}))
    _wire(monkeypatch, db_session, fake)

    out = await sync_mod._sync_device_status(str(fw.id))

    assert out["success"] is True, out
    assert str(fw.status) == "online"

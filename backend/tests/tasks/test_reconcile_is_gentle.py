# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The periodic config reconciliation contacts no device, and runs on a budget.

Measured cost per cycle (``enterprise-reconcile-all``): one ``SELECT`` of the
managed device ids, then one ``reconcile_device`` task per managed device on the
``sync`` queue, each one ``SELECT`` of the device, one of its DeviceConfig, the
template resolution, and one ``UPDATE``. ZERO device requests: the per-device
task compares desired with pushed config in the database; the adapter-based
``ReconciliationService.reconcile_site`` (which does call
``get_running_config``) has no caller. If the periodic path ever starts reading
running config from devices, it must take the device slot and honour the
breaker like every other poller; this test is the tripwire.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from app.core.celery_app import celery_app
from app.core.config import settings
from app.tasks import reconciliation

SOURCE = Path(reconciliation.__file__)


def test_the_periodic_reconciliation_never_builds_an_adapter() -> None:
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    names = {
        node.attr if isinstance(node, ast.Attribute) else node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute | ast.Name)
    }
    for device_call in (
        "get_running_config",
        "build_adapter_for_controller",
        "get_adapter",
        "build_adapter",
        "reconcile_site",
    ):
        assert device_call not in names, (
            f"app/tasks/reconciliation.py now uses {device_call}: a periodic device read "
            "must take the device slot (app/core/device_slot.py) and skip on an open "
            "breaker, like every other poller"
        )


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Session:
    def __init__(self, device, config):
        self.results = [_Result(device), _Result(config)]
        self.commits = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def execute(self, _stmt):
        return self.results.pop(0)

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        return None


def test_one_device_reconcile_is_database_only(monkeypatch) -> None:
    import app.adapters as adapters
    import app.services.adapter_factory as factory

    def no_device(*_a, **_k):
        raise AssertionError("reconcile_device contacted a device")

    monkeypatch.setattr(factory, "build_adapter_for_controller", no_device)
    monkeypatch.setattr(factory, "get_adapter", no_device)
    monkeypatch.setattr(adapters, "get_adapter", no_device)

    class _Resolver:
        def __init__(self, _session):
            pass

        async def resolve(self, _device):
            return {"vlan": 10}

    monkeypatch.setattr(reconciliation, "TemplateResolver", _Resolver)
    device = SimpleNamespace(id=uuid4(), lifecycle_state="managed")
    config = SimpleNamespace(
        pushed_config={"vlan": 20}, running_config=None, has_drift=False, drift_details=None
    )
    session = _Session(device, config)
    monkeypatch.setattr(reconciliation, "AsyncSessionLocal", lambda: session)
    result = asyncio.run(reconciliation._reconcile_device(str(device.id)))
    assert result == {"success": True, "device_id": str(device.id), "has_drift": True}
    assert session.commits == 1


def test_the_reconciliation_runs_on_its_budget() -> None:
    entry = celery_app.conf.beat_schedule["enterprise-reconcile-all"]
    assert float(entry["schedule"]) == float(settings.RECONCILE_INTERVAL_SECONDS) >= 300

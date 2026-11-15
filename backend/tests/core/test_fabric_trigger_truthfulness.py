# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The Fabric catalog must not offer triggers that cannot fire.

A trigger is only real if its event reaches the negotiator WITH an organization
(``Negotiator.would_handle`` drops org-less events). Six network events and two
gateway events were published without one, so every Connection wired to them
was dead; the ratchet below fails on any advertised event constructed without
``organization_id``.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

APP = Path(__file__).resolve().parents[2] / "app"
_PUBLISH_HELPERS = {"_emit", "_network_event"}


def _advertised_events() -> set[str]:
    import importlib
    import pkgutil

    import app.modules

    advertised: set[str] = set()
    for _finder, name, _pkg in pkgutil.iter_modules(app.modules.__path__, "app.modules."):
        try:
            module = importlib.import_module(name + ".module")
        except ModuleNotFoundError:
            continue
        for value in vars(module).values():
            getter = getattr(value, "get_emitted_events", None)
            if (
                isinstance(value, type)
                and getter is not None
                and value.__module__ == module.__name__
            ):
                try:
                    advertised |= {spec.event_type for spec in value().get_emitted_events()}
                except TypeError:
                    continue
    return advertised


def _orgless_publications(advertised: set[str]) -> list[str]:
    found = []
    for path in APP.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            keywords = {k.arg for k in node.keywords}
            event_type = None
            if name == "Event":
                for keyword in node.keywords:
                    if keyword.arg == "event_type" and isinstance(keyword.value, ast.Constant):
                        event_type = keyword.value.value
            elif name in _PUBLISH_HELPERS and node.args and isinstance(node.args[0], ast.Constant):
                event_type = node.args[0].value
            if (
                isinstance(event_type, str)
                and event_type in advertised
                and "organization_id" not in keywords
            ):
                found.append(f"{path.relative_to(APP.parent)}:{node.lineno} {event_type}")
    return found


def test_every_advertised_trigger_is_published_with_an_organization():
    advertised = _advertised_events()
    assert {"network.vlan.created", "gateway.sync.completed", "access.door.locked"} <= advertised
    assert _orgless_publications(advertised) == []


async def test_network_vlan_event_reaches_the_fabric_with_its_org(monkeypatch):
    from app.core.fabric.negotiator import Connection, Negotiator
    from app.modules.network import service as network_service

    published = []
    bus = SimpleNamespace(publish=AsyncMock(side_effect=published.append))
    monkeypatch.setattr(network_service, "get_event_bus", lambda: bus)
    db = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    svc = network_service.VlanService(db)
    monkeypatch.setattr(svc, "get_by_vlan_id", AsyncMock(return_value=None))
    org = uuid4()
    await svc.create(organization_id=org, vlan_id=30, name="cameras")
    [event] = published
    assert event.event_type == "network.vlan.created"
    assert event.organization_id == str(org)

    negotiator = Negotiator()
    negotiator._connections = {
        "c": Connection(
            id="c",
            organization_id=org,
            name="vlan wire",
            enabled=True,
            source_event="network.vlan.created",
            steps=[],
        )
    }
    assert negotiator.would_handle(event)

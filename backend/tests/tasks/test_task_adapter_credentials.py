# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Periodic tasks must authenticate with the credentials the controller page saved.

Creating a Proxmox controller with an API token stores ``config.token_id`` and an
encrypted ``config.token_secret`` (controllers.py create). Discovery reads them
through ``build_adapter_for_controller``. ``tasks/sync.py`` (device status every
minute, controller health every two minutes, device config) and
``tasks/metrics.py`` hand-built their own adapter kwargs with no token branch, so
a token-only controller connected with an empty username and password on every
one of those paths: the health check marked it UNREACHABLE every two minutes
while discovery marked it connected every five, the bug-14 flip-flop again.

Both tests fail on the previous tasks (captured kwargs carry no token_id) and run
on real PostgreSQL without opening any socket.
"""

from __future__ import annotations

from uuid import uuid4

import app.tasks.metrics as metrics_mod
import app.tasks.sync as sync_mod
from app.core.crypto import encrypt_credential
from app.models.core import Controller, ControllerStatus, Organization, Site
from app.services import adapter_factory

TOKEN_ID = "monitor@pve!readonly"
TOKEN_SECRET = "not-a-real-token-secret"


class _FakeAdapter:
    # The controller health check probes with connect() since 78c3d542; this
    # fake predated that and only had get_devices(), so the probe raised
    # AttributeError and the check marked the controller UNREACHABLE.
    async def connect(self):
        return True

    async def disconnect(self):
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_devices(self):
        return []

    async def get_system_info(self):
        return {"version": "9"}


async def _token_controller(db_session):
    suffix = uuid4().hex[:8]
    org = Organization(name="Tok Org", slug=f"tok-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="Tok Site", slug=f"tok-site-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name=f"PVE {suffix}",
        controller_type="proxmox",
        host="192.0.2.10",  # TEST-NET-1; nothing is contacted
        port=8006,
        site_id=site.id,
        is_active=True,
        sync_enabled=True,
        status=ControllerStatus.UNKNOWN,
        config={
            "token_id": TOKEN_ID,
            "token_secret": encrypt_credential(TOKEN_SECRET),
            "realm": "pve",
        },
    )
    db_session.add(ctrl)
    await db_session.flush()
    return ctrl


def _capture(monkeypatch, db_session, *modules):
    captured: list[dict] = []

    def _fake_get_adapter(*args, **kwargs):
        captured.append(kwargs)
        return _FakeAdapter()

    # The new code reaches get_adapter through build_adapter_for_controller; the
    # old code held its own reference. Patch both so neither opens a socket.
    monkeypatch.setattr(adapter_factory, "get_adapter", _fake_get_adapter)
    for mod in modules:
        monkeypatch.setattr(mod, "get_adapter", _fake_get_adapter, raising=False)

    class _Ctx:
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False

    for mod in modules:
        monkeypatch.setattr(mod, "AsyncSessionLocal", lambda: _Ctx())
    monkeypatch.setattr(db_session, "commit", db_session.flush)
    return captured


async def test_controller_health_check_passes_the_proxmox_api_token(db_session, monkeypatch):
    ctrl = await _token_controller(db_session)
    captured = _capture(monkeypatch, db_session, sync_mod)

    await sync_mod._check_controller_health()

    mine = [kw for kw in captured if kw.get("host") == ctrl.host]
    assert len(mine) == 1
    assert mine[0].get("token_id") == TOKEN_ID
    assert mine[0].get("token_secret") == TOKEN_SECRET
    assert mine[0].get("realm") == "pve"
    assert ctrl.status == ControllerStatus.CONNECTED


async def test_controller_metrics_pass_the_proxmox_api_token(db_session, monkeypatch):
    ctrl = await _token_controller(db_session)
    captured = _capture(monkeypatch, db_session, metrics_mod)

    out = await metrics_mod._collect_controller_metrics(str(ctrl.id))

    assert out["success"] is True
    assert [kw.get("token_id") for kw in captured] == [TOKEN_ID]
    assert captured[0].get("token_secret") == TOKEN_SECRET

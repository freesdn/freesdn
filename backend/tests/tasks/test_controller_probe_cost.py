# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A controller health probe no longer costs a login every run.

Evidence: the probe was ``connect()`` then ``disconnect()``. On Omada that is a
POST login and a logout every 120 s, about 720 logins a day per controller,
each in the controller's own log; on UniFi OS it also spends the identity
service's login rate limit. Now Omada keeps its session (in the worker's
memory) and asks ``loginStatus``, which never creates one; types that must log
in to be probed are probed at most every 300 s; types that authenticate every
request keep their per-run probe.

The Omada controller here is the session-tracking fake from the client tests
(its loginStatus, cookie and CSRF behaviour come from a real OC300).
"""

from __future__ import annotations

import asyncio

import pytest

from app.adapters.omada.adapter import OmadaAdapter
from app.adapters.omada.client import OmadaApiClient, OmadaClientConfig
from app.db.models import ControllerStatus
from app.tasks import sync as sync_tasks
from tests.adapters.omada.test_real_controller_semantics import (
    API,
)
from tests.adapters.omada.test_real_controller_semantics import (
    fake as fake,  # noqa: F401 - fixture
)
from tests.tasks.test_controller_health_recovery import _Controller, _row
from tests.tasks.test_controller_health_recovery import env as env  # noqa: F401


@pytest.fixture(autouse=True)
def _no_kept_sessions():
    sync_tasks._KEPT_OMADA_SESSIONS.clear()
    yield
    sync_tasks._KEPT_OMADA_SESSIONS.clear()


def _omada_client() -> OmadaApiClient:
    return OmadaApiClient(
        OmadaClientConfig(
            host="omada.invalid",
            username="probe",
            password="probe",
            max_retries=1,
            retry_backoff=0.0,
            rate_limit_rpm=6000,
        )
    )


# ── the client pieces (app/adapters/omada/client.py) ───────────────────


async def test_a_kept_session_is_resumed_with_one_login_status_and_no_login(fake):
    first = _omada_client()
    await first.login()
    state = first.session_state()
    await first.close_keeping_session()
    assert state is not None and fake.logins == 1
    assert fake.paths("/logout") == [], "keeping a session must not log it out"

    again = _omada_client()
    assert await again.resume_session(state) is True
    assert fake.logins == 1 and len(fake.paths("/loginStatus")) == 1
    # The resumed client is a working session: a read goes through without a login.
    status = await again._request("GET", "/maintenance/controllerStatus")
    assert status["name"] == "oc-fake" and fake.logins == 1
    await again.close_keeping_session()


async def test_a_session_the_controller_ended_is_not_resumed(fake):
    first = _omada_client()
    await first.login()
    state = first.session_state()
    await first.close_keeping_session()
    fake.end_all_sessions()

    again = _omada_client()
    assert await again.resume_session(state) is False
    assert [r.url.path for r in fake.requests[-1:]] == [f"{API}/loginStatus"]
    assert fake.logins == 1, "resume never logs in by itself"


# ── the health check ───────────────────────────────────────────────────


def test_the_omada_health_probe_logs_in_once_not_every_run(env, fake, monkeypatch):
    """Fails on the old probe: one login (and one logout) per run."""
    import app.services.adapter_factory as factory

    row = _row(ControllerStatus.CONNECTED)
    env([(row, lambda _w: None)])
    monkeypatch.setattr(
        factory,
        "build_adapter_for_controller",
        lambda _c: OmadaAdapter(host="omada.invalid", username="probe", password="probe"),
    )
    for _ in range(3):
        out = asyncio.run(sync_tasks._check_controller_health())
        assert out["checked"] == 1 and out["unreachable"] == 0
    assert fake.logins == 1
    assert len(fake.paths("/loginStatus")) == 2
    assert fake.paths("/logout") == []
    assert row.status == ControllerStatus.CONNECTED


def test_the_omada_probe_logs_in_again_when_the_controller_ended_the_session(
    env, fake, monkeypatch
):
    import app.services.adapter_factory as factory

    row = _row(ControllerStatus.CONNECTED)
    env([(row, lambda _w: None)])
    monkeypatch.setattr(
        factory,
        "build_adapter_for_controller",
        lambda _c: OmadaAdapter(host="omada.invalid", username="probe", password="probe"),
    )
    asyncio.run(sync_tasks._check_controller_health())
    fake.end_all_sessions()  # the controller restarted
    asyncio.run(sync_tasks._check_controller_health())
    assert fake.logins == 2
    assert row.status == ControllerStatus.CONNECTED


def test_a_type_that_must_log_in_is_probed_at_most_every_login_interval(env):
    """Fails on the old check: a UniFi login every run."""
    row = _row(ControllerStatus.CONNECTED)
    row.controller_type = "unifi"
    _, adapters = env([(row, lambda w: _Controller(w))])
    first = asyncio.run(sync_tasks._check_controller_health())
    second = asyncio.run(sync_tasks._check_controller_health())
    assert adapters[row.id].calls == ["connect"]
    assert first["checked"] == 1 and second["skipped"] == 1 and second["checked"] == 0
    assert row.status == ControllerStatus.CONNECTED, "a skipped probe changes nothing"


def test_a_type_that_opens_no_session_is_still_probed_every_run(env):
    row = _row(ControllerStatus.CONNECTED)
    row.controller_type = "opnsense"
    _, adapters = env([(row, lambda w: _Controller(w))])
    for _ in range(2):
        asyncio.run(sync_tasks._check_controller_health())
    assert adapters[row.id].calls == ["connect", "connect"]


@pytest.mark.parametrize(
    "kind,config,every_run",
    [
        ("omada", {}, True),
        ("omada", {"connection_mode": "cloud"}, False),
        ("opnsense", {}, True),
        ("pfsense", {}, True),
        ("mikrotik", {}, True),
        ("hikvision", {}, True),
        ("proxmox", {"token_id": "root@pam!probe"}, True),
        ("proxmox", {}, False),
        ("unifi", {}, False),
        ("openwrt", {}, False),
        ("truenas", {}, False),
        ("freepbx", {}, False),
        ("onvif", {}, False),
        ("unifi_protect", {}, False),
    ],
)
def test_each_type_gets_the_probe_its_cost_allows(kind, config, every_run):
    from types import SimpleNamespace

    ctrl = SimpleNamespace(
        controller_type=kind,
        connection_mode=config.get("connection_mode", "local"),
        config=config,
    )
    assert (sync_tasks._probe_spacing(ctrl) == 0) is every_run

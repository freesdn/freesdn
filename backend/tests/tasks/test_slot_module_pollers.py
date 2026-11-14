# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Module monitors (Omada, NVR, phone) take the device slot and the breaker.

Evidence (2026-11 soak): the office OPNsense got the full sync, the 2-minute
health poll and drift reads at the same moments, each holding a PHP worker,
and nothing coordinated them. These tests run the real poll bodies against
synthetic devices; the device slots and the breakers they consult live in the
real Valkey of the test run.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from app.core.crypto import encrypt_credential
from app.core.device_breaker import controller_key, phone_key
from app.core.device_slot import device_slots, nvr_slot_key


def _hold(key: str, holder: str = "another poller"):
    lease = device_slots.try_acquire(key, holder, ttl=60)
    assert lease is not None and lease.guarded, "the test needs real Valkey"
    return lease


class _MonitorResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._rows))

    def all(self):
        return []  # no organization has the module switched off


def test_the_omada_monitor_leaves_an_unreachable_controller_alone(monkeypatch):
    from app.core.device_breaker import controller_breaker
    from app.tasks import omada_monitor

    ctrl = SimpleNamespace(
        id=uuid4(),
        name="omada",
        host="192.0.2.50",
        connection_mode="local",
        site=SimpleNamespace(organization_id=uuid4()),
    )

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

        async def execute(self, _stmt):
            return _MonitorResult([ctrl])

    built: list = []
    monkeypatch.setattr(omada_monitor, "CelerySessionLocal", _Session)

    class _Down:
        async def connect(self):
            raise httpx.ConnectTimeout("no answer")

        async def disconnect(self):
            return None

    monkeypatch.setattr(omada_monitor, "_build_omada_adapter", lambda c: built.append(c) or _Down())
    results = [asyncio.run(omada_monitor._poll_omada_health()) for _ in range(4)]
    assert len(built) == 2, "two failed cycles, then the breaker holds it off"
    assert [r["skipped"] for r in results] == [0, 0, 1, 1]
    assert controller_breaker.peek(controller_key(ctrl.id)) == "open"


def test_the_camera_health_poll_leaves_an_nvr_the_alert_ingest_is_reading(monkeypatch):
    import app.adapters.hikvision.adapter as hik
    from app.tasks import cameras

    nvr = SimpleNamespace(
        id=uuid4(),
        username="admin",
        password_encrypted=encrypt_credential("pw"),
        ip_address="192.0.2.60",
        port=80,
        organization_id=uuid4(),
    )

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

        async def get(self, _model, _id):
            return nvr

    calls: list = []

    class _Nvr:
        def __init__(self, **_kw):
            pass

        async def connect(self):
            calls.append("connect")

        async def disconnect(self):
            calls.append("disconnect")

    monkeypatch.setattr(cameras, "AsyncSessionLocal", _Session)
    monkeypatch.setattr(hik, "HikvisionAdapter", _Nvr)
    held = _hold(nvr_slot_key(nvr), "NVR alert ingest")
    result = asyncio.run(cameras._poll_single_nvr_health(nvr.id))
    device_slots.release(held)
    assert calls == []
    assert result["skipped"] is True and "NVR alert ingest" in result["reason"]


@pytest.fixture
def phone_fakes(monkeypatch):
    import app.db.session as db_session
    import app.modules.voip.service as voip_service
    from tests.modules.test_voip_phone_polling import _FakeService, _FakeSession

    _FakeService.by_state = {}
    _FakeService.updates = []
    monkeypatch.setattr(db_session, "celery_session_factory", _FakeSession)
    monkeypatch.setattr(voip_service, "VoIPService", _FakeService)
    return _FakeService


def test_a_phone_that_does_not_answer_is_not_logged_into_every_cycle(phone_fakes, monkeypatch):
    """Fails on the old check: one login attempt per phone on every run."""
    from app.core.device_breaker import phone_breaker
    from app.modules.voip import tasks
    from tests.modules.test_voip_phone_polling import _phone

    phone = _phone({"web_password": encrypt_credential("pw")}, state="managed")
    phone.ip_address = "192.0.2.70"
    phone_fakes.by_state = {"managed": [phone]}
    logins: list = []

    class _Down:
        def __init__(self, **_kw):
            logins.append(1)

        async def __aenter__(self):
            raise httpx.ConnectTimeout("no answer")

        async def __aexit__(self, *_exc):
            return False

    monkeypatch.setattr(tasks, "_get_adapter", lambda _vendor, **kw: _Down(**kw))
    results = [tasks.health_check() for _ in range(4)]
    assert len(logins) == 2
    assert [r["skipped"] for r in results] == [0, 0, 1, 1]
    assert phone_breaker.peek(phone_key(phone.id)) == "open"

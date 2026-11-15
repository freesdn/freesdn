# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Phone polling must reach the phones an operator adopted, with their saved login.

Found on the 2026-11 soak VM with 15 real Grandstream phones: ``voip.health_check``
ran every five minutes and changed nothing. Two defects, each enough on its own:

* it polled only ``lifecycle_state == "managed"``, and nothing in the product
  moves a phone there (onboarding stops at "onboarding"; ``mark_phone_managed``
  has no caller), so it polled no phone at all;
* ``_phone_creds`` read ``settings.username/password``, which nothing writes,
  and defaulted to ``admin``/``admin``. ``save_phone_credentials`` stores
  ``web_username`` + an encrypted ``web_password``, so a polled phone would have
  been sent the factory default every five minutes.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.crypto import encrypt_credential
from app.modules.voip import tasks


def _phone(settings: dict, *, state: str = "onboarding") -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        ip_address="192.0.2.10",
        vendor="grandstream",
        settings=settings,
        mac_address="00:0b:82:00:00:01",
        status="online",
        last_seen=None,
        lifecycle_state=state,
    )


def test_the_saved_encrypted_login_is_used():
    phone = _phone({"web_username": "ops", "web_password": encrypt_credential("s3cret")})
    assert tasks._phone_creds(phone) == ("ops", "s3cret")


def test_rows_with_the_older_plain_keys_still_work():
    assert tasks._phone_creds(_phone({"username": "u", "password": "p"})) == ("u", "p")


@pytest.mark.parametrize("settings", [{}, {"web_username": "admin"}, {"web_password": ""}])
def test_no_saved_password_means_no_guess(settings):
    assert tasks._phone_creds(_phone(settings)) is None


class _FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def commit(self):
        return None


class _FakeService:
    by_state: dict[str, list] = {}
    updates: list = []

    def __init__(self, _session):
        pass

    async def list_phones(self, *, site_id=None, lifecycle_state=None, limit=100):
        return list(self.by_state.get(lifecycle_state, [])), 0

    async def update_phone(self, phone_id, data):
        self.updates.append((phone_id, dict(data)))


class _FakeAdapter:
    logins: list = []

    def __init__(self, **kwargs):
        self.logins.append((kwargs["username"], kwargs["password"]))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def get_device_status(self, _mac):
        return {"data": {"sip_registered": True, "uptime": 42}}


@pytest.fixture
def fakes(monkeypatch):
    import app.db.session as db_session
    import app.modules.voip.service as voip_service

    _FakeService.by_state = {}
    _FakeService.updates = []
    _FakeAdapter.logins = []
    monkeypatch.setattr(db_session, "celery_session_factory", _FakeSession)
    monkeypatch.setattr(voip_service, "VoIPService", _FakeService)
    monkeypatch.setattr(tasks, "_get_adapter", lambda _vendor, **kw: _FakeAdapter(**kw))
    return _FakeService


def test_the_health_check_polls_adopted_phones_with_their_saved_login(fakes):
    onboarding = _phone({"web_username": "ops", "web_password": encrypt_credential("pw1")})
    managed = _phone({"web_password": encrypt_credential("pw2")}, state="managed")
    fakes.by_state = {"onboarding": [onboarding], "managed": [managed]}

    result = tasks.health_check()

    assert result["total"] == 2 and result["healthy"] == 2
    assert sorted(_FakeAdapter.logins) == [("admin", "pw2"), ("ops", "pw1")]
    statuses = {pid: data.get("status") for pid, data in fakes.updates}
    assert statuses == {onboarding.id: "online", managed.id: "online"}


def test_the_health_check_never_polls_a_discovered_phone(fakes):
    fakes.by_state = {"discovered": [_phone({"web_password": "x"}, state="discovered")]}
    result = tasks.health_check()
    assert result["total"] == 0 and _FakeAdapter.logins == []


def test_a_phone_without_a_saved_login_is_left_alone(fakes):
    phone = _phone({}, state="managed")
    fakes.by_state = {"managed": [phone]}

    result = tasks.health_check()

    assert result["no_credentials"] == 1
    assert _FakeAdapter.logins == [], "no login may be attempted without saved credentials"
    assert fakes.updates == [], "an unknown login says nothing about the phone's status"

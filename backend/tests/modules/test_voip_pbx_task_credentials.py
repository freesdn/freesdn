# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The PBX Celery tasks must log in with the PBX's saved credentials.

``voip.sync_cdr``, ``voip.sync_extensions`` and ``voip.poll_extension_states``
built their adapter from ``settings.api_username`` / ``settings.api_password``.
The password has lived in the encrypted ``web_password_enc`` column since the
VoIP secrets migration, so every one of these tasks sent an EMPTY password, and
none of them passed the AMI or ARI login at all. ``sync_extensions`` also
iterated the ``AdapterResult`` envelope instead of its data, so even a
successful listing could not have been read.

The UI path (``VoIPService._adapter_from_pbx``) and the staged-write bridge
already build through ``build_freepbx_adapter_from_pbx``; these tests pin the
tasks to the same factory by observing what the adapter is constructed with.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.adapters.base import AdapterResult
from app.core.crypto import encrypt_credential
from app.modules.voip import tasks


def _pbx() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        name="pbx-1",
        pbx_type="freepbx",
        ip_address="192.0.2.20",
        api_port=443,
        # What the PBX create/update path actually stores today: the logins in
        # settings, the secrets only in the encrypted columns.
        settings={"api_username": "admin", "ami_username": "freesdn-ami"},
        web_password_enc=encrypt_credential("web-secret"),
        ami_secret_enc=encrypt_credential("ami-secret"),
        ari_password_enc=None,
        api_client_id=None,
        api_client_secret_enc=None,
        tls_verify_disabled_acknowledged=False,
        last_sync_at=None,
    )


class _Recorder:
    built: list[dict] = []
    extensions: list[dict] = []

    def __init__(self, **kwargs):
        type(self).built.append(kwargs)
        self._ami = SimpleNamespace(connected=False)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def list_extensions(self):
        return AdapterResult.ok(data=list(type(self).extensions))

    async def search_call_logs(self, **_kw):
        return AdapterResult.ok(data=[])

    async def discover_devices(self):
        return []


class _FakeSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def commit(self):
        return None


class _FakeService:
    pbx: SimpleNamespace | None = None
    created: list[str] = []

    def __init__(self, _session):
        pass

    async def get_pbx(self, _pbx_id):
        return type(self).pbx

    async def list_pbx_systems(self, limit=200):
        return [type(self).pbx], 1

    async def list_extensions(self, pbx_id=None, limit=5000):
        return [], 0

    async def create_extension(self, *, pbx_id, extension_number, display_name, ext_type):
        type(self).created.append(extension_number)


@pytest.fixture
def harness(monkeypatch):
    import app.adapters.freepbx as freepbx_pkg
    import app.db.session as db_session
    import app.modules.voip.service as voip_service

    _Recorder.built = []
    _Recorder.extensions = []
    _FakeService.pbx = _pbx()
    _FakeService.created = []
    monkeypatch.setattr(db_session, "celery_session_factory", _FakeSession)
    monkeypatch.setattr(voip_service, "VoIPService", _FakeService)
    # The shared factory constructs FreePBXAdapter; the legacy path went through
    # the generic registry. Both are observed so the old code fails on the
    # credentials it sent, not on a network timeout.
    monkeypatch.setattr(freepbx_pkg, "FreePBXAdapter", _Recorder)
    # sync_cdr records its outcome on the (here unmapped) PBX row and holds a
    # per-PBX lock; neither is what these tests are about.
    monkeypatch.setattr(tasks, "_record_cdr_state", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        tasks,
        "_get_adapter",
        lambda _vendor, host, username, password, **kw: _Recorder(
            host=host, username=username, password=password, **kw
        ),
    )
    return _FakeService


def _only_login() -> dict:
    assert len(_Recorder.built) == 1, _Recorder.built
    return _Recorder.built[0]


@pytest.mark.parametrize(
    "run",
    [
        lambda pbx_id: tasks.sync_cdr.run(pbx_id),
        lambda pbx_id: tasks.sync_extensions.run(pbx_id),
        lambda _pbx_id: tasks.poll_extension_states.run(),
    ],
    ids=["sync_cdr", "sync_extensions", "poll_extension_states"],
)
def test_each_pbx_task_logs_in_with_the_saved_encrypted_credentials(harness, run):
    run(str(harness.pbx.id))

    login = _only_login()
    assert login["password"] == "web-secret"
    assert login.get("ami_username") == "freesdn-ami"
    assert login.get("ami_secret") == "ami-secret"
    # TLS stays verified unless the operator acknowledged otherwise.
    assert login.get("verify_ssl") is True


def test_extension_sync_reads_the_records_inside_the_result(harness):
    _Recorder.extensions = [{"extension": "101", "name": "Front desk"}]

    result = tasks.sync_extensions.run(str(harness.pbx.id))

    assert result["status"] == "success", result
    assert result["added"] == 1
    assert harness.created == ["101"]

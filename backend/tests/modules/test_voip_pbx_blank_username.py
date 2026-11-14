# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A blank PBX username means the same login on the test and on the saved PBX.

Before: the connection test turned a blank ``api_username`` into ``admin``,
while create and edit stored the blank and ``build_freepbx_adapter_from_pbx``
passed ``""`` as the login. A test could pass and the saved PBX then fail every
sync. The test's REST probe also dropped the OAuth2 client credentials, so a PBX
set up for the Admin API (where the web username is often left blank) failed
the test with a web-session login it never uses. A failed test did not say
which login it had tried.

Nothing here opens a socket: the AMI, ARI and REST clients are replaced.
"""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

import app.adapters.freepbx.adapter as freepbx_adapter
from app.adapters.freepbx import FreePBXAdapter
from app.adapters.freepbx.exceptions import AMIConnectionError, ARIConnectionError
from app.core.crypto import encrypt_credential
from app.modules.voip.adapter_factory import (
    DEFAULT_FREEPBX_USERNAME,
    build_freepbx_adapter_from_pbx,
)
from app.modules.voip.schemas import PBXCreate, PBXTestConnection
from app.modules.voip.service import VoIPService


class _Down:
    """An AMI or ARI client whose PBX does not answer."""

    def __init__(self, *_a, **kw) -> None:
        self.username = kw.get("username")
        self.secret = kw.get("secret")
        self.password = kw.get("password")
        self.port = kw.get("port", 0)

    async def connect(self) -> None:
        raise AMIConnectionError("no AMI here")

    async def disconnect(self) -> None:
        return None


class _AriDown(_Down):
    async def connect(self) -> None:
        raise ARIConnectionError("no ARI here")


class _Rest:
    """A REST client that connects only with OAuth2 client credentials."""

    built: list[dict] = []

    def __init__(self, **kw) -> None:
        type(self).built.append(kw)
        self.port = kw.get("port")
        self.use_ssl = kw.get("use_ssl", True)
        self.verify_ssl = kw.get("verify_ssl", True)
        self.api_client_id = kw.get("api_client_id")
        self.api_client_secret = kw.get("api_client_secret")

    async def connect(self) -> None:
        if not (self.api_client_id and self.api_client_secret):
            from app.adapters.freepbx.exceptions import FreePBXAuthError

            raise FreePBXAuthError("web login refused")

    async def check_availability(self) -> dict:
        return {"core": True}

    async def disconnect(self) -> None:
        return None


@pytest.fixture
def clients(monkeypatch):
    _Rest.built = []
    monkeypatch.setattr(freepbx_adapter, "AMIClient", _Down)
    monkeypatch.setattr(freepbx_adapter, "ARIClient", _AriDown)
    monkeypatch.setattr(freepbx_adapter, "FreePBXRestClient", _Rest)
    return _Rest


def _service() -> VoIPService:
    service = VoIPService.__new__(VoIPService)
    service.db = None
    return service


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_username_is_not_kept_on_create_or_test(blank):
    assert PBXCreate(name="p", ip_address="10.0.0.20", api_username=blank).api_username is None
    assert PBXTestConnection(ip_address="10.0.0.20", api_username=blank).api_username is None
    assert PBXCreate(name="p", ip_address="10.0.0.20", api_username=" ops ").api_username == "ops"


@pytest.mark.parametrize("stored", [None, "", "  "])
def test_the_saved_pbx_uses_the_same_default_login_as_the_test(stored):
    settings = {} if stored is None else {"api_username": stored}
    pbx = SimpleNamespace(
        id=uuid4(),
        ip_address="10.0.0.20",
        api_port=443,
        settings=settings,
        web_password_enc=encrypt_credential("web-secret"),
        ami_secret_enc=None,
        ari_password_enc=None,
        api_client_id=None,
        api_client_secret_enc=None,
        tls_verify_disabled_acknowledged=False,
    )
    adapter = build_freepbx_adapter_from_pbx(pbx)
    assert adapter.username == DEFAULT_FREEPBX_USERNAME
    assert adapter.ami.username == DEFAULT_FREEPBX_USERNAME


async def test_the_test_probe_uses_the_oauth2_client_credentials(clients):
    adapter = FreePBXAdapter(
        host="10.0.0.20",
        username="",
        password="",
        api_client_id="m2m-app",
        api_client_secret="m2m-secret",
    )
    result = await adapter.test_connection()

    assert result.success, result.error
    probe = clients.built[-1]
    assert probe["api_client_id"] == "m2m-app"
    assert probe["api_client_secret"] == "m2m-secret"


async def test_an_oauth2_pbx_with_no_username_passes_the_connection_test(clients):
    result = await _service().test_pbx_connection(
        pbx_type="freepbx",
        ip_address="10.0.0.20",
        api_username=None,
        api_password=None,
        api_client_id="m2m-app",
        api_client_secret="m2m-secret",
    )
    assert result["status"] == "success", result


async def test_a_failed_test_with_no_username_says_which_login_it_tried(clients):
    result = await _service().test_pbx_connection(
        pbx_type="freepbx",
        ip_address="10.0.0.20",
        api_username="  ",
        api_password="wrong",
    )
    assert result["status"] != "success"
    assert f"'{DEFAULT_FREEPBX_USERNAME}'" in result["message"]
    assert "No username was entered" in result["message"]
    assert all(call["username"] == DEFAULT_FREEPBX_USERNAME for call in clients.built)


async def test_a_failed_test_with_a_username_does_not_mention_the_default(clients):
    result = await _service().test_pbx_connection(
        pbx_type="freepbx",
        ip_address="10.0.0.20",
        api_username="ops",
        api_password="wrong",
    )
    assert result["status"] != "success"
    assert "No username was entered" not in result["message"]

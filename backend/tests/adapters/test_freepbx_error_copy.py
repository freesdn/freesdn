# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreePBX connection errors the operator reads carry no em dash.

These messages reach the PBX page and the connection test verbatim. The
project's copy rule is no em dashes in user-facing text; these five were the
FreePBX adapter's remaining ones. All offline: the three interfaces and the
web session are fakes.
"""

from __future__ import annotations

import pytest

from app.adapters.freepbx import adapter as adapter_mod
from app.adapters.freepbx.adapter import FreePBXAdapter
from app.adapters.freepbx.exceptions import (
    FreePBXApiError,
    FreePBXAuthError,
    FreePBXConnectionError,
)
from app.adapters.freepbx.rest_client import FreePBXRestClient

EM_DASH = "—"


def _adapter() -> FreePBXAdapter:
    return FreePBXAdapter(host="pbx.example.test", username="admin", password="x")


async def _refused(*_a, **_k):
    raise FreePBXConnectionError("connection refused")


async def test_connect_with_every_interface_down_says_so_without_an_em_dash(monkeypatch):
    pbx = _adapter()
    for client in (pbx._ami, pbx._ari, pbx._rest):
        monkeypatch.setattr(client, "connect", _refused)

    with pytest.raises(FreePBXConnectionError) as caught:
        await pbx.connect()

    message = str(caught.value)
    assert message.startswith("All interfaces failed")
    assert EM_DASH not in message


class _DownClient:
    """Stands in for AMIClient / ARIClient / FreePBXRestClient: nothing answers."""

    def __init__(self, *_a, **_k):
        pass

    async def connect(self):
        raise FreePBXConnectionError("connection refused")

    async def disconnect(self):
        return None


async def test_connection_test_with_every_interface_down_has_no_em_dash(monkeypatch):
    pbx = _adapter()  # its own clients are real; the test builds fresh ones
    for name in ("AMIClient", "ARIClient", "FreePBXRestClient"):
        monkeypatch.setattr(adapter_mod, name, _DownClient)

    result = await pbx.test_connection()

    assert not result.success
    assert result.error.startswith("All interfaces failed")
    assert EM_DASH not in result.error


class _Resp:
    def __init__(self, status: int, text: str):
        self.status = status
        self._text = text

    async def text(self) -> str:
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False


class _Session:
    def __init__(self, get: _Resp, post: _Resp | None = None):
        self._get, self._post = get, post

    def get(self, *_a, **_k):
        return self._get

    def post(self, *_a, **_k):
        return self._post


LOGIN_FORM = '<form><input name="username"><input name="password"></form>'


@pytest.mark.parametrize(
    "body", ["<p>Invalid username or password</p>", LOGIN_FORM], ids=["rejected", "login-form"]
)
async def test_a_failed_web_login_has_no_em_dash(body):
    rest = FreePBXRestClient(host="pbx.example.test", username="admin", password="x")
    rest._session = _Session(get=_Resp(200, LOGIN_FORM), post=_Resp(200, body))

    with pytest.raises(FreePBXAuthError) as caught:
        await rest._web_login()

    assert str(caught.value).startswith("FreePBX web login failed")
    assert EM_DASH not in str(caught.value)


async def test_a_rest_endpoint_that_is_not_enabled_has_no_em_dash():
    rest = FreePBXRestClient(
        host="pbx.example.test",
        username="admin",
        password="x",
        api_client_id="cid",
        api_client_secret="csec",
    )
    rest._session = _Session(get=_Resp(404, "not found"))

    async def _token():
        return "tok"

    rest._ensure_oauth2_token = _token  # type: ignore[method-assign]

    with pytest.raises(FreePBXApiError) as caught:
        await rest._rest_get("core/users")

    assert "returned 404" in str(caught.value)
    assert EM_DASH not in str(caught.value)

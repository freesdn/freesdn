# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
The phone connection test must not read or return the phone's passwords.

``POST /voip/phones/{id}/test-connection`` (and the ad-hoc variant) logs into
the phone, reads its configuration with ``config_get`` and returns every
non-empty value under ``raw_data["_config"]``. The P-value list it asked for
included P34, the SIP account's authentication password, so the response body
carried that password in clear text. SIP secrets are write-only everywhere else
(``sip_password_enc`` is stripped from every phone response, and the
push-sip-config plan is redacted), so this one path undid that.

The fix stops asking for P34 and drops any credential P-value the firmware
returns anyway, matched by number or by a ``password`` alias.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.modules.voip import discovery

PHONE_IP = "192.168.50.20"
SIP_SECRET = "sip-secret-value-7f3a"
ADMIN_SECRET = "admin-secret-value-91c2"


class _Resp:
    def __init__(self, status: int, body: Any) -> None:
        self.status = status
        self._text = body if isinstance(body, str) else json.dumps(body)

    async def text(self) -> str:
        return self._text

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None


class _FakePhone:
    """Answers the Grandstream web API sequence the connection test walks."""

    def __init__(self) -> None:
        self.requested_pvalues: list[str] = []

    def get(self, url: str, params: dict[str, str] | None = None, **_: Any) -> _Resp:
        path = url.split(PHONE_IP, 1)[1]
        if path == "/":
            return _Resp(200, "<html>webapp.nocache.js</html>")
        if path == "/cgi-bin/api.values.get":
            return _Resp(200, {"body": {"P67": "000b82aabbcc", "P68": "1.0.11.7"}})
        if path == "/cgi-bin/metaconfig_get":
            return _Resp(200, [])
        if path == "/cgi-bin/api-get_lockout":
            return _Resp(200, {"body": "ok"})
        if path == "/cgi-bin/config_get":
            self.requested_pvalues = (params or {}).get("pvalues", "").split(",")
            # Real firmware answers with what it has; it is not a filter we own.
            return _Resp(
                200,
                {
                    "configs": [
                        {
                            "pvalue": "47",
                            "value": "pbx.example.lan",
                            "alias": "account.1.sip.server.1.address",
                        },
                        {"pvalue": "35", "value": "1001", "alias": "account.1.sip.userid"},
                        {
                            "pvalue": "34",
                            "value": SIP_SECRET,
                            "alias": "account.1.sip.subscriber.password",
                        },
                        {"pvalue": "2", "value": ADMIN_SECRET, "alias": "users.admin.password"},
                        {"pvalue": "9999", "value": SIP_SECRET, "alias": "account.9.sip.password"},
                    ]
                },
            )
        return _Resp(404, "")

    def post(self, url: str, **_: Any) -> _Resp:
        path = url.split(PHONE_IP, 1)[1]
        if path == "/cgi-bin/access":
            return _Resp(200, {"response": "success", "body": "challenge-token"})
        if path == "/cgi-bin/dologin":
            return _Resp(200, {"response": "success", "body": {"sid": "sid-123"}})
        return _Resp(404, "")


class _SessionCM:
    def __init__(self, phone: _FakePhone) -> None:
        self._phone = phone

    async def __aenter__(self) -> _FakePhone:
        return self._phone

    async def __aexit__(self, *exc: object) -> None:
        return None


@pytest.fixture
def fake_phone(monkeypatch: pytest.MonkeyPatch) -> _FakePhone:
    phone = _FakePhone()
    monkeypatch.setattr(discovery, "build_aiohttp_session", lambda **_: _SessionCM(phone))
    return phone


async def test_connection_test_does_not_ask_the_phone_for_passwords(fake_phone: _FakePhone) -> None:
    result = await discovery.test_phone_connection(ip=PHONE_IP, username="admin", password="pw")

    assert result["authenticated"] is True
    assert fake_phone.requested_pvalues, "config_get was never requested"
    asked = {p.strip().upper().removeprefix("P") for p in fake_phone.requested_pvalues}
    assert not asked & discovery._CREDENTIAL_PVALUES


async def test_connection_test_response_carries_no_password(fake_phone: _FakePhone) -> None:
    result = await discovery.test_phone_connection(ip=PHONE_IP, username="admin", password="pw")

    dumped = json.dumps(result, default=str)
    assert SIP_SECRET not in dumped
    assert ADMIN_SECRET not in dumped
    # The non-secret values the test exists to show are still there.
    config = result["raw_data"]["_config"]
    assert config["47"]["value"] == "pbx.example.lan"
    assert config["35"]["value"] == "1001"


@pytest.mark.parametrize(
    ("pvalue", "alias", "expected"),
    [
        ("34", "", True),
        ("P34", "", True),
        ("p1634", "", True),
        ("406", "", True),
        ("1359", "", True),
        ("47", "account.1.sip.server.1.address", False),
        ("12345", "account.7.sip.subscriber.Password", True),
        ("35", "account.1.sip.userid", False),
    ],
)
def test_credential_pvalue_matching(pvalue: str, alias: str, expected: bool) -> None:
    assert discovery._is_credential_pvalue(pvalue, alias) is expected

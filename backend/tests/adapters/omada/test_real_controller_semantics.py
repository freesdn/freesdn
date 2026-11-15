# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""How the Omada client reads a real controller's answers.

The fake controller below reproduces what an OC300 running 6.3.0.111 answered
during a read-only soak (identifiers, MACs and names replaced with obviously
fake values):

* an unknown or ended session gets HTTP 302 to ``/{omadacId}/login``; a request
  with a wrong Csrf-Token gets the same redirect AND the controller ends that
  session;
* ``loginStatus`` answers ``{"login": bool}`` and never needs a session;
* ``setting/lan/networks`` and ``setting/lan/profiles`` answer -1001 "Invalid
  request parameters." without currentPage/currentPageSize;
* ``setting/lan``, ``setting/lan/profileOverrides`` and ``maintenance/sysInfo``
  answer -1600 "Unsupported request path.";
* the bare ``/maintenance/controllerStatus`` is HTTP 404, the prefixed one works;
* ``clients`` without ``filters.active`` answers -1 "General error.".
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.adapters.omada import client as client_mod
from app.adapters.omada.adapter import OmadaAdapter
from app.adapters.omada.client import OmadaApiClient, OmadaClientConfig
from app.adapters.omada.exceptions import (
    OmadaApiError,
    OmadaInvalidRequestError,
    OmadaSessionExpiredError,
    OmadaUnsupportedEndpointError,
)

CID = "0123456789abcdef0123456789abcdef"
SITE = "site-fake-0001"
API = f"/{CID}/api/v2"

NETWORK_ROWS = [
    {"id": "net-fake-1", "name": "LAN", "vlan": 1, "purpose": "interface", "vlanType": 0},
    {"id": "net-fake-2", "name": "Guest", "vlan": 20, "purpose": "interface", "vlanType": 0},
]
WIRELESS_ROW = {
    "mac": "02-00-00-00-00-01",
    "name": "phone-fake",
    "wireless": True,
    "active": True,
    "ssid": "FakeSSID",
    "rssi": -51,
    "signalLevel": 80,
    "channel": 36,
    "radioId": 1,
    "apMac": "02-00-00-00-01-00",
    "apName": "ap-fake",
}
WIRED_ROW = {
    "mac": "02-00-00-00-00-02",
    "name": "desk-fake",
    "wireless": False,
    "active": True,
    "port": 3,
    "switchMac": "02-00-00-00-02-00",
}
PROFILE_ROWS = [
    {"id": "prof-fake-1", "name": "All", "type": 0, "poe": 2, "lldpMedEnable": True},
    {"id": "prof-fake-2", "name": "Disable", "type": 0, "poe": 2, "lldpMedEnable": True},
]
CONTROLLER_STATUS = {
    "name": "oc-fake",
    "model": "OC300",
    "controllerVersion": "6.3.0.111",
    "firmwareVersion": "1.0.0",
    "upTime": 123456,
    "systemTime": 1700000000000,
}


def _ok(result: Any) -> httpx.Response:
    return httpx.Response(200, json={"errorCode": 0, "msg": "Success.", "result": result})


def _err(code: int, msg: str) -> httpx.Response:
    return httpx.Response(200, json={"errorCode": code, "msg": msg})


def _page(rows: list[dict[str, Any]], params: httpx.QueryParams) -> dict[str, Any]:
    page = int(params["currentPage"])
    size = int(params["currentPageSize"])
    chunk = rows[(page - 1) * size : page * size]
    return {"totalRows": len(rows), "currentPage": page, "currentSize": size, "data": chunk}


class FakeOmadaController:
    """Session-tracking stand-in for a 6.3 OC300 (read paths only)."""

    def __init__(self) -> None:
        self.sessions: dict[str, str] = {}  # session cookie -> csrf token
        self.logins = 0
        self.requests: list[httpx.Request] = []
        self.dead_session_errorcode: int | None = None  # simulate odd firmware
        self.wants_unpaged_networks = False  # simulate a firmware without paging

    def end_all_sessions(self) -> None:
        self.sessions.clear()

    def paths(self, suffix: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path.endswith(suffix)]

    async def handler(self, request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0)  # let concurrent requests interleave
        self.requests.append(request)
        path = request.url.path
        params = request.url.params
        if path == "/api/info":
            return _ok({"omadacId": CID, "controllerVer": "6.3.0.111", "apiVer": "3"})
        if path == f"{API}/login" and request.method == "POST":
            self.logins += 1
            sid, token = f"sid-{self.logins}", f"tok-{self.logins}"
            self.sessions[sid] = token
            return httpx.Response(
                200,
                json={"errorCode": 0, "msg": "Success.", "result": {"token": token}},
                headers={"set-cookie": f"TPOMADA_SESSIONID={sid}; Path=/"},
            )
        if path == f"/{CID}/login":
            return httpx.Response(
                200, text="<!DOCTYPE html><html>login</html>", headers={"content-type": "text/html"}
            )
        if path == f"{API}/loginStatus":
            sid = request.headers.get("cookie", "").partition("TPOMADA_SESSIONID=")[2]
            sid = sid.split(";")[0]
            return _ok({"login": sid in self.sessions})
        if path.startswith("/maintenance/"):
            return httpx.Response(404, json={"status": 404, "error": "Not Found"})
        if request.method != "GET":
            return httpx.Response(405)

        sid = request.headers.get("cookie", "").partition("TPOMADA_SESSIONID=")[2]
        sid = sid.split(";")[0]
        if sid not in self.sessions or self.sessions[sid] != request.headers.get("Csrf-Token"):
            self.sessions.pop(sid, None)  # a wrong token ends the session
            if self.dead_session_errorcode is not None:
                return _err(self.dead_session_errorcode, "General error.")
            return httpx.Response(302, headers={"location": f"/{CID}/login"})
        return self.route(path.removeprefix(API), params)

    def route(self, path: str, params: httpx.QueryParams) -> httpx.Response:
        paged = "currentPage" in params and "currentPageSize" in params
        if path == f"/sites/{SITE}/setting/lan/networks":
            if self.wants_unpaged_networks:
                if paged:
                    return _err(-1001, "Invalid request parameters.")
                return _ok({"data": NETWORK_ROWS})
            if not paged:
                return _err(-1001, "Invalid request parameters.")
            return _ok({**_page(NETWORK_ROWS, params), "supportMaxVlanNum": 4094})
        if path == f"/sites/{SITE}/setting/lan/profiles":
            if not paged:
                return _err(-1001, "Invalid request parameters.")
            return _ok(_page(PROFILE_ROWS, params))
        if path == f"/sites/{SITE}/setting/lan/profileSummary":
            return _ok(
                {"data": [{"id": r["id"], "name": r["name"], "type": 0} for r in PROFILE_ROWS]}
            )
        if path in (
            f"/sites/{SITE}/setting/lan",
            f"/sites/{SITE}/setting/lan/profileOverrides",
            "/maintenance/sysInfo",
        ):
            return _err(-1600, "Unsupported request path.")
        if path == "/maintenance/controllerStatus":
            return _ok(CONTROLLER_STATUS)
        if path == f"/sites/{SITE}/clients":
            if params.get("filters.active") != "true":
                return _err(-1, "General error.")
            rows = [WIRELESS_ROW, WIRED_ROW]
            if paged:
                return _ok({**_page(rows, params), "clientStat": {}})
            return _ok({"data": rows})
        if path.startswith(f"/sites/{SITE}/clients/"):
            return _ok({"mac": path.rsplit("/", 1)[1], "ipSetting": {}})
        if path == f"/sites/{SITE}/devices":
            return _ok([{"mac": "02-00-00-00-02-00", "type": "switch", "name": "sw-fake"}])
        if path == f"/sites/{SITE}/insight/clients":
            return _ok({"totalRows": 0, "currentPage": 1, "currentSize": 0, "data": []})
        return _err(-1600, "Unsupported request path.")


@pytest.fixture(autouse=True)
def _forget_unsupported_endpoints():
    client_mod._UNSUPPORTED_ENDPOINTS.clear()
    yield
    client_mod._UNSUPPORTED_ENDPOINTS.clear()


@pytest.fixture()
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeOmadaController:
    ctrl = FakeOmadaController()

    def _build(*, base_url: str, verify: bool, timeout: Any, follow_redirects: bool, **_: Any):
        return httpx.AsyncClient(
            base_url=base_url,
            transport=httpx.MockTransport(ctrl.handler),
            follow_redirects=follow_redirects,
        )

    monkeypatch.setattr(client_mod, "build_async_client", _build)
    return ctrl


async def _client() -> OmadaApiClient:
    client = OmadaApiClient(
        OmadaClientConfig(
            host="omada.invalid",
            username="replay",
            password="replay",
            max_retries=3,
            retry_backoff=0.0,
            rate_limit_rpm=6000,
        )
    )
    await client.login()
    return client


# ---------------------------------------------------------------------------
# Error classification: request problems never cost a login
# ---------------------------------------------------------------------------


async def test_invalid_request_parameters_is_not_a_session_error(fake):
    client = await _client()

    with pytest.raises(OmadaInvalidRequestError):
        await client._request("GET", f"/sites/{SITE}/setting/lan/networks")

    assert fake.logins == 1  # only the initial login
    assert len(fake.paths("/setting/lan/networks")) == 1  # not replayed
    assert fake.paths("/loginStatus") == []


async def test_unsupported_path_is_not_a_session_error(fake):
    client = await _client()

    with pytest.raises(OmadaUnsupportedEndpointError):
        await client._request("GET", f"/sites/{SITE}/setting/lan")

    assert fake.logins == 1


async def test_networks_are_read_in_one_paged_request(fake):
    client = await _client()

    rows = await client.get_networks(SITE)

    assert [r["vlan"] for r in rows] == [1, 20]
    reqs = fake.paths("/setting/lan/networks")
    assert len(reqs) == 1
    assert reqs[0].url.params["currentPage"] == "1"
    assert fake.paths("/setting/lan") == []
    assert fake.logins == 1


async def test_networks_fall_back_to_the_unpaged_form(fake):
    fake.wants_unpaged_networks = True
    client = await _client()

    rows = await client.get_networks(SITE)

    assert [r["id"] for r in rows] == ["net-fake-1", "net-fake-2"]
    assert fake.logins == 1


async def test_generic_error_with_live_session_retries_without_logging_in(fake):
    client = await _client()

    with pytest.raises(OmadaApiError, match="General error"):
        await client._request("GET", f"/sites/{SITE}/clients")

    assert fake.logins == 1
    assert len(fake.paths("/loginStatus")) == 1  # asked once, not per attempt
    assert len(fake.paths(f"/sites/{SITE}/clients")) == 3  # plain retries remain


async def test_generic_error_from_a_dead_session_still_recovers(fake):
    """What the old -1 re-login branch was for, kept: if a firmware answers a
    dead session with -1, loginStatus says so and the client logs in again."""
    client = await _client()
    fake.dead_session_errorcode = -1
    fake.end_all_sessions()

    rows = await client.get_networks(SITE)

    assert len(rows) == 2
    assert fake.logins == 2


async def test_http_401_with_live_session_does_not_log_in(fake, monkeypatch):
    client = await _client()

    original = fake.route

    def route(path, params):
        if path.endswith("/lan-profiles"):
            return httpx.Response(
                401,
                json={"errorCode": -44116, "msg": "Open API Authorized failed."},
            )
        return original(path, params)

    monkeypatch.setattr(fake, "route", route)

    with pytest.raises(OmadaApiError, match="401"):
        await client._request("GET", f"/sites/{SITE}/lan-profiles")

    assert fake.logins == 1


# ---------------------------------------------------------------------------
# A real expired session
# ---------------------------------------------------------------------------


async def test_login_redirect_relogs_in_once_and_replays(fake):
    client = await _client()
    fake.end_all_sessions()

    rows = await client.get_devices(SITE)

    assert rows and rows[0]["type"] == "switch"
    assert fake.logins == 2
    assert client._session_generation == 2  # initial login, then one re-login


async def test_concurrent_reads_on_a_dead_session_share_one_login(fake):
    client = await _client()
    first_http = client._http
    fake.end_all_sessions()

    results = await asyncio.gather(
        client.get_networks(SITE),
        client.get_devices(SITE),
        client.get_port_profiles(SITE),
        client.get_controller_status(),
        client.get_clients(SITE),
    )

    assert all(results)
    assert fake.logins == 2  # one re-login for five reads
    # The replaced client stays open for reads still in flight on it and is
    # closed at logout, not at the swap.
    assert client._http is not first_http
    assert not first_http.is_closed
    await client._close_retired_http()
    assert first_http.is_closed


async def test_redirect_after_relogin_is_reported_not_looped(fake, monkeypatch):
    client = await _client()

    async def handler(request: httpx.Request) -> httpx.Response:
        fake.requests.append(request)
        if request.url.path == f"{API}/login":
            fake.logins += 1
            return httpx.Response(200, json={"errorCode": 0, "result": {"token": "t"}})
        if request.url.path == "/api/info":
            return _ok({"omadacId": CID, "controllerVer": "6.3.0.111"})
        if request.url.path == f"/{CID}/login":
            return httpx.Response(200, text="<html>login</html>")
        return httpx.Response(302, headers={"location": f"/{CID}/login"})

    monkeypatch.setattr(fake, "handler", handler)
    client._http = httpx.AsyncClient(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
    )
    before = fake.logins

    with pytest.raises(OmadaSessionExpiredError):
        await client._request("GET", f"/sites/{SITE}/devices")

    assert fake.logins - before == 1


# ---------------------------------------------------------------------------
# The forms each read uses
# ---------------------------------------------------------------------------


async def test_clients_ask_for_active_clients_and_skip_needless_detail_reads(fake):
    client = await _client()

    rows = await client.get_clients_enriched(SITE)

    assert {r["mac"] for r in rows} == {WIRELESS_ROW["mac"], WIRED_ROW["mac"]}
    reqs = fake.paths(f"/sites/{SITE}/clients")
    assert len(reqs) == 1
    assert reqs[0].url.params["filters.active"] == "true"
    # The active list already carries ssid/rssi/channel: no per-client reads.
    assert [r for r in fake.requests if "/clients/" in r.url.path] == []
    assert fake.paths("/insight/clients") == []
    assert fake.logins == 1


async def test_paged_reads_keep_their_filters_on_every_page(fake):
    client = await _client()

    rows = await client._paginated_request(
        "GET", f"/sites/{SITE}/clients", page_size=1, params={"filters.active": "true"}
    )

    assert len(rows) == 2
    reqs = fake.paths(f"/sites/{SITE}/clients")
    assert [r.url.params["currentPage"] for r in reqs] == ["1", "2"]
    assert all(r.url.params["filters.active"] == "true" for r in reqs)


async def test_port_profiles_come_from_the_paged_profiles_list(fake):
    client = await _client()

    rows = await client.get_port_profiles(SITE)

    assert [r["id"] for r in rows] == ["prof-fake-1", "prof-fake-2"]
    assert fake.paths("/profileOverrides") == []
    normalized = OmadaAdapter._normalize_port_profile(rows[0])
    assert normalized.type == "0"
    assert normalized.poe_enabled is None  # a PoE mode number is not a yes/no
    assert normalized.lldp_enabled is True


async def test_controller_status_uses_the_controller_api_prefix(fake):
    client = await _client()

    status = await client.get_controller_status()

    assert status["model"] == "OC300"
    req = fake.paths("/maintenance/controllerStatus")[-1]
    assert req.url.path == f"{API}/maintenance/controllerStatus"
    assert req.headers["Csrf-Token"] == "tok-1"


async def test_unsupported_system_info_is_asked_once_and_logged_once(fake, caplog):
    caplog.set_level(logging.INFO, logger="adapter.omada.http")
    client = await _client()

    info = await client.get_system_info()
    again = await client.get_system_info()
    # The next sync builds a new client for the same controller and firmware.
    next_cycle = await _client()
    third = await next_cycle.get_system_info()

    for result in (info, again, third):
        assert result["controllerVer"] == "6.3.0.111"
        assert result["uptime"] == 123456
        assert result["model"] == "OC300"
    assert len(fake.paths("/maintenance/sysInfo")) == 1
    notes = [r for r in caplog.records if "not asking again" in r.getMessage()]
    assert len(notes) == 1
    assert notes[0].levelno == logging.INFO


async def test_adapter_reads_of_unserved_endpoints_do_not_log_errors(caplog):
    adapter = OmadaAdapter(host="omada.invalid", username="u", password="p", site_id=SITE)
    adapter._client.get_port_profiles = AsyncMock(
        side_effect=OmadaUnsupportedEndpointError("Unsupported request path.")
    )
    adapter._client.get_controller_status = AsyncMock(
        side_effect=OmadaUnsupportedEndpointError("HTTP error 404")
    )
    adapter._client.get_system_info = AsyncMock(
        side_effect=OmadaUnsupportedEndpointError("Unsupported request path.")
    )
    caplog.set_level(logging.DEBUG)

    assert await adapter.get_port_profiles() == []
    assert await adapter.get_controller_status() == {}
    assert await adapter.get_system_info() == {}
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []


# ---------------------------------------------------------------------------
# Cloud mode keeps token refresh for token errors only
# ---------------------------------------------------------------------------


def _cloud_client() -> tuple[OmadaApiClient, MagicMock]:
    client = OmadaApiClient(
        OmadaClientConfig(
            mode="cloud",
            client_id="cid",
            client_secret="secret",
            omada_id="omada-fake",
            cloud_region="us",
            retry_backoff=0.0,
        )
    )
    http = MagicMock()
    http.is_closed = False
    http.request = AsyncMock()
    client._http = http
    client._logged_in = True
    client._access_token = "token"
    client._token_expires_at = float("inf")
    client._rate_limiter.acquire = AsyncMock(return_value=True)
    client._refresh_cloud_token = AsyncMock()
    return client, http


def _json(code: int, msg: str = "", result: Any = None) -> httpx.Response:
    body: dict[str, Any] = {"errorCode": code, "msg": msg}
    if result is not None:
        body["result"] = result
    return httpx.Response(200, json=body, request=httpx.Request("GET", "https://x"))


async def test_cloud_expired_access_token_refreshes_and_replays():
    client, http = _cloud_client()
    http.request.side_effect = [
        _json(-44112, "The access token has expired."),
        _json(0, result={"ok": True}),
    ]

    assert await client._request("GET", "/sites") == {"ok": True}
    assert client._refresh_cloud_token.await_count == 1


async def test_cloud_invalid_request_does_not_refresh_the_token():
    client, http = _cloud_client()
    http.request.side_effect = [_json(-1001, "Invalid request parameters.")]

    with pytest.raises(OmadaInvalidRequestError):
        await client._request("GET", "/sites")
    assert client._refresh_cloud_token.await_count == 0

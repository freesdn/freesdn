"""LuCI CGI configuration export transport; synthetic peer, no hardware claim."""

import asyncio
import base64
import gzip
import io
import json
import tarfile
import time
from urllib.parse import parse_qs

import httpx
import pytest
import pytest_asyncio

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterTimeoutError,
)
from app.adapters.openwrt.adapter import OpenWRTAdapter
from app.core.config import settings

SECRET = "owned-openwrt-export-sensitive"
SID = "1234567890abcdef" * 2
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as tar:
    info = tarfile.TarInfo("etc/config/system")
    content = SECRET.encode()
    info.size = len(content)
    tar.addfile(info, io.BytesIO(content))
ARCHIVE = gzip.compress(buf.getvalue(), mtime=0)


class Stream(httpx.AsyncByteStream):
    def __init__(self, state):
        self.state = state

    async def __aiter__(self):
        self.state["body_reads"] += 1
        if self.state["error"]:
            raise self.state["error"]
        if self.state["slow"]:
            await asyncio.sleep(1)
        data = self.state["body"]
        for i in range(0, len(data), 8192):
            self.state["chunks"] += 1
            yield data[i : i + 8192]

    async def aclose(self):
        self.state["closed"] += 1


@pytest_asyncio.fixture
async def wire():
    adapter = OpenWRTAdapter(
        host="192.0.2.55", username="owned", password="owned", verify_ssl=True
    )
    client = adapter._api
    client._session_id = SID
    client._session_time = time.monotonic()
    state = {
        "body": ARCHIVE,
        "headers": {"content-type": "application/x-targz"},
        "status": 200,
        "error": None,
        "slow": False,
        "closed": 0,
        "body_reads": 0,
        "chunks": 0,
        "requests": [],
    }

    async def peer(request):
        state["requests"].append(request)
        if request.url.path == "/ubus":
            payload = json.loads(request.content)
            method = payload["params"][2]
            if method == "login":
                return httpx.Response(
                    200, json={"result": [0, {"ubus_rpc_session": SID}]}
                )
            if method == "board":
                return httpx.Response(
                    200, json={"result": [0, {"model": "Owned router"}]}
                )
            assert method == "backup"
            # Reproduce the old custom-RPC behavior without asserting it is stock.
            return httpx.Response(
                200, json={"result": [0, {"data": base64.b64encode(ARCHIVE).decode()}]}
            )
        assert request.url.path == "/cgi-bin/cgi-backup"
        assert request.method == "POST" and not request.url.query
        assert parse_qs(request.content.decode()) == {"sessionid": [SID]}
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(
            state["status"], headers=state["headers"], stream=Stream(state)
        )

    client._client = httpx.AsyncClient(
        base_url=client.base_url,
        transport=httpx.MockTransport(peer),
        follow_redirects=True,
    )
    try:
        yield adapter, client, state
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("declared_length", [False, True])
async def test_stock_CGI_export_preserves_bytes_and_uses_session_form(
    wire, monkeypatch, read_only, declared_length
):
    adapter, client, state = wire
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    if declared_length:
        state["headers"]["content-length"] = str(len(ARCHIVE))
    result = await adapter.download_config()
    assert result.success and result.data == {
        "backup_data": ARCHIVE,
        "format": "tar.gz",
        "scope": "sysupgrade",
    }
    assert [r.url.path for r in state["requests"]] == ["/cgi-bin/cgi-backup"]
    assert state["closed"] == 1


@pytest.mark.parametrize("entry", ["client", "adapter"])
@pytest.mark.parametrize(
    "case",
    [
        "status204",
        "status206",
        "status301",
        "status302",
        "status307",
        "status308",
        "status404",
        "status500",
        "HTML",
        "JSON",
        "empty",
        "truncated",
        "CRC",
        "encoded",
        "unknown-type",
        "missing-type",
        "length-negative",
        "length-unicode",
        "length-large",
        "length-mismatch",
        "stream-large",
        "inflated-large",
        "connection",
    ],
)
async def test_invalid_or_unavailable_export_fails_without_provider_material(
    wire, entry, case, caplog
):
    adapter, client, state = wire
    if case.startswith("status"):
        state["status"] = int(case.removeprefix("status"))
        state["headers"]["location"] = "https://other.example.test/" + SECRET
    elif case == "HTML":
        state["body"] = ("<html>" + SECRET + "</html>").encode()
    elif case == "JSON":
        state["body"] = json.dumps({"secret": SECRET}).encode()
    elif case == "empty":
        state["body"] = b""
    elif case == "truncated":
        state["body"] = ARCHIVE[:-8]
    elif case == "CRC":
        state["body"] = ARCHIVE[:-8] + b"BAD!" + ARCHIVE[-4:]
    elif case == "encoded":
        state["headers"]["content-encoding"] = "gzip"
    elif case == "unknown-type":
        state["headers"]["content-type"] = "text/html"
    elif case == "missing-type":
        state["headers"].pop("content-type")
    elif case == "length-negative":
        state["headers"]["content-length"] = "-1"
    elif case == "length-unicode":
        state["headers"]["content-length"] = "not-an-integer"
    elif case == "length-large":
        state["headers"]["content-length"] = str(16 * 1024 * 1024 + 1)
    elif case == "length-mismatch":
        state["headers"]["content-length"] = str(len(ARCHIVE) + 1)
    elif case == "stream-large":
        state["body"] = b"x" * (16 * 1024 * 1024 + 1)
    elif case == "inflated-large":
        state["body"] = gzip.compress(b"x" * (64 * 1024 * 1024 + 1), mtime=0)
    elif case == "connection":
        state["error"] = httpx.ReadError(SECRET)
    if entry == "client":
        with pytest.raises(
            AdapterConnectionError, match="^OpenWRT configuration download failed$"
        ):
            await client.create_backup()
    else:
        result = await adapter.download_config()
        assert not result.success and result.data is None
        assert (
            result.error == "Configuration download failed"
            and result.error_code == "DOWNLOAD_FAILED"
        )
    assert (
        len(state["requests"]) == 1
        and state["requests"][0].url.path == "/cgi-bin/cgi-backup"
    )
    assert state["closed"] == 1 and SECRET not in caplog.text
    if case in [
        "length-large",
        "length-negative",
        "length-unicode",
        "encoded",
        "missing-type",
        "unknown-type",
    ] or case.startswith("status"):
        assert state["body_reads"] == 0
    if case == "stream-large":
        assert state["chunks"] == 2049


@pytest.mark.parametrize("entry", ["client", "adapter"])
@pytest.mark.parametrize("status", [401, 403])
async def test_rejected_export_authentication_is_safe_and_does_not_retry(
    wire, entry, status
):
    adapter, client, state = wire
    state["status"] = status
    state["body"] = SECRET.encode()
    if entry == "client":
        with pytest.raises(
            AdapterAuthenticationError,
            match="^OpenWRT configuration export authentication failed$",
        ):
            await client.create_backup()
    else:
        result = await adapter.download_config()
        assert not result.success and result.error == "Configuration download failed"
    assert len(state["requests"]) == state["closed"] == 1 and state["body_reads"] == 0


@pytest.mark.parametrize("entry", ["client", "adapter"])
async def test_expired_session_refreshes_before_CGI_export(wire, entry):
    adapter, client, state = wire
    client._session_time = time.monotonic() - client.SESSION_TTL - 1
    result = await (
        client.create_backup() if entry == "client" else adapter.download_config()
    )
    assert result == ARCHIVE if entry == "client" else result.success
    assert [r.url.path for r in state["requests"]] == ["/ubus", "/cgi-bin/cgi-backup"]
    assert json.loads(state["requests"][0].content)["params"][2] == "login"


@pytest.mark.parametrize("session", [None, "", "0" * 32, SECRET])
async def test_invalid_session_is_not_sent_to_export(wire, session):
    _, client, state = wire
    client._session_id = session
    with pytest.raises(AdapterAuthenticationError):
        await client.create_backup()
    assert not state["requests"]


@pytest.mark.parametrize("entry", ["client", "adapter"])
async def test_cancellation_closes_response_and_propagates(wire, entry):
    adapter, client, state = wire
    state["error"] = asyncio.CancelledError(SECRET)
    with pytest.raises(asyncio.CancelledError):
        await (
            client.create_backup() if entry == "client" else adapter.download_config()
        )
    assert state["closed"] == 1


@pytest.mark.parametrize("entry", ["client", "adapter"])
async def test_total_deadline_bounds_slow_body(wire, entry):
    adapter, client, state = wire
    client.timeout = 0.02
    state["slow"] = True
    if entry == "client":
        with pytest.raises(
            AdapterTimeoutError, match="^OpenWRT configuration export timed out$"
        ):
            await client.create_backup()
    else:
        result = await adapter.download_config()
        assert not result.success and result.error == "Configuration download failed"
    assert state["closed"] == 1


@pytest.mark.parametrize("read_only", [False, True])
async def test_normal_ubus_read_remains_available(wire, monkeypatch, read_only):
    _, client, state = wire
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    assert await client.call("system", "board") == {"model": "Owned router"}
    assert len(state["requests"]) == 1 and state["requests"][0].url.path == "/ubus"


@pytest.mark.parametrize("read_only", [False, True])
async def test_saved_backup_creation_still_unsupported_without_export(
    wire, monkeypatch, read_only
):
    adapter, _, state = wire
    monkeypatch.setattr(settings, "ADAPTER_READ_ONLY", read_only)
    result = await adapter.create_backup()
    assert (
        not result.success
        and result.error_code == "NOT_SUPPORTED"
        and not state["requests"]
    )

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the TrueNAS WebSocket JSON-RPC client + adapter transport
selection (TrueNAS 25.04+ / 26.0).

The WS API is JSON-RPC 2.0 over a single socket. We drive it with a
``FakeWS`` whose ``recv()`` replays a pre-seeded sequence of raw
messages, so we can assert: auth-outcome mapping, request/response
id-matching (skipping event pushes), error translation, dataset
flatten+dedupe, snapshot method fallback, the mandatory-TLS port bump,
and the adapter's WS→REST fallback rules.
"""
from __future__ import annotations

import collections
import json
from typing import Any

import pytest

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
)
from app.adapters.truenas.client import TrueNASAPIError
from app.adapters.truenas.ws_client import TrueNASWSClient, _flatten_datasets


class FakeWS:
    """Minimal stand-in for a websockets client connection."""

    def __init__(self, outbox: list[str]) -> None:
        self.outbox = collections.deque(outbox)
        self.sent: list[str] = []
        self.closed = False

    async def send(self, msg: str) -> None:
        self.sent.append(msg)

    async def recv(self) -> str:
        if not self.outbox:
            raise AssertionError("recv() called with empty outbox")
        return self.outbox.popleft()

    async def close(self) -> None:
        self.closed = True


def _rpc(req_id: int, result: Any) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})


def _rpc_err(req_id: int, code: int, errname: str, message: str = "boom") -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message, "data": {"errname": errname}},
        }
    )


def _client_with(monkeypatch: pytest.MonkeyPatch, outbox: list[str], **kw: Any) -> tuple[TrueNASWSClient, FakeWS]:
    fake = FakeWS(outbox)

    async def fake_connect(*_a: Any, **_k: Any) -> FakeWS:
        return fake

    monkeypatch.setattr(
        "app.adapters.truenas.ws_client.websockets.connect", fake_connect
    )
    c = TrueNASWSClient(host="nas.lab", username="truenas_admin", api_key="4-k", **kw)
    return c, fake


# ---------------------------------------------------------------------------
# URI / TLS
# ---------------------------------------------------------------------------


class TestUri:
    def test_default_port_is_wss_443(self) -> None:
        c = TrueNASWSClient(host="nas.lab", api_key="k")
        assert c._uri == "wss://nas.lab:443/api/current"

    def test_plain_port_80_bumped_to_tls_443(self) -> None:
        # Operator copies ":80" from the browser; we must still use TLS.
        c = TrueNASWSClient(host="nas.lab", api_key="k", port=80)
        assert c._uri == "wss://nas.lab:443/api/current"

    def test_custom_https_port_preserved(self) -> None:
        c = TrueNASWSClient(host="nas.lab", api_key="k", port=8443)
        assert c._uri == "wss://nas.lab:8443/api/current"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class TestAuth:
    @pytest.mark.asyncio
    async def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, fake = _client_with(monkeypatch, [_rpc(1, {"response_type": "SUCCESS"})])
        await c.connect()
        # First (and only) sent message is the API_KEY_PLAIN login.
        sent = json.loads(fake.sent[0])
        assert sent["method"] == "auth.login_ex"
        assert sent["params"][0]["mechanism"] == "API_KEY_PLAIN"
        assert sent["params"][0]["username"] == "truenas_admin"
        await c.disconnect()
        assert fake.closed is True

    @pytest.mark.asyncio
    async def test_auth_err_raises_with_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, fake = _client_with(monkeypatch, [_rpc(1, {"response_type": "AUTH_ERR"})])
        with pytest.raises(AdapterAuthenticationError) as ei:
            await c.connect()
        assert "rejected" in str(ei.value).lower()
        # Socket cleaned up on failed auth.
        assert fake.closed is True

    @pytest.mark.asyncio
    async def test_expired_raises_mentions_reset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, _ = _client_with(monkeypatch, [_rpc(1, {"response_type": "EXPIRED"})])
        with pytest.raises(AdapterAuthenticationError) as ei:
            await c.connect()
        assert "expired" in str(ei.value).lower()

    @pytest.mark.asyncio
    async def test_password_mechanism_when_no_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeWS([_rpc(1, {"response_type": "SUCCESS"})])

        async def fake_connect(*_a: Any, **_k: Any) -> FakeWS:
            return fake

        monkeypatch.setattr(
            "app.adapters.truenas.ws_client.websockets.connect", fake_connect
        )
        c = TrueNASWSClient(host="nas.lab", username="truenas_admin", password="pw")
        await c.connect()
        sent = json.loads(fake.sent[0])
        assert sent["params"][0]["mechanism"] == "PASSWORD_PLAIN"
        assert sent["params"][0]["password"] == "pw"


# ---------------------------------------------------------------------------
# JSON-RPC call mechanics
# ---------------------------------------------------------------------------


class TestCall:
    @pytest.mark.asyncio
    async def test_skips_event_push_then_matches_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # auth(id=1) ok, then an event notification with NO id, then the
        # real pool.query response (id=2). The client must skip the push.
        event_push = json.dumps({"jsonrpc": "2.0", "method": "collection_update", "params": {}})
        c, _ = _client_with(
            monkeypatch,
            [
                _rpc(1, {"response_type": "SUCCESS"}),
                event_push,
                _rpc(2, [{"name": "tank", "status": "ONLINE"}]),
            ],
        )
        await c.connect()
        pools = await c.list_pools()
        assert pools[0]["name"] == "tank"

    @pytest.mark.asyncio
    async def test_not_authenticated_error_maps_to_auth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, _ = _client_with(
            monkeypatch,
            [
                _rpc(1, {"response_type": "SUCCESS"}),
                _rpc_err(2, -32001, "ENOTAUTHENTICATED"),
            ],
        )
        await c.connect()
        with pytest.raises(AdapterAuthenticationError):
            await c.list_pools()

    @pytest.mark.asyncio
    async def test_generic_error_maps_to_apierror(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, _ = _client_with(
            monkeypatch,
            [
                _rpc(1, {"response_type": "SUCCESS"}),
                _rpc_err(2, -32000, "ESOMETHING", "kaboom"),
            ],
        )
        await c.connect()
        with pytest.raises(TrueNASAPIError):
            await c.list_disks()


# ---------------------------------------------------------------------------
# Snapshot method fallback
# ---------------------------------------------------------------------------


class TestRichReads:
    @pytest.mark.asyncio
    async def test_alerts_temps_services(self, monkeypatch: pytest.MonkeyPatch) -> None:
        c, _ = _client_with(
            monkeypatch,
            [
                _rpc(1, {"response_type": "SUCCESS"}),
                _rpc(2, [{"level": "CRITICAL", "klass": "DiskTemperatureTooHot", "formatted": "hot"}]),
                _rpc(3, {"sda": 40.0, "sdb": 55.5}),
                _rpc(4, [{"service": "cifs", "state": "RUNNING", "enable": True}]),
            ],
        )
        await c.connect()
        assert (await c.list_alerts())[0]["level"] == "CRITICAL"
        assert (await c.disk_temperatures())["sdb"] == 55.5
        assert (await c.list_services())[0]["service"] == "cifs"

    @pytest.mark.asyncio
    async def test_data_protection_counts_resilient(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # snapshot tasks -> 2, replication errors -> 0 (swallowed), cloudsync -> 0.
        c, _ = _client_with(
            monkeypatch,
            [
                _rpc(1, {"response_type": "SUCCESS"}),
                _rpc(2, [{}, {}]),
                _rpc_err(3, -32000, "EOOPS"),
                _rpc(4, []),
            ],
        )
        await c.connect()
        dp = await c.data_protection_counts()
        assert dp == {"snapshot_tasks": 2, "replication": 0, "cloudsync": 0}


class TestSnapshots:
    @pytest.mark.asyncio
    async def test_falls_back_to_legacy_method(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # pool.snapshot.query → method-not-found (-32601); client retries
        # the legacy zfs.snapshot.query and succeeds.
        c, fake = _client_with(
            monkeypatch,
            [
                _rpc(1, {"response_type": "SUCCESS"}),
                _rpc_err(2, -32601, "ENOMETHOD", "no such method"),
                _rpc(3, [{"id": "tank@daily"}]),
            ],
        )
        await c.connect()
        snaps = await c.list_snapshots()
        assert snaps[0]["id"] == "tank@daily"
        methods = [json.loads(m)["method"] for m in fake.sent]
        assert methods == ["auth.login_ex", "pool.snapshot.query", "zfs.snapshot.query"]


# ---------------------------------------------------------------------------
# Dataset flatten + dedupe
# ---------------------------------------------------------------------------


class TestFlattenDatasets:
    def test_pure_tree_flattens(self) -> None:
        tree = [
            {"id": "tank", "children": [
                {"id": "tank/a", "children": []},
                {"id": "tank/b", "children": []},
            ]},
        ]
        out = _flatten_datasets(tree)
        assert [d["id"] for d in out] == ["tank", "tank/a", "tank/b"]
        # children stripped from the flattened rows
        assert all("children" not in d for d in out)

    def test_flat_with_redundant_children_deduped(self) -> None:
        # The 26.0 shape: child appears at top-level AND nested.
        nodes = [
            {"id": "tank", "children": [{"id": "tank/a", "children": []}]},
            {"id": "tank/a", "children": []},
        ]
        out = _flatten_datasets(nodes)
        assert [d["id"] for d in out] == ["tank", "tank/a"]  # no dupe


# ---------------------------------------------------------------------------
# Adapter transport selection (WS first, REST fallback)
# ---------------------------------------------------------------------------


class _WSConnFail:
    """WS endpoint unreachable / not present (pre-25.04 box)."""

    def __init__(self, **_kw: Any) -> None:
        pass

    async def connect(self) -> None:
        raise AdapterConnectionError("no /api/current here")

    async def disconnect(self) -> None:
        pass


class _WSAuthFail:
    """WS endpoint present but credential rejected."""

    def __init__(self, **_kw: Any) -> None:
        pass

    async def connect(self) -> None:
        raise AdapterAuthenticationError("bad key")

    async def disconnect(self) -> None:
        pass


class _WSOk:
    def __init__(self, **_kw: Any) -> None:
        pass

    async def connect(self) -> None:
        return None

    async def disconnect(self) -> None:
        pass


class _RESTOk:
    used = False

    def __init__(self, **_kw: Any) -> None:
        type(self).used = False

    async def connect(self) -> None:
        type(self).used = True

    async def disconnect(self) -> None:
        pass


class TestTransportSelection:
    def _adapter(self) -> Any:
        from app.adapters.truenas.adapter import TrueNASAdapter

        return TrueNASAdapter(host="nas.lab", username="truenas_admin", api_key="k")

    @pytest.mark.asyncio
    async def test_ws_preferred_when_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("app.adapters.truenas.adapter.TrueNASWSClient", _WSOk)
        monkeypatch.setattr("app.adapters.truenas.adapter.TrueNASClient", _RESTOk)
        a = self._adapter()
        await a.connect()
        assert a._transport == "ws"
        assert _RESTOk.used is False  # REST never touched

    @pytest.mark.asyncio
    async def test_falls_back_to_rest_on_ws_connection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("app.adapters.truenas.adapter.TrueNASWSClient", _WSConnFail)
        monkeypatch.setattr("app.adapters.truenas.adapter.TrueNASClient", _RESTOk)
        a = self._adapter()
        await a.connect()
        assert a._transport == "rest"
        assert _RESTOk.used is True

    @pytest.mark.asyncio
    async def test_ws_auth_error_not_masked_by_rest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("app.adapters.truenas.adapter.TrueNASWSClient", _WSAuthFail)
        monkeypatch.setattr("app.adapters.truenas.adapter.TrueNASClient", _RESTOk)
        _RESTOk.used = False  # reset class-level flag (REST __init__ never runs here)
        a = self._adapter()
        with pytest.raises(AdapterAuthenticationError):
            await a.connect()
        assert _RESTOk.used is False  # auth failure surfaced, no REST retry

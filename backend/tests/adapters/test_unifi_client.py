# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""HTTP-level tests for :class:`app.adapters.unifi.client.UniFiClient`.

Every test uses a mocked ``httpx.AsyncClient`` so no live UniFi
controller is contacted. Covers:

  * Auto-detection of UniFi OS vs Classic at login time.
  * Cookie / session reuse — the same httpx client survives across
    multiple ``_request`` calls.
  * 401 on a request triggers a single transparent re-login.
  * ``aclose()`` closes the underlying httpx client.
  * Shape of common read responses (envelope normalisation).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.adapters.unifi.client import UniFiClient
from app.adapters.unifi.exceptions import (
    UniFiAPIError,
    UniFiAuthError,
    UniFiConnectionError,
)


def _make_client(*, is_unifi_os: bool | None = None) -> UniFiClient:
    """Build a client pointed at TEST-NET-1; httpx is mocked so no I/O."""
    return UniFiClient(
        host="192.0.2.1",
        username="admin",
        password="x",
        port=8443,
        site="default",
        verify_ssl=False,
        is_unifi_os=is_unifi_os,
    )


def _ok_response(json_body: object, *, status: int = 200) -> MagicMock:
    """Build a mock ``httpx.Response`` that returns ``json_body``."""
    resp = MagicMock()
    resp.status_code = status
    resp.json = MagicMock(return_value=json_body)
    resp.text = str(json_body)
    resp.headers = {}
    return resp


# ─────────────────────────────────────────────────────────────────────
# Login probe
# ─────────────────────────────────────────────────────────────────────


class TestLoginProbe:
    @pytest.mark.asyncio
    async def test_classic_login_succeeds(self) -> None:
        """When the caller supplies ``is_unifi_os=False`` the probe
        is skipped and the Classic path is used directly."""
        client = _make_client(is_unifi_os=False)
        client._client.post = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response({"meta": {"rc": "ok"}, "data": []}),
        )
        ok = await client.login()
        assert ok is True
        assert client._authenticated is True
        assert client.is_unifi_os is False

    @pytest.mark.asyncio
    async def test_udm_login_succeeds(self) -> None:
        client = _make_client(is_unifi_os=True)
        client._client.post = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response(
                {"unique_id": "abc123", "username": "admin"},
            ),
        )
        ok = await client.login()
        assert ok is True
        assert client.is_unifi_os is True

    @pytest.mark.asyncio
    async def test_auto_detect_falls_back_to_classic(self) -> None:
        """No explicit mode → probe UDM (404), fall back to Classic (200)."""
        client = _make_client(is_unifi_os=None)
        # First call: UDM returns 404 — we don't tip the breaker.
        udm_resp = _ok_response({"meta": {"rc": "error"}}, status=404)
        classic_resp = _ok_response({"meta": {"rc": "ok"}, "data": []})
        client._client.post = AsyncMock(  # type: ignore[method-assign]
            side_effect=[udm_resp, classic_resp],
        )
        ok = await client.login()
        assert ok is True
        assert client.is_unifi_os is False
        # Two calls — one UDM probe, one classic login.
        assert client._client.post.await_count == 2

    @pytest.mark.asyncio
    async def test_auth_failure_is_definitive(self) -> None:
        """A 401 on the first probe surfaces immediately — the same
        credentials would be rejected on the other generation too."""
        client = _make_client(is_unifi_os=None)
        bad = _ok_response(
            {"meta": {"rc": "error", "msg": "Invalid login"}},
            status=401,
        )
        client._client.post = AsyncMock(  # type: ignore[method-assign]
            return_value=bad,
        )
        with pytest.raises(UniFiAuthError):
            await client.login()

    @pytest.mark.asyncio
    async def test_login_5xx_raises_api_error(self) -> None:
        client = _make_client(is_unifi_os=False)
        bad = _ok_response({"meta": {"rc": "error"}}, status=502)
        client._client.post = AsyncMock(  # type: ignore[method-assign]
            return_value=bad,
        )
        with pytest.raises(UniFiAPIError):
            await client.login()


# ─────────────────────────────────────────────────────────────────────
# Session reuse
# ─────────────────────────────────────────────────────────────────────


class TestSessionReuse:
    @pytest.mark.asyncio
    async def test_request_uses_same_underlying_client(self) -> None:
        """Two consecutive ``GET`` calls must reuse the same
        ``httpx.AsyncClient`` instance — that's how UniFi cookies
        survive across calls."""
        client = _make_client(is_unifi_os=False)
        client._authenticated = True
        underlying = client._client
        client._client.request = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response({"meta": {"rc": "ok"}, "data": []}),
        )
        await client.get("/stat/device")
        await client.get("/stat/sta")
        assert client._client is underlying
        assert client._client.request.await_count == 2


# ─────────────────────────────────────────────────────────────────────
# DNS-rebind pin + redirect hardening
# ─────────────────────────────────────────────────────────────────────


class TestConnectionPinning:
    def test_ip_host_pin_is_noop_and_redirects_off(self) -> None:
        """An IP host is a strict no-op for the DNS-rebind pin
        (base_url keeps the IP, no SNI extension) — so live IP/Tailscale controllers
        are untouched — and follow_redirects is OFF so a rebinding/compromised
        upstream cannot 30x-pivot the credentialed session to an internal host that
        httpx would re-resolve unvalidated."""
        client = _make_client()  # host=192.0.2.1 (an IP literal)
        assert "192.0.2.1" in client.base_url
        assert client._req_extensions is None
        assert client._client.follow_redirects is False

    def test_blocked_host_fails_closed(self) -> None:
        """A host that resolves to a blocked (loopback/metadata)
        address must FAIL CLOSED — refuse to build the client — NOT fall back to the
        raw host (which httpx would re-resolve and DNS-rebind straight to it)."""
        with pytest.raises(UniFiConnectionError):
            UniFiClient(
                host="127.0.0.1",  # loopback → resolve_and_pin_host rejects it
                username="admin",
                password="x",
                port=443,
                use_ssl=True,
                verify_ssl=False,
                is_unifi_os=False,
            )


# ─────────────────────────────────────────────────────────────────────
# 401 retry-on-expired-session
# ─────────────────────────────────────────────────────────────────────


class Test401RetryFlow:
    @pytest.mark.asyncio
    async def test_401_triggers_relogin_then_retry(self) -> None:
        """First call gets 401 → client re-logs in → original call
        retried → second call returns 200."""
        client = _make_client(is_unifi_os=False)
        client._authenticated = True

        # First GET: 401. Re-login POST: 200. Retry GET: 200.
        request_responses = [
            _ok_response({"meta": {"rc": "error"}}, status=401),
            _ok_response({"meta": {"rc": "ok"}, "data": [{"x": 1}]}, status=200),
        ]
        client._client.request = AsyncMock(  # type: ignore[method-assign]
            side_effect=request_responses,
        )
        client._client.post = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response(
                {"meta": {"rc": "ok"}, "data": []},
                status=200,
            ),
        )
        result = await client.get("/stat/device")
        assert result == {"meta": {"rc": "ok"}, "data": [{"x": 1}]}
        # One re-login POST + two GETs.
        assert client._client.post.await_count == 1
        assert client._client.request.await_count == 2

    @pytest.mark.asyncio
    async def test_write_post_401_does_not_replay(self, monkeypatch) -> None:
        """A non-idempotent POST (create) that 401s must NOT be
        blindly replayed — the original may have reached the device before the
        completing response carried 401, so a replay would DUPLICATE the object. The
        client re-logins (refreshes the pooled session) then RAISES, so a half-applied
        write is visible for the operator to re-check rather than silently doubled."""
        # Isolate the 401-retry logic from the staged-write gate (that boundary is
        # covered by the safety tests); here we just need the POST to reach the wire.
        from app.adapters.unifi import client as _unifi_client

        monkeypatch.setattr(_unifi_client, "_is_adapter_read_only", lambda: False)
        client = _make_client(is_unifi_os=False)
        client._authenticated = True

        client._client.request = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response({"meta": {"rc": "error"}}, status=401),
        )
        client._client.post = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response({"meta": {"rc": "ok"}, "data": []}, status=200),
        )
        with pytest.raises(UniFiAuthError):
            await client._request("POST", "/rest/networkconf", json={"name": "x"})
        # The data POST was issued exactly ONCE (never replayed) — but the session
        # WAS refreshed so the operator's re-apply succeeds on a fresh session.
        assert client._client.request.await_count == 1
        assert client._client.post.await_count == 1

    @pytest.mark.asyncio
    async def test_concurrent_401s_trigger_only_one_relogin(self) -> None:
        """The adapter pool hands ONE client to many concurrent requests, so a
        session expiry yields a burst of simultaneous 401s. The session-generation
        guard must collapse them to a SINGLE re-login (not N) — else the storm
        hammers the controller's Identity layer, which 429s/403s it and trips the
        breaker."""
        import asyncio

        client = _make_client(is_unifi_os=False)
        client._authenticated = True

        # Stateful transport: every data request 401s until a login flips the
        # session valid; thereafter it 200s. The login POST is the only thing
        # that flips it — so counting logins counts the storm collapse.
        state = {"valid": False, "logins": 0}

        async def fake_request(method, url, **kw):
            if state["valid"]:
                return _ok_response({"meta": {"rc": "ok"}, "data": [{"ok": 1}]}, status=200)
            return _ok_response({"meta": {"rc": "error"}}, status=401)

        async def fake_post(url, **kw):
            state["logins"] += 1
            state["valid"] = True
            return _ok_response({"meta": {"rc": "ok"}, "data": []}, status=200)

        client._client.request = AsyncMock(side_effect=fake_request)  # type: ignore[method-assign]
        client._client.post = AsyncMock(side_effect=fake_post)  # type: ignore[method-assign]

        # 8 concurrent reads, all racing into the same expired session.
        results = await asyncio.gather(*(client.get("/stat/device") for _ in range(8)))

        assert all(r["data"] == [{"ok": 1}] for r in results)
        assert state["logins"] == 1, (
            f"expected exactly ONE re-login for the concurrent 401 burst, "
            f"got {state['logins']} (login storm not collapsed)"
        )
        assert client._auth_generation == 1

    @pytest.mark.asyncio
    async def test_persistent_401_propagates(self) -> None:
        """If the retry also returns 401, we surface ``UniFiAuthError``."""
        client = _make_client(is_unifi_os=False)
        client._authenticated = True

        client._client.request = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response(
                {"meta": {"rc": "error"}},
                status=401,
            ),
        )
        client._client.post = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response(
                {"meta": {"rc": "ok"}, "data": []},
                status=200,
            ),
        )
        with pytest.raises(UniFiAuthError):
            await client.get("/stat/device")


# ─────────────────────────────────────────────────────────────────────
# Resource hygiene
# ─────────────────────────────────────────────────────────────────────


class TestAclose:
    @pytest.mark.asyncio
    async def test_aclose_closes_httpx_client(self) -> None:
        client = _make_client(is_unifi_os=False)
        client._authenticated = True
        client._client.post = AsyncMock()  # type: ignore[method-assign]
        client._client.aclose = AsyncMock()  # type: ignore[method-assign]
        await client.aclose()
        client._client.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_aclose_is_idempotent(self) -> None:
        client = _make_client(is_unifi_os=False)
        client._client.aclose = AsyncMock()  # type: ignore[method-assign]
        await client.aclose()
        await client.aclose()
        assert client._client.aclose.await_count == 2  # safe-to-double-call

    @pytest.mark.asyncio
    async def test_close_alias_works(self) -> None:
        """``close()`` is the legacy name; ``aclose()`` is the
        canonical one. Both must work."""
        client = _make_client(is_unifi_os=False)
        client._client.aclose = AsyncMock()  # type: ignore[method-assign]
        await client.close()
        client._client.aclose.assert_awaited_once()


# ─────────────────────────────────────────────────────────────────────
# Common reads (shape of normalised response)
# ─────────────────────────────────────────────────────────────────────


class TestReadShape:
    @pytest.mark.asyncio
    async def test_get_devices_returns_envelope(self) -> None:
        client = _make_client(is_unifi_os=False)
        client._authenticated = True
        client._client.request = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response(
                {"meta": {"rc": "ok"}, "data": [{"mac": "aa:bb:cc:dd:ee:ff"}]},
            ),
        )
        result = await client.get_devices()
        assert result["meta"]["rc"] == "ok"
        assert isinstance(result["data"], list)

    @pytest.mark.asyncio
    async def test_get_sites_uses_unscoped_url(self) -> None:
        """``/api/self/sites`` lives outside the site scope —
        verify the request goes to the right URL."""
        client = _make_client(is_unifi_os=False)
        client._authenticated = True
        client._client.request = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response(
                {"meta": {"rc": "ok"}, "data": []},
            ),
        )
        await client.get_sites()
        args, kwargs = client._client.request.await_args
        assert args[1].endswith("/api/self/sites")

    @pytest.mark.asyncio
    async def test_envelope_added_when_body_missing_meta(self) -> None:
        """Some UniFi endpoints return a bare list — the client
        wraps it in the envelope so callers see a uniform shape."""
        client = _make_client(is_unifi_os=False)
        client._authenticated = True
        client._client.request = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response([{"foo": 1}, {"foo": 2}]),
        )
        result = await client.get("/stat/device")
        assert result["meta"]["rc"] == "ok"
        assert result["data"] == [{"foo": 1}, {"foo": 2}]


# ─────────────────────────────────────────────────────────────────────
# Circuit-breaker integration
# ─────────────────────────────────────────────────────────────────────


class TestBreakerIntegration:
    @pytest.mark.asyncio
    async def test_open_breaker_short_circuits_request(self) -> None:
        client = _make_client(is_unifi_os=False)
        client._authenticated = True
        # Manually trip the breaker.
        for _ in range(client._breaker.failure_threshold):
            client._breaker.record_failure()
        assert client._breaker.allow_request() is False
        with pytest.raises(UniFiConnectionError):
            await client.get("/stat/device")

    @pytest.mark.asyncio
    async def test_5xx_response_ticks_breaker(self) -> None:
        client = _make_client(is_unifi_os=False)
        client._authenticated = True
        client._client.request = AsyncMock(  # type: ignore[method-assign]
            return_value=_ok_response(
                {"meta": {"rc": "error"}},
                status=503,
            ),
        )
        start_failures = client._breaker._failure_count
        with pytest.raises(UniFiAPIError):
            await client.get("/stat/device")
        assert client._breaker._failure_count == start_failures + 1


# ─────────────────────────────────────────────────────────────────────
# Network error mapping
# ─────────────────────────────────────────────────────────────────────


class TestNetworkErrorMapping:
    @pytest.mark.asyncio
    async def test_timeout_raises_timeout_error(self) -> None:
        from app.adapters.exceptions import AdapterTimeoutError

        client = _make_client(is_unifi_os=False)
        client._authenticated = True
        client._client.request = AsyncMock(  # type: ignore[method-assign]
            side_effect=httpx.ReadTimeout("read timeout"),
        )
        with pytest.raises(AdapterTimeoutError):
            await client.get("/stat/device")

    @pytest.mark.asyncio
    async def test_connect_error_raises_connection_error(self) -> None:
        from app.adapters.exceptions import AdapterConnectionError

        client = _make_client(is_unifi_os=False)
        client._authenticated = True
        client._client.request = AsyncMock(  # type: ignore[method-assign]
            side_effect=httpx.ConnectError("no route to host"),
        )
        with pytest.raises(AdapterConnectionError):
            await client.get("/stat/device")

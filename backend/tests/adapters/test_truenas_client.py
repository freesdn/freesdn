# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Client-layer tests for ``TrueNASClient``.

Mock the underlying httpx exchange with ``respx`` (already in the
backend test deps via the other adapter test suites) so we exercise
the real client paths — auth header construction, error translation,
size cap, JSON parsing — without a live appliance.
"""
from __future__ import annotations

import json

import httpx
import pytest

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterNotFoundError,
    AdapterTimeoutError,
)
from app.adapters.truenas.client import TrueNASAPIError, TrueNASClient
from app.adapters.truenas.constants import (
    EP_AUTH_CHECK,
    EP_POOL,
    EP_SYSTEM_INFO,
    MAX_RESPONSE_BYTES,
)


def _make_client(*, api_key: str | None = "test-key") -> TrueNASClient:
    return TrueNASClient(
        host="truenas.lab",
        username="admin",
        password="pw",
        api_key=api_key,
        port=443,
        verify_ssl=False,
    )


def _mount_transport(client: TrueNASClient, handler) -> None:
    """Replace the live httpx client with one backed by MockTransport."""
    transport = httpx.MockTransport(handler)
    client._client = httpx.AsyncClient(
        base_url=client.base_url,
        transport=transport,
        headers=client._auth_headers(),
        auth=None if client.api_key else (client.username, client.password),
    )


# ---------------------------------------------------------------------------
# Auth headers + auth probe
# ---------------------------------------------------------------------------

class TestAuthHeaders:
    def test_api_key_emits_bearer(self) -> None:
        c = _make_client(api_key="abc-123")
        assert c._auth_headers()["Authorization"] == "Bearer abc-123"

    def test_no_api_key_no_authorization_header(self) -> None:
        """Basic auth is provided via ``httpx.AsyncClient(auth=...)``,
        not via a manual Authorization header, so the header dict
        intentionally lacks one."""
        c = _make_client(api_key=None)
        assert "Authorization" not in c._auth_headers()


class TestProbeAuth:
    @pytest.mark.asyncio
    async def test_401_raises_auth_error(self) -> None:
        c = _make_client()

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == EP_AUTH_CHECK
            return httpx.Response(401, json={"detail": "no"})

        _mount_transport(c, handler)
        with pytest.raises(AdapterAuthenticationError):
            await c._probe_auth()

    @pytest.mark.asyncio
    async def test_500_raises_connection_error(self) -> None:
        c = _make_client()
        _mount_transport(c, lambda r: httpx.Response(503))
        with pytest.raises(AdapterConnectionError):
            await c._probe_auth()

    @pytest.mark.asyncio
    async def test_connection_refused_translated(self) -> None:
        c = _make_client()

        def boom(_r):
            raise httpx.ConnectError("refused")

        _mount_transport(c, boom)
        with pytest.raises(AdapterConnectionError):
            await c._probe_auth()

    @pytest.mark.asyncio
    async def test_timeout_translated(self) -> None:
        c = _make_client()

        def boom(_r):
            raise httpx.ConnectTimeout("slow")

        _mount_transport(c, boom)
        with pytest.raises(AdapterTimeoutError):
            await c._probe_auth()

    @pytest.mark.asyncio
    async def test_200_passes(self) -> None:
        c = _make_client()
        _mount_transport(c, lambda r: httpx.Response(200, json={"state": "READY"}))
        await c._probe_auth()  # no raise


# ---------------------------------------------------------------------------
# _get_json error translation
# ---------------------------------------------------------------------------

class TestGetJsonErrors:
    @pytest.mark.asyncio
    async def test_404_raises_not_found(self) -> None:
        c = _make_client()
        _mount_transport(c, lambda r: httpx.Response(404, json={"detail": "no"}))
        with pytest.raises(AdapterNotFoundError):
            await c._get_json("/api/v2.0/missing")

    @pytest.mark.asyncio
    async def test_403_raises_auth_error(self) -> None:
        c = _make_client()
        _mount_transport(c, lambda r: httpx.Response(403))
        with pytest.raises(AdapterAuthenticationError):
            await c._get_json("/api/v2.0/pool")

    @pytest.mark.asyncio
    async def test_500_raises_api_error_with_body(self) -> None:
        c = _make_client()
        _mount_transport(c, lambda r: httpx.Response(500, text="boom"))
        with pytest.raises(TrueNASAPIError) as e:
            await c._get_json("/api/v2.0/pool")
        assert e.value.status_code == 500
        assert "boom" in e.value.body

    @pytest.mark.asyncio
    async def test_non_2xx_other_raises(self) -> None:
        c = _make_client()
        _mount_transport(c, lambda r: httpx.Response(418, text="teapot"))
        with pytest.raises(TrueNASAPIError):
            await c._get_json("/api/v2.0/pool")

    @pytest.mark.asyncio
    async def test_non_json_body_raises(self) -> None:
        c = _make_client()
        _mount_transport(c, lambda r: httpx.Response(200, text="<html>nope</html>"))
        with pytest.raises(TrueNASAPIError) as e:
            await c._get_json("/api/v2.0/pool")
        assert "non-JSON" in str(e.value)

    @pytest.mark.asyncio
    async def test_response_size_cap_enforced(self) -> None:
        """A payload over MAX_RESPONSE_BYTES is rejected before parse.

        Build a JSON array large enough to exceed the cap. We use
        repeated padding rather than allocating MAX_RESPONSE_BYTES of
        actual bytes — we just need to trip the length check.
        """
        c = _make_client()
        # Lower the cap temporarily by monkeypatching the module constant
        # via the client's _get_json — easier path is to feed a body
        # larger than 50 MB. We construct one programmatically.
        oversized = b"x" * (MAX_RESPONSE_BYTES + 100)
        _mount_transport(c, lambda r: httpx.Response(
            200, content=oversized, headers={"content-type": "application/json"},
        ))
        with pytest.raises(TrueNASAPIError) as e:
            await c._get_json("/api/v2.0/pool")
        assert "size cap" in str(e.value)


# ---------------------------------------------------------------------------
# Read methods — shape guards
# ---------------------------------------------------------------------------

class TestReadMethods:
    @pytest.mark.asyncio
    async def test_get_system_info_returns_dict(self) -> None:
        c = _make_client()
        payload = {"version": "TrueNAS-SCALE-23.10.2", "hostname": "nas01"}
        _mount_transport(c, lambda r: httpx.Response(200, json=payload))
        out = await c.get_system_info()
        assert out["version"] == "TrueNAS-SCALE-23.10.2"

    @pytest.mark.asyncio
    async def test_get_system_info_rejects_non_object(self) -> None:
        """If TrueNAS ever returns a list here, refuse loudly — the FE
        and parser both assume an object."""
        c = _make_client()
        _mount_transport(c, lambda r: httpx.Response(200, json=["bad"]))
        with pytest.raises(TrueNASAPIError):
            await c.get_system_info()

    @pytest.mark.asyncio
    async def test_list_pools_returns_list(self) -> None:
        c = _make_client()
        payload = [{"name": "tank", "status": "ONLINE"}]
        _mount_transport(c, lambda r: httpx.Response(200, json=payload))
        out = await c.list_pools()
        assert out[0]["name"] == "tank"

    @pytest.mark.asyncio
    async def test_list_pools_rejects_non_list(self) -> None:
        c = _make_client()
        _mount_transport(c, lambda r: httpx.Response(200, json={"oops": True}))
        with pytest.raises(TrueNASAPIError):
            await c.list_pools()

    @pytest.mark.asyncio
    async def test_request_when_disconnected_raises(self) -> None:
        """Calling a method on a client whose ``_client`` is None must
        raise an actionable error rather than crashing with an opaque
        ``NoneType`` AttributeError."""
        c = _make_client()
        # Do NOT mount transport — _client stays None.
        with pytest.raises(AdapterConnectionError):
            await c.list_pools()

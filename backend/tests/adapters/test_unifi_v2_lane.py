# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Behavioural tests for the UniFi client **v2 "modern" lane**.

UniFi OS 10.x exposes a second API surface — the zone-based-firewall /
policy engine — under ``/v2/api/site/{site}/...``. Unlike the classic v1
lane (which wraps every body in ``{"meta":{"rc":...}}`` and treats a
non-"ok" ``rc`` at HTTP 200 as a logical failure), the v2 lane returns
**bare JSON** and signals success/failure purely via the HTTP status:

  * 200 / 201       → success; the bare body is normalised into the
                      classic ``{"meta":{"rc":"ok"},"data":<body>}`` envelope
                      so the adapter layer stays generation-agnostic.
  * 204 / empty     → success with an empty ``data`` list.
  * 4xx (errorCode) → :class:`UniFiAPIError`.

The HTTP layer is mocked everywhere (real ``httpx.Response`` objects fed
through a patched ``client._client.request``) so **no live controller is
contacted** — every client points at TEST-NET-1 (RFC 5737).

Fixture bodies mirror the real UCG Fiber captures (``static-dns`` create
returns a single object; the list reads return a bare ``[]``).

CRITICALLY: this module also pins the v1 ``meta.rc`` honesty gate as a
**regression guard** — adding the v2 lane must not relax the v1 rule that
an HTTP 200 carrying ``{"meta":{"rc":"error"}}`` still raises.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.adapters.unifi.client import UniFiClient
from app.adapters.unifi.exceptions import UniFiAPIError

# Patch path for the client-layer read-only gate (mirrors test_unifi_safety).
_CLIENT_GATE = "app.adapters.unifi.client._is_adapter_read_only"

# A faithful single-object create body (from the real static-dns write capture).
_STATIC_DNS_OBJ = {
    "_id": "6a435e75dfcf14f660ab05b3",
    "enabled": True,
    "key": "fsdn-cap.local",
    "port": 0,
    "priority": 0,
    "record_type": "A",
    "ttl": 0,
    "value": "10.77.0.5",
    "weight": 0,
}


def _make_client(*, is_unifi_os: bool = True) -> UniFiClient:
    """A UniFi-OS client pointed at TEST-NET-1; no I/O until login.

    ``is_unifi_os=True`` so the v2 URL carries the ``/proxy/network``
    prefix the real gateway uses. A CSRF token is pre-seeded so mutating
    verbs attach the ``X-CSRF-Token`` header without a login round-trip.
    """
    client = UniFiClient(
        host="192.0.2.1",
        username="admin",
        password="x",
        port=8443,
        site="default",
        verify_ssl=False,
        is_unifi_os=is_unifi_os,
    )
    client._authenticated = True
    client._csrf_token = "csrf-test-token"
    return client


def _capture_request(client: UniFiClient, response: httpx.Response) -> AsyncMock:
    """Patch ``client._client.request`` to return ``response`` and capture args."""
    mock = AsyncMock(return_value=response)
    client._client.request = mock  # type: ignore[method-assign]
    return mock


# ─────────────────────────────────────────────────────────────────────
# URL construction
# ─────────────────────────────────────────────────────────────────────


class TestV2UrlConstruction:
    """``_request(lane="v2")`` must hit ``/proxy/network/v2/api/site/{site}/...``
    on UniFi OS (and the bare ``/v2/api/site/{site}/...`` on Classic)."""

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_v2_get_builds_proxy_network_v2_site_url(self) -> None:
        client = _make_client(is_unifi_os=True)
        mock = _capture_request(client, httpx.Response(200, json=[]))
        try:
            await client._request("GET", "/firewall-policies", lane="v2")
        finally:
            await client._client.aclose()
        method, url = mock.await_args.args[0], mock.await_args.args[1]
        assert method == "GET"
        assert url == "/proxy/network/v2/api/site/default/firewall-policies"

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_v2_classic_url_has_no_proxy_prefix(self) -> None:
        client = _make_client(is_unifi_os=False)
        mock = _capture_request(client, httpx.Response(200, json=[]))
        try:
            await client._request("GET", "/static-dns", lane="v2")
        finally:
            await client._client.aclose()
        url = mock.await_args.args[1]
        assert url == "/v2/api/site/default/static-dns"

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_v2_non_site_scoped_url(self) -> None:
        """``site_scoped=False`` drops the ``/site/{site}`` segment but keeps
        the ``/v2/api`` root (used for controller-wide v2 surfaces)."""
        client = _make_client(is_unifi_os=True)
        mock = _capture_request(client, httpx.Response(200, json={"x": 1}))
        try:
            await client._request("GET", "/info", lane="v2", site_scoped=False)
        finally:
            await client._client.aclose()
        url = mock.await_args.args[1]
        assert url == "/proxy/network/v2/api/info"

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_v2_url_tracks_site_mutation(self) -> None:
        """The v2 URL reads ``self.site`` live, so an adapter that sets
        ``self._api.site = site`` redirects the v2 call too."""
        client = _make_client(is_unifi_os=True)
        client.site = "office-eu"
        mock = _capture_request(client, httpx.Response(200, json=[]))
        try:
            await client._request("GET", "/nat", lane="v2")
        finally:
            await client._client.aclose()
        assert mock.await_args.args[1] == "/proxy/network/v2/api/site/office-eu/nat"

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_v2_post_attaches_csrf_header(self) -> None:
        """UniFi OS requires ``X-CSRF-Token`` on every mutating verb."""
        client = _make_client(is_unifi_os=True)
        mock = _capture_request(client, httpx.Response(200, json=_STATIC_DNS_OBJ))
        try:
            await client._request("POST", "/static-dns", lane="v2", json={"key": "x"})
        finally:
            await client._client.aclose()
        headers = mock.await_args.kwargs["headers"]
        assert headers and headers.get("X-CSRF-Token") == "csrf-test-token"


# ─────────────────────────────────────────────────────────────────────
# Body normalisation (bare JSON → classic envelope)
# ─────────────────────────────────────────────────────────────────────


class TestV2BodyNormalisation:
    """A bare list / object body carries NO ``meta`` — the client wraps it
    so the adapter layer sees a uniform ``{"meta":{"rc":"ok"},"data":...}``."""

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_bare_list_body_wrapped(self) -> None:
        client = _make_client()
        body = [{"_id": "a", "name": "p1"}, {"_id": "b", "name": "p2"}]
        _capture_request(client, httpx.Response(200, json=body))
        try:
            result = await client._request("GET", "/firewall-policies", lane="v2")
        finally:
            await client._client.aclose()
        assert result == {"meta": {"rc": "ok"}, "data": body}

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_empty_list_body_wrapped(self) -> None:
        """The real static-dns / firewall-policies reads return a bare ``[]``."""
        client = _make_client()
        _capture_request(client, httpx.Response(200, json=[]))
        try:
            result = await client._request("GET", "/static-dns", lane="v2")
        finally:
            await client._client.aclose()
        assert result == {"meta": {"rc": "ok"}, "data": []}

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_single_object_body_wrapped_verbatim(self) -> None:
        """A v2 create returns a single object (not a list); it must land
        under ``data`` exactly as-is — no list-coercion."""
        client = _make_client()
        _capture_request(client, httpx.Response(200, json=_STATIC_DNS_OBJ))
        try:
            result = await client._request(
                "POST", "/static-dns", lane="v2", json={"key": "fsdn-cap.local"}
            )
        finally:
            await client._client.aclose()
        assert result["meta"]["rc"] == "ok"
        assert result["data"] == _STATIC_DNS_OBJ
        assert result["data"]["_id"] == "6a435e75dfcf14f660ab05b3"

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_v2_does_not_apply_meta_rc_gate(self) -> None:
        """A v2 body that happens to contain a ``meta`` key is NOT subject to
        the v1 rc-gate — v2 success already rode the HTTP status, so the body
        is wrapped wholesale under ``data`` (the rc-gate is v1-only)."""
        client = _make_client()
        # Pathological: a v2 object whose payload literally has meta.rc=error.
        # Because lane=="v2" returns BEFORE the rc-gate, this must NOT raise.
        body = {"meta": {"rc": "error"}, "name": "p"}
        _capture_request(client, httpx.Response(200, json=body))
        try:
            result = await client._request("GET", "/qos-rules", lane="v2")
        finally:
            await client._client.aclose()
        assert result == {"meta": {"rc": "ok"}, "data": body}


# ─────────────────────────────────────────────────────────────────────
# Status-code interpretation (the v2 honesty gate IS the HTTP status)
# ─────────────────────────────────────────────────────────────────────


class TestV2StatusCodes:
    """201 = created (success); 204 / empty = success-empty; 4xx = error."""

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_201_treated_as_success(self) -> None:
        client = _make_client()
        _capture_request(client, httpx.Response(201, json=_STATIC_DNS_OBJ))
        try:
            result = await client._request(
                "POST", "/static-dns", lane="v2", json={"key": "x"}
            )
        finally:
            await client._client.aclose()
        assert result["meta"]["rc"] == "ok"
        assert result["data"] == _STATIC_DNS_OBJ

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_204_no_content_is_success_empty(self) -> None:
        """A v2 DELETE answers 204 No Content; ``resp.json()`` would raise,
        so the client short-circuits to an empty-data ok envelope."""
        client = _make_client()
        _capture_request(client, httpx.Response(204))
        try:
            result = await client._request(
                "DELETE", "/static-dns/6a435e75dfcf14f660ab05b3", lane="v2"
            )
        finally:
            await client._client.aclose()
        assert result == {"meta": {"rc": "ok"}, "data": []}

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_200_empty_body_is_success_empty(self) -> None:
        """Some v2 deletes answer 200 with a zero-length body — same path."""
        client = _make_client()
        _capture_request(client, httpx.Response(200, content=b""))
        try:
            result = await client._request("DELETE", "/nat/x", lane="v2")
        finally:
            await client._client.aclose()
        assert result == {"meta": {"rc": "ok"}, "data": []}

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_4xx_with_errorcode_raises(self) -> None:
        """A v2 validation failure is a 4xx with ``errorCode``/``message`` —
        it must surface as UniFiAPIError (the 4xx branch reads the v2 shape)."""
        client = _make_client()
        _capture_request(
            client,
            httpx.Response(
                400,
                json={"errorCode": "InvalidPayload", "message": "key is required"},
            ),
        )
        try:
            with pytest.raises(UniFiAPIError) as exc:
                await client._request("POST", "/static-dns", lane="v2", json={})
        finally:
            await client._client.aclose()
        # The v2 error shape is surfaced (errorCode → meta_rc, message → meta_msg).
        assert exc.value.status_code == 400
        assert exc.value.meta_rc == "InvalidPayload"
        assert "key is required" in (exc.value.meta_msg or "")

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_404_raises_without_tipping_breaker(self) -> None:
        """A 4xx is an app-layer rejection — it propagates but must NOT
        record a breaker failure (only 5xx/408/429/transport do)."""
        client = _make_client()
        _capture_request(client, httpx.Response(404, json={"message": "no such zone"}))
        start = client._breaker._failure_count
        try:
            with pytest.raises(UniFiAPIError):
                await client._request("GET", "/firewall/zone/x", lane="v2")
        finally:
            await client._client.aclose()
        assert client._breaker._failure_count == start

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_5xx_raises_and_ticks_breaker(self) -> None:
        client = _make_client()
        _capture_request(client, httpx.Response(503, json={"message": "down"}))
        start = client._breaker._failure_count
        try:
            with pytest.raises(UniFiAPIError):
                await client._request("GET", "/topology", lane="v2")
        finally:
            await client._client.aclose()
        assert client._breaker._failure_count == start + 1


# ─────────────────────────────────────────────────────────────────────
# REGRESSION GUARD — the v1 meta.rc honesty gate must be UNCHANGED
# ─────────────────────────────────────────────────────────────────────


class TestV1HonestyGateUnchanged:
    """Adding the v2 lane must NOT relax the v1 rule: an HTTP 200 carrying
    ``{"meta":{"rc":"error"}}`` is a LOGICAL FAILURE on the v1 lane and must
    still raise. (On v2 the same body would be wrapped — see
    ``TestV2BodyNormalisation.test_v2_does_not_apply_meta_rc_gate`` — so this
    pair proves the lanes diverge exactly where they should.)"""

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_v1_200_rc_error_still_raises(self) -> None:
        client = _make_client(is_unifi_os=False)
        _capture_request(
            client,
            httpx.Response(
                200,
                json={"meta": {"rc": "error", "msg": "api.err.UnknownStation"}, "data": []},
            ),
        )
        try:
            with pytest.raises(UniFiAPIError) as exc:
                # No explicit lane → defaults to v1.
                await client._request("POST", "/cmd/stamgr", json={"cmd": "block-sta"})
        finally:
            await client._client.aclose()
        assert exc.value.meta_rc == "error"
        assert "api.err.UnknownStation" in (exc.value.meta_msg or "")

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_v1_200_rc_ok_returns_envelope(self) -> None:
        client = _make_client(is_unifi_os=False)
        _capture_request(
            client,
            httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [{"x": 1}]}),
        )
        try:
            result = await client._request("POST", "/cmd/stamgr", json={"cmd": "unblock-sta"})
        finally:
            await client._client.aclose()
        assert result["meta"]["rc"] == "ok"
        assert result["data"] == [{"x": 1}]

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_v1_bare_list_still_wrapped(self) -> None:
        """The pre-existing v1 normalisation (bare list → envelope) is intact."""
        client = _make_client(is_unifi_os=False)
        _capture_request(client, httpx.Response(200, json=[{"foo": 1}]))
        try:
            result = await client._request("GET", "/stat/device")
        finally:
            await client._client.aclose()
        assert result == {"meta": {"rc": "ok"}, "data": [{"foo": 1}]}


# ─────────────────────────────────────────────────────────────────────
# v2 client convenience methods route through lane="v2"
# ─────────────────────────────────────────────────────────────────────


class TestV2ClientMethodsUseV2Lane:
    """The high-level v2 read/write helpers must funnel through the v2 lane
    (hit ``/v2/api/site/...``), not the classic ``/api/s/...`` path."""

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_get_firewall_policies_hits_v2_path(self) -> None:
        client = _make_client()
        mock = _capture_request(client, httpx.Response(200, json=[]))
        try:
            await client.get_firewall_policies()
        finally:
            await client._client.aclose()
        assert mock.await_args.args[1] == (
            "/proxy/network/v2/api/site/default/firewall-policies"
        )

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_create_firewall_policy_posts_to_v2_path(self) -> None:
        client = _make_client()
        mock = _capture_request(client, httpx.Response(200, json={"_id": "x"}))
        try:
            await client.create_firewall_policy({"name": "p"})
        finally:
            await client._client.aclose()
        method, url = mock.await_args.args[0], mock.await_args.args[1]
        assert method == "POST"
        assert url == "/proxy/network/v2/api/site/default/firewall-policies"
        assert mock.await_args.kwargs["json"] == {"name": "p"}

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_batch_delete_posts_ids_to_v2_path(self) -> None:
        client = _make_client()
        mock = _capture_request(client, httpx.Response(200, json={}))
        try:
            await client.batch_delete_firewall_policies(["a1", "b2"])
        finally:
            await client._client.aclose()
        method, url = mock.await_args.args[0], mock.await_args.args[1]
        assert method == "POST"
        assert url.endswith("/firewall-policies/batch-delete")
        assert mock.await_args.kwargs["json"] == {"ids": ["a1", "b2"]}

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: False)
    async def test_delete_static_dns_hits_v2_delete(self) -> None:
        client = _make_client()
        mock = _capture_request(client, httpx.Response(204))
        try:
            await client.delete_static_dns("6a435e75dfcf14f660ab05b3")
        finally:
            await client._client.aclose()
        method, url = mock.await_args.args[0], mock.await_args.args[1]
        assert method == "DELETE"
        assert url.endswith("/static-dns/6a435e75dfcf14f660ab05b3")


# ─────────────────────────────────────────────────────────────────────
# v2 lane still honours the client-layer read-only write gate (Bucket A)
# ─────────────────────────────────────────────────────────────────────


class TestV2LaneReadOnlyGate:
    """The Bucket-A client gate is lane-agnostic: a v2 mutating verb is
    refused under read-only outside an approved apply window, just like v1.
    (force can't bypass it; only AdapterStagingService opens the window.)"""

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: True)
    async def test_v2_write_refused_under_readonly(self) -> None:
        from app.adapters.unifi.exceptions import AdapterReadOnlyError

        client = _make_client()
        try:
            with pytest.raises(AdapterReadOnlyError):
                await client._request(
                    "POST", "/static-dns", lane="v2", json={"key": "x"}
                )
        finally:
            await client._client.aclose()

    @pytest.mark.asyncio
    @patch(_CLIENT_GATE, lambda: True)
    async def test_v2_get_never_refused_under_readonly(self) -> None:
        """Reads are never gated — a v2 GET passes the gate and reaches the
        wire (here it returns a normal body)."""
        client = _make_client()
        _capture_request(client, httpx.Response(200, json=[]))
        try:
            result = await client._request("GET", "/topology", lane="v2")
        finally:
            await client._client.aclose()
        assert result == {"meta": {"rc": "ok"}, "data": []}

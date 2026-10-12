# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Focused tests for OmadaApiClient retry/auth/fallback behavior.
"""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.adapters.omada.client import OmadaApiClient, OmadaClientConfig
from app.adapters.omada.constants import (
    OMADA_ERROR_INVALID_PARAMS,
    OMADA_ERROR_PERMISSION_DENIED,
    OMADA_ERROR_SESSION_EXPIRED,
)
from app.adapters.omada.exceptions import (
    OmadaAuthorizationError,
    OmadaNotFoundError,
    OmadaValidationError,
)


class MockHttpResponse:
    """Minimal HTTP response test double for Omada client tests."""

    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://omada.local")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("status error", request=request, response=response)


def _make_client() -> tuple[OmadaApiClient, MagicMock]:
    """Create a logged-in OmadaApiClient with a mocked HTTP transport."""
    client = OmadaApiClient(
        OmadaClientConfig(
            host="omada.local",
            username="admin",
            password="secret",
            verify_ssl=False,
            max_retries=3,
            retry_backoff=0.01,
        )
    )
    http = MagicMock()
    http.is_closed = False
    http.request = AsyncMock()

    client._http = http
    client._logged_in = True
    client._controller_id = "ctrl-1"
    client._csrf_token = "csrf-token"
    client._rate_limiter.acquire = AsyncMock(return_value=True)
    return client, http


class TestOmadaApiClient:
    """Focused tests for retry, auth refresh, and endpoint fallback behavior."""

    @pytest.mark.asyncio
    async def test_request_retries_transient_http_status_then_succeeds(self):
        client, http = _make_client()
        http.request.side_effect = [
            MockHttpResponse(503, {}),
            MockHttpResponse(200, {"errorCode": 0, "result": {"value": 1}}),
        ]

        result = await client._request("GET", "/sites")

        assert result == {"value": 1}
        assert http.request.await_count == 2
        assert client._retry_count >= 1

    @pytest.mark.asyncio
    async def test_request_refreshes_session_on_session_expired_error_code(self):
        client, http = _make_client()
        http.request.side_effect = [
            MockHttpResponse(
                200,
                {"errorCode": OMADA_ERROR_SESSION_EXPIRED, "msg": "session expired"},
            ),
            MockHttpResponse(200, {"errorCode": 0, "result": {"ok": True}}),
        ]
        client.login = AsyncMock(return_value={"controller_id": "ctrl-1", "version": "5.14"})

        result = await client._request("GET", "/sites")

        assert result == {"ok": True}
        assert client.login.await_count == 1

    @pytest.mark.asyncio
    async def test_request_maps_permission_denied_to_authorization_error(self):
        client, http = _make_client()
        http.request.side_effect = [
            MockHttpResponse(
                200,
                {"errorCode": OMADA_ERROR_PERMISSION_DENIED, "msg": "insufficient perms"},
            )
        ]

        with pytest.raises(OmadaAuthorizationError):
            await client._request("GET", "/sites")

    @pytest.mark.asyncio
    async def test_request_maps_invalid_params_to_validation_error(self):
        client, http = _make_client()
        http.request.side_effect = [
            MockHttpResponse(
                200,
                {"errorCode": OMADA_ERROR_INVALID_PARAMS, "msg": "invalid payload"},
            )
        ]

        # apply_window(): this exercises the API error-mapping for a write that
        # REACHES the controller; the read-only write gate would
        # otherwise refuse the POST before the mocked response is returned.
        from app.adapters.apply_context import apply_window

        with pytest.raises(OmadaValidationError), apply_window():
            await client._request("POST", "/sites/site-1/setting/wlans", json_data={"x": "bad"})

    @pytest.mark.asyncio
    async def test_request_with_fallback_uses_next_endpoint_on_not_found(self):
        client, _ = _make_client()
        client._request = AsyncMock(side_effect=[OmadaNotFoundError("not found"), {"ok": True}])

        result = await client._request_with_fallback("GET", ["/primary", "/fallback"])

        assert result == {"ok": True}
        assert client._request.await_count == 2

    @pytest.mark.asyncio
    async def test_trigger_firmware_upgrade_uses_compatibility_paths(self):
        client, _ = _make_client()
        client._request_with_fallback = AsyncMock(return_value={"jobId": "fw-1"})

        payload = await client.trigger_firmware_upgrade("site-1", "AA:BB:CC:DD:EE:FF")

        assert payload == {"jobId": "fw-1"}
        client._request_with_fallback.assert_awaited_once_with(
            "POST",
            [
                "/sites/site-1/cmd/devices/AA:BB:CC:DD:EE:FF/upgrade",
                "/sites/site-1/devices/AA:BB:CC:DD:EE:FF/firmware/upgrade",
            ],
        )


# ── Found by the live parameterized-endpoint sweep: two 500s ────────────────


class NonJsonResponse:
    """A 200 whose body is not JSON.

    An Omada controller serves its HTML app for API paths the firmware does
    not implement, so `raise_for_status()` passes and `.json()` then raises.
    """

    status_code = 200
    text = "<!DOCTYPE html><html><head><title>Omada</title></head><body></body></html>"

    def json(self) -> dict:
        import json

        raise json.JSONDecodeError("Expecting value", self.text, 0)

    def raise_for_status(self) -> None:
        return None


class TestOmadaLiveSweepRegressions:
    @pytest.mark.asyncio
    async def test_non_json_200_raises_adapter_error_not_jsondecodeerror(self):
        """A non-JSON 200 must surface as OmadaApiError, which maps to 502.

        Before: the JSONDecodeError escaped the adapter uncaught and the
        request answered 500. Confirmed live on
        /gateway-system/{id}/sites/{id}/reboot-schedules and
        /gateway-vpn/{id}/sites/{id}/wireguard/peers.
        """
        from app.adapters.omada.exceptions import OmadaApiError

        client, http = _make_client()
        http.request.side_effect = [NonJsonResponse()]

        with pytest.raises(OmadaApiError) as ei:
            await client._request("GET", "/reboot-schedules")

        # The message has to name the real cause, or the operator is told
        # nothing actionable.
        msg = str(ei.value)
        assert "non-JSON" in msg
        assert "/reboot-schedules" in msg

    @pytest.mark.asyncio
    async def test_open_api_builds_url_from_the_resolved_base(self):
        """The Open API block read a config attribute that does not exist.

        `OmadaClientConfig` has host/port/use_ssl and a computed
        `effective_base_url`; it has never had `base_url`. Every Open API entry
        point -- token, refresh, sites, introspect -- raised AttributeError on
        its first line of real work, so /gateway-openapi/{id}/sites was a 500.
        """
        client, http = _make_client()
        client._ensure_session = AsyncMock()
        captured: dict[str, str] = {}

        async def fake_get(url, **_kw):
            captured["url"] = url
            return MockHttpResponse(200, {"result": {"data": [{"siteId": "s1"}]}})

        http.get = fake_get

        sites = await client.open_api_get_sites(access_token="tok")

        assert sites == [{"siteId": "s1"}]
        assert captured["url"] == f"{client.base_url}/openapi/v1/sites"

    def test_no_code_references_a_config_attribute_that_does_not_exist(self):
        """Ratchet: `config.base_url` must not come back.

        The resolved value lives on the CLIENT (`self.base_url`, set in
        __init__ from `config.effective_base_url`). Four call sites reached
        through `self.config` instead, and because nothing exercised the Open
        API path the mistake shipped.
        """
        import inspect

        from app.adapters.omada import client as omada_client

        assert not hasattr(OmadaClientConfig(host="h"), "base_url")
        src = inspect.getsource(omada_client)
        assert "config.base_url" not in src, (
            "OmadaClientConfig has no `base_url`; use self.base_url (or config.effective_base_url)"
        )

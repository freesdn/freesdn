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
        client._request = AsyncMock(
            side_effect=[OmadaNotFoundError("not found"), {"ok": True}]
        )

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

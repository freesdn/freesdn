# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""FreeSDN — TrueNAS REST API client.

Async ``httpx``-backed client for the TrueNAS v2.0 REST API. Backs
the read-only adapter foundation.

Auth modes supported (preferred order):

  1. ``api_key`` kwarg → ``Authorization: Bearer <key>``
  2. ``username + password`` → HTTP Basic

Resilience: circuit breaker + bounded response body size + explicit
error translation (auth / not-found / connection / timeout). No
retry loop here — the service layer wraps the call and the breaker
handles repeated failures.

NOTE: writes are NOT implemented. Calling ``post`` / ``put`` / ``delete``
would land on real datasets/shares; until the write surface ships with
the staging pipeline + role gates per CONTRACT §3, the client only
exposes ``get``.
"""

from __future__ import annotations

import contextlib
import json
import logging
from typing import Any

import httpx

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterError,
    AdapterNotFoundError,
    AdapterTimeoutError,
)
from app.adapters.http_utils import CircuitBreaker
from app.adapters.truenas.constants import (
    BREAKER_FAILURE_THRESHOLD,
    BREAKER_RESET_TIMEOUT_SEC,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_READ_TIMEOUT,
    EP_AUTH_CHECK,
    EP_DATASET,
    EP_DISK,
    EP_POOL,
    EP_SNAPSHOT,
    EP_SYSTEM_INFO,
    MAX_RESPONSE_BYTES,
)
from app.core.http_client import build_async_client

logger = logging.getLogger(__name__)


class TrueNASAPIError(AdapterError):
    """Generic TrueNAS API failure (non-auth, non-network)."""

    def __init__(self, message: str, status_code: int = 0, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class TrueNASClient:
    """Async HTTP client for the TrueNAS v2.0 REST API.

    Parameters
    ----------
    host : str
        TrueNAS hostname or IP.
    username : str
        Login username, used for Basic auth when ``api_key`` is unset.
    password : str
        Login password, used for Basic auth when ``api_key`` is unset.
    api_key : str | None
        Preferred auth path — bearer token from Settings → API Keys.
        When set, ``username`` / ``password`` are ignored.
    port : int
        HTTPS port (default 443).
    verify_ssl : bool
        Whether to verify the TLS certificate. TrueNAS appliances
        ship with self-signed certs by default, so the BaseAdapter
        default of ``False`` is intentional for lab installs.
    timeout : int | None
        Override the read timeout. ``connect`` is fixed lower so
        firewalled hosts fail fast.
    """

    def __init__(
        self,
        host: str,
        username: str = "",
        password: str = "",
        *,
        api_key: str | None = None,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: float | None = None,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.api_key = api_key
        self.port = port
        self.verify_ssl = verify_ssl
        self.timeout = timeout or DEFAULT_READ_TIMEOUT

        scheme = "https" if port == 443 or port == 8443 else "http"
        self.base_url = f"{scheme}://{host}:{port}"

        self._client: httpx.AsyncClient | None = None
        self._breaker = CircuitBreaker(
            failure_threshold=BREAKER_FAILURE_THRESHOLD,
            reset_timeout=BREAKER_RESET_TIMEOUT_SEC,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the underlying ``httpx.AsyncClient`` and probe auth.

        We open the connection AND make a single low-cost authenticated
        call so connection failures surface immediately at startup
        instead of being deferred to the first list_pools().
        """
        self._client = build_async_client(
            base_url=self.base_url,
            verify=self.verify_ssl,
            timeout=httpx.Timeout(self.timeout, connect=DEFAULT_CONNECT_TIMEOUT),
            follow_redirects=True,
            headers=self._auth_headers(),
            # TrueNAS Basic auth still respects ``auth=`` even when
            # Bearer is used; we pass auth explicitly only when no key.
            auth=None if self.api_key else (self.username, self.password),
        )
        try:
            await self._probe_auth()
        except Exception:
            await self.disconnect()
            raise

    async def disconnect(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            with contextlib.suppress(Exception):
                await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> TrueNASClient:
        await self.connect()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.disconnect()

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        if self.api_key:
            return {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
        return {"Content-Type": "application/json"}

    async def _probe_auth(self) -> None:
        """Cheap auth probe — GET /system/state.

        Raises ``AdapterAuthenticationError`` on 401/403 so callers
        can surface "wrong API key" without conflating it with
        "controller offline".
        """
        try:
            resp = await self._raw_get(EP_AUTH_CHECK)
        except httpx.ConnectError as exc:
            raise AdapterConnectionError(
                f"Cannot reach TrueNAS at {self.host}: {exc}",
            ) from exc
        except httpx.TimeoutException as exc:
            raise AdapterTimeoutError(
                f"TrueNAS at {self.host} timed out during auth probe",
            ) from exc

        if resp.status_code in (401, 403):
            raise AdapterAuthenticationError(
                f"TrueNAS rejected credentials at {self.host} (HTTP {resp.status_code})",
            )
        if resp.status_code >= 500:
            raise AdapterConnectionError(
                f"TrueNAS at {self.host} returned HTTP {resp.status_code} during auth probe",
            )

    # ------------------------------------------------------------------
    # Low-level request
    # ------------------------------------------------------------------

    async def _raw_get(self, path: str, **params: Any) -> httpx.Response:
        """Issue a GET with the breaker recording success/failure.

        Response body is read into memory but bounded — TrueNAS
        listings on populated appliances can exceed 5 MB; we cap at
        50 MB so a runaway endpoint can't pin a worker.
        """
        if self._client is None:
            raise AdapterConnectionError("TrueNAS client is not connected")

        # Match the openwrt/proxmox pattern: check breaker state, do
        # the call, then record success or failure. CircuitBreaker
        # exposes ``allow_request`` / ``record_success`` /
        # ``record_failure`` — no async ``.call()`` wrapper.
        if not self._breaker.allow_request():
            raise AdapterConnectionError(
                f"TrueNAS at {self.host}: circuit breaker open — refusing call",
            )

        try:
            resp = await self._client.get(path, params=params or None)
        except httpx.TimeoutException as exc:
            self._breaker.record_failure()
            raise AdapterTimeoutError(
                f"TrueNAS GET {path} timed out",
            ) from exc
        except httpx.HTTPError as exc:
            self._breaker.record_failure()
            raise AdapterConnectionError(
                f"TrueNAS GET {path} failed: {exc}",
            ) from exc

        from app.adapters._response_limits import check_response_size

        check_response_size(resp)  # bound device body before read

        # 5xx counts as a transport failure for breaker purposes — a
        # backend that's returning 500 on every read is just as broken
        # as one that's dropping connections.
        if resp.status_code >= 500:
            self._breaker.record_failure()
        else:
            self._breaker.record_success()
        return resp

    async def _get_json(self, path: str, **params: Any) -> Any:
        """GET + translate HTTP errors + parse JSON, size-capped."""
        resp = await self._raw_get(path, **params)

        if resp.status_code in (401, 403):
            raise AdapterAuthenticationError(
                f"TrueNAS denied access to {path} (HTTP {resp.status_code})",
            )
        if resp.status_code == 404:
            raise AdapterNotFoundError(f"TrueNAS {path} not found")
        if resp.status_code >= 500:
            raise TrueNASAPIError(
                f"TrueNAS {path} server error",
                status_code=resp.status_code,
                body=resp.text[:512],
            )
        if not (200 <= resp.status_code < 300):
            raise TrueNASAPIError(
                f"TrueNAS {path} returned HTTP {resp.status_code}",
                status_code=resp.status_code,
                body=resp.text[:512],
            )

        # Body size cap — read content then check, since httpx has
        # already pulled the bytes. The protection is against a buggy
        # caller passing the response to a slow JSON parser, not
        # against streaming overload (httpx caps that separately).
        raw = resp.content
        if len(raw) > MAX_RESPONSE_BYTES:
            raise TrueNASAPIError(
                f"TrueNAS {path} response exceeded size cap ({len(raw)} > {MAX_RESPONSE_BYTES})",
                status_code=resp.status_code,
            )

        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise TrueNASAPIError(
                f"TrueNAS {path} returned non-JSON: {exc}",
                status_code=resp.status_code,
                body=resp.text[:512],
            ) from exc

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    async def get_system_info(self) -> dict[str, Any]:
        """Return the raw ``GET /system/info`` payload."""
        data = await self._get_json(EP_SYSTEM_INFO)
        if not isinstance(data, dict):
            raise TrueNASAPIError(
                "TrueNAS /system/info returned non-object",
            )
        return data

    async def list_pools(self) -> list[dict[str, Any]]:
        """Return the raw ``GET /pool`` payload (list of pools)."""
        data = await self._get_json(EP_POOL)
        if not isinstance(data, list):
            raise TrueNASAPIError("TrueNAS /pool returned non-list")
        return data

    async def list_datasets(self) -> list[dict[str, Any]]:
        """Return the raw ``GET /pool/dataset`` payload."""
        data = await self._get_json(EP_DATASET)
        if not isinstance(data, list):
            raise TrueNASAPIError("TrueNAS /pool/dataset returned non-list")
        return data

    async def list_snapshots(self) -> list[dict[str, Any]]:
        """Return the raw ``GET /zfs/snapshot`` payload."""
        data = await self._get_json(EP_SNAPSHOT)
        if not isinstance(data, list):
            raise TrueNASAPIError("TrueNAS /zfs/snapshot returned non-list")
        return data

    async def list_disks(self) -> list[dict[str, Any]]:
        """Return the raw ``GET /disk`` payload."""
        data = await self._get_json(EP_DISK)
        if not isinstance(data, list):
            raise TrueNASAPIError("TrueNAS /disk returned non-list")
        return data

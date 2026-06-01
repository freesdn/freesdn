# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Omada API client.

Supports both **local** controllers (internal API w/ session auth) and
**cloud** controllers (OpenAPI w/ OAuth2 client_credentials).
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from app.adapters.apply_context import in_apply_window
from app.adapters.circuit_breaker import CircuitBreaker, CircuitOpenError
from app.adapters.omada.constants import (
    CACHE_TTL_CLIENTS,
    CACHE_TTL_CONFIG,
    CACHE_TTL_DEVICES,
    CACHE_TTL_PORTS,
    CACHE_TTL_SITES,
    CLOUD_ACCESS_TOKEN_LIFETIME,
    CLOUD_DEFAULT_RPM,
    CLOUD_REGION_URLS,
    CONNECTION_MODE_CLOUD,
    CONNECTION_MODE_LOCAL,
    DEFAULT_OMADA_PORT,
    LOCAL_PAGE_PARAM,
    LOCAL_PAGE_SIZE_PARAM,
    MIN_SUPPORTED_MAJOR,
    OMADA_ERROR_CSRF_INVALID,
    OMADA_ERROR_GENERIC,
    OMADA_ERROR_INVALID_PARAMS,
    OMADA_ERROR_NOT_FOUND,
    OMADA_ERROR_PERMISSION_DENIED,
    OMADA_ERROR_SESSION_EXPIRED,
    OMADA_SUCCESS,
    OPENAPI_PAGE_PARAM,
    OPENAPI_PAGE_SIZE_PARAM,
    PATH_API_PREFIX_TEMPLATE,
    PATH_CLOUD_TOKEN,
    PATH_INFO,
    PATH_LOGIN_TEMPLATE,
    PATH_LOGOUT_TEMPLATE,
    PATH_OPENAPI_PREFIX_TEMPLATE,
    RETRYABLE_HTTP_STATUS,
)
from app.adapters.omada.exceptions import (
    OmadaApiError,
    OmadaAuthError,
    OmadaAuthorizationError,
    OmadaConnectionError,
    OmadaNotFoundError,
    OmadaRateLimitError,
    OmadaSessionExpiredError,
    OmadaTimeoutError,
    OmadaUnsupportedVersionError,
    OmadaValidationError,
)
from app.adapters.omada.models import OmadaApiEnvelope, OmadaControllerInfo, OmadaPaginatedData
from app.adapters.omada.utils import (
    SimpleCache,
    TokenBucketRateLimiter,
    is_version_below_fully_supported,
    parse_version,
)
from app.core.http_client import build_async_client
from app.core.metrics import (
    adapter_errors_total,
    adapter_request_duration,
    adapter_requests_total,
)

logger_auth = logging.getLogger("adapter.omada.auth")
logger_http = logging.getLogger("adapter.omada.http")
logger_cache = logging.getLogger("adapter.omada.cache")
logger_rate_limit = logging.getLogger("adapter.omada.rate_limit")

# Mutating HTTP verbs. Omada was historically the ONE vendor whose client layer
# never gated writes on read-only mode (every other adapter — mikrotik/proxmox/
# opnsense/pfsense/unifi — refuses writes unless explicitly opted in)..
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _is_adapter_read_only() -> bool:
    """True (default-safe) unless read-only mode is explicitly disabled.

    Mirrors ``AdapterStagingService.is_read_only()`` EXACTLY so the client gate
    and the staging gate can never disagree: a single platform-wide
    ``ADAPTER_READ_ONLY`` flag governs every adapter (the legacy per-vendor
    ``OMADA_READ_ONLY`` is no longer OR'd in — one clear read-only ↔ read-write
    state). Code default is fail-safe True; shipped deployment default is
    read-write.
    """
    from app.core.runtime_flags import is_adapter_read_only

    return is_adapter_read_only()


def _record_metric(method: str, outcome: str) -> None:
    """Emit Prometheus counters for an Omada request. Never raises."""
    try:
        adapter_requests_total.labels(adapter="omada", method=method, outcome=outcome).inc()
    except Exception:
        pass


def _omada_mac(mac: str) -> str:
    """Convert any MAC format to Omada's dash-separated uppercase format for URL paths.

    Omada API requires ``AA-BB-CC-DD-EE-FF`` in URL path segments.
    ``normalize_mac()`` outputs ``AA:BB:CC:DD:EE:FF`` (colons), which Omada
    rejects with "Unsupported request path".
    """
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(clean) != 12:
        return mac.upper().replace(":", "-").replace(".", "-")
    return "-".join(clean[i : i + 2] for i in range(0, 12, 2)).upper()


@dataclass
class OmadaClientConfig:
    """Configuration for Omada API client.

    **Local mode** (default):
        host + username + password → internal API via session auth.

    **Cloud mode** (mode="cloud"):
        client_id + client_secret + omada_id + cloud_region
        → OpenAPI via OAuth2 client_credentials.
    """

    # --- Connection mode ---
    mode: str = CONNECTION_MODE_LOCAL  # "local" | "cloud"

    # --- Local mode fields ---
    host: str = ""
    username: str = ""
    password: str = ""
    port: int = DEFAULT_OMADA_PORT

    # --- Cloud mode fields ---
    client_id: str = ""
    client_secret: str = ""
    omada_id: str = ""  # controller / org ID (required for cloud, auto-discovered local)
    cloud_region: str = ""  # "use1" | "euw1" | "aps1" (or alias "us" | "eu" | "asia")

    # --- Common fields ---
    use_ssl: bool = True
    verify_ssl: bool = False
    timeout: float = 30.0
    connect_timeout: float = 10.0
    max_retries: int = 3
    retry_backoff: float = 1.0
    rate_limit_rpm: int = 60
    rate_limit_concurrent: int = 5
    cache_ttl_devices: int = CACHE_TTL_DEVICES
    cache_ttl_ports: int = CACHE_TTL_PORTS
    cache_ttl_clients: int = CACHE_TTL_CLIENTS
    cache_ttl_config: int = CACHE_TTL_CONFIG
    # Circuit breaker: trip after this many consecutive failures and
    # fail-fast for ``circuit_cooldown_seconds`` before allowing a
    # probe. 5 + 30s is conservative — avoids hammering a recovering
    # controller while not over-tripping on transient blips (the
    # existing retry layer already absorbs those).
    circuit_failure_threshold: int = 5
    circuit_cooldown_seconds: float = 30.0

    @property
    def is_cloud(self) -> bool:
        return self.mode == CONNECTION_MODE_CLOUD

    def validate(self) -> None:
        """Raise ValueError if required fields are missing."""
        if self.is_cloud:
            missing = [
                f
                for f in ("client_id", "client_secret", "omada_id", "cloud_region")
                if not getattr(self, f)
            ]
            if missing:
                raise ValueError(f"Cloud mode requires: {', '.join(missing)}")
            if self.cloud_region not in CLOUD_REGION_URLS:
                raise ValueError(
                    f"Unknown cloud region '{self.cloud_region}'. "
                    f"Valid: {', '.join(sorted(CLOUD_REGION_URLS))}"
                )
        else:
            if not self.host:
                raise ValueError("Local mode requires 'host'")
            if not self.username or not self.password:
                raise ValueError("Local mode requires 'username' and 'password'")

    @property
    def effective_base_url(self) -> str:
        """Compute the base URL from mode + config fields."""
        if self.is_cloud:
            return CLOUD_REGION_URLS[self.cloud_region]
        host = self.host.strip()
        if host.startswith("http"):
            return host
        scheme = "https" if self.use_ssl else "http"
        return f"{scheme}://{host}:{self.port}"


class OmadaApiClient:
    """
    Low-level async Omada API client.

    Supports two connection modes:

    * **local** — Session auth against ``/{controllerId}/api/v2/...``
    * **cloud** — OAuth2 client_credentials against ``/openapi/v1/{controllerId}/...``

    The public API endpoint wrappers (``get_devices``, ``get_switch_ports``, …)
    are mode-agnostic; only the auth and URL prefix layers differ.
    """

    def __init__(self, config: OmadaClientConfig):
        config.validate()
        self.config = config
        self.base_url = config.effective_base_url

        self._controller_id: str | None = config.omada_id or None
        self._controller_version: str | None = None
        self._csrf_token: str | None = None
        self._http: httpx.AsyncClient | None = None
        self._logged_in = False

        # --- Cloud OAuth2 state ---
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._token_expires_at: float = 0.0  # monotonic

        # Rate limiting — cloud has stricter limits
        rpm = config.rate_limit_rpm
        if config.is_cloud and rpm > CLOUD_DEFAULT_RPM:
            rpm = CLOUD_DEFAULT_RPM
        tokens_per_second = max(rpm / 60.0, 0.1)
        self._rate_limiter = TokenBucketRateLimiter(
            tokens_per_second=tokens_per_second,
            bucket_size=max(config.rate_limit_concurrent * 2, 1),
        )
        self._semaphore = asyncio.Semaphore(max(config.rate_limit_concurrent, 1))
        self._cache = SimpleCache(max_entries=2048)
        self._session_lock = asyncio.Lock()

        # Per-controller circuit breaker. After
        # ``circuit_failure_threshold`` consecutive _request failures,
        # the breaker trips open and rejects calls for
        # ``circuit_cooldown_seconds``. Then a single probe call
        # ("half-open") decides whether to restore or stay open.
        self._breaker = CircuitBreaker(
            name="omada",
            host=self.base_url,
            failure_threshold=config.circuit_failure_threshold,
            cooldown_seconds=config.circuit_cooldown_seconds,
        )

        self._request_count = 0
        self._error_count = 0
        self._retry_count = 0
        self._total_latency_ms = 0.0
        self._last_successful_request: datetime | None = None

    # ------------------------------------------------------------------
    # Lifecycle / auth
    # ------------------------------------------------------------------

    async def __aenter__(self) -> OmadaApiClient:
        await self.login()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.logout()

    async def login(self) -> dict[str, Any]:
        """Authenticate and initialize session state.

        * **local mode**: ``GET /api/info`` → ``POST /{id}/api/v2/login``
        * **cloud mode**: ``POST /openapi/authorize/token`` (client_credentials)
        """
        async with self._session_lock:
            if self._logged_in and self._http and not self._http.is_closed:
                return {
                    "controller_id": self._controller_id,
                    "version": self._controller_version,
                    "mode": self.config.mode,
                }

            if self._http and not self._http.is_closed:
                await self._http.aclose()

            timeout = httpx.Timeout(
                timeout=self.config.timeout,
                connect=self.config.connect_timeout,
            )
            self._http = build_async_client(
                base_url=self.base_url,
                verify=self.config.verify_ssl,
                timeout=timeout,
                follow_redirects=True,
            )

            try:
                if self.config.is_cloud:
                    return await self._login_cloud()
                return await self._login_local()
            except Exception:
                # Close the httpx client if login fails to avoid resource leak
                if self._http and not self._http.is_closed:
                    await self._http.aclose()
                self._http = None
                raise

    # ---- Local auth flow ------------------------------------------------

    async def _login_local(self) -> dict[str, Any]:
        """Local controller: /api/info → session login w/ CSRF token."""
        assert self._http is not None

        try:
            info_response = await self._http.get(PATH_INFO)
            info_response.raise_for_status()
        except httpx.TimeoutException as exc:
            logger_auth.error("controller info request timed out: %s → %s", self.base_url, exc)
            raise OmadaTimeoutError(
                f"Controller timed out at {self.base_url} — check host/port and network connectivity",
                adapter_id="omada",
            ) from exc
        except httpx.ConnectError as exc:
            err_str = str(exc).lower()
            if "ssl" in err_str or "certificate" in err_str or "tls" in err_str:
                logger_auth.error("SSL/TLS error connecting to %s: %s", self.base_url, exc)
                raise OmadaConnectionError(
                    f"SSL certificate verification failed for {self.base_url} — "
                    "try setting verify_ssl to false (Omada controllers typically use self-signed certs)",
                    adapter_id="omada",
                ) from exc
            logger_auth.error("connection refused/unreachable %s: %s", self.base_url, exc)
            raise OmadaConnectionError(
                f"Cannot connect to {self.base_url}{PATH_INFO} — "
                "verify host, port, and use_ssl settings. "
                "If running in Docker, ensure the controller IP is reachable from the container.",
                adapter_id="omada",
            ) from exc
        except httpx.HTTPError as exc:
            logger_auth.error("controller info request failed: %s → %s", self.base_url, exc)
            raise OmadaConnectionError(
                f"Failed to reach Omada controller at {self.base_url}: {exc}",
                adapter_id="omada",
            ) from exc

        info_payload = info_response.json()
        info_result = OmadaControllerInfo.model_validate(info_payload.get("result", {}))

        controller_id = info_result.omadacId
        controller_version = info_result.controllerVer or "0.0.0"
        if not controller_id:
            raise OmadaConnectionError("Controller ID missing in /api/info response")

        major, minor, _ = parse_version(controller_version)
        if major < MIN_SUPPORTED_MAJOR:
            raise OmadaUnsupportedVersionError(
                f"Unsupported Omada version {controller_version}",
                error_code=None,
            )
        # The "fully supported" floor is a property of the 5.x line (5.9+).
        # Newer majors (6.x) reset the minor, so a bare ``minor < 9`` check
        # spuriously flagged v6.2 as unsupported even though it is NEWER than
        # 5.14. Only warn for the old 5.x line below the floor.
        if is_version_below_fully_supported(major, minor):
            logger_auth.warning(
                "adapter.omada.unsupported_version",
                extra={"version": controller_version},
            )

        login_path = PATH_LOGIN_TEMPLATE.format(controller_id=controller_id)
        login_payload = {
            "username": self.config.username,
            "password": self.config.password,
        }

        try:
            login_response = await self._http.post(login_path, json=login_payload)
            login_response.raise_for_status()
        except httpx.TimeoutException as exc:
            logger_auth.error("login timed out")
            raise OmadaTimeoutError("Login request timed out", adapter_id="omada") from exc
        except httpx.HTTPError as exc:
            logger_auth.error("login request failed: %s", exc)
            raise OmadaAuthError("Login request failed", adapter_id="omada") from exc

        envelope = OmadaApiEnvelope.model_validate(login_response.json())
        if envelope.errorCode != OMADA_SUCCESS:
            raise OmadaAuthError(
                f"Login failed: {envelope.msg or envelope.errorCode}",
                adapter_id="omada",
            )

        result = envelope.result or {}
        self._controller_id = controller_id
        self._controller_version = controller_version
        self._csrf_token = result.get("token")
        self._logged_in = True

        logger_auth.info(
            "login successful (local)",
            extra={"controller_id": controller_id, "version": controller_version},
        )
        return {
            "controller_id": controller_id,
            "version": controller_version,
            "role": result.get("roleType"),
            "mode": CONNECTION_MODE_LOCAL,
        }

    # ---- Cloud OAuth2 flow -----------------------------------------------

    async def _login_cloud(self) -> dict[str, Any]:
        """Cloud controller: OAuth2 client_credentials → access token."""
        assert self._http is not None

        token_payload = {
            "omadacId": self.config.omada_id,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        try:
            token_response = await self._http.post(
                PATH_CLOUD_TOKEN,
                params={"grant_type": "client_credentials"},
                json=token_payload,
            )
            token_response.raise_for_status()
        except httpx.TimeoutException as exc:
            logger_auth.error("cloud token request timed out")
            raise OmadaTimeoutError("Cloud token request timed out", adapter_id="omada") from exc
        except httpx.HTTPError as exc:
            detail = "Cloud OAuth2 token request failed"
            if hasattr(exc, "response") and exc.response is not None:
                try:
                    err_body = exc.response.json()
                    msg = err_body.get("msg", "")
                    code = err_body.get("errorCode", "")
                    if msg:
                        detail = f"Cloud auth failed (code {code}): {msg}"
                    else:
                        detail = (
                            f"Cloud OAuth2 token request failed (HTTP {exc.response.status_code})"
                        )
                except Exception:
                    detail = f"Cloud OAuth2 token request failed (HTTP {exc.response.status_code})"
            logger_auth.error("cloud token request failed: %s — %s", exc, detail)
            raise OmadaAuthError(detail, adapter_id="omada") from exc

        body = token_response.json()
        error_code = body.get("errorCode", 0)
        if error_code != 0:
            raise OmadaAuthError(
                f"Cloud auth failed: {body.get('msg', error_code)}",
                adapter_id="omada",
            )

        result = body.get("result", body)
        access_token = result.get("accessToken")
        refresh_token = result.get("refreshToken")
        expires_in = result.get("expiresIn", CLOUD_ACCESS_TOKEN_LIFETIME)

        if not access_token:
            raise OmadaAuthError("No accessToken in cloud token response", adapter_id="omada")

        self._access_token = access_token
        self._refresh_token = refresh_token
        self._token_expires_at = time.monotonic() + max(expires_in - 300, 60)  # refresh 5 min early
        self._controller_id = self.config.omada_id
        self._logged_in = True

        logger_auth.info(
            "login successful (cloud)",
            extra={"controller_id": self._controller_id, "expires_in": expires_in},
        )
        return {
            "controller_id": self._controller_id,
            "mode": CONNECTION_MODE_CLOUD,
            "expires_in": expires_in,
        }

    async def _refresh_cloud_token(self) -> None:
        """Refresh an expired OAuth2 access token using the refresh token."""
        if not self._refresh_token or not self._http:
            # No refresh token available — full re-auth
            self._logged_in = False
            await self.login()
            return

        try:
            resp = await self._http.post(
                PATH_CLOUD_TOKEN,
                params={"grant_type": "refresh_token"},
                json={
                    "refreshToken": self._refresh_token,
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                },
            )
            resp.raise_for_status()
            body = resp.json()
            result = body.get("result", body)
            new_access = result.get("accessToken")
            new_refresh = result.get("refreshToken")
            expires_in = result.get("expiresIn", CLOUD_ACCESS_TOKEN_LIFETIME)

            if not new_access:
                raise OmadaAuthError("Refresh returned no accessToken")

            self._access_token = new_access
            if new_refresh:
                self._refresh_token = new_refresh
            self._token_expires_at = time.monotonic() + max(expires_in - 300, 60)

            logger_auth.info("cloud token refreshed", extra={"expires_in": expires_in})
        except Exception as exc:
            logger_auth.warning("cloud token refresh failed, re-authenticating: %s", exc)
            self._logged_in = False
            await self.login()

    async def logout(self) -> None:
        """Logout and close HTTP session."""
        if not self._http:
            self._logged_in = False
            return

        try:
            if not self.config.is_cloud and self._logged_in and self._controller_id:
                path = PATH_LOGOUT_TEMPLATE.format(controller_id=self._controller_id)
                headers: dict[str, str] = {}
                if self._csrf_token:
                    headers["Csrf-Token"] = self._csrf_token
                await self._http.post(path, headers=headers)
            # Cloud mode: no explicit logout needed — tokens expire
        except Exception as exc:
            logger_auth.debug("Logout failed (non-critical): %s", exc)
        finally:
            await self._http.aclose()
            self._http = None
            self._logged_in = False
            self._csrf_token = None
            self._access_token = None
            self._refresh_token = None

    async def _ensure_session(self) -> None:
        if not self._logged_in or not self._http or self._http.is_closed:
            await self.login()
        # Cloud mode: proactively refresh if token is about to expire
        elif self.config.is_cloud and time.monotonic() >= self._token_expires_at:
            await self._refresh_cloud_token()

    # ------------------------------------------------------------------
    # Core request pipeline
    # ------------------------------------------------------------------

    def _api_path(self, path: str) -> str:
        """Build the full API path based on connection mode.

        * **local**: ``/{controllerId}/api/v2{path}``
        * **cloud**: ``/openapi/v1/{controllerId}{path}``
        """
        if path.startswith("/maintenance/"):
            return path
        if not self._controller_id:
            raise OmadaConnectionError("Controller ID missing; login required")
        if self.config.is_cloud:
            prefix = PATH_OPENAPI_PREFIX_TEMPLATE.format(controller_id=self._controller_id)
        else:
            prefix = PATH_API_PREFIX_TEMPLATE.format(controller_id=self._controller_id)
        return f"{prefix}{path}"

    def _cache_key(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None,
        payload: dict[str, Any] | None,
    ) -> str:
        return json.dumps(
            {
                "m": method.upper(),
                "p": path,
                "q": params or {},
                "b": payload or {},
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | list[Any] | None = None,
        cache_ttl: int | None = None,
        retry: bool = True,
    ) -> dict[str, Any]:
        """
        Execute an authenticated Omada API request.

        Returns the `result` payload from Omada envelope.
        """
        # Universal read-only write gate. Omada's client never
        # gated writes, so any direct endpoint (controller batch reboot/firmware,
        # AP radio/SSID/LAN/reboot/adopt/forget/firmware, switch port/PoE/VLAN/ACL)
        # mutated the LIVE controller even under read-only mode, bypassing the
        # staged-write safety boundary. Refuse mutating verbs while read-only is
        # engaged UNLESS we are inside an approved staged-apply window opened by
        # AdapterStagingService.apply_change (which already enforced ADAPTER_READ_ONLY
        # + force). No-op when read-only is off (live-write deployments unaffected).
        if method.upper() in _WRITE_METHODS and _is_adapter_read_only() and not in_apply_window():
            _record_metric(method.upper(), "read_only_blocked")
            raise OmadaApiError(
                "ADAPTER_READ_ONLY (or OMADA_READ_ONLY) is set — Omada write "
                "refused outside an approved staged apply. Route the change "
                "through AdapterStagingService (stage → apply), or set both "
                "ADAPTER_READ_ONLY=false and OMADA_READ_ONLY=false to permit "
                "direct live writes.",
                adapter_id="omada",
            )

        # Circuit breaker: fail-fast if we've seen N consecutive
        # failures recently. The retry layer below absorbs transient
        # blips; this protects against a hard-down controller. A
        # downed controller would otherwise eat the timeout budget on
        # every queued request and starve the worker pool.
        try:
            self._breaker.before_call()
        except CircuitOpenError as exc:
            _record_metric(method.upper(), "circuit_open")
            raise OmadaConnectionError(
                f"controller circuit breaker is open ({exc})",
                adapter_id="omada",
            ) from exc

        await self._ensure_session()
        if not self._http:
            raise OmadaConnectionError("HTTP client is not initialized")

        method_upper = method.upper()
        # Path-traversal guard (chokepoint for ALL endpoint wrappers). Path
        # segments are built from caller-supplied values (MAC, site_id,
        # ssid_id, network_id, …) that can originate from untrusted API path
        # params — e.g. /gateway-firmware/.../devices/{device_mac}. The MAC
        # normalize regex below only matches *valid* colon-MACs and would pass
        # a hostile value like "AA../BB:CC:DD:EE:FF" or a percent-encoded
        # "%2e%2e%2f" through to the controller URL, where path normalization
        # could escape the intended resource. No legitimate Omada path
        # parameter contains "..", a backslash, or percent-encoding, so reject
        # them outright instead of trying to encode-and-forward.
        if ".." in path or "\\" in path or re.search(r"%(?:2[eEfF]|5[cC])", path):
            _record_metric(method_upper, "invalid_path")
            raise OmadaValidationError(
                "Refusing Omada request with unsafe path segment (possible path traversal)",
            )
        # Omada API requires dash-separated MACs in URL paths.
        # normalize_mac() uses colons — convert any colon-MAC segments to dashes.
        path = re.sub(
            r"(?<=/)[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}(?=/|$)",
            lambda m: m.group().replace(":", "-"),
            path,
        )
        api_path = self._api_path(path)

        cache_key: str | None = None
        if method_upper == "GET" and cache_ttl and cache_ttl > 0:
            cache_key = self._cache_key(method_upper, api_path, params, None)
            cached = self._cache.get(cache_key)
            if cached is not None:
                logger_cache.debug("cache hit", extra={"path": path})
                return cached
            logger_cache.debug("cache miss", extra={"path": path})

        reauth_attempted = False
        max_attempts = self.config.max_retries if retry else 1

        for attempt in range(1, max_attempts + 1):
            allowed = await self._rate_limiter.acquire(timeout=self.config.timeout)
            if not allowed:
                self._error_count += 1
                logger_rate_limit.warning("rate limit wait timed out")
                raise OmadaRateLimitError(
                    "Local rate limit timeout",
                    adapter_id="omada",
                )

            async with self._semaphore:
                headers: dict[str, str] = {}
                if self.config.is_cloud:
                    # Cloud: OAuth2 bearer-style access token
                    if self._access_token:
                        headers["Authorization"] = f"AccessToken={self._access_token}"
                else:
                    # Local: CSRF session token
                    if self._csrf_token and not path.startswith("/maintenance/"):
                        headers["Csrf-Token"] = self._csrf_token

                start = time.monotonic()
                try:
                    response = await self._http.request(
                        method_upper,
                        api_path,
                        params=params,
                        json=json_data,
                        headers=headers,
                    )
                except httpx.TimeoutException as exc:
                    self._error_count += 1
                    if retry and attempt < max_attempts:
                        await self._retry_sleep(attempt, "timeout", path)
                        continue
                    self._breaker.on_failure()
                    _record_metric(method_upper, "timeout")
                    try:
                        adapter_errors_total.labels(adapter="omada", error_type="timeout").inc()
                    except Exception:
                        pass
                    raise OmadaTimeoutError("Request timed out", adapter_id="omada") from exc
                except httpx.HTTPError as exc:
                    self._error_count += 1
                    if retry and attempt < max_attempts:
                        await self._retry_sleep(attempt, "connection_error", path)
                        continue
                    self._breaker.on_failure()
                    _record_metric(method_upper, "connection_error")
                    try:
                        adapter_errors_total.labels(adapter="omada", error_type="connection").inc()
                    except Exception:
                        pass
                    raise OmadaConnectionError("Request failed", adapter_id="omada") from exc
                finally:
                    latency_ms = (time.monotonic() - start) * 1000
                    self._request_count += 1
                    self._total_latency_ms += latency_ms
                    if latency_ms > 5000:
                        logger_http.warning(
                            "slow request",
                            extra={"path": path, "latency_ms": round(latency_ms, 2)},
                        )

            # reject an over-large device body before .json()
            # materializes it (httpx has no default size cap). No-op for any
            # legitimate response (Content-Length absent or well under 64 MB).
            from app.adapters._response_limits import check_response_size

            check_response_size(response)
            if response.status_code in RETRYABLE_HTTP_STATUS:
                self._error_count += 1
                if retry and attempt < max_attempts:
                    await self._retry_sleep(attempt, f"http_{response.status_code}", path)
                    continue
                self._breaker.on_failure()
                _record_metric(method_upper, f"http_{response.status_code}")
                try:
                    adapter_errors_total.labels(
                        adapter="omada", error_type=f"http_{response.status_code}"
                    ).inc()
                except Exception:
                    pass
                raise OmadaConnectionError(
                    f"Controller unavailable (HTTP {response.status_code})",
                    adapter_id="omada",
                )

            if response.status_code in {401, 403} and not reauth_attempted:
                reauth_attempted = True
                logger_auth.info("session refresh requested by HTTP status")
                if self.config.is_cloud:
                    await self._refresh_cloud_token()
                else:
                    self._logged_in = False
                    await self.login()
                continue

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                self._error_count += 1
                # 4xx/5xx that wasn't already retried. Treat 5xx as
                # breaker failures; 4xx as application errors that
                # don't reflect controller health.
                if response.status_code >= 500:
                    self._breaker.on_failure()
                _record_metric(method_upper, f"http_{response.status_code}")
                try:
                    adapter_errors_total.labels(
                        adapter="omada", error_type=f"http_{response.status_code}"
                    ).inc()
                except Exception:
                    pass
                raise OmadaApiError(
                    f"HTTP error {response.status_code}",
                    error_code=response.status_code,
                ) from exc

            payload = response.json()
            envelope = OmadaApiEnvelope.model_validate(payload)
            code = envelope.errorCode

            if code == OMADA_SUCCESS:
                result: dict[str, Any]
                if isinstance(envelope.result, dict):
                    result = envelope.result
                elif envelope.result is None:
                    # Some firmware places data in top-level "data" instead of "result"
                    result = {"data": payload["data"]} if "data" in payload else {}
                else:
                    result = {"data": envelope.result}
                if cache_key:
                    self._cache.set(cache_key, result, cache_ttl or 0)
                self._last_successful_request = datetime.now(UTC)
                logger_http.debug("request complete", extra={"path": path, "attempt": attempt})
                # Metrics + breaker: success path.
                self._breaker.on_success()
                _record_metric(method_upper, "success")
                try:
                    adapter_request_duration.labels(adapter="omada", method=method_upper).observe(
                        latency_ms / 1000.0
                    )
                except Exception:
                    pass
                return result

            self._error_count += 1
            logger_http.warning(
                "non-zero errorCode",
                extra={
                    "path": path,
                    "errorCode": code,
                    "omada_msg": envelope.msg,
                    "attempt": attempt,
                },
            )
            if code in {OMADA_ERROR_SESSION_EXPIRED, OMADA_ERROR_CSRF_INVALID}:
                if reauth_attempted:
                    # Endpoint may be incompatible rather than session truly expired
                    logger_auth.warning(
                        "persistent session error after re-auth",
                        extra={"path": path, "errorCode": code},
                    )
                    raise OmadaApiError(
                        f"Endpoint returned session error after re-auth: {envelope.msg or code}",
                        error_code=code,
                    )
                reauth_attempted = True
                logger_auth.info("session refresh requested by Omada error code")
                if self.config.is_cloud:
                    await self._refresh_cloud_token()
                else:
                    self._logged_in = False
                    await self.login()
                continue
            if code == OMADA_ERROR_PERMISSION_DENIED:
                raise OmadaAuthorizationError("Insufficient permissions", error_code=code)
            if code == OMADA_ERROR_INVALID_PARAMS:
                raise OmadaValidationError(f"Invalid parameters: {envelope.msg}")
            if code == OMADA_ERROR_NOT_FOUND:
                raise OmadaNotFoundError("Resource not found", adapter_id="omada")
            if code == OMADA_ERROR_GENERIC and retry and attempt < max_attempts:
                # Some firmware versions return -1 (generic) instead of
                # -1001 (session expired).  Attempt a session refresh on the
                # first generic error before falling back to plain retries.
                if not reauth_attempted:
                    reauth_attempted = True
                    logger_auth.info(
                        "session refresh requested by generic error code",
                        extra={"path": path},
                    )
                    if self.config.is_cloud:
                        await self._refresh_cloud_token()
                    else:
                        self._logged_in = False
                        await self.login()
                    continue
                await self._retry_sleep(attempt, "omada_generic", path)
                continue
            raise OmadaApiError(envelope.msg or f"Omada error {code}", error_code=code)

        raise OmadaApiError("Request exhausted retries")

    async def _request_with_fallback(
        self,
        method: str,
        paths: list[str],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Try multiple endpoint paths for controller-version compatibility.

        Falls back on ``OmadaNotFoundError``, ``OmadaSessionExpiredError``,
        and ``OmadaApiError`` (endpoint-level errors, not auth errors).
        """
        if not paths:
            raise OmadaApiError("No endpoint paths provided")

        last_error: Exception | None = None
        for index, path in enumerate(paths):
            try:
                return await self._request(method, path, **kwargs)
            except (OmadaNotFoundError, OmadaSessionExpiredError, OmadaApiError) as exc:
                last_error = exc
                if index < len(paths) - 1:
                    logger_http.debug(
                        "endpoint fallback",
                        extra={"from": path, "to": paths[index + 1]},
                    )
                    continue
                raise

        if last_error:
            raise last_error
        raise OmadaApiError("Endpoint fallback exhausted")

    async def _retry_sleep(self, attempt: int, reason: str, path: str) -> None:
        self._retry_count += 1
        # Decorrelated jitter (uniform 0.8–1.2× the backoff) avoids
        # the thundering-herd effect when multiple FreeSDN workers
        # all retry against the same controller after a transient
        # failure.
        base = self.config.retry_backoff * (2 ** (attempt - 1))
        wait_time = base * random.uniform(0.8, 1.2)
        logger_http.warning(
            "retry request",
            extra={"path": path, "attempt": attempt, "wait": wait_time, "reason": reason},
        )
        await asyncio.sleep(wait_time)

    async def _paginated_request(
        self,
        method: str,
        path: str,
        *,
        page_size: int = 100,
        max_pages: int = 20,
        max_total_rows: int = 5000,
        cache_ttl: int | None = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Fetch all pages from Omada paginated endpoint.

        Defaults are bounded so a runaway controller (or a hostile
        cloud response) can't push us into an unbounded accumulate-
        in-memory loop. Callers that need more can pass explicit
        ``max_pages`` / ``max_total_rows`` overrides.

        Auto-detects pagination param names based on connection mode:
        - local:  ``currentPage`` / ``currentPageSize``
        - cloud:  ``page`` / ``pageSize``
        """
        rows: list[dict[str, Any]] = []
        current_page = 1
        # Pagination param names differ between internal API and OpenAPI
        if self.config.is_cloud:
            page_key, size_key = OPENAPI_PAGE_PARAM, OPENAPI_PAGE_SIZE_PARAM
        else:
            page_key, size_key = LOCAL_PAGE_PARAM, LOCAL_PAGE_SIZE_PARAM

        while current_page <= max_pages:
            params = dict(kwargs.pop("params", {}) or {})
            params[page_key] = current_page
            params[size_key] = page_size
            result = await self._request(
                method,
                path,
                params=params,
                cache_ttl=cache_ttl,
                **kwargs,
            )
            page_data = OmadaPaginatedData.model_validate(result)
            rows.extend(page_data.data)
            if len(rows) >= page_data.totalRows:
                break
            if not page_data.data:
                break
            if len(rows) >= max_total_rows:
                logger_http.warning(
                    "_paginated_request hit max_total_rows guard "
                    "(path=%s rows=%d limit=%d) — truncating",
                    path,
                    len(rows),
                    max_total_rows,
                )
                break
            current_page += 1
        return rows

    # Default invalidation patterns for the generic ``_invalidate_on_write()``
    # call shape. We previously cleared the entire cache on every write,
    # which discarded long-lived metadata (sites, SSID lists, profile
    # catalogs) for changes that only affected one entity. The default
    # set below keeps the impact localised to data the controller
    # actually mutates frequently — devices, ports, switches, APs,
    # gateways, networks, clients — while preserving stable lookups.
    _DEFAULT_INVALIDATE_PATTERNS: tuple[str, ...] = (
        "*devices*",
        "*switches*",
        "*eaps*",
        "*gateways*",
        "*ports*",
        "*clients*",
        "*networks*",
        "*lags*",
        "*acl*",
        "*qos*",
        "*stp*",
        "*igmp*",
        "*mirror*",
        "*dhcp*",
        "*lldp*",
        "*vlans*",
        "*firmware*",
    )

    def _invalidate_on_write(self, *patterns: str) -> None:
        """Invalidate cache entries matching ``patterns`` after a write.

        Without arguments, falls back to a curated list of patterns
        covering the entity types the API typically mutates. Pass
        explicit patterns (e.g. ``"*sites/{id}/networks*"``) to scope
        an invalidation tightly when the call-site knows which
        endpoints changed.
        """
        targets = patterns or self._DEFAULT_INVALIDATE_PATTERNS
        for pattern in targets:
            self._cache.invalidate(pattern)

    # ------------------------------------------------------------------
    # API endpoint wrappers
    # ------------------------------------------------------------------

    async def get_sites(self) -> list[dict[str, Any]]:
        return await self._paginated_request(
            "GET",
            "/sites",
            page_size=100,
            cache_ttl=CACHE_TTL_SITES,
        )

    async def get_site(self, site_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/sites/{site_id}", cache_ttl=CACHE_TTL_SITES)

    async def get_devices(self, site_id: str) -> list[dict[str, Any]]:
        return await self._paginated_request(
            "GET",
            f"/sites/{site_id}/devices",
            page_size=200,
            cache_ttl=self.config.cache_ttl_devices,
        )

    async def get_device(self, site_id: str, mac: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/devices/{mac}",
            cache_ttl=self.config.cache_ttl_devices,
        )

    async def adopt_device(self, site_id: str, mac: str) -> dict[str, Any]:
        result = await self._request("POST", f"/sites/{site_id}/cmd/devices/{mac}/adopt")
        self._invalidate_on_write()
        return result

    async def forget_device(self, site_id: str, mac: str) -> dict[str, Any]:
        result = await self._request("POST", f"/sites/{site_id}/cmd/devices/{mac}/forget")
        self._invalidate_on_write()
        return result

    async def reboot_device(self, site_id: str, mac: str, device_type: str) -> dict[str, Any]:
        if device_type == "ap":
            paths = [
                f"/sites/{site_id}/eaps/{mac}/reboot",
                f"/sites/{site_id}/devices/{mac}/reboot",
            ]
        elif device_type == "gateway":
            paths = [
                f"/sites/{site_id}/gateways/{mac}/reboot",
                f"/sites/{site_id}/devices/{mac}/reboot",
            ]
        else:
            paths = [
                f"/sites/{site_id}/switches/{mac}/reboot",
                f"/sites/{site_id}/devices/{mac}/reboot",
            ]
        result = await self._request_with_fallback("POST", paths)
        self._invalidate_on_write()
        return result

    async def get_switch_ports(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/switches/{mac}/ports",
            cache_ttl=self.config.cache_ttl_ports,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def update_switch_port(
        self,
        site_id: str,
        mac: str,
        port_id: int,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/switches/{mac}/ports/{port_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_port_statistics(self, site_id: str, mac: str, port_id: int) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/switches/{mac}/ports/{port_id}/stats",
            cache_ttl=self.config.cache_ttl_ports,
        )

    async def set_port_poe(
        self, site_id: str, mac: str, port_id: int, enabled: bool
    ) -> dict[str, Any]:
        return await self.update_switch_port(
            site_id=site_id,
            mac=mac,
            port_id=port_id,
            config={"poe": {"enable": enabled}},
        )

    async def cycle_port_poe(
        self,
        site_id: str,
        mac: str,
        port_id: int,
        delay: int = 5,
    ) -> dict[str, Any]:
        await self.set_port_poe(site_id, mac, port_id, False)
        await asyncio.sleep(delay)
        return await self.set_port_poe(site_id, mac, port_id, True)

    async def get_networks(self, site_id: str) -> list[dict[str, Any]]:
        paths = [
            f"/sites/{site_id}/setting/lan/networks",
            f"/sites/{site_id}/setting/lan",
        ]
        try:
            data = await self._request_with_fallback(
                "GET",
                paths,
                cache_ttl=self.config.cache_ttl_config,
            )
        except (OmadaSessionExpiredError, OmadaApiError):
            # Fallback: try as paginated endpoint (some firmware versions)
            try:
                return await self._paginated_request(
                    "GET",
                    f"/sites/{site_id}/setting/lan/networks",
                    page_size=100,
                    cache_ttl=self.config.cache_ttl_config,
                )
            except Exception:
                return []
        if isinstance(data, list):
            return data
        # Handle envelope variants: {"data": [...]}, {"networks": [...]}
        if "data" in data:
            return data["data"]
        if "networks" in data:
            return data["networks"]
        # Last resort: return first list value found
        for v in data.values():
            if isinstance(v, list):
                return v
        return []

    async def create_network(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/lan/networks",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_network(
        self, site_id: str, network_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/lan/networks/{network_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_network(self, site_id: str, network_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE", f"/sites/{site_id}/setting/lan/networks/{network_id}"
        )
        self._invalidate_on_write()
        return result

    async def get_wlan_groups(self, site_id: str) -> list[dict[str, Any]]:
        """Get WLAN groups (not individual SSIDs)."""
        rows = await self._paginated_request(
            "GET",
            f"/sites/{site_id}/setting/wlans",
            page_size=100,
            cache_ttl=self.config.cache_ttl_config,
        )
        return rows

    async def get_ssids(self, site_id: str) -> list[dict[str, Any]]:
        """Get ALL SSIDs across all WLAN groups."""
        groups = await self.get_wlan_groups(site_id)
        all_ssids: list[dict[str, Any]] = []
        for group in groups:
            group_id = group.get("id")
            if not group_id:
                continue
            try:
                ssids = await self._paginated_request(
                    "GET",
                    f"/sites/{site_id}/setting/wlans/{group_id}/ssids",
                    page_size=100,
                    cache_ttl=self.config.cache_ttl_config,
                )
                for s in ssids:
                    s["_wlanGroupId"] = group_id
                    s["_wlanGroupName"] = group.get("name", "")
                all_ssids.extend(ssids)
            except Exception:
                pass  # skip groups that don't support nested SSIDs
        return all_ssids

    async def create_ssid(
        self,
        site_id: str,
        config: dict[str, Any],
        wlan_id: str | None = None,
    ) -> dict[str, Any]:
        if not wlan_id:
            groups = await self.get_wlan_groups(site_id)
            wlan_id = groups[0]["id"] if groups else None
        if not wlan_id:
            raise OmadaApiError("No WLAN group available", adapter_id="omada")
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/wlans/{wlan_id}/ssids",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_ssid(
        self,
        site_id: str,
        ssid_id: str,
        config: dict[str, Any],
        wlan_id: str | None = None,
    ) -> dict[str, Any]:
        if not wlan_id:
            # Resolve wlan_id by finding the SSID across groups
            groups = await self.get_wlan_groups(site_id)
            for g in groups:
                gid = g.get("id")
                if not gid:
                    continue
                try:
                    ssids = await self._paginated_request(
                        "GET",
                        f"/sites/{site_id}/setting/wlans/{gid}/ssids",
                        page_size=100,
                    )
                    if any(s.get("id") == ssid_id for s in ssids):
                        wlan_id = gid
                        break
                except Exception:
                    continue
        if not wlan_id:
            raise OmadaApiError("WLAN group not found for SSID", adapter_id="omada")
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_ssid(
        self,
        site_id: str,
        ssid_id: str,
        wlan_id: str | None = None,
    ) -> dict[str, Any]:
        if not wlan_id:
            groups = await self.get_wlan_groups(site_id)
            for g in groups:
                gid = g.get("id")
                if not gid:
                    continue
                try:
                    ssids = await self._paginated_request(
                        "GET",
                        f"/sites/{site_id}/setting/wlans/{gid}/ssids",
                        page_size=100,
                    )
                    if any(s.get("id") == ssid_id for s in ssids):
                        wlan_id = gid
                        break
                except Exception:
                    continue
        if not wlan_id:
            raise OmadaApiError("WLAN group not found for SSID", adapter_id="omada")
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_clients(self, site_id: str) -> list[dict[str, Any]]:
        paths = [
            f"/sites/{site_id}/clients",
            f"/sites/{site_id}/insight/clients",
            f"/sites/{site_id}/stat/clients",
        ]
        # Cache the path that worked last time so subsequent calls
        # skip the (potentially 4 × timeout-seconds) fallback walk.
        working = getattr(self, "_working_clients_path", None)
        if working and working in paths:
            paths = [working] + [p for p in paths if p != working]

        last_exc: Exception | None = None
        for i, path in enumerate(paths):
            try:
                # Disable inner-retry on non-primary paths so each
                # fallback fails fast — we don't want to wait 4 × the
                # full retry budget when the controller has simply
                # moved the endpoint to a different location.
                retry = i == 0
                rows = await self._paginated_request(
                    "GET",
                    path,
                    page_size=500,
                    cache_ttl=self.config.cache_ttl_clients,
                    retry=retry,
                )
                self._working_clients_path = path
                return rows
            except (OmadaSessionExpiredError, OmadaApiError, OmadaNotFoundError) as exc:
                last_exc = exc
                if i < len(paths) - 1:
                    logger_http.debug(
                        "client endpoint fallback",
                        extra={"from": path, "to": paths[i + 1]},
                    )
                    continue

        # Paginated requests all failed — try non-paginated as last resort.
        # Some Omada firmware returns errorCode on paginated params but works
        # fine without them, returning all clients in a single response.
        for path in paths[:1]:  # Only try the primary endpoint
            try:
                data = await self._request(
                    "GET",
                    path,
                    cache_ttl=self.config.cache_ttl_clients,
                    retry=False,
                )
                if isinstance(data, dict):
                    rows = data.get("data") or data.get("result") or data.get("clientList") or []
                    if isinstance(rows, list) and rows:
                        logger_http.info(
                            "client list succeeded via non-paginated fallback",
                            extra={"path": path, "count": len(rows)},
                        )
                        self._working_clients_path = path
                        return rows
            except Exception as exc:
                logger_http.debug("client endpoint path failed: %s — %s", path, exc)

        logger_http.warning(
            "all client endpoint paths failed",
            extra={"last_error": str(last_exc)},
        )
        return []

    async def get_clients_enriched(
        self, site_id: str, concurrency: int = 8
    ) -> list[dict[str, Any]]:
        """Get all clients, enriching wireless ones with detail (WiFi fields).

        The list endpoint (/sites/{id}/clients) returns minimal fields.
        Wireless clients lack ssid/band/channel/signal.  We fetch per-client
        detail for wireless clients via /sites/{id}/clients/{mac} in parallel
        batches and merge the rich data back.
        """
        clients = await self.get_clients(site_id)
        if not clients:
            return clients

        # Identify wireless clients that need enrichment
        wireless_macs = [c["mac"] for c in clients if c.get("wireless") is True and c.get("mac")]
        if not wireless_macs:
            return clients

        # Fetch details concurrently with a semaphore to limit load
        sem = asyncio.Semaphore(concurrency)

        async def _fetch_detail(mac: str) -> tuple[str, dict[str, Any] | None]:
            async with sem:
                try:
                    detail = await self.get_client(site_id, mac)
                    return (mac, detail)
                except Exception:
                    logger_http.debug("client detail fallback failed", extra={"mac": mac})
                    return (mac, None)

        results = await asyncio.gather(
            *[_fetch_detail(m) for m in wireless_macs],
            return_exceptions=True,
        )

        detail_map: dict[str, dict[str, Any]] = {}
        for r in results:
            if isinstance(r, tuple) and r[1] is not None:
                detail_map[r[0].upper()] = r[1]

        # Merge detail data back into list entries
        enriched: list[dict[str, Any]] = []
        for c in clients:
            mac_upper = (c.get("mac") or "").upper()
            if mac_upper in detail_map:
                # Detail response is the superset — use it, filling gaps
                merged = {**c, **detail_map[mac_upper]}
                enriched.append(merged)
            else:
                enriched.append(c)

        logger_http.info(
            "clients enriched",
            extra={"total": len(clients), "wireless_enriched": len(detail_map)},
        )
        return enriched

    async def block_client(self, site_id: str, mac: str) -> dict[str, Any]:
        result = await self._request("POST", f"/sites/{site_id}/cmd/clients/{mac}/block")
        self._invalidate_on_write()
        return result

    async def unblock_client(self, site_id: str, mac: str) -> dict[str, Any]:
        result = await self._request("POST", f"/sites/{site_id}/cmd/clients/{mac}/unblock")
        self._invalidate_on_write()
        return result

    async def kick_client(self, site_id: str, mac: str) -> dict[str, Any]:
        """Alias for reconnect_client (backwards compat)."""
        return await self.reconnect_client(site_id, mac)

    # ------------------------------------------------------------------
    # Switch-specific endpoints
    # ------------------------------------------------------------------

    async def get_switches(self, site_id: str) -> list[dict[str, Any]]:
        """Get all switches with full detail (device_capabilities, ports, uplinks).

        Per-switch detail calls fan out concurrently behind a bounded
        semaphore. The previous sequential loop made the switches
        page take O(n × per-call latency) seconds.
        """
        devices = await self.get_devices(site_id)
        switch_devices = [d for d in devices if d.get("type") == "switch"]
        sem = asyncio.Semaphore(10)

        async def _detail(d: dict[str, Any]) -> dict[str, Any]:
            async with sem:
                try:
                    return await self._request(
                        "GET",
                        f"/sites/{site_id}/switches/{d.get('mac')}",
                        cache_ttl=self.config.cache_ttl_devices,
                    )
                except Exception:
                    return d

        gathered = await asyncio.gather(
            *[_detail(d) for d in switch_devices], return_exceptions=True
        )
        return [
            r if isinstance(r, dict) else d for d, r in zip(switch_devices, gathered, strict=False)
        ]

    async def get_switch(self, site_id: str, mac: str) -> dict[str, Any]:
        """Get full switch detail: device_capabilities, ports, uplinks, downlinks."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/switches/{mac}",
            cache_ttl=self.config.cache_ttl_devices,
        )

    async def get_switch_port_overrides(
        self, site_id: str, mac: str, port_id: int
    ) -> dict[str, Any]:
        """Get current port profile override settings for a switch port."""
        port = await self._request(
            "GET",
            f"/sites/{site_id}/switches/{mac}/ports/{port_id}",
            cache_ttl=self.config.cache_ttl_ports,
        )
        return port

    async def update_switch_port_profile(
        self,
        site_id: str,
        mac: str,
        port_id: int,
        profile_overrides: dict[str, Any],
    ) -> dict[str, Any]:
        """Apply port-profile overrides (STP, LLDP, port isolation, bandwidth, etc.)."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/switches/{mac}/ports/{port_id}",
            json_data={"profileOverrides": profile_overrides},
        )
        self._invalidate_on_write()
        return result

    async def set_switch_port_stp(
        self, site_id: str, mac: str, port_id: int, enabled: bool
    ) -> dict[str, Any]:
        """Enable / disable spanning tree on a single switch port."""
        return await self.update_switch_port_profile(
            site_id,
            mac,
            port_id,
            {"spanningTreeEnable": enabled},
        )

    async def set_switch_port_lldp(
        self, site_id: str, mac: str, port_id: int, enabled: bool
    ) -> dict[str, Any]:
        """Enable / disable LLDP-MED on a single switch port."""
        return await self.update_switch_port_profile(
            site_id,
            mac,
            port_id,
            {"lldpMedEnable": enabled},
        )

    async def set_switch_port_isolation(
        self, site_id: str, mac: str, port_id: int, enabled: bool
    ) -> dict[str, Any]:
        """Enable / disable port isolation on a switch port."""
        return await self.update_switch_port_profile(
            site_id,
            mac,
            port_id,
            {"portIsolationEnable": enabled},
        )

    async def set_switch_port_loopback_detect(
        self, site_id: str, mac: str, port_id: int, enabled: bool
    ) -> dict[str, Any]:
        """Enable / disable loopback detection on a switch port."""
        return await self.update_switch_port_profile(
            site_id,
            mac,
            port_id,
            {"loopbackDetectEnable": enabled},
        )

    async def set_switch_port_flow_control(
        self, site_id: str, mac: str, port_id: int, enabled: bool
    ) -> dict[str, Any]:
        """Enable / disable 802.3x flow control on a switch port."""
        return await self.update_switch_port_profile(
            site_id,
            mac,
            port_id,
            {"flowControlEnable": enabled},
        )

    async def set_switch_port_speed_duplex(
        self,
        site_id: str,
        mac: str,
        port_id: int,
        speed: str = "auto",
        duplex: str = "auto",
    ) -> dict[str, Any]:
        """Set link speed / duplex on a switch port (auto | 10M | 100M | 1G etc.)."""
        return await self.update_switch_port_profile(
            site_id,
            mac,
            port_id,
            {"linkSpeed": speed, "duplex": duplex},
        )

    async def get_switch_stp_config(self, site_id: str) -> dict[str, Any]:
        """Get site-level STP / RSTP global config."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/lan/stp",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_stp_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Update site-level STP config (mode, priority, hello, forward delay, max age)."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/lan/stp",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_switch_lag_groups(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        """Get LAG / LAGG groups for a switch."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/switches/{mac}/lags",
            cache_ttl=self.config.cache_ttl_config,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def create_switch_lag(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a LAG group on a switch."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/switches/{mac}/lags",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_switch_lag(
        self, site_id: str, mac: str, lag_id: int, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Update a LAG group on a switch."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/switches/{mac}/lags/{lag_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_switch_lag(
        self,
        site_id: str,
        mac: str,
        lag_id: int,
    ) -> dict[str, Any]:
        """Delete a LAG group from a switch."""
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/switches/{mac}/lags/{lag_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_switch_mirror_config(self, site_id: str, mac: str) -> dict[str, Any]:
        """Get port mirror config for a switch."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/switches/{mac}/mirror",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_mirror_config(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Update port mirror config (session, source, destination)."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/switches/{mac}/mirror",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_switch_igmp_config(self, site_id: str, mac: str) -> dict[str, Any]:
        """Get IGMP snooping config for a switch."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/switches/{mac}/igmpSnooping",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def get_switch_acl_rules(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        """Get ACL rules bound to a switch."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/switches/{mac}/acl",
            cache_ttl=self.config.cache_ttl_config,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    # ------------------------------------------------------------------
    # Access Point endpoints
    # ------------------------------------------------------------------

    async def get_aps(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET", f"/sites/{site_id}/eaps", cache_ttl=self.config.cache_ttl_devices
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def get_ap(self, site_id: str, mac: str) -> dict[str, Any]:
        return await self._request(
            "GET", f"/sites/{site_id}/eaps/{mac}", cache_ttl=self.config.cache_ttl_devices
        )

    async def get_ap_lan_port(self, site_id: str, mac: str) -> dict[str, Any]:
        """Get AP LAN port settings (VLAN, PoE out)."""
        ap = await self.get_ap(site_id, mac)
        return ap.get("lanPortSettings", ap.get("lanPort", {}))

    async def update_ap(self, site_id: str, mac: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request("PATCH", f"/sites/{site_id}/eaps/{mac}", json_data=config)
        self._invalidate_on_write()
        return result

    async def update_ap_lan_port(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Update AP LAN port (VLAN tagging, PoE passthrough)."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/eaps/{mac}",
            json_data={"lanPortSettings": config},
        )
        self._invalidate_on_write()
        return result

    async def set_ap_led(
        self, site_id: str, mac: str, enabled: bool, duration: int = 0
    ) -> dict[str, Any]:
        payload = {"ledSetting": 1 if enabled else 0, "duration": duration}
        result = await self._request("POST", f"/sites/{site_id}/eaps/{mac}/led", json_data=payload)
        self._invalidate_on_write()
        return result

    async def set_device_led(
        self, site_id: str, mac: str, device_type: str, setting: int = 1
    ) -> dict[str, Any]:
        """Generic LED control (0=off, 1=on, 2=site_settings). Works for any device type."""
        endpoint = {"ap": "eaps", "switch": "switches", "gateway": "gateways"}.get(
            device_type, "devices"
        )
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/{endpoint}/{mac}",
            json_data={"ledSetting": setting},
        )
        self._invalidate_on_write()
        return result

    async def get_ap_radios(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        """Get detailed radio config (channels, tx power, band) for an AP."""
        ap = await self.get_ap(site_id, mac)
        radios = ap.get("radioSetting") or ap.get("radioConfig") or ap.get("radios") or []
        if isinstance(radios, dict):
            radios = [radios]
        elif not isinstance(radios, list):
            radios = []

        # Handle per-band keys: radioSetting2g, radioSetting5g, radioSetting5g2, radioSetting6g
        if not radios:
            for suffix, band_name in [("2g", "2g"), ("5g", "5g"), ("5g2", "5g-2"), ("6g", "6g")]:
                key = f"radioSetting{suffix}"
                if key in ap and ap[key]:
                    entry = dict(ap[key])
                    entry["band"] = band_name
                    # Also merge traffic stats if available
                    traffic_key = f"radioTraffic{suffix}"
                    if traffic_key in ap and ap[traffic_key]:
                        entry["traffic"] = ap[traffic_key]
                    radios.append(entry)

        return radios

    async def update_ap_radio(
        self, site_id: str, mac: str, radio_band: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Update radio settings (channel, txPower, channelWidth) for a given band.

        ``radio_band``: ``"2g"`` | ``"5g"`` | ``"5g2"`` | ``"6g"``.
        """
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/eaps/{mac}",
            json_data={"radioSetting": {radio_band: config}},
        )
        self._invalidate_on_write()
        return result

    async def get_ap_ssid_overrides(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        """Get per-AP SSID overrides (which WLANs are enabled/disabled on this AP)."""
        ap = await self.get_ap(site_id, mac)
        return ap.get("ssidOverrides") or ap.get("wlanGroup") or []

    async def update_ap_ssid_override(
        self, site_id: str, mac: str, overrides: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Set per-AP SSID overrides."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/eaps/{mac}",
            json_data={"ssidOverrides": overrides},
        )
        self._invalidate_on_write()
        return result

    async def get_ap_clients(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        """Get clients connected to a specific AP."""
        all_clients = await self.get_clients(site_id)
        return [c for c in all_clients if c.get("apMac", "").lower() == mac.lower()]

    async def set_ap_mesh(self, site_id: str, mac: str, enabled: bool) -> dict[str, Any]:
        """Enable / disable mesh on an AP."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/eaps/{mac}",
            json_data={"meshEnabled": enabled},
        )
        self._invalidate_on_write()
        return result

    async def set_ap_location(
        self, site_id: str, mac: str, latitude: float, longitude: float
    ) -> dict[str, Any]:
        """Set AP geographical location."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/eaps/{mac}",
            json_data={"location": {"latitude": latitude, "longitude": longitude}},
        )
        self._invalidate_on_write()
        return result

    async def get_ap_rf_scan(self, site_id: str, mac: str) -> dict[str, Any]:
        """Trigger / get last RF scan results for an AP."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/eaps/{mac}/rfscan",
            cache_ttl=self.config.cache_ttl_config,
        )

    # ------------------------------------------------------------------
    # Gateway endpoints
    # ------------------------------------------------------------------

    async def get_gateways(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/gateways",
            cache_ttl=self.config.cache_ttl_devices,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def get_gateway(self, site_id: str, mac: str) -> dict[str, Any]:
        """Get full gateway details including portStats, portConfigs, poeSettings."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/gateways/{mac}",
            cache_ttl=self.config.cache_ttl_devices,
        )

    async def set_gateway_wan_port_connect_state(
        self,
        site_id: str,
        mac: str,
        port_number: int,
        connect: bool,
        ipv6: bool = False,
    ) -> dict[str, Any]:
        """Connect/disconnect a WAN port (IPv4 or IPv6)."""
        if ipv6:
            path = f"/sites/{site_id}/cmd/gateways/{mac}/ipv6State"
        else:
            path = f"/sites/{site_id}/cmd/gateways/{mac}/internetState"
        result = await self._request(
            "POST",
            path,
            json_data={"port": port_number, "enable": connect},
        )
        self._invalidate_on_write()
        return result

    async def set_gateway_port_settings(
        self,
        site_id: str,
        mac: str,
        port_number: int,
        settings: dict[str, Any],
    ) -> dict[str, Any]:
        """Update gateway port settings (PoE, LLDP enable, echo server)."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/gateways/{mac}",
            json_data={
                "portConfigs": [{"port": port_number, **settings}],
            },
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # WAN / LAN / DHCP config
    # ------------------------------------------------------------------

    async def get_wan_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wan",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_wan_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request("PATCH", f"/sites/{site_id}/setting/wan", json_data=config)
        self._invalidate_on_write()
        return result

    async def get_dhcp_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/lan/networks",
            cache_ttl=self.config.cache_ttl_config,
        )

    # ------------------------------------------------------------------
    # Client endpoints (expanded)
    # ------------------------------------------------------------------

    async def get_known_clients(self, site_id: str) -> list[dict[str, Any]]:
        """Get all known clients (including previously connected / offline)."""
        return await self._paginated_request(
            "GET",
            f"/sites/{site_id}/insight/clients",
            page_size=500,
            cache_ttl=self.config.cache_ttl_clients,
        )

    async def get_client(self, site_id: str, mac: str) -> dict[str, Any]:
        """Get detailed info for a single client."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/clients/{mac}",
            cache_ttl=self.config.cache_ttl_clients,
        )

    async def update_client(
        self, site_id: str, mac: str, settings: dict[str, Any]
    ) -> dict[str, Any]:
        """Update client settings (name, lock to APs, fixed IP)."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/clients/{mac}",
            json_data=settings,
        )
        self._invalidate_on_write()
        return result

    async def reconnect_client(self, site_id: str, mac: str) -> dict[str, Any]:
        """Force client reconnection (distinct from kick/block)."""
        result = await self._request("POST", f"/sites/{site_id}/cmd/clients/{mac}/reconnect")
        self._invalidate_on_write()
        return result

    async def get_firewall_rules(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/firewall/rules",
            cache_ttl=self.config.cache_ttl_config,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def get_vpn_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def get_port_profiles(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/lan/profileOverrides",
            cache_ttl=self.config.cache_ttl_config,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def get_port_profile(self, site_id: str, profile_id: str) -> dict[str, Any]:
        """Get a single port profile by ID."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/lan/profileOverrides/{profile_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def create_port_profile(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/lan/profileOverrides",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_port_profile(
        self,
        site_id: str,
        profile_id: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/lan/profileOverrides/{profile_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_port_profile(self, site_id: str, profile_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/lan/profileOverrides/{profile_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_firmware_info(self, site_id: str, mac: str) -> dict[str, Any]:
        return await self._request_with_fallback(
            "GET",
            [
                f"/sites/{site_id}/devices/{mac}/firmware",
                f"/sites/{site_id}/firmware/devices/{mac}",
            ],
            cache_ttl=self.config.cache_ttl_config,
        )

    async def trigger_firmware_upgrade(self, site_id: str, mac: str) -> dict[str, Any]:
        result = await self._request_with_fallback(
            "POST",
            [
                f"/sites/{site_id}/cmd/devices/{mac}/upgrade",
                f"/sites/{site_id}/devices/{mac}/firmware/upgrade",
            ],
        )
        self._invalidate_on_write()
        return result

    async def get_controller_status(self) -> dict[str, Any]:
        return await self._request("GET", "/maintenance/controllerStatus", cache_ttl=15)

    async def get_system_info(self) -> dict[str, Any]:
        return await self._request("GET", "/maintenance/sysInfo", cache_ttl=15)

    # ------------------------------------------------------------------
    # Firmware Management (Enterprise)
    # ------------------------------------------------------------------

    async def get_firmware_list(self, site_id: str) -> list[dict[str, Any]]:
        """Get firmware status for ALL devices in a site at once."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/firmware",
            cache_ttl=CACHE_TTL_CONFIG,
        )
        if isinstance(data, list):
            return data
        return data.get("data", data.get("devices", []))

    async def get_firmware_upgrade_log(self, site_id: str) -> list[dict[str, Any]]:
        """Get firmware upgrade history / log."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/firmware/upgradeLog",
            cache_ttl=CACHE_TTL_CONFIG,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def batch_firmware_check(self, site_id: str) -> list[dict[str, Any]]:
        """Check firmware updates for all devices.

        Fans out per-device firmware lookups concurrently with a
        bounded semaphore so we don't melt the controller. Was
        sequential — one round-trip per device — which made fleet-
        wide scans take minutes on sites with 50+ devices.
        """
        devices = await self.get_devices(site_id)
        sem = asyncio.Semaphore(10)

        async def _fetch(d: dict[str, Any]) -> dict[str, Any] | None:
            mac = d.get("mac")
            if not mac:
                return None
            async with sem:
                try:
                    fw = await self.get_firmware_info(site_id, mac)
                    fw["mac"] = mac
                    fw["name"] = d.get("name")
                    fw["model"] = d.get("model")
                    fw["type"] = d.get("type")
                    fw["currentVersion"] = d.get("firmwareVersion")
                    return fw
                except Exception:
                    return {
                        "mac": mac,
                        "name": d.get("name"),
                        "model": d.get("model"),
                        "type": d.get("type"),
                        "currentVersion": d.get("firmwareVersion"),
                        "error": True,
                    }

        gathered = await asyncio.gather(*[_fetch(d) for d in devices], return_exceptions=True)
        return [r for r in gathered if isinstance(r, dict)]

    # ------------------------------------------------------------------
    # DHCP Reservations
    # ------------------------------------------------------------------

    async def get_dhcp_reservations(self, site_id: str, network_id: str) -> list[dict[str, Any]]:
        """Get DHCP static reservations for a network."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/lan/networks/{network_id}/dhcpReservations",
            cache_ttl=self.config.cache_ttl_config,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def create_dhcp_reservation(
        self, site_id: str, network_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a DHCP static reservation."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/lan/networks/{network_id}/dhcpReservations",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_dhcp_reservation(
        self, site_id: str, network_id: str, reservation_id: str
    ) -> dict[str, Any]:
        """Delete a DHCP static reservation."""
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/lan/networks/{network_id}/dhcpReservations/{reservation_id}",
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # IP Groups / Network Groups
    # ------------------------------------------------------------------

    async def get_ip_groups(self, site_id: str) -> list[dict[str, Any]]:
        """Get IP groups for firewall / ACL rules."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/firewall/ipGroups",
            cache_ttl=self.config.cache_ttl_config,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def create_ip_group(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/firewall/ipGroups",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_ip_group(
        self, site_id: str, group_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/firewall/ipGroups/{group_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_ip_group(self, site_id: str, group_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/firewall/ipGroups/{group_id}",
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # URL Filtering
    # ------------------------------------------------------------------

    async def get_url_filter(self, site_id: str) -> dict[str, Any]:
        """Get URL filter configuration."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/firewall/urlFilter",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_url_filter(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/firewall/urlFilter",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # Firewall Rules (full CRUD)
    # ------------------------------------------------------------------

    async def create_firewall_rule(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/firewall/rules",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_firewall_rule(
        self, site_id: str, rule_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/firewall/rules/{rule_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_firewall_rule(self, site_id: str, rule_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/firewall/rules/{rule_id}",
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # Static Routes
    # ------------------------------------------------------------------

    async def get_static_routes(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/routing/static",
            cache_ttl=self.config.cache_ttl_config,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def create_static_route(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/routing/static",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_static_route(
        self, site_id: str, route_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/routing/static/{route_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_static_route(self, site_id: str, route_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/routing/static/{route_id}",
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # IP-MAC Binding
    # ------------------------------------------------------------------

    async def get_ip_mac_bindings(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/lan/ipMacBinding",
            cache_ttl=self.config.cache_ttl_config,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def create_ip_mac_binding(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/lan/ipMacBinding",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_ip_mac_binding(self, site_id: str, binding_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/lan/ipMacBinding/{binding_id}",
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # DDNS
    # ------------------------------------------------------------------

    async def get_ddns_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wan/ddns",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_ddns_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/wan/ddns",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # WAN Failover / Load Balance
    # ------------------------------------------------------------------

    async def get_wan_failover_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wan/failover",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_wan_failover_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/wan/failover",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_wan_load_balance_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wan/loadBalance",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_wan_load_balance_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/wan/loadBalance",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # Switch Advanced: MAC Table, IGMP, ACL, QoS, 802.1x, DHCP Snooping
    # ------------------------------------------------------------------

    async def get_switch_mac_table(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        """Get the MAC address table from a switch.

        Tries multiple endpoint paths for compatibility across Omada versions:
        - ``/switches/{mac}/macTable`` (Omada 5.9+)
        - ``/switches/{mac}/mac-table``
        - ``/insight/switches/{mac}/macTable`` (insight API)
        """
        paths = [
            f"/sites/{site_id}/switches/{mac}/macTable",
            f"/sites/{site_id}/switches/{mac}/mac-table",
            f"/sites/{site_id}/insight/switches/{mac}/macTable",
        ]
        last_exc: Exception | None = None
        for path in paths:
            try:
                return await self._paginated_request(
                    "GET",
                    path,
                    page_size=1000,
                    cache_ttl=15,
                )
            except Exception as exc:
                last_exc = exc
                logger_http.debug(
                    "macTable path failed",
                    extra={"path": path, "error": str(exc)},
                )
            # Also try non-paginated for this path
            try:
                data = await self._request("GET", path, cache_ttl=15)
                if isinstance(data, list) and data:
                    return data
                if isinstance(data, dict):
                    rows = data.get("data", data.get("result", []))
                    if rows:
                        return rows
            except Exception as exc:
                logger_http.debug("macTable path failed: %s — %s", path, exc)
        logger_http.warning(
            "all macTable paths failed",
            extra={"mac": mac, "last_error": str(last_exc)},
        )
        return []

    async def update_switch_igmp_config(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Update IGMP snooping config for a switch."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/switches/{mac}/igmpSnooping",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def create_switch_acl_rule(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Create an ACL rule on a switch."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/switches/{mac}/acl",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_switch_acl_rule(
        self, site_id: str, mac: str, rule_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/switches/{mac}/acl/{rule_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_switch_acl_rule(self, site_id: str, mac: str, rule_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/switches/{mac}/acl/{rule_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_dot1x_config(self, site_id: str) -> dict[str, Any]:
        """Get site-level 802.1x / RADIUS configuration."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/lan/dot1x",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_dot1x_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/lan/dot1x",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_qos_config(self, site_id: str) -> dict[str, Any]:
        """Get site-level QoS configuration."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/lan/qos",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_qos_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/lan/qos",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_dhcp_snooping_config(self, site_id: str) -> dict[str, Any]:
        """Get DHCP snooping configuration."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/lan/dhcpSnooping",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_dhcp_snooping_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/lan/dhcpSnooping",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # AP Advanced: Rogue APs, Channel Utilization, Site Radios
    # ------------------------------------------------------------------

    async def get_rogue_aps(self, site_id: str) -> list[dict[str, Any]]:
        """Get detected rogue / neighboring APs."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/rogueAps",
            cache_ttl=60,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def get_channel_utilization(self, site_id: str) -> list[dict[str, Any]]:
        """Get RF channel utilization stats across all APs."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/stat/channelUtilization",
            cache_ttl=30,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def get_site_radio_settings(self, site_id: str) -> dict[str, Any]:
        """Get site-level radio settings (channel plan, tx power, etc.)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wlans/radioSetting",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_site_radio_settings(
        self, site_id: str, band: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Update site-level radio settings for a specific band."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/wlans/radioSetting/{band}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # Hotspot / Captive Portal
    # ------------------------------------------------------------------

    async def get_hotspot_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/hotspot",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_hotspot_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/hotspot",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_captive_portal_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/captivePortal",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_captive_portal_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/captivePortal",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_vouchers(self, site_id: str) -> list[dict[str, Any]]:
        """Get hotspot vouchers."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/hotspot/vouchers",
            cache_ttl=self.config.cache_ttl_config,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def create_vouchers(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Generate hotspot vouchers."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/hotspot/vouchers",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_voucher(self, site_id: str, voucher_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/hotspot/vouchers/{voucher_id}",
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # Events / Alerts
    # ------------------------------------------------------------------

    async def get_events(self, site_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent events from the controller."""
        data = await self._paginated_request(
            "GET",
            f"/sites/{site_id}/events",
            page_size=limit,
            max_pages=1,
            cache_ttl=15,
        )
        return data

    async def get_alerts(self, site_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Get active alerts from the controller."""
        data = await self._paginated_request(
            "GET",
            f"/sites/{site_id}/alerts",
            page_size=limit,
            max_pages=1,
            cache_ttl=15,
        )
        return data

    # ------------------------------------------------------------------
    # PoE Schedule
    # ------------------------------------------------------------------

    async def get_poe_schedules(self, site_id: str) -> list[dict[str, Any]]:
        """Get PoE schedules for a site."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/lan/poeSchedule",
            cache_ttl=self.config.cache_ttl_config,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    async def create_poe_schedule(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/lan/poeSchedule",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_poe_schedule(
        self, site_id: str, schedule_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/lan/poeSchedule/{schedule_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_poe_schedule(self, site_id: str, schedule_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/lan/poeSchedule/{schedule_id}",
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # Site Settings
    # ------------------------------------------------------------------

    async def get_site_settings(self, site_id: str) -> dict[str, Any]:
        """Get comprehensive site settings."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_site_settings(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ------------------------------------------------------------------
    # Controller Maintenance
    # ------------------------------------------------------------------

    async def create_controller_backup(self) -> dict[str, Any]:
        """Trigger a controller backup."""
        result = await self._request("POST", "/maintenance/backup")
        self._invalidate_on_write()
        return result

    async def get_controller_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get controller maintenance/system logs."""
        data = await self._request(
            "GET",
            "/maintenance/logs",
            params={"limit": limit},
            cache_ttl=15,
        )
        if isinstance(data, list):
            return data
        return data.get("data", [])

    # ------------------------------------------------------------------
    # Topology-enriched device queries
    # ------------------------------------------------------------------

    async def get_devices_with_topology(self, site_id: str) -> list[dict[str, Any]]:
        """Get all devices with full detail including uplink/downlink topology info.

        For each device, fetches the type-specific detail endpoint which
        contains ``uplink``, ``downlink``, and ``lldpNeighbors`` data
        that the generic ``/devices`` endpoint omits.

        Detail fetches run concurrently behind a bounded semaphore.
        Was sequential, which made topology refresh on a 50-device
        site take 50× the per-call latency.
        """
        devices = await self.get_devices(site_id)
        sem = asyncio.Semaphore(10)

        async def _enrich(d: dict[str, Any]) -> dict[str, Any]:
            mac = d.get("mac")
            dtype = d.get("type")
            if not mac:
                return d
            async with sem:
                try:
                    if dtype == "switch":
                        return await self._request(
                            "GET",
                            f"/sites/{site_id}/switches/{mac}",
                            cache_ttl=self.config.cache_ttl_devices,
                        )
                    if dtype == "ap":
                        return await self._request(
                            "GET",
                            f"/sites/{site_id}/eaps/{mac}",
                            cache_ttl=self.config.cache_ttl_devices,
                        )
                    if dtype == "gateway":
                        return await self._request(
                            "GET",
                            f"/sites/{site_id}/gateways/{mac}",
                            cache_ttl=self.config.cache_ttl_devices,
                        )
                    return d
                except Exception:
                    return d

        gathered = await asyncio.gather(*[_enrich(d) for d in devices], return_exceptions=True)
        return [r if isinstance(r, dict) else d for d, r in zip(devices, gathered, strict=False)]

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    @property
    def controller_id(self) -> str | None:
        return self._controller_id

    @property
    def controller_version(self) -> str | None:
        return self._controller_version

    def get_health(self) -> dict[str, Any]:
        """Return low-level client metrics."""
        avg_latency = self._total_latency_ms / self._request_count if self._request_count else 0.0
        error_rate = self._error_count / self._request_count if self._request_count else 0.0
        cache_stats = self._cache.stats
        return {
            "logged_in": self._logged_in,
            "mode": self.config.mode,
            "controller_id": self._controller_id,
            "controller_version": self._controller_version,
            "request_count": self._request_count,
            "error_count": self._error_count,
            "retry_count": self._retry_count,
            "error_rate": round(error_rate, 4),
            "avg_latency_ms": round(avg_latency, 2),
            "cache_hit_rate": cache_stats["hit_rate"],
            "cache_size": cache_stats["size"],
            "rate_limit_remaining": self._rate_limiter.available_tokens,
            "last_successful_request": (
                self._last_successful_request.isoformat() if self._last_successful_request else None
            ),
            "cloud_token_expires_in": (
                max(0, int(self._token_expires_at - time.monotonic()))
                if self.config.is_cloud and self._logged_in
                else None
            ),
        }

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    async def run_cable_test(self, site_id: str, mac: str, port: int) -> dict[str, Any]:
        """Run cable diagnostic test on a switch port."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/{mac}/cableTest",
            json_data={"port": port},
        )

    async def run_ping(self, site_id: str, mac: str, target: str, count: int = 5) -> dict[str, Any]:
        """Run ping from a device to a target host."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/{mac}/ping",
            json_data={"target": target, "count": count},
        )

    async def run_traceroute(
        self, site_id: str, mac: str, target: str, max_hops: int = 30
    ) -> dict[str, Any]:
        """Run traceroute from a device to a target host."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/{mac}/traceroute",
            json_data={"target": target, "maxHops": max_hops},
        )

    # =========================================================================
    # MILESTONE A — VPN module
    # =========================================================================
    # Omada Controller v5/v6 supports 7 VPN protocol families. Each family has
    # its own ``/setting/vpn/<type>`` collection with full CRUD semantics
    # (server config, peer/profile list, runtime stats). Endpoint shapes follow
    # what's exposed on the controller's web UI under Settings → VPN.
    #
    # Common verb pattern per family:
    #   list_<type>_<entity>(site_id)              → GET    list
    #   get_<type>_<entity>(site_id, entity_id)    → GET    single
    #   create_<type>_<entity>(site_id, config)    → POST   create
    #   update_<type>_<entity>(site_id, eid, cfg)  → PATCH  update
    #   delete_<type>_<entity>(site_id, entity_id) → DELETE remove
    #
    # Site-level "global" config (e.g. enable/disable) uses a single GET/PUT
    # pair without entity_id.

    # ── IPsec (site-to-site + IKEv1/v2 client) ──────────────────────────────

    async def get_ipsec_config(self, site_id: str) -> dict[str, Any]:
        """Site-level IPsec settings (global enable, NAT-T, MTU)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/ipsec",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_ipsec_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/ipsec",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def list_ipsec_policies(self, site_id: str) -> list[dict[str, Any]]:
        """Return the list of configured IPsec site-to-site / client tunnels."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/ipsec/policies",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_ipsec_policy(self, site_id: str, policy_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/ipsec/policies/{policy_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def create_ipsec_policy(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create an IPsec policy.

        ``config`` mirrors the Omada UI form: ``name``, ``mode``
        (siteToSite|clientToSite), ``ikeVersion``, ``localSubnet``,
        ``remoteSubnet``, ``remoteGateway``, ``preSharedKey``, ``ikeProposal``,
        ``ipsecProposal``, ``perfectForwardSecrecy``, ``deadPeerDetection``,
        ``natTraversal``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/vpn/ipsec/policies",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_ipsec_policy(
        self, site_id: str, policy_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/ipsec/policies/{policy_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_ipsec_policy(self, site_id: str, policy_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/vpn/ipsec/policies/{policy_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_ipsec_status(self, site_id: str) -> list[dict[str, Any]]:
        """Active IPsec tunnels with SA stats (peer, bytes, since)."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/vpn/ipsec/status",
        )
        return data if isinstance(data, list) else data.get("data", [])

    # ── OpenVPN (server + client modes) ──────────────────────────────────────

    async def get_openvpn_config(self, site_id: str) -> dict[str, Any]:
        """Server-mode OpenVPN settings: protocol, port, subnet, cipher, auth."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/openVpn",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_openvpn_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/openVpn",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def list_openvpn_users(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/openVpn/users",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_openvpn_user(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create an OpenVPN user. ``config``: ``username``, ``password``,
        ``maxConnections``, ``allowedSubnets``."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/vpn/openVpn/users",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_openvpn_user(
        self, site_id: str, user_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/openVpn/users/{user_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_openvpn_user(self, site_id: str, user_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/vpn/openVpn/users/{user_id}",
        )
        self._invalidate_on_write()
        return result

    async def export_openvpn_client_config(self, site_id: str, user_id: str) -> dict[str, Any]:
        """Generate the OpenVPN ``.ovpn`` profile for a user (returned inline)."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/vpn/openVpn/users/{user_id}/exportConfig",
        )

    async def get_openvpn_status(self, site_id: str) -> list[dict[str, Any]]:
        """Connected OpenVPN clients with bytes/since stats."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/vpn/openVpn/status",
        )
        return data if isinstance(data, list) else data.get("data", [])

    # ── L2TP (over IPsec, server mode) ───────────────────────────────────────

    async def get_l2tp_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/l2tp",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_l2tp_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """L2TP server: ``enabled``, ``ipPoolStart``, ``ipPoolEnd``,
        ``preSharedKey``, ``primaryDns``, ``secondaryDns``, ``mppe``."""
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/l2tp",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def list_l2tp_users(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/l2tp/users",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_l2tp_user(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/vpn/l2tp/users",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_l2tp_user(
        self, site_id: str, user_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/l2tp/users/{user_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_l2tp_user(self, site_id: str, user_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/vpn/l2tp/users/{user_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_l2tp_status(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/vpn/l2tp/status",
        )
        return data if isinstance(data, list) else data.get("data", [])

    # ── PPTP (legacy; still used in the field, marked deprecated by Omada) ──

    async def get_pptp_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/pptp",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_pptp_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/pptp",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def list_pptp_users(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/pptp/users",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_pptp_user(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/vpn/pptp/users",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_pptp_user(
        self, site_id: str, user_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/pptp/users/{user_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_pptp_user(self, site_id: str, user_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/vpn/pptp/users/{user_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_pptp_status(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/vpn/pptp/status",
        )
        return data if isinstance(data, list) else data.get("data", [])

    # ── WireGuard (added in Omada v5.14+) ───────────────────────────────────

    async def get_wireguard_config(self, site_id: str) -> dict[str, Any]:
        """Server-mode WireGuard settings: listenPort, endpoint, MTU, dns."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/wireguard",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_wireguard_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/wireguard",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def list_wireguard_peers(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/wireguard/peers",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_wireguard_peer(self, site_id: str, peer_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/wireguard/peers/{peer_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def create_wireguard_peer(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create a WireGuard peer.

        ``config``: ``name``, ``publicKey`` (peer's, controller generates if
        omitted), ``presharedKey`` (optional), ``allowedIps`` (CIDR list),
        ``persistentKeepalive`` seconds, ``endpoint`` for site-to-site mode.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/vpn/wireguard/peers",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_wireguard_peer(
        self, site_id: str, peer_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/wireguard/peers/{peer_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_wireguard_peer(self, site_id: str, peer_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/vpn/wireguard/peers/{peer_id}",
        )
        self._invalidate_on_write()
        return result

    async def export_wireguard_peer_config(self, site_id: str, peer_id: str) -> dict[str, Any]:
        """Generate the ``wg-quick`` peer config (and QR code) for a peer."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/vpn/wireguard/peers/{peer_id}/exportConfig",
        )

    async def get_wireguard_status(self, site_id: str) -> list[dict[str, Any]]:
        """Per-peer handshake/transfer stats (latest handshake, bytes rx/tx)."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/vpn/wireguard/status",
        )
        return data if isinstance(data, list) else data.get("data", [])

    # ── SSL-VPN (browser-friendly remote access; HTTPS-tunneled) ────────────

    async def get_sslvpn_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/sslVpn",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_sslvpn_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/sslVpn",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def list_sslvpn_users(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/sslVpn/users",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_sslvpn_user(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/vpn/sslVpn/users",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_sslvpn_user(
        self, site_id: str, user_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/sslVpn/users/{user_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_sslvpn_user(self, site_id: str, user_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/vpn/sslVpn/users/{user_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_sslvpn_status(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/vpn/sslVpn/status",
        )
        return data if isinstance(data, list) else data.get("data", [])

    # ── GRE tunnels (encapsulation only — pair with IPsec for transport sec) ─

    async def list_gre_tunnels(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/gre",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_gre_tunnel(self, site_id: str, tunnel_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/vpn/gre/{tunnel_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def create_gre_tunnel(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create a GRE tunnel.

        ``config``: ``name``, ``localAddress``, ``remoteAddress``,
        ``tunnelLocalIp``, ``tunnelRemoteIp``, ``ttl``, ``mtu``,
        ``keepalive`` (bool), ``keepaliveInterval``, ``keepaliveRetries``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/vpn/gre",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_gre_tunnel(
        self, site_id: str, tunnel_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/vpn/gre/{tunnel_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_gre_tunnel(self, site_id: str, tunnel_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/vpn/gre/{tunnel_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_gre_status(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/vpn/gre/status",
        )
        return data if isinstance(data, list) else data.get("data", [])

    # =========================================================================
    # MILESTONE B — Profile / Group layer (foundational object catalog)
    # =========================================================================
    # Many Omada features (URL filter, app control, ACLs, bandwidth control,
    # captive portal, RADIUS-backed SSIDs) reference REUSABLE OBJECTS rather
    # than embedding raw IPs/MACs/schedules. Without these primitives we can't
    # author the higher-level features above.
    #
    # Object types covered:
    #   - IP groups        (groups of IPv4/IPv6 hosts/subnets)
    #   - MAC groups       (groups of client MACs)
    #   - Domain groups    (groups of FQDNs/wildcards for URL filtering)
    #   - OUI profiles     (vendor-OUI groups for surveillance/voice VLAN)
    #   - Time ranges      (recurring schedule objects)
    #   - Rate limit       (bandwidth profiles for SSID/voucher/client)
    #   - PPSK profiles    (per-user pre-shared keys for WiFi)
    #   - RADIUS profiles  (auth/acct server config)
    #   - LDAP profiles    (directory backend for portal/802.1X)

    # ── IP groups: see existing get_ip_groups / create_ip_group / etc.
    #    (The existing client already covers IP groups via the older
    #    ``setting/firewall/ipGroups`` endpoint — those work in production
    #    and we keep them as-is. The v6 controller exposes the same data
    #    under ``setting/profiles/groups/ip`` but the older path remains
    #    backward-compatible, so no duplicate definitions here.)

    # ── MAC groups ──────────────────────────────────────────────────────────

    async def list_mac_groups(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/groups/mac",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_mac_group(self, site_id: str, group_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/groups/mac/{group_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def create_mac_group(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create MAC group. ``config``: ``name``, ``macList`` (list of MACs)."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/profiles/groups/mac",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_mac_group(
        self, site_id: str, group_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/profiles/groups/mac/{group_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_mac_group(self, site_id: str, group_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/profiles/groups/mac/{group_id}",
        )
        self._invalidate_on_write()
        return result

    # ── Domain groups (used by URL filter + walled garden) ──────────────────

    async def list_domain_groups(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/groups/domain",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_domain_group(self, site_id: str, group_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/groups/domain/{group_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def create_domain_group(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create domain group. ``config``: ``name``, ``domainList`` (list of
        FQDNs; supports ``*.`` wildcard prefix)."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/profiles/groups/domain",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_domain_group(
        self, site_id: str, group_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/profiles/groups/domain/{group_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_domain_group(self, site_id: str, group_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/profiles/groups/domain/{group_id}",
        )
        self._invalidate_on_write()
        return result

    # ── OUI profiles (used by surveillance VLAN, voice VLAN) ────────────────

    async def list_oui_profiles(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/groups/oui",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_oui_profile(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create OUI profile. ``config``: ``name``, ``ouiList`` (list of
        24-bit MAC prefixes, ``XX:XX:XX``)."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/profiles/groups/oui",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_oui_profile(
        self, site_id: str, profile_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/profiles/groups/oui/{profile_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_oui_profile(self, site_id: str, profile_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/profiles/groups/oui/{profile_id}",
        )
        self._invalidate_on_write()
        return result

    # ── Time range profiles ─────────────────────────────────────────────────

    async def list_time_ranges(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/timeRange",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_time_range(self, site_id: str, range_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/timeRange/{range_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def create_time_range(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create time range. ``config``: ``name``, ``daysOfWeek`` (list of
        Mon..Sun), ``startTime`` (HH:MM), ``endTime`` (HH:MM), ``timezone``."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/profiles/timeRange",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_time_range(
        self, site_id: str, range_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/profiles/timeRange/{range_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_time_range(self, site_id: str, range_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/profiles/timeRange/{range_id}",
        )
        self._invalidate_on_write()
        return result

    # ── Rate limit profiles ─────────────────────────────────────────────────

    async def list_rate_limit_profiles(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/rateLimit",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_rate_limit_profile(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Create rate limit. ``config``: ``name``, ``downKbps``, ``upKbps``
        (0 means unlimited)."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/profiles/rateLimit",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_rate_limit_profile(
        self, site_id: str, profile_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/profiles/rateLimit/{profile_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_rate_limit_profile(self, site_id: str, profile_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/profiles/rateLimit/{profile_id}",
        )
        self._invalidate_on_write()
        return result

    # ── PPSK (Private PSK) profiles — per-user WiFi pre-shared keys ─────────

    async def list_ppsk_profiles(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/ppsk",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_ppsk_profile(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create PPSK profile. ``config``: ``name``, ``users`` (list of
        ``{username, psk, vlan, rateLimitProfileId}``)."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/profiles/ppsk",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_ppsk_profile(
        self, site_id: str, profile_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/profiles/ppsk/{profile_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_ppsk_profile(self, site_id: str, profile_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/profiles/ppsk/{profile_id}",
        )
        self._invalidate_on_write()
        return result

    # ── RADIUS profiles (auth + accounting servers) ─────────────────────────

    async def list_radius_profiles(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/radius",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_radius_profile(self, site_id: str, profile_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/radius/{profile_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def create_radius_profile(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create RADIUS profile.

        ``config``: ``name``, ``authServers`` (list of {host, port, secret}),
        ``acctServers`` (list of {host, port, secret}), ``acctEnabled``,
        ``acctInterimUpdateInterval``, ``nasId``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/profiles/radius",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_radius_profile(
        self, site_id: str, profile_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/profiles/radius/{profile_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_radius_profile(self, site_id: str, profile_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/profiles/radius/{profile_id}",
        )
        self._invalidate_on_write()
        return result

    async def test_radius_profile(
        self, site_id: str, profile_id: str, username: str, password: str
    ) -> dict[str, Any]:
        """Send a probe Access-Request to verify the RADIUS profile."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/profiles/radius/{profile_id}/test",
            json_data={"username": username, "password": password},
        )

    # ── LDAP profiles (auth backend for captive portal + 802.1X) ────────────

    async def list_ldap_profiles(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/profiles/ldap",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_ldap_profile(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create LDAP profile.

        ``config``: ``name``, ``server``, ``port``, ``useTls``, ``baseDn``,
        ``bindDn``, ``bindPassword``, ``userFilter``, ``timeoutSec``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/profiles/ldap",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_ldap_profile(
        self, site_id: str, profile_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/profiles/ldap/{profile_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_ldap_profile(self, site_id: str, profile_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/profiles/ldap/{profile_id}",
        )
        self._invalidate_on_write()
        return result

    async def test_ldap_profile(
        self, site_id: str, profile_id: str, username: str, password: str
    ) -> dict[str, Any]:
        """Verify LDAP bind + user lookup with credentials."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/profiles/ldap/{profile_id}/test",
            json_data={"username": username, "password": password},
        )

    # =========================================================================
    # MILESTONE C — Firewall depth
    # =========================================================================
    # Beyond the basic "Firewall Rules" CRUD already in this client we add
    # URL filtering, application/DPI control, port forwarding (DNAT), DMZ,
    # one-to-one NAT, UPnP toggling + dynamic mappings inspection, attack
    # defense (DDoS/anomaly), and ALG (NAT helpers).

    # ── URL filter rules ────────────────────────────────────────────────────

    async def list_url_filter_rules(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/firewall/urlFilter",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_url_filter_rule(self, site_id: str, rule_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/firewall/urlFilter/{rule_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def create_url_filter_rule(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create URL filter rule.

        ``config``: ``name``, ``policy`` (block|allow), ``sourceType``
        (ipGroup|network|all), ``sourceId``, ``domainGroupIds`` (list),
        ``timeRangeId`` (optional), ``enabled``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/firewall/urlFilter",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_url_filter_rule(
        self, site_id: str, rule_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/firewall/urlFilter/{rule_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_url_filter_rule(self, site_id: str, rule_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/firewall/urlFilter/{rule_id}",
        )
        self._invalidate_on_write()
        return result

    # ── Application control / DPI ───────────────────────────────────────────

    async def get_app_categories(self, site_id: str) -> list[dict[str, Any]]:
        """Fetch the catalog of DPI categories the controller can identify
        (BitTorrent, TikTok, Zoom, Slack, …). Required to author appFilter rules."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/firewall/appCategories",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def list_app_filter_rules(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/firewall/appFilter",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_app_filter_rule(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create app-control rule.

        ``config``: ``name``, ``policy``, ``sourceType``, ``sourceId``,
        ``categoryIds`` (list of category IDs from get_app_categories),
        ``appIds`` (list of specific app IDs, optional), ``timeRangeId``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/firewall/appFilter",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_app_filter_rule(
        self, site_id: str, rule_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/firewall/appFilter/{rule_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_app_filter_rule(self, site_id: str, rule_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/firewall/appFilter/{rule_id}",
        )
        self._invalidate_on_write()
        return result

    # ── Port forwarding (DNAT / Virtual Server) ─────────────────────────────

    async def list_port_forwards(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/transmission/portForwarding",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_port_forward(self, site_id: str, rule_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/transmission/portForwarding/{rule_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def create_port_forward(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create port-forward (virtual server).

        ``config``: ``name``, ``protocol`` (tcp|udp|tcpUdp|all), ``wanInterface``
        (wan1|wan2), ``externalPort`` or ``externalPortRange`` ``[start, end]``,
        ``internalIp``, ``internalPort``, ``enabled``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/transmission/portForwarding",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_port_forward(
        self, site_id: str, rule_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/transmission/portForwarding/{rule_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_port_forward(self, site_id: str, rule_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/transmission/portForwarding/{rule_id}",
        )
        self._invalidate_on_write()
        return result

    # ── DMZ ─────────────────────────────────────────────────────────────────

    async def get_dmz_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/transmission/dmz",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_dmz_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Set DMZ host. ``config``: ``enabled``, ``dmzHost`` (LAN IP)."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/transmission/dmz",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── One-to-One NAT ──────────────────────────────────────────────────────

    async def list_one_to_one_nat(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/transmission/oneToOneNat",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_one_to_one_nat(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create 1:1 NAT mapping.

        ``config``: ``name``, ``wanInterface``, ``externalIp``, ``internalIp``,
        ``portMode`` (all|range), ``portRangeStart``, ``portRangeEnd``,
        ``allowDmzPassthrough``, ``enabled``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/transmission/oneToOneNat",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_one_to_one_nat(
        self, site_id: str, mapping_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/transmission/oneToOneNat/{mapping_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_one_to_one_nat(self, site_id: str, mapping_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/transmission/oneToOneNat/{mapping_id}",
        )
        self._invalidate_on_write()
        return result

    # ── UPnP ────────────────────────────────────────────────────────────────

    async def get_upnp_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/transmission/upnp",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_upnp_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Toggle UPnP. ``config``: ``enabled``, ``wanInterface``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/transmission/upnp",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def list_upnp_mappings(self, site_id: str) -> list[dict[str, Any]]:
        """Inspect dynamic UPnP mappings created by clients."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/upnpMappings",
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def delete_upnp_mapping(self, site_id: str, mapping_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/insight/upnpMappings/{mapping_id}",
        )
        self._invalidate_on_write()
        return result

    # ── Attack defense (gateway DDoS protection) ────────────────────────────

    async def get_attack_defense_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/firewall/attackDefense",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_attack_defense_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Configure attack defenses. ``config``: per-attack toggles for
        ``synFlood``, ``udpFlood``, ``icmpFlood``, ``smurf``, ``pingOfDeath``,
        ``teardrop``, ``land``, ``winNuke``, ``portScan``, ``ipSpoof``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/firewall/attackDefense",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── ALG (Application Layer Gateway helpers) ─────────────────────────────

    async def get_alg_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/transmission/alg",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_alg_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Toggle NAT helpers. ``config``: per-protocol bool for
        ``sip``, ``h323``, ``ftp``, ``pptp``, ``ipsec``, ``l2tp``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/transmission/alg",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── IDS / IPS (intrusion detection / prevention) ────────────────────────

    async def get_ids_ips_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/firewall/idsIps",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_ids_ips_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Configure IDS/IPS. ``config``: ``mode`` (off|detect|prevent),
        ``severityThreshold``, ``categories`` (list of enabled category IDs)."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/firewall/idsIps",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_ids_ips_signatures(self, site_id: str) -> dict[str, Any]:
        """Trigger an on-demand signature DB refresh from the cloud."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/idsIps/updateDb",
        )

    async def get_ids_ips_events(self, site_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """Recent IDS/IPS detections."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/idsIps/events",
            params={"limit": limit},
        )
        return data if isinstance(data, list) else data.get("data", [])

    # =========================================================================
    # MILESTONE D — WiFi advanced
    # =========================================================================
    # The basic SSID CRUD already in this client doesn't expose the knobs
    # WiFi engineers actually tune: band steering, fast roaming (802.11r/k/v),
    # WPA3 modes, MU-MIMO, beacon/DTIM, RSSI thresholds, multicast handling,
    # mesh tuning, and per-SSID MAC filters.
    #
    # Most settings live in two scopes:
    #   - WLAN GROUP-level (radio defaults, band steering, fast roaming)
    #     PATCH /sites/{siteId}/setting/wlans/{wlanId}
    #   - SSID-level (security mode, encryption, schedule, MAC filter)
    #     PATCH /sites/{siteId}/setting/wlans/{wlanId}/ssids/{ssidId}
    #
    # The methods below are explicit thin wrappers so callers do not have to
    # juggle the schema themselves. They forward whatever fields the caller
    # supplies — the controller validates the rest.

    # ── WLAN group advanced ─────────────────────────────────────────────────

    async def update_wlan_group_advanced(
        self, site_id: str, wlan_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Update WLAN-group-level advanced settings.

        Supported fields:
          ``bandSteering``         (true|false)
          ``bandSteeringStrategy`` (preferGhz5|forceGhz5|balanced)
          ``airtimeFairness``      (true|false)
          ``loadBalance``          (true|false)
          ``loadBalanceClientLimit`` (int)
          ``minRssiAssociate``     (dBm threshold for association)
          ``minRssiKick``          (dBm threshold for client kick)
          ``broadcastFiltering``   (true|false — drops unknown broadcast)
          ``multicastFiltering``   (true|false)
          ``mesh``                 (true|false)
          ``meshAutoFailover``     (true|false)
        """
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/wlans/{wlan_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_wlan_group_advanced(self, site_id: str, wlan_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wlans/{wlan_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    # ── SSID advanced ───────────────────────────────────────────────────────

    async def update_ssid_advanced(
        self,
        site_id: str,
        wlan_id: str,
        ssid_id: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """Update SSID-level advanced settings.

        Notable fields:
          ``securityMode``       (none|wpa-personal|wpa-enterprise|wpa3-personal|
                                  wpa3-enterprise|wpa2wpa3-personal|owe)
          ``wpaVersion``         (wpa|wpa2|wpa2wpa3|wpa3)
          ``wpaCipher``          (auto|tkip|aes|tkipAes)
          ``encryption``         (encryption mode for WPA-Enterprise)
          ``ssidBroadcast``      (false to hide SSID)
          ``apIsolation``        (true|false — block client-to-client)
          ``guestPolicy``        (true|false — apply guest network policy)
          ``rateLimitProfileId`` (per-SSID rate cap; from list_rate_limit_profiles)
          ``vlanId``             (tag VLAN for SSID traffic)
          ``vlanEnabled``        (true|false)
          ``scheduleId``         (time-range profile)
          ``ssid80211r``         (true|false — Fast BSS Transition)
          ``ssid80211k``         (true|false — neighbor reports)
          ``ssid80211v``         (true|false — BSS transition mgmt)
          ``ssid80211w``         (disabled|optional|required — PMF)
          ``muMimo``             (true|false)
          ``ofdma``              (true|false — Wi-Fi 6)
          ``twtSupport``         (true|false — Target Wake Time, Wi-Fi 6)
          ``beaconInterval``     (ms, 25-2000)
          ``dtim24g`` ``dtim5g`` ``dtim6g``  (1-15)
          ``minDataRate24g``     (Mbps; 0 disables; raise to drop legacy)
          ``minDataRate5g``      (Mbps)
          ``radiusProfileId``    (for WPA-Enterprise)
          ``ppskProfileId``      (for per-user PSK)
          ``portalEnabled``      (route via captive portal)
          ``walledGardenIds``    (list of allowed domain group IDs pre-auth)
        """
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_ssid_advanced(self, site_id: str, wlan_id: str, ssid_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}",
            cache_ttl=self.config.cache_ttl_config,
        )

    # ── Per-SSID MAC filter (whitelist / blacklist) ─────────────────────────

    async def get_ssid_mac_filter(self, site_id: str, wlan_id: str, ssid_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}/macFilter",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_ssid_mac_filter(
        self,
        site_id: str,
        wlan_id: str,
        ssid_id: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """Update SSID MAC filter.

        ``config``: ``mode`` (disabled|whitelist|blacklist),
        ``macGroupId`` (from list_mac_groups), ``macList`` (inline MACs).
        """
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/wlans/{wlan_id}/ssids/{ssid_id}/macFilter",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── Surveillance VLAN (auto-tag camera OUIs) ────────────────────────────

    async def get_surveillance_vlan_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/surveillanceVlan",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_surveillance_vlan_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``enabled``, ``vlanId``, ``ouiProfileIds``,
        ``priority`` (802.1p)."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/surveillanceVlan",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── Walled garden (captive-portal pre-auth domain whitelist) ────────────

    async def list_walled_garden_entries(
        self, site_id: str, portal_id: str
    ) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/portal/{portal_id}/walledGarden",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_walled_garden_entry(
        self, site_id: str, portal_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``type`` (domain|ip|domainGroup|ipGroup),
        ``value``, ``description``."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/portal/{portal_id}/walledGarden",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_walled_garden_entry(
        self,
        site_id: str,
        portal_id: str,
        entry_id: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/portal/{portal_id}/walledGarden/{entry_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_walled_garden_entry(
        self, site_id: str, portal_id: str, entry_id: str
    ) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/portal/{portal_id}/walledGarden/{entry_id}",
        )
        self._invalidate_on_write()
        return result

    # ── Voucher templates (printable splash branding) ───────────────────────

    async def list_voucher_templates(self, site_id: str, portal_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/portal/{portal_id}/voucher/templates",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_voucher_template(
        self, site_id: str, portal_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``name``, ``logoUrl``, ``headerColor``, ``footerText``,
        ``vouchersPerPage``, ``paperSize``."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/portal/{portal_id}/voucher/templates",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_voucher_template(
        self,
        site_id: str,
        portal_id: str,
        template_id: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/portal/{portal_id}/voucher/templates/{template_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_voucher_template(
        self, site_id: str, portal_id: str, template_id: str
    ) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/portal/{portal_id}/voucher/templates/{template_id}",
        )
        self._invalidate_on_write()
        return result

    # ── Wi-Fi 6E / 6 GHz radio band ─────────────────────────────────────────

    async def update_radio_6ghz(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Configure the 6 GHz radio on an EAP780/AX-style AP. The 5 GHz and
        2.4 GHz radios already have ``update_ap_radio``; this is the new band.

        ``config``: ``enabled``, ``channel`` (auto|N), ``channelWidth``
        (20|40|80|160), ``txPower`` (dBm), ``rrm`` (true|false), ``upcMin``.
        """
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/eaps/{mac}/radios/6g",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── AP locate (blink LED for field tech) ────────────────────────────────

    async def locate_ap(
        self, site_id: str, mac: str, *, duration_seconds: int = 60
    ) -> dict[str, Any]:
        """Make the AP's LED flash for ``duration_seconds`` so a field tech
        can identify it physically."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/eaps/{mac}/locate",
            json_data={"duration": duration_seconds},
        )

    # =========================================================================
    # MILESTONE E — Firmware management
    # =========================================================================
    # The existing client has reboot_device but cannot upgrade firmware. These
    # methods cover per-device upgrade, fleet-wide auto-upgrade schedules, and
    # available-version queries. Operators need this to patch CVEs without
    # dropping into the Omada UI.

    async def get_device_firmware_info(self, site_id: str, mac: str) -> dict[str, Any]:
        """Current firmware + available upgrade for a device.

        Response includes: ``currentVersion``, ``upgradeAvailable``,
        ``latestVersion``, ``releaseNotes``, ``checksum``.
        """
        return await self._request(
            "GET",
            f"/sites/{site_id}/devices/{mac}/firmware",
        )

    async def upgrade_device_firmware(
        self, site_id: str, mac: str, *, version: str | None = None
    ) -> dict[str, Any]:
        """Trigger an immediate firmware upgrade on a device.

        Pass ``version=None`` to pull the latest. Pass an explicit version
        string when staying on a specific train. Operation is async on the
        controller; poll ``get_device_firmware_info`` for completion.
        """
        body: dict[str, Any] = {}
        if version is not None:
            body["version"] = version
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/{mac}/upgrade",
            json_data=body,
        )

    async def upgrade_devices_firmware_batch(
        self, site_id: str, macs: list[str], *, version: str | None = None
    ) -> dict[str, Any]:
        """Upgrade multiple devices in one call. Controller queues them
        internally and reports progress via the events stream."""
        body: dict[str, Any] = {"macList": macs}
        if version is not None:
            body["version"] = version
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/batch/upgrade",
            json_data=body,
        )

    async def get_available_firmware(
        self, site_id: str, model: str | None = None
    ) -> list[dict[str, Any]]:
        """List firmware images available for adopted devices on this site.

        ``model`` filters to a specific hardware model (e.g. ``EAP670``).
        """
        params = {"model": model} if model else None
        data = await self._request(
            "GET",
            f"/sites/{site_id}/firmware/available",
            params=params,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def list_firmware_upgrade_schedules(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/firmwareUpgradeSchedule",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_firmware_upgrade_schedule(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Create an auto-upgrade schedule.

        ``config``: ``name``, ``deviceModels`` (list, or ``["all"]``),
        ``deviceMacs`` (list, optional explicit set), ``cron`` or
        ``recurrence`` (``daily|weekly|monthly``), ``timeOfDay``, ``timezone``,
        ``stableOnly`` (true|false), ``maintenanceWindowMinutes``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/firmwareUpgradeSchedule",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_firmware_upgrade_schedule(
        self, site_id: str, schedule_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/firmwareUpgradeSchedule/{schedule_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_firmware_upgrade_schedule(
        self, site_id: str, schedule_id: str
    ) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/firmwareUpgradeSchedule/{schedule_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_firmware_upgrade_history(
        self, site_id: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Recent firmware upgrade attempts (success/fail/in-progress)."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/firmwareUpgradeHistory",
            params={"limit": limit},
        )
        return data if isinstance(data, list) else data.get("data", [])

    # =========================================================================
    # MILESTONE F — Insights / Analytics
    # =========================================================================
    # The dashboard widgets shipped in v2.6.0 need richer feed data. Today we
    # only have channel utilization and a basic events feed. These add per-app
    # traffic stats, top talkers, historical session data, and RF heatmap.

    async def get_app_traffic_stats(
        self,
        site_id: str,
        *,
        period: str = "1h",
        top_n: int = 10,
    ) -> list[dict[str, Any]]:
        """Per-application bytes sent/received for the most recent ``period``.

        ``period``: ``1h|24h|7d|30d``. Returns top ``top_n`` by volume.
        """
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/appStat",
            params={"period": period, "topN": top_n},
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_app_traffic_history(
        self,
        site_id: str,
        app_id: str,
        *,
        granularity: str = "hour",
        period: str = "24h",
    ) -> list[dict[str, Any]]:
        """Time-series data for a specific app over ``period``."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/appStat/history",
            params={
                "appId": app_id,
                "granularity": granularity,
                "period": period,
            },
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_top_talkers(
        self,
        site_id: str,
        *,
        period: str = "1h",
        top_n: int = 10,
        kind: str = "client",
    ) -> list[dict[str, Any]]:
        """Top-N traffic generators.

        ``kind``: ``client`` (per device) | ``ssid`` | ``ap``.
        """
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/{kind}Stat",
            params={"period": period, "topN": top_n, "sort": "trafficDesc"},
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_past_connections(
        self,
        site_id: str,
        *,
        client_mac: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Historical client connections (associate/disconnect events)."""
        params: dict[str, Any] = {"limit": limit}
        if client_mac is not None:
            params["clientMac"] = client_mac
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/pastConn",
            params=params,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_rf_heatmap(self, site_id: str) -> dict[str, Any]:
        """RF coverage map for the site (per-AP RSSI grid)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/insight/rfHeatmap",
        )

    async def get_wifi_survey(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        """On-demand survey of nearby BSSIDs/channels from one AP."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/wifiSurvey/{mac}",
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_anomalies(self, site_id: str, *, period: str = "24h") -> list[dict[str, Any]]:
        """Omada v6 AI-flagged anomalies (traffic spikes, RF interference,
        connect failures clustered above baseline)."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/anomaly",
            params={"period": period},
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_ai_suggestions(self, site_id: str) -> list[dict[str, Any]]:
        """Controller-generated optimisation suggestions (channel changes,
        radio power tweaks, security warnings)."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/aiSuggestions",
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_mesh_topology_tree(self, site_id: str) -> dict[str, Any]:
        """Logical mesh tree: root APs + child uplinks. Distinct from the
        L2 network topology already exposed via ``get_devices_with_topology``."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/insight/meshTopology",
        )

    async def get_cable_diag_history(
        self, site_id: str, mac: str, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Past cable test results for a switch (vs. live ``run_cable_test``)."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/cableDiagHistory/{mac}",
            params={"limit": limit},
        )
        return data if isinstance(data, list) else data.get("data", [])

    # =========================================================================
    # CROSS-CUTTING — Switch features
    # =========================================================================
    # Filling out switch-side gaps: voice VLAN, DHCP relay, storm control,
    # jumbo frames, ARP inspection, port-based 802.1X (per-port, distinct
    # from the existing site-level dot1x), MAC-based auth.

    # ── Voice VLAN (auto-tag IP phones via OUI) ─────────────────────────────

    async def get_voice_vlan_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/voiceVlan",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_voice_vlan_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``enabled``, ``vlanId``, ``priority`` (0-7),
        ``ouiProfileIds`` (from list_oui_profiles)."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/voiceVlan",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── DHCP Relay (forward DHCP to upstream server) ────────────────────────

    async def get_dhcp_relay_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/dhcpRelay",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_dhcp_relay_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``enabled``, ``servers`` (list of upstream IPs),
        ``circuitId``, ``insertOption82``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/dhcpRelay",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── Storm control (per-switch) ──────────────────────────────────────────

    async def get_switch_storm_control(self, site_id: str, mac: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/stormControl",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_storm_control(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Per-port storm control thresholds. ``config``: ``ports`` (list of
        ``{portId, broadcastPps, multicastPps, unknownUnicastPps, action}``)."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/stormControl",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── Jumbo frames ────────────────────────────────────────────────────────

    async def get_switch_jumbo_frame(self, site_id: str, mac: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/jumboFrame",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_jumbo_frame(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``enabled``, ``mtu`` (e.g. 9216)."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/jumboFrame",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── ARP inspection (DAI) ────────────────────────────────────────────────

    async def get_switch_arp_inspection(self, site_id: str, mac: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/arpInspection",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_arp_inspection(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``enabled``, ``trustedPorts`` (list), ``rateLimitPps``,
        ``logViolations``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/arpInspection",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── Port-based 802.1X (per-port, vs site-level) ────────────────────────

    async def get_port_dot1x_config(self, site_id: str, mac: str, port_id: int) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/ports/{port_id}/dot1x",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_port_dot1x_config(
        self, site_id: str, mac: str, port_id: int, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``enabled``, ``mode`` (single|multi|both),
        ``radiusProfileId``, ``guestVlanId``, ``authVlanId``, ``failVlanId``,
        ``reauthIntervalSec``, ``maxReauthAttempts``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/ports/{port_id}/dot1x",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── MAC-based authentication ────────────────────────────────────────────

    async def get_port_mac_auth_config(
        self, site_id: str, mac: str, port_id: int
    ) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/ports/{port_id}/macAuth",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_port_mac_auth_config(
        self, site_id: str, mac: str, port_id: int, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``enabled``, ``radiusProfileId``, ``passwordFormat``
        (mac|custom), ``customPassword``, ``reauthIntervalSec``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/ports/{port_id}/macAuth",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # =========================================================================
    # CROSS-CUTTING — Routing + Bandwidth
    # =========================================================================

    # ── Policy-based routing (the closest Omada gets to SD-WAN) ─────────────

    async def list_policy_routes(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/transmission/policyRouting",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_policy_route(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Create a PBR rule.

        ``config``: ``name``, ``sourceType``, ``sourceId``, ``destType``,
        ``destId``, ``protocol``, ``portRange``, ``wanInterface`` (wan1|wan2|
        loadBalance), ``priority``, ``enabled``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/transmission/policyRouting",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_policy_route(
        self, site_id: str, rule_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/transmission/policyRouting/{rule_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_policy_route(self, site_id: str, rule_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/transmission/policyRouting/{rule_id}",
        )
        self._invalidate_on_write()
        return result

    # ── OSPF ────────────────────────────────────────────────────────────────

    async def get_ospf_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/routing/ospf",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_ospf_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``enabled``, ``routerId``, ``areas`` (list of
        ``{areaId, type, networks, authMode, authKey}``), ``redistribute``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/routing/ospf",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_ospf_neighbors(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/routing/ospf/neighbors",
        )
        return data if isinstance(data, list) else data.get("data", [])

    # ── RIP ─────────────────────────────────────────────────────────────────

    async def get_rip_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/routing/rip",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_rip_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``enabled``, ``version`` (1|2), ``networks``,
        ``authMode``, ``redistribute``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/routing/rip",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── Bandwidth control (per-IP / per-VLAN gateway rate caps) ─────────────

    async def list_bandwidth_control_rules(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/transmission/bandwidthControl",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_bandwidth_control_rule(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a bandwidth control rule.

        ``config``: ``name``, ``targetType`` (ip|ipGroup|vlan|all),
        ``targetId``, ``downKbps``, ``upKbps``, ``priority``, ``enabled``.
        """
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/transmission/bandwidthControl",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_bandwidth_control_rule(
        self, site_id: str, rule_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/transmission/bandwidthControl/{rule_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_bandwidth_control_rule(self, site_id: str, rule_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/transmission/bandwidthControl/{rule_id}",
        )
        self._invalidate_on_write()
        return result

    # ── Multi-WAN policy: weighted load-balance + link-backup mode ──────────

    async def update_wan_link_backup(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """Beyond the existing failover/load-balance toggle, this configures
        weighted distribution + primary/secondary roles.

        ``config``: ``mode`` (loadBalance|primaryBackup), ``primaryWan``,
        ``backupWan``, ``weights`` (``{wan1: 60, wan2: 40}``),
        ``failoverHealthCheck`` (``{enabled, target, intervalSec, retries}``).
        """
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/wan/linkBackup",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ── DHCP options (43, 60, 82, 138, custom) ──────────────────────────────

    async def update_network_dhcp_options(
        self, site_id: str, network_id: str, options: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Set DHCP options on a LAN/VLAN.

        ``options``: list of ``{code, type, value}``. Common:
          - 43 (vendor-specific, e.g. AP zero-touch URLs)
          - 60 (vendor class identifier)
          - 66 (TFTP server)
          - 138 (CAPWAP AP controller)
          - 150 (TFTP servers, VoIP)
        """
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/lan/{network_id}",
            json_data={"dhcpOptions": options},
        )
        self._invalidate_on_write()
        return result

    # =========================================================================
    # MILESTONE G — Open API client (OAuth2 /openapi/v1/...)
    # =========================================================================
    # Omada v5.12+ exposes an OFFICIAL, documented API at /openapi/v1/...
    # secured by OAuth2 client-credentials. The current client uses the
    # reverse-engineered v2 web-UI API which can break across controller
    # upgrades. The Open API is stable and forward-compatible.
    #
    # Strategy: Open API is layered ALONGSIDE the v2 client — not a
    # replacement. Each Open API call uses its own token/refresh flow. We
    # gate routes behind a feature-flag so production callers can opt in.
    #
    # The full Open API surface mirrors the v2 surface but with different
    # paths. Today we expose just the bootstrap (token + introspect + sites)
    # so the migration path is real but progressive — adapters can move
    # individual methods over as the Open API matures.

    async def open_api_get_token(self, *, client_id: str, client_secret: str) -> dict[str, Any]:
        """Obtain a bearer token via OAuth2 client-credentials.

        The Open API authorize endpoint sits at the controller root, NOT
        under ``/api/v2/...``. Use a one-shot httpx call rather than
        ``self._request`` so we don't re-enter the v2 cookie-auth flow.

        Returns ``{accessToken, refreshToken, expiresInSec, tokenType}``.
        """
        await self._ensure_session()
        if not self._http:
            raise OmadaConnectionError("HTTP client is not initialized")

        url = f"{self.config.base_url.rstrip('/')}/openapi/authorize/token"
        body = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        resp = await self._http.post(
            url,
            params={"grant_type": "client_credentials"},
            json=body,
        )
        resp.raise_for_status()
        payload = resp.json()
        # Both wrapped and unwrapped responses occur in the wild.
        return payload.get("result", payload)

    async def open_api_refresh_token(
        self,
        *,
        client_id: str,
        client_secret: str,
        refresh_token: str,
    ) -> dict[str, Any]:
        """Refresh an Open API access token without re-authenticating."""
        await self._ensure_session()
        if not self._http:
            raise OmadaConnectionError("HTTP client is not initialized")

        url = f"{self.config.base_url.rstrip('/')}/openapi/authorize/token"
        body = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
        }
        resp = await self._http.post(url, json=body)
        resp.raise_for_status()
        payload = resp.json()
        return payload.get("result", payload)

    async def open_api_get_sites(
        self, *, access_token: str, page: int = 1, page_size: int = 100
    ) -> list[dict[str, Any]]:
        """List sites via the documented Open API. Useful as a probe to
        confirm the OAuth2 token works before migrating any reads."""
        await self._ensure_session()
        if not self._http:
            raise OmadaConnectionError("HTTP client is not initialized")

        url = f"{self.config.base_url.rstrip('/')}/openapi/v1/sites"
        resp = await self._http.get(
            url,
            params={"page": page, "pageSize": page_size},
            headers={"Authorization": f"AccessToken={access_token}"},
        )
        resp.raise_for_status()
        payload = resp.json()
        result = payload.get("result", payload)
        if isinstance(result, dict):
            return result.get("data", [])
        return result if isinstance(result, list) else []

    async def open_api_introspect(self, *, access_token: str) -> dict[str, Any]:
        """Inspect a token's scopes + remaining lifetime (debugging aid)."""
        await self._ensure_session()
        if not self._http:
            raise OmadaConnectionError("HTTP client is not initialized")

        url = f"{self.config.base_url.rstrip('/')}/openapi/authorize/introspect"
        resp = await self._http.post(
            url,
            json={"access_token": access_token},
        )
        resp.raise_for_status()
        payload = resp.json()
        return payload.get("result", payload)

    # =========================================================================
    # ENTERPRISE COMPLETION — covers the remaining Omada surface
    # =========================================================================
    # Methods below fill in the rest of what an enterprise operator
    # would expect: bulk operations, controller/system management,
    # switch advanced (sFlow / mirror sessions / QinQ / PoE budget),
    # WiFi WIDS-WIPS / mesh detail / regulatory domain, hotspot
    # operator accounts / SMS / free-auth, advanced routing (VRRP /
    # IPv6 / BGP), site time / NTP / notifications, site cloning,
    # reboot schedules, and a final raw-passthrough escape hatch.

    # ─────────────────────────────────────────────────────────────────
    # BULK operations on devices (across an entire site)
    # ─────────────────────────────────────────────────────────────────

    async def bulk_adopt_devices(self, site_id: str, macs: list[str]) -> dict[str, Any]:
        """Adopt many discovered devices in one call. Returns a summary
        with per-mac success/failure."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/batch/adopt",
            json_data={"macList": macs},
        )

    async def bulk_forget_devices(self, site_id: str, macs: list[str]) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/batch/forget",
            json_data={"macList": macs},
        )

    async def bulk_reboot_devices(self, site_id: str, macs: list[str]) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/batch/reboot",
            json_data={"macList": macs},
        )

    async def bulk_move_devices_to_site(
        self,
        site_id: str,
        macs: list[str],
        *,
        target_site_id: str,
    ) -> dict[str, Any]:
        """Move N devices from this site to ``target_site_id`` (Omada
        site rebalancing without losing adoption state)."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/batch/moveSite",
            json_data={"macList": macs, "targetSiteId": target_site_id},
        )

    async def bulk_factory_reset_devices(self, site_id: str, macs: list[str]) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/batch/factoryReset",
            json_data={"macList": macs},
        )

    async def bulk_locate_devices(
        self, site_id: str, macs: list[str], *, duration_seconds: int = 60
    ) -> dict[str, Any]:
        """Make every selected device's LED flash for N seconds."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/devices/batch/locate",
            json_data={"macList": macs, "duration": duration_seconds},
        )

    async def bulk_set_ssid_state(
        self, site_id: str, ssid_ids: list[str], *, enabled: bool
    ) -> dict[str, Any]:
        """Enable or disable a list of SSIDs in one call."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/wlans/ssids/batch/state",
            json_data={"ssidIds": ssid_ids, "enabled": enabled},
        )

    async def bulk_block_clients(self, site_id: str, macs: list[str]) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/clients/batch/block",
            json_data={"macList": macs},
        )

    async def bulk_unblock_clients(self, site_id: str, macs: list[str]) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/clients/batch/unblock",
            json_data={"macList": macs},
        )

    async def bulk_kick_clients(self, site_id: str, macs: list[str]) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/clients/batch/kick",
            json_data={"macList": macs},
        )

    # ─────────────────────────────────────────────────────────────────
    # SITE cloning + templates
    # ─────────────────────────────────────────────────────────────────

    async def clone_site(
        self,
        source_site_id: str,
        *,
        new_name: str,
        copy_devices: bool = False,
    ) -> dict[str, Any]:
        """Create a new site from this one. ``copy_devices=False`` only
        clones the configuration; True attempts to re-adopt them."""
        return await self._request(
            "POST",
            f"/sites/{source_site_id}/cmd/clone",
            json_data={"name": new_name, "copyDevices": copy_devices},
        )

    async def export_site_template(self, site_id: str, *, name: str) -> dict[str, Any]:
        """Save the current site config as a reusable template."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/exportTemplate",
            json_data={"name": name},
        )

    async def list_site_templates(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/setting/siteTemplates")
        return data if isinstance(data, list) else data.get("data", [])

    async def apply_site_template(self, site_id: str, *, template_id: str) -> dict[str, Any]:
        """Apply a saved template to an existing site (overlay-style)."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/applyTemplate",
            json_data={"templateId": template_id},
        )

    async def delete_site_template(self, template_id: str) -> dict[str, Any]:
        return await self._request(
            "DELETE",
            f"/setting/siteTemplates/{template_id}",
        )

    # ─────────────────────────────────────────────────────────────────
    # CONTROLLER / SYSTEM management
    # ─────────────────────────────────────────────────────────────────

    async def list_controller_backups(self) -> list[dict[str, Any]]:
        """List controller-level config backups stored on the controller."""
        data = await self._request("GET", "/cmd/backup")
        return data if isinstance(data, list) else data.get("data", [])

    async def download_controller_backup(self, backup_id: str) -> bytes:
        """Stream a controller backup to bytes (caller saves to disk)."""
        await self._ensure_session()
        if not self._http:
            raise OmadaConnectionError("HTTP client not initialized")
        url = self._api_path(f"/cmd/backup/{backup_id}/download")
        resp = await self._http.get(url)
        resp.raise_for_status()
        return resp.content

    async def restore_controller_backup(self, backup_id: str) -> dict[str, Any]:
        """Restore from a previously created backup. Triggers a controller
        restart — handle the disconnect."""
        return await self._request("POST", f"/cmd/backup/{backup_id}/restore")

    async def delete_controller_backup(self, backup_id: str) -> dict[str, Any]:
        return await self._request("DELETE", f"/cmd/backup/{backup_id}")

    async def get_controller_smtp_config(self) -> dict[str, Any]:
        """SMTP server settings for outbound notification email."""
        return await self._request("GET", "/setting/system/email")

    async def update_controller_smtp_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``server``, ``port``, ``security`` (none|tls|starttls),
        ``username``, ``password``, ``fromAddress``, ``replyTo``."""
        result = await self._request("PUT", "/setting/system/email", json_data=config)
        self._invalidate_on_write()
        return result

    async def test_controller_smtp(self, recipient: str) -> dict[str, Any]:
        """Send a probe email to ``recipient`` — verifies SMTP works."""
        return await self._request(
            "POST",
            "/cmd/system/email/test",
            json_data={"recipient": recipient},
        )

    async def get_controller_notification_settings(self) -> dict[str, Any]:
        return await self._request("GET", "/setting/system/notifications")

    async def update_controller_notification_settings(
        self, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: per-event-class subscription map +
        ``recipients`` (list of emails / webhook URLs)."""
        result = await self._request("PUT", "/setting/system/notifications", json_data=config)
        self._invalidate_on_write()
        return result

    async def get_controller_ssl_cert(self) -> dict[str, Any]:
        return await self._request("GET", "/setting/system/sslCert")

    async def upload_controller_ssl_cert(
        self,
        *,
        cert_pem: str,
        key_pem: str,
        ca_chain_pem: str | None = None,
    ) -> dict[str, Any]:
        """Replace the controller's HTTPS cert. Triggers a brief
        listener restart."""
        body: dict[str, Any] = {"cert": cert_pem, "key": key_pem}
        if ca_chain_pem is not None:
            body["caChain"] = ca_chain_pem
        result = await self._request("PUT", "/setting/system/sslCert", json_data=body)
        self._invalidate_on_write()
        return result

    async def get_controller_admins(self) -> list[dict[str, Any]]:
        """Local admin accounts on the controller (separate from FreeSDN)."""
        data = await self._request("GET", "/users")
        return data if isinstance(data, list) else data.get("data", [])

    async def create_controller_admin(self, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``username``, ``password``, ``email``, ``role``
        (admin|viewer|operator), ``sites`` (scope list)."""
        result = await self._request("POST", "/users", json_data=config)
        self._invalidate_on_write()
        return result

    async def update_controller_admin(self, user_id: str, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request("PATCH", f"/users/{user_id}", json_data=config)
        self._invalidate_on_write()
        return result

    async def delete_controller_admin(self, user_id: str) -> dict[str, Any]:
        result = await self._request("DELETE", f"/users/{user_id}")
        self._invalidate_on_write()
        return result

    async def get_controller_global_settings(self) -> dict[str, Any]:
        """Controller-wide preferences: language, theme, login banner,
        session timeout, idle timeout, log retention, etc."""
        return await self._request("GET", "/setting/global")

    async def update_controller_global_settings(self, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request("PUT", "/setting/global", json_data=config)
        self._invalidate_on_write()
        return result

    async def get_controller_maintenance_window(self) -> dict[str, Any]:
        return await self._request("GET", "/setting/system/maintenance")

    async def update_controller_maintenance_window(self, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``enabled``, ``cron``, ``durationMinutes``,
        ``actions`` (list: firmware|reboot|both)."""
        result = await self._request("PUT", "/setting/system/maintenance", json_data=config)
        self._invalidate_on_write()
        return result

    async def get_cloud_access_status(self) -> dict[str, Any]:
        """Whether the controller is bonded to TP-Link Cloud, status,
        cloud-user assignments."""
        return await self._request("GET", "/setting/cloudAccess")

    async def update_cloud_access(self, config: dict[str, Any]) -> dict[str, Any]:
        result = await self._request("PUT", "/setting/cloudAccess", json_data=config)
        self._invalidate_on_write()
        return result

    # ─────────────────────────────────────────────────────────────────
    # SITE-level system: NTP / time / LED schedule / reboot schedule
    # ─────────────────────────────────────────────────────────────────

    async def get_site_time_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/time",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_site_time_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``timezone`` (Olson), ``ntpServers`` (list of host),
        ``manualTime`` (epoch seconds, used when ``mode=manual``),
        ``mode`` (auto|manual)."""
        result = await self._request("PUT", f"/sites/{site_id}/setting/time", json_data=config)
        self._invalidate_on_write()
        return result

    async def get_led_schedule(self, site_id: str) -> dict[str, Any]:
        """Site-wide LED on/off schedule (applied to all APs/switches)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/ledSchedule",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_led_schedule(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``enabled``, ``timeRangeId``, ``ledOn`` (in-window
        behavior, on|off|blink)."""
        result = await self._request(
            "PUT", f"/sites/{site_id}/setting/ledSchedule", json_data=config
        )
        self._invalidate_on_write()
        return result

    async def list_reboot_schedules(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/rebootSchedule",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_reboot_schedule(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``name``, ``cron``, ``deviceMacs`` (or
        ``deviceModels``), ``timezone``, ``maintenanceWindowMinutes``."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/rebootSchedule",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_reboot_schedule(
        self, site_id: str, schedule_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/rebootSchedule/{schedule_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_reboot_schedule(self, site_id: str, schedule_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/rebootSchedule/{schedule_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_site_notifications_subscription(self, site_id: str) -> dict[str, Any]:
        """Per-site subscription to controller-level notification classes."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/notifications",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_site_notifications_subscription(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/notifications",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ─────────────────────────────────────────────────────────────────
    # SWITCH advanced: sFlow, mirror sessions, LLDP-MED, QinQ,
    # per-port jumbo, PoE budget
    # ─────────────────────────────────────────────────────────────────

    async def get_switch_sflow_config(self, site_id: str, mac: str) -> dict[str, Any]:
        """sFlow agent config (collector IP, sampling rate, polling)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/sflow",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_sflow_config(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``enabled``, ``collectorIp``, ``collectorPort``,
        ``samplingRate``, ``pollingIntervalSec``, ``ports`` (list)."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/sflow",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def list_switch_mirror_sessions(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        """Multi-session port-mirror config (vs. the older single-session
        ``get_switch_mirror_config``)."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/mirrorSessions",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_switch_mirror_session(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``sessionId``, ``sourcePorts`` (list with direction
        rx|tx|both), ``destinationPort``, ``mode`` (local|rspan)."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/switch/{mac}/mirrorSessions",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_switch_mirror_session(
        self,
        site_id: str,
        mac: str,
        session_id: str,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/switch/{mac}/mirrorSessions/{session_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_switch_mirror_session(
        self, site_id: str, mac: str, session_id: str
    ) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/switch/{mac}/mirrorSessions/{session_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_switch_lldp_med_config(self, site_id: str, mac: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/lldpMed",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_lldp_med_config(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """LLDP-MED extensions (PoE+ negotiation, voice VLAN advertise)."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/lldpMed",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_switch_qinq_config(self, site_id: str, mac: str) -> dict[str, Any]:
        """802.1ad Q-in-Q (provider VLAN tag stacking)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/qinq",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_qinq_config(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/qinq",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_switch_per_port_jumbo(
        self, site_id: str, mac: str, port_id: int
    ) -> dict[str, Any]:
        """Per-port jumbo-frame override (vs. the switch-global setting)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/ports/{port_id}/jumboFrame",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_per_port_jumbo(
        self,
        site_id: str,
        mac: str,
        port_id: int,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/ports/{port_id}/jumboFrame",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_switch_poe_budget(self, site_id: str, mac: str) -> dict[str, Any]:
        """PoE budget allocation: total wattage, used, per-port reservations."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/poeBudget",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_poe_budget(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``perPortReservations`` (list of {portId, watts}),
        ``priorityMode`` (firstCome|highPriorityFirst)."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/poeBudget",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_switch_voice_vlan_per_switch(self, site_id: str, mac: str) -> dict[str, Any]:
        """Voice VLAN per-switch override (vs. the site-level config)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/voiceVlan",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_voice_vlan_per_switch(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/voiceVlan",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_switch_mstp_config(self, site_id: str, mac: str) -> dict[str, Any]:
        """Multiple Spanning Tree (802.1s) — per-instance config."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/switch/{mac}/mstp",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_switch_mstp_config(
        self, site_id: str, mac: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``enabled``, ``regionName``, ``revision``,
        ``instances`` (list of {instanceId, vlans, priority, rootPort})."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/switch/{mac}/mstp",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # ─────────────────────────────────────────────────────────────────
    # WiFi: WIDS/WIPS, mesh detail, regulatory domain, DFS
    # ─────────────────────────────────────────────────────────────────

    async def get_wids_wips_config(self, site_id: str) -> dict[str, Any]:
        """Wireless intrusion detection / prevention configuration."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wireless/widsWips",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_wids_wips_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: per-attack toggles (deauth flood, beacon flood,
        karma, evil twin, ...) + ``mode`` (detect|prevent)."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/wireless/widsWips",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_wids_wips_events(self, site_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/wireless/widsWipsEvents",
            params={"limit": limit},
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_mesh_detail_config(self, site_id: str) -> dict[str, Any]:
        """Mesh tuning: max hops, root selection, RSSI thresholds."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wireless/mesh",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_mesh_detail_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``enabled``, ``rootSelection`` (auto|manual),
        ``rootMacs``, ``maxHops``, ``meshOnlyApMacs``, ``minLinkRssi``,
        ``autoFailoverThreshold``, ``failoverGraceSec``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/wireless/mesh",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_regulatory_domain(self, site_id: str) -> dict[str, Any]:
        """Country code / regulatory domain (per site)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wireless/regulatory",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_regulatory_domain(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``country`` (ISO 3166), ``allowDfs``, ``allowOutdoor``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/wireless/regulatory",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_dfs_config(self, site_id: str) -> dict[str, Any]:
        """DFS (Dynamic Frequency Selection) on 5 GHz radar bands."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wireless/dfs",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_dfs_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``enabled``, ``preferDfsChannels``,
        ``dfsHoldOffMinutes``, ``radarDetectionAction``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/wireless/dfs",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_channel_pilot_schedule(self, site_id: str) -> dict[str, Any]:
        """Auto-pilot channel scanning schedule (when to redo channel
        selection across the fleet)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/wireless/channelPilot",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_channel_pilot_schedule(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/wireless/channelPilot",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def trigger_channel_optimization(self, site_id: str) -> dict[str, Any]:
        """Force an immediate channel-pilot run across the site."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/wireless/channelPilot/run",
        )

    # ─────────────────────────────────────────────────────────────────
    # HOTSPOT: operator accounts, SMS, form-auth, free-auth policies
    # ─────────────────────────────────────────────────────────────────

    async def list_hotspot_operators(self, site_id: str) -> list[dict[str, Any]]:
        """Hotspot operator accounts (separate from controller admins —
        can issue vouchers but not change site config)."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/hotspot/operators",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_hotspot_operator(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``username``, ``password``, ``portalIds`` (scope),
        ``permissions`` (issueVouchers|viewLogs|extendVouchers|...)."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/hotspot/operators",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_hotspot_operator(
        self, site_id: str, operator_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/hotspot/operators/{operator_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_hotspot_operator(self, site_id: str, operator_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/hotspot/operators/{operator_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_sms_gateway_config(self, site_id: str) -> dict[str, Any]:
        """SMS provider settings used for SMS-auth captive portals."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/hotspot/smsGateway",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_sms_gateway_config(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``provider`` (twilio|aliyun|nexmo|...), ``apiKey``,
        ``apiSecret``, ``fromNumber``, ``messageTemplate``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/hotspot/smsGateway",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def test_sms_gateway(
        self, site_id: str, *, recipient: str, message: str
    ) -> dict[str, Any]:
        """Send a probe SMS to ``recipient``."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/hotspot/smsGateway/test",
            json_data={"recipient": recipient, "message": message},
        )

    async def get_form_auth_fields(self, site_id: str, portal_id: str) -> list[dict[str, Any]]:
        """Custom form fields the captive-portal splash page asks for."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/portal/{portal_id}/formFields",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def update_form_auth_fields(
        self, site_id: str, portal_id: str, fields: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """``fields``: ordered list of ``{name, label, type
        (text|email|tel|select|checkbox), required, options[]}``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/portal/{portal_id}/formFields",
            json_data={"fields": fields},
        )
        self._invalidate_on_write()
        return result

    async def list_free_auth_policies(self, site_id: str) -> list[dict[str, Any]]:
        """Pre-auth pass-through rules — like walled garden but for
        groups of clients (e.g. employees) that bypass the portal."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/portal/freeAuthPolicies",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_free_auth_policy(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``name``, ``sourceType`` (mac|macGroup|ipGroup|all),
        ``sourceId``, ``destType``, ``destId``, ``protocol``, ``ports``."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/portal/freeAuthPolicies",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_free_auth_policy(
        self, site_id: str, policy_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/portal/freeAuthPolicies/{policy_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_free_auth_policy(self, site_id: str, policy_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/portal/freeAuthPolicies/{policy_id}",
        )
        self._invalidate_on_write()
        return result

    # ─────────────────────────────────────────────────────────────────
    # ADVANCED routing: VRRP / HA, static IPv6, BGP
    # ─────────────────────────────────────────────────────────────────

    async def get_vrrp_config(self, site_id: str) -> dict[str, Any]:
        """Virtual Router Redundancy Protocol — for HA gateway pairs."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/routing/vrrp",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_vrrp_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``enabled``, ``groups`` (list of {id, virtualIp,
        priority, advertInterval, authMode, authKey, preempt})."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/routing/vrrp",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def list_static_ipv6_routes(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/setting/routing/staticIpv6",
            cache_ttl=self.config.cache_ttl_config,
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def create_static_ipv6_route(
        self, site_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """``config``: ``name``, ``destinationCidr``, ``nextHop``,
        ``interface``, ``metric``, ``enabled``."""
        result = await self._request(
            "POST",
            f"/sites/{site_id}/setting/routing/staticIpv6",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def update_static_ipv6_route(
        self, site_id: str, route_id: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        result = await self._request(
            "PATCH",
            f"/sites/{site_id}/setting/routing/staticIpv6/{route_id}",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def delete_static_ipv6_route(self, site_id: str, route_id: str) -> dict[str, Any]:
        result = await self._request(
            "DELETE",
            f"/sites/{site_id}/setting/routing/staticIpv6/{route_id}",
        )
        self._invalidate_on_write()
        return result

    async def get_bgp_config(self, site_id: str) -> dict[str, Any]:
        """BGP config (Omada gateways with ER/ER-X firmware)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/routing/bgp",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_bgp_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``enabled``, ``asn``, ``routerId``, ``neighbors``
        (list of {peerIp, remoteAsn, password, holdTimer, keepalive,
        importPolicy, exportPolicy}), ``redistribute``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/routing/bgp",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_bgp_neighbors(self, site_id: str) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/routing/bgp/neighbors",
        )
        return data if isinstance(data, list) else data.get("data", [])

    async def get_routing_table(
        self, site_id: str, *, family: str = "ipv4"
    ) -> list[dict[str, Any]]:
        """Snapshot of the gateway's active routing table (RIB)."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/routing/table",
            params={"family": family},
        )
        return data if isinstance(data, list) else data.get("data", [])

    # ─────────────────────────────────────────────────────────────────
    # Speed test, ALG verbs, advanced gateway features
    # ─────────────────────────────────────────────────────────────────

    async def run_gateway_speed_test(self, site_id: str, mac: str) -> dict[str, Any]:
        """Trigger a one-shot speed test from the gateway WAN."""
        return await self._request(
            "POST",
            f"/sites/{site_id}/cmd/gateways/{mac}/speedTest",
        )

    async def get_gateway_speed_test_result(self, site_id: str, mac: str) -> dict[str, Any]:
        """Last speed test result (download Mbps, upload Mbps, ping ms)."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/insight/gateways/{mac}/speedTestResult",
        )

    async def get_gateway_session_stats(self, site_id: str, mac: str) -> dict[str, Any]:
        """Active NAT session count, pps, top destinations."""
        return await self._request(
            "GET",
            f"/sites/{site_id}/insight/gateways/{mac}/sessions",
        )

    async def get_gateway_active_sessions(
        self, site_id: str, mac: str, *, limit: int = 200
    ) -> list[dict[str, Any]]:
        """Detailed connection table: src/dst/proto/state/age."""
        data = await self._request(
            "GET",
            f"/sites/{site_id}/insight/gateways/{mac}/sessions/list",
            params={"limit": limit},
        )
        return data if isinstance(data, list) else data.get("data", [])

    # ─────────────────────────────────────────────────────────────────
    # SNMP / Syslog forwarding (controller-level monitoring agents)
    # ─────────────────────────────────────────────────────────────────

    async def get_snmp_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/monitoring/snmp",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_snmp_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``enabled``, ``version`` (v2c|v3), ``community``,
        ``v3Users`` (list), ``trapServers`` (list), ``contact``,
        ``location``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/monitoring/snmp",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    async def get_syslog_config(self, site_id: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/sites/{site_id}/setting/monitoring/syslog",
            cache_ttl=self.config.cache_ttl_config,
        )

    async def update_syslog_config(self, site_id: str, config: dict[str, Any]) -> dict[str, Any]:
        """``config``: ``enabled``, ``servers`` (list of {host, port,
        protocol, severity, facility}), ``includeAuthEvents``,
        ``includeFirewallEvents``."""
        result = await self._request(
            "PUT",
            f"/sites/{site_id}/setting/monitoring/syslog",
            json_data=config,
        )
        self._invalidate_on_write()
        return result

    # =========================================================================
    # RAW PASSTHROUGH — escape hatch for any Omada API we have not typed
    # =========================================================================
    # The Omada Controller surface evolves faster than we can wrap it.
    # Operators who need an endpoint not exposed by a typed method can
    # call ``raw_call(method, path, body=...)`` and get the result.
    # The wrapper still goes through our auth + retry + reauth layer
    # so callers do not have to manage the cookie themselves.
    #
    # This is intentionally narrowly typed — body and response are both
    # ``dict | list`` with no schema validation. A real production caller
    # should validate the response shape with their own Pydantic model.

    async def raw_call(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | list[Any] | None = None,
        cache_ttl: int | None = None,
    ) -> Any:
        """Direct Omada v2 API call.

        ``path`` is relative to the controller's API root (e.g.
        ``/sites/{siteId}/setting/foo/bar``). The wrapper handles auth,
        retry on 401, and the standard response envelope unwrap.

        Examples::

            # GET an unwrapped endpoint:
            data = await client.raw_call("GET", f"/sites/{sid}/setting/exotic/v6Feature")

            # POST a config:
            await client.raw_call(
                "POST",
                f"/sites/{sid}/setting/foo/bar",
                body={"enabled": True, "name": "x"},
            )

        For unsupported methods (anything other than GET/POST/PUT/PATCH/
        DELETE) raise ``ValueError`` immediately so we don't open holes.
        """
        method_upper = method.upper()
        if method_upper not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            raise ValueError(f"raw_call only supports GET/POST/PUT/PATCH/DELETE; got {method!r}")
        # Normalise leading slash for callers
        if not path.startswith("/"):
            path = "/" + path
        # GET requests can opt into the existing cache layer.
        # ``body`` may legitimately be a JSON array (some Omada endpoints take
        # a top-level list, e.g. bulk port/setting payloads). httpx's ``json=``
        # serialises both dict and list, so forward either rather than silently
        # dropping a list to ``None`` (which would send an empty-body write).
        return await self._request(
            method_upper,
            path,
            params=params,
            json_data=body if isinstance(body, (dict, list)) else None,
            cache_ttl=cache_ttl if method_upper == "GET" else None,
        )

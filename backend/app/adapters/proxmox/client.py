# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Proxmox VE API Client
====================================

Low-level HTTP client for the Proxmox VE REST API.
Supports both API token and ticket-based authentication.

Usage:
    client = ProxmoxClient(host="192.168.1.100", token_id="user@pam!mytoken", token_secret="xxx")
    async with client:
        nodes = await client.get("/nodes")
"""

from __future__ import annotations

import asyncio
import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

from app.adapters.exceptions import AdapterError, AdapterReadOnlyError
from app.adapters.http_utils import CircuitBreaker
from app.adapters.proxmox.constants import (
    API_BASE,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DEFAULT_VERIFY_SSL,
    RATE_LIMIT_CONCURRENT,
)
from app.core.http_client import build_async_client

logger = logging.getLogger(__name__)


# ── Path safety ──────────────────────────────────────────────────────
# Proxmox API paths follow ``/api2/json/<section>/...`` (or are passed
# without the prefix and concatenated by the client). A misuse — for
# example a VM ID that contains ``..`` — would walk the controller
# API surface. Reject any path containing traversal segments or
# control characters before httpx sees it.
_SAFE_PATH_RE = re.compile(r"^/?[A-Za-z0-9_./@:%\-]+/?$")

# percent-encoded traversal payloads (``%2e``, ``%2f``) and
# their uppercase variants must be rejected so a payload that bypasses
# the literal ``..`` / ``/`` filter via URL-encoding can't reach
# httpx — which decodes the path before sending it. Single-dot
# segments (``/foo/./bar``) and repeated slashes (``//``) are also
# rejected as path-normalization tells.
_ENCODED_TRAVERSAL_RE = re.compile(r"%2[eEfF]")
_DOT_SEGMENT_RE = re.compile(r"(^|/)\.(?=/|$)")
_DOUBLE_SLASH_RE = re.compile(r"//")


def _validate_path(path: str) -> None:
    """Reject paths that contain traversal payloads or control chars.

    Proxmox accepts user@realm in URL paths (e.g. ``/access/users/u@pam``)
    so ``@`` and ``%`` are permitted. ``..`` and whitespace / null
    bytes / query smuggling are not. Also rejects percent-encoded
    traversal sequences and dot-segment / repeated-slash normalization
    tells (Item 5).
    """
    if not path or not _SAFE_PATH_RE.match(path):
        raise AdapterError(
            f"unsafe Proxmox API path: {path!r}",
            adapter_id="proxmox",
        )
    if ".." in path:
        raise AdapterError(
            f"path traversal segment in Proxmox API path: {path!r}",
            adapter_id="proxmox",
        )
    if _ENCODED_TRAVERSAL_RE.search(path):
        raise AdapterError(
            f"percent-encoded traversal in Proxmox API path: {path!r}",
            adapter_id="proxmox",
        )
    if _DOUBLE_SLASH_RE.search(path):
        raise AdapterError(
            f"repeated slashes in Proxmox API path: {path!r}",
            adapter_id="proxmox",
        )
    if _DOT_SEGMENT_RE.search(path):
        raise AdapterError(
            f"dot segment in Proxmox API path: {path!r}",
            adapter_id="proxmox",
        )


# ── Read-only gate ───────────────────────────────────────────────────
# Same dual-gate Omada and OPNsense use. A Proxmox cluster has the
# most catastrophic writes in the platform (VM destroy, node shutdown,
# storage volume delete, certificate replace, guest-agent code exec).
# Default-on means every write is refused unless an operator
# explicitly sets ``ADAPTER_READ_ONLY=false`` AND the call passes
# ``force=True`` — same shape as Omada's apply-path.
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _is_adapter_read_only() -> bool:
    """Returns True (default-safe) unless ``ADAPTER_READ_ONLY=false``.

    Per-vendor isolation: Proxmox reads ONLY ``ADAPTER_READ_ONLY``, not the
    legacy ``OMADA_READ_ONLY``. A previous version OR'd both flags, so an
    operator who set ``ADAPTER_READ_ONLY=false`` to enable Proxmox writes was
    still blocked because ``OMADA_READ_ONLY`` defaults True — and the refusal
    message never mentioned it. This matches the OPNsense/pfSense/MikroTik
    gates, which already dropped the cross-vendor OR; Proxmox was missed.
    """
    from app.core.runtime_flags import is_adapter_read_only

    return is_adapter_read_only()


# ── Metric emitters (all best-effort, never raise) ──────────────────


def _record_request_metric(method: str, outcome: str) -> None:
    try:
        from app.core.metrics import adapter_requests_total

        adapter_requests_total.labels(adapter="proxmox", method=method, outcome=outcome).inc()
    except Exception:
        pass


def _record_latency(method: str, latency_seconds: float) -> None:
    try:
        from app.core.metrics import adapter_request_duration

        adapter_request_duration.labels(adapter="proxmox", method=method).observe(latency_seconds)
    except Exception:
        pass


def _record_error(error_type: str) -> None:
    try:
        from app.core.metrics import adapter_errors_total

        adapter_errors_total.labels(adapter="proxmox", error_type=error_type).inc()
    except Exception:
        pass


# ── Connection cache & reachability ───────────────────────────────────────


class _ConnectionCache:
    """Cache authenticated Proxmox clients by (host, port, username) key.

    Entries expire after `ttl` seconds. Thread-safe.
    PDM uses 30s TTL with automatic cleanup.
    """

    def __init__(self, ttl: int = 30, size_threshold: int = 32):
        self._ttl = ttl
        self._size_threshold = size_threshold
        self._cache: dict[str, tuple[float, ProxmoxClient]] = {}
        # threading.Lock is correct here: operations inside the lock are fast
        # dict lookups only (no awaits), and this is called from both sync
        # (Celery tasks) and async (FastAPI) contexts.
        self._lock = threading.Lock()

    def get(self, key: str) -> ProxmoxClient | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry and (time.monotonic() - entry[0]) < self._ttl:
                return entry[1]
            if entry:
                del self._cache[key]
            return None

    def put(self, key: str, client: ProxmoxClient) -> None:
        with self._lock:
            self._cache[key] = (time.monotonic(), client)
            # lazy prune. Walking the entire cache on every
            # put is fine at ~10 hosts; only sweep when we cross the
            # threshold so the common path is O(1).
            if len(self._cache) > self._size_threshold:
                now = time.monotonic()
                expired = [k for k, (ts, _) in self._cache.items() if now - ts >= self._ttl]
                for k in expired:
                    del self._cache[k]

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)


# ticket cache lives separately from the connection cache.
# Every gateway service calls ``adapter.disconnect()`` in a
# ``finally:`` block, which invalidates the per-instance httpx client
# (and used to invalidate the connection cache too) — so the
# connection cache was effectively never reused. The ticket cache is
# a per-process, ephemeral memo of (ticket, csrf_token, expires_at)
# keyed by (host, port, realm, username); ``connect()`` checks it
# before falling back to a full ``/access/ticket`` round-trip, and
# ``close()`` does NOT invalidate it. Useful for high-frequency
# bursts of independent service calls against the same controller.
#
# Proxmox tickets are valid for 2 hours per the docs; we cache for
# 90 minutes so we never serve a ticket that's about to expire.
_TICKET_CACHE_TTL_SECONDS = 90 * 60


@dataclass
class _CachedTicket:
    ticket: str
    csrf_token: str
    cached_at: float

    def is_fresh(self) -> bool:
        return (time.monotonic() - self.cached_at) < _TICKET_CACHE_TTL_SECONDS


class _TicketCache:
    """Per-process ticket memo, decoupled from connection lifetime.

    The cache is intentionally ephemeral (no persistence, no eviction
    beyond TTL + manual invalidation). Useful only for high-frequency
    request bursts where the same operator hits the same Proxmox
    cluster across many independent service calls.
    """

    def __init__(self) -> None:
        self._cache: dict[tuple[str, int, str, str], _CachedTicket] = {}
        self._lock = threading.Lock()

    def get(self, host: str, port: int, realm: str, username: str) -> _CachedTicket | None:
        key = (host, port, realm, username)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if not entry.is_fresh():
                self._cache.pop(key, None)
                return None
            return entry

    def put(
        self,
        host: str,
        port: int,
        realm: str,
        username: str,
        ticket: str,
        csrf_token: str,
    ) -> None:
        if not ticket:
            return
        key = (host, port, realm, username)
        with self._lock:
            self._cache[key] = _CachedTicket(
                ticket=ticket,
                csrf_token=csrf_token or "",
                cached_at=time.monotonic(),
            )

    def invalidate(self, host: str, port: int, realm: str, username: str) -> None:
        key = (host, port, realm, username)
        with self._lock:
            self._cache.pop(key, None)


class _ReachabilityTracker:
    """Track which hosts are reachable. Skip unreachable hosts for cooldown_seconds."""

    def __init__(self, cooldown: int = 10):
        self._cooldown = cooldown
        self._failures: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_reachable(self, host: str) -> bool:
        with self._lock:
            fail_time = self._failures.get(host)
            return not (fail_time and time.monotonic() - fail_time < self._cooldown)

    def mark_unreachable(self, host: str) -> None:
        with self._lock:
            self._failures[host] = time.monotonic()

    def mark_reachable(self, host: str) -> None:
        with self._lock:
            self._failures.pop(host, None)


# Items 2/3: idempotent HTTP methods can be safely retried after a
# transient 5xx, a Timeout, or a 401 (re-login then replay). Anything
# else surfaces the failure to the caller — re-staging is the right
# UX for non-idempotent writes that fail.
_IDEMPOTENT_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})
_TRANSIENT_RETRY_CODES: frozenset[int] = frozenset({502, 503, 504})
_MAX_TRANSIENT_RETRIES = 3
_RETRY_BASE_DELAY = 0.25  # seconds; jittered exponential

_connection_cache = _ConnectionCache(ttl=30)
# cooldown reduced from 60s to 10s so a transient packet
# loss / NIC bounce / DHCP renewal doesn't lock out an operator for
# a full minute. Test-connection callers can still trigger the
# cooldown but recovery is fast.
_reachability = _ReachabilityTracker(cooldown=10)
_ticket_cache = _TicketCache()


def reset_host_reachability(host: str) -> None:
    """Manual override — drop a host from the unreachable list.

    Exposed so the controller test-connection endpoint can clear a
    cooldown after the operator has fixed connectivity, rather than
    forcing them to wait the full ``cooldown`` window.
    """
    _reachability.mark_reachable(host)


@dataclass
class ProxmoxClientConfig:
    """Connection configuration for a Proxmox VE host."""

    host: str
    port: int = DEFAULT_PORT
    use_ssl: bool = True
    verify_ssl: bool = DEFAULT_VERIFY_SSL
    timeout: float = DEFAULT_TIMEOUT

    # API token auth (preferred)
    token_id: str = ""  # e.g. "user@pam!tokenname"
    token_secret: str = ""

    # Ticket auth (fallback)
    username: str = ""
    password: str = ""
    realm: str = "pam"  # pam, pve, ldap, ad


# httpx exception messages embed full URLs ("Connection
# failed for https://192.168.1.10:8006/api2/json/access/ticket") and
# sometimes header fragments. We don't want any of that bleeding into
# user-facing error responses or logs that ship to a SaaS aggregator.
# Strip URLs (anything that looks like ``scheme://host[:port]/...``)
# and percent-encoded query fragments in ProxmoxApiError.__str__.
_URL_LIKE_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_TICKET_LIKE_RE = re.compile(r"PVE:[^\s'\"]+", re.IGNORECASE)


def _redact_error_text(text: str) -> str:
    """Strip URLs and ticket fragments from an error message string."""
    if not text:
        return text
    text = _URL_LIKE_RE.sub("<url>", text)
    text = _TICKET_LIKE_RE.sub("<ticket>", text)
    return text


class ProxmoxApiError(Exception):
    """Raised when the Proxmox API returns an error.

    ``__str__`` strips URLs / ticket fragments embedded by
    httpx so a logged error or an HTTPException detail doesn't leak
    the controller's internal address or auth material.
    """

    def __init__(self, message: str, status_code: int = 0, errors: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.errors = errors or {}

    def __str__(self) -> str:
        return _redact_error_text(super().__str__())


class ProxmoxClient:
    """Async HTTP client for Proxmox VE API."""

    def __init__(
        self,
        config: ProxmoxClientConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.config = config
        # Optional transport — pass an AgentHTTPTransport to route this client's
        # requests through the site's agent (appliance/agent-only sites the
        # controller can't reach directly). None = direct (overlay-aware) reach.
        self._transport = transport
        self._http: httpx.AsyncClient | None = None
        self._ticket: str | None = None
        self._csrf_token: str | None = None
        self._semaphore = asyncio.Semaphore(RATE_LIMIT_CONCURRENT)
        # uploads (4GB+ ISOs) hold a slot for minutes. If they
        # share the API semaphore, normal API calls starve. A dedicated
        # 2-slot upload semaphore lets uploads run concurrently with
        # the 10-slot API queue without cross-blocking.
        self._upload_semaphore = asyncio.Semaphore(2)
        self._authenticated = False
        # Tagged breaker so dashboards graph Proxmox alongside other
        # adapters via ``freesdn_adapter_circuit_state``. After 5
        # consecutive failures the breaker fails-fast for 60s before
        # probing again.
        self._circuit = CircuitBreaker(
            failure_threshold=5,
            reset_timeout=60.0,
            name="proxmox",
            host=f"{config.host}:{config.port}",
        )

    # ── Context manager ────────────────────────────────────────────────────

    async def __aenter__(self) -> ProxmoxClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # ── Connection lifecycle ───────────────────────────────────────────────

    @property
    def base_url(self) -> str:
        scheme = "https" if self.config.use_ssl else "http"
        return f"{scheme}://{self.config.host}:{self.config.port}{API_BASE}"

    @classmethod
    def get_cached(
        cls,
        host: str,
        port: int = DEFAULT_PORT,
        username: str = "",
        password: str = "",
        *,
        use_ssl: bool = True,
        verify_ssl: bool = DEFAULT_VERIFY_SSL,
        timeout: float = DEFAULT_TIMEOUT,
        token_id: str = "",
        token_secret: str = "",
        realm: str = "pam",
    ) -> ProxmoxClient | None:
        """Return a cached client if one exists and is still valid, else None.

        The caller should fall back to creating a new client and calling connect().
        """
        cache_key = f"{host}:{port}:{username or token_id}"
        cached = _connection_cache.get(cache_key)
        if cached and cached.is_connected:
            return cached
        return None

    def _cache_key(self) -> str:
        """Build cache key from config."""
        identifier = self.config.username or self.config.token_id
        return f"{self.config.host}:{self.config.port}:{identifier}"

    async def connect(self) -> None:
        """Create HTTP client and authenticate.

        Reuses cached auth tokens (ticket + CSRF) when available to avoid
        redundant authentication round-trips for the same host/user.
        """
        if self._http and not self._http.is_closed:
            return

        host = self.config.host
        if not _reachability.is_reachable(host):
            raise ProxmoxApiError(f"Host {host} is in cooldown after a recent connection failure")

        self._http = build_async_client(
            base_url=self.base_url,
            verify=self.config.verify_ssl,
            timeout=httpx.Timeout(self.config.timeout, connect=10.0),
            follow_redirects=True,
            # route via the site's agent when one was injected; else direct
            **({"transport": self._transport} if self._transport is not None else {}),
        )

        try:
            # Authenticate
            if self.config.token_id and self.config.token_secret:
                # API token — no login needed, just set header
                self._http.headers["Authorization"] = (
                    f"PVEAPIToken={self.config.token_id}={self.config.token_secret}"
                )
                self._authenticated = True
                logger.debug("Proxmox: using API token auth for %s", host)
            elif self.config.username and self.config.password:
                # check the ticket cache first. The ticket
                # cache outlives the per-instance httpx client (which
                # gets closed in every service's ``finally:`` block)
                # so high-frequency bursts skip the auth round-trip.
                cached_ticket = _ticket_cache.get(
                    host,
                    self.config.port,
                    self.config.realm,
                    self.config.username,
                )
                if cached_ticket is not None:
                    self._ticket = cached_ticket.ticket
                    self._csrf_token = cached_ticket.csrf_token
                    self._http.cookies.set("PVEAuthCookie", self._ticket)
                    self._http.headers["CSRFPreventionToken"] = self._csrf_token or ""
                    self._authenticated = True
                    logger.debug(
                        "Proxmox: reusing cached ticket for %s@%s",
                        self.config.username,
                        host,
                    )
                else:
                    await self._ticket_login()
            else:
                raise ProxmoxApiError("No authentication credentials provided")

            _reachability.mark_reachable(host)
            _connection_cache.put(self._cache_key(), self)
        except (ProxmoxApiError, httpx.ConnectError, httpx.TimeoutException) as e:
            _reachability.mark_unreachable(host)
            if self._http is not None:
                await self._http.aclose()
                self._http = None
            # don't echo httpx URL strings into the error.
            raise ProxmoxApiError(
                f"Connection to {host} failed: {_redact_error_text(str(e))}"
            ) from e

    async def _ticket_login(self) -> None:
        """Authenticate with username/password to get a ticket + CSRF token."""
        assert self._http is not None
        resp = await self._http.post(
            "/access/ticket",
            data={
                "username": f"{self.config.username}@{self.config.realm}",
                "password": self.config.password,
            },
        )
        if resp.status_code != 200:
            raise ProxmoxApiError(
                "Authentication failed",
                status_code=resp.status_code,
            )

        body = resp.json().get("data", {})
        self._ticket = body.get("ticket")
        self._csrf_token = body.get("CSRFPreventionToken")

        if not self._ticket:
            raise ProxmoxApiError("No ticket in auth response")

        # Set cookie and CSRF header for subsequent requests
        self._http.cookies.set("PVEAuthCookie", self._ticket)
        self._http.headers["CSRFPreventionToken"] = self._csrf_token or ""
        self._authenticated = True
        # persist the freshly-issued ticket in the
        # cross-instance cache so the next call from a different
        # service skips the auth round-trip.
        _ticket_cache.put(
            self.config.host,
            self.config.port,
            self.config.realm,
            self.config.username,
            self._ticket or "",
            self._csrf_token or "",
        )
        logger.debug("Proxmox: ticket auth successful for %s", self.config.host)

    async def close(self) -> None:
        """Close the HTTP client.

        ``close()`` clears the per-instance httpx state but
        does NOT invalidate the ticket cache. The ticket is still
        valid (Proxmox doesn't revoke it on client disconnect) so a
        subsequent ``connect()`` from a fresh instance can reuse it.
        """
        if self._http and not self._http.is_closed:
            await self._http.aclose()
        self._http = None
        _connection_cache.invalidate(self._cache_key())
        self._authenticated = False
        self._ticket = None
        self._csrf_token = None

    # ── HTTP methods ───────────────────────────────────────────────────────

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """GET request. Returns the 'data' field from response."""
        return await self._request("GET", path, params=params)

    async def post(
        self,
        path: str,
        data: dict[str, Any] | None = None,
        *,
        force: bool = False,
    ) -> Any:
        """POST request. ``force`` propagates to the read-only gate;
        the staging applier on the apply path passes ``force=True``."""
        return await self._request("POST", path, data=data, force=force)

    async def put(
        self,
        path: str,
        data: dict[str, Any] | None = None,
        *,
        force: bool = False,
    ) -> Any:
        return await self._request("PUT", path, data=data, force=force)

    async def delete(
        self,
        path: str,
        *,
        force: bool = False,
        params: dict[str, Any] | None = None,
    ) -> Any:
        return await self._request("DELETE", path, params=params, force=force)

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        *,
        force: bool = False,
    ) -> Any:
        """Execute an API request with concurrency limiting + safety gates."""
        method_upper = method.upper()

        # Path-traversal guard — single chokepoint covers every
        # interpolation site in the adapter.
        _validate_path(path)

        # Universal read-only gate: refuse mutations unless the caller
        # has explicitly opted in via ``force=True``. The default
        # config has ``ADAPTER_READ_ONLY=True``, so production
        # deployments are safe out-of-the-box even without staging.
        if method_upper in _WRITE_METHODS and _is_adapter_read_only() and not force:
            _record_request_metric(method_upper, "read_only_blocked")
            raise AdapterReadOnlyError(
                "ADAPTER_READ_ONLY is set — Proxmox write refused. Set "
                "ADAPTER_READ_ONLY=false in the environment AND pass "
                "force=true to override. Both safeties must be down "
                "before a write reaches the cluster.",
                adapter_id="proxmox",
            )

        # Circuit breaker: fail-fast after consecutive failures so a
        # downed node doesn't burn the timeout budget on every queued
        # request.
        if not self._circuit.allow_request():
            _record_request_metric(method_upper, "circuit_open")
            raise ProxmoxApiError(
                f"Circuit breaker OPEN for {self.config.host}:{self.config.port} — "
                "too many recent failures, backing off",
                status_code=503,
            )

        if not self._http or self._http.is_closed:
            raise ProxmoxApiError("Client not connected. Call connect() first.")
        if not self._authenticated:
            raise ProxmoxApiError("Client not authenticated.")

        is_idempotent = method_upper in _IDEMPOTENT_METHODS
        request_start = time.monotonic()
        attempts = _MAX_TRANSIENT_RETRIES if is_idempotent else 1
        retried_after_401 = False

        for attempt in range(attempts):
            async with self._semaphore:
                try:
                    resp = await self._http.request(
                        method_upper,
                        path,
                        params=params,
                        data=data,
                    )
                except httpx.ConnectError as e:
                    self._circuit.record_failure()
                    _record_request_metric(method_upper, "connection")
                    _record_error("connection")
                    raise ProxmoxApiError(
                        f"Connection failed to {self.config.host}:{self.config.port}: "
                        f"{_redact_error_text(str(e))}"
                    ) from e
                except httpx.TimeoutException as e:
                    # timeouts on idempotent methods are
                    # retried with jittered backoff.
                    if is_idempotent and attempt < attempts - 1:
                        _record_request_metric(method_upper, "timeout_retry")
                        await self._retry_backoff(attempt)
                        continue
                    self._circuit.record_failure()
                    _record_request_metric(method_upper, "timeout")
                    _record_error("timeout")
                    raise ProxmoxApiError(f"Request timed out: {method_upper} {path}") from e

            from app.adapters._response_limits import check_response_size

            check_response_size(resp)  # bound device body before read

            # 401 → drop the cached ticket and retry once
            # after re-login. Idempotent methods only — POST/PUT/PATCH/
            # DELETE bubble the 401 to the caller (they re-stage).
            if resp.status_code == 401:
                if (
                    is_idempotent
                    and not retried_after_401
                    and (self.config.username and self.config.password)
                ):
                    retried_after_401 = True
                    _ticket_cache.invalidate(
                        self.config.host,
                        self.config.port,
                        self.config.realm,
                        self.config.username,
                    )
                    self._authenticated = False
                    self._ticket = None
                    self._csrf_token = None
                    _record_request_metric(method_upper, "http_401_retry")
                    try:
                        await self._ticket_login()
                    except ProxmoxApiError:
                        # re-login failure surfaces the original 401.
                        pass
                    if self._authenticated:
                        # Don't count this as an attempt — try again.
                        continue

                self._circuit.record_failure()
                _record_request_metric(method_upper, "http_401")
                _record_error("auth")
                raise ProxmoxApiError("Authentication expired or invalid", status_code=401)

            # transient 5xx on idempotent methods → backoff +
            # retry up to MAX_TRANSIENT_RETRIES.
            if (
                resp.status_code in _TRANSIENT_RETRY_CODES
                and is_idempotent
                and attempt < attempts - 1
            ):
                _record_request_metric(method_upper, f"http_{resp.status_code}_retry")
                await self._retry_backoff(attempt)
                continue

            break

        if resp.status_code >= 400:
            # Application-level error — controller is reachable, just
            # rejected. Don't trip the breaker on 4xx (only 5xx counts
            # as a controller-health failure).
            errors: dict = {}
            try:
                body = resp.json()
                errors = body.get("errors", {})
                msg = (
                    ", ".join(f"{k}: {v}" for k, v in errors.items()) if errors else resp.text[:200]
                )
            except Exception:
                msg = resp.text[:200]
            if resp.status_code >= 500:
                self._circuit.record_failure()
            _record_request_metric(method_upper, f"http_{resp.status_code}")
            _record_error(f"http_{resp.status_code}")
            raise ProxmoxApiError(
                f"API error {resp.status_code}: {_redact_error_text(msg)}",
                status_code=resp.status_code,
                errors=errors,
            )

        # Success path — record metrics + close the breaker.
        self._circuit.record_success()
        _record_request_metric(method_upper, "success")
        _record_latency(method_upper, time.monotonic() - request_start)

        try:
            body = resp.json()
        except Exception:
            return None

        return body.get("data")

    async def _retry_backoff(self, attempt: int) -> None:
        """Jittered exponential backoff between retry attempts."""
        # 0.25s, 0.5s, 1.0s … with a small random jitter so a thundering
        # herd of stuck callers doesn't all retry on the same tick.
        import random

        delay = _RETRY_BASE_DELAY * (2**attempt)
        jitter = random.uniform(0, delay * 0.25)
        await asyncio.sleep(delay + jitter)

    async def post_multipart(
        self,
        path: str,
        *,
        files: dict[str, Any],
        data: dict[str, Any] | None = None,
        force: bool = False,
    ) -> httpx.Response:
        """Multipart POST that respects the same safety gates as ``_request``.

        The Proxmox storage-upload path needs ``files=...`` semantics
        (httpx multipart) which ``_request`` does not support. Without
        this helper the adapter would call ``self._http.post`` directly
        and bypass:

          - the ADAPTER_READ_ONLY gate
          - the path-traversal guard
          - the circuit breaker
          - the request-metric / latency / error-counter emitters

        Returns the raw ``httpx.Response`` so the adapter can inspect
        the status code (the upload endpoint returns text / non-JSON
        on some error paths). Mirrors the existing ``_request`` flow
        for everything else.
        """
        method = "POST"
        _validate_path(path)

        if method in _WRITE_METHODS and _is_adapter_read_only() and not force:
            _record_request_metric(method, "read_only_blocked")
            raise AdapterError(
                "ADAPTER_READ_ONLY is set — Proxmox upload refused. Set "
                "ADAPTER_READ_ONLY=false in the environment AND pass "
                "force=true to override.",
                adapter_id="proxmox",
            )

        if not self._circuit.allow_request():
            _record_request_metric(method, "circuit_open")
            raise ProxmoxApiError(
                f"Circuit breaker OPEN for {self.config.host}:{self.config.port} — "
                "too many recent failures, backing off",
                status_code=503,
            )

        if not self._http or self._http.is_closed:
            raise ProxmoxApiError("Client not connected. Call connect() first.")
        if not self._authenticated:
            raise ProxmoxApiError("Client not authenticated.")

        request_start = time.monotonic()
        # upload-only semaphore. ISO/template uploads can run
        # for minutes and would otherwise starve normal API calls if
        # they shared the 10-slot API queue. 2-slot upload semaphore
        # caps concurrent uploads-per-host without cross-blocking.
        async with self._upload_semaphore:
            try:
                resp = await self._http.post(
                    path,
                    files=files,
                    data=data,
                )
            except httpx.ConnectError as e:
                self._circuit.record_failure()
                _record_request_metric(method, "connection")
                _record_error("connection")
                raise ProxmoxApiError(
                    f"Connection failed to {self.config.host}:{self.config.port}: "
                    f"{_redact_error_text(str(e))}"
                ) from e
            except httpx.TimeoutException as e:
                self._circuit.record_failure()
                _record_request_metric(method, "timeout")
                _record_error("timeout")
                raise ProxmoxApiError(f"Request timed out: {method} {path}") from e

        if resp.status_code >= 400:
            if resp.status_code >= 500:
                self._circuit.record_failure()
            _record_request_metric(method, f"http_{resp.status_code}")
            _record_error(f"http_{resp.status_code}")
        else:
            self._circuit.record_success()
            _record_request_metric(method, "success")
            _record_latency(method, time.monotonic() - request_start)

        return resp

    # ── Convenience ────────────────────────────────────────────────────────

    @property
    def is_connected(self) -> bool:
        return self._http is not None and not self._http.is_closed and self._authenticated

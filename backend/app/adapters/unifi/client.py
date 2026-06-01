# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — UniFi Controller HTTP client.

Handles the Network Application REST API for both API generations:

  - **Classic UniFi Controller** (self-hosted on a VM, Cloud Key Gen1):
    authentication at ``/api/login``, site-scoped endpoints under
    ``/api/s/{site}/...``.
  - **UniFi OS** (UDM / UDM-Pro / UDM-SE / UDR / UCG / Cloud Key Gen2+):
    authentication at ``/api/auth/login``, every endpoint prefixed
    with ``/proxy/network/...`` plus a ``X-CSRF-Token`` header that
    the gateway emits on the login response.

The mode is **auto-detected at login time** — we try the Classic
path first and fall back to UniFi OS on a 404. The detected mode is
cached on the instance so subsequent calls don't pay the probe cost.

Gold-standard contract
----------------------
This client participates in the same resilience contract as every
other reference adapter:

  * A tagged :class:`CircuitBreaker` wraps every HTTP call. The
    breaker emits the shared ``freesdn_adapter_circuit_state``
    Prometheus gauge so UniFi shows up on the same Grafana dashboard
    as Omada / OPNsense / Hikvision.
  * 401 responses trigger a single re-login attempt; subsequent
    401s propagate to the caller so credential rotation doesn't
    silently loop.
  * ``httpx.AsyncClient`` is constructed once per adapter and
    reused across calls (cookie + connection-pool persistence). It
    is closed cleanly on ``aclose()``.
  * Path-segment helpers live in :mod:`unifi.validators` — every
    method that interpolates a caller-supplied site / MAC / ID
    funnels through those validators before touching the wire.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import time
from typing import Any

import httpx

# Task-local active site. The adapter pool hands the SAME UniFiClient to every
# concurrent caller for a (controller, vendor) tuple, and UniFi legitimately
# hosts multiple sites under one controller. A plain ``self.site`` instance
# attribute would let two concurrent requests for different sites clobber each
# other between the ``site = X`` assignment and the awaited request — a silent
# wrong-site read/write (cross-site IDOR + data corruption). A ContextVar is
# copied per asyncio task, so each request's site is isolated; the value set
# right before a call survives the await within that task and is invisible to
# every other task. ``None`` ⇒ fall back to the client's construction default.
_active_site: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "unifi_active_site", default=None
)

from app.adapters.apply_context import in_apply_window
from app.adapters.exceptions import (
    AdapterConnectionError,
    AdapterTimeoutError,
)
from app.adapters.http_utils import CircuitBreaker
from app.adapters.unifi.exceptions import (
    AdapterReadOnlyError,
    UniFiAPIError,
    UniFiAuthError,
    UniFiConnectionError,
)

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30.0

# HTTP verbs that mutate live-controller state. The client-layer gate below
# refuses these while read-only mode is engaged UNLESS we are inside an
# approved staged-apply window (see app/adapters/apply_context.py). This
# mirrors the Omada client gate (omada/client.py) so UniFi's read-only
# posture is airtight at the single write chokepoint: a caller-supplied
# ``force=True`` clears the adapter-layer gate but can no longer, on its own,
# push a DIRECT write to a live controller while read-only is on — only a
# sanctioned ``AdapterStagingService.apply_change`` (which opens the window)
# may. No-op when read-only is off (live-write deployments unaffected).
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _is_adapter_read_only() -> bool:
    """True (default-safe) unless ``ADAPTER_READ_ONLY=false`` in env.

    Mirrors the UniFi adapter helper and ``AdapterStagingService.is_read_only``
    so the client gate and the staging gate can never disagree. Fails closed:
    if config can't be read, refuse writes.
    """
    from app.core.runtime_flags import is_adapter_read_only

    return is_adapter_read_only()


# Both UniFi generations advertise themselves on these probe paths.
# UniFi OS responds 200 + {"meta":{"up":true}} on /api/auth/sysinfo
# (unauthenticated); the Classic controller 404s on that path.
_CLASSIC_LOGIN_PATH = "/api/login"
_UDM_LOGIN_PATH = "/api/auth/login"

# Maximum number of authentication retries on a 401 inside a single
# call. Set to 1 so a stale session is recovered transparently but a
# truly bad credential rotation surfaces as an error.
_AUTH_RETRY_LIMIT = 1


def _norm_login_response(payload: Any) -> bool:
    """Return True if a UniFi login JSON body looks like success.

    Classic controllers return ``{"meta": {"rc": "ok"}, "data": []}``.
    UniFi OS returns a full user object with a ``unique_id`` and
    no ``meta`` wrapper. We accept either shape.
    """
    if not isinstance(payload, dict):
        return False
    meta = payload.get("meta")
    if isinstance(meta, dict) and meta.get("rc") == "ok":
        return True
    # UniFi OS — presence of a unique_id is the strongest signal.
    return bool(payload.get("unique_id") or payload.get("id"))


class UniFiClient:
    """Async REST client for the UniFi Network Application.

    Construction is cheap — no I/O happens until :meth:`login` is
    called. A single ``httpx.AsyncClient`` is created at __init__
    time and reused across every call so cookies persist (UniFi's
    auth model is session-cookie-based, not bearer-token).
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = 8443,
        site: str = "default",
        use_ssl: bool = True,
        verify_ssl: bool = False,
        is_unifi_os: bool | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        breaker: CircuitBreaker | None = None,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        # Construction default for ``site``; the live value is task-local (the
        # ``site`` property below reads/writes ``_active_site``). See the module
        # docstring on ``_active_site`` for the cross-site-race rationale.
        self._site_default = site
        # ``None`` means "auto-detect at login"; an explicit bool
        # short-circuits the probe (useful for tests + when the
        # operator already knows which generation they're talking to).
        self._explicit_os_mode: bool | None = is_unifi_os
        self.is_unifi_os: bool = bool(is_unifi_os) if is_unifi_os is not None else False
        self._timeout = timeout

        scheme = "https" if use_ssl else "http"
        # DNS-rebind defense: PIN the connection to a validated IP literal so httpx
        # cannot silently re-resolve the hostname to loopback / cloud-metadata between
        # validate-time and request-time (validate_controller_host only *checks* +
        # returns the host; httpx re-resolves per new connection). resolve_and_pin_host
        # is a NO-OP for an IP host (returns it unchanged — so the live IP/Tailscale
        # controllers are untouched); for a hostname it resolves + validates ONCE and
        # returns the safe IP, and we carry the original host as the Host header (+ TLS
        # SNI when verifying) so vhost routing / cert checks still work. Fails CLOSED
        # on a resolve/validation error: a hostname that resolves to a blocked
        # (loopback/link-local/metadata) address — or that cannot be resolved — must
        # NOT fall back to the raw hostname (that would let httpx DNS-rebind straight
        # to it), so we refuse to build the client. A reachable controller either is
        # an IP (resolve_and_pin_host is a no-op) or resolves to a safe IP; a transient
        # DNS failure would fail the request at httpx time anyway.
        from app.core.security_utils import resolve_and_pin_host

        self._req_extensions: dict[str, Any] | None = None
        default_headers: dict[str, str] | None = None
        try:
            pinned = resolve_and_pin_host(host)
        except Exception as exc:
            from app.adapters.unifi.exceptions import UniFiConnectionError

            raise UniFiConnectionError(
                f"UniFi controller host {host!r} failed SSRF pin validation — "
                "refusing to connect to an unvalidated / rebinding host.",
                adapter_id="unifi",
            ) from exc
        if pinned != host:
            default_headers = {"Host": host if port in (80, 443) else f"{host}:{port}"}
            if verify_ssl:
                self._req_extensions = {"sni_hostname": host}
        self.base_url = f"{scheme}://{pinned}:{port}"

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            verify=verify_ssl,
            headers=default_headers,
            # Cap the connect phase so an unreachable controller fails fast
            # (~8s) instead of hanging — UniFi compounds it by probing both the
            # Classic and UniFi-OS login paths during mode auto-detect.
            timeout=httpx.Timeout(timeout, connect=min(timeout, 8.0)),
            # follow_redirects=False: a rebinding / compromised upstream must not be
            # able to 30x-pivot the credentialed session to an internal host that httpx
            # would re-resolve unvalidated (openwrt/client.py already does this).
            follow_redirects=False,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        self._authenticated = False
        self._csrf_token: str | None = None
        # Lock so two concurrent calls don't race to re-login during
        # session expiry recovery (would also race the CSRF token).
        self._auth_lock = asyncio.Lock()
        # Monotonic session generation, bumped on every successful login.
        # The 401-recovery path captures the generation of the session it
        # USED and, under ``_auth_lock``, only re-logs-in if no other
        # coroutine already refreshed it — so a burst of concurrent 401s
        # against the shared pooled client collapses to ONE re-login instead
        # of N stampeding the controller's Identity layer (which 429s / 403s
        # a login storm and would trip the breaker).
        self._auth_generation = 0

        self._breaker = breaker or CircuitBreaker(
            failure_threshold=5,
            reset_timeout=60.0,
            name="unifi",
            host=self.base_url,
        )

    # ─────────────────────────────────────────────────────────────────
    # URL helpers
    # ─────────────────────────────────────────────────────────────────

    @property
    def site(self) -> str:
        """The active UniFi site for THIS asyncio task.

        Task-local (``_active_site``) rather than a shared instance attribute,
        because the adapter pool hands one client to every concurrent request
        for the controller — a plain attribute would race (cross-site
        read/write). Falls back to the construction default when unset.
        """
        val = _active_site.get()
        return val if val is not None else self._site_default

    @site.setter
    def site(self, value: str) -> None:
        _active_site.set(value)

    @property
    def _api_prefix(self) -> str:
        return "/proxy/network" if self.is_unifi_os else ""

    @property
    def _site_url(self) -> str:
        return f"{self._api_prefix}/api/s/{self.site}"

    @property
    def _v2_site_url(self) -> str:
        # UniFi OS 10.x "modern" lane: note ``site/`` (full word) vs the
        # classic ``s/`` — and the v2 surface returns BARE JSON with no
        # ``{meta:{rc}}`` envelope, signalling errors via HTTP status +
        # ``errorCode``/``message`` (see ``_request(lane="v2")``).
        return f"{self._api_prefix}/v2/api/site/{self.site}"

    def _login_url(self) -> str:
        return f"{self._api_prefix}{_UDM_LOGIN_PATH if self.is_unifi_os else _CLASSIC_LOGIN_PATH}"

    def _logout_url(self) -> str:
        # UniFi OS Identity logout lives at the *root* ``/api/auth/logout``
        # (the same layer that handled login), NOT under the
        # ``/proxy/network`` prefix used for Network-app calls. The
        # previous code prepended ``/proxy/network``, which the Network
        # app proxies to its OWN logout — that endpoint requires a
        # different auth state and returns 401/403 even with a valid
        # TOKEN cookie. On UniFi OS 10.x, ``/api/auth/logout`` returns
        # 200 with the same cookie that 401s against the proxied path.
        if self.is_unifi_os:
            return "/api/auth/logout"
        return "/api/logout"

    # ─────────────────────────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────────────────────────

    async def login(self) -> bool:
        """Authenticate, auto-detecting UniFi OS vs Classic if needed.

        Idempotent — if a session is already established (``TOKEN``
        cookie present + ``_authenticated`` flag set), return True
        without re-posting credentials. On UniFi OS, posting
        ``/api/auth/login`` while already authenticated returns
        **403 Forbidden**, not a 202/200 short-circuit — the gateway's
        Identity layer treats a
        re-login attempt as a forbidden state transition. Without the
        idempotence check, callers that legitimately call ``login()``
        after the adapter's ``__aenter__`` already authenticated (e.g.
        ``test_connection`` for symmetry; service code that doesn't
        track adapter state across boundaries) get a misleading
        "credentials rejected" error.

        Strategy:
          1. If a session is already live, return True immediately.
          2. If the caller passed an explicit ``is_unifi_os`` flag, use
             that path directly.
          3. Otherwise try the UniFi OS path first (it's the most
             common deployment today); a 400 / 404 falls back to the
             Classic path.

        Returns True on success, False on credential rejection.
        Raises :class:`UniFiConnectionError` on network failure /
        breaker-open.
        """
        async with self._auth_lock:
            # Idempotence — see docstring; UOS 403s a re-login attempt.
            # ``_authenticated`` is invalidated by ``logout()`` and by
            # the 401-recovery path in :meth:`request`, so this flag is
            # the single source of truth for session liveness.
            if self._authenticated:
                return True
            return await self._do_login()

    async def _do_login(self) -> bool:
        # Cookie-jar hygiene: the httpx client jar
        # auto-appends every Set-Cookie header. Re-logins (session
        # expiry recovery, controller reboot, password rotation) all
        # land here, and the jar would otherwise grow unbounded with
        # stale TOKEN values from previous sessions — only the latest
        # is actually valid. Clear before each login so the response
        # replaces the cookie set cleanly instead of stacking.
        try:
            self._client.cookies.clear()
        except Exception:
            # Defensive: in some httpx versions ``cookies.clear()``
            # raises on a partially-initialized jar. Either way, a
            # clear-failure is not a login-failure.
            pass

        if self._explicit_os_mode is not None:
            return await self._attempt_login(self.is_unifi_os)

        # Probe UniFi OS first.
        try:
            ok = await self._attempt_login(udm=True)
            if ok:
                self.is_unifi_os = True
                return True
        except UniFiAuthError:
            # Credential rejection on the UDM path is definitive —
            # the same credentials will be rejected on the Classic
            # path. Surface to the caller.
            raise
        except AdapterConnectionError:
            # The host is unreachable (connect failed / timed out) — the Classic
            # probe would fail identically against the same host, so surface it
            # now instead of paying a second connect timeout.
            raise
        except UniFiAPIError:
            # 404 / 400 — reachable but not UniFi-OS; fall through to Classic.
            logger.debug("UniFi OS login probe failed, trying Classic mode")

        ok = await self._attempt_login(udm=False)
        if ok:
            self.is_unifi_os = False
            return True
        return False

    async def _attempt_login(self, udm: bool) -> bool:
        path = f"/proxy/network{_UDM_LOGIN_PATH}" if udm else _CLASSIC_LOGIN_PATH
        # During the probe, ``_api_prefix`` may not match the path we
        # actually want to hit (mode is still being decided). Issue
        # the request directly against the base client.
        if udm:
            path = _UDM_LOGIN_PATH  # UDM login lives at /api/auth/login (no /proxy/network prefix on login)
        try:
            if not self._breaker.allow_request():
                raise UniFiConnectionError(
                    f"UniFi circuit breaker OPEN for {self.base_url}",
                    adapter_id="unifi",
                )
            resp = await self._client.post(
                path,
                json={
                    "username": self.username,
                    "password": self.password,
                    "remember": True,
                },
                extensions=self._req_extensions,
            )
        except httpx.TimeoutException as exc:
            self._breaker.record_failure()
            raise AdapterTimeoutError(
                f"UniFi login timed out after {self._timeout}s",
                adapter_id="unifi",
                timeout=self._timeout,
            ) from exc
        except httpx.HTTPError as exc:
            self._breaker.record_failure()
            raise AdapterConnectionError(
                f"UniFi login network error: {exc}",
                adapter_id="unifi",
            ) from exc

        if resp.status_code in (401, 403):
            # Credentials rejected — definitive failure, breaker
            # stays closed (this is an app-layer 4xx not a
            # transport-layer outage).
            try:
                body = resp.json()
            except Exception:
                body = {}
            raise UniFiAuthError(
                f"UniFi credentials rejected by {self.base_url}: "
                f"{body.get('meta', {}).get('msg') or resp.text[:200]}",
                adapter_id="unifi",
            )

        if resp.status_code in (404, 400):
            # Wrong API generation — caller will retry with the
            # other path. Don't tick the breaker.
            return False

        if resp.status_code >= 500 or resp.status_code == 408 or resp.status_code == 429:
            self._breaker.record_failure()
            raise UniFiAPIError(
                f"UniFi login HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        try:
            data = resp.json()
        except Exception:
            data = {}

        if resp.status_code == 200 and _norm_login_response(data):
            self._breaker.record_success()
            self._authenticated = True
            self._auth_generation += 1  # mark a fresh session for 401-recovery
            # UniFi OS returns a CSRF token in the response headers
            # (and the cookie). Cache it for mutation requests.
            self._csrf_token = resp.headers.get("x-csrf-token") or resp.headers.get("X-CSRF-Token")
            return True

        self._breaker.record_failure()
        raise UniFiAPIError(
            f"UniFi login returned HTTP {resp.status_code} but body did not "
            f"look like a success response",
            status_code=resp.status_code,
        )

    async def logout(self) -> None:
        """End the controller session (best-effort)."""
        if not self._authenticated:
            return
        try:
            await self._client.post(self._logout_url())
        except Exception:
            # Logout failures are non-fatal; the session will expire
            # on its own and we don't want teardown to mask the
            # original error.
            pass
        self._authenticated = False
        self._csrf_token = None

    async def aclose(self) -> None:
        """Close the underlying HTTP client + session.

        Idempotent — safe to call multiple times. Matches the
        ``httpx.AsyncClient.aclose`` naming so resource hygiene
        looks the same across every reference adapter.
        """
        try:
            await self.logout()
        finally:
            try:
                await self._client.aclose()
            except Exception:
                pass

    # Backwards-compat alias — pre-Beta callers used ``close()``.
    async def close(self) -> None:
        await self.aclose()

    # ─────────────────────────────────────────────────────────────────
    # Core request path
    # ─────────────────────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        site_scoped: bool = True,
        lane: str = "v1",
        _retried_auth: int = 0,
    ) -> dict[str, Any]:
        """Issue an authenticated request with breaker + retry-on-401.

        ``lane`` selects the API generation:
          * ``"v1"`` (classic) — ``/api/s/{site}`` paths, ``{meta:{rc}}``
            envelope; a non-"ok" ``rc`` at HTTP 200 is treated as a logical
            failure (the false-success honesty gate).
          * ``"v2"`` (modern, UniFi OS 10.x) — ``/v2/api/site/{site}`` paths,
            BARE JSON body, no ``meta``. Success/failure rides the HTTP status
            (201 create, 204 delete, 4xx/5xx error with ``errorCode``/``message``),
            so the rc-gate doesn't apply — the status-code branches below ARE the
            v2 honesty check.

        Every call goes through:
          1. Circuit breaker gate.
          2. ``httpx`` request (cookie auth carried automatically).
          3. 401 handler — re-login once, then retry the original call.
          4. Status-code interpretation:
               * 2xx        → return JSON body.
               * 5xx/408/429 → tick the breaker and raise ``UniFiAPIError``.
               * 4xx        → raise ``UniFiAPIError`` without breaker hit.
        """
        # Staged-write safety boundary (Bucket A). Refuse mutating verbs while
        # read-only is engaged UNLESS we are inside an approved staged-apply
        # window opened by AdapterStagingService.apply_change. Login uses
        # self._client.post directly (not _request), so auth is unaffected.
        # No-op when read-only is off.
        if method.upper() in _WRITE_METHODS and _is_adapter_read_only() and not in_apply_window():
            raise AdapterReadOnlyError(
                "ADAPTER_READ_ONLY is set — UniFi write refused outside an "
                "approved staged apply. Route the change through "
                "AdapterStagingService (stage → apply), or set "
                "ADAPTER_READ_ONLY=false to permit direct live writes.",
            )

        if not self._breaker.allow_request():
            raise UniFiConnectionError(
                f"UniFi circuit breaker OPEN for {self.base_url}",
                adapter_id="unifi",
            )

        if lane == "v2":
            url = (
                f"{self._v2_site_url}{path}" if site_scoped else f"{self._api_prefix}/v2/api{path}"
            )
        else:
            url = f"{self._site_url}{path}" if site_scoped else f"{self._api_prefix}{path}"
        headers: dict[str, str] = {}
        if self.is_unifi_os and self._csrf_token and method.upper() != "GET":
            headers["X-CSRF-Token"] = self._csrf_token

        # Capture the session generation BEFORE the send so the 401-recovery
        # path can tell whether the session it used has already been refreshed
        # by another concurrent coroutine (see ``_auth_generation``).
        session_gen = self._auth_generation
        started = time.monotonic()
        try:
            resp = await self._client.request(
                method,
                url,
                json=json,
                params=params,
                headers=headers or None,
                extensions=self._req_extensions,
            )
        except httpx.TimeoutException as exc:
            self._breaker.record_failure()
            raise AdapterTimeoutError(
                f"UniFi request timed out after {self._timeout}s",
                adapter_id="unifi",
                timeout=self._timeout,
            ) from exc
        except httpx.HTTPError as exc:
            self._breaker.record_failure()
            raise AdapterConnectionError(
                f"UniFi request network error: {exc}",
                adapter_id="unifi",
            ) from exc

        from app.adapters._response_limits import check_response_size

        check_response_size(resp)  # bound device body before read
        elapsed_ms = (time.monotonic() - started) * 1000
        logger.debug(
            "UniFi %s %s -> %s in %.1fms",
            method,
            url,
            resp.status_code,
            elapsed_ms,
        )

        if resp.status_code in (401, 403):
            # Session expired — try to recover once.
            if _retried_auth >= _AUTH_RETRY_LIMIT:
                self._breaker.record_failure()
                raise UniFiAuthError(
                    f"UniFi rejected request after re-login attempt: HTTP {resp.status_code}",
                    adapter_id="unifi",
                )
            logger.info(
                "UniFi session expired (%s) — re-authenticating",
                resp.status_code,
            )
            # Serialize re-auth: the adapter pool hands the SAME client to many
            # concurrent requests, so a session expiry yields a burst of 401s.
            # Without the lock each would call _do_login() in parallel, hammering
            # the controller's Identity layer with N logins (which it 429s/403s,
            # tripping the breaker). Under the lock, only re-login if the session
            # we used hasn't already been refreshed by a peer; otherwise reuse it.
            async with self._auth_lock:
                if self._auth_generation == session_gen:
                    self._authenticated = False
                    await self._do_login()
                # else: a concurrent coroutine already refreshed the session —
                # skip the redundant login and just retry with the new one.
            # Only AUTO-REPLAY idempotent reads. A non-idempotent write (POST create;
            # conservatively every non-GET) must NOT be blindly replayed: the original
            # may have reached the device before the COMPLETING response carried
            # 401/403, so a replay would create a DUPLICATE object (a second
            # networkconf/wlanconf/firewall rule). The pooled session is now refreshed,
            # so the operator's re-apply of the staged change succeeds — and surfacing
            # the failure makes any half-applied write VISIBLE (operator re-checks
            # device state) instead of silently duplicated.
            if method.upper() in ("GET", "HEAD"):
                return await self._request(
                    method,
                    path,
                    json=json,
                    params=params,
                    site_scoped=site_scoped,
                    lane=lane,
                    _retried_auth=_retried_auth + 1,
                )
            raise UniFiAuthError(
                f"UniFi session expired during a {method} write; re-authenticated. "
                "Re-apply the change — the write was NOT auto-replayed to avoid "
                "creating a duplicate object.",
                adapter_id="unifi",
            )

        if resp.status_code in (408, 429) or resp.status_code >= 500:
            self._breaker.record_failure()
            try:
                body = resp.json()
                msg = body.get("meta", {}).get("msg", "")
            except Exception:
                msg = resp.text[:200]
            raise UniFiAPIError(
                f"UniFi HTTP {resp.status_code} on {method} {path}: {msg}",
                status_code=resp.status_code,
            )

        if resp.status_code >= 400:
            # Client-side 4xx — propagate but don't tip the breaker. Handle both
            # the v1 ``{meta:{rc,msg}}`` shape and the v2 ``{errorCode,message,code}``
            # shape so v2 validation errors aren't reduced to a raw text dump.
            try:
                body = resp.json()
                meta = body.get("meta", {}) if isinstance(body, dict) else {}
                v2msg = (
                    (body.get("message") or body.get("code")) if isinstance(body, dict) else None
                )
                msg = meta.get("msg") or v2msg or resp.text[:200]
                rc = meta.get("rc") or (body.get("errorCode") if isinstance(body, dict) else None)
            except Exception:
                msg = resp.text[:200]
                rc = None
            raise UniFiAPIError(
                f"UniFi HTTP {resp.status_code} on {method} {path}: {msg}",
                status_code=resp.status_code,
                meta_rc=rc,
                meta_msg=msg,
            )

        # 2xx
        self._breaker.record_success()

        # v2 DELETE (and a few commands) answer 204 No Content / empty body.
        # Calling resp.json() on that raises; short-circuit to an ok envelope.
        if resp.status_code == 204 or not (resp.content or b"").strip():
            return {"meta": {"rc": "ok"}, "data": []}

        try:
            data = resp.json()
        except Exception as exc:
            raise UniFiAPIError(
                f"UniFi returned non-JSON body on {method} {path}",
            ) from exc

        if lane == "v2":
            # v2 carries NO {meta:{rc}} envelope; success/failure already rode
            # the HTTP status (the 4xx/5xx branches above ARE the v2 honesty
            # gate — a logical failure is a 4xx, never a 200). Normalise the
            # bare body into the classic envelope so the adapter layer stays
            # generation-agnostic. v2 bodies are a list or a single object.
            return {"meta": {"rc": "ok"}, "data": data}

        # A 2xx status is NOT sufficient to call the command a success: UniFi
        # classic / UniFi-OS controllers return HTTP 200 with
        # {"meta":{"rc":"error","msg":"api.err..."}} when a command (e.g.
        # /cmd/stamgr block/unblock/forget) is LOGICALLY rejected (unknown MAC,
        # not permitted, transient). The 4xx branch above already inspects rc;
        # the success path must too — otherwise the adapter returns normally and
        # block/unblock/forget enforcement silently false-succeeds (the DB records
        # "blocked" while the client stays reachable). Treat a non-"ok" rc as a
        # failure and raise, symmetric with the Omada client's errorCode gate.
        if isinstance(data, dict) and "meta" in data:
            meta = data.get("meta") or {}
            rc = meta.get("rc")
            if rc is not None and rc != "ok":
                raise UniFiAPIError(
                    f"UniFi command rejected on {method} {path}: {meta.get('msg') or rc}",
                    meta_rc=rc,
                    meta_msg=meta.get("msg"),
                )
            if "data" in data:
                return data
        # Normalise to the Classic-style envelope so the adapter layer doesn't
        # need to know which generation responded.
        return {"meta": {"rc": "ok"}, "data": data}

    # Convenience verb wrappers
    async def get(self, path: str, **kw: Any) -> dict[str, Any]:
        return await self._request("GET", path, **kw)

    async def post(self, path: str, **kw: Any) -> dict[str, Any]:
        return await self._request("POST", path, **kw)

    async def put(self, path: str, **kw: Any) -> dict[str, Any]:
        return await self._request("PUT", path, **kw)

    async def delete(self, path: str, **kw: Any) -> dict[str, Any]:
        return await self._request("DELETE", path, **kw)

    # ─────────────────────────────────────────────────────────────────
    # Read endpoints
    # ─────────────────────────────────────────────────────────────────

    async def get_sites(self) -> dict[str, Any]:
        """List sites visible to this account (not site-scoped)."""
        return await self._request("GET", "/api/self/sites", site_scoped=False)

    async def get_sysinfo(self) -> dict[str, Any]:
        return await self.get("/stat/sysinfo")

    async def get_health(self) -> dict[str, Any]:
        return await self.get("/stat/health")

    async def get_devices(self, *, limit: int = 2000) -> dict[str, Any]:
        """Adopted devices. Bounded with ``?_limit`` (best-effort — older
        controllers ignore it) for parity with :meth:`get_clients`; the hard
        memory guard remains ``check_response_size`` in ``_request``. Devices
        are far fewer than clients, so the default 2000 covers any real site;
        the 5000 cap stops a careless caller asking for unbounded."""
        bounded = max(1, min(int(limit), 5000))
        return await self.get(f"/stat/device?_limit={bounded}")

    async def get_device(self, mac: str) -> dict[str, Any]:
        return await self.get(f"/stat/device/{mac}")

    async def get_device_basic(self) -> dict[str, Any]:
        """Lightweight device list — name, mac, model only."""
        return await self.get("/stat/device-basic")

    async def get_clients(self, *, limit: int = 1000) -> dict[str, Any]:
        """Active clients. Bounded at 1000 by default — busy controllers
        (5k+ STA) used to return 50MB+ payloads that blocked the event
        loop on JSON parse + serialize. Callers can raise the limit
        explicitly when they really need the full set (rare; usually
        a bulk export use case).
        """
        # UniFi REST API accepts ?_limit=N for paginatable list endpoints.
        # /stat/sta honors it; controllers older than v7.0 ignore it
        # gracefully (return everything). Bounding here is best-effort
        # bandwidth + memory; the canonical fix is for callers to
        # paginate or stream. Hard upper-bound 5000 — even a careless
        # caller can't ask for unbounded.
        bounded = max(1, min(int(limit), 5000))
        return await self.get(f"/stat/sta?_limit={bounded}")

    async def get_active_clients(self) -> dict[str, Any]:
        return await self.get("/stat/sta")

    async def get_all_clients(self) -> dict[str, Any]:
        """Includes offline / historical clients."""
        return await self.get("/rest/user")

    async def get_client(self, mac: str) -> dict[str, Any]:
        return await self.get(f"/stat/user/{mac}")

    async def get_networks(self) -> dict[str, Any]:
        return await self.get("/rest/networkconf")

    async def get_network(self, network_id: str) -> dict[str, Any]:
        return await self.get(f"/rest/networkconf/{network_id}")

    async def get_wlans(self) -> dict[str, Any]:
        return await self.get("/rest/wlanconf")

    async def get_wlan(self, wlan_id: str) -> dict[str, Any]:
        return await self.get(f"/rest/wlanconf/{wlan_id}")

    async def get_wlan_groups(self) -> dict[str, Any]:
        return await self.get("/rest/wlangroup")

    async def get_port_profiles(self) -> dict[str, Any]:
        return await self.get("/rest/portconf")

    async def get_firewall_rules(self) -> dict[str, Any]:
        return await self.get("/rest/firewallrule")

    async def get_firewall_groups(self) -> dict[str, Any]:
        return await self.get("/rest/firewallgroup")

    async def get_port_forwards(self) -> dict[str, Any]:
        return await self.get("/rest/portforward")

    async def get_radius_profiles(self) -> dict[str, Any]:
        return await self.get("/rest/radiusprofile")

    async def get_radius_users(self) -> dict[str, Any]:
        return await self.get("/rest/account")

    async def get_vpn_clients(self) -> dict[str, Any]:
        """VPN connection list (legacy endpoint, present on both gens)."""
        return await self.get("/stat/remoteuservpn")

    async def get_alerts(self, limit: int = 50) -> dict[str, Any]:
        # UniFi 10.x renamed the alerts endpoint: ``/stat/alarm`` 404s,
        # ``/list/alarm`` returns the standard ``{meta, data: [...]}``
        # envelope. The classic path is left as a fallback for older
        # controllers (UniFi 7.x and earlier still expose ``/stat/alarm``).
        path = (
            f"/list/alarm?_limit={int(limit)}"
            if self.is_unifi_os
            else f"/stat/alarm?_limit={int(limit)}"
        )
        return await self.get(path)

    async def get_events(self, limit: int = 100) -> dict[str, Any]:
        # UniFi OS 10.x removed the classic ``/stat/event`` endpoint
        # (HTTP 404) and the obvious renames (``/list/event``,
        # ``/rest/event``) all return ``api.err.InvalidObject`` —
        # event-log retrieval moved to an unannounced new shape on
        # the 10.x line and Ubiquiti hasn't published a migration
        # path yet. Until that surfaces, swallow the not-found from
        # the legacy path so callers see an empty list rather than
        # a fatal 4xx. Classic-mode
        # controllers (UniFi 7.x and earlier) keep working via the
        # original path.
        from app.adapters.unifi.exceptions import UniFiAPIError

        try:
            return await self.get(f"/stat/event?_limit={int(limit)}")
        except UniFiAPIError as exc:
            if exc.status_code in (400, 404):
                return {"meta": {"rc": "ok"}, "data": []}
            raise

    async def get_routing(self) -> dict[str, Any]:
        return await self.get("/rest/routing")

    # ─────────────────────────────────────────────────────────────────
    # Write endpoints (called by the reference adapter writes)
    # ─────────────────────────────────────────────────────────────────

    async def cmd_devmgr(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send a ``devmgr`` command (restart, adopt, locate, etc.)."""
        return await self.post("/cmd/devmgr", json=payload)

    async def cmd_stamgr(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send a ``stamgr`` (station-manager) command — block / kick."""
        return await self.post("/cmd/stamgr", json=payload)

    async def update_device(self, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """PUT the device record (used for port_overrides, disabled flag)."""
        return await self.put(f"/rest/device/{device_id}", json=payload)

    async def update_wlan(self, wlan_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/wlanconf/{wlan_id}", json=payload)

    async def update_network(self, network_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/networkconf/{network_id}", json=payload)

    async def create_network(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/networkconf", json=payload)

    async def create_wlan(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/wlanconf", json=payload)

    async def delete_network(self, network_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/networkconf/{network_id}")

    async def delete_wlan(self, wlan_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/wlanconf/{wlan_id}")

    # ── WLAN groups (v1) ──
    async def create_wlan_group(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/wlangroup", json=payload)

    async def update_wlan_group(self, group_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/wlangroup/{group_id}", json=payload)

    async def delete_wlan_group(self, group_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/wlangroup/{group_id}")

    # ── Firewall groups (v1) ──
    async def create_firewall_group(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/firewallgroup", json=payload)

    async def update_firewall_group(self, group_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/firewallgroup/{group_id}", json=payload)

    async def delete_firewall_group(self, group_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/firewallgroup/{group_id}")

    # ── Firewall rules (v1 legacy ruleset) ──
    async def create_firewall_rule(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/firewallrule", json=payload)

    async def update_firewall_rule(self, rule_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/firewallrule/{rule_id}", json=payload)

    async def delete_firewall_rule(self, rule_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/firewallrule/{rule_id}")

    # ── RADIUS accounts (v1) ──
    async def create_radius_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/account", json=payload)

    async def update_radius_user(self, account_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/account/{account_id}", json=payload)

    async def delete_radius_user(self, account_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/account/{account_id}")

    # ── Port profiles (v1) ──
    async def create_port_profile(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/portconf", json=payload)

    async def update_port_profile(self, profile_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/portconf/{profile_id}", json=payload)

    async def delete_port_profile(self, profile_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/portconf/{profile_id}")

    # ── User (bandwidth) groups (v1) ──
    async def get_user_groups(self) -> dict[str, Any]:
        return await self.get("/rest/usergroup")

    async def create_user_group(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/usergroup", json=payload)

    async def update_user_group(self, group_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/usergroup/{group_id}", json=payload)

    async def delete_user_group(self, group_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/usergroup/{group_id}")

    # ── DPI restriction groups (v1) ──
    async def get_dpi_apps(self) -> dict[str, Any]:
        return await self.get("/rest/dpiapp")

    async def create_dpi_app(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/dpiapp", json=payload)

    async def update_dpi_app(self, app_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/dpiapp/{app_id}", json=payload)

    async def delete_dpi_app(self, app_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/dpiapp/{app_id}")

    # ── Port forwards (v1) ──
    async def create_port_forward(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/portforward", json=payload)

    async def update_port_forward(self, fwd_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/portforward/{fwd_id}", json=payload)

    async def delete_port_forward(self, fwd_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/portforward/{fwd_id}")

    # ── Dynamic DNS (v1) ──
    async def get_dynamic_dns(self) -> dict[str, Any]:
        return await self.get("/rest/dynamicdns")

    async def create_dynamic_dns(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/dynamicdns", json=payload)

    async def update_dynamic_dns(self, dyn_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/dynamicdns/{dyn_id}", json=payload)

    async def delete_dynamic_dns(self, dyn_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/dynamicdns/{dyn_id}")

    # ── Static routes (v1 routing) ──
    async def create_routing(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/routing", json=payload)

    async def update_routing(self, route_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.put(f"/rest/routing/{route_id}", json=payload)

    async def delete_routing(self, route_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/routing/{route_id}")

    # ── Guest hotspot operators + vouchers (v1) ──
    async def get_hotspot_operators(self) -> dict[str, Any]:
        return await self.get("/rest/hotspotop")

    async def create_hotspot_operator(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.post("/rest/hotspotop", json=payload)

    async def delete_hotspot_operator(self, op_id: str) -> dict[str, Any]:
        return await self.delete(f"/rest/hotspotop/{op_id}")

    async def get_vouchers(self) -> dict[str, Any]:
        return await self.get("/stat/voucher")

    async def cmd_hotspot(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Hotspot manager command (create-voucher / delete-voucher / authorize-guest)."""
        return await self.post("/cmd/hotspot", json=payload)

    # ─────────────────────────────────────────────────────────────────
    # v2 modern lane (UniFi OS 10.x) — the zone-based-firewall / policy
    # engine surface. Every call rides ``_request(lane="v2")`` so it hits
    # ``/v2/api/site/{site}/...`` and is gated on HTTP status, not meta.rc.
    # IDs are validated at the adapter layer before reaching here (same
    # contract as the v1 write methods above).
    # ─────────────────────────────────────────────────────────────────

    async def v2_get(self, path: str, **kw: Any) -> dict[str, Any]:
        return await self._request("GET", path, lane="v2", **kw)

    async def v2_post(self, path: str, **kw: Any) -> dict[str, Any]:
        return await self._request("POST", path, lane="v2", **kw)

    async def v2_put(self, path: str, **kw: Any) -> dict[str, Any]:
        return await self._request("PUT", path, lane="v2", **kw)

    async def v2_delete(self, path: str, **kw: Any) -> dict[str, Any]:
        return await self._request("DELETE", path, lane="v2", **kw)

    # ── Zone-based firewall: policies ──
    async def get_firewall_policies(self) -> dict[str, Any]:
        return await self.v2_get("/firewall-policies")

    async def create_firewall_policy(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_post("/firewall-policies", json=payload)

    async def update_firewall_policy(
        self, policy_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return await self.v2_put(f"/firewall-policies/{policy_id}", json=payload)

    async def delete_firewall_policy(self, policy_id: str) -> dict[str, Any]:
        return await self.v2_delete(f"/firewall-policies/{policy_id}")

    async def batch_delete_firewall_policies(self, ids: list[str]) -> dict[str, Any]:
        return await self.v2_post("/firewall-policies/batch-delete", json={"ids": list(ids)})

    # ── Zone-based firewall: zones ──
    async def get_firewall_zones(self) -> dict[str, Any]:
        return await self.v2_get("/firewall/zone")

    async def get_firewall_zone_matrix(self) -> dict[str, Any]:
        return await self.v2_get("/firewall/zone-matrix")

    async def create_firewall_zone(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_post("/firewall/zone", json=payload)

    async def update_firewall_zone(self, zone_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_put(f"/firewall/zone/{zone_id}", json=payload)

    async def delete_firewall_zone(self, zone_id: str) -> dict[str, Any]:
        return await self.v2_delete(f"/firewall/zone/{zone_id}")

    # ── NAT rules ──
    async def get_nat_rules(self) -> dict[str, Any]:
        return await self.v2_get("/nat")

    async def create_nat_rule(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_post("/nat", json=payload)

    async def update_nat_rule(self, rule_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_put(f"/nat/{rule_id}", json=payload)

    async def delete_nat_rule(self, rule_id: str) -> dict[str, Any]:
        return await self.v2_delete(f"/nat/{rule_id}")

    # ── QoS rules ──
    async def get_qos_rules(self) -> dict[str, Any]:
        return await self.v2_get("/qos-rules")

    async def create_qos_rule(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_post("/qos-rules", json=payload)

    async def update_qos_rule(self, rule_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_put(f"/qos-rules/{rule_id}", json=payload)

    async def delete_qos_rule(self, rule_id: str) -> dict[str, Any]:
        return await self.v2_delete(f"/qos-rules/{rule_id}")

    # ── Traffic rules ──
    async def get_traffic_rules(self) -> dict[str, Any]:
        return await self.v2_get("/trafficrules")

    async def create_traffic_rule(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_post("/trafficrules", json=payload)

    async def update_traffic_rule(self, rule_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_put(f"/trafficrules/{rule_id}", json=payload)

    async def delete_traffic_rule(self, rule_id: str) -> dict[str, Any]:
        return await self.v2_delete(f"/trafficrules/{rule_id}")

    # ── Traffic routes ──
    async def get_traffic_routes(self) -> dict[str, Any]:
        return await self.v2_get("/trafficroutes")

    async def create_traffic_route(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_post("/trafficroutes", json=payload)

    async def update_traffic_route(self, route_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_put(f"/trafficroutes/{route_id}", json=payload)

    async def delete_traffic_route(self, route_id: str) -> dict[str, Any]:
        return await self.v2_delete(f"/trafficroutes/{route_id}")

    # ── Static DNS records ──
    async def get_static_dns(self) -> dict[str, Any]:
        return await self.v2_get("/static-dns")

    async def create_static_dns(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_post("/static-dns", json=payload)

    async def update_static_dns(self, record_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self.v2_put(f"/static-dns/{record_id}", json=payload)

    async def delete_static_dns(self, record_id: str) -> dict[str, Any]:
        return await self.v2_delete(f"/static-dns/{record_id}")

    # ── Read-only v2 surfaces ──
    async def get_content_filtering(self) -> dict[str, Any]:
        return await self.v2_get("/content-filtering")

    async def get_topology(self) -> dict[str, Any]:
        return await self.v2_get("/topology")

    async def get_ap_groups(self) -> dict[str, Any]:
        return await self.v2_get("/apgroups")

    async def get_v2_devices(self) -> dict[str, Any]:
        """Cross-app device aggregate (network/protect/access/talk/...)."""
        return await self.v2_get("/device")


__all__ = ["UniFiClient"]

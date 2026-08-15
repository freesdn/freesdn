# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - FreePBX REST API Client
=======================================

HTTP client for the FreePBX admin interface.

Uses two authentication strategies in priority order:

1. **Session / AJAX** – Log into the FreePBX admin web UI to obtain a
   ``PHPSESSID`` cookie, then call the internal AJAX endpoints
   (``/admin/ajax.php``) with the session cookie.  Works with every FreePBX
   version (15-17) without extra module configuration.

2. **OAuth2 REST** – ``POST /admin/api/api/token`` with
   ``client_credentials`` grant.  Requires an API client to be registered in
   FreePBX → Admin → API → Applications.  The adapter will attempt this first
   if ``api_client_id`` / ``api_client_secret`` are supplied.

The public surface (``list_extensions``, ``list_trunks``, …) is identical
regardless of which transport is active.
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
import re
from typing import Any

import aiohttp

from app.core.http_client import build_aiohttp_session

from .constants import (
    FREEPBX_AJAX_ENDPOINTS,
    FREEPBX_WEB_PORT,
    REST_MAX_RETRIES,
    REST_REQUEST_TIMEOUT,
    REST_RETRY_DELAY,
)
from .exceptions import (
    FreePBXApiError,
    FreePBXAuthError,
    FreePBXConnectionError,
)

logger = logging.getLogger("freesdn.adapters.freepbx.rest")

# Regex for extracting the CSRF token from the FreePBX login page
_CSRF_RE = re.compile(r'name="__csrf_token"\s+value="([^"]+)"')


class FreePBXRestClient:
    """
    Async HTTP client for FreePBX.

    Uses session-cookie authentication against the built-in admin AJAX
    endpoints, which avoids the need for OAuth2 client configuration.

    Usage::

        client = FreePBXRestClient(
            host="198.51.100.10", username="admin", password="<PASSWORD>",
        )
        await client.connect()
        extensions = await client.list_extensions()
        await client.disconnect()
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = FREEPBX_WEB_PORT,
        use_ssl: bool = True,
        # ``verify_ssl`` defaults to True. Brownfield FreePBX installs
        # that ship a self-signed cert must explicitly pass
        # ``verify_ssl=False`` AND the operator must set the
        # ``tls_verify_disabled_acknowledged`` flag on the PBX row.
        # That acknowledgement gate lives in the service layer
        # (``_adapter_from_pbx``); the bare client trusts whatever
        # value the caller supplies.
        verify_ssl: bool = True,
        # ── OAuth2 (FreePBX 16+ Admin API → Applications → M2M) ──
        # When BOTH ``api_client_id`` and ``api_client_secret`` are
        # supplied, the client uses the OAuth2 ``client_credentials``
        # flow against ``/admin/api/api/token`` and calls the modern
        # REST surface at ``/admin/api/api/rest/...``. When omitted,
        # falls back to web session login + the legacy AJAX
        # endpoints (works on every FreePBX version with no M2M setup).
        # Preferring OAuth2 is the contract route — closes the
        # ``api_client_id`` / ``api_client_secret`` gap described in
        # the top-of-file docstring.
        api_client_id: str | None = None,
        api_client_secret: str | None = None,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.verify_ssl = verify_ssl
        self.api_client_id = api_client_id
        self.api_client_secret = api_client_secret

        self._scheme = "https" if use_ssl else "http"
        self._base_url = f"{self._scheme}://{self.host}:{self.port}"

        self._session: aiohttp.ClientSession | None = None
        self._connected = False
        self._api_available = False
        # OAuth2 state — populated by ``_oauth2_login`` when M2M
        # credentials are configured. ``_oauth2_token`` is the active
        # Bearer; ``_oauth2_expires_at`` is the monotonic timestamp
        # at which it expires (we refresh ~60s early to avoid races).
        self._oauth2_token: str | None = None
        self._oauth2_expires_at: float = 0.0
        # Serialize token refresh: without it, N concurrent calls that all see
        # an expired token each fire _oauth2_login, hammering the token
        # endpoint and racing to overwrite _oauth2_token / _expires_at.
        self._oauth2_lock = asyncio.Lock()
        self._auth_mode: str = "session"  # "session" | "oauth2"

    # ── properties ─────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def api_available(self) -> bool:
        return self._api_available

    # ── lifecycle ──────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Create HTTP session and authenticate.

        Auth priority:
            1. OAuth2 client_credentials when ``api_client_id`` +
               ``api_client_secret`` are configured. Uses the modern
               REST surface (``/admin/api/api/rest/...``) for FreePBX
               16+ Admin API.
            2. Web session login otherwise (legacy AJAX endpoints,
               works on every FreePBX 15-17 install).

        Either path being unreachable falls the client into AMI/ARI-
        only mode rather than failing — the AMI side of the adapter
        is independent.
        """
        if self._connected:
            return

        ssl_ctx: bool | None = None
        if self.use_ssl:
            ssl_ctx = self.verify_ssl  # False = skip verification

        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        # sock_connect caps the TCP-connect phase so an unreachable PBX fails
        # fast (~8s) instead of hanging up to the (long) total request timeout.
        timeout = aiohttp.ClientTimeout(total=REST_REQUEST_TIMEOUT, sock_connect=8.0)
        # unsafe=True is required for IP-address-based hosts (no domain)
        jar = aiohttp.CookieJar(unsafe=True)
        self._session = build_aiohttp_session(
            connector=connector,
            timeout=timeout,
            cookie_jar=jar,
        )

        # OAuth2 preferred when configured.
        if self.api_client_id and self.api_client_secret:
            try:
                await self._oauth2_login()
                self._auth_mode = "oauth2"
                self._connected = True
                self._api_available = True
                logger.info(
                    "FreePBX OAuth2 connected to %s (M2M client_id=%s...)",
                    self.host,
                    self.api_client_id[:8],
                )
                return
            except FreePBXAuthError:
                # Bad creds — surface to the caller, don't silently fall back.
                raise
            except (TimeoutError, FreePBXConnectionError, FreePBXApiError, OSError) as exc:
                logger.warning(
                    "FreePBX OAuth2 reachable but failed (%s); falling back to session auth",
                    exc,
                )
                # Fall through to web login as a last resort.

        try:
            await self._web_login()
            self._auth_mode = "session"
            self._connected = True
            self._api_available = True
            logger.info("FreePBX session-auth connected to %s", self.host)
        except FreePBXAuthError:
            raise
        except (TimeoutError, FreePBXConnectionError, FreePBXApiError, OSError) as exc:
            logger.warning(
                "FreePBX web login failed (%s); adapter will run in AMI/ARI-only mode",
                exc,
            )
            self._connected = True
            self._api_available = False

    async def disconnect(self) -> None:
        """Close the HTTP session."""
        self._connected = False
        self._api_available = False
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        logger.info("FreePBX REST client disconnected")

    async def close(self) -> None:
        """Alias for disconnect."""
        await self.disconnect()

    async def __aenter__(self) -> FreePBXRestClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.disconnect()

    # ── session authentication ─────────────────────────────────────────

    async def _web_login(self) -> None:
        """
        Authenticate by POSTing to the FreePBX admin login form.

        1. GET ``/admin/config.php`` to obtain the CSRF token.
        2. POST username + password + CSRF token.
        3. Validate the response contains a logged-in page.

        On success, ``self._session`` holds a ``PHPSESSID`` cookie that is
        automatically attached to subsequent requests.
        """
        assert self._session is not None
        login_url = f"{self._base_url}/admin/config.php"

        try:
            # Step 1 — fetch the login page
            async with self._session.get(login_url) as resp:
                if resp.status != 200:
                    raise FreePBXConnectionError(f"FreePBX login page returned HTTP {resp.status}")
                html = await resp.text()

            csrf_match = _CSRF_RE.search(html)
            csrf_token = csrf_match.group(1) if csrf_match else None

            # Step 2 — submit credentials
            form_data: dict[str, str] = {
                "username": self.username,
                "password": self.password,
            }
            if csrf_token:
                form_data["__csrf_token"] = csrf_token

            async with self._session.post(
                login_url,
                data=form_data,
                allow_redirects=True,
            ) as resp:
                body = await resp.text()

            # Step 3 — verify login succeeded
            body_lower = body.lower()
            if "logout" in body_lower or "dashboard" in body_lower:
                logger.debug("FreePBX web login succeeded for %s", self.username)
                return

            # Check for common failure indicators
            if "incorrect" in body_lower or "invalid" in body_lower:
                raise FreePBXAuthError("FreePBX web login failed — invalid credentials")

            # If we land back on the login form, auth failed
            if 'name="username"' in body and 'name="password"' in body:
                raise FreePBXAuthError("FreePBX web login failed — still on login page")

            # Optimistic — session cookie obtained, assume logged in
            logger.debug(
                "FreePBX login response did not contain clear success markers "
                "but session cookie was set; proceeding"
            )

        except (TimeoutError, aiohttp.ClientError, OSError) as exc:
            raise FreePBXConnectionError(f"Cannot reach FreePBX at {self.host}: {exc}") from exc

    # ── OAuth2 authentication + REST request helper ────────────────────

    async def _oauth2_login(self) -> None:
        """POST ``/admin/api/api/token`` with ``client_credentials``.

        Stores the access token + expiry in ``self._oauth2_token`` /
        ``self._oauth2_expires_at``. Raises :class:`FreePBXAuthError`
        on 401 (bad client_id / client_secret) so the caller doesn't
        silently fall through to session auth with wrong M2M creds.
        """
        assert self._session is not None
        token_url = f"{self._base_url}/admin/api/api/token"
        form = {
            "grant_type": "client_credentials",
            "client_id": self.api_client_id or "",
            "client_secret": self.api_client_secret or "",
        }
        try:
            async with self._session.post(token_url, data=form) as resp:
                body = await resp.text()
                if resp.status == 401:
                    raise FreePBXAuthError(
                        "FreePBX OAuth2 token request rejected: invalid client_id or client_secret"
                    )
                if resp.status != 200:
                    raise FreePBXApiError(
                        f"FreePBX OAuth2 token endpoint returned HTTP {resp.status}: {body[:200]}",
                        status_code=resp.status,
                    )
                try:
                    data = _json.loads(body)
                except _json.JSONDecodeError as exc:
                    raise FreePBXApiError(
                        f"FreePBX OAuth2 returned non-JSON: {body[:200]}"
                    ) from exc

                token = data.get("access_token")
                if not token:
                    raise FreePBXAuthError(
                        f"FreePBX OAuth2 response missing access_token: {body[:200]}"
                    )
                # Refresh ~60s before expiry to avoid mid-call expiry races.
                import time as _time

                expires_in = int(data.get("expires_in", 3600))
                self._oauth2_token = token
                self._oauth2_expires_at = _time.monotonic() + max(expires_in - 60, 60)
        except (TimeoutError, aiohttp.ClientError, OSError) as exc:
            raise FreePBXConnectionError(f"FreePBX OAuth2 token request failed: {exc}") from exc

    async def _ensure_oauth2_token(self) -> str:
        """Return a valid OAuth2 token, refreshing if expired.

        Double-checked locking: the common path (valid cached token) takes no
        lock; only a refresh serializes through ``_oauth2_lock``, and the
        re-check inside the lock means concurrent callers that queued behind a
        refresh reuse the freshly-minted token instead of each re-logging in.
        """
        import time as _time

        if self._oauth2_token and _time.monotonic() < self._oauth2_expires_at:
            return self._oauth2_token
        async with self._oauth2_lock:
            if not self._oauth2_token or _time.monotonic() >= self._oauth2_expires_at:
                await self._oauth2_login()
        if not self._oauth2_token:
            raise FreePBXAuthError("FreePBX OAuth2 token unavailable after login attempt")
        return self._oauth2_token

    async def _graphql(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        *,
        operation_name: str | None = None,
        idempotent: bool = False,
    ) -> dict[str, Any]:
        """POST ``/admin/api/api/gql`` with a GraphQL query/mutation.

        FreePBX 16+ exposes a much richer GraphQL surface than the
        sparse legacy REST endpoints (78 queries + 105 mutations on
        a stock install vs. ~4 REST endpoints). When OAuth2 is the
        active auth mode, this is the preferred transport for
        anything that has a GraphQL field — extensions, ring groups,
        inbound routes, callbacks, recordings, blacklist, followme,
        voicemail toggle, modules, firewall config, SSL certs, CDR
        search, system reload (``doreload``), and more.

        Returns the ``data`` block from the response on success.
        Raises:
            FreePBXAuthError on token rejection (after one re-login
                retry).
            FreePBXApiError on GraphQL ``errors`` array OR non-2xx
                HTTP. The error detail surfaces the first GraphQL
                error's message so the caller sees the actual cause
                (field not found, validation failure, etc.).
        """
        if not self._session:
            raise FreePBXConnectionError("FreePBX REST client not connected")

        url = f"{self._base_url}/admin/api/api/gql"
        body: dict[str, Any] = {"query": query}
        if variables:
            body["variables"] = variables
        if operation_name:
            body["operationName"] = operation_name

        async def _do_request(token: str) -> tuple[int, str]:
            async with self._session.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json=body,
            ) as resp:
                return resp.status, await resp.text()

        token = await self._ensure_oauth2_token()
        # Transient connection blips are retried with backoff ONLY for
        # idempotent calls (reads, and update/delete by stable key). Writes
        # default to a single attempt — auto-retrying a create could
        # double-write since addExtension/addInboundRoute aren't deduped
        # server-side. A FreePBXApiError (HTTP!=200 / GraphQL errors array) is
        # a definitive server response and is never retried.
        attempts = REST_MAX_RETRIES if idempotent else 1
        for attempt in range(1, attempts + 1):
            try:
                status, text = await _do_request(token)
                if status == 401:
                    logger.debug("FreePBX GraphQL 401 — refreshing token")
                    async with self._oauth2_lock:
                        # Re-login only if another coroutine hasn't already
                        # refreshed the (now-rejected) token under the lock.
                        if self._oauth2_token == token:
                            await self._oauth2_login()
                    token = self._oauth2_token or ""
                    status, text = await _do_request(token)
                if status != 200:
                    raise FreePBXApiError(
                        f"FreePBX GraphQL returned HTTP {status}: {text[:200]}",
                        status_code=status,
                    )
                try:
                    payload = _json.loads(text)
                except _json.JSONDecodeError as exc:
                    raise FreePBXApiError(
                        f"FreePBX GraphQL returned non-JSON: {text[:200]}"
                    ) from exc

                # GraphQL transports errors in a top-level ``errors`` array
                # alongside (or instead of) ``data``. Surface the first
                # error message — it's almost always more useful than the
                # boilerplate.
                if payload.get("errors"):
                    first = payload["errors"][0]
                    msg = first.get("message", str(first))
                    raise FreePBXApiError(
                        f"FreePBX GraphQL error: {msg}",
                        status_code=200,
                    )
                return payload.get("data") or {}
            except (TimeoutError, aiohttp.ClientError, OSError) as exc:
                if attempt < attempts:
                    logger.debug(
                        "FreePBX GraphQL transient error (attempt %d/%d): %s",
                        attempt,
                        attempts,
                        exc,
                    )
                    await asyncio.sleep(REST_RETRY_DELAY * attempt)
                    continue
                raise FreePBXConnectionError(f"FreePBX GraphQL request failed: {exc}") from exc
        # Unreachable: the loop either returns or raises on the final attempt.
        raise FreePBXConnectionError("FreePBX GraphQL request failed")

    async def _rest_get(self, path: str) -> Any:
        """GET ``/admin/api/api/rest/<path>`` with Bearer auth.

        Used by methods that prefer the modern REST surface when
        OAuth2 is the active auth mode. Caller passes the path
        AFTER ``/admin/api/api/rest/`` (e.g. ``"core/users"``).

        Raises :class:`FreePBXApiError` on non-2xx,
        :class:`FreePBXAuthError` if the token gets rejected and
        re-login also fails.
        """
        if not self._session:
            raise FreePBXConnectionError("FreePBX REST client not connected")

        url = f"{self._base_url}/admin/api/api/rest/{path.lstrip('/')}"

        async def _do_request(token: str) -> tuple[int, str]:
            async with self._session.get(url, headers={"Authorization": f"Bearer {token}"}) as resp:
                return resp.status, await resp.text()

        token = await self._ensure_oauth2_token()
        try:
            status, body = await _do_request(token)
            # Token might have been rotated externally; re-login once.
            if status == 401:
                logger.debug("FreePBX REST 401 — refreshing OAuth2 token")
                async with self._oauth2_lock:
                    if self._oauth2_token == token:
                        await self._oauth2_login()
                token = self._oauth2_token or ""
                status, body = await _do_request(token)
            if status == 404:
                # The route isn't enabled for this M2M app's scopes
                # (or the underlying *_api module isn't installed).
                raise FreePBXApiError(
                    f"FreePBX REST {path!r} returned 404 — endpoint "
                    "not enabled for this M2M client or required "
                    "*_api module not installed",
                    status_code=404,
                )
            if status != 200:
                raise FreePBXApiError(
                    f"FreePBX REST {path!r} returned HTTP {status}: {body[:200]}",
                    status_code=status,
                )
            try:
                return _json.loads(body)
            except _json.JSONDecodeError as exc:
                raise FreePBXApiError(
                    f"FreePBX REST {path!r} returned non-JSON: {body[:200]}"
                ) from exc
        except (TimeoutError, aiohttp.ClientError, OSError) as exc:
            raise FreePBXConnectionError(f"FreePBX REST {path!r} request failed: {exc}") from exc

    # ── AJAX request helper ────────────────────────────────────────────

    def _ajax_headers(self) -> dict[str, str]:
        """Standard headers required by FreePBX AJAX endpoints.

        FreePBX validates the ``Referer`` header against
        ``$_SERVER['HTTP_HOST']``, which omits default ports (443 for HTTPS,
        80 for HTTP).  We must therefore strip the port from the Referer /
        Origin when it matches the scheme default.
        """
        # Build origin without redundant default port
        default_port = 443 if self.use_ssl else 80
        if self.port == default_port:
            origin = f"{self._scheme}://{self.host}"
        else:
            origin = f"{self._scheme}://{self.host}:{self.port}"

        return {
            "Referer": f"{origin}/admin/config.php?display=extensions",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": origin,
            "Host": self.host,
        }

    async def _ajax_get(
        self,
        params: str,
        *,
        _retry: bool = True,
    ) -> Any:
        """
        GET ``/admin/ajax.php?<params>`` with session auth.

        Automatically re-authenticates on 403 / session-expired once.
        Returns the parsed JSON response.
        """
        if not self._session:
            raise FreePBXConnectionError("FreePBX REST client not connected")
        if not self._api_available:
            raise FreePBXApiError("FreePBX REST API is not available on this system")

        url = f"{self._base_url}/admin/ajax.php?{params}"
        headers = self._ajax_headers()

        last_exc: Exception | None = None
        for attempt in range(1, REST_MAX_RETRIES + 1):
            try:
                async with self._session.get(
                    url,
                    headers=headers,
                ) as resp:
                    body_text = await resp.text()

                    # Session expired — re-login once
                    if resp.status == 403 and _retry:
                        logger.debug("AJAX 403 — re-authenticating")
                        await self._web_login()
                        return await self._ajax_get(params, _retry=False)

                    if resp.status == 403:
                        raise FreePBXAuthError("FreePBX AJAX request forbidden after re-auth")

                    if resp.status != 200:
                        raise FreePBXApiError(
                            f"FreePBX AJAX returned HTTP {resp.status}: {body_text[:200]}",
                            status_code=resp.status,
                        )

                    # Parse JSON
                    try:
                        data = _json.loads(body_text)
                    except _json.JSONDecodeError:
                        raise FreePBXApiError(f"FreePBX AJAX returned non-JSON: {body_text[:200]}")

                    # FreePBX returns {"message": null} for empty results
                    if isinstance(data, dict) and data == {"message": None}:
                        return []

                    # Some endpoints return {"error": "..."}
                    if isinstance(data, dict) and "error" in data:
                        err = data["error"]
                        if isinstance(err, str) and "declined" in err.lower():
                            if _retry:
                                await self._web_login()
                                return await self._ajax_get(params, _retry=False)
                            raise FreePBXAuthError(f"FreePBX AJAX: {err}")
                        raise FreePBXApiError(
                            f"FreePBX AJAX error: {err}",
                            status_code=resp.status,
                        )

                    return data

            except (TimeoutError, aiohttp.ClientError, OSError) as exc:
                last_exc = exc
                if attempt < REST_MAX_RETRIES:
                    await asyncio.sleep(REST_RETRY_DELAY * attempt)
                    continue
                raise FreePBXConnectionError(
                    f"FreePBX AJAX request failed after {REST_MAX_RETRIES} retries: {exc}"
                ) from exc

        raise FreePBXConnectionError(f"FreePBX AJAX request exhausted retries: {last_exc}")

    # ═══════════════════════════════════════════════════════════════════
    # Check API availability
    # ═══════════════════════════════════════════════════════════════════

    async def check_availability(self) -> dict[str, bool]:
        """
        Probe which AJAX endpoints respond.

        Returns dict of module name → bool.
        """
        results: dict[str, bool] = {}
        for name, params in FREEPBX_AJAX_ENDPOINTS.items():
            try:
                data = await self._ajax_get(params)
                results[name] = data is not None
            except (FreePBXApiError, FreePBXConnectionError):
                results[name] = False
        return results

    # ═══════════════════════════════════════════════════════════════════
    # Extensions
    # ═══════════════════════════════════════════════════════════════════

    async def list_extensions(self) -> list[dict[str, Any]]:
        """List all extensions.

        Auth dispatch (priority order):
            1. GraphQL ``fetchAllExtensions`` — preferred under OAuth2.
               Returns the full ext list with extension/name/tech/email
               in one round-trip.
            2. REST ``GET /admin/api/api/rest/core/users`` — fallback
               under OAuth2 if GraphQL is unreachable for some reason.
            3. AJAX grid endpoint — session-auth fallback for installs
               without M2M configured.

        All three normalise to ``list[dict[str, Any]]`` so callers
        don't see the wire-format difference.
        """
        if self._auth_mode == "oauth2":
            try:
                data = await self._graphql(
                    "{ fetchAllExtensions { status message totalCount "
                    "extension { id extensionId user { name } } } }"
                )
                wrapper = data.get("fetchAllExtensions") or {}
                items = wrapper.get("extension") or []
                # Normalise to the legacy shape callers expect.
                return [
                    {
                        "extension": e.get("extensionId") or e.get("id"),
                        "name": (e.get("user") or {}).get("name", ""),
                        **{k: v for k, v in e.items() if k != "user"},
                    }
                    for e in items
                    if isinstance(e, dict)
                ]
            except (FreePBXApiError, FreePBXConnectionError) as exc:
                logger.debug(
                    "fetchAllExtensions GraphQL failed (%s), trying REST",
                    exc,
                )
                # REST fallback: {"200": {"extension": "200", ...}, ...}
                try:
                    data = await self._rest_get("core/users")
                    if isinstance(data, dict):
                        return [
                            {**v, "extension": v.get("extension", k)}
                            if isinstance(v, dict)
                            else {"extension": k, "value": v}
                            for k, v in data.items()
                        ]
                    if isinstance(data, list):
                        return data
                    return []
                except FreePBXApiError:
                    pass

        # Session-auth fallback. Connection/auth failures here escape as
        # FreePBXConnectionError / FreePBXAuthError, which do NOT inherit from
        # FreePBXError (they extend the Adapter*Error bases), so the adapter's
        # ``except FreePBXError`` would miss them and surface a raw 500. Re-wrap
        # them as FreePBXApiError (a FreePBXError) so the adapter maps the
        # failure cleanly (middleware: conn -> 502, auth -> 401) instead of
        # leaking an unhandled exception.
        try:
            result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["extensions"])
        except (FreePBXConnectionError, FreePBXAuthError) as exc:
            raise FreePBXApiError(f"FreePBX extension listing failed: {exc}") from exc
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", result.get("extensions", []))
        return []

    async def get_extension(self, ext_number: str) -> dict[str, Any] | None:
        """Get a specific extension (from the full list)."""
        extensions = await self.list_extensions()
        for ext in extensions:
            if str(ext.get("extension", ext.get("id", ""))) == str(ext_number):
                return ext
        return None

    # GraphQL {add,update}ExtensionInput fields (camelCase, from live schema
    # introspection). Loose snake/lower payload keys are mapped onto these so
    # the staged payload doesn't have to know FreePBX's exact casing.
    _EXTENSION_INPUT_ALIASES = {
        "outboundcid": "outboundCid",
        "emergencycid": "emergencyCid",
        "callerid": "callerID",
        "channelname": "channelName",
        "vmenable": "vmEnable",
        "vmpassword": "vmPassword",
        "extpassword": "extPassword",
        "umenable": "umEnable",
        "umgroups": "umGroups",
        "umpassword": "umPassword",
        "maxcontacts": "maxContacts",
    }
    _EXTENSION_INPUT_FIELDS = {
        "tech",
        "channelName",
        "name",
        "outboundCid",
        "emergencyCid",
        "email",
        "umEnable",
        "umGroups",
        "vmEnable",
        "vmPassword",
        "callerID",
        "extPassword",
        "umPassword",
        "maxContacts",
    }

    def _extension_input(self, ext_number: str, data: dict[str, Any]) -> dict[str, Any]:
        """Build a {add,update}ExtensionInput from a staged payload.

        Always sets ``extensionId``. Maps loose keys (e.g. ``outboundcid``) to
        the GraphQL field (``outboundCid``) and drops unknown / empty values so
        an update never clobbers a field the operator didn't set.
        """
        inp: dict[str, Any] = {"extensionId": str(ext_number)}
        for key, val in (data or {}).items():
            if val is None or val == "":
                continue
            field = (
                key
                if key in self._EXTENSION_INPUT_FIELDS
                else self._EXTENSION_INPUT_ALIASES.get(key.lower())
            )
            if field:
                inp[field] = val
        return inp

    @staticmethod
    def _gql_write_result(data_block: dict[str, Any] | None, field: str) -> dict[str, Any]:
        """Unwrap a mutation payload, raising on ``status: false``."""
        payload = (data_block or {}).get(field) or {}
        if payload.get("status") is False:
            raise FreePBXApiError(payload.get("message") or f"{field} failed")
        return payload

    async def create_extension(
        self, ext_number: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Create an extension via the FreePBX Admin API (GraphQL addExtension)."""
        if self._auth_mode != "oauth2":
            raise FreePBXApiError("Extension creation requires the FreePBX Admin API (OAuth2)")
        inp = self._extension_input(ext_number, data)
        # addExtension requires extensionId, name, email (all non-null) + a tech.
        inp.setdefault("tech", "pjsip")
        inp.setdefault("name", str(ext_number))
        inp.setdefault("email", "")
        result = await self._graphql(
            "mutation($input: addExtensionInput!){ addExtension(input:$input){ status message } }",
            variables={"input": inp},
        )
        return self._gql_write_result(result, "addExtension")

    async def update_extension(
        self, ext_number: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Update an extension via the FreePBX Admin API (GraphQL updateExtension)."""
        if self._auth_mode != "oauth2":
            raise FreePBXApiError("Extension update requires the FreePBX Admin API (OAuth2)")
        inp = self._extension_input(ext_number, data)
        result = await self._graphql(
            "mutation($input: updateExtensionInput!){ updateExtension(input:$input){ status message } }",
            variables={"input": inp},
        )
        return self._gql_write_result(result, "updateExtension")

    async def delete_extension(self, ext_number: str) -> None:
        """Delete an extension via the FreePBX Admin API (GraphQL deleteExtension)."""
        if self._auth_mode != "oauth2":
            raise FreePBXApiError("Extension deletion requires the FreePBX Admin API (OAuth2)")
        result = await self._graphql(
            "mutation($input: deleteExtensionInput!){ deleteExtension(input:$input){ status message } }",
            variables={"input": {"extensionId": str(ext_number)}},
        )
        self._gql_write_result(result, "deleteExtension")

    # ═══════════════════════════════════════════════════════════════════
    # Trunks
    # ═══════════════════════════════════════════════════════════════════

    async def list_trunks(self) -> list[dict[str, Any]]:
        """List all SIP trunks."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["trunks"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", result.get("trunks", []))
        return []

    async def get_trunk(self, trunk_id: str) -> dict[str, Any] | None:
        """Get a specific trunk with full PJSIP detail.

        Merges grid-level data from ``allTrunks`` with the PJSIP
        configuration scraped from the trunk edit page HTML.
        """
        # Start with grid data
        trunks = await self.list_trunks()
        base: dict[str, Any] = {}
        for t in trunks:
            if str(t.get("trunkid", t.get("channelid", ""))) == str(trunk_id):
                base = dict(t)
                break
        if not base:
            return None

        # Scrape PJSIP settings from the trunk config page
        pjsip = await self.get_trunk_pjsip_settings(trunk_id)
        if pjsip:
            base.update(pjsip)
        # Derive status from config fields
        base["status"] = self._derive_trunk_status(base)
        return base

    async def get_trunk_pjsip_settings(self, trunk_id: str) -> dict[str, Any]:
        """Scrape PJSIP trunk settings from the FreePBX config page.

        The AJAX API only returns grid-level trunk data.  Full PJSIP
        configuration (host, transport, codecs, authentication, etc.)
        is only available via the trunk edit HTML form.
        """
        if not self._session:
            raise FreePBXConnectionError("FreePBX REST client not connected")

        url = f"{self._base_url}/admin/config.php?display=trunks&extdisplay={trunk_id}"
        try:
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    logger.warning(
                        "Trunk config page returned %d for trunk %s",
                        resp.status,
                        trunk_id,
                    )
                    return {}
                html = await resp.text()
        except Exception as exc:
            logger.warning("Failed to fetch trunk config page: %s", exc)
            return {}

        return self._parse_trunk_html(html)

    @staticmethod
    def _parse_trunk_html(html: str) -> dict[str, Any]:
        """Extract form field values from a FreePBX trunk edit page."""
        settings: dict[str, Any] = {}

        # Identify radio-button field names (so we only keep the checked one)
        radio_names: set[str] = set()
        for m in re.finditer(
            r'<input[^>]*type=["\']radio["\'][^>]*name=["\']([^"\']+)["\']',
            html,
            re.I,
        ):
            radio_names.add(m.group(1))

        # ── non-radio <input> values ──
        for m in re.finditer(
            r'<input[^>]*\bname=["\']([^"\']+)["\'][^>]*\bvalue=["\']([^"\']*)["\']',
            html,
        ):
            name, val = m.group(1), m.group(2)
            if (
                name not in radio_names
                and val
                and val
                not in (
                    "Submit",
                    "Submit Changes",
                    "Delete",
                    "Duplicate",
                    "Reset",
                )
            ):
                settings[name] = val

        # ── checked radio buttons ──
        for m in re.finditer(
            r'<input[^>]*type=["\']radio["\'][^>]*checked[^>]*>',
            html,
            re.I,
        ):
            tag = m.group(0)
            nm = re.search(r'name=["\']([^"\']+)["\']', tag)
            vl = re.search(r'value=["\']([^"\']*)["\']', tag)
            if nm and vl:
                settings[nm.group(1)] = vl.group(1)

        # ── <select> with selected <option> ──
        for sel in re.finditer(
            r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</select>',
            html,
            re.DOTALL | re.I,
        ):
            sel_name = sel.group(1)
            body = sel.group(2)
            opt = re.search(
                r'<option[^>]*selected[^>]*value=["\']([^"\']*)["\']',
                body,
            ) or re.search(
                r'<option[^>]*value=["\']([^"\']*)["\'][^>]*selected',
                body,
            )
            if opt:
                settings[sel_name] = opt.group(1)

        # ── codec priorities ──
        # Checked codecs have value="N" AND checked attribute.
        # value may appear before or after name in the tag.
        codecs: dict[str, int] = {}
        for m in re.finditer(
            r'<input[^>]*\bchecked\b[^>]*name=["\']codec\[([^\]]+)\]["\'][^>]*value=["\'](\d+)["\']'
            r'|<input[^>]*value=["\'](\d+)["\'][^>]*name=["\']codec\[([^\]]+)\]["\'][^>]*\bchecked\b',
            html,
        ):
            if m.group(1):
                codecs[m.group(1)] = int(m.group(2))
            else:
                codecs[m.group(4)] = int(m.group(3))
        if codecs:
            # Sort by priority (lowest number = highest priority)
            ordered = sorted(codecs.items(), key=lambda kv: kv[1])
            settings["codecs"] = ", ".join(c[0] for c in ordered)
            settings["codec_priorities"] = codecs

        # ── clean up noise ──
        skip = {
            "display",
            "action",
            "extdisplay",
            "sv_trunk_name",
            "sv_channelid",
            "delete",
            "duplicate",
            "reset",
            "__csrf_token",
            "hcid",
        }
        return {k: v for k, v in settings.items() if k not in skip and not k.startswith("fw_")}

    @staticmethod
    def _derive_trunk_status(trunk: dict[str, Any]) -> str:
        """Derive a human-readable status from trunk configuration fields.

        Priority:
        1. ``disabled == "on"`` → ``"disabled"``
        2. ``registration == "send"`` (outbound) → ``"registered"``
        3. ``registration == "receive"`` → ``"online"``
        4. Everything else → ``"configured"``

        NOTE: This is a *config-derived* status, not a live registration
        check. A future enhancement could query AMI
        ``PJSIPShowRegistrations`` for true live state.
        """
        disabled = str(trunk.get("disabled", trunk.get("disabletrunk", "")))
        if disabled.lower() in ("on", "yes", "1", "true"):
            return "disabled"

        reg = str(trunk.get("registration", "")).lower()
        if reg == "send":
            return "registered"
        if reg == "receive":
            return "online"

        return "configured"

    async def list_trunks_with_details(self) -> list[dict[str, Any]]:
        """List all trunks with full PJSIP detail (grid + config page).

        Fetches trunk config pages in parallel via asyncio.gather
        to avoid N+1 sequential HTTP requests.
        """
        import asyncio

        trunks = await self.list_trunks()
        if not trunks:
            return []

        trunk_ids = [str(t.get("trunkid", t.get("channelid", ""))) for t in trunks]

        # Parallel fetch all trunk config pages at once
        pjsip_results = await asyncio.gather(
            *(self.get_trunk_pjsip_settings(tid) for tid in trunk_ids),
            return_exceptions=True,
        )

        detailed: list[dict[str, Any]] = []
        for t, pjsip in zip(trunks, pjsip_results, strict=False):
            if isinstance(pjsip, Exception):
                pjsip = {}  # graceful fallback
            merged = {**t, **pjsip}
            merged["status"] = self._derive_trunk_status(merged)
            detailed.append(merged)
        return detailed

    async def create_trunk(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """Create a SIP trunk — not supported via AJAX (read-only)."""
        raise FreePBXApiError(
            "Trunk creation requires FreePBX REST API (OAuth2) or direct AMI access"
        )

    async def update_trunk(self, trunk_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Update a SIP trunk — not supported via AJAX (read-only)."""
        raise FreePBXApiError(
            "Trunk update requires FreePBX REST API (OAuth2) or direct AMI access"
        )

    async def delete_trunk(self, trunk_id: str) -> None:
        """Delete a SIP trunk — not supported via AJAX (read-only)."""
        raise FreePBXApiError(
            "Trunk deletion requires FreePBX REST API (OAuth2) or direct AMI access"
        )

    # ═══════════════════════════════════════════════════════════════════
    # Ring Groups
    # ═══════════════════════════════════════════════════════════════════

    async def list_ring_groups(self) -> list[dict[str, Any]]:
        """List all ring groups.

        GraphQL path uses ``fetchAllRingGroups { ringgroups { ... } }`` —
        the sanctioned FreePBX 16+ surface. Session/AJAX fallback for
        installs without M2M.
        """
        if self._auth_mode == "oauth2":
            try:
                data = await self._graphql(
                    "{ fetchAllRingGroups { ringgroups { id groupNumber "
                    "description groupList groupTime strategy callRecording "
                    "alertInfo ringingMusic } totalCount status message } }"
                )
                wrapper = data.get("fetchAllRingGroups") or {}
                return wrapper.get("ringgroups") or []
            except (FreePBXApiError, FreePBXConnectionError) as exc:
                logger.debug(
                    "fetchAllRingGroups GraphQL failed (%s); falling back to AJAX",
                    exc,
                )

        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["ring_groups"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", result.get("ringgroups", []))
        return []

    async def get_ring_group(self, grpnum: str) -> dict[str, Any] | None:
        """Get a specific ring group."""
        groups = await self.list_ring_groups()
        for rg in groups:
            if str(rg.get("grpnum", "")) == str(grpnum):
                return rg
        return None

    # GraphQL {add,update}RingGroupInput camelCase fields (from live schema).
    _RINGGROUP_INPUT_ALIASES = {
        "grpnum": "groupNumber",
        "grplist": "extensionList",
        "extension_list": "extensionList",
        "ringtime": "ringTime",
        "grppre": "groupPrefix",
        "group_prefix": "groupPrefix",
    }
    _RINGGROUP_INPUT_FIELDS = {
        "groupNumber",
        "description",
        "strategy",
        "extensionList",
        "ringTime",
        "groupPrefix",
        "alertInfo",
        "ringingMusic",
        "changecid",
        "fixedcid",
    }

    def _ringgroup_input(self, data: dict[str, Any]) -> dict[str, Any]:
        inp: dict[str, Any] = {}
        for key, val in (data or {}).items():
            if val is None or val == "":
                continue
            field = (
                key
                if key in self._RINGGROUP_INPUT_FIELDS
                else self._RINGGROUP_INPUT_ALIASES.get(key.lower())
            )
            if field:
                inp[field] = val
        return inp

    async def create_ring_group(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """Create a ring group via the FreePBX Admin API (GraphQL addRingGroup)."""
        if self._auth_mode != "oauth2":
            raise FreePBXApiError("Ring group creation requires the FreePBX Admin API (OAuth2)")
        result = await self._graphql(
            "mutation($input: addRingGroupInput!){ addRingGroup(input:$input){ status message } }",
            variables={"input": self._ringgroup_input(data)},
        )
        return self._gql_write_result(result, "addRingGroup")

    async def update_ring_group(self, grpnum: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Update a ring group via the FreePBX Admin API (GraphQL updateRingGroup)."""
        if self._auth_mode != "oauth2":
            raise FreePBXApiError("Ring group update requires the FreePBX Admin API (OAuth2)")
        inp = self._ringgroup_input(data)
        inp["groupNumber"] = str(grpnum)
        result = await self._graphql(
            "mutation($input: updateRingGroupInput!){ updateRingGroup(input:$input){ status message } }",
            variables={"input": inp},
        )
        return self._gql_write_result(result, "updateRingGroup")

    async def delete_ring_group(self, grpnum: str) -> None:
        """Delete a ring group via the FreePBX Admin API (GraphQL deleteRingGroup)."""
        if self._auth_mode != "oauth2":
            raise FreePBXApiError("Ring group deletion requires the FreePBX Admin API (OAuth2)")
        result = await self._graphql(
            "mutation($input: DeleteRingGroupInput!){ deleteRingGroup(input:$input){ status message } }",
            variables={"input": {"groupNumber": str(grpnum)}},
        )
        self._gql_write_result(result, "deleteRingGroup")

    # ═══════════════════════════════════════════════════════════════════
    # Queues
    # ═══════════════════════════════════════════════════════════════════

    async def list_queues(self) -> list[dict[str, Any]]:
        """List all call queues."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["queues"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", result.get("queues", []))
        return []

    async def get_queue(self, queue_ext: str) -> dict[str, Any] | None:
        """Get a specific queue."""
        queues = await self.list_queues()
        for q in queues:
            if str(q.get("extension", "")) == str(queue_ext):
                return q
        return None

    async def create_queue(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """Create a queue — requires the FreePBX REST API (OAuth2)."""
        raise FreePBXApiError("Queue creation requires the FreePBX REST API (OAuth2)")

    async def update_queue(self, queue_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Update a queue — requires the FreePBX REST API (OAuth2)."""
        raise FreePBXApiError("Queue update requires the FreePBX REST API (OAuth2)")

    async def delete_queue(self, queue_id: str) -> None:
        """Delete a queue — requires the FreePBX REST API (OAuth2)."""
        raise FreePBXApiError("Queue deletion requires the FreePBX REST API (OAuth2)")

    # ═══════════════════════════════════════════════════════════════════
    # IVR
    # ═══════════════════════════════════════════════════════════════════

    async def list_ivrs(self) -> list[dict[str, Any]]:
        """List all IVR menus."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["ivr"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", result.get("ivrs", []))
        return []

    async def get_ivr(self, ivr_id: str) -> dict[str, Any] | None:
        """Get a specific IVR menu."""
        ivrs = await self.list_ivrs()
        for ivr in ivrs:
            if str(ivr.get("id", "")) == str(ivr_id):
                return ivr
        return None

    async def create_ivr(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """Create an IVR menu — requires the FreePBX REST API (OAuth2)."""
        raise FreePBXApiError("IVR creation requires the FreePBX REST API (OAuth2)")

    async def update_ivr(self, ivr_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Update an IVR menu — requires the FreePBX REST API (OAuth2)."""
        raise FreePBXApiError("IVR update requires the FreePBX REST API (OAuth2)")

    async def delete_ivr(self, ivr_id: str) -> None:
        """Delete an IVR menu — requires the FreePBX REST API (OAuth2)."""
        raise FreePBXApiError("IVR deletion requires the FreePBX REST API (OAuth2)")

    # ═══════════════════════════════════════════════════════════════════
    # DIDs / Inbound Routes
    # ═══════════════════════════════════════════════════════════════════

    async def list_dids(self) -> list[dict[str, Any]]:
        """List all DIDs (inbound routes).

        GraphQL path: ``allInboundRoutes { inboundRoutes { ... } }``.
        AJAX fallback for legacy installs.
        """
        if self._auth_mode == "oauth2":
            try:
                data = await self._graphql(
                    "{ allInboundRoutes { inboundRoutes { id extension cidnum "
                    "description privacyman alertinfo ringing mohclass } "
                    "totalCount } }",
                    idempotent=True,
                )
                wrapper = data.get("allInboundRoutes") or {}
                return wrapper.get("inboundRoutes") or []
            except (FreePBXApiError, FreePBXConnectionError) as exc:
                logger.debug(
                    "allInboundRoutes GraphQL failed (%s); falling back to AJAX",
                    exc,
                )

        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["dids"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", result.get("dids", []))
        return []

    # GraphQL {add,update}InboundRouteInput fields (snake/lower already match
    # the schema for most). Inbound routes are keyed by (extension, cidnum);
    # update therefore also needs oldExtension/oldCidnum to find the row.
    _DID_INPUT_FIELDS = {
        "extension",
        "cidnum",
        "description",
        "alertinfo",
        "ringing",
        "mohclass",
        "grppre",
        "delay_answer",
        "pricid",
        "privacyman",
        "reversal",
        "rvolume",
        "fanswer",
        "destination",
    }

    def _did_input(self, data: dict[str, Any]) -> dict[str, Any]:
        return {
            k: v
            for k, v in (data or {}).items()
            if k in self._DID_INPUT_FIELDS and v not in (None, "")
        }

    async def create_did(self, data: dict[str, Any]) -> dict[str, Any] | None:
        """Create an inbound route via the FreePBX Admin API (addInboundRoute)."""
        if self._auth_mode != "oauth2":
            raise FreePBXApiError("Inbound route creation requires the FreePBX Admin API (OAuth2)")
        result = await self._graphql(
            "mutation($input: addInboundRouteInput!){ addInboundRoute(input:$input){ status message } }",
            variables={"input": self._did_input(data)},
        )
        return self._gql_write_result(result, "addInboundRoute")

    async def update_did(self, did_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """Update an inbound route via the FreePBX Admin API (updateInboundRoute).

        Inbound routes have no surrogate id — they're keyed by
        (extension, cidnum). ``did_id`` is the current ``extension/cidnum``
        ("did/cid" form, or just the DID) and the payload carries the new
        values. We thread oldExtension/oldCidnum from ``did_id`` so FreePBX
        can locate the existing row.
        """
        if self._auth_mode != "oauth2":
            raise FreePBXApiError("Inbound route update requires the FreePBX Admin API (OAuth2)")
        old_ext, _, old_cid = str(did_id).partition("/")
        inp = self._did_input(data)
        inp.setdefault("extension", old_ext)
        inp["oldExtension"] = old_ext
        inp["oldCidnum"] = old_cid or data.get("cidnum") or ""
        result = await self._graphql(
            "mutation($input: updateInboundRouteInput!){ updateInboundRoute(input:$input){ status message } }",
            variables={"input": inp},
        )
        return self._gql_write_result(result, "updateInboundRoute")

    async def delete_did(self, did_id: str) -> None:
        """Delete an inbound route via the FreePBX Admin API (removeInboundRoute, by id)."""
        if self._auth_mode != "oauth2":
            raise FreePBXApiError("Inbound route deletion requires the FreePBX Admin API (OAuth2)")
        result = await self._graphql(
            "mutation($input: removeInboundRouteInput!){ removeInboundRoute(input:$input){ status message } }",
            variables={"input": {"id": str(did_id)}},
        )
        self._gql_write_result(result, "removeInboundRoute")

    # ═══════════════════════════════════════════════════════════════════
    # Outbound Routes
    # ═══════════════════════════════════════════════════════════════════

    async def list_outbound_routes(self) -> list[dict[str, Any]]:
        """List all outbound routes."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["outbound_routes"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", result.get("routes", []))
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Follow Me
    # ═══════════════════════════════════════════════════════════════════

    async def list_followme(self) -> list[dict[str, Any]]:
        """List all Follow-Me / Find-Me-Follow-Me configs."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["followme"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Announcements
    # ═══════════════════════════════════════════════════════════════════

    async def list_announcements(self) -> list[dict[str, Any]]:
        """List all announcement recordings / destinations."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["announcements"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Paging Groups
    # ═══════════════════════════════════════════════════════════════════

    async def list_paging_groups(self) -> list[dict[str, Any]]:
        """List all paging / intercom groups."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["paging"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Day/Night Control
    # ═══════════════════════════════════════════════════════════════════

    async def list_daynight(self) -> list[dict[str, Any]]:
        """List all day/night toggle controls."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["daynight"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Blacklist
    # ═══════════════════════════════════════════════════════════════════

    async def list_blacklist(self) -> list[dict[str, Any]]:
        """List all blacklisted caller numbers.

        OAuth2 path: GraphQL ``allBlacklists { blacklists { ... } }``.
        Session path: legacy AJAX grid.
        """
        if self._auth_mode == "oauth2":
            try:
                data = await self._graphql(
                    "{ allBlacklists { blacklists { id number description } totalCount } }"
                )
                return (data.get("allBlacklists") or {}).get("blacklists") or []
            except (FreePBXApiError, FreePBXConnectionError) as exc:
                logger.debug("allBlacklists GraphQL failed (%s)", exc)

        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["blacklist"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # PIN Sets
    # ═══════════════════════════════════════════════════════════════════

    async def list_pinsets(self) -> list[dict[str, Any]]:
        """List all PIN sets."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["pinsets"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Misc Destinations
    # ═══════════════════════════════════════════════════════════════════

    async def list_misc_destinations(self) -> list[dict[str, Any]]:
        """List all miscellaneous destinations."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["misc_destinations"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Admin Users
    # ═══════════════════════════════════════════════════════════════════

    async def list_admin_users(self) -> list[dict[str, Any]]:
        """List FreePBX admin / operator accounts.

        Strips password hashes for security — only returns usernames,
        roles, extensions, and department info.
        """
        _ADMIN_STRIP = {"password_sha1", "password", "sha1", "actions"}
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["admin_users"])
        if isinstance(result, list):
            for u in result:
                for k in _ADMIN_STRIP:
                    u.pop(k, None)
            return result
        if isinstance(result, dict):
            items = result.get("data", [])
            for u in items:
                for k in _ADMIN_STRIP:
                    u.pop(k, None)
            return items
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Certificates
    # ═══════════════════════════════════════════════════════════════════

    async def list_certificates(self) -> list[dict[str, Any]]:
        """List all TLS/SSL certificates managed by Certificate Manager."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["certificates"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Time Conditions
    # ═══════════════════════════════════════════════════════════════════

    async def list_time_conditions(self) -> list[dict[str, Any]]:
        """List time conditions / time-based routing rules."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["time_conditions"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Contact Manager
    # ═══════════════════════════════════════════════════════════════════

    async def list_contacts(self) -> list[dict[str, Any]]:
        """List contacts from the FreePBX contact manager."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["contacts"])
        if isinstance(result, list):
            # Strip password hashes and HTML actions for security
            for c in result:
                c.pop("password", None)
                c.pop("actions", None)
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # System Recordings
    # ═══════════════════════════════════════════════════════════════════

    async def list_system_recordings(self) -> list[dict[str, Any]]:
        """List system recordings (prompts, greetings, etc.)."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["system_recordings"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Music on Hold
    # ═══════════════════════════════════════════════════════════════════

    async def list_music_on_hold(self) -> list[dict[str, Any]]:
        """List music-on-hold categories.

        OAuth2 path: GraphQL ``allMusiconholds { musiconholds { ... } }``.
        Session path: legacy AJAX grid.
        """
        if self._auth_mode == "oauth2":
            try:
                data = await self._graphql(
                    "{ allMusiconholds { musiconholds { id category type "
                    "application format } totalCount } }"
                )
                return (data.get("allMusiconholds") or {}).get("musiconholds") or []
            except (FreePBXApiError, FreePBXConnectionError) as exc:
                logger.debug("allMusiconholds GraphQL failed (%s)", exc)

        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["music_on_hold"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # AMI Managers
    # ═══════════════════════════════════════════════════════════════════

    async def list_ami_managers(self) -> list[dict[str, Any]]:
        """List Asterisk Manager Interface accounts.

        Strips secret/password fields for security — only returns
        names, permissions, and network ACLs.
        """
        _AMI_STRIP = {"secret", "password", "ha1", "md5secret", "Actions"}
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["ami_managers"])
        if isinstance(result, list):
            for m in result:
                for k in _AMI_STRIP:
                    m.pop(k, None)
            return result
        if isinstance(result, dict):
            items = result.get("data", [])
            for m in items:
                for k in _AMI_STRIP:
                    m.pop(k, None)
            return items
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Backup Jobs
    # ═══════════════════════════════════════════════════════════════════

    async def list_backup_jobs(self) -> list[dict[str, Any]]:
        """List configured backup jobs."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["backup_jobs"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Callback
    # ═══════════════════════════════════════════════════════════════════

    async def list_callback(self) -> list[dict[str, Any]]:
        """List callback entries."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["callback"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # DISA (Direct Inward System Access)
    # ═══════════════════════════════════════════════════════════════════

    async def list_disa(self) -> list[dict[str, Any]]:
        """List DISA entries."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["disa"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Call Recording Modes
    # ═══════════════════════════════════════════════════════════════════

    async def list_call_recording_modes(self) -> list[dict[str, Any]]:
        """List call recording mode configurations."""
        result = await self._ajax_get(FREEPBX_AJAX_ENDPOINTS["call_recording_modes"])
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data", [])
        return []

    # ═══════════════════════════════════════════════════════════════════
    # SIP Settings (HTML scrape)
    # ═══════════════════════════════════════════════════════════════════

    async def get_sip_settings(self) -> dict[str, Any]:
        """Scrape SIP/PJSIP settings from the FreePBX settings page."""
        if not self._session:
            return {}
        url = f"{self._base_url}/admin/config.php?display=sipsettings"
        headers = self._ajax_headers()
        try:
            async with self._session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return {}
                html = await resp.text()
                import re as _re

                fields = _re.findall(r'name="([^"]+)"[^>]*value="([^"]*)"', html)
                sip_config: dict[str, Any] = {}
                skip = {"Submit", "category", "__csrf_magic", "submit", "reset"}
                for name, val in fields:
                    if name not in skip and val:
                        sip_config[name] = val
                return sip_config
        except Exception as exc:
            logger.debug("SIP settings scrape failed: %s", exc)
            return {}

    # ═══════════════════════════════════════════════════════════════════
    # Parking Lots (HTML scrape)
    # ═══════════════════════════════════════════════════════════════════

    async def get_parking_config(self) -> dict[str, Any]:
        """Scrape parking lot configuration from the settings page."""
        if not self._session:
            return {}
        url = f"{self._base_url}/admin/config.php?display=parking"
        headers = self._ajax_headers()
        try:
            async with self._session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return {}
                html = await resp.text()
                import re as _re

                fields = _re.findall(r'name="([^"]+)"[^>]*value="([^"]*)"', html)
                pk: dict[str, Any] = {}
                skip = {"Submit", "display", "action", "__csrf_magic", "submit", "reset"}
                for name, val in fields:
                    if name not in skip and val:
                        pk[name] = val
                return pk
        except Exception as exc:
            logger.debug("Parking config scrape failed: %s", exc)
            return {}

    # ═══════════════════════════════════════════════════════════════════
    # Feature Codes (HTML scrape)
    # ═══════════════════════════════════════════════════════════════════

    async def get_feature_codes(self) -> list[str]:
        """Scrape feature codes (star codes) from the admin page."""
        if not self._session:
            return []
        url = f"{self._base_url}/admin/config.php?display=featurecodeadmin"
        headers = self._ajax_headers()
        try:
            async with self._session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return []
                html = await resp.text()
                import re as _re

                codes = _re.findall(r'value="(\*\d+)"', html)
                return sorted(set(codes))
        except Exception as exc:
            logger.debug("Feature codes scrape failed: %s", exc)
            return []

    # ═══════════════════════════════════════════════════════════════════
    # Installed Modules (HTML scrape)
    # ═══════════════════════════════════════════════════════════════════

    async def get_installed_modules(self) -> list[str]:
        """Scrape list of installed FreePBX modules."""
        if not self._session:
            return []
        url = f"{self._base_url}/admin/config.php?display=modules"
        headers = self._ajax_headers()
        try:
            async with self._session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return []
                html = await resp.text()
                import re as _re

                mods = _re.findall(r'data-module="([^"]*)"', html)
                return sorted(set(mods))
        except Exception as exc:
            logger.debug("Module list scrape failed: %s", exc)
            return []

    # ═══════════════════════════════════════════════════════════════════
    # CDR (Call Detail Records) — not available via AJAX
    # ═══════════════════════════════════════════════════════════════════

    async def search_cdr(
        self,
        *,
        start_date: str | None = None,
        end_date: str | None = None,
        src: str | None = None,
        dst: str | None = None,
        disposition: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Search call detail records (not currently available via AJAX)."""
        logger.warning("CDR search via AJAX is not supported; returning empty list")
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Voicemail — not available via AJAX
    # ═══════════════════════════════════════════════════════════════════

    async def list_voicemail_boxes(self) -> list[dict[str, Any]]:
        """List all voicemail boxes (not available via AJAX)."""
        logger.warning("Voicemail listing via AJAX is not supported; returning empty list")
        return []

    async def get_voicemail_box(self, mailbox: str) -> dict[str, Any] | None:
        """Get a voicemail box (not available via AJAX)."""
        return None

    # ═══════════════════════════════════════════════════════════════════
    # System
    # ═══════════════════════════════════════════════════════════════════

    async def apply_config(self) -> dict[str, Any] | None:
        """Apply staged config (``fwconsole reload``) via the FreePBX Admin API.

        OAuth2 path: the GraphQL ``doreload`` mutation commits all pending
        config to the running Asterisk (the GraphQL writes land in the DB
        immediately but only take effect on reload). Returns the payload.
        AJAX/session mode has no reload endpoint — logs + returns None.
        """
        if self._auth_mode != "oauth2":
            logger.warning("apply_config not available via AJAX session auth")
            return None
        result = await self._graphql(
            "mutation($input: doreloadInput!){ doreload(input:$input){ status message } }",
            variables={"input": {}},
        )
        return self._gql_write_result(result, "doreload")

    async def get_system_status(self) -> dict[str, Any] | None:
        """Get system status / Asterisk details.

        OAuth2 path: GraphQL ``fetchAsteriskDetails { ... }`` — returns
        Asterisk version, status, AMI status, DB status, pending
        reload + module/security update flags. Rich data for the
        dashboard widgets.

        Session path: returns None (no AJAX equivalent exists).
        """
        if self._auth_mode == "oauth2":
            try:
                data = await self._graphql(
                    "{ fetchAsteriskDetails { id version engine needReload "
                    "message status asteriskStatus asteriskVersion amiStatus "
                    "dbStatus guiMode systemUpdates moduleUpdates "
                    "moduleSecurityUpdates } }",
                    idempotent=True,
                )
                return data.get("fetchAsteriskDetails")
            except (FreePBXApiError, FreePBXConnectionError) as exc:
                logger.debug("fetchAsteriskDetails GraphQL failed (%s)", exc)
        return None

    # ═══════════════════════════════════════════════════════════════════
    # Modules (GraphQL-only)
    # ═══════════════════════════════════════════════════════════════════

    async def list_module_status(self) -> list[dict[str, Any]]:
        """List every installed FreePBX module + status.

        OAuth2 path: GraphQL ``fetchAllModuleStatus { modules { ... } }``.
        Returns name, displayname, version, state for each module.

        Powers an "installed modules" admin pane and informs the
        adapter which feature surfaces are usable (e.g. if
        ``ivr_api`` isn't in the list, IVR CRUD via REST will 404 —
        the staging service captures intent but apply will 501).

        Session path: returns an empty list (no AJAX equivalent; the
        legacy :meth:`get_installed_modules` HTML-scraping path
        remains for the old code path callers).
        """
        if self._auth_mode == "oauth2":
            try:
                data = await self._graphql(
                    "{ fetchAllModuleStatus { modules { name displayname "
                    "version state } totalCount } }"
                )
                return (data.get("fetchAllModuleStatus") or {}).get("modules") or []
            except (FreePBXApiError, FreePBXConnectionError) as exc:
                logger.debug("fetchAllModuleStatus GraphQL failed (%s)", exc)
        return []

    # ═══════════════════════════════════════════════════════════════════
    # Callbacks (GraphQL-only)
    # ═══════════════════════════════════════════════════════════════════

    async def list_callbacks(self) -> list[dict[str, Any]]:
        """List Callback destinations.

        OAuth2 path: GraphQL ``allCallbacks { callbacks { ... } }``.
        Session path: returns an empty list — no AJAX equivalent
        exists for the callback module.
        """
        if self._auth_mode == "oauth2":
            try:
                data = await self._graphql(
                    "{ allCallbacks { callbacks { id description callbacknum "
                    "destination sleep } totalCount } }"
                )
                return (data.get("allCallbacks") or {}).get("callbacks") or []
            except (FreePBXApiError, FreePBXConnectionError) as exc:
                logger.debug("allCallbacks GraphQL failed (%s)", exc)
        return []

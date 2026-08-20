# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Grandstream Phone HTTP Client (GXP2170-class firmware)
================================================================

Per-phone HTTP client for Grandstream's CGI-based admin API.

The earlier client targeted an older firmware family and silently 404'd on
every modern GXP-21xx / GRP-26xx / GXP-22xx phone (it used
``/cgi-bin/api-send_request`` style endpoints that simply do not exist on
firmware ≥ 1.0.11). The rewrite below mirrors the *actual* protocol the
phone speaks — extracted from the GWT permutation bundle on a live unit
and confirmed end-to-end against a lab GXP2170 (firmware 1.0.11.106).

Protocol summary
----------------
* 3-step challenge-response auth using ``sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(x))``:

  1. ``POST /cgi-bin/access`` with ``access=sha256_hex(username)`` →
     returns a 31-char base64-ish token.
  2. ``POST /cgi-bin/dologin`` with
     ``username=<u>&password=sha256_hex(password + token)`` →
     returns ``{sid, role, mac, ver}``.
  3. Every subsequent request appends ``&sid=<sid>`` as a query param —
     the phone does NOT use Set-Cookie for the session.

* ``Origin:`` and ``Referer:`` headers are MANDATORY. Missing them yields
  a 403 *before* the auth code even runs.

* 5 failed dologins lock the user account (queryable via ``/cgi-bin/api-get_lockout``).
  Treat that as a hard error — don't retry on ``"locked"``.

* The session expires unless ``POST /cgi-bin/dorefresh`` is hit every ~30 s.
  This client starts a background task to do that automatically.

Public API (preserved from the old client so ``adapter.py`` works unchanged):
    connect / disconnect / get_status / get_config / set_config / reboot /
    factory_reset. New methods added: ``get_accounts``, ``get_line_status``,
    ``get_screenshot``, ``make_call``, ``phone_operation``, ``get_lockout``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
from typing import Any
from urllib.parse import urlencode

import aiohttp

from app.core.http_client import build_aiohttp_session

from .constants import (
    PHONE_API_ACCESS,
    PHONE_API_CONFIG_GET,
    PHONE_API_CONFIG_UPDATE,
    PHONE_API_DOLOGIN,
    PHONE_API_DOLOGOUT,
    PHONE_API_DOREFRESH,
    PHONE_API_GET_ACCOUNTS,
    PHONE_API_GET_LINE_STATUS,
    PHONE_API_GET_LOCKOUT,
    PHONE_API_GET_PHONE_STATUS,
    PHONE_API_GET_SCREENSHOT,
    PHONE_API_GET_SYSTEM_STATUS,
    PHONE_API_GET_TIME,
    PHONE_API_MAKE_CALL,
    PHONE_API_PHONE_OPERATION,
    PHONE_API_SYS_OPERATION,
    PHONE_DEFAULT_PORT,
    PHONE_DEFAULT_USERNAME,
    PHONE_KEEPALIVE_INTERVAL,
    PHONE_MAX_RETRIES,
    PHONE_REQUEST_TIMEOUT,
)
from .exceptions import (
    GrandstreamApiError,
    GrandstreamAuthError,
    GrandstreamConnectionError,
)
from .models import (
    PhoneInfo,
    PhoneStatus,
    RegistrationStatus,
    SIPAccountStatus,
)

logger = logging.getLogger("freesdn.adapters.grandstream.client")


def _sha256_hex(value: str) -> str:
    """sjcl-compatible: hex-encoded SHA-256."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class GrandstreamPhoneClient:
    """
    Async HTTP client for a single Grandstream phone.

    Usage::

        client = GrandstreamPhoneClient(
            host="192.0.2.10",
            password="<phone-admin-password>",
            username="admin",          # default
            use_ssl=False,
            acknowledge_plaintext=True,
        )
        async with client:
            status = await client.get_status()
            await client.set_config({"P35": "203"})
            await client.reboot()
    """

    def __init__(
        self,
        host: str,
        password: str,
        *,
        username: str = PHONE_DEFAULT_USERNAME,
        port: int = PHONE_DEFAULT_PORT,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        acknowledge_plaintext: bool = False,
    ):
        if not use_ssl and not acknowledge_plaintext:
            raise GrandstreamConnectionError(
                f"Refusing to connect to {host} over plain HTTP: "
                "set acknowledge_plaintext=True on the phone record to opt in"
            )
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl

        self._scheme = "https" if use_ssl else "http"
        self._base_url = f"{self._scheme}://{self.host}:{self.port}"

        self._session: aiohttp.ClientSession | None = None
        self._connected = False
        self._sid: str | None = None
        # Captured at login time from the dologin response body
        self._role: str | None = None
        self._mac: str | None = None
        self._ver: str | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._connector_ssl: bool | None = verify_ssl if use_ssl else None

    # ── properties ─────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def sid(self) -> str | None:
        return self._sid

    @property
    def mac(self) -> str | None:
        return self._mac

    @property
    def role(self) -> str | None:
        return self._role

    # ── headers ────────────────────────────────────────────────────────

    def _headers(self, *, json_body: bool = False) -> dict[str, str]:
        """Build the Origin/Referer headers the phone requires."""
        h = {
            "User-Agent": "FreeSDN/1.0 GrandstreamClient",
            "Accept": "*/*",
            "Origin": self._base_url,
            "Referer": f"{self._base_url}/",
            "X-Requested-With": "XMLHttpRequest",
        }
        if json_body:
            h["Content-Type"] = "application/json"
        return h

    # ── lifecycle ──────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Create session, run the 3-step auth, start the keep-alive task."""
        if self._connected:
            return

        connector = aiohttp.TCPConnector(ssl=self._connector_ssl)
        # sock_connect caps the TCP-connect phase so an unreachable phone fails
        # fast (~8s) instead of hanging up to the (long) total request timeout.
        timeout = aiohttp.ClientTimeout(total=PHONE_REQUEST_TIMEOUT, sock_connect=8.0)
        # NOTE: aiohttp's default CookieJar refuses to store cookies for
        # IP-address-based URLs (RFC 6265). The phone is always reached
        # by IP, and uses Set-Cookie for ``session-identity`` /
        # ``session-role`` which is how every ``/cgi-bin/api-*`` endpoint
        # authenticates. We MUST use ``CookieJar(unsafe=True)`` here, or
        # every authenticated call after dologin will 401.
        cookie_jar = aiohttp.CookieJar(unsafe=True)
        self._session = build_aiohttp_session(
            connector=connector,
            timeout=timeout,
            cookie_jar=cookie_jar,
        )

        try:
            # NOTE: we used to call ``_check_lockout()`` here as a pre-flight,
            # but it racy-times-out on busy phones and silently lengthens
            # connect latency. ``_login()`` already raises
            # ``GrandstreamAuthError("…is locked out…")`` when the phone
            # responds with ``body="locked"`` — that's the authoritative
            # signal. External callers can still invoke ``get_lockout()``
            # directly if they want to probe lockout state explicitly.
            await self._login()
        except Exception:
            if self._session and not self._session.closed:
                await self._session.close()
            self._session = None
            raise

        self._connected = True

        # Background keep-alive — the phone tears the session down after
        # ~60 s of silence. The browser polls dorefresh every ~30 s.
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

        # Orphan-task hygiene: if the keepalive loop crashes
        # (Grandstream firmware reboot, NAT timeout, etc.) the
        # exception used to vanish into asyncio's task GC and the
        # phone session silently went stale. Log at warning so
        # operators can see why a phone "lost" its admin session.
        def _on_keepalive_done(t: asyncio.Task[Any]) -> None:
            if t.cancelled():
                return
            e = t.exception()
            if e is not None:
                logger.warning(
                    "Grandstream keepalive task crashed (%s mac=%s): %s",
                    self.host,
                    self._mac,
                    e,
                )

        self._keepalive_task.add_done_callback(_on_keepalive_done)
        logger.info(
            "Connected to Grandstream phone at %s (role=%s mac=%s)",
            self.host,
            self._role,
            self._mac,
        )

    async def disconnect(self) -> None:
        """Stop the keep-alive, call dologout, close the session."""
        if self._keepalive_task:
            self._keepalive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._keepalive_task
            self._keepalive_task = None

        if self._sid and self._session and not self._session.closed:
            # Best-effort logout — don't raise if the phone already
            # tore the session down.
            with contextlib.suppress(Exception):
                await self._session.post(
                    f"{self._base_url}{PHONE_API_DOLOGOUT}",
                    data={"sid": self._sid},
                    headers=self._headers(),
                )

        self._connected = False
        self._sid = None
        self._role = None
        self._mac = None
        self._ver = None
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def close(self) -> None:
        await self.disconnect()

    async def __aenter__(self) -> GrandstreamPhoneClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.disconnect()

    # ── auth flow ──────────────────────────────────────────────────────

    async def _check_lockout(self) -> None:
        """Fail fast if the phone has locked the admin out (5 failed logins).

        Best-effort: only ``"lockout"`` causes us to raise. Network timeouts,
        404s, or other probe failures fall through silently — the subsequent
        ``_login()`` will surface any real connectivity problem with a clearer
        error.
        """
        assert self._session is not None
        try:
            # Short timeout so a busy phone doesn't block login.
            async with self._session.get(
                f"{self._base_url}{PHONE_API_GET_LOCKOUT}",
                headers=self._headers(),
                timeout=aiohttp.ClientTimeout(total=3),
            ) as resp:
                if resp.status != 200:
                    return
                try:
                    body = await resp.json(content_type=None)
                except Exception:
                    return
                if str(body.get("body", "")).lower() == "lockout":
                    raise GrandstreamAuthError(
                        f"Grandstream phone {self.host} is locked out "
                        "(5+ failed logins). Wait for the phone-side timeout "
                        "or factory-reset before retrying."
                    )
        except GrandstreamAuthError:
            raise
        except (aiohttp.ClientError, TimeoutError):
            # Phone may be slow / probe path may not exist on some firmware.
            # Let _login() be the authoritative connectivity test.
            return

    async def _login(self) -> None:
        """Run the 3-step challenge-response auth."""
        assert self._session is not None

        # Step 1 — access challenge. Body must be ``access=sha256_hex(username)``.
        try:
            async with self._session.post(
                f"{self._base_url}{PHONE_API_ACCESS}",
                data={"access": _sha256_hex(self.username)},
                headers=self._headers(),
            ) as resp:
                if resp.status == 403:
                    raise GrandstreamAuthError(
                        f"Grandstream phone at {self.host} returned 403 — "
                        "missing Origin/Referer headers or wrong scheme"
                    )
                if resp.status != 200:
                    raise GrandstreamApiError(
                        f"Access challenge failed: HTTP {resp.status}",
                        status_code=resp.status,
                    )
                challenge = await resp.json(content_type=None)
        except aiohttp.ClientError as exc:
            raise GrandstreamConnectionError(
                f"Cannot reach Grandstream phone at {self.host}: {exc}"
            ) from exc

        if challenge.get("response") != "success" or not challenge.get("body"):
            raise GrandstreamAuthError(
                f"Grandstream phone at {self.host} rejected access challenge: {challenge!r}"
            )
        token = str(challenge["body"])

        # Step 2 — dologin. Password is ``sha256_hex(password + token)``.
        try:
            async with self._session.post(
                f"{self._base_url}{PHONE_API_DOLOGIN}",
                data={
                    "username": self.username,
                    "password": _sha256_hex(self.password + token),
                },
                headers=self._headers(),
            ) as resp:
                if resp.status != 200:
                    raise GrandstreamApiError(
                        f"dologin failed: HTTP {resp.status}",
                        status_code=resp.status,
                    )
                login = await resp.json(content_type=None)
        except aiohttp.ClientError as exc:
            raise GrandstreamConnectionError(
                f"Cannot reach Grandstream phone at {self.host}: {exc}"
            ) from exc

        # Body shape on success:
        #   {response: "success",
        #    body: {sid, role, ver, mac, defaultAuth}}
        # On failure:
        #   {response: "error", body: "wrong4" | "wrong3" | … | "locked"}
        body = login.get("body")
        if login.get("response") != "success" or not isinstance(body, dict):
            err = body if isinstance(body, str) else "unknown"
            if err == "locked":
                raise GrandstreamAuthError(
                    f"Phone {self.host} is locked out (5+ failed logins). "
                    "Wait for timeout or factory-reset."
                )
            raise GrandstreamAuthError(f"Phone {self.host} rejected credentials: {err}")

        self._sid = body.get("sid")
        self._role = body.get("role")
        self._mac = body.get("mac")
        self._ver = body.get("ver")
        if not self._sid:
            raise GrandstreamAuthError(f"Phone {self.host} login succeeded but returned no sid")

    async def _keepalive_loop(self) -> None:
        """Periodically POST /cgi-bin/dorefresh to keep the session alive."""
        try:
            while self._connected and self._sid:
                await asyncio.sleep(PHONE_KEEPALIVE_INTERVAL)
                if not self._connected or not self._sid:
                    return
                with contextlib.suppress(Exception):
                    assert self._session is not None
                    await self._session.post(
                        f"{self._base_url}{PHONE_API_DOREFRESH}",
                        data={"sid": self._sid},
                        headers=self._headers(),
                    )
        except asyncio.CancelledError:
            return

    # ── internal request helper ────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        json_body: list | dict | None = None,
        include_sid: bool = False,
    ) -> dict[str, Any] | list | str:
        """Send an authenticated request to the phone.

        The phone sets two cookies at dologin time:
          ``session-identity=<sid>``  and  ``session-role=<role>``
        (HttpOnly, path=/cgi-bin) and ALL ``/cgi-bin/api-*`` endpoints
        authenticate via those cookies. aiohttp carries them in the same
        ``ClientSession`` automatically, so the default is ``include_sid=False``.

        ONLY ``/cgi-bin/config_get`` and ``/cgi-bin/config_update`` also
        require the sid to be threaded through the query string —
        :meth:`get_config` and :meth:`set_config` pass ``include_sid=True``
        for that.

        Re-login once on a 401 (session expired) before failing.
        """
        if not self._session:
            raise GrandstreamConnectionError("Not connected to phone")

        # Most endpoints rely on the cookie that aiohttp already carries.
        # Only config_get / config_update need the explicit sid query.
        query = dict(params or {})
        if include_sid and self._sid:
            query["sid"] = self._sid

        qs = ("?" + urlencode(query)) if query else ""
        url = f"{self._base_url}{path}{qs}"

        last_exc: Exception | None = None
        for attempt in range(1, PHONE_MAX_RETRIES + 1):
            try:
                if json_body is not None:
                    req = self._session.request(
                        method,
                        url,
                        json=json_body,
                        headers=self._headers(json_body=True),
                    )
                else:
                    req = self._session.request(
                        method,
                        url,
                        data=data,
                        headers=self._headers(),
                    )
                async with req as resp:
                    if resp.status == 401:
                        if attempt == 1:
                            # Try to recover by re-logging-in once.
                            with contextlib.suppress(Exception):
                                await self._login()
                            continue
                        raise GrandstreamAuthError("Phone session expired")

                    if resp.status >= 400:
                        raise GrandstreamApiError(
                            f"Phone API error: HTTP {resp.status}",
                            status_code=resp.status,
                        )

                    content_type = resp.content_type or ""
                    if "json" in content_type:
                        return await resp.json(content_type=None)
                    text = await resp.text()
                    # Many of the api-* endpoints return JSON with
                    # text/plain content-type. Try to parse defensively.
                    try:
                        return json.loads(text)
                    except (ValueError, json.JSONDecodeError):
                        return text

            except aiohttp.ClientError as exc:
                last_exc = exc
                if attempt < PHONE_MAX_RETRIES:
                    await asyncio.sleep(1.0)
                    continue
                raise GrandstreamConnectionError(f"Phone request failed: {exc}") from exc

        raise GrandstreamConnectionError(f"Phone request exhausted retries: {last_exc}")

    # ═══════════════════════════════════════════════════════════════════
    # Configuration read/write
    # ═══════════════════════════════════════════════════════════════════

    async def get_config(self, p_values: list[str] | None = None) -> dict[str, str]:
        """
        Read configuration values from the phone.

        ``p_values`` accepts BOTH the legacy numeric P-values (``P35``,
        ``P124``, …) and the firmware-1.0.11+ named keys
        (``phone_model``, ``vendor_fullname``, ``AccountRegistered1``,
        ``AccountRegisteredServer1``, …). Older numeric P-values that
        don't exist on this firmware return empty strings rather than
        erroring — be defensive.

        Calling with ``p_values=None`` returns a small default set
        (model + vendor + 6 account registration statuses) — the same
        bundle the status_account.js page requests.
        """
        if p_values is None:
            p_values = [
                "phone_model",
                "vendor_fullname",
                "AccountRegistered1",
                "AccountRegisteredServer1",
                "AccountRegistered2",
                "AccountRegisteredServer2",
                "AccountRegistered3",
                "AccountRegisteredServer3",
                "AccountRegistered4",
                "AccountRegisteredServer4",
                "AccountRegistered5",
                "AccountRegisteredServer5",
                "AccountRegistered6",
                "AccountRegisteredServer6",
                # The SIP user IDs for accounts 1-6
                "35",
                "404",
                "504",
                "604",
                "704",
                "804",
            ]

        result = await self._request(
            "GET",
            PHONE_API_CONFIG_GET,
            params={"pvalues": ",".join(p_values)},
            include_sid=True,
        )

        # Expected shape: { "configs": [ { alias, pvalue, value }, ... ] }
        config: dict[str, str] = {}
        if isinstance(result, dict):
            for row in result.get("configs", []):
                if isinstance(row, dict) and "pvalue" in row:
                    config[str(row["pvalue"])] = str(row.get("value", ""))
        return config

    async def set_config(self, p_values: dict[str, str]) -> bool:
        """
        Write configuration values to the phone.

        Uses ``/cgi-bin/config_update`` with a JSON body of the shape the
        GWT bundle builds — split into two maps:

            {
              "alias":  { "@call.dial.clickToDial.enable": "1", ... },
              "pvalue": { "P35": "203", "P3": "Display Name", ... }
            }

        Keys starting with ``@`` are routed to ``alias``; everything else
        (``P35``, ``35``, ``AccountRegistered1``, etc.) goes to ``pvalue``.

        Returns True if the phone acknowledged the write with
        ``{response: "success"}``.
        """
        if not p_values:
            return True

        alias_map: dict[str, str] = {}
        pvalue_map: dict[str, str] = {}
        for k, v in p_values.items():
            key = str(k)
            val = str(v)
            if key.startswith("@"):
                alias_map[key] = val
            else:
                # Strip a leading 'P' since the phone accepts the
                # numeric form too. ``P35`` and ``35`` both target the
                # SIP user-ID field.
                pvalue_map[key[1:] if key.startswith("P") and key[1:].isdigit() else key] = val

        body = {"alias": alias_map, "pvalue": pvalue_map}
        # NOTE: config_update uses HTTP PUT (not POST) — extracted from
        # the GWT bundle's RequestBuilder.PUT constant for this endpoint.
        # POST returns ``501 Not Implemented`` on this firmware.
        result = await self._request(
            "PUT",
            PHONE_API_CONFIG_UPDATE,
            json_body=body,
            include_sid=True,
        )
        if isinstance(result, dict):
            ok = result.get("response") == "success"
            if not ok:
                logger.warning(
                    "config_update failed for %s: %s",
                    self.host,
                    result,
                )
            return ok
        # Some firmware revs return a plain "OK" string
        return isinstance(result, str) and "success" in result.lower()

    # ═══════════════════════════════════════════════════════════════════
    # Status
    # ═══════════════════════════════════════════════════════════════════

    async def get_status(self) -> PhoneStatus:
        """Get the phone's current status (model, firmware, SIP registration).

        Aggregates four endpoints to build the same PhoneStatus shape the
        old adapter promised — but using the real ones the GXP firmware
        actually exposes.
        """
        # 1. Phone state (available / in_call / ringing / ...)
        phone_state_resp = await self._request(
            "POST",
            PHONE_API_GET_PHONE_STATUS,
            data={},
        )
        phone_state = ""
        if isinstance(phone_state_resp, dict):
            phone_state = str(phone_state_resp.get("body", ""))

        # 2. Time + uptime
        time_resp = await self._request("GET", PHONE_API_GET_TIME)
        uptime_str = ""
        if isinstance(time_resp, dict):
            uptime_str = str(time_resp.get("uptime", ""))

        # 3. Config: model + accounts
        config = await self.get_config()

        # 4. System (process VSZ) — best-effort
        sys_resp = await self._request(
            "GET",
            PHONE_API_GET_SYSTEM_STATUS,
        )
        system_processes = []
        if isinstance(sys_resp, dict):
            system_processes = sys_resp.get("results", []) or []

        info = PhoneInfo(
            mac_address=self._mac or "",
            model=config.get("phone_model", ""),
            firmware_version=self._ver or "",
            ip_address=self.host,
        )

        accounts: list[SIPAccountStatus] = []
        for i in range(1, 7):
            registered_raw = config.get(f"AccountRegistered{i}", "")
            server = config.get(f"AccountRegisteredServer{i}", "")
            sip_user = config.get(_account_user_pvalue(i), "")
            reg_status = (
                RegistrationStatus.REGISTERED
                if registered_raw.lower() in ("true", "yes", "1")
                else RegistrationStatus.UNREGISTERED
            )
            if not sip_user and reg_status == RegistrationStatus.UNREGISTERED:
                continue
            accounts.append(
                SIPAccountStatus(
                    account_index=i - 1,
                    active=bool(sip_user) or reg_status == RegistrationStatus.REGISTERED,
                    sip_user_id=sip_user,
                    sip_server=server,
                    registration_status=reg_status,
                )
            )

        return PhoneStatus(
            info=info,
            accounts=accounts,
            network={
                "ip_address": self.host,
                "phone_state": phone_state,
                "uptime": uptime_str,
                "system_processes": system_processes,
            },
        )

    async def get_phone_info(self) -> PhoneInfo:
        return (await self.get_status()).info

    async def get_lockout(self) -> str:
        """Return the lockout state of the admin user (``ok`` or ``lockout``)."""
        resp = await self._request("GET", PHONE_API_GET_LOCKOUT, include_sid=False)
        if isinstance(resp, dict):
            return str(resp.get("body", "?"))
        return "?"

    async def get_accounts(self, *, registered_only: bool = False) -> list[dict[str, Any]]:
        """Return the SIP accounts as the phone's web UI sees them.

        Uses ``/cgi-bin/api-get_accounts``. With ``registered_only=True``
        the phone returns only accounts in the REGISTERED state.
        """
        params: dict[str, Any] = {}
        if registered_only:
            params["registered"] = "true"
        resp = await self._request("GET", PHONE_API_GET_ACCOUNTS, params=params)
        if isinstance(resp, dict):
            return resp.get("body", []) or resp.get("results", []) or []
        return []

    async def get_line_status(self) -> dict[str, Any]:
        """Return per-line SIP state (used to render the dot-status icons in the UI)."""
        resp = await self._request("GET", PHONE_API_GET_LINE_STATUS)
        return resp if isinstance(resp, dict) else {}

    async def get_screenshot(self) -> dict[str, Any]:
        """Return the list of available LCD screenshots (and trigger capture).

        The phone caches screenshots in /tmp; the api-get_screenshot
        response gives you the list — you'd then GET each via the
        ``/images`` endpoint to render them in the UI.
        """
        resp = await self._request("GET", PHONE_API_GET_SCREENSHOT)
        return resp if isinstance(resp, dict) else {"results": []}

    # ═══════════════════════════════════════════════════════════════════
    # System operations
    # ═══════════════════════════════════════════════════════════════════

    async def _sys_operation(self, op: str) -> bool:
        """Run ``api-sys_operation`` with form-encoded body.

        Body shape from the GWT bundle::

            request=<op>&sid=<sid>

        ``op`` is one of: ``REBOOT``, ``RESET`` (factory reset),
        ``PROV`` (provision now), ``KILLGUI`` (restart UI process).
        Content-Type is ``application/x-www-form-urlencoded`` —
        JSON body returns 501 on this firmware.
        """
        await self._request(
            "POST",
            PHONE_API_SYS_OPERATION,
            data={"request": op, "sid": self._sid or ""},
        )
        return True

    async def reboot(self) -> bool:
        """Reboot the phone.

        Mirrors :meth:`factory_reset`: True ONLY when the phone
        acknowledged the command, either with a response or by dropping
        the connection as it goes down. A rejection (expired sid, auth
        failure) is NOT a reboot, and the blanket ``except Exception:
        return True`` this used to end with reported one as a success.
        """
        try:
            await self._sys_operation("REBOOT")
            logger.info("Reboot command sent to %s", self.host)
            return True
        except (aiohttp.ServerDisconnectedError, aiohttp.ClientPayloadError, TimeoutError):
            # Connection went away mid-response — phone is rebooting.
            logger.info("Reboot acknowledged via dropped connection at %s", self.host)
            return True
        except GrandstreamConnectionError as exc:
            logger.warning("Reboot transport error at %s: %s", self.host, exc)
            return False
        except (ConnectionError, OSError) as exc:
            logger.warning("Reboot failed at %s (transport): %s", self.host, exc)
            return False
        except aiohttp.ClientError as exc:
            logger.warning("Reboot failed at %s (client): %s", self.host, exc)
            return False

    async def factory_reset(self) -> bool:
        """Factory reset the phone.

        Returns True ONLY when the phone acknowledged the reset (either
        with a JSON response or by dropping the connection while the
        reset begins). Bare network errors return False.
        """
        try:
            await self._sys_operation("RESET")
            return True
        except (aiohttp.ServerDisconnectedError, aiohttp.ClientPayloadError, TimeoutError):
            logger.info("Factory reset acknowledged via dropped connection at %s", self.host)
            return True
        except GrandstreamConnectionError as exc:
            logger.warning("Factory reset transport error at %s: %s", self.host, exc)
            return False
        except (ConnectionError, OSError) as exc:
            logger.warning("Factory reset failed at %s (transport): %s", self.host, exc)
            return False
        except aiohttp.ClientError as exc:
            logger.warning("Factory reset failed at %s (client): %s", self.host, exc)
            return False

    async def provision_now(self) -> bool:
        """Trigger an immediate provisioning fetch.

        Same endpoint as reboot/factory_reset, op=PROV.
        Lets the operator manually re-fetch from the FreeSDN provisioning
        server without waiting for the next scheduled check-in.
        """
        try:
            await self._sys_operation("PROV")
            logger.info("Provision command sent to %s", self.host)
            return True
        except Exception as exc:
            logger.warning("provision_now failed for %s: %s", self.host, exc)
            return False

    # ═══════════════════════════════════════════════════════════════════
    # Call control
    # ═══════════════════════════════════════════════════════════════════

    async def make_call(self, number: str, *, account: int = 0) -> bool:
        """Initiate an outbound call from the phone."""
        resp = await self._request(
            "POST",
            PHONE_API_MAKE_CALL,
            json_body={"number": str(number), "account": int(account)},
        )
        if isinstance(resp, dict):
            return resp.get("response") == "success"
        return False

    async def phone_operation(self, op: str, **kwargs: Any) -> bool:
        """Drive in-call operations: answer / hangup / hold / unhold / transfer.

        ``op`` is one of: ``ANSWER``, ``HANGUP``, ``HOLD``, ``UNHOLD``,
        ``TRANSFER``, ``CONFERENCE``, ``DTMF``. Extra args depend on op:
            phone_operation("TRANSFER", number="201")
            phone_operation("DTMF", digit="5")
        """
        payload = {"request": op.upper(), **kwargs}
        resp = await self._request(
            "POST",
            PHONE_API_PHONE_OPERATION,
            json_body=payload,
        )
        if isinstance(resp, dict):
            return resp.get("response") == "success"
        return False


def _account_user_pvalue(account_idx: int) -> str:
    """Numeric P-value for the SIP user-id of a given account index (1-based).

    Account 1 → P35, Account 2 → P404, Account 3 → P504, Account 4 → P604,
    Account 5 → P704, Account 6 → P804. This matches the layout the
    status_account.js page requests.
    """
    return {1: "35", 2: "404", 3: "504", 4: "604", 5: "704", 6: "804"}.get(account_idx, "")


def _parse_reg_status(raw: str) -> RegistrationStatus:
    """Parse a raw registration status string."""
    raw_lower = raw.lower()
    if "registered" in raw_lower and "un" not in raw_lower:
        return RegistrationStatus.REGISTERED
    if "unregistered" in raw_lower or "not registered" in raw_lower:
        return RegistrationStatus.UNREGISTERED
    if "trying" in raw_lower:
        return RegistrationStatus.TRYING
    if "fail" in raw_lower or "error" in raw_lower:
        return RegistrationStatus.FAILED
    return RegistrationStatus.UNKNOWN

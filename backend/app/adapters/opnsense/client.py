# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - OPNsense API Client
===================================

Low-level async HTTP client for the OPNsense REST API.
All endpoints live under /api/{module}/{controller}/{action}.

Covers:
  - System / Firmware / Reboot / Backup
  - Interfaces / ARP / NDP
  - Firewall Rules (filter CRUD + apply)
  - Firewall Aliases (CRUD + reconfigure)
  - NAT — Source NAT + Port Forwards (CRUD + apply)
  - DHCP — Leases + Static Mappings (CRUD)
  - DNS — Unbound host overrides + domain overrides (CRUD)
  - WireGuard — Servers + Peers (CRUD)
  - OpenVPN — Instances + status
  - IPsec — Tunnels + SAD/SPD + status
  - Routing — Static routes (CRUD) + kernel table
  - Gateway health
  - Services (list / start / stop / restart)
  - IDS/IPS — Suricata settings / rules / alerts
  - Traffic Shaper — Pipes / Queues / Rules (CRUD)
  - Diagnostics — Logs / Traffic / Ping / Traceroute / DNS Lookup
  - Configuration backup / restore
"""

import asyncio
import logging
import re
import time
from typing import Any, ClassVar

import httpx

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterError,
)
from app.adapters.http_utils import CircuitBreaker
from app.core.http_client import build_async_client

logger = logging.getLogger(__name__)


# OPNsense API paths follow ``/api/{module}/{controller}/{action}[/{uuid}]``.
# We accept ASCII letters, digits, ``_``, ``.``, ``-``, slash, and
# percent-encoded byte sequences (``%XX`` where XX is two hex digits).
# Anything else — ``..``, control bytes, query strings smuggled into
# the path, whitespace, raw colon, raw brackets — gets rejected
# before httpx even sees it.
#
# Tightened: raw ``:`` was previously allowed because the
# OpenVPN ``killSession/{session_id}`` and the diagnostics
# reverse-lookup endpoints interpolate values that contain colons.
# That widened the attack surface across every other path. Call
# sites that need ``:`` now URL-encode it (``%3A``) before
# interpolation; diagnostic endpoints that legitimately need IPv6
# bracket syntax in raw form use :data:`_DIAGNOSTICS_PATH_RE` via
# the ``_validate_path(..., allow_ipv6=True)`` call.
#
# This regex is the LAST-RESORT guard at the entry point of
# ``_request``. It is NOT the only validation: every call site that
# interpolates a user-controlled value into the path MUST also call
# :func:`app.adapters.validation.validate_id` (or a stricter shape
# check, e.g. ``_validate_uuid``) at the call site.
_SAFE_PATH_RE = re.compile(r"^/api(?:/(?:[A-Za-z0-9_.\-]|%[0-9A-Fa-f]{2}){1,128})+/?$")

# Narrow exception for diagnostic paths that interpolate a hostname
# value (e.g. an IPv6 address with embedded ``:`` or ``[``/``]``).
# Only diagnostic endpoints — ``/api/diagnostics/...`` — are eligible
# to use this loosened pattern, and the call site must explicitly
# opt in by passing ``allow_ipv6=True`` to :func:`_validate_path`.
_DIAGNOSTICS_PATH_RE = re.compile(
    r"^/api/diagnostics(?:/(?:[A-Za-z0-9_.\-:\[\]]|%[0-9A-Fa-f]{2}){1,128})+/?$"
)


def _validate_path(path: str, *, allow_ipv6: bool = False) -> None:
    """Reject paths that contain traversal payloads or smuggled query/body.

    Raises ``AdapterError`` (with ``adapter_id="opnsense"``) on
    violation so callers get a 400 rather than letting httpx send a
    request that walks the controller's API surface.

    ``allow_ipv6`` opts the call into the diagnostics-only
    :data:`_DIAGNOSTICS_PATH_RE` pattern that admits ``:`` and
    ``[``/``]`` for IPv6-bracketed hostnames. The path must still
    start with ``/api/diagnostics`` for the loosened pattern to
    apply, so a non-diagnostic endpoint can't quietly piggyback on
    this exception.
    """
    if not path:
        raise AdapterError(
            f"unsafe OPNsense API path: {path!r}",
            adapter_id="opnsense",
        )
    pattern = _DIAGNOSTICS_PATH_RE if allow_ipv6 else _SAFE_PATH_RE
    if not pattern.match(path):
        raise AdapterError(
            f"unsafe OPNsense API path: {path!r}",
            adapter_id="opnsense",
        )
    if ".." in path:
        raise AdapterError(
            f"path traversal segment in OPNsense API path: {path!r}",
            adapter_id="opnsense",
        )
    # Defense against percent-encoded traversal: ``%2e%2e``,
    # ``%2E%2E``, ``%2e.``, ``.%2e`` all decode to ``..``. Reject
    # the encoded forms too — the regex permits ``%XX`` but only to
    # carry a colon or other host-shaped character through, never
    # to smuggle a dot.
    from urllib.parse import unquote

    if ".." in unquote(path):
        raise AdapterError(
            f"percent-encoded path traversal in OPNsense API path: {path!r}",
            adapter_id="opnsense",
        )


# HTTP methods that mutate state on the controller. Subject to the
# ``ADAPTER_READ_ONLY`` gate plus an explicit ``force=True`` opt-in,
# matching the dual-gate Omada uses on its apply path.
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# OPNsense's MVC API uses HTTP **POST** for many *read* endpoints — e.g.
# ``/api/firewall/filter/searchRule``, ``/api/firewall/alias/searchItem``,
# ``/api/firewall/source_nat/searchRule``. Those mutate nothing, so the
# read-only gate must NOT treat them as writes — otherwise read-only mode
# (the safe default, and the standing posture for a production firewall)
# can't even list firewall rules / aliases / NAT / VPN peers.
#
# Classify a POST as a READ by the leading verb of its final path segment.
# CONSERVATIVE / fail-safe: anything not clearly a read verb is treated as a
# write and stays gated. No OPNsense *write* endpoint (set/add/del/toggle/
# apply/reconfigure/start/stop/restart/reboot/halt/update/backup/revert/
# import/connect/disconnect…) begins with one of these verbs, and writes with
# a trailing path arg (``setRule/{uuid}``, ``toggleRule/{uuid}/1``) end in the
# arg — so they never match here and remain blocked.
_READ_POST_VERBS: tuple[str, ...] = (
    "search",
    "get",
    "list",
    "export",
    "details",
    "detail",
    "dump",
    "stats",
    "status",
    "info",
    "diff",
    "find",
    "show",
    "query",
    "download",
)


def _is_read_only_post(path: str) -> bool:
    """True if a POST to ``path`` is an OPNsense READ (search/get/list/…)."""
    seg = path.rstrip("/").rsplit("/", 1)[-1].split("?", 1)[0].lower()
    return seg.startswith(_READ_POST_VERBS)


def _is_adapter_read_only() -> bool:
    """Check the universal read-only gate.

    Returns True (default-safe) unless ``ADAPTER_READ_ONLY=false`` is
    set in the environment. Operators must explicitly opt out to
    allow writes — never the other way around.

    Per-vendor isolation: OPNsense reads ONLY ``ADAPTER_READ_ONLY``,
    not the legacy ``OMADA_READ_ONLY``. A previous version OR'd both
    flags so a deployment flipping ``OMADA_READ_ONLY=false`` for
    Omada writes inadvertently opened OPNsense writes too. Each
    adapter now respects its own gate.
    """
    from app.core.runtime_flags import is_adapter_read_only

    return is_adapter_read_only()


def _record_request_metric(method: str, outcome: str) -> None:
    """Emit ``freesdn_adapter_requests_total`` for OPNsense. Never raises."""
    try:
        from app.core.metrics import adapter_requests_total

        adapter_requests_total.labels(adapter="opnsense", method=method, outcome=outcome).inc()
    except Exception:
        pass


def _record_latency(method: str, latency_seconds: float) -> None:
    try:
        from app.core.metrics import adapter_request_duration

        adapter_request_duration.labels(adapter="opnsense", method=method).observe(latency_seconds)
    except Exception:
        pass


def _record_error(error_type: str) -> None:
    try:
        from app.core.metrics import adapter_errors_total

        adapter_errors_total.labels(adapter="opnsense", error_type=error_type).inc()
    except Exception:
        pass


class OPNsenseAPIError(AdapterError):
    """OPNsense API error with HTTP context."""

    def __init__(self, message: str, status_code: int | None = None, response: dict | None = None):
        super().__init__(message, adapter_id="opnsense")
        self.status_code = status_code
        self.response = response


class OPNsenseClient:
    """
    Async HTTP client for OPNsense API.

    Authentication uses API key + secret delivered as HTTP Basic Auth.
    Endpoints follow ``/api/<module>/<controller>/<action>`` convention.

    Example::

        async with OPNsenseClient("192.168.1.1", "key", "secret") as client:
            rules = await client.get_firewall_rules()
    """

    # dedupe the "SSL verification disabled" warning. Without
    # this, a healthy reload of the same controller emits the same
    # log line on every reconnect, drowning out genuine signals. The
    # set lives at class level so all clients targeting the same
    # (host, port, verify_ssl) tuple share one warning.
    _ssl_warning_emitted: ClassVar[set[tuple[str, int]]] = set()

    def __init__(
        self,
        host: str,
        api_key: str,
        api_secret: str,
        *,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: int = 60,
        max_retries: int = 3,
    ):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.base_url = f"https://{host}:{port}"
        self._client: httpx.AsyncClient | None = None
        # Tagged breaker: state transitions land in the shared
        # ``freesdn_adapter_circuit_state{adapter,host}`` gauge so
        # dashboards graph OPNsense alongside Omada/MikroTik.
        self._circuit = CircuitBreaker(
            failure_threshold=5,
            reset_timeout=60.0,
            name="opnsense",
            host=self.base_url,
        )

        # only emit the warning once per (host, port) tuple.
        if not verify_ssl:
            key = (host, port)
            if key not in OPNsenseClient._ssl_warning_emitted:
                OPNsenseClient._ssl_warning_emitted.add(key)
                logger.warning(
                    "SSL verification disabled for %s:%s — consider "
                    "enabling for production (further reconnects to "
                    "this controller will not repeat this message)",
                    host,
                    port,
                )

    # ── lifecycle ────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Create the underlying httpx session."""
        if self._client is None or self._client.is_closed:
            self._client = build_async_client(
                base_url=self.base_url,
                auth=(self.api_key, self.api_secret),
                verify=self.verify_ssl,
                timeout=self.timeout,
                follow_redirects=True,
                headers={
                    "Accept": "application/json",
                },
            )

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "OPNsenseClient":
        await self.connect()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # ── low-level HTTP ───────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        data: dict | None = None,
        params: dict | None = None,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        method_upper = method.upper()

        # ── Path safety ────────────────────────────────────────────
        # Reject any path containing ``..`` or characters outside the
        # known-safe set before httpx sees it. Catches all f-string
        # interpolation sites in this file at one chokepoint rather
        # than auditing each call.
        #
        # Diagnostic endpoints that legitimately interpolate a host
        # value (DNS reverse-lookup with IPv6 brackets, IPv6 ping/
        # traceroute targets in the path) opt into the loosened
        # ``_DIAGNOSTICS_PATH_RE`` via ``allow_ipv6=True``. The
        # heuristic is path-prefix based so a non-diagnostic call
        # site can't piggyback on the exception.
        _validate_path(
            path,
            allow_ipv6=path.startswith("/api/diagnostics/"),
        )

        # ── Universal read-only gate ────────────────────────────────
        # OPNsense mutating calls go through here. If
        # ``ADAPTER_READ_ONLY`` is set in the environment, refuse
        # unless the caller has explicitly opted in via ``force=True``.
        # This is the dual-gate the contract requires for every
        # adapter — Omada has it on its apply path; we apply the
        # same shape here so future adapters inherit the pattern.
        # A POST to an OPNsense read endpoint (searchRule, searchItem, …) is a
        # READ, not a mutation — don't let the read-only gate block it.
        is_write = method_upper in _WRITE_METHODS and not (
            method_upper == "POST" and _is_read_only_post(path)
        )
        if is_write and _is_adapter_read_only() and not force:
            _record_request_metric(method_upper, "read_only_blocked")
            raise AdapterError(
                "ADAPTER_READ_ONLY is set — write refused. Set "
                "ADAPTER_READ_ONLY=false in the environment AND pass "
                "force=true on the call to override. Both safeties "
                "must be down before a write reaches the controller.",
                adapter_id="opnsense",
            )

        # Circuit breaker check
        if not self._circuit.allow_request():
            _record_request_metric(method_upper, "circuit_open")
            raise AdapterConnectionError(
                f"Circuit breaker OPEN for {self.host}:{self.port} — "
                "too many recent failures, backing off",
                adapter_id="opnsense",
            )

        if self._client is None or self._client.is_closed:
            await self.connect()
        assert self._client is not None

        request_start = time.monotonic()

        for attempt in range(1, self.max_retries + 1):
            try:
                kw: dict[str, Any] = {"params": params}
                if method_upper in ("POST", "PUT", "PATCH"):
                    # OPNsense action endpoints (delItem, apply, reboot, toggle…)
                    # are body-less POSTs. Declaring Content-Type: application/json
                    # with a null/empty body makes OPNsense reject the request with
                    # "Invalid JSON syntax", so send a valid empty object instead —
                    # which OPNsense parses fine and which body-carrying calls
                    # (add/set) override with their real payload.
                    kw["json"] = data if data is not None else {}
                    kw["headers"] = {"Content-Type": "application/json"}

                response = await self._client.request(method_upper, path, **kw)
                from app.adapters._response_limits import check_response_size

                check_response_size(response)  # bound device body before read

                if response.status_code == 401:
                    self._circuit.record_failure()
                    _record_request_metric(method_upper, "http_401")
                    _record_error("auth")
                    raise AdapterAuthenticationError(
                        "OPNsense authentication failed – check API key/secret",
                        adapter_id="opnsense",
                    )

                if response.status_code >= 500:
                    # Server error — retryable
                    raise OPNsenseAPIError(
                        f"OPNsense API server error {response.status_code}",
                        status_code=response.status_code,
                    )

                if response.status_code >= 400:
                    msg = f"OPNsense API {response.status_code}"
                    try:
                        body = response.json()
                        msg = body.get("message", msg)
                    except (ValueError, KeyError):
                        msg = response.text or msg
                    # 4xx errors are not retryable, but they ARE
                    # application-level errors — count toward metrics
                    # so dashboards see them; don't trip the breaker
                    # (the controller is reachable, just rejected).
                    self._circuit.record_success()
                    _record_request_metric(method_upper, f"http_{response.status_code}")
                    _record_error(f"http_{response.status_code}")
                    raise OPNsenseAPIError(msg, status_code=response.status_code)

                # Parse JSON response, handling non-JSON bodies gracefully
                if not response.text:
                    self._circuit.record_success()
                    _record_request_metric(method_upper, "success")
                    _record_latency(method_upper, time.monotonic() - request_start)
                    return {}
                try:
                    result = response.json()
                    self._circuit.record_success()
                    _record_request_metric(method_upper, "success")
                    _record_latency(method_upper, time.monotonic() - request_start)
                    return result
                except (ValueError, TypeError) as exc:
                    snippet = (
                        (response.text[:200] + "...") if len(response.text) > 200 else response.text
                    )
                    content_type = response.headers.get("content-type", "unknown")
                    # Diagnose common OPNsense issues
                    if "<html" in response.text.lower():
                        hint = (
                            " — OPNsense returned an HTML page instead of JSON. "
                            "This usually means: (1) the API credentials are wrong, "
                            "(2) the API user lacks permission for this endpoint, or "
                            "(3) the OPNsense web UI is intercepting the request."
                        )
                    elif response.text.strip().startswith("<?xml"):
                        hint = " — OPNsense returned XML; expected JSON."
                    else:
                        hint = ""
                    self._circuit.record_failure()
                    _record_request_metric(method_upper, "non_json")
                    _record_error("non_json")
                    raise AdapterConnectionError(
                        f"OPNsense returned non-JSON response on {method} {path} "
                        f"(status={response.status_code}, content-type: {content_type}): "
                        f"{snippet}{hint}",
                        adapter_id="opnsense",
                    ) from exc

            except (httpx.RequestError, httpx.TimeoutException) as exc:
                # A connect failure (host down / unreachable) won't recover on a
                # 1-2s retry — fail fast rather than burning the whole retry budget
                # (3x the connect timeout + backoff ≈ a 27s hung page). Read / other
                # transient request errors still retry as before.
                connect_failure = isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout))
                if attempt < self.max_retries and not connect_failure:
                    delay = min(2 ** (attempt - 1), 8)  # 1s, 2s, 4s, 8s cap
                    logger.warning(
                        "OPNsense request %s %s attempt %d/%d failed: %s — retrying in %ss",
                        method,
                        path,
                        attempt,
                        self.max_retries,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                self._circuit.record_failure()
                err_type = "timeout" if isinstance(exc, httpx.TimeoutException) else "connection"
                _record_request_metric(method_upper, err_type)
                _record_error(err_type)
                raise AdapterConnectionError(
                    f"OPNsense connection error after {self.max_retries} attempts: {exc}",
                    adapter_id="opnsense",
                ) from exc

            except OPNsenseAPIError as exc:
                if exc.status_code and exc.status_code >= 500 and attempt < self.max_retries:
                    # 502/503/504 are emitted transiently for ~3s
                    # while OPNsense reloads pf after a
                    # ``reconfigure`` call. The default 1s/2s/4s
                    # backoff is too short — by attempt 3 pf is
                    # often still rebuilding state. Use longer
                    # waits (5s, 10s) for these gateway-style
                    # codes; keep the standard exponential backoff
                    # for 500/501 (which usually mean the API
                    # itself is broken and won't recover quickly
                    # anyway).
                    if exc.status_code in (502, 503, 504):
                        delay = 5 * attempt  # 5s, 10s, 15s
                    else:
                        delay = min(2 ** (attempt - 1), 8)
                    logger.warning(
                        "OPNsense server error %s on %s attempt %d/%d — retrying in %ss",
                        exc.status_code,
                        path,
                        attempt,
                        self.max_retries,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    continue
                self._circuit.record_failure()
                raise

            except AdapterAuthenticationError:
                raise  # Never retry auth failures

        # Should not reach here, but just in case
        self._circuit.record_failure()
        raise AdapterConnectionError(
            f"OPNsense request failed after {self.max_retries} attempts",
            adapter_id="opnsense",
        )

    async def get(self, path: str, params: dict | None = None) -> dict[str, Any]:
        return await self._request("GET", path, params=params)

    async def post(
        self,
        path: str,
        data: dict | None = None,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """POST to ``path``. ``force`` propagates to the read-only gate;
        callers that need to write (typically a staging applier on the
        apply path) pass ``force=True``."""
        return await self._request("POST", path, data=data, force=force)

    async def put(
        self,
        path: str,
        data: dict | None = None,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        return await self._request("PUT", path, data=data, force=force)

    async def delete(self, path: str, *, force: bool = False) -> dict[str, Any]:
        return await self._request("DELETE", path, force=force)

    async def get_raw(self, path: str, params: dict | None = None) -> str:
        """GET that returns the raw response body (text) instead of JSON.

        Useful for endpoints that return XML (e.g. config backup) or
        plain text.

        this used to bypass both the universal path
        validator AND the circuit-breaker / metrics machinery in
        ``_request``, which made the raw-body endpoint (the
        config.xml download in particular) the easiest place to land
        a path-traversal payload. We now run the SAME path-safety
        check at the top, then go through ``_client.get`` directly
        (we still bypass JSON parsing because the body is XML/text).
        """
        # Path safety — same gate ``_request`` uses. The XML config
        # endpoint MUST go through this, no exceptions. (No IPv6
        # exception here: the config-XML download path is fixed and
        # doesn't interpolate any host value.)
        _validate_path(path)

        if not self._circuit.allow_request():
            _record_request_metric("GET", "circuit_open")
            raise AdapterConnectionError(
                f"Circuit breaker OPEN for {self.host}:{self.port}",
                adapter_id="opnsense",
            )
        if self._client is None or self._client.is_closed:
            await self.connect()
        assert self._client is not None

        request_start = time.monotonic()
        try:
            response = await self._client.get(path, params=params)
            # bound the raw device body BEFORE materializing
            # response.text — same guard the JSON path (_request) already applies.
            # get_raw was the only unguarded raw-text reader; the config.xml
            # fallback (download_config_xml) is its sole caller and could
            # otherwise buffer an oversized config in memory before the
            # post-download parse cap rejects it.
            from app.adapters._response_limits import check_response_size

            check_response_size(response)
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            self._circuit.record_failure()
            err_type = "timeout" if isinstance(exc, httpx.TimeoutException) else "connection"
            _record_request_metric("GET", err_type)
            _record_error(err_type)
            raise AdapterConnectionError(
                f"OPNsense get_raw error: {exc}",
                adapter_id="opnsense",
            ) from exc
        if response.status_code == 401:
            self._circuit.record_failure()
            _record_request_metric("GET", "http_401")
            _record_error("auth")
            raise AdapterAuthenticationError(
                "OPNsense authentication failed – check API key/secret",
                adapter_id="opnsense",
            )
        if response.status_code >= 400:
            # Treat as application error, not breaker trip — the
            # controller is reachable, just rejected.
            self._circuit.record_success()
            _record_request_metric("GET", f"http_{response.status_code}")
            _record_error(f"http_{response.status_code}")
            raise OPNsenseAPIError(
                f"OPNsense API error {response.status_code} on GET {path}",
                status_code=response.status_code,
            )
        self._circuit.record_success()
        _record_request_metric("GET", "success")
        _record_latency("GET", time.monotonic() - request_start)
        return response.text

    # ═══════════════════════════════════════════════════════════════════════
    # System
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_status(self) -> dict[str, Any]:
        return await self.get("/api/core/system/status")

    async def get_firmware_status(self) -> dict[str, Any]:
        return await self.get("/api/core/firmware/status")

    async def get_system_time(self) -> dict[str, Any]:
        return await self.get("/api/core/system/time")

    # ═══════════════════════════════════════════════════════════════════════
    # Interfaces
    # ═══════════════════════════════════════════════════════════════════════

    async def get_interfaces(self) -> dict[str, Any]:
        return await self.get("/api/interfaces/overview/export")

    async def get_interface_statistics(self) -> dict[str, Any]:
        return await self.get("/api/diagnostics/interface/getInterfaceStatistics")

    async def get_arp_table(self) -> dict[str, Any]:
        return await self.get("/api/diagnostics/interface/getArp")

    # ═══════════════════════════════════════════════════════════════════════
    # Configuration Backup / Download
    # ═══════════════════════════════════════════════════════════════════════

    async def download_config_xml(self) -> str:
        """Download the full OPNsense config.xml as raw XML text.

        Uses /api/core/backup/download/this which requires API auth and
        returns raw XML (not JSON).
        """
        return await self.get_raw("/api/core/backup/download/this")

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall Rules
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_rules(self, search: str = "") -> dict[str, Any]:
        return await self.post(
            "/api/firewall/filter/searchRule",
            {"current": 1, "rowCount": 1000, "searchPhrase": search},
        )

    async def get_firewall_rule(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/firewall/filter/getRule/{uuid}")

    async def add_firewall_rule(
        self, rule: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post("/api/firewall/filter/addRule", {"rule": rule}, force=force)

    async def update_firewall_rule(
        self, uuid: str, rule: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/firewall/filter/setRule/{uuid}",
            {"rule": rule},
            force=force,
        )

    async def delete_firewall_rule(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/firewall/filter/delRule/{uuid}", force=force)

    async def toggle_firewall_rule(
        self, uuid: str, enabled: bool, *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/firewall/filter/toggleRule/{uuid}/{1 if enabled else 0}",
            force=force,
        )

    async def apply_firewall_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/firewall/filter/apply", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall Aliases
    # ═══════════════════════════════════════════════════════════════════════

    async def get_aliases(self, search: str = "") -> dict[str, Any]:
        return await self.post(
            "/api/firewall/alias/searchItem",
            {"current": 1, "rowCount": 1000, "searchPhrase": search},
        )

    async def get_alias(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/firewall/alias/getItem/{uuid}")

    async def add_alias(self, alias: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/firewall/alias/addItem", {"alias": alias}, force=force)

    async def update_alias(
        self, uuid: str, alias: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/firewall/alias/setItem/{uuid}",
            {"alias": alias},
            force=force,
        )

    async def delete_alias(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/firewall/alias/delItem/{uuid}", force=force)

    async def apply_alias_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/firewall/alias/reconfigure", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # NAT
    # ═══════════════════════════════════════════════════════════════════════

    async def get_nat_rules(self) -> dict[str, Any]:
        return await self.post(
            "/api/firewall/source_nat/searchRule",
            {"current": 1, "rowCount": 1000},
        )

    async def get_port_forwards(self) -> dict[str, Any]:
        return await self.get("/api/firewall/nat/get")

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_leases(self) -> dict[str, Any]:
        return await self.get("/api/dhcpv4/leases/searchLease")

    async def get_dhcp_static_mappings(self) -> dict[str, Any]:
        return await self.post(
            "/api/dhcpv4/settings/searchStaticMap",
            {"current": 1, "rowCount": 1000},
        )

    # ═══════════════════════════════════════════════════════════════════════
    # DNS (Unbound)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dns_overrides(self) -> dict[str, Any]:
        return await self.post(
            "/api/unbound/settings/searchHostOverride",
            {"current": 1, "rowCount": 1000},
        )

    async def add_dns_override(
        self, override: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            "/api/unbound/settings/addHostOverride",
            {"host": override},
            force=force,
        )

    async def delete_dns_override(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/unbound/settings/delHostOverride/{uuid}", force=force)

    async def apply_dns_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/unbound/service/reconfigure", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # VPN – WireGuard
    # ═══════════════════════════════════════════════════════════════════════

    async def get_wireguard_status(self) -> dict[str, Any]:
        return await self.get("/api/wireguard/general/get")

    async def get_wireguard_peers(self) -> dict[str, Any]:
        return await self.post(
            "/api/wireguard/client/searchClient",
            {"current": 1, "rowCount": 1000},
        )

    async def get_wireguard_servers(self) -> dict[str, Any]:
        return await self.post(
            "/api/wireguard/server/searchServer",
            {"current": 1, "rowCount": 1000},
        )

    # ═══════════════════════════════════════════════════════════════════════
    # VPN – OpenVPN
    # ═══════════════════════════════════════════════════════════════════════

    async def get_openvpn_providers(self) -> dict[str, Any]:
        return await self.get("/api/openvpn/export/providers")

    async def get_openvpn_instances(self) -> dict[str, Any]:
        return await self.post(
            "/api/openvpn/instances/search",
            {"current": 1, "rowCount": 1000},
        )

    # ═══════════════════════════════════════════════════════════════════════
    # Gateway / Routing
    # ═══════════════════════════════════════════════════════════════════════

    async def get_gateway_status(self) -> dict[str, Any]:
        return await self.get("/api/routes/gateway/status")

    # ═══════════════════════════════════════════════════════════════════════
    # Services
    # ═══════════════════════════════════════════════════════════════════════

    async def get_services(self) -> dict[str, Any]:
        return await self.get("/api/core/service/search")

    async def restart_service(self, service: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/core/service/restart/{service}", force=force)

    async def stop_service(self, service: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/core/service/stop/{service}", force=force)

    async def start_service(self, service: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/core/service/start/{service}", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Diagnostics / Logs
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_log(self, limit: int = 100) -> dict[str, Any]:
        return await self.get(f"/api/diagnostics/log/core/system/{limit}")

    async def get_firewall_log(self, limit: int = 100) -> dict[str, Any]:
        return await self.get(f"/api/diagnostics/log/core/filter/{limit}")

    async def get_traffic_stats(self) -> dict[str, Any]:
        return await self.get("/api/diagnostics/traffic/top/wan")

    # ═══════════════════════════════════════════════════════════════════════
    # System — extended
    # ═══════════════════════════════════════════════════════════════════════

    async def reboot(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/core/system/reboot", force=force)

    async def halt(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/core/system/halt", force=force)

    async def get_system_resources(self) -> dict[str, Any]:
        """CPU / memory / disk / swap overview from the activity endpoint."""
        return await self.get("/api/diagnostics/activity/getActivity")

    # ═══════════════════════════════════════════════════════════════════════
    # Firmware — extended
    # ═══════════════════════════════════════════════════════════════════════

    async def firmware_check(self, *, force: bool = False) -> dict[str, Any]:
        """Trigger a firmware check (async: poll status afterwards)."""
        return await self.post("/api/core/firmware/check", force=force)

    async def firmware_update(self, *, force: bool = False) -> dict[str, Any]:
        """Start the firmware update process."""
        return await self.post("/api/core/firmware/update", force=force)

    async def firmware_upgrade_status(self) -> dict[str, Any]:
        return await self.get("/api/core/firmware/upgradestatus")

    async def get_firmware_changelog(self) -> dict[str, Any]:
        return await self.get("/api/core/firmware/changelog/list")

    async def get_installed_packages(self) -> dict[str, Any]:
        return await self.post(
            "/api/core/firmware/info",
            {"current": 1, "rowCount": -1},
        )

    async def get_installed_plugins(self) -> dict[str, Any]:
        return await self.get("/api/core/firmware/getPlugins")

    # ═══════════════════════════════════════════════════════════════════════
    # Configuration Backup / Restore
    # ═══════════════════════════════════════════════════════════════════════

    async def get_backup_list(self) -> dict[str, Any]:
        return await self.get("/api/core/backup/backups")

    async def create_backup(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/core/backup/backup", force=force)

    async def delete_backup(self, filename: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(
            "/api/core/backup/deleteBackup",
            {"filename": filename},
            force=force,
        )

    async def revert_backup(self, filename: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(
            "/api/core/backup/revertBackup",
            {"filename": filename},
            force=force,
        )

    async def download_config(self) -> dict[str, Any]:
        """Download the current running configuration (XML)."""
        return await self.get("/api/core/backup/download/this")

    # ═══════════════════════════════════════════════════════════════════════
    # NAT — Source NAT (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_source_nat_rule(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/firewall/source_nat/getRule/{uuid}")

    async def add_source_nat_rule(
        self, rule: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post("/api/firewall/source_nat/addRule", {"rule": rule}, force=force)

    async def update_source_nat_rule(
        self, uuid: str, rule: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/firewall/source_nat/setRule/{uuid}",
            {"rule": rule},
            force=force,
        )

    async def delete_source_nat_rule(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/firewall/source_nat/delRule/{uuid}", force=force)

    async def apply_source_nat_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/firewall/source_nat/apply", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # NAT — Port Forwards / Destination NAT (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_port_forward_rules(self) -> dict[str, Any]:
        return await self.post(
            "/api/firewall/dnat/searchRule",
            {"current": 1, "rowCount": 1000},
        )

    async def get_port_forward_rule(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/firewall/dnat/getRule/{uuid}")

    async def add_port_forward_rule(
        self, rule: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post("/api/firewall/dnat/addRule", {"rule": rule}, force=force)

    async def update_port_forward_rule(
        self, uuid: str, rule: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(f"/api/firewall/dnat/setRule/{uuid}", {"rule": rule}, force=force)

    async def delete_port_forward_rule(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/firewall/dnat/delRule/{uuid}", force=force)

    async def apply_port_forward_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/firewall/dnat/apply", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP — Extended (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_static_mapping(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/dhcpv4/settings/getStaticMap/{uuid}")

    async def add_dhcp_static_mapping(
        self, mapping: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            "/api/dhcpv4/settings/addStaticMap",
            {"staticmap": mapping},
            force=force,
        )

    async def update_dhcp_static_mapping(
        self, uuid: str, mapping: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/dhcpv4/settings/setStaticMap/{uuid}",
            {"staticmap": mapping},
            force=force,
        )

    async def delete_dhcp_static_mapping(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/dhcpv4/settings/delStaticMap/{uuid}", force=force)

    async def apply_dhcp_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/dhcpv4/service/reconfigure", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # DNS — Extended (domain overrides, update)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dns_override(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/unbound/settings/getHostOverride/{uuid}")

    async def update_dns_override(
        self, uuid: str, override: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/unbound/settings/setHostOverride/{uuid}",
            {"host": override},
            force=force,
        )

    async def get_dns_domain_overrides(self) -> dict[str, Any]:
        return await self.post(
            "/api/unbound/settings/searchDomainOverride",
            {"current": 1, "rowCount": 1000},
        )

    async def add_dns_domain_override(
        self, override: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            "/api/unbound/settings/addDomainOverride",
            {"domain": override},
            force=force,
        )

    async def update_dns_domain_override(
        self, uuid: str, override: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/unbound/settings/setDomainOverride/{uuid}",
            {"domain": override},
            force=force,
        )

    async def delete_dns_domain_override(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/unbound/settings/delDomainOverride/{uuid}", force=force)

    async def get_unbound_status(self) -> dict[str, Any]:
        return await self.get("/api/unbound/service/status")

    # ═══════════════════════════════════════════════════════════════════════
    # VPN — WireGuard (CRUD)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_wireguard_server(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/wireguard/server/getServer/{uuid}")

    async def add_wireguard_server(
        self, server: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            "/api/wireguard/server/addServer",
            {"server": server},
            force=force,
        )

    async def update_wireguard_server(
        self, uuid: str, server: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/wireguard/server/setServer/{uuid}",
            {"server": server},
            force=force,
        )

    async def delete_wireguard_server(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/wireguard/server/delServer/{uuid}", force=force)

    async def get_wireguard_peer(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/wireguard/client/getClient/{uuid}")

    async def add_wireguard_peer(
        self, peer: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            "/api/wireguard/client/addClient",
            {"client": peer},
            force=force,
        )

    async def update_wireguard_peer(
        self, uuid: str, peer: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/wireguard/client/setClient/{uuid}",
            {"client": peer},
            force=force,
        )

    async def delete_wireguard_peer(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/wireguard/client/delClient/{uuid}", force=force)

    async def apply_wireguard_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/wireguard/service/reconfigure", force=force)

    async def get_wireguard_handshakes(self) -> dict[str, Any]:
        return await self.get("/api/wireguard/service/showhandshake")

    async def get_wireguard_config(self) -> dict[str, Any]:
        return await self.get("/api/wireguard/service/showconf")

    # ═══════════════════════════════════════════════════════════════════════
    # VPN — OpenVPN (CRUD + status)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_openvpn_instance(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/openvpn/instances/get/{uuid}")

    async def add_openvpn_instance(
        self, instance: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            "/api/openvpn/instances/add",
            {"instance": instance},
            force=force,
        )

    async def update_openvpn_instance(
        self, uuid: str, instance: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/openvpn/instances/set/{uuid}",
            {"instance": instance},
            force=force,
        )

    async def delete_openvpn_instance(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/openvpn/instances/del/{uuid}", force=force)

    async def apply_openvpn_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/openvpn/service/reconfigure", force=force)

    async def get_openvpn_sessions(self) -> dict[str, Any]:
        return await self.get("/api/openvpn/service/searchSessions")

    async def kill_openvpn_session(self, session_id: str, *, force: bool = False) -> dict[str, Any]:
        # accept ``force`` so the staging applier and
        # adapter-level helper can opt in to the write through the
        # universal ``ADAPTER_READ_ONLY`` gate.
        #
        # Real OPNsense session IDs have the shape
        # ``<remote_ip>:<port>`` or ``<remote_ip>:<port>:<cn>`` and
        # contain colons. The tightened ``_SAFE_PATH_RE`` no longer
        # admits raw ``:``, so URL-encode the session_id here. The
        # caller (the adapter helper) already validated the session
        # ID against the session-id regex; this is just the encoding
        # step so the path regex still passes.
        from urllib.parse import quote

        encoded = quote(session_id, safe="")
        return await self.post(
            f"/api/openvpn/service/killSession/{encoded}",
            force=force,
        )

    # ═══════════════════════════════════════════════════════════════════════
    # VPN — IPsec
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ipsec_tunnels(self) -> dict[str, Any]:
        return await self.post(
            "/api/ipsec/tunnel/searchPhase1",
            {"current": 1, "rowCount": 1000},
        )

    async def get_ipsec_phase2(self) -> dict[str, Any]:
        return await self.post(
            "/api/ipsec/tunnel/searchPhase2",
            {"current": 1, "rowCount": 1000},
        )

    async def get_ipsec_status(self) -> dict[str, Any]:
        return await self.get("/api/ipsec/sessions/searchSad")

    async def get_ipsec_spd(self) -> dict[str, Any]:
        return await self.get("/api/ipsec/sessions/searchSpd")

    async def get_ipsec_sa(self) -> dict[str, Any]:
        return await self.get("/api/ipsec/leases/pool")

    async def connect_ipsec_tunnel(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/ipsec/sessions/connect/{uuid}", force=force)

    async def disconnect_ipsec_tunnel(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/ipsec/sessions/disconnect/{uuid}", force=force)

    async def apply_ipsec_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/ipsec/service/reconfigure", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Routing — Static Routes (CRUD) + Kernel Table
    # ═══════════════════════════════════════════════════════════════════════

    async def get_static_routes(self) -> dict[str, Any]:
        return await self.post(
            "/api/routes/routes/searchroute",
            {"current": 1, "rowCount": 1000},
        )

    async def get_static_route(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/routes/routes/getroute/{uuid}")

    async def add_static_route(
        self, route: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post("/api/routes/routes/addroute", {"route": route}, force=force)

    async def update_static_route(
        self, uuid: str, route: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/routes/routes/setroute/{uuid}",
            {"route": route},
            force=force,
        )

    async def delete_static_route(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/routes/routes/delroute/{uuid}", force=force)

    async def apply_route_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/routes/routes/reconfigure", force=force)

    async def get_routing_table(self) -> dict[str, Any]:
        return await self.get("/api/diagnostics/interface/getRoutes")

    # ═══════════════════════════════════════════════════════════════════════
    # Interfaces — extended
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ndp_table(self) -> dict[str, Any]:
        return await self.get("/api/diagnostics/interface/getNdp")

    async def flush_arp(self, *, force: bool = False) -> dict[str, Any]:
        # accept ``force`` (write-shaped diagnostic).
        return await self.post(
            "/api/diagnostics/interface/flushArp",
            force=force,
        )

    async def get_vip_status(self) -> dict[str, Any]:
        """Virtual IPs (CARP, alias, etc.)."""
        return await self.get("/api/diagnostics/interface/get_vip_status")

    # ═══════════════════════════════════════════════════════════════════════
    # IDS/IPS — Suricata
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ids_settings(self) -> dict[str, Any]:
        return await self.get("/api/ids/settings/get")

    async def update_ids_settings(
        self, settings: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post("/api/ids/settings/set", settings, force=force)

    async def get_ids_rules(self) -> dict[str, Any]:
        return await self.post(
            "/api/ids/settings/searchInstalledRules",
            {"current": 1, "rowCount": 1000},
        )

    async def toggle_ids_rule(
        self, sid: str, enabled: bool, *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/ids/settings/toggleRule/{sid}/{1 if enabled else 0}",
            force=force,
        )

    async def get_ids_rulesets(self) -> dict[str, Any]:
        return await self.get("/api/ids/settings/getRulesetproperties")

    async def get_ids_alerts(self, limit: int = 500) -> dict[str, Any]:
        return await self.post(
            "/api/ids/service/queryAlerts",
            {"current": 1, "rowCount": limit},
        )

    async def drop_ids_alert_log(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/ids/service/dropAlertLog", force=force)

    async def apply_ids_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/ids/service/reconfigure", force=force)

    async def reload_ids_rules(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/ids/service/reloadRules", force=force)

    async def get_ids_status(self) -> dict[str, Any]:
        return await self.get("/api/ids/service/status")

    async def start_ids(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/ids/service/start", force=force)

    async def stop_ids(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/ids/service/stop", force=force)

    async def restart_ids(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/ids/service/restart", force=force)

    async def update_ids_rules_download(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/ids/service/updateRules", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Traffic Shaper (ipfw pipes / queues / rules)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_shaper_pipes(self) -> dict[str, Any]:
        return await self.post(
            "/api/trafficshaper/settings/searchPipes",
            {"current": 1, "rowCount": 1000},
        )

    async def add_shaper_pipe(self, pipe: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/trafficshaper/settings/addPipe", {"pipe": pipe}, force=force)

    async def update_shaper_pipe(
        self, uuid: str, pipe: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/trafficshaper/settings/setPipe/{uuid}",
            {"pipe": pipe},
            force=force,
        )

    async def delete_shaper_pipe(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/trafficshaper/settings/delPipe/{uuid}", force=force)

    async def get_shaper_queues(self) -> dict[str, Any]:
        return await self.post(
            "/api/trafficshaper/settings/searchQueues",
            {"current": 1, "rowCount": 1000},
        )

    async def add_shaper_queue(
        self, queue: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            "/api/trafficshaper/settings/addQueue",
            {"queue": queue},
            force=force,
        )

    async def update_shaper_queue(
        self, uuid: str, queue: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/trafficshaper/settings/setQueue/{uuid}",
            {"queue": queue},
            force=force,
        )

    async def delete_shaper_queue(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/trafficshaper/settings/delQueue/{uuid}", force=force)

    async def get_shaper_rules(self) -> dict[str, Any]:
        return await self.post(
            "/api/trafficshaper/settings/searchRules",
            {"current": 1, "rowCount": 1000},
        )

    async def add_shaper_rule(self, rule: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
        return await self.post(
            "/api/trafficshaper/settings/addRule",
            {"rule": rule},
            force=force,
        )

    async def update_shaper_rule(
        self, uuid: str, rule: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/trafficshaper/settings/setRule/{uuid}",
            {"rule": rule},
            force=force,
        )

    async def delete_shaper_rule(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/trafficshaper/settings/delRule/{uuid}", force=force)

    async def apply_shaper_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/trafficshaper/service/reconfigure", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Diagnostics — extended
    # ═══════════════════════════════════════════════════════════════════════

    async def dns_lookup(self, hostname: str) -> dict[str, Any]:
        # Hostnames may include ``:`` (IPv6) or other reserved
        # characters; URL-encode to keep the path regex happy. The
        # diagnostics path opts into the loosened regex which DOES
        # permit raw ``:``, but encoding is the safer baseline.
        from urllib.parse import quote

        encoded = quote(hostname, safe="")
        return await self.get(f"/api/diagnostics/dns/reverse_lookup/{encoded}")

    async def ping(self, host: str, count: int = 3, *, force: bool = False) -> dict[str, Any]:
        return await self.post(
            "/api/diagnostics/interface/ping",
            {"address": host, "count": str(count)},
            force=force,
        )

    async def traceroute(self, host: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(
            "/api/diagnostics/interface/traceroute",
            {"address": host},
            force=force,
        )

    async def get_connections(self) -> dict[str, Any]:
        """Active connection tracking table (state table)."""
        return await self.get("/api/diagnostics/firewall/pf_states")

    async def get_pf_info(self) -> dict[str, Any]:
        """PF (packet filter) statistics."""
        return await self.get("/api/diagnostics/firewall/pf_info")

    async def get_pf_statistics(self) -> dict[str, Any]:
        return await self.get("/api/diagnostics/firewall/pf_statistics")

    async def get_memory_stats(self) -> dict[str, Any]:
        return await self.get("/api/diagnostics/system/memory")

    async def get_cpu_stats(self) -> dict[str, Any]:
        return await self.get("/api/diagnostics/cpu_usage/getCPUType")

    async def get_disk_usage(self) -> dict[str, Any]:
        return await self.get("/api/diagnostics/system/systemDisk")

    async def get_temperature(self) -> dict[str, Any]:
        return await self.get("/api/diagnostics/system/systemTemperature")

    # ═══════════════════════════════════════════════════════════════════════
    # Cron (scheduled tasks)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_cron_jobs(self) -> dict[str, Any]:
        return await self.post(
            "/api/cron/settings/searchJobs",
            {"current": 1, "rowCount": 1000},
        )

    async def get_cron_job(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/cron/settings/getJob/{uuid}")

    async def add_cron_job(self, job: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/cron/settings/addJob", {"job": job}, force=force)

    async def update_cron_job(
        self, uuid: str, job: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/cron/settings/setJob/{uuid}",
            {"job": job},
            force=force,
        )

    async def delete_cron_job(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/cron/settings/delJob/{uuid}", force=force)

    async def apply_cron_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/cron/service/reconfigure", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # VLAN Interface CRUD
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vlan_items(self) -> dict[str, Any]:
        """List all VLAN sub-interfaces."""
        return await self.post(
            "/api/interfaces/vlan_settings/searchItem",
            {"current": 1, "rowCount": -1},
        )

    async def get_vlan_item(self, uuid: str) -> dict[str, Any]:
        return await self.get(f"/api/interfaces/vlan_settings/getItem/{uuid}")

    async def add_vlan_item(self, vlan: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
        return await self.post(
            "/api/interfaces/vlan_settings/addItem",
            {"vlan": vlan},
            force=force,
        )

    async def update_vlan_item(
        self, uuid: str, vlan: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self.post(
            f"/api/interfaces/vlan_settings/setItem/{uuid}",
            {"vlan": vlan},
            force=force,
        )

    async def delete_vlan_item(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        return await self.post(f"/api/interfaces/vlan_settings/delItem/{uuid}", force=force)

    async def apply_vlan_changes(self, *, force: bool = False) -> dict[str, Any]:
        return await self.post("/api/interfaces/vlan_settings/reconfigure", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Interface Assignment
    # ═══════════════════════════════════════════════════════════════════════

    async def get_interface_list(self) -> dict[str, Any]:
        """Return all assignable interfaces and their current config."""
        return await self.get("/api/interfaces/overview/export")

    # ═══════════════════════════════════════════════════════════════════════
    # ISC DHCPv4 Scope / Subnet
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcpv4_settings(self) -> dict[str, Any]:
        """Full DHCPv4 service configuration (scopes per interface)."""
        return await self.get("/api/dhcpv4/settings/get")

    async def set_dhcpv4_interface(
        self,
        iface: str,
        settings: dict[str, Any],
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Update DHCP settings for a specific interface (scope).

        validate ``iface`` as an opaque ID before it lands
        anywhere near the request body, and accept ``force`` so the
        sanctioned write path can opt past the read-only gate.
        ``iface`` is interpolated into the JSON body, not the URL —
        so the adapter-level path validator does not catch it; we
        validate explicitly here.
        """
        # Imported lazily to avoid a top-of-module circular dep with
        # callers that wire ``validate_id`` into adapter helpers.
        from app.adapters.validation import validate_id

        validate_id(iface, label="dhcpv4_iface")
        return await self.post(
            "/api/dhcpv4/settings/set",
            {"dhcpd": {iface: settings}},
            force=force,
        )

    # ═══════════════════════════════════════════════════════════════════════
    # KEA DHCPv4 Scope / Subnet  (OPNsense 24.7+)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_kea_dhcpv4_subnets(self) -> dict[str, Any]:
        """List KEA DHCPv4 subnets."""
        return await self.post(
            "/api/kea/dhcpv4/searchSubnet",
            {"current": 1, "rowCount": -1},
        )

    async def add_kea_dhcpv4_subnet(
        self,
        subnet: dict[str, Any],
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Create a KEA DHCPv4 subnet."""
        return await self.post(
            "/api/kea/dhcpv4/addSubnet",
            {"subnet": subnet},
            force=force,
        )

    async def set_kea_dhcpv4_subnet(
        self,
        uuid: str,
        subnet: dict[str, Any],
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Update a KEA DHCPv4 subnet."""
        return await self.post(
            f"/api/kea/dhcpv4/setSubnet/{uuid}",
            {"subnet": subnet},
            force=force,
        )

    async def del_kea_dhcpv4_subnet(self, uuid: str, *, force: bool = False) -> dict[str, Any]:
        """Delete a KEA DHCPv4 subnet."""
        return await self.post(f"/api/kea/dhcpv4/delSubnet/{uuid}", force=force)

    async def apply_kea_changes(self, *, force: bool = False) -> dict[str, Any]:
        """Reconfigure the KEA DHCP service."""
        return await self.post("/api/kea/service/reconfigure", force=force)

# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - MikroTik RouterOS REST Client
=============================================

Low-level async HTTP client for MikroTik RouterOS REST API (v7.1+).
Auth uses HTTP Basic with username/password.
Endpoints live under ``/rest/{path}``.

NOTE on caching: do NOT add module-level mutable caches (dicts/sets
keyed by org/user/host) to this module. The current breaker is
per-instance and that's intentional — deployments with thousands of
RouterOS devices across hundreds of organizations would leak the
cache indefinitely. If a future patch needs caching here, use
``functools.lru_cache(maxsize=N)`` with a small N, or an explicit
TTL+size policy in ``app.core.cache``. Bounded eviction is required.
"""

import asyncio
import logging
import re
import time
from typing import Any

import httpx

from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterError,
    AdapterTimeoutError,
)
from app.adapters.http_utils import CircuitBreaker
from app.core.http_client import build_async_client

logger = logging.getLogger(__name__)


# RouterOS REST API paths follow ``/rest/<section>/<id?>``. RouterOS
# IDs are typically ``*<hex>`` (e.g. ``*1A``) or canonical names —
# we accept the asterisk and standard alphanumerics. Reject anything
# outside the safe set before httpx sees it.
_SAFE_PATH_RE = re.compile(r"^/?[A-Za-z0-9_./*@\-]+/?$")


def _validate_path(path: str) -> None:
    """Reject paths that contain traversal payloads or control chars."""
    # Length cap — RouterOS REST paths cluster around 30-40 chars; a
    # 256-byte cap is a generous ceiling that keeps malformed/abusive
    # inputs from reaching httpx where they could be exploited via
    # absurdly long URL parsing or accidental log spam.
    if len(path) > 256:
        raise AdapterError(
            "MikroTik API path too long (>256 chars)",
            adapter_id="mikrotik",
        )
    if not path or not _SAFE_PATH_RE.match(path):
        raise AdapterError(
            f"unsafe MikroTik API path: {path!r}",
            adapter_id="mikrotik",
        )
    if ".." in path:
        raise AdapterError(
            f"path traversal segment in MikroTik API path: {path!r}",
            adapter_id="mikrotik",
        )


# HTTP methods that mutate state — subject to the dual-gate.
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _is_adapter_read_only() -> bool:
    """Returns True (default-safe) unless ``ADAPTER_READ_ONLY=false``.

    Per-vendor isolation: MikroTik reads ONLY ``ADAPTER_READ_ONLY``,
    not the legacy ``OMADA_READ_ONLY``. Previously the OR'd fallback
    meant a deployment flipping ``OMADA_READ_ONLY=false`` for Omada
    writes inadvertently opened MikroTik too. Each adapter respects
    its own gate now.
    """
    from app.core.runtime_flags import is_adapter_read_only

    return is_adapter_read_only()


def _record_request_metric(method: str, outcome: str) -> None:
    try:
        from app.core.metrics import adapter_requests_total

        adapter_requests_total.labels(adapter="mikrotik", method=method, outcome=outcome).inc()
    except Exception:
        pass


def _record_latency(method: str, latency_seconds: float) -> None:
    try:
        from app.core.metrics import adapter_request_duration

        adapter_request_duration.labels(adapter="mikrotik", method=method).observe(latency_seconds)
    except Exception:
        pass


def _record_error(error_type: str) -> None:
    try:
        from app.core.metrics import adapter_errors_total

        adapter_errors_total.labels(adapter="mikrotik", error_type=error_type).inc()
    except Exception:
        pass


class MikroTikAPIError(Exception):
    """MikroTik API error."""

    def __init__(self, message: str, error_code: int | None = None, details: dict | None = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}


class MikroTikClient:
    """
    Async HTTP client for MikroTik RouterOS REST API.

    Requires RouterOS 7.1+ for REST API support.
    Falls back to HTTPS on port 443 by default.

    Example::

        async with MikroTikClient("192.168.88.1", "admin", "pw") as c:
            rules = await c.get_firewall_filter_rules()
    """

    # Class-level set so the "TLS verification disabled" warning is
    # logged only once per (host, verify_ssl=False) combo for the
    # lifetime of the process — otherwise the warning floods logs on
    # every controller probe.
    _verify_warning_seen: set[tuple[str, bool]] = set()

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = 443,
        use_ssl: bool | None = None,
        verify_ssl: bool = False,
        timeout: int = 30,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        # Auto-derive SSL from port when not explicitly set
        self.use_ssl = use_ssl if use_ssl is not None else (port in (443, 8729))
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        protocol = "https" if self.use_ssl else "http"
        self.base_url = f"{protocol}://{host}:{port}"
        self._client: httpx.AsyncClient | None = None
        # Tagged breaker so dashboards graph MikroTik alongside
        # OPNsense / pfSense / Omada / Proxmox.
        self._breaker = CircuitBreaker(
            failure_threshold=5,
            reset_timeout=60.0,
            name="mikrotik",
            host=self.base_url,
        )
        # One-shot WARN if running with TLS verification off — common
        # in homelab self-signed setups but a real risk in production.
        if self.use_ssl and not self.verify_ssl:
            key = (host, self.verify_ssl)
            if key not in MikroTikClient._verify_warning_seen:
                MikroTikClient._verify_warning_seen.add(key)
                logger.warning(
                    "MikroTik client constructed with verify_ssl=False "
                    "for host=%s — connection is exposed to MITM. "
                    "Set verify_ssl=True and provide a trusted CA in "
                    "production.",
                    host,
                )

    # ── lifecycle ────────────────────────────────────────────────────────

    async def connect(self) -> None:
        if self._client is None or self._client.is_closed:
            # Split timeout — connect / read should not share the
            # same budget. Connect is bounded tight (5s) so a stuck
            # SYN doesn't burn the read window; pool gets the same
            # 5s ceiling. Read/write inherit the caller-supplied
            # ``timeout`` since some RouterOS calls (e.g. exports)
            # legitimately stream for a while.
            timeout = httpx.Timeout(
                connect=5.0,
                read=float(self.timeout),
                write=float(self.timeout),
                pool=5.0,
            )
            # Build into a local first so a constructor exception
            # (rare — bad URL/kwargs) doesn't half-attach a client.
            # If we ever add an auth-probe step here, the try/except
            # already guarantees we close on failure.
            client = build_async_client(
                base_url=self.base_url,
                verify=self.verify_ssl,
                timeout=timeout,
                auth=(self.username, self.password),
                follow_redirects=True,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            try:
                self._client = client
            except Exception:
                await client.aclose()
                raise

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "MikroTikClient":
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
    ) -> Any:
        method_upper = method.upper()

        # Path-traversal guard — single chokepoint.
        _validate_path(path)

        # Universal read-only gate. Default-on; refuses writes unless
        # the caller explicitly opted in via ``force=True``.
        if method_upper in _WRITE_METHODS and _is_adapter_read_only() and not force:
            _record_request_metric(method_upper, "read_only_blocked")
            raise AdapterError(
                "ADAPTER_READ_ONLY is set — MikroTik write refused. Set "
                "ADAPTER_READ_ONLY=false in the environment AND pass "
                "force=true to override.",
                adapter_id="mikrotik",
            )

        if self._client is None or self._client.is_closed:
            await self.connect()
        assert self._client is not None

        if not self._breaker.allow_request():
            _record_request_metric(method_upper, "circuit_open")
            raise AdapterConnectionError(
                "Circuit breaker OPEN — too many recent failures",
                adapter_id="mikrotik",
            )

        if not path.startswith("/rest/"):
            path = f"/rest{path}"

        request_start = time.monotonic()
        try:
            kw: dict[str, Any] = {"params": params}
            if method_upper in ("POST", "PUT", "PATCH"):
                kw["json"] = data

            response = await self._client.request(method_upper, path, **kw)
            from app.adapters._response_limits import check_response_size

            check_response_size(response)  # bound device body before read

            if response.status_code == 401:
                self._breaker.record_failure()
                _record_request_metric(method_upper, "http_401")
                _record_error("auth")
                # Close the client so the next request rebuilds it
                # with whatever creds the pool currently holds. If
                # the operator just rotated the password, this lets
                # the pooled adapter pick up the new value on the
                # next call instead of looping 401s with the stale
                # ``auth=`` kwarg baked into the closed httpx client.
                #
                try:
                    await self.close()
                except Exception:
                    pass
                raise AdapterAuthenticationError(
                    "MikroTik authentication failed – check username/password",
                    adapter_id="mikrotik",
                )

            if response.status_code >= 400:
                msg = f"MikroTik API {response.status_code}"
                try:
                    body = response.json()
                    msg = body.get("message", body.get("error", msg))
                except (ValueError, KeyError):
                    msg = response.text or msg
                # Trip breaker on 5xx and the two 4xx codes that
                # actually indicate the controller is overwhelmed:
                # 408 (request timeout) and 429 (too many requests).
                # RouterOS REST emits both under load — letting the
                # breaker absorb the burst keeps a thundering-herd
                # client from pinning the device and prevents the
                # operator's UI from spinning forever on a stuck
                # router. Other 4xx codes are still semantic errors
                # (bad payload, missing row, unauthorized) and do
                # NOT count against the breaker.
                if response.status_code >= 500 or response.status_code in (
                    408,
                    429,
                ):
                    self._breaker.record_failure()
                _record_request_metric(method_upper, f"http_{response.status_code}")
                _record_error(f"http_{response.status_code}")
                raise MikroTikAPIError(msg, error_code=response.status_code)

            self._breaker.record_success()
            _record_request_metric(method_upper, "success")
            _record_latency(method_upper, time.monotonic() - request_start)
            if not response.text:
                return {}
            try:
                return response.json()
            except (ValueError, UnicodeDecodeError) as exc:
                # Non-JSON response — REST API may not be enabled
                content_type = response.headers.get("content-type", "")
                _record_error("non_json")
                if "text/html" in content_type:
                    raise AdapterConnectionError(
                        "MikroTik returned HTML instead of JSON — "
                        "ensure the REST API is available (RouterOS 7.1+)",
                        adapter_id="mikrotik",
                    ) from exc
                raise AdapterConnectionError(
                    f"MikroTik returned non-JSON response: {content_type}",
                    adapter_id="mikrotik",
                ) from exc

        except httpx.TimeoutException as exc:
            self._breaker.record_failure()
            _record_request_metric(method_upper, "timeout")
            _record_error("timeout")
            raise AdapterTimeoutError(
                f"MikroTik request timed out: {path}",
            ) from exc
        except (AdapterConnectionError, AdapterAuthenticationError, MikroTikAPIError):
            raise
        except httpx.RequestError as exc:
            self._breaker.record_failure()
            _record_request_metric(method_upper, "connection")
            _record_error("connection")
            # ``str(httpx.RequestError)`` includes the target URL —
            # which carries the controller host:port and reveals the
            # vendor by signature. Surface only the exception class
            # name; the full repr stays in the server-side log via
            # ``log.exception`` upstream.
            raise AdapterConnectionError(
                f"MikroTik connection error ({type(exc).__name__})",
                adapter_id="mikrotik",
            ) from exc

    async def get(self, path: str, params: dict | None = None) -> Any:
        return await self._request("GET", path, params=params)

    # ───────────────────────────────────────────────────────────────────
    # Write helpers — canonical RouterOS REST pattern
    # ───────────────────────────────────────────────────────────────────
    # RouterOS REST does NOT accept PATCH/DELETE/raw POST-to-menu the way
    # a REST-ful API does. Verified against CHR 7.21.3:
    #   PATCH /menu/<id>      → 400 "missing or invalid resource identifier"
    #   DELETE /menu/<id>     → 400 "missing or invalid resource identifier"
    #   POST   /menu (no /add)→ 400 "no such command"
    # The canonical pattern is to call the menu's CLI verb:
    #   PUT  /menu                       — add (body = fields)
    #   POST /menu/set     {".id": ID, ...}  — update items-by-id
    #   POST /menu/set     {...fields...}    — update singletons (no .id)
    #   POST /menu/remove  {".id": ID}       — delete
    # The helpers below preserve the callsite signatures
    # (post(path, data) / patch(path, data) / delete(path, id)) but
    # translate to the canonical wire pattern internally.
    #
    # Integration test against real CHR: tests/integration/test_mikrotik_chr.py

    async def post(
        self,
        path: str,
        data: dict | None = None,
        *,
        force: bool = False,
    ) -> Any:
        """Execute an action verb on a menu (``/menu/<action>``).

        Maps to literal ``POST /rest/<path>``. This is the right verb
        for RouterOS action commands like ``/system/backup/save``,
        ``/ip/firewall/filter/move``, ``/certificate/sign``,
        ``/ip/dns/cache/flush``, etc.

        For ADD operations (``/menu`` with no action suffix), use
        :meth:`put` instead — RouterOS rejects POST-to-bare-menu with
        ``"no such command"``. An earlier fix collapsed
        post() into PUT for add-semantics, but that broke every action
        verb in the adapter. Reverted to literal POST.

        ``force`` propagates to the read-only gate.
        """
        return await self._request("POST", path, data=data, force=force)

    async def put(
        self,
        path: str,
        data: dict | None = None,
        *,
        force: bool = False,
    ) -> Any:
        """Add a new item under ``path`` (RouterOS ``/menu/add``).

        Maps to ``PUT /rest/<path>`` per the RouterOS REST contract.
        Returns the created row including the generated ``.id``.
        """
        return await self._request("PUT", path, data=data, force=force)

    async def patch(
        self,
        path: str,
        data: dict | None = None,
        *,
        force: bool = False,
    ) -> Any:
        """Update fields on a singleton or an item-by-id.

        For singletons (e.g. ``/system/identity``) pass the bare path.
        For item-by-id, the caller embedded ``.id`` in the path
        (``/ip/firewall/filter/*1``) — we split it back out and put it
        in the body, because RouterOS REST won't accept ``.id`` in the
        URL. Maps to ``POST /<menu>/set`` with ``{".id": ID, ...}``.
        """
        body = dict(data or {})

        # Heuristic: a trailing path segment that looks like a RouterOS
        # ID (``*<hex>``) is the .id, NOT a sub-resource. Split it off.
        if "/" in path:
            head, _, tail = path.rpartition("/")
            if tail.startswith("*") and len(tail) >= 2:
                body[".id"] = tail
                path = head

        return await self._request("POST", f"{path}/set", data=body, force=force)

    async def delete(
        self,
        path: str,
        item_id: str | None = None,
        *,
        force: bool = False,
    ) -> Any:
        """Remove an item-by-id (RouterOS ``/menu/remove``).

        Maps to ``POST /<path>/remove`` with ``{".id": item_id}`` in
        the body. The legacy URL-suffix form (``self.delete(path, id)``)
        is preserved so callers do not need to change.
        """
        body: dict[str, Any] = {}
        if item_id:
            body[".id"] = item_id
        return await self._request("POST", f"{path}/remove", data=body, force=force)

    # helper to unwrap single-item list responses
    def _first(self, result: Any) -> dict[str, Any]:
        return (
            result[0]
            if isinstance(result, list) and result
            else (result if isinstance(result, dict) else {})
        )

    # ═══════════════════════════════════════════════════════════════════════
    # System
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_resource(self) -> dict[str, Any]:
        return self._first(await self.get("/system/resource"))

    async def get_system_identity(self) -> dict[str, Any]:
        return self._first(await self.get("/system/identity"))

    async def set_system_identity(self, name: str, *, force: bool = False) -> Any:
        """PATCH ``/system/identity`` to rename the router.

        RouterOS identity is a singleton row — ``name`` is the only
        attribute. The applier passes ``force=True`` to clear the
        read-only client gate; the dual-gate at the apply endpoint
        already verified the operator opted in.
        """
        return await self.patch("/system/identity", {"name": name}, force=force)

    async def get_system_ntp_client(self) -> dict[str, Any]:
        """GET the NTP client config.

        RouterOS exposes the NTP client at ``/system/ntp/client`` in
        7.x; in older 7.0/7.1 builds it lives at ``/system/clock`` —
        we don't catch the 404 here because reads of this endpoint
        are not currently wired into the system service. Add a try/
        except if a UI ever calls it directly.
        """
        return self._first(await self.get("/system/ntp/client"))

    async def set_ntp_client(self, data: dict[str, Any], *, force: bool = False) -> Any:
        """PATCH ``/system/ntp/client`` to set primary / secondary NTP.

        Payload is the full RouterOS keys (``primary-ntp``,
        ``secondary-ntp``, ``enabled``). Empty strings clear the
        respective server.
        """
        return await self.patch("/system/ntp/client", data, force=force)

    async def get_system_routerboard(self) -> dict[str, Any]:
        try:
            return self._first(await self.get("/system/routerboard"))
        except MikroTikAPIError:
            return {}

    async def get_system_license(self) -> dict[str, Any]:
        return self._first(await self.get("/system/license"))

    async def get_system_health(self) -> list[dict[str, Any]]:
        try:
            result = await self.get("/system/health")
            return result if isinstance(result, list) else []
        except MikroTikAPIError:
            return []

    # ═══════════════════════════════════════════════════════════════════════
    # Interfaces
    # ═══════════════════════════════════════════════════════════════════════

    async def get_interfaces(self) -> list[dict[str, Any]]:
        return await self.get("/interface")

    async def get_interface(self, iid: str) -> dict[str, Any]:
        return self._first(await self.get(f"/interface/{iid}"))

    async def enable_interface(self, iid: str, *, force: bool = False) -> Any:
        return await self.patch(f"/interface/{iid}", {"disabled": "false"}, force=force)

    async def disable_interface(self, iid: str, *, force: bool = False) -> Any:
        return await self.patch(f"/interface/{iid}", {"disabled": "true"}, force=force)

    async def get_ethernet_interfaces(self) -> list[dict[str, Any]]:
        return await self.get("/interface/ethernet")

    async def get_bridge_interfaces(self) -> list[dict[str, Any]]:
        return await self.get("/interface/bridge")

    async def get_vlan_interfaces(self) -> list[dict[str, Any]]:
        return await self.get("/interface/vlan")

    async def add_vlan_interface(
        self,
        name: str,
        vlan_id: int,
        interface: str,
        *,
        force: bool = False,
        **kw: Any,
    ) -> Any:
        return await self.put(
            "/interface/vlan",
            {
                "name": name,
                "vlan-id": str(vlan_id),
                "interface": interface,
                **kw,
            },
            force=force,
        )

    async def update_vlan_interface(
        self, vid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/interface/vlan/{vid}", data, force=force)

    async def delete_vlan_interface(self, vid: str, *, force: bool = False) -> Any:
        return await self.delete("/interface/vlan", vid, force=force)

    async def get_bridge_ports(self) -> list[dict[str, Any]]:
        return await self.get("/interface/bridge/port")

    async def get_bridge_vlans(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/interface/bridge/vlan")
        except MikroTikAPIError:
            return []

    # ``vlan-ids`` accepts a single id, a comma-separated list, or
    # dash-ranges (e.g. "10,20-25,40"). Reject anything outside that
    # grammar — RouterOS will accept arbitrary garbage and silently
    # produce an unusable VLAN entry. The earlier regex
    # ``^\d+([,-]\d+)*$`` accidentally matched ``1-2-3`` (chain of
    # ranges) which RouterOS treats as an invalid value. The
    # tightened grammar below requires each token to be either a
    # bare integer or a single ``a-b`` range.
    _BRIDGE_VLAN_IDS_RE = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")
    _BRIDGE_VLAN_IDS_MAX_COUNT = 100

    async def add_bridge_vlan(
        self,
        bridge: str,
        vlan_ids: str,
        *,
        force: bool = False,
        **kw: Any,
    ) -> Any:
        if not isinstance(vlan_ids, str) or not vlan_ids:
            raise ValueError("vlan_ids must be a non-empty string")
        if not self._BRIDGE_VLAN_IDS_RE.match(vlan_ids):
            raise ValueError(
                f"vlan_ids must match digits with comma/dash separators: got {vlan_ids!r}"
            )
        # Count distinct tokens (each comma- or dash-separated piece).
        # Both "10-20" and "10,20" count as 2; this is a coarse cap
        # that keeps the request body bounded.
        token_count = len(re.split(r"[,\-]", vlan_ids))
        if token_count > self._BRIDGE_VLAN_IDS_MAX_COUNT:
            raise ValueError(
                f"vlan_ids count {token_count} exceeds cap {self._BRIDGE_VLAN_IDS_MAX_COUNT}"
            )
        return await self.put(
            "/interface/bridge/vlan",
            {"bridge": bridge, "vlan-ids": vlan_ids, **kw},
            force=force,
        )

    async def delete_bridge_vlan(self, vid: str, *, force: bool = False) -> Any:
        return await self.delete("/interface/bridge/vlan", vid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # IP Addresses
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ip_addresses(self) -> list[dict[str, Any]]:
        return await self.get("/ip/address")

    async def add_ip_address(
        self,
        address: str,
        interface: str,
        *,
        force: bool = False,
        **kw: Any,
    ) -> Any:
        return await self.put(
            "/ip/address",
            {"address": address, "interface": interface, **kw},
            force=force,
        )

    async def delete_ip_address(self, aid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/address", aid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall Filter
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_filter_rules(
        self,
        *,
        chain: str | None = None,
    ) -> list[dict[str, Any]]:
        """List filter rules. Optionally filter by chain at the
        controller (``?chain=input``) — saves bandwidth + the in-Python
        slice when the UI only renders one chain.
        """
        params: dict[str, Any] = {}
        if chain:
            params["chain"] = chain
        return await self.get("/ip/firewall/filter", params=params or None)

    async def get_firewall_filter_rule(self, rid: str) -> dict[str, Any]:
        return self._first(await self.get(f"/ip/firewall/filter/{rid}"))

    async def add_firewall_filter_rule(self, rule: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/firewall/filter", rule, force=force)

    async def update_firewall_filter_rule(
        self, rid: str, rule: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/firewall/filter/{rid}", rule, force=force)

    async def delete_firewall_filter_rule(self, rid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/firewall/filter", rid, force=force)

    async def enable_firewall_filter_rule(self, rid: str, *, force: bool = False) -> Any:
        return await self.patch(f"/ip/firewall/filter/{rid}", {"disabled": "false"}, force=force)

    async def disable_firewall_filter_rule(self, rid: str, *, force: bool = False) -> Any:
        return await self.patch(f"/ip/firewall/filter/{rid}", {"disabled": "true"}, force=force)

    async def move_firewall_filter_rule(
        self,
        rid: str,
        destination: str | None = None,
        *,
        force: bool = False,
    ) -> Any:
        """POST ``/ip/firewall/filter/move`` to reposition a filter rule.

        RouterOS firewall is order-sensitive (match-first wins); the
        ``move`` action takes ``numbers`` (the rule to move) and an
        optional ``destination`` (the rule *before which* it should
        land). Omitting ``destination`` moves the rule to the end of
        the chain. The reorder applier walks the staged ID array and
        emits a sequence of ``move`` calls to land them in order.
        """
        body: dict[str, Any] = {"numbers": rid}
        if destination is not None:
            body["destination"] = destination
        return await self.post("/ip/firewall/filter/move", body, force=force)

    async def validate_filter_rule_ids_exist(self, ids: list[str]) -> tuple[set[str], set[str]]:
        """Resolve a list of RouterOS firewall filter rule IDs into the
        subset that exist and the subset that don't.

        Returns ``(existing, missing)``: two sets that partition
        ``ids`` based on whether each ID is present in the current
        ``/ip/firewall/filter`` table. The service layer
        (``adapter_mikrotik_firewall.move_firewall_filter_rule``)
        calls this before issuing a reorder so a partially-stale
        staged array doesn't lead to a mid-reorder failure that
        leaves the chain in a permanently broken intermediate
        order. RouterOS firewall is match-first — a half-applied
        reorder can drop legitimate traffic until the operator
        manually fixes the chain.

        The caller decides what to do with the missing set:
          * Refuse the entire reorder (safest)
          * Skip the missing IDs and emit moves for the rest
          * Surface a user-visible warning and proceed

        We deliberately don't make that decision in the client because
        it's a policy question, not a wire-format question.

        IDs are returned as the strings the caller passed in (we do
        not re-canonicalise the ``*<hex>`` form — RouterOS accepts
        both cases on the wire and the service-layer code wants
        round-trip equality with the operator's staged values).
        """
        if not ids:
            return set(), set()
        # Single GET is cheaper than N point lookups and tolerates a
        # very large filter chain without N round-trips. The list is
        # bounded by the firewall row count (typically < 1000) so
        # streaming through it is fine.
        try:
            rows = await self.get_firewall_filter_rules()
        except (MikroTikAPIError, AdapterError):
            # If we can't read the chain at all we conservatively
            # report every ID as missing — the caller will refuse
            # the reorder.
            return set(), set(ids)
        present: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_id = row.get(".id")
            if isinstance(row_id, str) and row_id:
                present.add(row_id)
        wanted = set(ids)
        existing = wanted & present
        missing = wanted - present
        return existing, missing

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall NAT
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_nat_rules(self) -> list[dict[str, Any]]:
        return await self.get("/ip/firewall/nat")

    async def add_firewall_nat_rule(self, rule: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/firewall/nat", rule, force=force)

    async def update_firewall_nat_rule(
        self, rid: str, rule: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/firewall/nat/{rid}", rule, force=force)

    async def delete_firewall_nat_rule(self, rid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/firewall/nat", rid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall Mangle
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_mangle_rules(self) -> list[dict[str, Any]]:
        return await self.get("/ip/firewall/mangle")

    async def add_firewall_mangle_rule(self, rule: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/firewall/mangle", rule, force=force)

    async def update_firewall_mangle_rule(
        self, rid: str, rule: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/firewall/mangle/{rid}", rule, force=force)

    async def delete_firewall_mangle_rule(self, rid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/firewall/mangle", rid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Address Lists (alias-equivalent)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_address_lists(self) -> list[dict[str, Any]]:
        return await self.get("/ip/firewall/address-list")

    async def add_firewall_address_list(
        self,
        list_name: str,
        address: str,
        *,
        force: bool = False,
        **kw: Any,
    ) -> Any:
        return await self.put(
            "/ip/firewall/address-list",
            {"list": list_name, "address": address, **kw},
            force=force,
        )

    async def delete_firewall_address_list(self, eid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/firewall/address-list", eid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_servers(self) -> list[dict[str, Any]]:
        return await self.get("/ip/dhcp-server")

    async def add_dhcp_server(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/dhcp-server", data, force=force)

    async def update_dhcp_server(
        self, sid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/dhcp-server/{sid}", data, force=force)

    async def delete_dhcp_server(self, sid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/dhcp-server", sid, force=force)

    async def get_dhcp_leases(self) -> list[dict[str, Any]]:
        return await self.get("/ip/dhcp-server/lease")

    async def add_dhcp_static_lease(
        self,
        mac: str,
        address: str,
        *,
        force: bool = False,
        **kw: Any,
    ) -> Any:
        return await self.put(
            "/ip/dhcp-server/lease",
            {"mac-address": mac, "address": address, **kw},
            force=force,
        )

    async def update_dhcp_static_lease(
        self, lid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/dhcp-server/lease/{lid}", data, force=force)

    async def delete_dhcp_lease(self, lid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/dhcp-server/lease", lid, force=force)

    async def get_dhcp_networks(self) -> list[dict[str, Any]]:
        return await self.get("/ip/dhcp-server/network")

    async def add_dhcp_network(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/dhcp-server/network", data, force=force)

    async def update_dhcp_network(
        self, nid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/dhcp-server/network/{nid}", data, force=force)

    async def delete_dhcp_network(self, nid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/dhcp-server/network", nid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # IP Pools
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ip_pools(self) -> list[dict[str, Any]]:
        return await self.get("/ip/pool")

    async def add_ip_pool(
        self,
        name: str,
        ranges: str,
        *,
        force: bool = False,
        **kw: Any,
    ) -> Any:
        return await self.put(
            "/ip/pool",
            {"name": name, "ranges": ranges, **kw},
            force=force,
        )

    async def update_ip_pool(self, pid: str, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.patch(f"/ip/pool/{pid}", data, force=force)

    async def delete_ip_pool(self, pid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/pool", pid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # DNS
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dns_settings(self) -> dict[str, Any]:
        return self._first(await self.get("/ip/dns"))

    async def update_dns_settings(self, data: dict[str, Any], *, force: bool = False) -> Any:
        # ``/ip/dns`` is a singleton config object on RouterOS; the
        # standard idiom is PATCH on the section path itself.
        return await self.patch("/ip/dns", data, force=force)

    async def get_dns_static_entries(self) -> list[dict[str, Any]]:
        return await self.get("/ip/dns/static")

    async def get_dns_cache(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/dns/cache")
        except MikroTikAPIError:
            return []

    async def add_dns_static_entry(
        self,
        name: str,
        address: str,
        *,
        force: bool = False,
        **kw: Any,
    ) -> Any:
        return await self.put(
            "/ip/dns/static",
            {"name": name, "address": address, **kw},
            force=force,
        )

    async def update_dns_static_entry(
        self, eid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/dns/static/{eid}", data, force=force)

    async def delete_dns_static_entry(self, eid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/dns/static", eid, force=force)

    async def flush_dns_cache(self, *, force: bool = False) -> Any:
        return await self.post("/ip/dns/cache/flush", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Routing — static routes
    # ═══════════════════════════════════════════════════════════════════════

    async def get_routes(self) -> list[dict[str, Any]]:
        return await self.get("/ip/route")

    async def add_route(self, data: dict[str, Any], *, force: bool = False) -> Any:
        # Accepts a full payload dict so the staging applier can pass
        # arbitrary RouterOS route fields (distance, scope, vrf-interface,
        # check-gateway, …). Callers that have only ``dst`` + ``gateway``
        # build the dict themselves.
        return await self.put("/ip/route", data, force=force)

    async def update_route(self, rid: str, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.patch(f"/ip/route/{rid}", data, force=force)

    async def delete_route(self, rid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/route", rid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # ARP
    # ═══════════════════════════════════════════════════════════════════════

    async def get_arp_table(self) -> list[dict[str, Any]]:
        return await self.get("/ip/arp")

    # ═══════════════════════════════════════════════════════════════════════
    # Queues (QoS) — simple queues, queue tree, queue types
    # ═══════════════════════════════════════════════════════════════════════

    async def get_simple_queues(self) -> list[dict[str, Any]]:
        return await self.get("/queue/simple")

    async def add_simple_queue(self, data: dict[str, Any], *, force: bool = False) -> Any:
        # Full payload so callers can pass max-limit, burst-limit,
        # burst-threshold, parent, priority, time, queue, packet-marks, …
        return await self.put("/queue/simple", data, force=force)

    async def update_simple_queue(
        self, qid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/queue/simple/{qid}", data, force=force)

    async def delete_simple_queue(self, qid: str, *, force: bool = False) -> Any:
        return await self.delete("/queue/simple", qid, force=force)

    # ── Queue tree (HTB) ─────────────────────────────────────────────

    async def get_queue_tree(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/queue/tree")
        except MikroTikAPIError:
            return []

    async def add_queue_tree(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/queue/tree", data, force=force)

    async def update_queue_tree(
        self, tid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/queue/tree/{tid}", data, force=force)

    async def delete_queue_tree(self, tid: str, *, force: bool = False) -> Any:
        return await self.delete("/queue/tree", tid, force=force)

    # ── Queue types (kind: pcq, sfq, red, fq-codec, …) ───────────────

    async def get_queue_types(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/queue/type")
        except MikroTikAPIError:
            return []

    async def add_queue_type(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/queue/type", data, force=force)

    async def update_queue_type(
        self, tid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/queue/type/{tid}", data, force=force)

    async def delete_queue_type(self, tid: str, *, force: bool = False) -> Any:
        return await self.delete("/queue/type", tid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # VPN – IPsec
    # ─── /ip/ipsec/peer, /ip/ipsec/identity, /ip/ipsec/policy,
    #     /ip/ipsec/profile, /ip/ipsec/proposal, /ip/ipsec/active-peers ───
    # ═══════════════════════════════════════════════════════════════════════

    # ── Peers ────────────────────────────────────────────────────────

    async def get_ipsec_peers(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/ipsec/peer")
        except MikroTikAPIError:
            return []

    async def add_ipsec_peer(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/ipsec/peer", data, force=force)

    async def update_ipsec_peer(
        self, pid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/ipsec/peer/{pid}", data, force=force)

    async def delete_ipsec_peer(self, pid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/ipsec/peer", pid, force=force)

    # ── Identities (peer credentials / auth-method binding) ──────────

    async def get_ipsec_identities(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/ipsec/identity")
        except MikroTikAPIError:
            return []

    async def add_ipsec_identity(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/ipsec/identity", data, force=force)

    async def update_ipsec_identity(
        self, iid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/ipsec/identity/{iid}", data, force=force)

    async def delete_ipsec_identity(self, iid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/ipsec/identity", iid, force=force)

    # ── Policies ─────────────────────────────────────────────────────

    async def get_ipsec_policies(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/ipsec/policy")
        except MikroTikAPIError:
            return []

    async def add_ipsec_policy(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/ipsec/policy", data, force=force)

    async def update_ipsec_policy(
        self, pid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/ipsec/policy/{pid}", data, force=force)

    async def delete_ipsec_policy(self, pid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/ipsec/policy", pid, force=force)

    # ── Profiles (IKE phase-1 parameters) ────────────────────────────

    async def get_ipsec_profiles(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/ipsec/profile")
        except MikroTikAPIError:
            return []

    async def add_ipsec_profile(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/ipsec/profile", data, force=force)

    async def update_ipsec_profile(
        self, pid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/ipsec/profile/{pid}", data, force=force)

    async def delete_ipsec_profile(self, pid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/ipsec/profile", pid, force=force)

    # ── Proposals (IKE phase-2 parameters) ───────────────────────────

    async def get_ipsec_proposals(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/ipsec/proposal")
        except MikroTikAPIError:
            return []

    # ── Active SAs (read-only operational state) ─────────────────────

    async def get_ipsec_active(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/ipsec/active-peers")
        except MikroTikAPIError:
            return []

    # ═══════════════════════════════════════════════════════════════════════
    # VPN – WireGuard (RouterOS 7+)
    # ─── /interface/wireguard, /interface/wireguard/peers ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_wireguard_interfaces(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/interface/wireguard")
        except MikroTikAPIError:
            return []

    async def add_wireguard_interface(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/interface/wireguard", data, force=force)

    async def update_wireguard_interface(
        self, iid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/interface/wireguard/{iid}", data, force=force)

    async def delete_wireguard_interface(self, iid: str, *, force: bool = False) -> Any:
        return await self.delete("/interface/wireguard", iid, force=force)

    async def get_wireguard_peers(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/interface/wireguard/peers")
        except MikroTikAPIError:
            return []

    async def add_wireguard_peer(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/interface/wireguard/peers", data, force=force)

    async def update_wireguard_peer(
        self, pid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/interface/wireguard/peers/{pid}", data, force=force)

    async def delete_wireguard_peer(self, pid: str, *, force: bool = False) -> Any:
        return await self.delete("/interface/wireguard/peers", pid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # VPN – L2TP / PPTP server settings
    # ─── /interface/l2tp-server/server, /interface/pptp-server/server ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_l2tp_server(self) -> dict[str, Any]:
        try:
            return self._first(await self.get("/interface/l2tp-server/server"))
        except MikroTikAPIError:
            return {}

    async def update_l2tp_server(self, data: dict[str, Any], *, force: bool = False) -> Any:
        # L2TP server is a singleton resource — RouterOS uses the
        # ``/set`` action. We hit the path directly with PATCH which
        # the REST layer maps onto ``set``. ``data`` typically holds
        # ``{"enabled": "true"|"false", "default-profile": "...", …}``.
        return await self.patch("/interface/l2tp-server/server", data, force=force)

    async def get_pptp_server(self) -> dict[str, Any]:
        try:
            return self._first(await self.get("/interface/pptp-server/server"))
        except MikroTikAPIError:
            return {}

    async def update_pptp_server(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.patch("/interface/pptp-server/server", data, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Users (RouterOS console / API accounts — /user)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_users(self) -> list[dict[str, Any]]:
        return await self.get("/user")

    async def add_user(self, data: dict[str, Any], *, force: bool = False) -> Any:
        # Payload typically: {"name": "...", "password": "...",
        # "group": "full"|"read"|"write", "address": "0.0.0.0/0"}.
        return await self.put("/user", data, force=force)

    async def update_user(self, uid: str, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.patch(f"/user/{uid}", data, force=force)

    async def delete_user(self, uid: str, *, force: bool = False) -> Any:
        return await self.delete("/user", uid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Logs
    # ═══════════════════════════════════════════════════════════════════════

    async def get_logs(
        self,
        *,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Pull the RouterOS log. Bounded at 500 entries by default
        (5000 max) — multi-year deployments have logs in the 100MB
        range and the client holds the whole response in memory
        before pydantic parses it. Caller can opt into a larger
        window for forensic exports.

        Uses ``?.proplist`` to return only the columns the UI
        actually renders (time, topics, message) and ``?.query`` to
        slice via RouterOS' own filter syntax (best-effort; older
        RouterOS ignores).
        """
        bounded = max(1, min(int(limit), 5000))
        return await self.get(
            "/log",
            params={".proplist": "time,topics,message", ".query": f".id<={bounded}"},
        )

    # ═══════════════════════════════════════════════════════════════════════
    # System utilities — reboot / shutdown
    # ═══════════════════════════════════════════════════════════════════════

    async def reboot(self, *, force: bool = False) -> Any:
        return await self.post("/system/reboot", force=force)

    # Alias used by the staging applier so the feature name
    # ``mikrotik.system.reboot`` can map to ``reboot_router``.
    async def reboot_router(self, *, force: bool = False) -> Any:
        return await self.reboot(force=force)

    async def shutdown_router(self, *, force: bool = False) -> Any:
        # RouterOS exposes the shutdown action at /system/shutdown.
        return await self.post("/system/shutdown", force=force)

    async def get_packages(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/system/package")
        except MikroTikAPIError:
            return []

    async def get_system_clock(self) -> dict[str, Any]:
        try:
            return self._first(await self.get("/system/clock"))
        except MikroTikAPIError:
            return {}

    async def create_backup(
        self,
        name: str = "freesdn",
        password: str | None = None,
        *,
        force: bool = False,
    ) -> Any:
        payload: dict[str, Any] = {"name": name}
        if password is not None:
            payload["password"] = password
        result = await self.post("/system/backup/save", payload, force=force)
        # Some RouterOS versions echo the request body back in the
        # response envelope (incl. the encryption password). The
        # applied response is persisted to ``adapter_pending_changes``
        # so we strip secrets defensively here at the bottom of the
        # stack — not just in the adapter wrapper.
        from app.core.redaction import redact_secrets

        return redact_secrets(result)

    async def get_files(self) -> list[dict[str, Any]]:
        return await self.get("/file")

    # ═══════════════════════════════════════════════════════════════════════
    # Diagnostics
    # ═══════════════════════════════════════════════════════════════════════

    async def run_ping(
        self, address: str, count: int = 4, *, force: bool = False
    ) -> list[dict[str, Any]]:
        # ``ping`` is non-mutating in spirit but RouterOS REST exposes
        # it as a POST, which the dual-gate refuses by default.
        # Diagnostic adapter callers pass force=True to opt in.
        try:
            result = await self.post(
                "/tool/ping",
                {"address": address, "count": str(count)},
                force=force,
            )
            return result if isinstance(result, list) else []
        except MikroTikAPIError:
            return []

    async def run_traceroute(self, address: str, *, force: bool = False) -> list[dict[str, Any]]:
        try:
            result = await self.post("/tool/traceroute", {"address": address}, force=force)
            return result if isinstance(result, list) else []
        except MikroTikAPIError:
            return []

    # ═══════════════════════════════════════════════════════════════════════
    # Services (IP → Services)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_services(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/service")
        except MikroTikAPIError:
            return []

    async def update_service(self, sid: str, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.patch(f"/ip/service/{sid}", data, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # PPPoE
    # ─── /interface/pppoe-server/server, /interface/pppoe-server,
    #     /interface/pppoe-client, /ppp/secret, /ppp/profile, /ppp/active ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_pppoe_servers(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/interface/pppoe-server/server")
        except MikroTikAPIError:
            return []

    async def add_pppoe_server(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/interface/pppoe-server/server", data, force=force)

    async def update_pppoe_server(
        self, sid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/interface/pppoe-server/server/{sid}", data, force=force)

    async def delete_pppoe_server(self, sid: str, *, force: bool = False) -> Any:
        return await self.delete("/interface/pppoe-server/server", sid, force=force)

    async def get_pppoe_server_sessions(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/interface/pppoe-server")
        except MikroTikAPIError:
            return []

    async def get_pppoe_clients(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/interface/pppoe-client")
        except MikroTikAPIError:
            return []

    async def add_pppoe_client(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/interface/pppoe-client", data, force=force)

    async def update_pppoe_client(
        self, cid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/interface/pppoe-client/{cid}", data, force=force)

    async def delete_pppoe_client(self, cid: str, *, force: bool = False) -> Any:
        return await self.delete("/interface/pppoe-client", cid, force=force)

    async def get_ppp_secrets(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ppp/secret")
        except MikroTikAPIError:
            return []

    async def add_ppp_secret(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ppp/secret", data, force=force)

    async def update_ppp_secret(
        self, sid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ppp/secret/{sid}", data, force=force)

    async def delete_ppp_secret(self, sid: str, *, force: bool = False) -> Any:
        return await self.delete("/ppp/secret", sid, force=force)

    async def get_ppp_profiles(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ppp/profile")
        except MikroTikAPIError:
            return []

    async def add_ppp_profile(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ppp/profile", data, force=force)

    async def update_ppp_profile(
        self, pid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ppp/profile/{pid}", data, force=force)

    async def delete_ppp_profile(self, pid: str, *, force: bool = False) -> Any:
        return await self.delete("/ppp/profile", pid, force=force)

    async def get_ppp_active(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ppp/active")
        except MikroTikAPIError:
            return []

    # ═══════════════════════════════════════════════════════════════════════
    # Hotspot (captive portal)
    # ─── /ip/hotspot, /ip/hotspot/profile, /ip/hotspot/user,
    #     /ip/hotspot/user/profile, /ip/hotspot/active, /ip/hotspot/host,
    #     /ip/hotspot/walled-garden ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_hotspot_servers(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/hotspot")
        except MikroTikAPIError:
            return []

    async def add_hotspot_server(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/hotspot", data, force=force)

    async def update_hotspot_server(
        self, sid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/hotspot/{sid}", data, force=force)

    async def delete_hotspot_server(self, sid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/hotspot", sid, force=force)

    async def get_hotspot_profiles(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/hotspot/profile")
        except MikroTikAPIError:
            return []

    async def add_hotspot_profile(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/hotspot/profile", data, force=force)

    async def update_hotspot_profile(
        self, pid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/hotspot/profile/{pid}", data, force=force)

    async def delete_hotspot_profile(self, pid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/hotspot/profile", pid, force=force)

    async def get_hotspot_users(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/hotspot/user")
        except MikroTikAPIError:
            return []

    async def add_hotspot_user(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/hotspot/user", data, force=force)

    async def update_hotspot_user(
        self, uid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/hotspot/user/{uid}", data, force=force)

    async def delete_hotspot_user(self, uid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/hotspot/user", uid, force=force)

    async def get_hotspot_user_profiles(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/hotspot/user/profile")
        except MikroTikAPIError:
            return []

    async def add_hotspot_user_profile(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/ip/hotspot/user/profile", data, force=force)

    async def update_hotspot_user_profile(
        self, pid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/ip/hotspot/user/profile/{pid}", data, force=force)

    async def delete_hotspot_user_profile(self, pid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/hotspot/user/profile", pid, force=force)

    async def get_hotspot_active(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/hotspot/active")
        except MikroTikAPIError:
            return []

    async def get_hotspot_hosts(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/hotspot/host")
        except MikroTikAPIError:
            return []

    async def get_hotspot_walled_garden(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/ip/hotspot/walled-garden")
        except MikroTikAPIError:
            return []

    async def add_hotspot_walled_garden_entry(
        self, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.put("/ip/hotspot/walled-garden", data, force=force)

    async def delete_hotspot_walled_garden_entry(self, eid: str, *, force: bool = False) -> Any:
        return await self.delete("/ip/hotspot/walled-garden", eid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Certificates
    # ─── /certificate ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_certificates(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/certificate")
        except MikroTikAPIError:
            return []

    async def get_certificate(self, cid: str) -> dict[str, Any]:
        return self._first(await self.get(f"/certificate/{cid}"))

    async def add_certificate(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/certificate", data, force=force)

    async def update_certificate(
        self, cid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/certificate/{cid}", data, force=force)

    async def delete_certificate(self, cid: str, *, force: bool = False) -> Any:
        return await self.delete("/certificate", cid, force=force)

    async def sign_certificate(
        self, cid: str, data: dict[str, Any] | None = None, *, force: bool = False
    ) -> Any:
        payload = {"number": cid, **(data or {})}
        return await self.post("/certificate/sign", payload, force=force)

    async def import_certificate(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.post("/certificate/import", data, force=force)

    # NOTE: ``decrypt_certificate`` has been removed. It accepted a
    # passphrase in the POST body and had zero callers in-tree (audit
    # confirmed via grep). Re-introducing it would put encryption
    # passphrases in HTTP request bodies, which would land in any
    # downstream debug-log of httpx if logging level were lowered.
    # If RouterOS certificate decryption is ever needed, build a
    # do-not-log wrapper that masks ``passphrase`` before issuing
    # the request and add an explicit audit-log entry.

    async def revoke_certificate(self, cid: str, *, force: bool = False) -> Any:
        return await self.post("/certificate/issued-revoke", {"number": cid}, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # SNMP
    # ─── /snmp, /snmp/community ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_snmp_settings(self) -> dict[str, Any]:
        try:
            return self._first(await self.get("/snmp"))
        except MikroTikAPIError:
            return {}

    async def update_snmp_settings(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.patch("/snmp", data, force=force)

    async def get_snmp_communities(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/snmp/community")
        except MikroTikAPIError:
            return []

    async def add_snmp_community(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/snmp/community", data, force=force)

    async def update_snmp_community(
        self, cid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/snmp/community/{cid}", data, force=force)

    async def delete_snmp_community(self, cid: str, *, force: bool = False) -> Any:
        return await self.delete("/snmp/community", cid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # RADIUS
    # ─── /radius, /radius/incoming ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_radius_servers(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/radius")
        except MikroTikAPIError:
            return []

    async def add_radius_server(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/radius", data, force=force)

    async def update_radius_server(
        self, rid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/radius/{rid}", data, force=force)

    async def delete_radius_server(self, rid: str, *, force: bool = False) -> Any:
        return await self.delete("/radius", rid, force=force)

    async def get_radius_incoming_settings(self) -> dict[str, Any]:
        try:
            return self._first(await self.get("/radius/incoming"))
        except MikroTikAPIError:
            return {}

    async def update_radius_incoming_settings(
        self, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch("/radius/incoming", data, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # CAPsMAN (centralized AP management)
    # ─── /caps-man/configuration, /caps-man/datapath, /caps-man/security,
    #     /caps-man/manager, /caps-man/access-list,
    #     /caps-man/registration-table, /caps-man/interface ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_capsman_configurations(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/caps-man/configuration")
        except MikroTikAPIError:
            return []

    async def add_capsman_configuration(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/caps-man/configuration", data, force=force)

    async def update_capsman_configuration(
        self, cid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/caps-man/configuration/{cid}", data, force=force)

    async def delete_capsman_configuration(self, cid: str, *, force: bool = False) -> Any:
        return await self.delete("/caps-man/configuration", cid, force=force)

    async def get_capsman_datapaths(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/caps-man/datapath")
        except MikroTikAPIError:
            return []

    async def add_capsman_datapath(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/caps-man/datapath", data, force=force)

    async def update_capsman_datapath(
        self, did: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/caps-man/datapath/{did}", data, force=force)

    async def delete_capsman_datapath(self, did: str, *, force: bool = False) -> Any:
        return await self.delete("/caps-man/datapath", did, force=force)

    async def get_capsman_security(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/caps-man/security")
        except MikroTikAPIError:
            return []

    async def add_capsman_security_profile(
        self, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.put("/caps-man/security", data, force=force)

    async def update_capsman_security_profile(
        self, sid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/caps-man/security/{sid}", data, force=force)

    async def delete_capsman_security_profile(self, sid: str, *, force: bool = False) -> Any:
        return await self.delete("/caps-man/security", sid, force=force)

    async def get_capsman_manager(self) -> dict[str, Any]:
        try:
            return self._first(await self.get("/caps-man/manager"))
        except MikroTikAPIError:
            return {}

    async def update_capsman_manager(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.patch("/caps-man/manager", data, force=force)

    async def get_capsman_access_list(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/caps-man/access-list")
        except MikroTikAPIError:
            return []

    async def add_capsman_access_list_entry(
        self, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.put("/caps-man/access-list", data, force=force)

    async def delete_capsman_access_list_entry(self, eid: str, *, force: bool = False) -> Any:
        return await self.delete("/caps-man/access-list", eid, force=force)

    async def get_capsman_registrations(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/caps-man/registration-table")
        except MikroTikAPIError:
            return []

    async def get_capsman_interfaces(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/caps-man/interface")
        except MikroTikAPIError:
            return []

    async def update_capsman_interface(
        self, iid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/caps-man/interface/{iid}", data, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # OSPF
    # ─── /routing/ospf/instance, /routing/ospf/area, /routing/ospf/area-range,
    #     /routing/ospf/interface-template, /routing/ospf/neighbor ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ospf_instances(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/routing/ospf/instance")
        except MikroTikAPIError:
            return []

    async def add_ospf_instance(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/routing/ospf/instance", data, force=force)

    async def update_ospf_instance(
        self, iid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/routing/ospf/instance/{iid}", data, force=force)

    async def delete_ospf_instance(self, iid: str, *, force: bool = False) -> Any:
        return await self.delete("/routing/ospf/instance", iid, force=force)

    async def get_ospf_areas(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/routing/ospf/area")
        except MikroTikAPIError:
            return []

    async def add_ospf_area(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/routing/ospf/area", data, force=force)

    async def update_ospf_area(self, aid: str, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.patch(f"/routing/ospf/area/{aid}", data, force=force)

    async def delete_ospf_area(self, aid: str, *, force: bool = False) -> Any:
        return await self.delete("/routing/ospf/area", aid, force=force)

    async def get_ospf_area_ranges(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/routing/ospf/area-range")
        except MikroTikAPIError:
            return []

    async def add_ospf_area_range(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/routing/ospf/area-range", data, force=force)

    async def delete_ospf_area_range(self, rid: str, *, force: bool = False) -> Any:
        return await self.delete("/routing/ospf/area-range", rid, force=force)

    async def get_ospf_interface_templates(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/routing/ospf/interface-template")
        except MikroTikAPIError:
            return []

    async def add_ospf_interface_template(
        self, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.put("/routing/ospf/interface-template", data, force=force)

    async def update_ospf_interface_template(
        self, tid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/routing/ospf/interface-template/{tid}", data, force=force)

    async def delete_ospf_interface_template(self, tid: str, *, force: bool = False) -> Any:
        return await self.delete("/routing/ospf/interface-template", tid, force=force)

    async def get_ospf_neighbors(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/routing/ospf/neighbor")
        except MikroTikAPIError:
            return []

    # ═══════════════════════════════════════════════════════════════════════
    # BGP
    # ─── /routing/bgp/connection, /routing/bgp/template,
    #     /routing/bgp/session ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_bgp_connections(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/routing/bgp/connection")
        except MikroTikAPIError:
            return []

    async def add_bgp_connection(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/routing/bgp/connection", data, force=force)

    async def update_bgp_connection(
        self, cid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/routing/bgp/connection/{cid}", data, force=force)

    async def delete_bgp_connection(self, cid: str, *, force: bool = False) -> Any:
        return await self.delete("/routing/bgp/connection", cid, force=force)

    async def get_bgp_templates(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/routing/bgp/template")
        except MikroTikAPIError:
            return []

    async def add_bgp_template(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/routing/bgp/template", data, force=force)

    async def update_bgp_template(
        self, tid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/routing/bgp/template/{tid}", data, force=force)

    async def delete_bgp_template(self, tid: str, *, force: bool = False) -> Any:
        return await self.delete("/routing/bgp/template", tid, force=force)

    async def get_bgp_sessions(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/routing/bgp/session")
        except MikroTikAPIError:
            return []

    # ═══════════════════════════════════════════════════════════════════════
    # Backup / Export
    # ─── /system/backup, /file, /export ───
    # ═══════════════════════════════════════════════════════════════════════

    async def load_backup(
        self, name: str, password: str | None = None, *, force: bool = False
    ) -> Any:
        # /system/backup/load takes the encryption password in the
        # request body. httpx logs the full request body at DEBUG
        # level, so a verbose deployment would persist the password
        # in the application log. Suppress httpx + httpcore loggers
        # for the duration of this call to keep the credential out
        # of the log stream regardless of operator log-level config.
        # This is per-call (not global) so other diagnostic logging
        # remains intact.
        payload: dict[str, Any] = {"name": name}
        if password is not None:
            payload["password"] = password
        httpx_logger = logging.getLogger("httpx")
        httpcore_logger = logging.getLogger("httpcore")
        prev_httpx = httpx_logger.disabled
        prev_httpcore = httpcore_logger.disabled
        try:
            httpx_logger.disabled = True
            httpcore_logger.disabled = True
            result = await self.post("/system/backup/load", payload, force=force)
        finally:
            httpx_logger.disabled = prev_httpx
            httpcore_logger.disabled = prev_httpcore
        from app.core.redaction import redact_secrets

        return redact_secrets(result)

    async def delete_file(self, fid: str, *, force: bool = False) -> Any:
        return await self.delete("/file", fid, force=force)

    async def export_config(self, file: str | None = None, *, force: bool = False) -> Any:
        payload: dict[str, Any] = {}
        if file is not None:
            payload["file"] = file
        return await self.post("/export", payload, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Switch chip / SwOS-lite
    # ─── /interface/ethernet/switch, /interface/ethernet/switch/port,
    #     /interface/ethernet/switch/vlan, /interface/ethernet/switch/rule ───
    # ═══════════════════════════════════════════════════════════════════════

    async def get_switch_chips(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/interface/ethernet/switch")
        except MikroTikAPIError:
            return []

    async def get_switch_ports(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/interface/ethernet/switch/port")
        except MikroTikAPIError:
            return []

    async def update_switch_port(
        self, pid: str, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        return await self.patch(f"/interface/ethernet/switch/port/{pid}", data, force=force)

    async def get_switch_vlans(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/interface/ethernet/switch/vlan")
        except MikroTikAPIError:
            return []

    async def add_switch_vlan(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/interface/ethernet/switch/vlan", data, force=force)

    async def delete_switch_vlan(self, vid: str, *, force: bool = False) -> Any:
        return await self.delete("/interface/ethernet/switch/vlan", vid, force=force)

    async def get_switch_rules(self) -> list[dict[str, Any]]:
        try:
            return await self.get("/interface/ethernet/switch/rule")
        except MikroTikAPIError:
            return []

    async def add_switch_rule(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.put("/interface/ethernet/switch/rule", data, force=force)

    async def delete_switch_rule(self, rid: str, *, force: bool = False) -> Any:
        return await self.delete("/interface/ethernet/switch/rule", rid, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Tools (extended) — Bandwidth Test / Fetch / Torch
    # ─── /tool/bandwidth-test, /tool/fetch, /tool/torch ───
    # ═══════════════════════════════════════════════════════════════════════

    async def run_bandwidth_test(self, data: dict[str, Any], *, force: bool = False) -> Any:
        try:
            result = await self.post("/tool/bandwidth-test", data, force=force)
            return result if isinstance(result, list) else result
        except MikroTikAPIError:
            return []

    async def fetch_url(self, data: dict[str, Any], *, force: bool = False) -> Any:
        return await self.post("/tool/fetch", data, force=force)

    async def run_torch(
        self,
        interface: str,
        duration: int = 10,
        *,
        force: bool = False,
        timeout_override: float | None = None,
    ) -> Any:
        # Torch streams traffic stats for the duration of the call;
        # the client's read timeout (typically 30s) silently
        # truncates a 60s torch capture. ``timeout_override`` lets
        # the diagnostic adapter pass the torch duration as the read
        # timeout so the operator sees the full window.
        #
        # Implementation note: httpx is a request-scoped client, so
        # we override the timeout on the underlying client just for
        # this call by setting the request's per-call timeout.
        try:
            if timeout_override is not None:
                # Build a one-shot httpx.Timeout. Connect + pool keep
                # the small caps; read/write get the override so the
                # full torch can stream.
                if self._client is None or self._client.is_closed:
                    await self.connect()
                assert self._client is not None
                kw_timeout = httpx.Timeout(
                    connect=5.0,
                    read=float(timeout_override),
                    write=float(timeout_override),
                    pool=5.0,
                )
                # Path-traversal guard + dual-gate happen inside
                # _request — fall through to the standard call but
                # with a bumped session timeout. The read timeout is
                # set on the request itself.
                _validate_path("/tool/torch")
                if _is_adapter_read_only() and not force:
                    raise AdapterError(
                        "ADAPTER_READ_ONLY is set — MikroTik write refused. "
                        "Set ADAPTER_READ_ONLY=false in the environment AND "
                        "pass force=true to override.",
                        adapter_id="mikrotik",
                    )
                resp = await self._client.request(
                    "POST",
                    "/rest/tool/torch",
                    json={
                        "interface": interface,
                        "duration": str(duration),
                    },
                    timeout=kw_timeout,
                )
                if resp.status_code >= 400:
                    return []
                if not resp.text:
                    return []
                try:
                    body = resp.json()
                except (ValueError, UnicodeDecodeError):
                    return []
                return body if isinstance(body, list) else []
            result = await self.post(
                "/tool/torch",
                {"interface": interface, "duration": str(duration)},
                force=force,
            )
            return result if isinstance(result, list) else []
        except MikroTikAPIError:
            return []

    # ═══════════════════════════════════════════════════════════════════════
    # Firmware lifecycle (RouterOS package update channel)
    # ─── /system/package/update, /system/package ───
    # ═══════════════════════════════════════════════════════════════════════
    #
    # Parity gap A. RouterOS package management is
    # split across two menus:
    #   * /system/package/update  — singleton with the update worker
    #     state (installed-version, latest-version, channel, status).
    #     The action verbs (check-for-updates, download, install,
    #     cancel) live as sub-paths under it.
    #   * /system/package         — list of installed packages; each
    #     row supports the disable/enable/uninstall sub-actions.
    #
    # Install reboots the router. That is a hard-dual-gate operation
    # — the engine MUST pass force=True after the operator has
    # confirmed at the apply endpoint.

    async def get_update_status(self) -> dict[str, Any]:
        """GET ``/system/package/update`` — installed + available info.

        Returns a singleton row with keys like ``installed-version``,
        ``latest-version``, ``channel``, ``status``. Returns ``{}`` if
        the endpoint is unavailable (some firmware images have the
        update worker disabled).
        """
        try:
            return self._first(await self.get("/system/package/update"))
        except MikroTikAPIError:
            return {}

    # Channel names RouterOS accepts. Anything else → 400 from the
    # router AND we reject early so the operator sees a clean error.
    _UPDATE_CHANNELS: frozenset[str] = frozenset({"stable", "long-term", "testing", "development"})

    async def set_update_channel(self, channel: str, *, force: bool = False) -> Any:
        """PATCH ``/system/package/update`` to switch update channel."""
        if channel not in self._UPDATE_CHANNELS:
            raise ValueError(
                f"channel must be one of {sorted(self._UPDATE_CHANNELS)!r}, got {channel!r}"
            )
        return await self.patch("/system/package/update", {"channel": channel}, force=force)

    async def check_for_updates(self, *, force: bool = False) -> Any:
        """POST ``/system/package/update/check-for-updates`` —
        ask RouterOS to re-fetch the channel manifest.

        The router emits the action as POST against the parent menu
        (not a sub-row), which means the canonical helper path is to
        hit the action directly with self.post rather than going
        through the patch/delete machinery.
        """
        return await self.post("/system/package/update/check-for-updates", force=force)

    async def download_update(self, *, force: bool = False) -> Any:
        """POST ``/system/package/update/download`` — fetch the
        latest package set without rebooting. Pairs with
        ``download_and_install_update`` for the two-step rollout."""
        return await self.post("/system/package/update/download", force=force)

    async def cancel_update_download(self, *, force: bool = False) -> Any:
        """POST ``/system/package/update/cancel`` — abort an in-flight
        download. Safe even when nothing is downloading (no-op on the
        router)."""
        return await self.post("/system/package/update/cancel", force=force)

    async def download_and_install_update(self, *, force: bool = False) -> Any:
        """POST ``/system/package/update/install`` — download (if
        needed) and reboot into the new image.

        DANGEROUS. Reboots the router. The applier MUST pass
        ``force=True`` after operator confirmation. The dual-gate at
        the apply endpoint is the user-visible barrier; the client
        gate is the seatbelt.
        """
        return await self.post("/system/package/update/install", force=force)

    async def get_installed_packages(self) -> list[dict[str, Any]]:
        """GET ``/system/package`` — list installed packages with
        their version, build, scheduled status and disabled flag."""
        try:
            return await self.get("/system/package")
        except MikroTikAPIError:
            return []

    async def disable_package(self, pid: str, *, force: bool = False) -> Any:
        """POST ``/system/package/disable`` with ``.id`` in body.

        RouterOS does not expose ``disable`` as a generic verb on
        every menu — ``/system/package`` is one of the few that uses
        ``numbers`` (it predates the unified ``.id`` API). To stay on
        the canonical wire format we POST against the action with
        ``numbers=<id>``.
        """
        return await self._request(
            "POST",
            "/system/package/disable",
            data={"numbers": pid},
            force=force,
        )

    async def enable_package(self, pid: str, *, force: bool = False) -> Any:
        """POST ``/system/package/enable`` — symmetric to
        ``disable_package``."""
        return await self._request(
            "POST",
            "/system/package/enable",
            data={"numbers": pid},
            force=force,
        )

    async def uninstall_package(self, pid: str, *, force: bool = False) -> Any:
        """POST ``/system/package/uninstall`` — schedules the package
        for removal on next reboot. Operator confirmation only —
        a reboot is required for the uninstall to take effect."""
        return await self._request(
            "POST",
            "/system/package/uninstall",
            data={"numbers": pid},
            force=force,
        )

    # ═══════════════════════════════════════════════════════════════════════
    # Config backup / restore — extended surface
    # ─── /file (list/contents/delete), /system/backup ───
    # ═══════════════════════════════════════════════════════════════════════
    #
    # Parity gap B. The existing helpers create / load / delete /
    # export, but operators need the full life-cycle (list filtered
    # by file kind, fetch the bytes, push a backup back up).

    # File-name validation. The /file menu treats slashes as the
    # FTP-style separator and most operations expect a flat name in
    # the root of the file system. We accept word characters plus
    # ``.``, ``-``, ``_`` and a single ``/`` to allow paths into the
    # writable ``/disk1/`` directory on devices that have one. No
    # ``..``, no shell metachars, no null bytes.
    _BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)*$")
    _BACKUP_NAME_MAX_LEN = 128

    @classmethod
    def _validate_backup_name(cls, name: str) -> None:
        if not isinstance(name, str) or not name:
            raise ValueError("backup file name must be a non-empty string")
        if len(name) > cls._BACKUP_NAME_MAX_LEN:
            raise ValueError(
                f"backup file name length {len(name)} exceeds cap {cls._BACKUP_NAME_MAX_LEN}"
            )
        if ".." in name:
            raise ValueError(f"backup file name contains '..': {name!r}")
        if not cls._BACKUP_NAME_RE.match(name):
            raise ValueError(f"backup file name has unsafe characters: {name!r}")

    # File extensions recognised as configuration artefacts. ``.backup``
    # is the binary backup format; ``.rsc`` is the text export; ``.npk``
    # is a package file the firmware updater drops on the disk. We
    # surface all three so the operator can manage what's on the box.
    _BACKUP_EXTENSIONS: tuple[str, ...] = (".backup", ".rsc", ".npk")

    async def list_backups(self) -> list[dict[str, Any]]:
        """Filtered view of ``/file`` → only backup / export / package
        artefacts. Each row has the RouterOS file metadata
        (``name``, ``size``, ``creation-time``, ``type``)."""
        try:
            rows = await self.get("/file")
        except MikroTikAPIError:
            return []
        if not isinstance(rows, list):
            return []
        return [
            row
            for row in rows
            if isinstance(row, dict)
            and isinstance(row.get("name"), str)
            and row["name"].endswith(self._BACKUP_EXTENSIONS)
        ]

    async def get_backup_metadata(self, name: str) -> dict[str, Any]:
        """GET ``/file/<name>`` — single-row metadata for a named
        artefact. Returns ``{}`` if the file is absent."""
        self._validate_backup_name(name)
        try:
            result = await self.get(f"/file/{name}")
        except MikroTikAPIError:
            return {}
        return self._first(result)

    async def download_backup_content(self, name: str) -> str:
        """GET the ``.contents`` field of a file row.

        RouterOS REST returns file contents on the row itself for
        small files (the ``contents`` field). For larger binary
        backups the operator should use the FTP/SCP service — this
        helper is for the text exports and small backups the UI
        typically deals with. Returns an empty string when the file
        is absent or has no readable contents.
        """
        self._validate_backup_name(name)
        # enforce the backup-extension whitelist on the DOWNLOAD
        # path too (list_backups already filters by it). Without this, the
        # name-validated GET /file/{name} could read the ``contents`` of ANY
        # RouterOS file row, not just backup/export artifacts.
        if not name.endswith(self._BACKUP_EXTENSIONS):
            return ""
        try:
            result = await self.get(f"/file/{name}")
        except MikroTikAPIError:
            return ""
        row = self._first(result)
        contents = row.get("contents") if isinstance(row, dict) else None
        if not isinstance(contents, str):
            return ""
        return contents

    async def upload_backup_content(
        self,
        name: str,
        contents: str,
        *,
        force: bool = False,
    ) -> Any:
        """PUT (RouterOS ``add``) a new file at ``/file`` with the
        given contents.

        Use case: the frontend re-uploads a previously downloaded
        ``.rsc`` text export so the operator can roll back. Binary
        ``.backup`` files cannot be created this way reliably and
        should go via FTP/SCP — we keep the helper for the text
        path which is the common case.
        """
        self._validate_backup_name(name)
        if not isinstance(contents, str):
            raise ValueError("contents must be a string")
        # Per the file menu contract, ``name`` is the on-router path
        # and ``contents`` is the body. The applier marks force=True
        # because a malicious operator could otherwise push arbitrary
        # config script content.
        return await self.put(
            "/file",
            {"name": name, "contents": contents},
            force=force,
        )

    async def delete_backup(self, name: str, *, force: bool = False) -> Any:
        """Remove a backup / export artefact by name (not by .id).

        RouterOS REST accepts either form; we use ``.id`` per the
        canonical wire-format but find it via a list lookup first so
        the caller can refer to the artefact by its on-router name.

        HIGH-idempotent fix: an operator clicking "delete" twice (or
        a stale frontend cache replaying the request) used to surface
        a ``MikroTikAPIError`` on the second attempt — "file not
        found" 400. The goal-state ("file gone") was reached so the
        right response is success, not error. The current logic:

          1. List backups; if absent, return success with
             ``was_already_absent=True``.
          2. POST /remove. If that POST fails, re-list — if the file
             is now gone, treat the failure as a race against another
             delete and return success.
          3. Only raise if the file persists after the failed POST.

        Returns ``{"ok": True, "was_already_absent": bool}`` so the
        caller can distinguish "already gone" from "we deleted it".
        """
        self._validate_backup_name(name)
        rows = await self.list_backups()
        target = next(
            (r for r in rows if isinstance(r, dict) and r.get("name") == name),
            None,
        )
        if target is None:
            return {"ok": True, "was_already_absent": True}
        rid = target.get(".id")
        if not isinstance(rid, str):
            return {"ok": True, "was_already_absent": True}
        try:
            await self.delete("/file", rid, force=force)
            return {"ok": True, "was_already_absent": False}
        except MikroTikAPIError as exc:
            # Race window: a parallel client / scheduler may have
            # deleted the file between our list and our POST. Re-list
            # and confirm — if the file is gone, treat the POST
            # failure as a benign race rather than a real error.
            after = await self.list_backups()
            still_present = any(isinstance(r, dict) and r.get("name") == name for r in after)
            if not still_present:
                return {"ok": True, "was_already_absent": True}
            raise exc

    async def restore_backup(
        self,
        name: str,
        password: str | None = None,
        *,
        force: bool = False,
    ) -> Any:
        """Alias of ``load_backup`` named after what the operator
        actually wants to do.

        Routes to the existing ``load_backup`` so we don't duplicate
        the password-log-suppression logic. The applier passes
        ``force=True`` after operator confirmation.
        """
        return await self.load_backup(name, password=password, force=force)

    async def export_config_to_text(
        self,
        file: str | None = None,
        *,
        force: bool = False,
    ) -> str:
        """Wrapper over ``export_config`` that normalises the response
        into a single string the frontend can display in a code box.

        RouterOS returns either a list of lines or a dict-shaped
        response with a single ``ret`` key depending on the firmware
        build; we collapse both into a plain string.
        """
        result = await self.export_config(file=file, force=force)
        if isinstance(result, str):
            return result
        if isinstance(result, list):
            return "\n".join(line for line in result if isinstance(line, str))
        if isinstance(result, dict):
            ret = result.get("ret")
            if isinstance(ret, str):
                return ret
        return ""

    # ═══════════════════════════════════════════════════════════════════════
    # Neighbor discovery + topology
    # ─── /ip/neighbor, /ip/neighbor/discovery-settings ───
    # ═══════════════════════════════════════════════════════════════════════
    #
    # Parity gap C. Omada gives us `get_devices_with_topology` for
    # free; we have to compose ours from /ip/neighbor + /interface.
    # The shape of `build_topology` mirrors Omada so the frontend can
    # render either vendor through the same graph component.

    async def get_neighbors(self) -> list[dict[str, Any]]:
        """GET ``/ip/neighbor`` — all discovered neighbours.

        Returns rows with ``mac-address``, ``identity``,
        ``interface``, ``platform``, ``board``, ``version`` for
        each LLDP / CDP / MNDP discovery (and OSPF/BGP-derived
        rows on routers with those daemons enabled).
        """
        try:
            return await self.get("/ip/neighbor")
        except MikroTikAPIError:
            return []

    async def get_neighbor_discovery_settings(self) -> dict[str, Any]:
        """GET the discovery-settings singleton.

        RouterOS 7.x exposes the settings at
        ``/ip/neighbor/discovery-settings``; older builds keep them
        in the bare ``/ip/neighbor`` row. We try the modern path first
        and fall through gracefully if the firmware doesn't have it.
        """
        try:
            return self._first(await self.get("/ip/neighbor/discovery-settings"))
        except MikroTikAPIError:
            return {}

    async def update_neighbor_discovery_settings(
        self, data: dict[str, Any], *, force: bool = False
    ) -> Any:
        """PATCH the discovery-settings singleton.

        Operator-facing fields: ``discover-interface-list``,
        ``protocol`` (comma-list of cdp,lldp,mndp).
        """
        return await self.patch("/ip/neighbor/discovery-settings", data, force=force)

    async def get_lldp_interfaces(self) -> list[dict[str, Any]]:
        """GET ``/interface/lldp`` — per-interface LLDP state when
        the LLDP package is installed.

        Returns an empty list when the LLDP package is absent or the
        endpoint is unavailable.
        """
        try:
            return await self.get("/interface/lldp")
        except MikroTikAPIError:
            return []

    async def get_lldp_neighbours(self) -> list[dict[str, Any]]:
        """GET ``/interface/lldp/neighbor`` — discovered LLDP peers.

        Distinct from ``/ip/neighbor`` which only aggregates the
        proprietary MNDP + CDP discovery. LLDP is an IEEE-standard
        protocol that switches/APs from non-MikroTik vendors broadcast,
        so ``build_topology`` needs both feeds to get a complete graph.

        Returns an empty list when the LLDP package is absent — older
        RouterOS builds and `routerboard`-mini images don't ship LLDP
        by default.
        """
        try:
            return await self.get("/interface/lldp/neighbor")
        except MikroTikAPIError:
            return []

    async def build_topology(self) -> dict[str, Any]:
        """Compose a ``{nodes, edges}`` topology envelope from the
        device's identity, interfaces, and discovered neighbours.

        The shape matches what the frontend graph component expects
        for the Omada vendor (mirrors ``get_devices_with_topology``).
        That makes a single frontend renderer work across vendors.

        - The local device contributes a single ``router`` node.
        - Each discovered neighbour contributes a node keyed by its
          MAC (deduplicated when LLDP and MNDP both report the same
          peer).
        - One edge per (local-interface, neighbour-mac) pair.

        Walking ``/ip/neighbor`` only (CDP/MNDP/RouterOS-discovery) skips
        the LLDP feed entirely — peers reachable only via IEEE LLDP would be
        invisible in the graph. The current implementation walks BOTH
        ``/ip/neighbor`` AND ``/interface/lldp/neighbor`` and merges
        on remote MAC.

        CRIT-perf: identity / interfaces / IP-neighbors / LLDP-neighbors
        were 4 sequential round-trips. They are now issued in parallel
        via ``asyncio.gather(... return_exceptions=True)`` so the
        topology page loads in ~max(individual_times) instead of
        ~sum. If any read fails the root node carries
        ``degraded: True`` and ``degraded_reasons: [...]`` so the
        frontend can surface a banner explaining the partial graph.

        Errors during composition do not raise — partial topologies
        are returned with whatever data we managed to collect, plus
        a ``warnings`` list explaining what failed. Callers can render
        the partial graph and surface the warnings.
        """
        warnings: list[str] = []
        degraded_reasons: list[str] = []

        # Parallelise the 4 reads. ``return_exceptions=True`` keeps a
        # single sub-call failure from poisoning the whole gather —
        # each result is checked individually below.
        identity_res, interfaces_res, neighbors_res, lldp_res = await asyncio.gather(
            self.get_system_identity(),
            self.get_interfaces(),
            self.get_neighbors(),
            self.get_lldp_neighbours(),
            return_exceptions=True,
        )

        def _unwrap(value: Any, name: str, fallback: Any) -> Any:
            if isinstance(value, BaseException):
                warnings.append(f"{name}: {value}")
                degraded_reasons.append(name)
                return fallback
            return value

        identity: dict[str, Any] = _unwrap(identity_res, "identity", {})
        interfaces: list[dict[str, Any]] = _unwrap(interfaces_res, "interfaces", [])
        neighbors: list[dict[str, Any]] = _unwrap(neighbors_res, "neighbors", [])
        lldp_neighbors: list[dict[str, Any]] = _unwrap(lldp_res, "lldp_neighbors", [])

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        local_name = identity.get("name") or "router"
        local_id = f"local:{local_name}"
        root: dict[str, Any] = {
            "id": local_id,
            "label": local_name,
            "type": "router",
            "vendor": "mikrotik",
            "interface_count": len(interfaces),
        }
        if degraded_reasons:
            # Frontend uses this to show a "partial data" banner.
            root["degraded"] = True
            root["degraded_reasons"] = list(degraded_reasons)
        nodes.append(root)

        seen_macs: set[str] = set()

        def _ingest(row: Any, default_proto: str) -> None:
            """Merge a single neighbour row into nodes/edges. Used for
            both /ip/neighbor and /interface/lldp/neighbor entries; the
            LLDP feed uses ``chassis-id`` / ``mac-address`` for the
            peer MAC and ``system-name`` / ``identity`` for the label."""
            if not isinstance(row, dict):
                return
            mac = row.get("mac-address") or row.get("chassis-id") or row.get("address")
            if not isinstance(mac, str) or not mac:
                return
            # MNDP + LLDP can announce the same peer; dedupe by MAC.
            if mac not in seen_macs:
                seen_macs.add(mac)
                nodes.append(
                    {
                        "id": f"neighbor:{mac}",
                        "label": (row.get("identity") or row.get("system-name") or mac),
                        "type": "neighbor",
                        "platform": row.get("platform"),
                        "board": row.get("board"),
                        "version": (row.get("version") or row.get("system-description")),
                    }
                )
            edges.append(
                {
                    "source": local_id,
                    "target": f"neighbor:{mac}",
                    "interface": row.get("interface"),
                    "protocol": row.get("discovered-by") or default_proto,
                }
            )

        for row in neighbors:
            _ingest(row, "mndp")
        for row in lldp_neighbors:
            _ingest(row, "lldp")

        envelope: dict[str, Any] = {
            "nodes": nodes,
            "edges": edges,
            "warnings": warnings,
        }
        if degraded_reasons:
            envelope["degraded"] = True
            envelope["degraded_reasons"] = list(degraded_reasons)
        return envelope

    # ═══════════════════════════════════════════════════════════════════════
    # SNMP — trap targets + SNMPv3 users
    # ─── /snmp (singleton), /snmp/community, /snmp/users ───
    # ═══════════════════════════════════════════════════════════════════════
    #
    # Parity gap G. The half already in place is the singleton get /
    # update plus full community CRUD. Adding:
    #   * trap target add/remove (operates on the singleton's
    #     comma-list field)
    #   * SNMPv3 users CRUD

    @staticmethod
    def _snmp_targets_split(value: str | None) -> list[str]:
        """Normalise a RouterOS comma-list field into a deduped list.

        RouterOS represents multi-value fields as comma-joined
        strings (no whitespace canonicalisation). We split + strip +
        drop empties so set arithmetic is well-defined.
        """
        if not isinstance(value, str) or not value:
            return []
        return [tok.strip() for tok in value.split(",") if tok.strip()]

    @staticmethod
    def _snmp_targets_join(values: list[str]) -> str:
        """Join deduplicating in-order — RouterOS comma-list shape."""
        seen: set[str] = set()
        result: list[str] = []
        for v in values:
            if v and v not in seen:
                seen.add(v)
                result.append(v)
        return ",".join(result)

    async def get_snmp_trap_targets(self) -> list[str]:
        """Read the ``trap-target`` comma-list off the SNMP singleton."""
        settings = await self.get_snmp_settings()
        return self._snmp_targets_split(settings.get("trap-target"))

    async def add_snmp_trap_target(self, host: str, *, force: bool = False) -> Any:
        """Append ``host`` to the SNMP ``trap-target`` comma-list.

        Idempotent — re-adding an existing host is a no-op (we still
        send the PATCH because RouterOS may have reordered or
        whitespace-canonicalised the field).
        """
        if not isinstance(host, str) or not host.strip():
            raise ValueError("trap target host must be a non-empty string")
        current = await self.get_snmp_trap_targets()
        if host not in current:
            current.append(host)
        return await self.update_snmp_settings(
            {"trap-target": self._snmp_targets_join(current)}, force=force
        )

    async def remove_snmp_trap_target(self, host: str, *, force: bool = False) -> Any:
        """Remove ``host`` from the SNMP ``trap-target`` comma-list.

        Idempotent — removing an absent host is a no-op.
        """
        if not isinstance(host, str) or not host.strip():
            raise ValueError("trap target host must be a non-empty string")
        current = await self.get_snmp_trap_targets()
        filtered = [t for t in current if t != host]
        return await self.update_snmp_settings(
            {"trap-target": self._snmp_targets_join(filtered)}, force=force
        )

    async def get_snmp_users(self) -> list[dict[str, Any]]:
        """GET ``/snmp/users`` — list of SNMPv3 users."""
        try:
            return await self.get("/snmp/users")
        except MikroTikAPIError:
            return []

    async def add_snmp_user(self, data: dict[str, Any], *, force: bool = False) -> Any:
        """Add an SNMPv3 user. Payload is the RouterOS shape:
        ``{"name": "...", "auth-protocol": "MD5"|"SHA1",
        "auth-password": "...", "encryption-protocol": "DES"|"AES",
        "encryption-password": "..."}``.

        The response is run through ``redact_secrets`` because
        RouterOS sometimes echoes the password fields back in the
        ``add`` response envelope; we don't want those landing in
        ``adapter_pending_changes`` plaintext.
        """
        result = await self.put("/snmp/users", data, force=force)
        from app.core.redaction import redact_secrets

        return redact_secrets(result)

    async def update_snmp_user(self, uid: str, data: dict[str, Any], *, force: bool = False) -> Any:
        """Update an SNMPv3 user. Same payload as ``add_snmp_user``."""
        result = await self.patch(f"/snmp/users/{uid}", data, force=force)
        from app.core.redaction import redact_secrets

        return redact_secrets(result)

    async def delete_snmp_user(self, uid: str, *, force: bool = False) -> Any:
        """Delete an SNMPv3 user by RouterOS id."""
        return await self.delete("/snmp/users", uid, force=force)

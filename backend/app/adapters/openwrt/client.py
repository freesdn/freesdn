# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — OpenWRT ubus JSON-RPC Client
==========================================

HTTP client for OpenWRT's ubus RPC interface.  Unlike OPNsense/pfSense
REST APIs, OpenWRT exposes a JSON-RPC 2.0 endpoint backed by ``ubus``.

Key differences from REST adapters:
  - Authentication is session-based (login → token → expires 300 s).
  - Configuration uses UCI (``uci get/set/add/delete/commit``).
  - No UUIDs — config entries use positional or hash-based names.
  - Changes require explicit ``uci commit`` + service restart.

Endpoint layout::

    POST /ubus                  — all RPC calls go here
    POST /cgi-bin/luci/rpc/sys  — alternative (LuCI JSON-RPC)

We prefer the ``/ubus`` endpoint which is available via ``uhttpd``
and the ``rpcd`` daemon.
"""

from __future__ import annotations

import contextlib
import logging
import time
from typing import Any

import httpx

from app.adapters.apply_context import in_apply_window
from app.adapters.exceptions import (
    AdapterAuthenticationError,
    AdapterConnectionError,
    AdapterTimeoutError,
)
from app.adapters.http_utils import CircuitBreaker
from app.core.http_client import build_async_client

logger = logging.getLogger(__name__)


class OpenWRTAPIError(Exception):
    """Error returned by OpenWRT ubus RPC."""

    def __init__(self, message: str, code: int = 0):
        super().__init__(message)
        self.code = code


# ── Read-only write gate (parity with omada/opnsense/pfsense/mikrotik/…) ──────
#
# OpenWrt was, alongside Omada, one of the adapters whose request layer never
# refused live-device writes while ADAPTER_READ_ONLY was engaged. Unlike the
# REST adapters (which classify by HTTP verb), ubus tunnels BOTH reads and
# writes over the same ``POST /ubus``, so the gate must classify by the ubus
# *method verb*. Every read on this client uses a distinct, non-mutating verb
# (board / info / dump / status / get / changes / list / read / backup /
# getDHCPLeases / getARPTable / diskfree / process_list / syslog / packagelist /
# *_count …), so a mutating-verb denylist catches every write wrapper
# (system.reboot|halt, network.restart, uci.add|set|delete|commit|revert,
# service.restart, rc.exec) and never a read. Any NEW mutating RPC verb MUST be
# added here.
_UBUS_WRITE_METHODS: frozenset[str] = frozenset(
    {
        "reboot",
        "halt",
        "poweroff",
        "shutdown",
        "restart",
        "reload",
        "start",
        "stop",
        "add",
        "set",
        "delete",
        "commit",
        "revert",
        "rename",
        "order",
        "exec",
        "write",
        "upload",
        "remove",
        "create",
        "update",
    }
)


def _is_adapter_read_only() -> bool:
    """True (default-safe) unless ``ADAPTER_READ_ONLY=false`` in env.

    Mirrors ``AdapterStagingService.is_read_only()`` for the global flag.
    OpenWrt has no vendor-specific override, so only the global flag is
    consulted (operators opt IN to live writes via the env, never out).
    """
    from app.core.runtime_flags import is_adapter_read_only

    return is_adapter_read_only()


def _is_ubus_write(method: str) -> bool:
    """Classify a ubus call as state-mutating by its method verb."""
    return method.lower() in _UBUS_WRITE_METHODS


# ubus RPC error codes
_UBUS_ERRORS = {
    0: "OK",
    1: "INVALID_COMMAND",
    2: "INVALID_ARGUMENT",
    3: "METHOD_NOT_FOUND",
    4: "NOT_FOUND",
    5: "NO_DATA",
    6: "PERMISSION_DENIED",
    7: "TIMEOUT",
}

# Maximum size of any single ubus response. Bounded so a runaway
# ``uci_get_all`` on a complex deployment (50+ VLANs × DHCP rules +
# wireless config) doesn't pin the worker on JSON parse. Most
# legitimate reads are well under 1MB.
_MAX_OPENWRT_RESPONSE_BYTES = 20 * 1024 * 1024  # 20 MB


class OpenWRTClient:
    """
    Async HTTP client for OpenWRT ubus JSON-RPC.

    All RPC calls are sent as POST to ``/ubus`` with a JSON-RPC 2.0
    envelope.  The session token is obtained via ``session.login``
    and refreshed automatically before expiry.

    Parameters
    ----------
    host : str
        OpenWRT hostname or IP.
    username : str
        Login username (typically ``root``).
    password : str
        Login password.
    port : int
        HTTPS port (default 443, some use 80 for HTTP).
    verify_ssl : bool
        Whether to verify the TLS certificate.
    timeout : int
        HTTP request timeout in seconds.
    """

    SESSION_TTL = 280  # refresh before 300 s expiry

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: int = 30,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        scheme = "https" if port == 443 else "http"
        self.base_url = f"{scheme}://{host}:{port}"

        self._session_id: str = "00000000000000000000000000000000"
        self._session_time: float = 0.0
        self._rpc_id: int = 0
        self._client: httpx.AsyncClient | None = None
        self._breaker = CircuitBreaker(failure_threshold=5, reset_timeout=60.0)

    # ── Connection lifecycle ─────────────────────────────────────────────

    async def connect(self) -> None:
        """Create HTTP client and authenticate."""
        self._client = build_async_client(
            base_url=self.base_url,
            verify=self.verify_ssl,
            timeout=httpx.Timeout(self.timeout, connect=10.0),
            # F2: ubus is a fixed JSON-RPC POST endpoint that carries the
            # authenticated session id in the request BODY. On a 307/308 redirect
            # httpx re-sends the body (incl. the session token) to the redirect
            # target — unlike Authorization/Cookie which httpx strips cross-origin.
            # An OpenWrt host has no legitimate need to follow a 3xx, so don't.
            follow_redirects=False,
        )
        try:
            await self._login()
        except Exception:
            if self._client:
                await self._client.aclose()
                self._client = None
            raise

    async def disconnect(self) -> None:
        """Close the HTTP client."""
        if self._client:
            with contextlib.suppress(Exception):
                await self._client.aclose()
            self._client = None
        self._session_id = "00000000000000000000000000000000"

    async def __aenter__(self) -> OpenWRTClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.disconnect()

    # ── Authentication ───────────────────────────────────────────────────

    async def _login(self) -> None:
        """Obtain a ubus session token."""
        try:
            result = await self._raw_call(
                "session",
                "login",
                {"username": self.username, "password": self.password},
                session="00000000000000000000000000000000",
            )
            sid = result.get("ubus_rpc_session", "")
            if not sid or sid == "00000000000000000000000000000000":
                raise AdapterAuthenticationError("OpenWRT login failed — invalid credentials")
            self._session_id = sid
            self._session_time = time.monotonic()
            logger.debug("OpenWRT session established: %s…", sid[:8])
        except AdapterAuthenticationError:
            raise
        except Exception as exc:
            raise AdapterConnectionError(
                f"Failed to connect to OpenWRT at {self.host}: {exc}"
            ) from exc

    async def _ensure_session(self) -> None:
        """Refresh the session if it's about to expire.

        If ``_login`` fails (auth rejection, timeout, transient network
        glitch), clear the stale session state so the NEXT call
        re-authenticates fresh instead of looping on a dead session.
        Without this reset the client would keep trying to use the
        old expired session_id, cycling failed logins on every call
        until the breaker opens.
        """
        if time.monotonic() - self._session_time > self.SESSION_TTL:
            logger.debug("Refreshing OpenWRT session")
            try:
                await self._login()
            except Exception:
                # Force a fresh re-auth on the next call; don't retain
                # whatever stale id/timestamp we had.
                self._session_id = None
                self._session_time = 0.0
                raise

    # ── Core RPC ─────────────────────────────────────────────────────────

    async def _raw_call(
        self,
        path: str,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        session: str | None = None,
    ) -> dict[str, Any]:
        """Send a single ubus JSON-RPC call and return the result dict."""
        if not self._client:
            raise AdapterConnectionError("Not connected")

        if not self._breaker.allow_request():
            raise AdapterConnectionError("Circuit breaker OPEN — too many recent failures")

        self._rpc_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._rpc_id,
            "method": "call",
            "params": [
                session or self._session_id,
                path,
                method,
                params or {},
            ],
        }

        try:
            resp = await self._client.post("/ubus", json=payload)
            resp.raise_for_status()
            # Response-size guard: UCI
            # exports on multi-SSID / multi-VLAN boxes can hit 50MB+;
            # holding that in memory + parsing JSON blocks the event
            # loop. Cap at 20MB by checking Content-Length when
            # advertised, then re-checking the parsed body size. The
            # cap is intentionally generous (most legitimate UCI
            # reads are <1MB) so this triggers only on pathological
            # responses or a misbehaving controller.
            content_length = resp.headers.get("content-length")
            if content_length and int(content_length) > _MAX_OPENWRT_RESPONSE_BYTES:
                self._breaker.record_failure()
                raise AdapterConnectionError(
                    f"OpenWRT response too large "
                    f"({content_length} bytes > "
                    f"{_MAX_OPENWRT_RESPONSE_BYTES}): {path}.{method}"
                )
            body_bytes = resp.content
            if len(body_bytes) > _MAX_OPENWRT_RESPONSE_BYTES:
                self._breaker.record_failure()
                raise AdapterConnectionError(
                    f"OpenWRT response too large "
                    f"({len(body_bytes)} bytes > "
                    f"{_MAX_OPENWRT_RESPONSE_BYTES}): {path}.{method}"
                )
            data = resp.json()
        except httpx.TimeoutException as exc:
            self._breaker.record_failure()
            raise AdapterTimeoutError(f"OpenWRT request timed out: {path}.{method}") from exc
        except httpx.HTTPStatusError as exc:
            self._breaker.record_failure()
            if exc.response.status_code in (401, 403):
                raise AdapterAuthenticationError("OpenWRT authentication failed") from exc
            raise AdapterConnectionError(
                f"OpenWRT HTTP {exc.response.status_code}: {path}.{method}"
            ) from exc
        except Exception as exc:
            self._breaker.record_failure()
            raise AdapterConnectionError(f"OpenWRT request failed: {exc}") from exc

        # Parse JSON-RPC response
        if "error" in data:
            err = data["error"]
            self._breaker.record_failure()
            raise OpenWRTAPIError(
                f"ubus error: {err.get('message', err)}",
                code=err.get("code", 0),
            )

        result = data.get("result")
        if isinstance(result, list):
            # ubus returns [code, {data}] or [code]
            code = result[0] if result else 0
            if code != 0:
                err_msg = _UBUS_ERRORS.get(code, f"ubus error code {code}")
                if code == 6:
                    raise AdapterAuthenticationError(f"OpenWRT permission denied: {path}.{method}")
                self._breaker.record_failure()
                raise OpenWRTAPIError(err_msg, code=code)
            self._breaker.record_success()
            return result[1] if len(result) > 1 else {}

        self._breaker.record_success()
        return result if isinstance(result, dict) else {}

    async def call(
        self,
        path: str,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Authenticated ubus RPC call with automatic session refresh.

        Refuses state-mutating ubus calls while read-only mode is engaged,
        UNLESS we are inside an approved staged-apply window opened by
        ``AdapterStagingService.apply_change`` (which already enforced
        ``ADAPTER_READ_ONLY`` + ``force``). No-op when read-only is off, so
        live-write deployments are unaffected. Authentication (``_login`` →
        ``_raw_call``) bypasses this — it is not a device-state write.
        """
        if _is_ubus_write(method) and _is_adapter_read_only() and not in_apply_window():
            raise OpenWRTAPIError(
                f"ADAPTER_READ_ONLY is set — OpenWrt write ({path}.{method}) "
                "refused outside an approved staged apply. Route the change "
                "through AdapterStagingService (stage → apply), or set "
                "ADAPTER_READ_ONLY=false to permit direct live writes."
            )
        await self._ensure_session()
        return await self._raw_call(path, method, params)

    # ═══════════════════════════════════════════════════════════════════════
    # System
    # ═══════════════════════════════════════════════════════════════════════

    async def get_board_info(self) -> dict[str, Any]:
        """System board info (model, hostname, kernel, etc.)."""
        return await self.call("system", "board")

    async def get_system_info(self) -> dict[str, Any]:
        """System uptime, load, memory."""
        return await self.call("system", "info")

    async def reboot(self) -> dict[str, Any]:
        """Reboot the device."""
        return await self.call("system", "reboot")

    # ═══════════════════════════════════════════════════════════════════════
    # Network / Interfaces
    # ═══════════════════════════════════════════════════════════════════════

    async def get_network_interfaces(self) -> dict[str, Any]:
        """Dump all network interface status."""
        return await self.call("network.interface", "dump")

    async def get_interface_status(self, iface: str) -> dict[str, Any]:
        """Status of a single logical interface."""
        return await self.call(f"network.interface.{iface}", "status")

    async def reload_network(self) -> dict[str, Any]:
        """Reload the network service.

        Best-effort: the UCI writes preceding this call have already
        been committed to ``/etc/config/*``, so a failed reload still
        leaves the box in a self-consistent state — the next manual
        ``/etc/init.d/network reload`` or reboot will pick the change
        up. Common ubus failures (``Access denied`` on 24.10+ without
        ACL grants; ``INVALID_ARGUMENT`` when procd is mid-restart;
        timeouts when the iface comes back slow) are swallowed and
        returned as a sentinel ``{reload_skipped, reason}`` dict so
        the calling write reports success rather than a misleading
        503 that suggests the data didn't land.
        """
        try:
            return await self.call("network", "restart")
        except Exception as exc:
            return {"reload_skipped": True, "reason": str(exc)}

    # ═══════════════════════════════════════════════════════════════════════
    # UCI — Unified Configuration Interface
    # ═══════════════════════════════════════════════════════════════════════

    async def uci_get(
        self,
        config: str,
        *,
        section: str | None = None,
        option: str | None = None,
        type: str | None = None,
    ) -> dict[str, Any]:
        """Read UCI config values."""
        params: dict[str, Any] = {"config": config}
        if section:
            params["section"] = section
        if option:
            params["option"] = option
        if type:
            params["type"] = type
        return await self.call("uci", "get", params)

    async def uci_get_all(self, config: str) -> dict[str, Any]:
        """Read entire UCI config file."""
        return await self.call("uci", "get", {"config": config})

    async def uci_add(
        self,
        config: str,
        type: str,
        name: str | None = None,
        values: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Add a new UCI config section."""
        params: dict[str, Any] = {"config": config, "type": type}
        if name:
            params["name"] = name
        if values:
            params["values"] = values
        return await self.call("uci", "add", params)

    async def uci_set(
        self,
        config: str,
        section: str,
        values: dict[str, Any],
    ) -> dict[str, Any]:
        """Set values on an existing UCI config section."""
        return await self.call(
            "uci",
            "set",
            {
                "config": config,
                "section": section,
                "values": values,
            },
        )

    async def uci_delete(
        self,
        config: str,
        section: str,
        option: str | None = None,
    ) -> dict[str, Any]:
        """Delete a UCI config section or option."""
        params: dict[str, Any] = {"config": config, "section": section}
        if option:
            params["option"] = option
        return await self.call("uci", "delete", params)

    async def uci_commit(self, config: str) -> dict[str, Any]:
        """Commit pending UCI changes for a config file."""
        return await self.call("uci", "commit", {"config": config})

    async def uci_revert(self, config: str) -> dict[str, Any]:
        """Revert uncommitted UCI changes."""
        return await self.call("uci", "revert", {"config": config})

    async def uci_changes(self, config: str) -> dict[str, Any]:
        """List uncommitted UCI changes."""
        return await self.call("uci", "changes", {"config": config})

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP / DNS (dnsmasq)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_leases(self) -> dict[str, Any]:
        """Active DHCP leases.

        ``dhcp.ipv4leases`` / ``dhcp.ipv6leases`` return ``Access denied``
        on OpenWrt 24.10+ even for root via ubus RPC — those endpoints
        are restricted to local dnsmasq IPC. The LuCI RPC package
        (``luci-rpc``) wraps the lease file read with proper ACLs and
        returns both v4 and v6 leases in one call as
        ``{dhcp_leases: [...], dhcp6_leases: [...]}``. Always present
        on LuCI-equipped builds; only fails on minimal/headless builds.
        """
        return await self.call("luci-rpc", "getDHCPLeases")

    async def get_dhcp_leases_v6(self) -> dict[str, Any]:
        """Active DHCPv6 leases — included in getDHCPLeases under the
        ``dhcp6_leases`` key. Kept as a separate method so callers
        that only want v6 don't have to know about the merged shape.
        """
        full = await self.call("luci-rpc", "getDHCPLeases")
        return {"leases": full.get("dhcp6_leases", [])}

    # ═══════════════════════════════════════════════════════════════════════
    # Services
    # ═══════════════════════════════════════════════════════════════════════

    async def get_services(self) -> dict[str, Any]:
        """List all registered services and their instances."""
        return await self.call("service", "list")

    async def get_service(self, name: str) -> dict[str, Any]:
        """Status of a single service."""
        return await self.call("service", "list", {"name": name})

    async def restart_service(self, name: str) -> dict[str, Any]:
        """Restart a service by init script name.

        Best-effort — see ``reload_network`` for the rationale. The
        UCI commit upstream has already taken effect; the live reload
        is what's missed when ubus refuses (``Access denied`` without
        ACL grants, ``INVALID_ARGUMENT`` from procd during contention,
        timeouts when the service is slow to come back). Returns a
        sentinel dict on any failure so the calling write reports
        success rather than a misleading 503.
        """
        # OpenWRT uses /etc/init.d/<name> restart via procd
        try:
            return await self.call(
                "rc",
                "exec",
                {"name": name, "command": "restart"},
            )
        except Exception as exc:
            return {"reload_skipped": True, "service": name, "reason": str(exc)}

    # ═══════════════════════════════════════════════════════════════════════
    # System utilities
    # ═══════════════════════════════════════════════════════════════════════

    async def get_package_list(self) -> dict[str, Any]:
        """List installed packages (requires rpcd-mod-packagelist)."""
        try:
            return await self.call("rpc-sys", "packagelist")
        except OpenWRTAPIError:
            # packagelist module may not be installed
            return {"packages": {}}

    async def create_backup(self) -> bytes:
        """Generate a backup tar.gz of /etc/config/."""
        import base64
        import binascii

        result = await self.call("rpc-sys", "backup")
        # The backup data may be base64-encoded in the response
        if isinstance(result, dict) and "data" in result:
            try:
                return base64.b64decode(result["data"])
            except (binascii.Error, ValueError) as exc:
                logger.error("Failed to decode backup data: %s", exc)
                return b""
        return b""

    async def get_filesystem_usage(self) -> dict[str, Any]:
        """Disk/flash usage stats."""
        try:
            return await self.call("luci2.system", "diskfree")
        except OpenWRTAPIError:
            return {}

    async def get_process_list(self) -> dict[str, Any]:
        """Running process list."""
        try:
            return await self.call("luci2.system", "process_list")
        except OpenWRTAPIError:
            return {}

    # ═══════════════════════════════════════════════════════════════════════
    # Extended system / network
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_log(self, lines: int = 100) -> dict[str, Any]:
        """Read system log entries."""
        try:
            return await self.call("log", "read", {"lines": lines})
        except OpenWRTAPIError:
            try:
                return await self.call("luci2.system", "syslog")
            except OpenWRTAPIError:
                return {"log": []}

    async def get_arp_table(self) -> dict[str, Any]:
        """ARP table entries."""
        try:
            return await self.call("luci-rpc", "getARPTable")
        except OpenWRTAPIError:
            try:
                return await self.call("luci2.network", "arp_table")
            except OpenWRTAPIError:
                return {"entries": []}

    async def get_conntrack_count(self) -> dict[str, Any]:
        """Connection tracking count."""
        try:
            return await self.call("luci2.network", "conntrack_count")
        except OpenWRTAPIError:
            return {}

    async def start_service(self, name: str) -> dict[str, Any]:
        """Start a service by init script name."""
        return await self.call("rc", "exec", {"name": name, "command": "start"})

    async def stop_service(self, name: str) -> dict[str, Any]:
        """Stop a service by init script name."""
        return await self.call("rc", "exec", {"name": name, "command": "stop"})

    async def halt(self) -> dict[str, Any]:
        """Shutdown the device."""
        return await self.call("system", "halt")

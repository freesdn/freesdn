# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - pfSense API Client
==================================

Low-level async HTTP client for the pfSense REST API package.
Auth uses ``Authorization: {api_key} {api_secret}`` header.
Endpoints live under ``/api/v2/{resource}`` (v1 fallback supported).
"""

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
from app.adapters.validation import validate_id
from app.core.http_client import build_async_client

logger = logging.getLogger(__name__)


# pfSense API paths follow ``/api/v2/<section>/...``. Reject anything
# outside the safe-path regex before httpx sees it — this single
# chokepoint covers every interpolation site in the adapter.
#
# This regex is DELIBERATELY tight. ``?``/``=``/``&``/``%`` are NOT
# permitted: every query param MUST flow through httpx's ``params=``
# kwarg so a caller-supplied value (e.g. an alias name carrying
# ``foo&id=99``) cannot smuggle additional selectors into the URL.
# Mirrors the OPNsense client's pattern.
_SAFE_PATH_RE = re.compile(r"^/?[A-Za-z0-9_./\-:]+/?$")


def _validate_path(path: str) -> None:
    """Reject paths that contain traversal payloads or control chars."""
    if not path or not _SAFE_PATH_RE.match(path):
        raise AdapterError(
            f"unsafe pfSense API path: {path!r}",
            adapter_id="pfsense",
        )
    if ".." in path:
        raise AdapterError(
            f"path traversal segment in pfSense API path: {path!r}",
            adapter_id="pfsense",
        )


# HTTP methods that mutate state — subject to the dual-gate.
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _is_adapter_read_only() -> bool:
    """Returns True (default-safe) unless ``ADAPTER_READ_ONLY=false``.

    pfSense respects ONLY ``ADAPTER_READ_ONLY``. The Omada-era
    ``OMADA_READ_ONLY`` flag is intentionally NOT consulted here — the
    previous OR-fallback meant an operator who wanted writes on pfSense
    while keeping Omada locked could not get them: any environment with
    ``OMADA_READ_ONLY=true`` (the default for fleets that haven't
    deliberately opened it) would force pfSense closed too. Each
    adapter now respects its own flag; cross-adapter read-only is
    expressed via ``ADAPTER_READ_ONLY``.
    """
    from app.core.runtime_flags import is_adapter_read_only

    return is_adapter_read_only()


_ERROR_MESSAGE_MAX = 200
_SECRETY_TOKENS: tuple[str, ...] = ("password", "secret", "passwd", "token", "key")


def _sanitize_error_message(msg: str) -> str:
    """Strip secret-looking tokens, then truncate.

    pfSense controllers echo offending request payloads back inside
    error messages — including, sometimes, partial password material
    when an auth submission was malformed. Strip FIRST so a long
    secret token straddling the 200-char boundary gets fully masked,
    THEN truncate to bound message length. Reversing the order leaks
    the head of long secrets through the truncation cut.
    """
    if not msg:
        return msg
    out_parts: list[str] = []
    # Split on whitespace to evaluate each token; keep it simple so the
    # operator still gets enough context to debug a real error.
    for token in msg.split():
        lower = token.lower()
        if any(t in lower for t in _SECRETY_TOKENS):
            out_parts.append("***")
        else:
            out_parts.append(token)
    sanitized = " ".join(out_parts)
    return sanitized[:_ERROR_MESSAGE_MAX]


def _record_request_metric(method: str, outcome: str) -> None:
    try:
        from app.core.metrics import adapter_requests_total

        adapter_requests_total.labels(adapter="pfsense", method=method, outcome=outcome).inc()
    except Exception:
        pass


def _record_latency(method: str, latency_seconds: float) -> None:
    try:
        from app.core.metrics import adapter_request_duration

        adapter_request_duration.labels(adapter="pfsense", method=method).observe(latency_seconds)
    except Exception:
        pass


def _record_error(error_type: str) -> None:
    try:
        from app.core.metrics import adapter_errors_total

        adapter_errors_total.labels(adapter="pfsense", error_type=error_type).inc()
    except Exception:
        pass


class PfSenseAPIError(Exception):
    """pfSense API error with HTTP context."""

    def __init__(self, message: str, status_code: int | None = None, response: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class PfSenseClient:
    """
    Async HTTP client for pfSense REST API.

    Uses ``Authorization: {api_key} {api_secret}`` header.
    Response data is auto-unwrapped from the ``"data"`` envelope.

    Example::

        async with PfSenseClient("192.168.1.1", "key", "secret") as c:
            rules = await c.get_firewall_rules()
    """

    def __init__(
        self,
        host: str,
        api_key: str,
        api_secret: str,
        *,
        port: int = 443,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        timeout: int = 30,
        api_version: str = "v2",
    ):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.api_secret = api_secret
        self.use_ssl = use_ssl
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.api_version = api_version
        scheme = "https" if use_ssl else "http"
        self.base_url = f"{scheme}://{host}:{port}"
        self._client: httpx.AsyncClient | None = None
        # Tagged breaker so dashboards graph pfSense alongside OPNsense
        # via ``freesdn_adapter_circuit_state{adapter,host}``.
        #
        # NOTE: the breaker is per-client-instance. Because the client
        # is rebuilt per request (the adapter is created freshly inside
        # each service call), breaker state effectively resets between
        # requests — it acts as a per-request short-circuit only,
        # detecting cascading failures within a single call's chained
        # API hits rather than across requests. This is the intentional
        # trade-off (matches OPNsense). Promoting the breaker to a
        # module-level cache keyed by ``(name, host)`` is a follow-up
        # if cross-request memory of failures becomes useful — at which
        # point the dashboards keyed by ``host`` will start to reflect
        # multi-request state.
        self._breaker = CircuitBreaker(
            failure_threshold=5,
            reset_timeout=60.0,
            name="pfsense",
            host=self.base_url,
        )

    # ── lifecycle ────────────────────────────────────────────────────────

    async def connect(self) -> None:
        if self._client is None or self._client.is_closed:
            self._client = build_async_client(
                base_url=self.base_url,
                verify=self.verify_ssl,
                timeout=self.timeout,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Authorization": f"{self.api_key} {self.api_secret}",
                },
            )

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "PfSenseClient":
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
    ) -> dict[str, Any] | list[Any]:
        method_upper = method.upper()

        # Path-traversal guard — single chokepoint.
        _validate_path(path)

        # Universal read-only gate. Default-on; refuses writes unless
        # the caller explicitly opted in via ``force=True``. Same
        # shape Omada / OPNsense / Proxmox use.
        if method_upper in _WRITE_METHODS and _is_adapter_read_only() and not force:
            _record_request_metric(method_upper, "read_only_blocked")
            raise AdapterError(
                "ADAPTER_READ_ONLY is set — pfSense write refused. Set "
                "ADAPTER_READ_ONLY=false in the environment AND pass "
                "force=true to override. Both safeties must be down "
                "before a write reaches the firewall.",
                adapter_id="pfsense",
            )

        if self._client is None or self._client.is_closed:
            await self.connect()
        assert self._client is not None

        if not self._breaker.allow_request():
            _record_request_metric(method_upper, "circuit_open")
            raise AdapterConnectionError(
                "Circuit breaker OPEN — too many recent failures",
                adapter_id="pfsense",
            )

        # auto-prefix /api/v2
        if not path.startswith("/api/"):
            path = f"/api/{self.api_version}{path}"

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
                raise AdapterAuthenticationError(
                    "pfSense authentication failed – check API key/secret",
                    adapter_id="pfsense",
                )

            if response.status_code >= 400:
                msg = f"pfSense API {response.status_code}"
                try:
                    body = response.json()
                    msg = body.get("message", body.get("error", msg))
                except (ValueError, KeyError):
                    msg = response.text or msg
                # Sanitize: pfSense error messages can echo offending
                # request payloads back, which sometimes contain partial
                # password material if the operator submitted bad creds.
                # Truncate hard and strip any line referencing secrets.
                msg = _sanitize_error_message(str(msg))
                # Don't trip breaker on 4xx — controller is reachable,
                # just rejected. 5xx counts as a controller-health
                # failure.
                if response.status_code >= 500:
                    self._breaker.record_failure()
                _record_request_metric(method_upper, f"http_{response.status_code}")
                _record_error(f"http_{response.status_code}")
                raise PfSenseAPIError(msg, status_code=response.status_code)

            # Success path.
            _record_latency(method_upper, time.monotonic() - request_start)

            if not response.text:
                self._breaker.record_success()
                _record_request_metric(method_upper, "success")
                return {}

            result = response.json()
            # pfSense responses sometimes carry an HTTP 200 yet declare
            # ``status: error`` in the body — treat that as a failure so
            # the breaker trips and the staging applier surfaces a real
            # error to the operator instead of silently ``ok``ing a
            # payload that never landed.
            if isinstance(result, dict):
                status_field = result.get("status")
                if isinstance(status_field, str) and status_field.lower() == "error":
                    err_msg = _sanitize_error_message(
                        str(
                            result.get("message")
                            or result.get("error")
                            or "pfSense returned status=error"
                        )
                    )
                    self._breaker.record_failure()
                    _record_request_metric(method_upper, "body_error")
                    _record_error("body_error")
                    raise PfSenseAPIError(
                        err_msg, status_code=response.status_code, response=result
                    )
                # pfSense API wraps payloads in "data" key
                if "data" in result:
                    self._breaker.record_success()
                    _record_request_metric(method_upper, "success")
                    return result["data"]
            self._breaker.record_success()
            _record_request_metric(method_upper, "success")
            return result

        except httpx.TimeoutException as exc:
            self._breaker.record_failure()
            _record_request_metric(method_upper, "timeout")
            _record_error("timeout")
            raise AdapterTimeoutError(
                f"pfSense request timed out: {path}",
            ) from exc
        except httpx.RequestError as exc:
            self._breaker.record_failure()
            raise AdapterConnectionError(
                f"pfSense connection error: {exc}",
                adapter_id="pfsense",
            ) from exc

    async def get(  # noqa: D401
        self, path: str, params: dict | None = None
    ) -> Any:
        return await self._request("GET", path, params=params)

    async def post(
        self,
        path: str,
        data: dict | None = None,
        *,
        force: bool = False,
    ) -> Any:
        """POST. ``force`` propagates to the read-only gate; the
        staging applier is the only sanctioned caller that passes
        ``force=True``."""
        return await self._request("POST", path, data=data, force=force)

    async def put(
        self,
        path: str,
        data: dict | None = None,
        *,
        force: bool = False,
    ) -> Any:
        return await self._request("PUT", path, data=data, force=force)

    async def patch(
        self,
        path: str,
        data: dict | None = None,
        *,
        force: bool = False,
    ) -> Any:
        return await self._request("PATCH", path, data=data, force=force)

    async def delete(
        self,
        path: str,
        params: dict | None = None,
        *,
        force: bool = False,
    ) -> Any:
        return await self._request("DELETE", path, params=params, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # System
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_status(self) -> dict[str, Any]:
        return await self.get("/status/system")

    async def get_system_info(self) -> dict[str, Any]:
        return await self.get("/system/hostname")

    async def get_system_version(self) -> dict[str, Any]:
        return await self.get("/system/version")

    # ═══════════════════════════════════════════════════════════════════════
    # Interfaces
    # ═══════════════════════════════════════════════════════════════════════

    async def get_interfaces(self) -> Any:
        return await self.get("/interface")

    async def get_interface(self, iface: str) -> Any:
        validate_id(iface, label="interface")
        return await self.get("/interface", params={"if": iface})

    async def get_interface_stats(self) -> Any:
        return await self.get("/status/interface")

    async def get_arp_table(self) -> Any:
        return await self.get("/diagnostics/arp_table")

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall Rules
    # ═══════════════════════════════════════════════════════════════════════

    async def get_firewall_rules(self, interface: str | None = None) -> Any:
        if interface is not None:
            validate_id(interface, label="interface")
        params = {"interface": interface} if interface else None
        return await self.get("/firewall/rule", params=params)

    async def get_firewall_rule(self, rule_id: int) -> Any:
        if rule_id is None:
            raise AdapterError("get_firewall_rule requires rule_id", adapter_id="pfsense")
        return await self.get("/firewall/rule", params={"id": int(rule_id)})

    async def add_firewall_rule(self, rule: dict[str, Any], *, force: bool = False) -> Any:
        if rule is None:
            raise AdapterError("add_firewall_rule requires rule payload", adapter_id="pfsense")
        return await self.post("/firewall/rule", data=rule, force=force)

    async def update_firewall_rule(
        self,
        rule_id: int,
        rule: dict[str, Any],
        *,
        force: bool = False,
    ) -> Any:
        if rule_id is None:
            raise AdapterError("update_firewall_rule requires rule_id", adapter_id="pfsense")
        if rule is None:
            raise AdapterError(
                "update_firewall_rule requires rule payload",
                adapter_id="pfsense",
            )
        # Copy: never mutate the caller-supplied dict — the staging
        # applier may inspect the original payload after this call
        # returns, and re-using the same reference would echo our
        # injected ``id`` back into the change record.
        payload = {**rule, "id": rule_id}
        return await self.put("/firewall/rule", data=payload, force=force)

    async def delete_firewall_rule(self, rule_id: int, *, force: bool = False) -> Any:
        if rule_id is None:
            raise AdapterError("delete_firewall_rule requires rule_id", adapter_id="pfsense")
        return await self.delete("/firewall/rule", params={"id": int(rule_id)}, force=force)

    async def apply_firewall_changes(self, *, force: bool = False) -> Any:
        return await self.post("/firewall/apply", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Firewall Aliases
    # ═══════════════════════════════════════════════════════════════════════

    async def get_aliases(self) -> Any:
        return await self.get("/firewall/alias")

    async def get_alias(self, name: str) -> Any:
        validate_id(name, label="alias_name")
        return await self.get("/firewall/alias", params={"name": name})

    async def add_alias(self, alias: dict[str, Any], *, force: bool = False) -> Any:
        if alias is None:
            raise AdapterError("add_alias requires alias payload", adapter_id="pfsense")
        return await self.post("/firewall/alias", data=alias, force=force)

    async def update_alias(
        self,
        name: str,
        alias: dict[str, Any],
        *,
        force: bool = False,
    ) -> Any:
        if name is None:
            raise AdapterError("update_alias requires name", adapter_id="pfsense")
        if alias is None:
            raise AdapterError("update_alias requires alias payload", adapter_id="pfsense")
        validate_id(name, label="alias_name")
        # Copy: never mutate the caller-supplied dict.
        payload = {**alias, "name": name}
        return await self.put("/firewall/alias", data=payload, force=force)

    async def delete_alias(self, name: str, *, force: bool = False) -> Any:
        if name is None:
            raise AdapterError("delete_alias requires name", adapter_id="pfsense")
        validate_id(name, label="alias_name")
        return await self.delete("/firewall/alias", params={"name": name}, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # NAT
    # ═══════════════════════════════════════════════════════════════════════

    async def get_nat_rules(self) -> Any:
        return await self.get("/firewall/nat/outbound")

    async def get_port_forwards(self) -> Any:
        return await self.get("/firewall/nat/port_forward")

    async def add_port_forward(self, rule: dict[str, Any], *, force: bool = False) -> Any:
        if rule is None:
            raise AdapterError("add_port_forward requires rule payload", adapter_id="pfsense")
        return await self.post("/firewall/nat/port_forward", data=rule, force=force)

    async def delete_port_forward(self, rule_id: int, *, force: bool = False) -> Any:
        if rule_id is None:
            raise AdapterError("delete_port_forward requires rule_id", adapter_id="pfsense")
        return await self.delete(
            "/firewall/nat/port_forward",
            params={"id": int(rule_id)},
            force=force,
        )

    async def get_nat_1to1(self) -> Any:
        return await self.get("/firewall/nat/one_to_one")

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dhcp_servers(self) -> Any:
        return await self.get("/services/dhcpd")

    async def get_dhcp_leases(self) -> Any:
        return await self.get("/services/dhcpd/lease")

    async def get_dhcp_static_mappings(self, interface: str = "lan") -> Any:
        validate_id(interface, label="interface")
        return await self.get(
            "/services/dhcpd/static_mapping",
            params={"interface": interface},
        )

    async def add_dhcp_static_mapping(self, mapping: dict[str, Any], *, force: bool = False) -> Any:
        if mapping is None:
            raise AdapterError(
                "add_dhcp_static_mapping requires mapping payload",
                adapter_id="pfsense",
            )
        return await self.post("/services/dhcpd/static_mapping", data=mapping, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # DNS (Unbound)
    # ═══════════════════════════════════════════════════════════════════════

    async def get_dns_host_overrides(self) -> Any:
        return await self.get("/services/unbound/host_override")

    async def add_dns_host_override(self, override: dict[str, Any], *, force: bool = False) -> Any:
        if override is None:
            raise AdapterError(
                "add_dns_host_override requires override payload",
                adapter_id="pfsense",
            )
        return await self.post("/services/unbound/host_override", data=override, force=force)

    async def delete_dns_host_override(self, host_id: int, *, force: bool = False) -> Any:
        if host_id is None:
            raise AdapterError(
                "delete_dns_host_override requires host_id",
                adapter_id="pfsense",
            )
        return await self.delete(
            "/services/unbound/host_override",
            params={"id": int(host_id)},
            force=force,
        )

    async def apply_dns_changes(self, *, force: bool = False) -> Any:
        return await self.post("/services/unbound/apply", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # VPN – OpenVPN
    # ═══════════════════════════════════════════════════════════════════════

    async def get_openvpn_servers(self) -> Any:
        return await self.get("/vpn/openvpn/server")

    async def get_openvpn_clients(self) -> Any:
        return await self.get("/vpn/openvpn/client")

    async def get_openvpn_status(self) -> Any:
        return await self.get("/status/openvpn")

    # ═══════════════════════════════════════════════════════════════════════
    # VPN – WireGuard
    # ═══════════════════════════════════════════════════════════════════════

    async def get_wireguard_tunnels(self) -> Any:
        # Distinguish 404 (WireGuard package not installed → legitimate
        # empty) from 401/403/5xx (auth or controller-health failure
        # that the operator MUST see). Swallowing the latter would
        # silently report "no tunnels" while a real outage masked
        # itself behind an empty list.
        try:
            return await self.get("/vpn/wireguard/tunnel")
        except PfSenseAPIError as exc:
            if exc.status_code == 404:
                return []
            raise

    async def get_wireguard_peers(self) -> Any:
        try:
            return await self.get("/vpn/wireguard/peer")
        except PfSenseAPIError as exc:
            if exc.status_code == 404:
                return []
            raise

    # ═══════════════════════════════════════════════════════════════════════
    # VPN – IPsec
    # ═══════════════════════════════════════════════════════════════════════

    async def get_ipsec_tunnels(self) -> Any:
        return await self.get("/vpn/ipsec/phase1")

    async def get_ipsec_status(self) -> Any:
        return await self.get("/status/ipsec")

    # ═══════════════════════════════════════════════════════════════════════
    # Gateway / Routing
    # ═══════════════════════════════════════════════════════════════════════

    async def get_gateways(self) -> Any:
        return await self.get("/routing/gateway")

    async def get_gateway_status(self) -> Any:
        return await self.get("/status/gateway")

    async def get_static_routes(self) -> Any:
        return await self.get("/routing/static_route")

    # ═══════════════════════════════════════════════════════════════════════
    # Services
    # ═══════════════════════════════════════════════════════════════════════

    async def get_services(self) -> Any:
        return await self.get("/status/service")

    async def restart_service(self, service: str, *, force: bool = False) -> Any:
        # ``service`` lands in the URL path. Even though the safe-path
        # regex now rejects ``?``/``=``/``&``, the regex still permits
        # ``/`` so a value like ``unbound/restart/foo`` would compose a
        # surprising URL. Validate at the entry point so only
        # service-shaped names ever interpolate.
        validate_id(service, label="service")
        return await self.post(f"/services/{service}/restart", force=force)

    async def stop_service(self, service: str, *, force: bool = False) -> Any:
        validate_id(service, label="service")
        return await self.post(f"/services/{service}/stop", force=force)

    async def start_service(self, service: str, *, force: bool = False) -> Any:
        validate_id(service, label="service")
        return await self.post(f"/services/{service}/start", force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # Logs
    # ═══════════════════════════════════════════════════════════════════════

    async def get_system_log(self, count: int = 100) -> Any:
        return await self.get("/diagnostics/log/system", params={"count": int(count)})

    async def get_firewall_log(self, count: int = 100) -> Any:
        return await self.get("/diagnostics/log/firewall", params={"count": int(count)})

    # ═══════════════════════════════════════════════════════════════════════
    # VLANs
    # ═══════════════════════════════════════════════════════════════════════

    async def get_vlans(self) -> Any:
        return await self.get("/interface/vlan")

    async def add_vlan(self, vlan: dict[str, Any], *, force: bool = False) -> Any:
        if vlan is None:
            raise AdapterError("add_vlan requires vlan payload", adapter_id="pfsense")
        return await self.post("/interface/vlan", data=vlan, force=force)

    async def update_vlan(
        self,
        vlan_id: int,
        vlan: dict[str, Any],
        *,
        force: bool = False,
    ) -> Any:
        if vlan_id is None:
            raise AdapterError("update_vlan requires vlan_id", adapter_id="pfsense")
        if vlan is None:
            raise AdapterError("update_vlan requires vlan payload", adapter_id="pfsense")
        # Copy: never mutate the caller-supplied dict.
        payload = {**vlan, "id": vlan_id}
        return await self.put("/interface/vlan", data=payload, force=force)

    async def delete_vlan(self, vlan_id: int, *, force: bool = False) -> Any:
        if vlan_id is None:
            raise AdapterError("delete_vlan requires vlan_id", adapter_id="pfsense")
        return await self.delete("/interface/vlan", params={"id": int(vlan_id)}, force=force)

    async def assign_interface(self, interface: dict[str, Any], *, force: bool = False) -> Any:
        """Assign/create a logical interface (e.g., OPT1 → igb0.100)."""
        if interface is None:
            raise AdapterError(
                "assign_interface requires interface payload",
                adapter_id="pfsense",
            )
        return await self.post("/interface", data=interface, force=force)

    async def update_interface(
        self,
        iface_id: str,
        data: dict[str, Any],
        *,
        force: bool = False,
    ) -> Any:
        """Update interface settings (IP, enable, etc.)."""
        if iface_id is None:
            raise AdapterError("update_interface requires iface_id", adapter_id="pfsense")
        if data is None:
            raise AdapterError("update_interface requires data payload", adapter_id="pfsense")
        # Copy: never mutate the caller-supplied dict.
        payload = {**data, "if": iface_id}
        return await self.put("/interface", data=payload, force=force)

    async def delete_interface(self, iface_id: str, *, force: bool = False) -> Any:
        """Remove an interface assignment."""
        if iface_id is None:
            raise AdapterError("delete_interface requires iface_id", adapter_id="pfsense")
        validate_id(iface_id, label="interface")
        return await self.delete("/interface", params={"if": iface_id}, force=force)

    # ═══════════════════════════════════════════════════════════════════════
    # DHCP Server CRUD
    # ═══════════════════════════════════════════════════════════════════════

    async def update_dhcp_server(
        self,
        interface: str,
        config: dict[str, Any],
        *,
        force: bool = False,
    ) -> Any:
        """Update DHCP server config for an interface."""
        if interface is None:
            raise AdapterError("update_dhcp_server requires interface", adapter_id="pfsense")
        if config is None:
            raise AdapterError(
                "update_dhcp_server requires config payload",
                adapter_id="pfsense",
            )
        # Copy: never mutate the caller-supplied dict.
        payload = {**config, "interface": interface}
        return await self.put("/services/dhcpd", data=payload, force=force)

    async def delete_dhcp_static_mapping(self, mapping_id: int, *, force: bool = False) -> Any:
        if mapping_id is None:
            raise AdapterError(
                "delete_dhcp_static_mapping requires mapping_id",
                adapter_id="pfsense",
            )
        return await self.delete(
            "/services/dhcpd/static_mapping",
            params={"id": int(mapping_id)},
            force=force,
        )

    # ═══════════════════════════════════════════════════════════════════════
    # System Utilities
    # ═══════════════════════════════════════════════════════════════════════

    async def reboot(self, *, force: bool = False) -> Any:
        return await self.post("/diagnostics/reboot", force=force)

    async def halt(self, *, force: bool = False) -> Any:
        return await self.post("/diagnostics/halt", force=force)

    async def create_backup(self) -> Any:
        # Re-raise so the staging applier sees the failure and marks
        # the change ``failed``. Previously swallowing returned ``{}``
        # and the change record showed ``success`` even when the
        # backup never landed.
        return await self.get("/diagnostics/config_history/backup")

    async def get_firmware_info(self) -> Any:
        try:
            return await self.get("/system/firmware")
        except PfSenseAPIError:
            return {}

    # ═══════════════════════════════════════════════════════════════════════
    # Diagnostics
    # ═══════════════════════════════════════════════════════════════════════

    async def run_ping(self, host: str, count: int = 4, *, force: bool = False) -> Any:
        try:
            return await self.post(
                "/diagnostics/ping",
                data={"host": host, "count": count},
                force=force,
            )
        except PfSenseAPIError:
            return {}

    async def run_traceroute(self, host: str, *, force: bool = False) -> Any:
        try:
            return await self.post(
                "/diagnostics/traceroute",
                data={"host": host},
                force=force,
            )
        except PfSenseAPIError:
            return {}

    async def run_dns_lookup(self, host: str, *, force: bool = False) -> Any:
        try:
            return await self.post(
                "/diagnostics/dns_lookup",
                data={"host": host},
                force=force,
            )
        except PfSenseAPIError:
            return {}

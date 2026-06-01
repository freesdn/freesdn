# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Ubiquiti UniFi Adapter
==================================

Beta-quality adapter for the UniFi Network Application. Supports both
the Classic controller (self-hosted) and UniFi OS (UDM / UDM-Pro /
UDR / UCG / Cloud Key Gen2+) — the underlying client auto-detects
which generation it's talking to at login time.

Gold-standard hardening contract
--------------------------------
This adapter participates in the dual-gate write contract shared
with Omada / Proxmox / OPNsense / pfSense / MikroTik / Hikvision:

  1. **Dual-gate writes** — every destructive method takes
     ``force: bool = False`` and refuses to execute unless the
     operator has cleared ``ADAPTER_READ_ONLY`` **and** the caller
     passed ``force=True``.
  2. **Tagged CircuitBreaker** wrapping every HTTP call (lives on the
     client). Trips on 5xx / 408 / 429 / network errors. Emits the
     shared ``freesdn_adapter_circuit_state`` Prometheus gauge.
  3. **Read-path redaction** — every method that returns nested data
     funnels through :func:`app.core.redaction.redact_secrets` so
     WLAN PSKs, RADIUS shared secrets, device passwords, API keys,
     and tokens never leak to the API consumer.
  4. **SSRF guard in __init__** — the controller host is validated
     via the unifi-local validator (loopback / link-local /
     multicast / IPv6 ULA always blocked; RFC1918 allowed by
     default since UniFi controllers virtually always live on
     private LAN ranges).
  5. **Path / query validators** — every method that interpolates a
     caller-supplied site / MAC / network ID / WLAN ID into a URL
     funnels through :mod:`unifi.validators` first.
  6. **Resource hygiene** — a single ``httpx.AsyncClient`` is
     constructed per adapter and reused; ``aclose()`` is exposed for
     deterministic teardown by the service layer.
  7. **Structured write-audit** — every write logs a
     ``unifi.write_attempted`` log record with ``{site, device,
     action, forced}`` so an operator can audit who flipped what.

Read paths (18 methods, all redacted)
-------------------------------------
sites, site_health, devices, device, clients, client, port_overrides,
networks, network, wlans, wlan, firewall_rules, firewall_groups,
port_forwards, radius_users, vpn_clients, controller_info,
sysinfo, alerts.

Write paths (Omada-parity, all dual-gated)
------------------------------------------
Two API generations are covered (see ``unifi.client``):
  * **v1 classic** — devices (restart/disable/port-override/PoE/locate/adopt/
    upgrade/force-provision/power-cycle), clients (block/unblock/forget/
    reconnect), WLAN/SSID lifecycle (create/update/delete + password/enable),
    networks/VLANs (create/update/delete), firewall groups + legacy rules,
    RADIUS accounts, port profiles, user (bandwidth) groups, DPI groups,
    port-forwards, dynamic-DNS, static routes, hotspot operators + vouchers.
  * **v2 modern (UniFi OS 10.x)** — the zone-based-firewall / policy engine:
    firewall policies + zones, NAT, QoS, traffic rules, traffic routes,
    static-DNS; plus topology / AP-groups / content-filtering reads.
All write payloads + shapes were captured live on a real UCG Fiber (Net 10.4)
and the gated adapter methods are create→read-back→delete validated against it.

Deferred (constrained by the test box, not the adapter)
-------------------------------------------------------
* Firewall **policies/zones** need ZBF enabled on the controller (the v2
  client + adapter methods + schemas are ready; zones don't exist until the
  operator turns ZBF on).
* SDN backup / restore; L2 adoption flows (manual SSH adoption only).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any, ClassVar

from app.adapters.base import (
    AdapterManifest,
    AdapterResult,
    BaseAdapter,
    DeviceTypeCapabilities,
    DiscoveredDevice,
)
from app.adapters.capabilities import Capability
from app.adapters.exceptions import AdapterError
from app.adapters.unifi.client import UniFiClient
from app.adapters.unifi.exceptions import AdapterReadOnlyError
from app.adapters.unifi.validators import (
    validate_controller_host,
    validate_mac,
    validate_object_id,
    validate_poe_mode,
    validate_port_idx,
    validate_site,
)
from app.core.redaction import redact_secrets

logger = logging.getLogger(__name__)


# Per-(controller, device-mac) lock serializing the device read-modify-write
# (GET device -> mutate radio_table / port_overrides / disabled -> PUT the whole
# record). The adapter pool shares ONE instance per controller within a process,
# so two concurrent staged applies (or direct writes) targeting the same device
# would otherwise GET the same snapshot and the second PUT would silently clobber
# the first (lost update — e.g. a PoE change reverting a port-profile set seconds
# earlier). Keyed by controller base_url + mac so it's stable across pool
# eviction/recreation. (audit #2 F2)
_DEVICE_WRITE_LOCKS: dict[tuple[str, str], asyncio.Lock] = {}
_DEVICE_WRITE_LOCKS_GUARD = asyncio.Lock()


async def _get_device_write_lock(base_url: str, mac: str) -> asyncio.Lock:
    key = (base_url, mac)
    async with _DEVICE_WRITE_LOCKS_GUARD:
        lock = _DEVICE_WRITE_LOCKS.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _DEVICE_WRITE_LOCKS[key] = lock
        return lock


# ════════════════════════════════════════════════════════════════════════
# Dual-gate helpers (mirrors the reference contract)
# ════════════════════════════════════════════════════════════════════════


def _is_adapter_read_only() -> bool:
    """True (default-safe) unless ``ADAPTER_READ_ONLY=false`` in env.

    Per-vendor isolation: the helper only consults the global
    ``settings.ADAPTER_READ_ONLY`` flag. UniFi does **not** fall
    back to any vendor-specific gate so an operator can't
    accidentally enable Omada writes and find UniFi turned on too.
    """
    from app.core.runtime_flags import is_adapter_read_only

    return is_adapter_read_only()


def _enforce_read_only(*, force: bool, action: str) -> None:
    """Refuse a live UniFi write unless the caller passes the explicit ``force=True``
    intent flag — ALWAYS, not only while ADAPTER_READ_ONLY is set.

    The legacy direct write routes advertise a "site_admin + force=True" gate, but
    ``force`` was previously ignored whenever read-only was off (the default
    "manage out of the box" mode), so a ``force=false`` / omitted-force direct write
    reached the live controller with no explicit-intent acknowledgement — bypassing
    the staged review contract. Requiring ``force=True`` unconditionally restores
    that gate. The sanctioned staged-apply path always opts in with ``force=True``
    (AdapterStagingService.apply_change → applier), so it is unaffected. Centralised
    so the refusal message + behaviour stay in sync across all write methods.
    """
    if not force:
        reason = (
            "refused: ADAPTER_READ_ONLY is set — set it false AND pass force=true"
            if _is_adapter_read_only()
            else "requires an explicit force=true intent flag (route mutations "
            "through the staged apply path, or pass force=true deliberately)"
        )
        raise AdapterReadOnlyError(
            f"UniFi {action} {reason}.",
            adapter_id="unifi",
        )


def _allow_private_controller_hosts() -> bool:
    """Resolve the ``ALLOW_PRIVATE_CONTROLLER_HOSTS`` opt-out.

    Defaults to True because UniFi controllers virtually always live
    on private RFC1918 LANs. A SaaS-style deployment that only
    manages public hosts can flip the setting to False in env to
    refuse RFC1918 controller hosts at adapter-init time.
    """
    try:
        from app.core.config import settings

        return bool(getattr(settings, "ALLOW_PRIVATE_CONTROLLER_HOSTS", True))
    except Exception:
        return True


def _write_audit(
    *,
    action: str,
    site: str | None,
    device: str | None,
    forced: bool,
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit the standardised ``unifi.write_attempted`` audit record.

    Every write method must call this **after** the read-only gate
    has been checked but **before** the controller is touched, so
    an operator can correlate a refused write with the live one
    that follows it.
    """
    payload = {
        "site": site,
        "device": device,
        "action": action,
        "forced": forced,
    }
    if extra:
        payload.update(extra)
    logger.info("unifi.write_attempted %s", payload)


# ════════════════════════════════════════════════════════════════════════
# Device type mapping
# ════════════════════════════════════════════════════════════════════════


_UNIFI_TYPE_MAP: dict[str, str] = {
    "uap": "ap",
    "usw": "switch",
    "ugw": "router",
    "udm": "router",
    "uxg": "router",
    "ubb": "ap",  # Building-to-Building bridge
    "ulte": "router",  # LTE backup
}


def _normalize_device_type(unifi_type: str) -> str:
    """Map UniFi device type codes to FreeSDN types."""
    return _UNIFI_TYPE_MAP.get((unifi_type or "").lower(), "switch")


def _redact(payload: Any) -> Any:
    """Run ``redact_secrets`` over every read-path return value.

    Wrapped in a try/except so a bug in the redactor can never
    block a read — the call site re-raises the original error if
    redaction throws.
    """
    try:
        return redact_secrets(payload)
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("UniFi redaction failed (returning empty list): %s", exc)
        return []


# ════════════════════════════════════════════════════════════════════════
# Adapter
# ════════════════════════════════════════════════════════════════════════


class UniFiAdapter(BaseAdapter):
    """
    Adapter for Ubiquiti UniFi Network Application.

    Targets both Classic UniFi controllers and UniFi OS appliances
    (UDM family, Cloud Key Gen2+). Device-type mapping covers APs,
    switches, gateways/routers, and LTE backups.
    """

    manifest: ClassVar[AdapterManifest] = AdapterManifest(
        id="unifi",
        name="Ubiquiti UniFi",
        vendor="Ubiquiti",
        version="2.0.0-beta",
        description=(
            "Beta-quality adapter for the UniFi Network Application "
            "(Classic + UniFi OS). Dual-gated writes + read-path "
            "redaction + tagged circuit breaker."
        ),
        controller_type="unifi",
        supports_controller=True,
        supports_direct=False,
        supported_versions=["7.x", "8.x", "9.x"],
        device_types={
            "ap": DeviceTypeCapabilities(
                module="network",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.DEVICE_LOCATE,
                    Capability.WIFI_SSID_MANAGEMENT,
                    Capability.WIFI_RADIO_CONFIG,
                    Capability.WIFI_CLIENT_LIST,
                    Capability.WIFI_CLIENT_BLOCK,
                    Capability.DEVICE_FIRMWARE_UPGRADE,
                ],
                models=[
                    "U6-Pro",
                    "U6-LR",
                    "U6-Lite",
                    "U6-Enterprise",
                    "U6+",
                    "UAP-*",
                    "U7-*",
                    "*",
                ],
            ),
            "switch": DeviceTypeCapabilities(
                module="network",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.SWITCH_PORT_CONFIG,
                    Capability.VLAN_MANAGEMENT,
                    Capability.PORT_STATISTICS,
                    Capability.POE_CONTROL,
                    Capability.DEVICE_FIRMWARE_UPGRADE,
                ],
                models=[
                    "USW-*",
                    "USW-Pro-*",
                    "USW-Enterprise-*",
                    "USW-Aggregation",
                    "*",
                ],
            ),
            "router": DeviceTypeCapabilities(
                module="network",
                capabilities=[
                    Capability.DEVICE_INFO,
                    Capability.DEVICE_REBOOT,
                    Capability.VLAN_MANAGEMENT,
                    Capability.FIREWALL_BASIC,
                    Capability.ROUTING_STATIC,
                    Capability.DHCP_SERVER,
                    Capability.DEVICE_FIRMWARE_UPGRADE,
                ],
                models=["UDM-*", "UXG-*", "USG-*", "UCG-*", "*"],
            ),
        },
        auth_methods=["username_password"],
        rate_limit_calls_per_minute=120,
        rate_limit_concurrent=5,
        default_sync_interval=300,
        min_sync_interval=60,
        supports_webhooks=False,
        supports_real_time_events=False,
        supports_bulk_operations=True,
    )

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        **kwargs: Any,
    ) -> None:
        # ── SSRF guard (Critical #5) ──────────────────────────────
        # Validate the controller host **before** anything else so
        # a poisoned credential row in the DB can't cause us to
        # construct a base_url targeting loopback / cloud metadata.
        validate_controller_host(
            host,
            allow_private=_allow_private_controller_hosts(),
        )

        super().__init__(host, username, password, **kwargs)

        # Default site at adapter level; per-call ``site=`` arguments
        # override this without touching the client default.
        self._default_site = kwargs.get("site", "default")

        self._api = UniFiClient(
            host=host,
            username=username,
            password=password,
            port=kwargs.get("port", 8443),
            site=self._default_site,
            use_ssl=kwargs.get("use_ssl", True),
            verify_ssl=kwargs.get("verify_ssl", False),
            is_unifi_os=kwargs.get("is_unifi_os"),
        )

    # ────────────────────────────────────────────────────────────────
    # IDOR guard — verify a caller-supplied site is reachable on THIS
    # controller before interpolating it into ``/api/s/{site}/...``
    # ────────────────────────────────────────────────────────────────

    async def _verify_site_owned(self, site: str) -> None:
        """Reject a ``site`` that does not exist on this controller.

        ``validate_site`` only checks the *format* of the slug — it does
        nothing to stop a caller from naming a site that belongs to a
        different tenant on a multi-tenant UniFi controller (the creds
        backing this adapter may legitimately see several sites). Without
        this check, ``site`` flows straight into ``/api/s/{site}/...`` on
        every write method and an operator could pivot to restart /
        disable / re-PSK devices on a sibling tenant's site (cross-site
        IDOR).

        The non-site-scoped ``/api/self/sites`` endpoint lists exactly
        the sites this account may touch, so membership in that set is
        the authoritative ownership check. This mirrors the live
        ``get_sites()`` fallback in
        :meth:`GatewayUniFiDevicesService._verify_unifi_site_owned`; the
        staged applier already performs the equivalent check, so adding
        it here primarily closes the *direct* REST write path.

        Raises :class:`AdapterError` (normalised to 4xx upstream) when
        the site is not visible. A transport error while listing sites
        also raises rather than fail-open, so a flaky controller can
        never silently disable the guard.
        """
        try:
            resp = await self._api.get_sites()
        except AdapterError:
            raise
        except Exception as exc:
            # Do not echo ``exc`` to the caller — a non-typed get_sites() failure
            # can embed the controller host/URL in its string (read-path recon
            # leak, audit #3 F3). Log it; surface a generic message upstream.
            logger.warning("UniFi site-ownership check could not list sites: %s", exc)
            raise AdapterError(
                f"could not verify UniFi site={site!r}",
                adapter_id="unifi",
            ) from exc
        rows = resp.get("data") if isinstance(resp, dict) else None
        site_names = (
            {r.get("name") for r in rows if isinstance(r, dict)}
            if isinstance(rows, list)
            else set()
        )
        if site not in site_names:
            # Mirror the service-layer contract: don't leak that the
            # site exists on some *other* controller — just "not found".
            raise AdapterError(
                f"UniFi site not found on this controller: {site!r}",
                adapter_id="unifi",
            )

    # ────────────────────────────────────────────────────────────────
    # Required abstract methods
    # ────────────────────────────────────────────────────────────────

    async def connect(self) -> bool:
        """Connect and authenticate with the UniFi controller."""
        try:
            ok = await self._api.login()
            self._connected = bool(ok)
            if ok:
                logger.info(
                    "Connected to UniFi controller at %s (mode=%s)",
                    self.host,
                    "unifi_os" if self._api.is_unifi_os else "classic",
                )
            return bool(ok)
        except AdapterError:
            # Network failure / breaker-open are typed (UniFiConnectionError ->
            # AdapterConnectionError, UniFiAuthError -> AdapterAuthenticationError).
            # Propagate so the central handler maps them (-> 502) instead of
            # swallowing them as ``return False`` — which left the caller with a
            # silently non-connected adapter that looked "connected" against an
            # unreachable controller and only failed on first use.
            self._connected = False
            raise
        except Exception as exc:
            logger.error("Failed to connect to UniFi at %s: %s", self.host, exc)
            self._connected = False
            return False

    async def disconnect(self) -> None:
        """Disconnect from the UniFi controller and close the client.

        Pool-managed adapters short-circuit: the unifi endpoints
        wrap calls in ``finally: await adapter.disconnect()`` for
        symmetry, but when the adapter came from
        ``adapter_pool.get_or_create_shared`` we MUST NOT close it —
        the next request would re-login and exhaust the UniFi OS
        Identity rate-limit. The pool's cleanup loop calls the real
        ``_destroy_connection`` path when actually evicting.
        """
        if getattr(self, "_pool_managed", False):
            return
        with contextlib.suppress(Exception):
            await self._api.aclose()
        self._connected = False

    async def test_connection(self) -> AdapterResult:
        """Test connection to the UniFi controller."""
        try:
            ok = await self._api.login()
            if not ok:
                return AdapterResult.fail("Authentication failed")
            info_result = await self._api.get_sysinfo()
            data = info_result.get("data", [{}])
            info = data[0] if isinstance(data, list) and data else (data or {})
            try:
                await self._api.logout()
            except Exception:
                pass
            return AdapterResult.ok(
                data=redact_secrets(
                    {
                        "version": info.get("version", "unknown"),
                        "hostname": info.get("hostname", self.host),
                        "model": info.get("ubnt_device_type", "UniFi Controller"),
                        "is_unifi_os": self._api.is_unifi_os,
                    }
                ),
                message="Connection successful",
            )
        except Exception as exc:
            return AdapterResult.fail(f"Connection failed: {exc}")

    async def discover_devices(self) -> list[DiscoveredDevice]:
        """Discover all devices managed by the current site."""
        try:
            result = await self._api.get_devices()
            devices: list[DiscoveredDevice] = []
            for dev in result.get("data", []) or []:
                devices.append(self._to_discovered_device(dev))
            return devices
        except Exception as exc:
            logger.error("UniFi device discovery failed: %s", exc)
            return []

    async def get_device_status(self, device_id: str) -> dict[str, Any]:
        """Get device status by MAC address."""
        try:
            mac = validate_mac(device_id)
            result = await self._api.get_device(mac)
            data = result.get("data", [])
            if isinstance(data, list) and data:
                dev = data[0]
                return redact_secrets(
                    {
                        "mac": dev.get("mac"),
                        "name": dev.get("name", dev.get("model", "Unknown")),
                        "model": dev.get("model"),
                        "status": "online" if dev.get("state") == 1 else "offline",
                        "uptime": dev.get("uptime"),
                        "firmware": dev.get("version"),
                        "ip": dev.get("ip"),
                        "clients": dev.get("num_sta", 0),
                        "cpu_usage": (dev.get("system-stats") or {}).get("cpu"),
                        "mem_usage": (dev.get("system-stats") or {}).get("mem"),
                    }
                )
            return {}
        except AdapterError:
            raise
        except Exception as exc:
            logger.error("Failed to get device status %s: %s", device_id, exc)
            return {}

    async def get_device_info(self, device_id: str) -> DiscoveredDevice | None:
        """Get device info by MAC address."""
        try:
            mac = validate_mac(device_id)
            result = await self._api.get_device(mac)
            data = result.get("data", [])
            if isinstance(data, list) and data:
                return self._to_discovered_device(data[0])
            return None
        except AdapterError:
            raise
        except Exception:
            return None

    # ════════════════════════════════════════════════════════════════
    # Read paths (18 methods) — all redacted via :func:`redact_secrets`
    # ════════════════════════════════════════════════════════════════

    # ── Sites ───────────────────────────────────────────────────────

    async def list_sites(self) -> list[dict[str, Any]]:
        """Enumerate every site visible to the current account.

        Result rows are the raw controller payload, redacted so any
        embedded admin passwords / API tokens in site config are
        stripped before they reach the API consumer.
        """
        result = await self._api.get_sites()
        rows = result.get("data", []) if isinstance(result, dict) else []
        return [_redact(row) for row in (rows or [])]

    async def get_site_health(self, site: str) -> list[dict[str, Any]]:
        """Per-subsystem health summary (WAN, LAN, WLAN, VPN, WWW)."""
        site = validate_site(site)
        self._api.site = site
        result = await self._api.get_health()
        return [_redact(r) for r in (result.get("data", []) or [])]

    # ── Devices ─────────────────────────────────────────────────────

    async def list_devices(self, site: str) -> list[dict[str, Any]]:
        """List every adopted device at *site*."""
        site = validate_site(site)
        await self._verify_site_owned(site)
        self._api.site = site
        result = await self._api.get_devices()
        return [_redact(r) for r in (result.get("data", []) or [])]

    async def get_device(self, site: str, mac: str) -> dict[str, Any] | None:
        """Look up a single device by MAC address.

        UniFi OS 10.x changed the not-found shape: instead of returning
        ``{"data": []}`` (which the historical empty-rows branch handled),
        the controller now raises ``api.err.UnknownDevice`` as an HTTP
        400. Catch that one specific error and return None so the
        endpoint layer can surface a clean 404.
        """
        from app.adapters.unifi.exceptions import UniFiAPIError

        site = validate_site(site)
        mac = validate_mac(mac)
        await self._verify_site_owned(site)
        self._api.site = site
        try:
            result = await self._api.get_device(mac)
        except UniFiAPIError as exc:
            if (exc.meta_msg or "").startswith("api.err.UnknownDevice"):
                return None
            raise
        rows = result.get("data", []) or []
        if not rows:
            return None
        return _redact(rows[0])

    async def list_clients(self, site: str) -> list[dict[str, Any]]:
        """List every connected (active) client at *site*."""
        site = validate_site(site)
        await self._verify_site_owned(site)
        self._api.site = site
        result = await self._api.get_clients()
        return [_redact(r) for r in (result.get("data", []) or [])]

    async def get_client(self, site: str, mac: str) -> dict[str, Any] | None:
        """Look up a single client by MAC address.

        Same UniFi 10.x not-found shape as :meth:`get_device`: a missing
        MAC raises ``api.err.UnknownUser`` as HTTP 400 rather than the
        legacy empty-data envelope. Catch and return None.
        """
        from app.adapters.unifi.exceptions import UniFiAPIError

        site = validate_site(site)
        mac = validate_mac(mac)
        await self._verify_site_owned(site)
        self._api.site = site
        try:
            result = await self._api.get_client(mac)
        except UniFiAPIError as exc:
            if (exc.meta_msg or "").startswith("api.err.UnknownUser"):
                return None
            raise
        rows = result.get("data", []) or []
        if not rows:
            return None
        return _redact(rows[0])

    async def list_port_overrides(
        self,
        site: str,
        device_mac: str,
    ) -> list[dict[str, Any]]:
        """Return per-port override configuration for a switch.

        The override list is embedded inside the device record under
        ``port_overrides``; this helper digs it out so callers don't
        need to know the UniFi response shape.
        """
        device = await self.get_device(site, device_mac)
        if device is None:
            return []
        overrides = device.get("port_overrides", []) or []
        return [_redact(r) for r in overrides]

    # ── Networks ────────────────────────────────────────────────────

    async def list_networks(self, site: str) -> list[dict[str, Any]]:
        """List networks (VLANs / subnets / DHCP scopes)."""
        site = validate_site(site)
        await self._verify_site_owned(site)
        self._api.site = site
        result = await self._api.get_networks()
        return [_redact(r) for r in (result.get("data", []) or [])]

    async def get_network(self, site: str, network_id: str) -> dict[str, Any] | None:
        """Look up a single network by Mongo ObjectID."""
        site = validate_site(site)
        network_id = validate_object_id(network_id, label="network_id")
        await self._verify_site_owned(site)
        self._api.site = site
        result = await self._api.get_network(network_id)
        rows = result.get("data", []) or []
        if not rows:
            return None
        return _redact(rows[0])

    # ── WLANs ───────────────────────────────────────────────────────

    async def list_wlans(self, site: str) -> list[dict[str, Any]]:
        """List wireless networks. PSK / RADIUS secrets are redacted."""
        site = validate_site(site)
        await self._verify_site_owned(site)
        self._api.site = site
        result = await self._api.get_wlans()
        return [_redact(r) for r in (result.get("data", []) or [])]

    async def get_wlan(self, site: str, wlan_id: str) -> dict[str, Any] | None:
        """Look up a single WLAN. PSK / RADIUS secrets are redacted."""
        site = validate_site(site)
        wlan_id = validate_object_id(wlan_id, label="wlan_id")
        await self._verify_site_owned(site)
        self._api.site = site
        result = await self._api.get_wlan(wlan_id)
        rows = result.get("data", []) or []
        if not rows:
            return None
        return _redact(rows[0])

    # ── Firewall ────────────────────────────────────────────────────

    async def list_firewall_rules(self, site: str) -> list[dict[str, Any]]:
        """List firewall rules (all chains)."""
        site = validate_site(site)
        self._api.site = site
        result = await self._api.get_firewall_rules()
        return [_redact(r) for r in (result.get("data", []) or [])]

    async def list_firewall_groups(self, site: str) -> list[dict[str, Any]]:
        """List firewall address / port groups."""
        site = validate_site(site)
        self._api.site = site
        result = await self._api.get_firewall_groups()
        return [_redact(r) for r in (result.get("data", []) or [])]

    # ── Port forwarding ─────────────────────────────────────────────

    async def list_port_forwards(self, site: str) -> list[dict[str, Any]]:
        """List port-forwarding rules (NAT DNAT entries)."""
        site = validate_site(site)
        self._api.site = site
        result = await self._api.get_port_forwards()
        return [_redact(r) for r in (result.get("data", []) or [])]

    # ── VPN ─────────────────────────────────────────────────────────

    async def list_radius_users(self, site: str) -> list[dict[str, Any]]:
        """List RADIUS user accounts. Per-user secret is redacted."""
        site = validate_site(site)
        self._api.site = site
        result = await self._api.get_radius_users()
        return [_redact(r) for r in (result.get("data", []) or [])]

    async def list_vpn_clients(self, site: str) -> list[dict[str, Any]]:
        """List currently-connected remote-user VPN sessions."""
        site = validate_site(site)
        self._api.site = site
        result = await self._api.get_vpn_clients()
        return [_redact(r) for r in (result.get("data", []) or [])]

    # ── System ──────────────────────────────────────────────────────

    async def get_controller_info(self) -> dict[str, Any]:
        """Return the controller version / hostname / mode summary."""
        result = await self._api.get_sysinfo()
        data = result.get("data", [{}])
        info = data[0] if isinstance(data, list) and data else (data or {})
        return _redact(
            {
                "version": info.get("version"),
                "hostname": info.get("hostname"),
                "build": info.get("build"),
                "ubnt_device_type": info.get("ubnt_device_type"),
                "is_unifi_os": self._api.is_unifi_os,
                "data_retention_time_in_hours_for_5minutes_scale": info.get(
                    "data_retention_time_in_hours_for_5minutes_scale"
                ),
                "timezone": info.get("timezone"),
            }
        )

    async def get_sysinfo(self, site: str) -> dict[str, Any]:
        """Site-scoped sysinfo block (separate from controller-level info)."""
        site = validate_site(site)
        self._api.site = site
        result = await self._api.get_sysinfo()
        data = result.get("data", [{}])
        info = data[0] if isinstance(data, list) and data else (data or {})
        return _redact(info)

    async def list_alerts(self, site: str, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most-recent active alarms."""
        site = validate_site(site)
        self._api.site = site
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 50
        if not (1 <= limit <= 1000):
            limit = 50
        result = await self._api.get_alerts(limit=limit)
        return [_redact(r) for r in (result.get("data", []) or [])]

    # ════════════════════════════════════════════════════════════════
    # Write paths (8 methods, all dual-gated + audit-logged)
    # ════════════════════════════════════════════════════════════════

    async def restart_device(
        self,
        site: str,
        mac: str,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Reboot a device (switch / AP / gateway) by MAC address."""
        _enforce_read_only(force=force, action=f"restart_device({mac})")
        site = validate_site(site)
        mac = validate_mac(mac)
        await self._verify_site_owned(site)
        _write_audit(
            action="restart_device",
            site=site,
            device=mac,
            forced=force,
        )
        self._api.site = site
        result = await self._api.cmd_devmgr({"cmd": "restart", "mac": mac})
        return _redact(result)

    async def update_port_override(
        self,
        site: str,
        device_mac: str,
        port_idx: int,
        profile_id: str,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Apply a port profile to a single switch port.

        UniFi stores port overrides as a list on the device record;
        we read the current list, merge / replace the entry for
        ``port_idx`` with the new profile, and PUT the device record
        back so untouched overrides survive the write.
        """
        _enforce_read_only(
            force=force,
            action=f"update_port_override({device_mac} port={port_idx})",
        )
        site = validate_site(site)
        mac = validate_mac(device_mac)
        idx = validate_port_idx(port_idx)
        profile_id = validate_object_id(profile_id, label="profile_id")
        await self._verify_site_owned(site)
        _write_audit(
            action="update_port_override",
            site=site,
            device=mac,
            forced=force,
            extra={"port_idx": idx, "profile_id": profile_id},
        )

        self._api.site = site

        # Read-modify-write under the per-device lock (carry forward all other
        # port_overrides; UniFi reverts any entry we drop to default).
        def _mutate(device: dict[str, Any]) -> dict[str, Any]:
            overrides = list(device.get("port_overrides", []) or [])
            entry = next((o for o in overrides if o.get("port_idx") == idx), None)
            if entry is None:
                entry = {"port_idx": idx}
                overrides.append(entry)
            entry["portconf_id"] = profile_id
            return {"port_overrides": overrides}

        return _redact(await self._patch_device(mac, _mutate))

    async def set_port_poe(
        self,
        site: str,
        device_mac: str,
        port_idx: int,
        poe_mode: str,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Set PoE mode on a single switch port (auto / off / passive24 / passthrough).

        Implemented as a port-override write (the same mechanism the
        UniFi UI uses).
        """
        _enforce_read_only(
            force=force,
            action=f"set_port_poe({device_mac} port={port_idx} {poe_mode})",
        )
        site = validate_site(site)
        mac = validate_mac(device_mac)
        idx = validate_port_idx(port_idx)
        mode = validate_poe_mode(poe_mode)
        await self._verify_site_owned(site)
        _write_audit(
            action="set_port_poe",
            site=site,
            device=mac,
            forced=force,
            extra={"port_idx": idx, "poe_mode": mode},
        )

        self._api.site = site

        def _mutate(device: dict[str, Any]) -> dict[str, Any]:
            overrides = list(device.get("port_overrides", []) or [])
            entry = next((o for o in overrides if o.get("port_idx") == idx), None)
            if entry is None:
                entry = {"port_idx": idx}
                overrides.append(entry)
            entry["poe_mode"] = mode
            return {"port_overrides": overrides}

        return _redact(await self._patch_device(mac, _mutate))

    async def update_wlan_password(
        self,
        site: str,
        wlan_id: str,
        new_psk: str,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Rotate the WPA-PSK on a wireless network.

        UniFi rejects PSKs shorter than 8 or longer than 63 chars
        (WPA2 spec). We validate here so the operator gets a clear
        error instead of an opaque controller 400.
        """
        _enforce_read_only(
            force=force,
            action=f"update_wlan_password({wlan_id})",
        )
        site = validate_site(site)
        wlan_id = validate_object_id(wlan_id, label="wlan_id")
        if not isinstance(new_psk, str) or not (8 <= len(new_psk) <= 63):
            raise AdapterError(
                "UniFi WPA-PSK must be 8..63 characters",
                adapter_id="unifi",
            )
        await self._verify_site_owned(site)
        _write_audit(
            action="update_wlan_password",
            site=site,
            device=None,
            forced=force,
            extra={"wlan_id": wlan_id},  # NB: PSK never logged
        )

        self._api.site = site
        result = await self._api.update_wlan(wlan_id, {"x_passphrase": new_psk})
        return _redact(result)

    async def enable_wlan(
        self,
        site: str,
        wlan_id: str,
        enabled: bool,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Toggle a wireless network on or off."""
        _enforce_read_only(
            force=force,
            action=f"enable_wlan({wlan_id}, enabled={enabled})",
        )
        site = validate_site(site)
        wlan_id = validate_object_id(wlan_id, label="wlan_id")
        await self._verify_site_owned(site)
        _write_audit(
            action="enable_wlan",
            site=site,
            device=None,
            forced=force,
            extra={"wlan_id": wlan_id, "enabled": bool(enabled)},
        )

        self._api.site = site
        result = await self._api.update_wlan(wlan_id, {"enabled": bool(enabled)})
        return _redact(result)

    async def block_client(
        self,
        site: str,
        client_mac: str,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Block a client from associating with any AP/network."""
        _enforce_read_only(
            force=force,
            action=f"block_client({client_mac})",
        )
        site = validate_site(site)
        mac = validate_mac(client_mac)
        await self._verify_site_owned(site)
        _write_audit(
            action="block_client",
            site=site,
            device=mac,
            forced=force,
        )

        self._api.site = site
        result = await self._api.cmd_stamgr({"cmd": "block-sta", "mac": mac})
        return _redact(result)

    async def unblock_client(
        self,
        site: str,
        client_mac: str,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Reverse an earlier :meth:`block_client` call."""
        _enforce_read_only(
            force=force,
            action=f"unblock_client({client_mac})",
        )
        site = validate_site(site)
        mac = validate_mac(client_mac)
        await self._verify_site_owned(site)
        _write_audit(
            action="unblock_client",
            site=site,
            device=mac,
            forced=force,
        )

        self._api.site = site
        result = await self._api.cmd_stamgr({"cmd": "unblock-sta", "mac": mac})
        return _redact(result)

    async def forget_client(
        self,
        site: str,
        client_mac: str,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Clear a client record from the controller.

        Different from blocking: this removes the historical entry
        (DHCP fingerprint, alias, group membership) so the client
        re-appears as brand-new on its next association.
        """
        _enforce_read_only(
            force=force,
            action=f"forget_client({client_mac})",
        )
        site = validate_site(site)
        mac = validate_mac(client_mac)
        await self._verify_site_owned(site)
        _write_audit(
            action="forget_client",
            site=site,
            device=mac,
            forced=force,
        )

        self._api.site = site
        result = await self._api.cmd_stamgr({"cmd": "forget-sta", "macs": [mac]})
        return _redact(result)

    async def disable_device(
        self,
        site: str,
        device_mac: str,
        disabled: bool,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Admin-disable a device without removing it from the controller.

        A disabled AP / switch keeps its config in the controller DB
        but stops broadcasting / forwarding. This is the soft-off
        equivalent of unplugging the cable.
        """
        _enforce_read_only(
            force=force,
            action=f"disable_device({device_mac}, disabled={disabled})",
        )
        site = validate_site(site)
        mac = validate_mac(device_mac)
        await self._verify_site_owned(site)
        _write_audit(
            action="disable_device",
            site=site,
            device=mac,
            forced=force,
            extra={"disabled": bool(disabled)},
        )

        self._api.site = site
        # Under the per-device lock so a disable can't clobber a concurrent
        # port_overrides write on the same device (both PUT the whole record).
        return _redact(await self._patch_device(mac, lambda _device: {"disabled": bool(disabled)}))

    # ════════════════════════════════════════════════════════════════
    # Expanded surface (Omada-parity) — shared gated helpers
    # ════════════════════════════════════════════════════════════════
    # Every read funnels through _do_read (site-validate → tenancy →
    # redact); every gated write through _do_write (read-only gate →
    # site-validate → tenancy → structured audit → live call → redact).
    # Caller-supplied IDs are validated by the public method first.

    async def _do_read(self, site: str, client_method: str, *args: Any, unwrap: bool = True) -> Any:
        site = validate_site(site)
        await self._verify_site_owned(site)
        self._api.site = site
        result = await getattr(self._api, client_method)(*args)
        data = result.get("data") if (unwrap and isinstance(result, dict)) else result
        return _redact(data)

    async def _do_write(
        self,
        *,
        site: str,
        action: str,
        client_call: Any,
        force: bool,
        audit_extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _enforce_read_only(force=force, action=action)
        site = validate_site(site)
        await self._verify_site_owned(site)
        _write_audit(
            action=action.split("(", 1)[0],
            site=site,
            device=None,
            forced=force,
            extra=audit_extra or {},
        )
        self._api.site = site
        result = await client_call(self._api)
        return _redact(result)

    # ════════════════════════════════════════════════════════════════
    # v2 modern surface — Zone-Based Firewall + policy engine
    # ════════════════════════════════════════════════════════════════

    # ── Firewall policies (ZBF) ──
    async def list_firewall_policies(self, site: str) -> Any:
        return await self._do_read(site, "get_firewall_policies")

    async def create_firewall_policy(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_firewall_policy",
            client_call=lambda c: c.create_firewall_policy(payload),
            force=force,
        )

    async def update_firewall_policy(
        self, site: str, policy_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        policy_id = validate_object_id(policy_id, label="policy_id")
        return await self._do_write(
            site=site,
            action=f"update_firewall_policy({policy_id})",
            client_call=lambda c: c.update_firewall_policy(policy_id, payload),
            force=force,
            audit_extra={"policy_id": policy_id},
        )

    async def delete_firewall_policy(
        self, site: str, policy_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        policy_id = validate_object_id(policy_id, label="policy_id")
        return await self._do_write(
            site=site,
            action=f"delete_firewall_policy({policy_id})",
            client_call=lambda c: c.delete_firewall_policy(policy_id),
            force=force,
            audit_extra={"policy_id": policy_id},
        )

    # ── Firewall zones (ZBF) ──
    async def list_firewall_zones(self, site: str) -> Any:
        return await self._do_read(site, "get_firewall_zones")

    async def get_firewall_zone_matrix(self, site: str) -> Any:
        return await self._do_read(site, "get_firewall_zone_matrix")

    async def create_firewall_zone(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_firewall_zone",
            client_call=lambda c: c.create_firewall_zone(payload),
            force=force,
        )

    async def update_firewall_zone(
        self, site: str, zone_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        zone_id = validate_object_id(zone_id, label="zone_id")
        return await self._do_write(
            site=site,
            action=f"update_firewall_zone({zone_id})",
            client_call=lambda c: c.update_firewall_zone(zone_id, payload),
            force=force,
            audit_extra={"zone_id": zone_id},
        )

    async def delete_firewall_zone(
        self, site: str, zone_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        zone_id = validate_object_id(zone_id, label="zone_id")
        return await self._do_write(
            site=site,
            action=f"delete_firewall_zone({zone_id})",
            client_call=lambda c: c.delete_firewall_zone(zone_id),
            force=force,
            audit_extra={"zone_id": zone_id},
        )

    # ── NAT rules (v2) ──
    async def list_nat_rules(self, site: str) -> Any:
        return await self._do_read(site, "get_nat_rules")

    async def create_nat_rule(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_nat_rule",
            client_call=lambda c: c.create_nat_rule(payload),
            force=force,
        )

    async def update_nat_rule(
        self, site: str, rule_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        rule_id = validate_object_id(rule_id, label="rule_id")
        return await self._do_write(
            site=site,
            action=f"update_nat_rule({rule_id})",
            client_call=lambda c: c.update_nat_rule(rule_id, payload),
            force=force,
            audit_extra={"rule_id": rule_id},
        )

    async def delete_nat_rule(
        self, site: str, rule_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        rule_id = validate_object_id(rule_id, label="rule_id")
        return await self._do_write(
            site=site,
            action=f"delete_nat_rule({rule_id})",
            client_call=lambda c: c.delete_nat_rule(rule_id),
            force=force,
            audit_extra={"rule_id": rule_id},
        )

    # ── QoS rules (v2) ──
    async def list_qos_rules(self, site: str) -> Any:
        return await self._do_read(site, "get_qos_rules")

    async def create_qos_rule(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_qos_rule",
            client_call=lambda c: c.create_qos_rule(payload),
            force=force,
        )

    async def update_qos_rule(
        self, site: str, rule_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        rule_id = validate_object_id(rule_id, label="rule_id")
        return await self._do_write(
            site=site,
            action=f"update_qos_rule({rule_id})",
            client_call=lambda c: c.update_qos_rule(rule_id, payload),
            force=force,
            audit_extra={"rule_id": rule_id},
        )

    async def delete_qos_rule(
        self, site: str, rule_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        rule_id = validate_object_id(rule_id, label="rule_id")
        return await self._do_write(
            site=site,
            action=f"delete_qos_rule({rule_id})",
            client_call=lambda c: c.delete_qos_rule(rule_id),
            force=force,
            audit_extra={"rule_id": rule_id},
        )

    # ── Traffic rules (v2) ──
    async def list_traffic_rules(self, site: str) -> Any:
        return await self._do_read(site, "get_traffic_rules")

    async def create_traffic_rule(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_traffic_rule",
            client_call=lambda c: c.create_traffic_rule(payload),
            force=force,
        )

    async def update_traffic_rule(
        self, site: str, rule_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        rule_id = validate_object_id(rule_id, label="rule_id")
        return await self._do_write(
            site=site,
            action=f"update_traffic_rule({rule_id})",
            client_call=lambda c: c.update_traffic_rule(rule_id, payload),
            force=force,
            audit_extra={"rule_id": rule_id},
        )

    async def delete_traffic_rule(
        self, site: str, rule_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        rule_id = validate_object_id(rule_id, label="rule_id")
        return await self._do_write(
            site=site,
            action=f"delete_traffic_rule({rule_id})",
            client_call=lambda c: c.delete_traffic_rule(rule_id),
            force=force,
            audit_extra={"rule_id": rule_id},
        )

    # ── Traffic routes (v2) ──
    async def list_traffic_routes(self, site: str) -> Any:
        return await self._do_read(site, "get_traffic_routes")

    async def create_traffic_route(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_traffic_route",
            client_call=lambda c: c.create_traffic_route(payload),
            force=force,
        )

    async def update_traffic_route(
        self, site: str, route_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        route_id = validate_object_id(route_id, label="route_id")
        return await self._do_write(
            site=site,
            action=f"update_traffic_route({route_id})",
            client_call=lambda c: c.update_traffic_route(route_id, payload),
            force=force,
            audit_extra={"route_id": route_id},
        )

    async def delete_traffic_route(
        self, site: str, route_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        route_id = validate_object_id(route_id, label="route_id")
        return await self._do_write(
            site=site,
            action=f"delete_traffic_route({route_id})",
            client_call=lambda c: c.delete_traffic_route(route_id),
            force=force,
            audit_extra={"route_id": route_id},
        )

    # ── Static DNS records (v2) ──
    async def list_static_dns(self, site: str) -> Any:
        return await self._do_read(site, "get_static_dns")

    async def create_static_dns(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_static_dns",
            client_call=lambda c: c.create_static_dns(payload),
            force=force,
        )

    async def update_static_dns(
        self, site: str, record_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        record_id = validate_object_id(record_id, label="record_id")
        return await self._do_write(
            site=site,
            action=f"update_static_dns({record_id})",
            client_call=lambda c: c.update_static_dns(record_id, payload),
            force=force,
            audit_extra={"record_id": record_id},
        )

    async def delete_static_dns(
        self, site: str, record_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        record_id = validate_object_id(record_id, label="record_id")
        return await self._do_write(
            site=site,
            action=f"delete_static_dns({record_id})",
            client_call=lambda c: c.delete_static_dns(record_id),
            force=force,
            audit_extra={"record_id": record_id},
        )

    # ── Read-only v2 surfaces ──
    async def get_topology(self, site: str) -> Any:
        return await self._do_read(site, "get_topology", unwrap=False)

    async def list_ap_groups(self, site: str) -> Any:
        return await self._do_read(site, "get_ap_groups")

    async def get_content_filtering(self, site: str) -> Any:
        return await self._do_read(site, "get_content_filtering")

    # ════════════════════════════════════════════════════════════════
    # v1 classic surface completion — full CRUD across every domain
    # ════════════════════════════════════════════════════════════════

    # ── WLAN / SSID lifecycle ──
    async def create_wlan(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_wlan",
            client_call=lambda c: c.create_wlan(payload),
            force=force,
        )

    async def delete_ssid(self, site: str, wlan_id: str, *, force: bool = False) -> dict[str, Any]:
        wlan_id = validate_object_id(wlan_id, label="wlan_id")
        return await self._do_write(
            site=site,
            action=f"delete_ssid({wlan_id})",
            client_call=lambda c: c.delete_wlan(wlan_id),
            force=force,
            audit_extra={"wlan_id": wlan_id},
        )

    async def update_wlan(
        self, site: str, wlan_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        wlan_id = validate_object_id(wlan_id, label="wlan_id")
        return await self._do_write(
            site=site,
            action=f"update_wlan({wlan_id})",
            client_call=lambda c: c.update_wlan(wlan_id, payload),
            force=force,
            audit_extra={"wlan_id": wlan_id},
        )

    # ── Network / VLAN update + delete ──
    async def update_network(
        self, site: str, network_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        network_id = validate_object_id(network_id, label="network_id")
        return await self._do_write(
            site=site,
            action=f"update_network({network_id})",
            client_call=lambda c: c.update_network(network_id, payload),
            force=force,
            audit_extra={"network_id": network_id},
        )

    async def delete_network(
        self, site: str, network_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        network_id = validate_object_id(network_id, label="network_id")
        return await self._do_write(
            site=site,
            action=f"delete_network({network_id})",
            client_call=lambda c: c.delete_network(network_id),
            force=force,
            audit_extra={"network_id": network_id},
        )

    # ── Firewall groups (v1) ──
    async def create_firewall_group(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_firewall_group",
            client_call=lambda c: c.create_firewall_group(payload),
            force=force,
        )

    async def update_firewall_group(
        self, site: str, group_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        group_id = validate_object_id(group_id, label="group_id")
        return await self._do_write(
            site=site,
            action=f"update_firewall_group({group_id})",
            client_call=lambda c: c.update_firewall_group(group_id, payload),
            force=force,
            audit_extra={"group_id": group_id},
        )

    async def delete_firewall_group(
        self, site: str, group_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        group_id = validate_object_id(group_id, label="group_id")
        return await self._do_write(
            site=site,
            action=f"delete_firewall_group({group_id})",
            client_call=lambda c: c.delete_firewall_group(group_id),
            force=force,
            audit_extra={"group_id": group_id},
        )

    # ── Firewall rules (v1 legacy ruleset) ──
    async def create_firewall_rule(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_firewall_rule",
            client_call=lambda c: c.create_firewall_rule(payload),
            force=force,
        )

    async def update_firewall_rule(
        self, site: str, rule_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        rule_id = validate_object_id(rule_id, label="rule_id")
        return await self._do_write(
            site=site,
            action=f"update_firewall_rule({rule_id})",
            client_call=lambda c: c.update_firewall_rule(rule_id, payload),
            force=force,
            audit_extra={"rule_id": rule_id},
        )

    async def delete_firewall_rule(
        self, site: str, rule_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        rule_id = validate_object_id(rule_id, label="rule_id")
        return await self._do_write(
            site=site,
            action=f"delete_firewall_rule({rule_id})",
            client_call=lambda c: c.delete_firewall_rule(rule_id),
            force=force,
            audit_extra={"rule_id": rule_id},
        )

    # ── RADIUS accounts (v1) ──
    async def create_radius_user(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_radius_user",
            client_call=lambda c: c.create_radius_user(payload),
            force=force,
        )

    async def update_radius_user(
        self, site: str, account_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        account_id = validate_object_id(account_id, label="account_id")
        return await self._do_write(
            site=site,
            action=f"update_radius_user({account_id})",
            client_call=lambda c: c.update_radius_user(account_id, payload),
            force=force,
            audit_extra={"account_id": account_id},
        )

    async def delete_radius_user(
        self, site: str, account_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        account_id = validate_object_id(account_id, label="account_id")
        return await self._do_write(
            site=site,
            action=f"delete_radius_user({account_id})",
            client_call=lambda c: c.delete_radius_user(account_id),
            force=force,
            audit_extra={"account_id": account_id},
        )

    # ── Port profiles (v1) ──
    async def list_port_profiles(self, site: str) -> Any:
        return await self._do_read(site, "get_port_profiles")

    async def create_port_profile(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_port_profile",
            client_call=lambda c: c.create_port_profile(payload),
            force=force,
        )

    async def update_port_profile(
        self, site: str, profile_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        profile_id = validate_object_id(profile_id, label="profile_id")
        return await self._do_write(
            site=site,
            action=f"update_port_profile({profile_id})",
            client_call=lambda c: c.update_port_profile(profile_id, payload),
            force=force,
            audit_extra={"profile_id": profile_id},
        )

    async def delete_port_profile(
        self, site: str, profile_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        profile_id = validate_object_id(profile_id, label="profile_id")
        return await self._do_write(
            site=site,
            action=f"delete_port_profile({profile_id})",
            client_call=lambda c: c.delete_port_profile(profile_id),
            force=force,
            audit_extra={"profile_id": profile_id},
        )

    # ── User (bandwidth) groups (v1) ──
    async def list_user_groups(self, site: str) -> Any:
        return await self._do_read(site, "get_user_groups")

    async def create_user_group(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_user_group",
            client_call=lambda c: c.create_user_group(payload),
            force=force,
        )

    async def update_user_group(
        self, site: str, group_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        group_id = validate_object_id(group_id, label="group_id")
        return await self._do_write(
            site=site,
            action=f"update_user_group({group_id})",
            client_call=lambda c: c.update_user_group(group_id, payload),
            force=force,
            audit_extra={"group_id": group_id},
        )

    async def delete_user_group(
        self, site: str, group_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        group_id = validate_object_id(group_id, label="group_id")
        return await self._do_write(
            site=site,
            action=f"delete_user_group({group_id})",
            client_call=lambda c: c.delete_user_group(group_id),
            force=force,
            audit_extra={"group_id": group_id},
        )

    # ── DPI restriction groups (v1) ──
    async def list_dpi_apps(self, site: str) -> Any:
        return await self._do_read(site, "get_dpi_apps")

    async def create_dpi_app(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_dpi_app",
            client_call=lambda c: c.create_dpi_app(payload),
            force=force,
        )

    async def update_dpi_app(
        self, site: str, app_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        app_id = validate_object_id(app_id, label="app_id")
        return await self._do_write(
            site=site,
            action=f"update_dpi_app({app_id})",
            client_call=lambda c: c.update_dpi_app(app_id, payload),
            force=force,
            audit_extra={"app_id": app_id},
        )

    async def delete_dpi_app(
        self, site: str, app_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        app_id = validate_object_id(app_id, label="app_id")
        return await self._do_write(
            site=site,
            action=f"delete_dpi_app({app_id})",
            client_call=lambda c: c.delete_dpi_app(app_id),
            force=force,
            audit_extra={"app_id": app_id},
        )

    # ── Port forwards (v1) ──
    async def create_port_forward(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_port_forward",
            client_call=lambda c: c.create_port_forward(payload),
            force=force,
        )

    async def update_port_forward(
        self, site: str, fwd_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        fwd_id = validate_object_id(fwd_id, label="fwd_id")
        return await self._do_write(
            site=site,
            action=f"update_port_forward({fwd_id})",
            client_call=lambda c: c.update_port_forward(fwd_id, payload),
            force=force,
            audit_extra={"fwd_id": fwd_id},
        )

    async def delete_port_forward(
        self, site: str, fwd_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        fwd_id = validate_object_id(fwd_id, label="fwd_id")
        return await self._do_write(
            site=site,
            action=f"delete_port_forward({fwd_id})",
            client_call=lambda c: c.delete_port_forward(fwd_id),
            force=force,
            audit_extra={"fwd_id": fwd_id},
        )

    # ── Dynamic DNS (v1) ──
    async def list_dynamic_dns(self, site: str) -> Any:
        return await self._do_read(site, "get_dynamic_dns")

    async def create_dynamic_dns(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_dynamic_dns",
            client_call=lambda c: c.create_dynamic_dns(payload),
            force=force,
        )

    async def update_dynamic_dns(
        self, site: str, dyn_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        dyn_id = validate_object_id(dyn_id, label="dyn_id")
        return await self._do_write(
            site=site,
            action=f"update_dynamic_dns({dyn_id})",
            client_call=lambda c: c.update_dynamic_dns(dyn_id, payload),
            force=force,
            audit_extra={"dyn_id": dyn_id},
        )

    async def delete_dynamic_dns(
        self, site: str, dyn_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        dyn_id = validate_object_id(dyn_id, label="dyn_id")
        return await self._do_write(
            site=site,
            action=f"delete_dynamic_dns({dyn_id})",
            client_call=lambda c: c.delete_dynamic_dns(dyn_id),
            force=force,
            audit_extra={"dyn_id": dyn_id},
        )

    # ── Static routes (v1 routing) ──
    async def list_routing(self, site: str) -> Any:
        return await self._do_read(site, "get_routing")

    async def create_route(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_route",
            client_call=lambda c: c.create_routing(payload),
            force=force,
        )

    async def update_route(
        self, site: str, route_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        route_id = validate_object_id(route_id, label="route_id")
        return await self._do_write(
            site=site,
            action=f"update_route({route_id})",
            client_call=lambda c: c.update_routing(route_id, payload),
            force=force,
            audit_extra={"route_id": route_id},
        )

    async def delete_route(
        self, site: str, route_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        route_id = validate_object_id(route_id, label="route_id")
        return await self._do_write(
            site=site,
            action=f"delete_route({route_id})",
            client_call=lambda c: c.delete_routing(route_id),
            force=force,
            audit_extra={"route_id": route_id},
        )

    # ── Guest hotspot operators + vouchers (v1) ──
    async def list_hotspot_operators(self, site: str) -> Any:
        return await self._do_read(site, "get_hotspot_operators")

    async def create_hotspot_operator(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_hotspot_operator",
            client_call=lambda c: c.create_hotspot_operator(payload),
            force=force,
        )

    async def delete_hotspot_operator(
        self, site: str, op_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        op_id = validate_object_id(op_id, label="op_id")
        return await self._do_write(
            site=site,
            action=f"delete_hotspot_operator({op_id})",
            client_call=lambda c: c.delete_hotspot_operator(op_id),
            force=force,
            audit_extra={"op_id": op_id},
        )

    async def list_vouchers(self, site: str) -> Any:
        return await self._do_read(site, "get_vouchers")

    async def create_voucher(
        self,
        site: str,
        *,
        count: int = 1,
        expire_minutes: int = 60,
        quota: int = 1,
        note: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        cmd: dict[str, Any] = {
            "cmd": "create-voucher",
            "n": int(count),
            "expire": int(expire_minutes),
            "quota": int(quota),
        }
        if note:
            cmd["note"] = str(note)
        return await self._do_write(
            site=site,
            action="create_voucher",
            client_call=lambda c: c.cmd_hotspot(cmd),
            force=force,
            audit_extra={"count": int(count), "expire_minutes": int(expire_minutes)},
        )

    async def revoke_voucher(
        self, site: str, voucher_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        voucher_id = validate_object_id(voucher_id, label="voucher_id")
        return await self._do_write(
            site=site,
            action=f"revoke_voucher({voucher_id})",
            client_call=lambda c: c.cmd_hotspot({"cmd": "delete-voucher", "_id": voucher_id}),
            force=force,
            audit_extra={"voucher_id": voucher_id},
        )

    # ── Device commands (devmgr) — act on real hardware ──
    # NB: ``locate_device`` is the BaseAdapter override further down (legacy
    # wrappers) — it keeps the contract ``(mac, enabled)`` signature; the
    # rest below are reference ``(site, device_mac, *, force)`` writes.
    async def adopt_device(
        self, site: str, device_mac: str, *, force: bool = False
    ) -> dict[str, Any]:
        mac = validate_mac(device_mac)
        return await self._do_write(
            site=site,
            action=f"adopt_device({mac})",
            client_call=lambda c: c.cmd_devmgr({"cmd": "adopt", "mac": mac}),
            force=force,
            audit_extra={"mac": mac},
        )

    async def upgrade_device(
        self, site: str, device_mac: str, *, force: bool = False
    ) -> dict[str, Any]:
        mac = validate_mac(device_mac)
        return await self._do_write(
            site=site,
            action=f"upgrade_device({mac})",
            client_call=lambda c: c.cmd_devmgr({"cmd": "upgrade", "mac": mac}),
            force=force,
            audit_extra={"mac": mac},
        )

    async def force_provision_device(
        self, site: str, device_mac: str, *, force: bool = False
    ) -> dict[str, Any]:
        mac = validate_mac(device_mac)
        return await self._do_write(
            site=site,
            action=f"force_provision_device({mac})",
            client_call=lambda c: c.cmd_devmgr({"cmd": "force-provision", "mac": mac}),
            force=force,
            audit_extra={"mac": mac},
        )

    async def power_cycle_port(
        self, site: str, device_mac: str, port_idx: int, *, force: bool = False
    ) -> dict[str, Any]:
        """PoE power-cycle a single switch port (drops the powered device briefly)."""
        mac = validate_mac(device_mac)
        port_idx = validate_port_idx(port_idx)
        return await self._do_write(
            site=site,
            action=f"power_cycle_port({mac}, port={port_idx})",
            client_call=lambda c: c.cmd_devmgr(
                {"cmd": "power-cycle", "mac": mac, "port_idx": port_idx}
            ),
            force=force,
            audit_extra={"mac": mac, "port_idx": port_idx},
        )

    # ── Client command (stamgr) ──
    async def reconnect_client(
        self, site: str, client_mac: str, *, force: bool = False
    ) -> dict[str, Any]:
        """Kick a client so it re-associates (reconnect)."""
        mac = validate_mac(client_mac)
        return await self._do_write(
            site=site,
            action=f"reconnect_client({mac})",
            client_call=lambda c: c.cmd_stamgr({"cmd": "kick-sta", "mac": mac}),
            force=force,
            audit_extra={"mac": mac},
        )

    # ════════════════════════════════════════════════════════════════
    # Role completion — Switch ports/radios, AP WLAN groups, Gateway VPN
    # ════════════════════════════════════════════════════════════════

    _VPN_PURPOSES: ClassVar[tuple[str, ...]] = (
        "vpn-server",
        "vpn-client",
        "site-vpn",
        "remote-user-vpn",
    )

    async def _patch_device(self, mac: str, mutate: Any) -> dict[str, Any]:
        """Read the device record, apply ``mutate(device) -> {fields}`` and PUT
        it back, SERIALIZED per (controller, mac) so two concurrent edits to the
        same device can't lost-update each other. Read-modify-write so untouched
        sibling entries (other ports / radios) survive — UniFi reverts anything
        dropped from the list to default."""
        lock = await _get_device_write_lock(self._api.base_url, mac)
        async with lock:
            existing = await self._api.get_device(mac)
            rows = existing.get("data", []) or []
            if not rows:
                raise AdapterError(f"UniFi device not found: {mac}", adapter_id="unifi")
            device = rows[0]
            device_id = device.get("_id")
            if not device_id:
                raise AdapterError(f"UniFi device {mac} is missing _id", adapter_id="unifi")
            return await self._api.update_device(device_id, mutate(device))

    # ── AP radios (channel / tx-power / band-width) ──
    async def update_radio(
        self,
        site: str,
        device_mac: str,
        radio: str,
        *,
        channel: int | str | None = None,
        tx_power_mode: str | None = None,
        tx_power: int | None = None,
        ht: int | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """Tune one radio on an AP (``radio`` ∈ ng | na | 6e). UniFi keeps radio
        config in the device ``radio_table``; merge by radio name + PUT."""
        _enforce_read_only(force=force, action=f"update_radio({device_mac}/{radio})")
        site = validate_site(site)
        mac = validate_mac(device_mac)
        await self._verify_site_owned(site)
        _write_audit(
            action="update_radio", site=site, device=mac, forced=force, extra={"radio": radio}
        )
        self._api.site = site

        def _mutate(device: dict[str, Any]) -> dict[str, Any]:
            table = list(device.get("radio_table", []) or [])
            entry = next((r for r in table if r.get("radio") == radio), None)
            if entry is None:
                entry = {"radio": radio}
                table.append(entry)
            if channel is not None:
                entry["channel"] = channel
            if tx_power_mode is not None:
                entry["tx_power_mode"] = tx_power_mode
            if tx_power is not None:
                entry["tx_power"] = int(tx_power)
            if ht is not None:
                entry["ht"] = int(ht)
            return {"radio_table": table}

        return _redact(await self._patch_device(mac, _mutate))

    # ── Switch port advanced (STP / storm-control / op-mode / aggregation / isolation) ──
    async def update_switch_port(
        self,
        site: str,
        device_mac: str,
        port_idx: int,
        settings: dict[str, Any],
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Merge arbitrary advanced per-port settings (stp_port_mode,
        stormctrl_*_enabled / *_rate, op_mode, aggregate_num_ports, isolation,
        port_security_enabled, full_duplex, speed, …) into the port_override."""
        _enforce_read_only(force=force, action=f"update_switch_port({device_mac} port={port_idx})")
        site = validate_site(site)
        mac = validate_mac(device_mac)
        idx = validate_port_idx(port_idx)
        await self._verify_site_owned(site)
        if not isinstance(settings, dict) or not settings:
            raise AdapterError(
                "update_switch_port requires a non-empty settings dict", adapter_id="unifi"
            )
        clean = {k: v for k, v in settings.items() if k not in {"port_idx", "_id"}}
        # Validate any object-id-bearing override field (portconf_id /
        # native_networkconf_id / *_ids). update_switch_port takes a free-form
        # settings dict, so a bogus/forged id would otherwise land verbatim in
        # the device record (the dedicated profile path validates it). (audit #3 F2)
        for _k, _v in clean.items():
            if _k.endswith("_id") and isinstance(_v, str) and _v:
                validate_object_id(_v, label=_k)
            elif _k.endswith("_ids") and isinstance(_v, list):
                for _item in _v:
                    if isinstance(_item, str) and _item:
                        validate_object_id(_item, label=_k)
        _write_audit(
            action="update_switch_port",
            site=site,
            device=mac,
            forced=force,
            extra={"port_idx": idx, "fields": sorted(clean)},
        )
        self._api.site = site

        def _mutate(device: dict[str, Any]) -> dict[str, Any]:
            overrides = list(device.get("port_overrides", []) or [])
            entry = next((o for o in overrides if o.get("port_idx") == idx), None)
            if entry is None:
                entry = {"port_idx": idx}
                overrides.append(entry)
            entry.update(clean)
            return {"port_overrides": overrides}

        return _redact(await self._patch_device(mac, _mutate))

    # ── AP WLAN groups ──
    async def list_wlan_groups(self, site: str) -> Any:
        return await self._do_read(site, "get_wlan_groups")

    async def create_wlan_group(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_wlan_group",
            client_call=lambda c: c.create_wlan_group(payload),
            force=force,
        )

    async def update_wlan_group(
        self, site: str, group_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        group_id = validate_object_id(group_id, label="group_id")
        return await self._do_write(
            site=site,
            action=f"update_wlan_group({group_id})",
            client_call=lambda c: c.update_wlan_group(group_id, payload),
            force=force,
            audit_extra={"group_id": group_id},
        )

    async def delete_wlan_group(
        self, site: str, group_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        group_id = validate_object_id(group_id, label="group_id")
        return await self._do_write(
            site=site,
            action=f"delete_wlan_group({group_id})",
            client_call=lambda c: c.delete_wlan_group(group_id),
            force=force,
            audit_extra={"group_id": group_id},
        )

    # ── Gateway VPN networks (server / client / site-to-site / remote-user) ──
    async def list_vpn_networks(self, site: str) -> Any:
        nets = await self._do_read(site, "get_networks")
        if isinstance(nets, list):
            return [n for n in nets if n.get("purpose") in self._VPN_PURPOSES]
        return nets

    async def create_vpn(
        self, site: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        return await self._do_write(
            site=site,
            action="create_vpn",
            client_call=lambda c: c.create_network(payload),
            force=force,
        )

    async def update_vpn(
        self, site: str, network_id: str, payload: dict[str, Any], *, force: bool = False
    ) -> dict[str, Any]:
        network_id = validate_object_id(network_id, label="network_id")
        return await self._do_write(
            site=site,
            action=f"update_vpn({network_id})",
            client_call=lambda c: c.update_network(network_id, payload),
            force=force,
            audit_extra={"network_id": network_id},
        )

    async def delete_vpn(
        self, site: str, network_id: str, *, force: bool = False
    ) -> dict[str, Any]:
        network_id = validate_object_id(network_id, label="network_id")
        return await self._do_write(
            site=site,
            action=f"delete_vpn({network_id})",
            client_call=lambda c: c.delete_network(network_id),
            force=force,
            audit_extra={"network_id": network_id},
        )

    # ── Role-focused reads (radio / switch-port management surfaces) ──
    async def list_radios(self, site: str) -> Any:
        """APs + their ``radio_table`` (the AP RF management read)."""
        site = validate_site(site)
        await self._verify_site_owned(site)
        self._api.site = site
        devices = (await self._api.get_devices()).get("data", []) or []
        out = [
            {
                "mac": d.get("mac"),
                "name": d.get("name") or d.get("model"),
                "model": d.get("model"),
                "type": d.get("type"),
                "radio_table": d.get("radio_table", []),
                "radio_table_stats": d.get("radio_table_stats", []),
            }
            for d in devices
            if d.get("type") == "uap" or d.get("radio_table")
        ]
        return _redact(out)

    async def list_switches(self, site: str) -> Any:
        """Switches + their ``port_table`` (live) and ``port_overrides`` (config)."""
        site = validate_site(site)
        await self._verify_site_owned(site)
        self._api.site = site
        devices = (await self._api.get_devices()).get("data", []) or []
        out = [
            {
                "mac": d.get("mac"),
                "name": d.get("name") or d.get("model"),
                "model": d.get("model"),
                "type": d.get("type"),
                "port_table": d.get("port_table", []),
                "port_overrides": d.get("port_overrides", []),
            }
            for d in devices
            if d.get("type") == "usw" or d.get("port_table")
        ]
        return _redact(out)

    async def list_switch_ports(self, site: str, device_mac: str) -> Any:
        """A single switch's ``port_table`` (live state) + ``port_overrides``."""
        site = validate_site(site)
        mac = validate_mac(device_mac)
        await self._verify_site_owned(site)
        self._api.site = site
        rows = (await self._api.get_device(mac)).get("data", []) or []
        if not rows:
            raise AdapterError(f"UniFi device not found: {mac}", adapter_id="unifi")
        d = rows[0]
        return _redact(
            {
                "mac": d.get("mac"),
                "name": d.get("name"),
                "model": d.get("model"),
                "port_table": d.get("port_table", []),
                "port_overrides": d.get("port_overrides", []),
            }
        )

    # ════════════════════════════════════════════════════════════════
    # Legacy / convenience wrappers (preserved for backward compat)
    # ════════════════════════════════════════════════════════════════
    # These predate the reference contract and remain so the
    # existing module-level network adapter dispatch doesn't break.
    # They route through the new dual-gated write methods where
    # state-changing.

    async def get_vlans(self) -> AdapterResult:
        """Legacy alias for ``list_networks(default_site)``."""
        try:
            data = await self.list_networks(self._default_site)
            return AdapterResult.ok(
                data=[
                    {
                        "id": net.get("_id"),
                        "name": net.get("name"),
                        "vlan_id": net.get("vlan"),
                        "purpose": net.get("purpose"),
                        "subnet": net.get("ip_subnet"),
                        "gateway": net.get("gateway_ip")
                        or ((net.get("ip_subnet") or "").split("/")[0] or None),
                        "dhcp_enabled": net.get("dhcpd_enabled", False),
                        "dhcp_start": net.get("dhcpd_start"),
                        "dhcp_stop": net.get("dhcpd_stop"),
                        "domain_name": net.get("domain_name"),
                        "enabled": net.get("enabled", True),
                        "is_nat": net.get("is_nat", True),
                    }
                    for net in data
                ]
            )
        except Exception as exc:
            return AdapterResult.fail(f"Failed to get VLANs: {exc}")

    async def create_vlan(
        self,
        vlan_id: int,
        name: str,
        *,
        force: bool = False,
        **kwargs: Any,
    ) -> AdapterResult:
        """Create a VLAN. Honors the ``BaseAdapter.create_vlan`` contract.

        Pre-May-2026 the UniFi implementation had a divergent
        ``create_vlan(data: dict)`` signature that broke Liskov against
        the base — any caller using the typed
        ``create_vlan(vlan_id=10, name="foo")`` shape got a TypeError.
        Signature now matches the base; ``**kwargs``
        absorbs UniFi-specific options (``subnet``, ``dhcp_enabled``,
        ``dhcp_start``, ``dhcp_stop``).

        Read-only gated like every other UniFi write method: a live VLAN
        creation is refused unless the operator clears ``ADAPTER_READ_ONLY``
        AND the caller passes ``force=True``. The staged applier
        (``adapter_unifi_networks.GatewayUniFiNetworksService``) opts in with
        ``force=True`` after the staging dual-gate; the direct legacy
        ``/network/vlans`` push path passes no force, so it is refused under
        read-only (the controller write is skipped; the DB row still records).
        """
        _enforce_read_only(force=force, action=f"create_vlan(vlan_id={vlan_id})")
        try:
            subnet = kwargs.get("subnet")
            payload: dict[str, Any] = {
                "name": name,
                "purpose": "vlan-only" if not subnet else "corporate",
                "vlan": vlan_id,
                "vlan_enabled": True,
                # networkgroup is OPTIONAL on UniFi Network 10.4.57 — the
                # controller accepts a vlan-enabled networkconf with OR without it
                # (auto-assigns when omitted). VERIFIED LIVE on the real UCG
                # (vlan60 with "LAN" + vlan61 omitted both accepted; evidence:
                # freesdn-cassettes/unifi/networkconf_vlan_networkgroup.json). We
                # send "LAN" as an explicit, kwargs-overridable default so a
                # distributed VLAN lands on the LAN switching group predictably.
                # NB: the REAL create constraint is the VLAN-ID range — the
                # controller rejects reserved-high ids (~>4000) with
                # api.err.InvalidPayload (an earlier "networkgroup required"
                # diagnosis was a misattribution of that id-range rejection).
                "networkgroup": kwargs.get("networkgroup", "LAN"),
            }
            if subnet:
                payload["ip_subnet"] = subnet
            if kwargs.get("dhcp_enabled"):
                payload["dhcpd_enabled"] = True
                if kwargs.get("dhcp_start"):
                    payload["dhcpd_start"] = kwargs["dhcp_start"]
                if kwargs.get("dhcp_stop"):
                    payload["dhcpd_stop"] = kwargs["dhcp_stop"]
            self._api.site = self._default_site
            result = await self._api.create_network(payload)
            return AdapterResult.ok(data=_redact(result.get("data", [])))
        except Exception as exc:
            return AdapterResult.fail(f"Failed to create VLAN: {exc}")

    # ════════════════════════════════════════════════════════════════
    # Network Distribution Engine target (Fabric Omada→UniFi cross-push)
    # ════════════════════════════════════════════════════════════════
    # The distribution engine pushes a CANONICAL VLAN as vendor-neutral actions
    # (create_vlan_interface / create_dhcp_scope / create_alias / create_vlan /
    # delete_*) to each assigned device's adapter (see gateway.distribution_
    # service._execute_step → getattr(adapter, action)(**params)). These methods
    # let a UniFi gateway be a first-class distribution TARGET — i.e. a VLAN
    # authored from any vendor (e.g. Omada) lands on UniFi. UniFi folds the L3
    # SVI + L2 VLAN + DHCP into ONE networkconf object, so the tiered actions map
    # onto a single network and an alias maps to a firewall group. All return
    # AdapterResult (the engine checks ``result.success``) and are dual-gated.

    async def _find_network_by_vlan(self, vlan_id: int) -> dict[str, Any] | None:
        self._api.site = self._default_site
        nets = await self._api.get_networks()
        for n in nets.get("data", []) or []:
            if n.get("vlan") == vlan_id:
                return n
        return None

    @staticmethod
    def _vlan_from_interface(interface: str | None) -> int | None:
        """The engine names a scope's interface ``vlan{N}``; pull N back out."""
        if not interface:
            return None
        digits = "".join(c for c in str(interface) if c.isdigit())
        return int(digits) if digits else None

    @staticmethod
    def _default_dhcp_range(
        gateway_ip: str | None, subnet: str | None
    ) -> tuple[str | None, str | None]:
        """A sane /24 DHCP window from the gateway's network base. UniFi requires
        a range on a corporate network at create time even though the engine
        defers DHCP to a later tier; create_dhcp_scope refines it afterwards."""
        ip = gateway_ip or (str(subnet).split("/")[0] if subnet else None)
        if not ip or ip.count(".") != 3:
            return None, None
        base = ip.rsplit(".", 1)[0]
        return f"{base}.6", f"{base}.254"

    async def create_vlan_interface(
        self,
        vlan_id: int,
        name: str,
        subnet: str | None = None,
        gateway_ip: str | None = None,
        description: str | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Brain L3 action → a UniFi corporate VLAN networkconf. Idempotent: an
        existing network already carrying this VLAN is returned untouched."""
        try:
            _enforce_read_only(force=force, action=f"create_vlan_interface(vlan_id={vlan_id})")
            existing = await self._find_network_by_vlan(int(vlan_id))
            if existing:
                return AdapterResult.ok(data=_redact(existing))
            payload: dict[str, Any] = {
                "purpose": "corporate" if subnet else "vlan-only",
                "name": name,
                "vlan_enabled": True,
                "vlan": int(vlan_id),
                # Optional on UniFi Network 10.x (see create_vlan) — sent as an
                # explicit default; the real create constraint is the VLAN-ID range.
                "networkgroup": "LAN",
            }
            if subnet:
                prefix = str(subnet).rsplit("/", 1)[-1] if "/" in str(subnet) else "24"
                payload["ip_subnet"] = f"{gateway_ip}/{prefix}" if gateway_ip else str(subnet)
                start, stop = self._default_dhcp_range(gateway_ip, subnet)
                if start:
                    payload.update(
                        {"dhcpd_enabled": True, "dhcpd_start": start, "dhcpd_stop": stop}
                    )
            self._api.site = self._default_site
            result = await self._api.create_network(payload)
            return AdapterResult.ok(data=_redact(result.get("data", [])))
        except AdapterReadOnlyError as exc:
            return AdapterResult.fail(str(exc), error_code="READ_ONLY")
        except Exception as exc:  # noqa: BLE001
            return AdapterResult.fail(f"create_vlan_interface failed: {exc}")

    async def create_dhcp_scope(
        self,
        interface: str,
        range_start: str,
        range_end: str,
        gateway: str | None = None,
        subnet: str | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Brain services action → enable DHCP on the VLAN's networkconf."""
        try:
            _enforce_read_only(force=force, action=f"create_dhcp_scope({interface})")
            vlan_id = self._vlan_from_interface(interface)
            net = await self._find_network_by_vlan(vlan_id) if vlan_id else None
            if not net:
                return AdapterResult.fail(f"create_dhcp_scope: no UniFi network for {interface!r}")
            self._api.site = self._default_site
            result = await self._api.update_network(
                net["_id"],
                {"dhcpd_enabled": True, "dhcpd_start": range_start, "dhcpd_stop": range_end},
            )
            return AdapterResult.ok(data=_redact(result.get("data", [])))
        except AdapterReadOnlyError as exc:
            return AdapterResult.fail(str(exc), error_code="READ_ONLY")
        except Exception as exc:  # noqa: BLE001
            return AdapterResult.fail(f"create_dhcp_scope failed: {exc}")

    async def create_alias(
        self,
        name: str,
        type: str,
        members: list[str],  # noqa: A002 - engine param name
        description: str | None = None,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Canonical alias → UniFi firewall group (address- or port-group)."""
        try:
            _enforce_read_only(force=force, action=f"create_alias({name})")
            group_type = "port-group" if str(type).lower().startswith("port") else "address-group"
            self._api.site = self._default_site
            result = await self._api.create_firewall_group(
                {"name": name, "group_type": group_type, "group_members": list(members)}
            )
            return AdapterResult.ok(data=_redact(result.get("data", [])))
        except AdapterReadOnlyError as exc:
            return AdapterResult.fail(str(exc), error_code="READ_ONLY")
        except Exception as exc:  # noqa: BLE001
            return AdapterResult.fail(f"create_alias failed: {exc}")

    async def suppress_dhcp(self, vlan_id: int, *, force: bool = False) -> AdapterResult:
        """Limb action → disable DHCP on a VLAN (a non-authoritative L2 segment)."""
        try:
            _enforce_read_only(force=force, action=f"suppress_dhcp(vlan_id={vlan_id})")
            net = await self._find_network_by_vlan(int(vlan_id))
            if not net:
                return AdapterResult.ok(data=[])  # nothing to suppress
            self._api.site = self._default_site
            result = await self._api.update_network(net["_id"], {"dhcpd_enabled": False})
            return AdapterResult.ok(data=_redact(result.get("data", [])))
        except AdapterReadOnlyError as exc:
            return AdapterResult.fail(str(exc), error_code="READ_ONLY")
        except Exception as exc:  # noqa: BLE001
            return AdapterResult.fail(f"suppress_dhcp failed: {exc}")

    async def delete_vlan_interface(
        self, vlan_id: int, *, force: bool = False, **_: Any
    ) -> AdapterResult:
        """Teardown → delete the VLAN's networkconf."""
        try:
            _enforce_read_only(force=force, action=f"delete_vlan_interface(vlan_id={vlan_id})")
            net = await self._find_network_by_vlan(int(vlan_id))
            if not net:
                return AdapterResult.ok(data=[])
            self._api.site = self._default_site
            result = await self._api.delete_network(net["_id"])
            return AdapterResult.ok(data=_redact(result.get("data", [])))
        except AdapterReadOnlyError as exc:
            return AdapterResult.fail(str(exc), error_code="READ_ONLY")
        except Exception as exc:  # noqa: BLE001
            return AdapterResult.fail(f"delete_vlan_interface failed: {exc}")

    async def delete_vlan(self, vlan_id: int, *, force: bool = False, **_: Any) -> AdapterResult:  # type: ignore[override]
        """Limb teardown → same as delete_vlan_interface on UniFi's unified model."""
        return await self.delete_vlan_interface(vlan_id, force=force)

    async def delete_dhcp_scope(
        self, interface: str, *, force: bool = False, **_: Any
    ) -> AdapterResult:
        """Teardown → disable DHCP on the VLAN's networkconf."""
        vlan_id = self._vlan_from_interface(interface)
        return (
            await self.suppress_dhcp(vlan_id, force=force) if vlan_id else AdapterResult.ok(data=[])
        )

    async def delete_alias(self, name: str, *, force: bool = False, **_: Any) -> AdapterResult:
        """Teardown → delete the UniFi firewall group with this name."""
        try:
            _enforce_read_only(force=force, action=f"delete_alias({name})")
            self._api.site = self._default_site
            groups = await self._api.get_firewall_groups()
            grp = next((g for g in groups.get("data", []) or [] if g.get("name") == name), None)
            if not grp:
                return AdapterResult.ok(data=[])
            result = await self._api.delete_firewall_group(grp["_id"])
            return AdapterResult.ok(data=_redact(result.get("data", [])))
        except AdapterReadOnlyError as exc:
            return AdapterResult.fail(str(exc), error_code="READ_ONLY")
        except Exception as exc:  # noqa: BLE001
            return AdapterResult.fail(f"delete_alias failed: {exc}")

    async def get_clients(self) -> AdapterResult:  # type: ignore[override]
        """Legacy alias for ``list_clients(default_site)``."""
        try:
            data = await self.list_clients(self._default_site)
            return AdapterResult.ok(
                data=[
                    {
                        "mac": cli.get("mac"),
                        "ip": cli.get("ip"),
                        "hostname": cli.get("hostname"),
                        "name": cli.get("name") or cli.get("hostname") or cli.get("mac"),
                        "oui": cli.get("oui"),
                        "network": cli.get("network"),
                        "vlan": cli.get("vlan"),
                        "is_wired": cli.get("is_wired", False),
                        "is_guest": cli.get("is_guest", False),
                        "signal": cli.get("signal"),
                        "rssi": cli.get("rssi"),
                        "channel": cli.get("channel"),
                        "radio": cli.get("radio"),
                        "essid": cli.get("essid"),
                        "ap_mac": cli.get("ap_mac"),
                        "sw_mac": cli.get("sw_mac"),
                        "sw_port": cli.get("sw_port"),
                        "rx_bytes": cli.get("rx_bytes", 0),
                        "tx_bytes": cli.get("tx_bytes", 0),
                        "uptime": cli.get("uptime"),
                        "satisfaction": cli.get("satisfaction"),
                    }
                    for cli in data
                ]
            )
        except Exception as exc:
            return AdapterResult.fail(f"Failed to get clients: {exc}")

    async def get_wlans(self) -> AdapterResult:  # type: ignore[override]
        """Legacy alias for ``list_wlans(default_site)``."""
        try:
            data = await self.list_wlans(self._default_site)
            return AdapterResult.ok(
                data=[
                    {
                        "id": w.get("_id"),
                        "name": w.get("name"),
                        "enabled": w.get("enabled", True),
                        "security": w.get("security", "wpapsk"),
                        "is_guest": w.get("is_guest", False),
                        "vlan": w.get("vlan"),
                        "vlan_enabled": w.get("vlan_enabled", False),
                        "band": w.get("wlan_band", "both"),
                        "hide_ssid": w.get("hide_ssid", False),
                        "mac_filter_enabled": w.get("mac_filter_enabled", False),
                    }
                    for w in data
                ]
            )
        except Exception as exc:
            return AdapterResult.fail(f"Failed to get WLANs: {exc}")

    async def get_port_profiles(self) -> AdapterResult:
        """Legacy alias — list port profiles for the default site."""
        try:
            self._api.site = self._default_site
            result = await self._api.get_port_profiles()
            return AdapterResult.ok(data=_redact(result.get("data", []) or []))
        except Exception as exc:
            return AdapterResult.fail(f"Failed to get port profiles: {exc}")

    async def get_firewall_rules(self) -> AdapterResult:  # type: ignore[override]
        try:
            data = await self.list_firewall_rules(self._default_site)
            return AdapterResult.ok(data=data)
        except Exception as exc:
            return AdapterResult.fail(f"Failed to get firewall rules: {exc}")

    async def reboot_device(self, mac: str) -> AdapterResult:
        """Legacy alias — preserved for the discovery / sync path.

        Routes through the dual-gated :meth:`restart_device`.
        """
        try:
            await self.restart_device(self._default_site, mac, force=False)
            return AdapterResult.ok(message=f"Reboot command sent to {mac}")
        except AdapterReadOnlyError as exc:
            return AdapterResult.fail(str(exc), error_code="READ_ONLY")
        except Exception as exc:
            return AdapterResult.fail(f"Failed to reboot device: {exc}")

    async def locate_device(
        self,
        mac: str,
        enabled: bool = True,
        *,
        site: str | None = None,
        force: bool = False,
    ) -> AdapterResult:  # type: ignore[override]
        """Blink (``enabled=True``) or stop blinking a device's locate LED.

        BaseAdapter contract method — keeps the ``(mac, enabled)`` signature; the
        UniFi staged applier additionally passes ``site=`` so the command targets
        the device's ACTUAL site. Without it, locate always hit ``_default_site``,
        so on a multi-site controller a device on a branch site would never blink
        (the cmd 404s on the default site). ``site=None`` keeps the historical
        default-site behaviour for the generic BaseAdapter caller.

        Dual-gated like every UniFi write (``force=True`` + cleared
        ``ADAPTER_READ_ONLY``); the staged applier opts in with ``force=True``.
        Live-validated against a real UCG (set-locate → unset-locate).
        """
        try:
            _enforce_read_only(force=force, action=f"locate_device({mac}, enabled={enabled})")
            validated = validate_mac(mac)
            target_site = validate_site(site) if site else self._default_site
            # IDOR parity with the other write methods — don't let a caller pivot
            # to a sibling tenant's site (the staged applier also verifies).
            await self._verify_site_owned(target_site)
            self._api.site = target_site
            cmd = "set-locate" if enabled else "unset-locate"
            result = await self._api.cmd_devmgr({"cmd": cmd, "mac": validated})
            return AdapterResult.ok(data=_redact(result.get("data", [])))
        except AdapterReadOnlyError as exc:
            return AdapterResult.fail(str(exc), error_code="READ_ONLY")
        except Exception as exc:  # noqa: BLE001
            return AdapterResult.fail(f"Failed to locate device: {exc}")

    # ────────────────────────────────────────────────────────────────
    # Internal helpers
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def _to_discovered_device(dev: dict[str, Any]) -> DiscoveredDevice:
        """Convert a UniFi device dict to a :class:`DiscoveredDevice`."""
        unifi_type = dev.get("type", "usw")
        return DiscoveredDevice(
            mac_address=dev.get("mac", ""),
            ip_address=dev.get("ip"),
            name=dev.get("name") or dev.get("model", "Unknown"),
            vendor="Ubiquiti",
            model=dev.get("model", "Unknown"),
            firmware_version=dev.get("version"),
            device_type=_normalize_device_type(unifi_type),
            status="online" if dev.get("state") == 1 else "offline",
            serial_number=dev.get("serial"),
            raw_data=_redact(
                {
                    "unifi_type": unifi_type,
                    "model_in_lts": dev.get("model_in_lts", False),
                    "model_in_eol": dev.get("model_in_eol", False),
                    "adopted": dev.get("adopted", False),
                    "uptime": dev.get("uptime"),
                    "num_sta": dev.get("num_sta", 0),
                    "satisfaction": dev.get("satisfaction"),
                }
            ),
        )


__all__ = [
    "UniFiAdapter",
    "AdapterReadOnlyError",
    "_is_adapter_read_only",
    "_enforce_read_only",
]

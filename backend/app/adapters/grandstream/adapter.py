# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Grandstream Adapter
===================================

High-level adapter for Grandstream IP phones.

Unlike the FreePBX adapter (single PBX server), the Grandstream adapter
manages a *fleet* of phones.  Each phone is accessed individually via its
HTTP admin interface.  Provisioning is done via XML files served by FreeSDN.

Architecture::

    GrandstreamAdapter  (BaseAdapter)
        ├── phone_clients: dict[mac, GrandstreamPhoneClient]  (per-phone HTTP)
        └── provisioner:   GrandstreamProvisioner              (XML generation)
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import logging
from typing import Any

import aiohttp

from app.adapters.base import (
    AdapterManifest,
    AdapterResult,
    BaseAdapter,
    DeviceTypeCapabilities,
    DiscoveredDevice,
)
from app.adapters.capabilities import Capability
from app.adapters.exceptions import AdapterReadOnlyError as _BaseAdapterReadOnlyError
from app.adapters.http_utils import CircuitBreaker
from app.core.http_client import build_aiohttp_session

from .client import GrandstreamPhoneClient
from .constants import PHONE_DEFAULT_PORT
from .exceptions import (
    GrandstreamConnectionError,
    GrandstreamError,
    GrandstreamTimeoutError,
)
from .models import (
    LineKeyConfig,
    PhoneConfig,
    SIPAccountConfig,
)
from .provisioner import GrandstreamProvisioner
from .utils import (
    normalize_mac,
)

logger = logging.getLogger("freesdn.adapters.grandstream")

# ── Gold-standard adapter contract ─────────────────────────────────────────
# Same pattern as the FreePBX / Omada / Proxmox adapters: dry-run by
# default (ADAPTER_READ_ONLY env var), per-call ``force=True`` to opt out.


class GrandstreamReadOnlyError(GrandstreamError, _BaseAdapterReadOnlyError):
    """Raised when a write operation is attempted in read-only mode.

    Also subclasses the canonical AdapterReadOnlyError so the central handler
    maps a Grandstream write-refusal to 403, not the 502 catch-all.
    """


# ── P-value allowlist for ``set_phone_config`` ────────────────────────────
# The raw ``set_config`` channel can write ANY Grandstream P-value
# including the admin password (P2), SIP auth password (P34), and the
# user password (P196). The audit found callers using ``set_phone_config``
# to push arbitrary p-values which is a stomp-the-credentials primitive.
#
# Restrict to read-or-display-only P-values that don't compromise the
# device's authentication or security posture. Any caller that needs to
# rotate credentials should call the explicit ``configure_sip_account``
# / ``provision_phone`` methods (which gate on the write-gate).
_SAFE_P_VALUE_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Display / personalisation
        "P270",  # Display name
        "P14",  # Ringtone
        "P78",  # Ring volume
        "P79",  # Speaker volume
        "P75",  # Handset volume
        "P77",  # Headset volume
        "P276",  # Default ringtone
        "P21102",  # LCD brightness
        "P1362",  # Language
        "P64",  # Timezone
        # NTP / time-of-day
        "P30",  # NTP server
        "P246",  # NTP update interval
        # Syslog / diagnostics
        "P207",  # Syslog server
        "P208",  # Syslog level
        # NOTE: P234 looks like a "local syslog" flag on some firmware
        # but on account-3-enabled phones it's the SIP Auth Password.
        # It's listed in _FORBIDDEN_P_VALUES — never expose either way.
        # BLF / line-key labels (NOT modes — mode changes need provisioning)
        "P325",
        "P326",
        "P327",
        "P328",
        "P329",
        "P3251",
        "P3252",
        "P3253",
        # Phonebook / contacts
        "P330",
        "P331",
        "P332",
        "P333",
        # Display-only — NEVER write credentials, dial plans, or registration
    }
)

# ── SIP password / auth password / admin password are explicitly blocked
# so a future helper-method can mention them by name without anyone
# accidentally writing them via set_phone_config.
_FORBIDDEN_P_VALUES: frozenset[str] = frozenset(
    {
        "P2",  # Admin password
        "P196",  # User / XML password
        "P34",  # SIP Auth Password (account 1)
        "P134",  # SIP Auth Password (account 2)
        "P234",  # SIP Auth Password (account 3) — also syslog-local
        # Auth Passwords for accounts 4-16 (Grandstream uses stride of 100)
        "P434",
        "P534",
        "P634",
        "P734",
        "P834",
        "P934",
        "P1034",
        "P1134",
        "P1234",
        "P1334",
        "P1434",
        "P1534",
        "P1634",
        "P237",  # Provisioning server URL — SSRF target, only set via provision API
        "P192",  # Firmware upgrade server URL — same reason
        "P145",  # XML config password (separate from P196)
    }
)


class GrandstreamAdapter(BaseAdapter):
    """
    Grandstream IP phone fleet adapter.

    Manages Grandstream phones discovered on the network.  Each phone is
    contacted directly via its HTTP admin API for status and config.

    The ``host`` parameter for this adapter is used as the FreeSDN server
    address (for provisioning URLs), not a phone address.  Individual
    phones are added via ``add_phone()``.

    Usage::

        adapter = GrandstreamAdapter(
            host="192.168.1.105",    # FreeSDN server for provisioning
            username="admin",
            password="admin",
            provision_base_url="http://192.168.1.105:8080/provision",
        )
        await adapter.connect()
        adapter.add_phone("192.168.1.100", mac="00:0B:82:12:34:56")
        devices = await adapter.discover_devices()
    """

    manifest = AdapterManifest(
        id="grandstream",
        name="Grandstream IP Phones",
        vendor="Grandstream",
        version="1.0.0",
        description=(
            "Adapter for Grandstream GRP, GXP, GXV, DP, and HT series phones. "
            "Provides per-phone configuration, BLF/line keys, provisioning, "
            "and fleet management."
        ),
        controller_type=None,
        supports_controller=False,
        supports_direct=True,
        supported_versions=["GRP26xx", "GXP21xx", "GXP16xx", "DP7xx", "GXV34xx", "HT8xx"],
        device_types={
            "phone": DeviceTypeCapabilities(
                module="voip",
                capabilities=[
                    Capability.PHONE_PROVISIONING,
                    Capability.PHONE_CONFIG,
                    Capability.PHONE_REBOOT,
                    Capability.PHONE_STATUS,
                    Capability.PHONE_LINE_CONFIG,
                    Capability.PHONE_BLF,
                    Capability.PHONE_DIRECTORY,
                ],
                models=["GRP*", "GXP*", "GXV*", "DP*", "HT*"],
            ),
        },
        auth_methods=["password"],
        rate_limit_calls_per_minute=120,
        rate_limit_concurrent=20,  # many phones in parallel
        default_sync_interval=600,  # 10 min
        min_sync_interval=120,
        supports_webhooks=False,
        supports_real_time_events=False,
        supports_bulk_operations=True,  # bulk provisioning via XML
    )

    # Concurrency limiter for phone fleet operations
    _MAX_CONCURRENT_PHONES = 20

    def __init__(
        self,
        host: str,
        username: str = "admin",
        password: str = "admin",
        *,
        provision_base_url: str = "",
        provision_protocol: str = "HTTP",
        phone_port: int = PHONE_DEFAULT_PORT,
        # ``phone_use_ssl`` now defaults to True. Brownfield phones that
        # only accept HTTP must set this False AND set
        # ``acknowledge_plaintext=True`` on the Phone row.
        phone_use_ssl: bool = True,
        # SSRF allowlist: passed in by the service layer from
        # ``Site.subnets`` so the adapter can validate every phone IP
        # against the site's known subnets before connecting. Empty
        # tuple disables the check (used by unit tests with mock IPs).
        allowed_subnets: tuple[str, ...] = (),
        read_only: bool | None = None,
        **kwargs: Any,
    ):
        super().__init__(host, username, password, **kwargs)

        self._provision_base_url = provision_base_url
        self._phone_port = phone_port
        self._phone_use_ssl = phone_use_ssl
        # None ⇒ the write gate resolves the LIVE runtime flag per call.
        self._read_only = read_only
        self._allowed_subnets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
            net for net in (_parse_subnet(s) for s in allowed_subnets) if net is not None
        )

        # Per-phone clients:  mac_address → (client, phone_ip)
        self._phones: dict[str, _PhoneEntry] = {}

        # Provisioner
        self._provisioner = GrandstreamProvisioner(
            freesdn_provision_url=provision_base_url,
            provision_protocol=provision_protocol,
        )

        # Tagged breaker for the fleet — host label is the provisioning URL
        # so dashboards can group all phones reaching the same provisioning
        # endpoint. Individual phone failures still count toward this
        # breaker because they all share the same upstream provisioning
        # config.
        self._circuit = CircuitBreaker(
            failure_threshold=10,  # higher than PBX — fleet of N phones
            reset_timeout=30.0,
            name="grandstream",
            host=host or "fleet",
        )

    # ── SSRF validation ────────────────────────────────────────────────
    def _validate_phone_ip(self, ip: str) -> None:
        """Reject phone IPs that don't pass the SSRF safety checks.

        Rejects:
          - Loopback (127.0.0.0/8, ::1)
          - Link-local (169.254.0.0/16, fe80::/10)
          - Multicast (224.0.0.0/4)
          - Unspecified (0.0.0.0, ::)
          - IPv6 unique-local (fc00::/7)
          - Any IP outside the allowed_subnets (when configured).

        RFC1918 addresses are PERMITTED — phones live on management
        VLANs which are RFC1918 by default.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise GrandstreamConnectionError(f"Invalid IP address for phone: {ip!r}") from exc
        if (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or addr.is_reserved
        ):
            raise GrandstreamConnectionError(
                f"Refusing to connect to disallowed phone address {ip!r} "
                "(loopback / link-local / multicast / reserved)"
            )
        # IPv6 unique-local
        if addr.version == 6 and addr in ipaddress.IPv6Network("fc00::/7"):
            raise GrandstreamConnectionError(
                f"Refusing to connect to IPv6 unique-local address {ip!r}"
            )
        # If a subnet allowlist is configured, enforce it
        if self._allowed_subnets and not any(addr in net for net in self._allowed_subnets):
            raise GrandstreamConnectionError(f"Phone IP {ip!r} is not in any allowed Site subnet")

    # ── Write-gate (read-only mode + per-call force=True) ──────────────
    def _check_write_allowed(self, force: bool, op: str) -> None:
        # Resolve the LIVE runtime read-only flag when the caller didn't pin it,
        # so an operator's live "freeze writes" toggle is honored (parity with
        # the other adapters + staging service; no worker restart needed).
        if self._read_only is None:
            from app.core.runtime_flags import is_adapter_read_only

            effective_ro = is_adapter_read_only()
        else:
            effective_ro = self._read_only
        if effective_ro and not force:
            raise GrandstreamReadOnlyError(
                f"Refusing {op}: adapter is in read-only mode "
                "(set ADAPTER_READ_ONLY=false and pass force=True to override)"
            )

    # ── properties ─────────────────────────────────────────────────────

    @property
    def provisioner(self) -> GrandstreamProvisioner:
        return self._provisioner

    @property
    def phone_count(self) -> int:
        return len(self._phones)

    # ═══════════════════════════════════════════════════════════════════
    # BaseAdapter — Connection lifecycle
    # ═══════════════════════════════════════════════════════════════════

    async def connect(self) -> bool:
        """
        Initialize the adapter.

        For Grandstream, "connect" just marks the adapter as ready.
        Actual phone connections happen on-demand.
        """
        self._connected = True
        logger.info(
            "Grandstream adapter initialized — %d phones registered",
            len(self._phones),
        )
        return True

    async def disconnect(self) -> None:
        """Disconnect all phone clients."""
        for entry in self._phones.values():
            if entry.client:
                with contextlib.suppress(GrandstreamError, ConnectionError, TimeoutError, OSError):
                    await entry.client.disconnect()
        self._phones.clear()
        self._connected = False
        logger.info("Grandstream adapter disconnected")

    async def test_connection(self) -> AdapterResult:
        """
        Test that we can reach at least one registered phone.
        """
        if not self._phones:
            return AdapterResult.ok(
                message="No phones registered yet — adapter ready for phone registration"
            )

        successes = 0
        errors: list[str] = []
        for mac, entry in self._phones.items():
            try:
                client = await self._get_or_connect(mac)
                info = await client.get_phone_info()
                if info.model:
                    successes += 1
            except Exception as exc:
                errors.append(f"{entry.ip}: {exc}")

        if successes > 0:
            return AdapterResult.ok(
                data={"reachable": successes, "total": len(self._phones)},
                message=f"{successes}/{len(self._phones)} phones reachable",
            )
        return AdapterResult.fail(error=f"No phones reachable: {'; '.join(errors[:3])}")

    # ═══════════════════════════════════════════════════════════════════
    # BaseAdapter — Discovery
    # ═══════════════════════════════════════════════════════════════════

    async def discover_devices(self) -> list[DiscoveredDevice]:
        """
        Query all registered phones for their status (concurrently).
        """
        devices: list[DiscoveredDevice] = []
        sem = asyncio.Semaphore(self._MAX_CONCURRENT_PHONES)

        async def _discover_one(mac: str, entry: _PhoneEntry) -> DiscoveredDevice:
            async with sem:
                try:
                    client = await self._get_or_connect(mac)
                    status = await client.get_status()

                    return DiscoveredDevice(
                        mac_address=mac,
                        ip_address=entry.ip,
                        name=status.info.model or f"Grandstream @ {entry.ip}",
                        vendor="Grandstream",
                        model=status.info.model,
                        firmware_version=status.info.firmware_version,
                        device_type="phone",
                        status="online",
                        serial_number=status.info.serial_number or None,
                        capabilities=[
                            Capability.PHONE_PROVISIONING,
                            Capability.PHONE_CONFIG,
                            Capability.PHONE_REBOOT,
                            Capability.PHONE_STATUS,
                            Capability.PHONE_LINE_CONFIG,
                            Capability.PHONE_BLF,
                        ],
                        raw_data={
                            "accounts": [a.model_dump() for a in status.accounts],
                            "active_calls": status.active_calls,
                        },
                    )

                except Exception as exc:
                    logger.warning("Cannot reach phone %s (%s): %s", mac, entry.ip, exc)
                    return DiscoveredDevice(
                        mac_address=mac,
                        ip_address=entry.ip,
                        name=f"Grandstream @ {entry.ip}",
                        vendor="Grandstream",
                        model="unknown",
                        firmware_version=None,
                        device_type="phone",
                        status="offline",
                    )

        results = await asyncio.gather(
            *(_discover_one(mac, entry) for mac, entry in self._phones.items()),
            return_exceptions=True,
        )
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                mac_list = list(self._phones.keys())
                logger.error("Unexpected error discovering phone %s: %s", mac_list[i], r)
                entry = list(self._phones.values())[i]
                results[i] = DiscoveredDevice(
                    mac_address=mac_list[i],
                    ip_address=entry.ip,
                    name=f"Grandstream @ {entry.ip}",
                    vendor="Grandstream",
                    model="unknown",
                    firmware_version=None,
                    device_type="phone",
                    status="offline",
                )
        devices.extend(results)

        return devices

    async def get_device_status(self, device_id: str) -> dict[str, Any]:
        """Get phone status by MAC address."""
        mac = normalize_mac(device_id)
        try:
            client = await self._get_or_connect(mac)
            status = await client.get_status()
            return status.model_dump()
        except Exception as exc:
            # Some exceptions (TimeoutError, etc.) have an empty
            # ``str()`` — fall back to the class name so the operator
            # sees something useful instead of ``error: ""``.
            err = str(exc) or type(exc).__name__
            return {"mac": mac, "status": "offline", "error": err}

    async def get_device_info(self, device_id: str) -> DiscoveredDevice | None:
        """Get device info for a specific phone."""
        mac = normalize_mac(device_id)
        entry = self._phones.get(mac)
        if not entry:
            return None

        try:
            client = await self._get_or_connect(mac)
            status = await client.get_status()
            return DiscoveredDevice(
                mac_address=mac,
                ip_address=entry.ip,
                name=status.info.model or f"Grandstream @ {entry.ip}",
                vendor="Grandstream",
                model=status.info.model,
                firmware_version=status.info.firmware_version,
                device_type="phone",
                status="online",
                serial_number=status.info.serial_number,
            )
        except (GrandstreamError, ConnectionError, TimeoutError, OSError):
            return None

    # ═══════════════════════════════════════════════════════════════════
    # Phone fleet management
    # ═══════════════════════════════════════════════════════════════════

    def add_phone(
        self,
        ip: str,
        *,
        mac: str = "",
        password: str | None = None,
        acknowledge_plaintext: bool = False,
    ) -> str:
        """
        Register a phone to be managed.

        Validates the phone IP through the SSRF guard before accepting
        the registration. Returns the normalized MAC address (or a
        placeholder if unknown).
        """
        self._validate_phone_ip(ip)
        mac_norm = normalize_mac(mac) if mac else f"pending:{ip}"
        pwd = password or self.password

        self._phones[mac_norm] = _PhoneEntry(
            ip=ip,
            password=pwd,
            client=None,
            acknowledge_plaintext=acknowledge_plaintext,
        )
        logger.info("Phone registered: %s at %s", mac_norm, ip)
        return mac_norm

    def remove_phone(self, mac: str) -> bool:
        """Remove a phone from management."""
        mac_norm = normalize_mac(mac)
        entry = self._phones.pop(mac_norm, None)
        if entry:
            logger.info("Phone removed: %s", mac_norm)
            return True
        return False

    def list_registered_phones(self) -> dict[str, str]:
        """Return {mac: ip} of all registered phones."""
        return {mac: entry.ip for mac, entry in self._phones.items()}

    # ═══════════════════════════════════════════════════════════════════
    # Phone configuration
    # ═══════════════════════════════════════════════════════════════════

    async def get_phone_config(self, mac: str, p_values: list[str] | None = None) -> AdapterResult:
        """Read P-values from a phone."""
        try:
            client = await self._get_or_connect(normalize_mac(mac))
            config = await client.get_config(p_values)
            # (B): the P-value map is keyed by opaque P-codes that the
            # central redactor can't recognise, so a future read endpoint would
            # leak SIP auth / admin / XML passwords and provisioning URLs. Mask
            # the exact P-codes set_phone_config already blocks on write — the
            # read path must be symmetric with the write block.
            if isinstance(config, dict):
                config = {k: ("***" if k in _FORBIDDEN_P_VALUES else v) for k, v in config.items()}
            return AdapterResult.ok(data=config)
        except GrandstreamError as exc:
            return AdapterResult.fail(error=str(exc))

    async def set_phone_config(
        self, mac: str, p_values: dict[str, str], *, force: bool = False
    ) -> AdapterResult:
        """Write P-values to a phone.

        The generic P-value write channel is now restricted to the
        ``_SAFE_P_VALUE_ALLOWLIST`` — display, locale, NTP, syslog
        settings only. Credential / SIP-auth / provisioning P-values
        are explicitly blocked because the previous unrestricted
        version was a credential-stomping primitive.

        Use :meth:`configure_sip_account` to rotate SIP creds and
        :meth:`provision_phone` for full template-driven config push.
        """
        try:
            self._check_write_allowed(force, "set_phone_config")
            blocked = sorted(k for k in p_values if k in _FORBIDDEN_P_VALUES)
            if blocked:
                raise GrandstreamError(
                    "set_phone_config refuses to write protected P-values "
                    f"{blocked}. Use the dedicated provisioning API instead."
                )
            unknown = sorted(k for k in p_values if k not in _SAFE_P_VALUE_ALLOWLIST)
            if unknown:
                raise GrandstreamError(
                    "set_phone_config refuses to write P-values outside the "
                    f"safe allowlist: {unknown}"
                )
            client = await self._get_or_connect(normalize_mac(mac))
            await client.set_config(p_values)
            self._circuit.record_success()
            return AdapterResult.ok(message=f"Config pushed to {mac}")
        except GrandstreamReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except GrandstreamError as exc:
            self._circuit.record_failure()
            return AdapterResult.fail(error=str(exc))

    async def provision_phone(
        self, mac: str, config: PhoneConfig, *, force: bool = False
    ) -> AdapterResult:
        """
        Provision a phone with a full config.

        Generates XML and pushes P-values directly if the phone is reachable.
        Write-gated.
        """
        try:
            self._check_write_allowed(force, "provision_phone")
            # Generate XML (for serving via provisioning endpoint)
            xml = self._provisioner.generate_config_xml(config)
            filename = self._provisioner.get_config_filename(mac)

            # Also push directly to the phone if reachable. Direct push is
            # best-effort: an *unreachable* phone legitimately degrades to
            # XML-only provisioning (direct_push=False). But genuine failures
            # (auth, API rejection, validation, read-only) must NOT be swallowed
            # as "success" — let them bubble to the outer GrandstreamError handler
            # so the caller gets AdapterResult.fail() instead of a false success.
            try:
                client = await self._get_or_connect(normalize_mac(mac))
                # Extract P-values from config and push
                p_values = self._config_to_p_values(config)
                await client.set_config(p_values)
                direct_push = True
            except (
                GrandstreamConnectionError,
                GrandstreamTimeoutError,
                TimeoutError,
                ConnectionError,
                OSError,
            ) as exc:
                logger.warning("Direct push to %s failed (%s), XML provisioning only", mac, exc)
                direct_push = False

            return AdapterResult.ok(
                data={
                    "xml": xml,
                    "filename": filename,
                    "direct_push": direct_push,
                },
                message=f"Phone {mac} provisioned"
                + (" (direct push)" if direct_push else " (XML only)"),
            )
        except GrandstreamReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except GrandstreamError as exc:
            return AdapterResult.fail(error=str(exc))

    async def reboot_phone(self, mac: str, *, force: bool = False) -> AdapterResult:
        """Reboot a phone. Write-gated."""
        try:
            self._check_write_allowed(force, "reboot_phone")
            client = await self._get_or_connect(normalize_mac(mac))
            await client.reboot()
            return AdapterResult.ok(message=f"Reboot sent to {mac}")
        except GrandstreamReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except GrandstreamError as exc:
            return AdapterResult.fail(error=str(exc))

    async def factory_reset_phone(self, mac: str, *, force: bool = False) -> AdapterResult:
        """Factory reset a phone. Strictly gated.

        The client returns False on transport errors so a typo can't
        masquerade as success. We propagate that as ``AdapterResult.fail``.
        """
        try:
            self._check_write_allowed(force, "factory_reset")
            client = await self._get_or_connect(normalize_mac(mac))
            ok = await client.factory_reset()
            if not ok:
                return AdapterResult.fail(error=f"Factory reset to {mac} could not be confirmed")
            return AdapterResult.ok(message=f"Factory reset issued to {mac}")
        except GrandstreamReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except GrandstreamError as exc:
            return AdapterResult.fail(error=str(exc))

    async def firmware_upgrade(
        self,
        mac: str,
        firmware_url: str,
        expected_sha256: str,
        *,
        force: bool = False,
    ) -> AdapterResult:
        """Push a firmware upgrade to a phone with checksum verification.

        Requires HTTPS firmware URL + caller-supplied sha256 of the
        firmware blob. The adapter downloads + verifies the blob
        before instructing the phone to apply it. A checksum mismatch
        aborts the operation (the phone never sees the firmware).
        """
        try:
            self._check_write_allowed(force, "firmware_upgrade")
            if not firmware_url.startswith("https://"):
                raise GrandstreamError(f"Firmware URL must use HTTPS, got: {firmware_url!r}")
            if not expected_sha256 or len(expected_sha256) != 64:
                raise GrandstreamError("Firmware upgrade requires a 64-char hex sha256 checksum")

            # Download firmware blob and verify checksum.
            timeout = aiohttp.ClientTimeout(total=120.0)
            async with build_aiohttp_session(timeout=timeout) as session:
                async with session.get(firmware_url) as resp:
                    if resp.status != 200:
                        raise GrandstreamError(f"Firmware download returned HTTP {resp.status}")
                    blob = await resp.read()
            actual = hashlib.sha256(blob).hexdigest().lower()
            if actual != expected_sha256.lower():
                raise GrandstreamError(
                    f"Firmware checksum mismatch: expected {expected_sha256}, got {actual}"
                )
            logger.info(
                "Firmware blob verified (%d bytes, sha256=%s); instructing phone %s",
                len(blob),
                actual,
                mac,
            )

            # Tell phone to fetch the (now-verified) firmware. The
            # phone will re-fetch via its own HTTPS connection — we
            # cannot push the blob over the CGI interface.
            client = await self._get_or_connect(normalize_mac(mac))
            await client.set_config(
                {
                    "P192": firmware_url.rsplit("/", 1)[0],  # upgrade server (URL minus filename)
                    "P145": "1",  # firmware upgrade enabled
                    "P237": firmware_url.rsplit("/", 1)[0],  # provision server (same path)
                }
            )
            return AdapterResult.ok(
                data={"firmware_url": firmware_url, "sha256": actual},
                message=f"Firmware upgrade scheduled on {mac}",
            )
        except GrandstreamReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except GrandstreamError as exc:
            return AdapterResult.fail(error=str(exc))
        except aiohttp.ClientError as exc:
            return AdapterResult.fail(error=f"Firmware download failed: {exc}")

    async def configure_sip_account(
        self,
        mac: str,
        sip_server: str,
        extension: str,
        password: str,
        *,
        display_name: str = "",
        account_index: int = 0,
        force: bool = False,
    ) -> AdapterResult:
        """Quick SIP registration setup for a phone. Write-gated.

        Pushes live SIP auth credentials to the phone, so it is gated
        exactly like the other Grandstream write methods (set_phone_config,
        reboot_phone, …): refused under ADAPTER_READ_ONLY unless force=True.
        """
        try:
            self._check_write_allowed(force, "configure_sip_account")
            client = await self._get_or_connect(normalize_mac(mac))
            xml = self._provisioner.generate_minimal_registration_xml(
                sip_server=sip_server,
                extension=extension,
                password=password,
                display_name=display_name,
                account_index=account_index,
            )
            # Parse the XML back to P-values and push directly
            config = PhoneConfig(
                accounts=[
                    SIPAccountConfig(
                        account_index=account_index,
                        active=True,
                        sip_server=sip_server,
                        sip_user_id=extension,
                        auth_id=extension,
                        auth_password=password,
                        display_name=display_name or extension,
                    )
                ]
            )
            p_values = self._config_to_p_values(config)
            await client.set_config(p_values)

            return AdapterResult.ok(
                data={"xml": xml, "extension": extension},
                message=f"SIP account {extension} configured on {mac}",
            )
        except GrandstreamReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except GrandstreamError as exc:
            return AdapterResult.fail(error=str(exc))

    async def configure_blf_keys(
        self, mac: str, keys: list[LineKeyConfig], *, force: bool = False
    ) -> AdapterResult:
        """Configure BLF/line keys on a phone. Write-gated."""
        try:
            self._check_write_allowed(force, "configure_blf_keys")
            client = await self._get_or_connect(normalize_mac(mac))
            p_values: dict[str, str] = {}
            for key in keys:
                p_values.update(self._provisioner._line_key_to_p_values(key))
            await client.set_config(p_values)
            return AdapterResult.ok(message=f"{len(keys)} line keys configured on {mac}")
        except GrandstreamReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))
        except GrandstreamError as exc:
            return AdapterResult.fail(error=str(exc))

    # ═══════════════════════════════════════════════════════════════════
    # Bulk operations
    # ═══════════════════════════════════════════════════════════════════

    async def bulk_reboot(
        self, mac_list: list[str] | None = None, *, force: bool = False
    ) -> AdapterResult:
        """Reboot multiple phones concurrently. Write-gated."""
        try:
            self._check_write_allowed(force, "bulk_reboot")
        except GrandstreamReadOnlyError as exc:
            return AdapterResult.fail(error=str(exc))

        targets = mac_list or list(self._phones.keys())
        sem = asyncio.Semaphore(self._MAX_CONCURRENT_PHONES)
        results: dict[str, bool] = {}

        async def _reboot_one(mac: str) -> None:
            async with sem:
                try:
                    client = await self._get_or_connect(normalize_mac(mac))
                    await client.reboot()
                    results[mac] = True
                except Exception as exc:
                    logger.warning("Reboot failed for %s: %s", mac, exc)
                    results[mac] = False

        gather_results = await asyncio.gather(
            *(_reboot_one(mac) for mac in targets),
            return_exceptions=True,
        )
        for i, r in enumerate(gather_results):
            if isinstance(r, Exception):
                logger.error("Unexpected error rebooting phone %s: %s", targets[i], r)
                results[targets[i]] = False

        success_count = sum(1 for v in results.values() if v)
        return AdapterResult.ok(
            data=results,
            message=f"Rebooted {success_count}/{len(targets)} phones",
        )

    async def generate_all_configs(self, configs: dict[str, PhoneConfig]) -> dict[str, str]:
        """
        Generate XML config files for multiple phones.

        Args:
            configs: {mac_address: PhoneConfig}

        Returns:
            {filename: xml_content}
        """
        result: dict[str, str] = {}
        for mac, config in configs.items():
            filename = self._provisioner.get_config_filename(mac)
            xml = self._provisioner.generate_config_xml(config)
            result[filename] = xml
        return result

    # ═══════════════════════════════════════════════════════════════════
    # Internal helpers
    # ═══════════════════════════════════════════════════════════════════

    async def _get_or_connect(self, mac: str) -> GrandstreamPhoneClient:
        """Get or create + connect a phone client.

        Re-validates the phone IP through the SSRF guard on every
        reconnect so a tampered ``_PhoneEntry.ip`` can't be exploited.
        """
        entry = self._phones.get(mac)
        if not entry:
            raise GrandstreamConnectionError(f"Phone {mac} not registered")

        # Re-validate IP on every connect — defense in depth.
        self._validate_phone_ip(entry.ip)

        if entry.client and entry.client.connected:
            return entry.client

        client = GrandstreamPhoneClient(
            host=entry.ip,
            password=entry.password,
            port=self._phone_port,
            use_ssl=self._phone_use_ssl,
            acknowledge_plaintext=entry.acknowledge_plaintext,
        )
        await client.connect()
        entry.client = client
        return client

    def _config_to_p_values(self, config: PhoneConfig) -> dict[str, str]:
        """Convert a PhoneConfig to flat P-value dict (via provisioner)."""
        # Re-use the provisioner's internal converters
        p: dict[str, str] = {}
        for account in config.accounts:
            p.update(self._provisioner._account_to_p_values(account))
        for key in config.line_keys:
            p.update(self._provisioner._line_key_to_p_values(key))
        p.update(self._provisioner._network_to_p_values(config))
        if config.raw_p_values:
            p.update(config.raw_p_values)
        return p


class _PhoneEntry:
    """Internal record for a registered phone."""

    __slots__ = ("ip", "password", "client", "acknowledge_plaintext")

    def __init__(
        self,
        ip: str,
        password: str,
        client: GrandstreamPhoneClient | None,
        *,
        acknowledge_plaintext: bool = False,
    ):
        self.ip = ip
        self.password = password
        self.client = client
        self.acknowledge_plaintext = acknowledge_plaintext


def _parse_subnet(
    cidr: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse a subnet string for the SSRF allowlist; return None on failure."""
    if not cidr:
        return None
    try:
        return ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        logger.warning("Ignoring invalid subnet in Grandstream allowlist: %r", cidr)
        return None

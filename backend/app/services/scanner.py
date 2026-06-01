# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Network Scanner
==============================

Comprehensive async network scanner for device discovery.
Ported from v1 with improvements for the v2 adapter system.

Supports:
- TCP connect scanning with banner grabbing
- mDNS/DNS-SD service discovery
- SSDP/UPnP device discovery
- HTTP/HTTPS service probing with vendor detection
- RTSP probing (cameras/NVRs)
- MAC OUI vendor lookup
- Reverse DNS hostname resolution
- Device type classification heuristics

4-Phase scan pipeline:
  1. Protocol Discovery (mDNS + SSDP broadcast)
  2. Port Scanning (async TCP connect, batched)
  3. Service Probing (HTTP title/server/vendor, RTSP OPTIONS)
  4. Hostname Resolution (reverse DNS)
"""

import asyncio
import contextlib
import ipaddress
import logging
import re
import socket
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS & CONFIG
# =============================================================================


class ScanMethod(StrEnum):
    """Network scanning methods."""

    ARP = "arp"
    ICMP = "icmp"
    TCP_SYN = "tcp_syn"
    TCP_CONNECT = "tcp_connect"
    UDP = "udp"
    SNMP = "snmp"
    MDNS = "mdns"
    SSDP = "ssdp"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass
class ScanConfig:
    """Scan configuration."""

    # Targets
    targets: list[str] = field(default_factory=list)
    exclude_targets: list[str] = field(default_factory=list)
    site_id: str | None = None

    # Methods
    methods: list[ScanMethod] = field(
        default_factory=lambda: [
            ScanMethod.TCP_CONNECT,
            ScanMethod.MDNS,
            ScanMethod.SSDP,
        ]
    )

    # Port lists
    tcp_ports: list[int] = field(
        default_factory=lambda: [
            22,
            23,
            80,
            443,
            554,
            8080,
            8443,
        ]
    )
    network_device_ports: list[int] = field(
        default_factory=lambda: [
            22,
            23,
            80,
            443,
            8043,
            8088,
            29810,
        ]
    )
    camera_ports: list[int] = field(
        default_factory=lambda: [
            80,
            443,
            554,
            8000,
            8443,
        ]
    )

    # Concurrency & rate limiting
    max_concurrent_hosts: int = 50
    max_concurrent_ports: int = 100
    scan_rate_per_second: float = 500

    # Timeouts
    tcp_timeout: float = 2.0
    udp_timeout: float = 3.0

    # Options
    probe_services: bool = True
    resolve_hostnames: bool = True
    follow_controllers: bool = True

    # Safety
    max_hosts: int = 1024


@dataclass
class ScanProgress:
    """Live scan progress."""

    scan_id: str
    started_at: datetime
    status: ScanStatus = ScanStatus.RUNNING

    total_hosts: int = 0
    scanned_hosts: int = 0
    discovered_hosts: int = 0

    current_phase: str = ""
    phase_progress: float = 0.0

    hosts_found: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    elapsed_seconds: float = 0.0
    estimated_remaining_seconds: float | None = None

    @property
    def progress_pct(self) -> float:
        if self.total_hosts == 0:
            return 0
        return min(100.0, (self.scanned_hosts / self.total_hosts) * 100)


@dataclass
class DiscoveredHost:
    """Host found during network scan."""

    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None

    open_tcp_ports: list[int] = field(default_factory=list)
    open_udp_ports: list[int] = field(default_factory=list)

    services: dict[int, dict[str, Any]] = field(default_factory=dict)
    discovered_via: list[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    response_time_ms: float | None = None

    mdns_services: list[str] = field(default_factory=list)
    ssdp_info: dict[str, Any] | None = None
    snmp_info: dict[str, Any] | None = None

    likely_device_types: list[str] = field(default_factory=list)

    # Fingerprint results (filled after fingerprinting)
    vendor_confidence: float = 0.0
    device_type_confidence: float = 0.0
    http_title: str | None = None
    http_server: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "vendor_confidence": self.vendor_confidence,
            "device_type": self.likely_device_types[0] if self.likely_device_types else None,
            "device_type_confidence": self.device_type_confidence,
            "open_ports": sorted(set(self.open_tcp_ports)),
            "services": {str(k): v for k, v in self.services.items()},
            "discovered_via": self.discovered_via,
            "discovered_at": self.discovered_at.isoformat(),
            "response_time_ms": self.response_time_ms,
            "mdns_services": self.mdns_services,
            "ssdp_info": self.ssdp_info,
            "likely_device_types": self.likely_device_types,
            "http_title": self.http_title,
            "http_server": self.http_server,
        }


# =============================================================================
# MAC OUI VENDOR LOOKUP
# =============================================================================

MAC_VENDOR_DB: dict[str, str] = {
    # TP-Link
    "00:5a:13": "tp-link",
    "10:7b:ef": "tp-link",
    "14:cc:20": "tp-link",
    "30:de:4b": "tp-link",
    "50:3e:aa": "tp-link",
    "60:e3:27": "tp-link",
    "ec:08:6b": "tp-link",
    "98:da:c4": "tp-link",
    "b0:be:76": "tp-link",
    "c0:06:c3": "tp-link",
    "c4:e9:84": "tp-link",
    "d8:07:b6": "tp-link",
    # Hikvision
    "00:0e:45": "hikvision",
    "4c:bd:8f": "hikvision",
    "54:c4:15": "hikvision",
    "80:e8:1a": "hikvision",
    "a4:14:37": "hikvision",
    "bc:ad:28": "hikvision",
    "c0:56:e3": "hikvision",
    "d4:64:24": "hikvision",
    "e8:e0:8f": "hikvision",
    # Ubiquiti
    "00:27:22": "ubiquiti",
    "04:18:d6": "ubiquiti",
    "24:5a:4c": "ubiquiti",
    "44:d9:e7": "ubiquiti",
    "68:72:51": "ubiquiti",
    "78:8a:20": "ubiquiti",
    "80:2a:a8": "ubiquiti",
    "b4:fb:e4": "ubiquiti",
    "dc:9f:db": "ubiquiti",
    "f0:9f:c2": "ubiquiti",
    "fc:ec:da": "ubiquiti",
    # Cisco
    "00:01:64": "cisco",
    "00:0b:fc": "cisco",
    "00:0d:ed": "cisco",
    "00:17:0e": "cisco",
    "00:1a:2f": "cisco",
    "00:1c:0e": "cisco",
    "00:24:c4": "cisco",
    "00:50:0f": "cisco",
    "00:50:bd": "cisco",
    # MikroTik
    "00:0c:42": "mikrotik",
    "08:55:31": "mikrotik",
    "18:fd:74": "mikrotik",
    "2c:c8:1b": "mikrotik",
    "48:8f:5a": "mikrotik",
    "4c:5e:0c": "mikrotik",
    "6c:3b:6b": "mikrotik",
    "b8:69:f4": "mikrotik",
    "cc:2d:e0": "mikrotik",
    "d4:01:c3": "mikrotik",
    "dc:2c:6e": "mikrotik",
    "e4:8d:8c": "mikrotik",
    # Grandstream
    "00:0b:82": "grandstream",
    # Ruckus
    "00:13:92": "ruckus",
    "00:1f:41": "ruckus",
    "00:25:c4": "ruckus",
    "08:86:3b": "ruckus",
    "20:10:7a": "ruckus",
    "58:b6:33": "ruckus",
    "74:91:1a": "ruckus",
    "84:18:88": "ruckus",
    "c0:c5:20": "ruckus",
    # Aruba
    "00:0b:86": "aruba",
    "00:1a:1e": "aruba",
    "00:24:6c": "aruba",
    "04:bd:88": "aruba",
    "20:4c:03": "aruba",
    "24:de:c6": "aruba",
    "40:e3:d6": "aruba",
    "6c:f3:7f": "aruba",
    "94:b4:0f": "aruba",
    # Fortinet
    "00:09:0f": "fortinet",
    "00:1d:71": "fortinet",
    "08:5b:0e": "fortinet",
    "70:4c:a5": "fortinet",
    "90:6c:ac": "fortinet",
    "e8:1c:ba": "fortinet",
    # Dahua
    "3c:ef:8c": "dahua",
    "4c:11:bf": "dahua",
    "90:02:a9": "dahua",
    "a0:bd:1d": "dahua",
    "b0:a7:32": "dahua",
    # Netgate / pfSense (commonly Dell / SuperMicro OUIs)
    "00:25:90": "supermicro",
    # Apple
    "00:03:93": "apple",
    "00:0a:95": "apple",
    "00:0d:93": "apple",
    "00:1c:b3": "apple",
    "00:25:00": "apple",
    "3c:15:c2": "apple",
    # Dell
    "00:14:22": "dell",
    "00:1e:c9": "dell",
    "18:a9:9b": "dell",
    "f8:bc:12": "dell",
    "b0:83:fe": "dell",
    # HPE / Aruba
    "00:1f:29": "hpe",
    "9c:8e:99": "hpe",
    # Juniper
    "00:05:85": "juniper",
    "00:12:1e": "juniper",
    # Synology
    "00:11:32": "synology",
    # QNAP
    "00:08:9b": "qnap",
}


def lookup_mac_vendor(mac: str | None) -> str | None:
    """Lookup vendor from MAC address OUI prefix."""
    if not mac:
        return None
    mac = mac.lower().replace("-", ":").replace(".", ":")
    prefix = mac[:8]
    return MAC_VENDOR_DB.get(prefix)


# =============================================================================
# NETWORK UTILITIES
# =============================================================================


# hard ceiling on materialized hosts (targets AND excludes), so a
# ScanConfig built programmatically (bypassing the ScanRequestSchema validator)
# can't blow up memory / stall the event loop by expanding 256 × /16 excludes
# into a ~16.7M-entry set. 4 × /16, matching MAX_SCAN_HOSTS_TOTAL in the schema.
_MAX_EXPAND_HOSTS = 262_144


class TargetExpansionLimitError(Exception):
    """expand_targets() would materialize more hosts than _MAX_EXPAND_HOSTS.

    Deliberately NOT a ValueError so the per-entry ``except ValueError`` (which
    only means "this entry is malformed, skip it") cannot swallow the limit and
    let the blow-up proceed.
    """


def _spec_host_count(spec: str) -> int:
    """O(1) estimate of how many hosts a single target/exclude spec expands to.

    Computed WITHOUT materializing the addresses (uses num_addresses / integer
    range arithmetic) so an oversized /8 is rejected before ~16M strings are
    built. Malformed specs return 0 (they'll be skipped during expansion).
    """
    try:
        if "/" in spec:
            return ipaddress.ip_network(spec, strict=False).num_addresses
        if "-" in spec:
            parts = spec.split("-")
            start_ip = ipaddress.ip_address(parts[0].strip())
            if "." in parts[1]:
                end_ip = ipaddress.ip_address(parts[1].strip())
            else:
                base = ".".join(parts[0].split(".")[:3])
                end_ip = ipaddress.ip_address(f"{base}.{parts[1].strip()}")
            return max(0, int(end_ip) - int(start_ip) + 1)
        return 1
    except ValueError:
        return 0


def expand_targets(targets: list[str], exclude: list[str] | None = None) -> set[str]:
    """
    Expand target specifications into individual IP addresses.
    Supports: single IPs, CIDR notation, IP ranges (192.168.1.1-254).

    Raises TargetExpansionLimitError if either the exclude pass or the target
    pass would exceed ``_MAX_EXPAND_HOSTS`` hosts (defense-in-depth
    for programmatic callers that bypass the ScanRequestSchema validator).
    """
    exclude = exclude or []
    result: set[str] = set()
    exclude_set: set[str] = set()

    # O(1) pre-check before materializing anything, so a single oversized CIDR
    # (e.g. a /8) is refused without building millions of strings.
    if sum(_spec_host_count(e) for e in exclude) > _MAX_EXPAND_HOSTS:
        raise TargetExpansionLimitError(
            f"exclude_targets expansion exceeds {_MAX_EXPAND_HOSTS} hosts — "
            "use coarser blocks or fewer entries."
        )
    if sum(_spec_host_count(t) for t in targets) > _MAX_EXPAND_HOSTS:
        raise TargetExpansionLimitError(
            f"targets expansion exceeds {_MAX_EXPAND_HOSTS} hosts — "
            "break the scan into smaller batches."
        )

    for exc in exclude:
        try:
            if "/" in exc:
                network = ipaddress.ip_network(exc, strict=False)
                exclude_set.update(str(ip) for ip in network.hosts())
            elif "-" in exc:
                parts = exc.split("-")
                start_ip = ipaddress.ip_address(parts[0].strip())
                end_ip = (
                    ipaddress.ip_address(parts[1].strip())
                    if "." in parts[1]
                    else ipaddress.ip_address(
                        ".".join(parts[0].split(".")[:3]) + "." + parts[1].strip()
                    )
                )
                while start_ip <= end_ip:
                    exclude_set.add(str(start_ip))
                    start_ip += 1
            else:
                exclude_set.add(exc)
        except ValueError:
            logger.warning("Invalid exclusion target: %s", exc)

    for target in targets:
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                for ip in network.hosts():
                    ip_str = str(ip)
                    if ip_str not in exclude_set:
                        result.add(ip_str)
            elif "-" in target:
                parts = target.split("-")
                start_ip = ipaddress.ip_address(parts[0].strip())
                if "." in parts[1]:
                    end_ip = ipaddress.ip_address(parts[1].strip())
                else:
                    base = ".".join(parts[0].split(".")[:3])
                    end_ip = ipaddress.ip_address(f"{base}.{parts[1].strip()}")
                while start_ip <= end_ip:
                    ip_str = str(start_ip)
                    if ip_str not in exclude_set:
                        result.add(ip_str)
                    start_ip += 1
            else:
                ipaddress.ip_address(target)
                if target not in exclude_set:
                    result.add(target)
        except ValueError as e:
            logger.warning("Invalid target: %s — %s", target, e)

    # Defense-in-depth SSRF guard: drop loopback / link-local
    # (incl. cloud metadata) / multicast / reserved / unspecified IPs even if a
    # ScanConfig was constructed programmatically, bypassing the schema validator.
    # RFC1918 is intentionally allowed — scanning on-prem gear is the point.
    _blocked_props = (
        "is_loopback",
        "is_link_local",
        "is_multicast",
        "is_reserved",
        "is_unspecified",
    )
    # Keep in sync with CLOUD_METADATA_IP_LITERALS (app/core/security_utils.py).
    _metadata = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200", "192.0.0.192"}
    safe: set[str] = set()
    for ip_str in result:
        try:
            ipobj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip_str in _metadata or any(getattr(ipobj, p, False) for p in _blocked_props):
            logger.warning("Dropping SSRF-blocked scan target: %s", ip_str)
            continue
        safe.add(ip_str)
    return safe


async def resolve_hostname(ip: str, timeout: float = 2.0) -> str | None:
    """Reverse DNS lookup."""
    try:
        loop = asyncio.get_running_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=timeout,
        )
        return result[0]
    except (TimeoutError, socket.herror, socket.gaierror, Exception):
        return None


# =============================================================================
# PORT SCANNER
# =============================================================================


class PortScanner:
    """Async TCP port scanner with banner grabbing."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrent_ports)

    async def scan_tcp_port(
        self, host: str, port: int, timeout: float | None = None
    ) -> tuple[int, bool, str | None]:
        timeout = timeout or self.config.tcp_timeout
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
                banner = None
                if self.config.probe_services:
                    try:
                        data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                        if data:
                            banner = data.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        logger.debug("Banner grab failed on %s:%s", host, port, exc_info=True)
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                return (port, True, banner)
            except (TimeoutError, ConnectionRefusedError, OSError):
                return (port, False, None)

    async def scan_tcp_ports(self, host: str, ports: list[int]) -> dict[int, dict[str, Any]]:
        tasks = [self.scan_tcp_port(host, port) for port in ports]
        completed = await asyncio.gather(*tasks, return_exceptions=True)
        results: dict[int, dict[str, Any]] = {}
        for result in completed:
            if isinstance(result, tuple):
                port, is_open, banner = result
                if is_open:
                    results[port] = {
                        "open": True,
                        "banner": banner,
                        "service": self._guess_service(port, banner),
                    }
        return results

    @staticmethod
    def _guess_service(port: int, banner: str | None) -> str | None:
        if banner:
            bl = banner.lower()
            if "ssh" in bl:
                return "ssh"
            if "http" in bl or "html" in bl:
                return "http"
            if "ftp" in bl:
                return "ftp"
            if "rtsp" in bl:
                return "rtsp"
        known = {
            22: "ssh",
            23: "telnet",
            80: "http",
            443: "https",
            554: "rtsp",
            8080: "http-alt",
            8443: "https-alt",
            8043: "omada-controller",
            29810: "omada-discovery",
            8000: "hikvision-sdk",
            161: "snmp",
            53: "dns",
        }
        return known.get(port)


# =============================================================================
# SERVICE PROBES
# =============================================================================


class ServiceProber:
    """Probes open ports to identify services and vendors."""

    HTTP_PORTS = {80, 443, 8080, 8443, 8043, 8088}

    def __init__(self, config: ScanConfig):
        self.config = config

    async def probe_http(self, host: str, port: int, use_ssl: bool | None = None) -> dict[str, Any]:
        """Probe HTTP/HTTPS service for vendor identification."""
        import httpx

        if use_ssl is None:
            use_ssl = port in {443, 8443}

        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{port}/"

        result: dict[str, Any] = {"service": "http", "ssl": use_ssl, "url": url}

        try:
            # NOTE: verify=False is required for scanning unknown devices (self-signed certs).
            # This is intentional for device discovery — never reuse this client for
            # user-facing or SSRF-sensitive requests.
            async with httpx.AsyncClient(
                verify=False,
                timeout=5.0,
                follow_redirects=False,
                max_redirects=0,
            ) as client:
                resp = await client.get(url)
                result["status_code"] = resp.status_code
                result["server"] = resp.headers.get("server")

                ct = resp.headers.get("content-type", "")
                if "html" in ct:
                    text = resp.text
                    match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                    if match:
                        result["title"] = match.group(1).strip()

                    # Vendor hints in HTML body
                    text_lower = text.lower()
                    for kw, vendor in [
                        ("omada", "omada_controller"),
                        ("hikvision", "hikvision"),
                        ("unifi", "unifi_controller"),
                        ("mikrotik", "mikrotik"),
                        ("routeros", "mikrotik"),
                        ("webfig", "mikrotik"),
                        ("pfsense", "pfsense"),
                        ("opnsense", "opnsense"),
                        ("fortinet", "fortinet"),
                        ("fortigate", "fortinet"),
                        ("synology", "synology"),
                        ("qnap", "qnap"),
                        ("grandstream", "grandstream"),
                    ]:
                        if kw in text_lower:
                            result["likely_type"] = vendor
                            break

                # Server header hints
                server = (result.get("server") or "").lower()
                for kw, vendor in [
                    ("hikvision", "hikvision"),
                    ("dahua", "dahua"),
                    ("davinci", "hikvision"),
                    ("mikrotik", "mikrotik"),
                    ("nginx", "generic_web"),
                    ("apache", "generic_web"),
                ]:
                    if kw in server:
                        result.setdefault("likely_type", vendor)
                        break

        except httpx.ConnectError:
            if use_ssl:
                return await self.probe_http(host, port, use_ssl=False)
            result["error"] = "connection_refused"
        except Exception as e:
            result["error"] = str(e)

        return result

    async def probe_rtsp(self, host: str, port: int = 554) -> dict[str, Any]:
        """Probe RTSP service (cameras/NVRs)."""
        result: dict[str, Any] = {"service": "rtsp", "port": port}
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3.0,
            )
            request = f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            response_str = response.decode("utf-8", errors="ignore")
            result["available"] = "RTSP/1.0 200 OK" in response_str
            for line in response_str.split("\r\n"):
                if line.lower().startswith("server:"):
                    result["server"] = line.split(":", 1)[1].strip()
                    break
        except Exception as e:
            result["error"] = str(e)
            result["available"] = False
        finally:
            # Release the connected socket on ALL paths — a drain()/read()
            # failure after open_connection succeeded must not leak the writer.
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
        return result

    async def probe_host(self, host: str, open_ports: list[int]) -> dict[int, dict[str, Any]]:
        results: dict[int, dict[str, Any]] = {}
        for port in open_ports:
            try:
                if port in self.HTTP_PORTS:
                    results[port] = await self.probe_http(host, port)
                elif port == 554:
                    results[port] = await self.probe_rtsp(host, port)
            except Exception as e:
                results[port] = {"error": str(e)}
        return results


# =============================================================================
# mDNS / SSDP DISCOVERY
# =============================================================================


class MDNSDiscovery:
    """mDNS/DNS-SD service discovery."""

    MDNS_SERVICES = [
        "_http._tcp.local.",
        "_https._tcp.local.",
        "_ssh._tcp.local.",
        "_telnet._tcp.local.",
        "_rtsp._tcp.local.",
        "_nvr._tcp.local.",
        "_workstation._tcp.local.",
        "_device-info._tcp.local.",
    ]

    async def discover(self, timeout: float = 5.0) -> list[DiscoveredHost]:
        discovered: list[DiscoveredHost] = []
        try:
            from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

            class Listener(ServiceListener):
                def __init__(self):
                    self.services: list[dict] = []

                def add_service(self, zc, type_, name):
                    info = zc.get_service_info(type_, name)
                    if info:
                        self.services.append(
                            {
                                "name": name,
                                "type": type_,
                                "addresses": [
                                    str(a)
                                    for a in (
                                        info.parsed_addresses()
                                        if hasattr(info, "parsed_addresses")
                                        else []
                                    )
                                ],
                                "port": info.port,
                            }
                        )

                def remove_service(self, zc, type_, name):
                    pass

                def update_service(self, zc, type_, name):
                    pass

            zc = Zeroconf()
            listener = Listener()
            [ServiceBrowser(zc, svc, listener) for svc in self.MDNS_SERVICES]
            await asyncio.sleep(timeout)

            hosts_by_ip: dict[str, DiscoveredHost] = {}
            for svc in listener.services:
                for addr in svc.get("addresses", []):
                    if addr not in hosts_by_ip:
                        hosts_by_ip[addr] = DiscoveredHost(ip_address=addr, discovered_via=["mdns"])
                    hosts_by_ip[addr].mdns_services.append(svc.get("type", ""))

            discovered = list(hosts_by_ip.values())
            zc.close()
        except ImportError:
            logger.info("zeroconf not installed — skipping mDNS discovery")
        except Exception as e:
            logger.error("mDNS discovery failed: %s", e)
        return discovered


class SSDPDiscovery:
    """SSDP/UPnP device discovery."""

    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    SEARCH_REQUEST = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )

    async def discover(self, timeout: float = 5.0) -> list[DiscoveredHost]:
        discovered: dict[str, DiscoveredHost] = {}
        try:
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.sendto(self.SEARCH_REQUEST.encode(), (self.SSDP_ADDR, self.SSDP_PORT))

            end_time = time.time() + timeout
            while time.time() < end_time:
                try:
                    data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=0.5)
                    ip = addr[0]
                    ssdp_info = {}
                    for line in data.decode("utf-8", errors="ignore").split("\r\n"):
                        if ":" in line:
                            key, value = line.split(":", 1)
                            ssdp_info[key.strip().lower()] = value.strip()
                    if ip not in discovered:
                        discovered[ip] = DiscoveredHost(
                            ip_address=ip, discovered_via=["ssdp"], ssdp_info=ssdp_info
                        )
                    elif discovered[ip].ssdp_info:
                        discovered[ip].ssdp_info.update(ssdp_info)
                    else:
                        discovered[ip].ssdp_info = ssdp_info
                except TimeoutError:
                    continue
            sock.close()
        except Exception as e:
            logger.error("SSDP discovery failed: %s", e)
        return list(discovered.values())


# =============================================================================
# MAIN NETWORK SCANNER
# =============================================================================


class NetworkScanner:
    """
    Main orchestrator for network device discovery.
    4-phase async scan pipeline.

    Usage:
        config = ScanConfig(targets=["192.168.1.0/24"])
        scanner = NetworkScanner(config)
        async for host in scanner.scan():
            print(host.ip_address, host.open_tcp_ports)
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.port_scanner = PortScanner(config)
        self.service_prober = ServiceProber(config)
        self.mdns = MDNSDiscovery()
        self.ssdp = SSDPDiscovery()
        self._cancelled = False
        self._progress: ScanProgress | None = None

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    async def scan(
        self,
        progress_callback: Callable[[ScanProgress], None] | None = None,
    ) -> AsyncIterator[DiscoveredHost]:
        """Run full 4-phase scan, yielding hosts as they are discovered."""
        self._cancelled = False
        scan_id = str(uuid4())

        targets = expand_targets(self.config.targets, self.config.exclude_targets)
        if len(targets) > self.config.max_hosts:
            logger.warning(
                "Target count %d exceeds limit %s, truncating", len(targets), self.config.max_hosts
            )
            targets = set(list(targets)[: self.config.max_hosts])

        self._progress = ScanProgress(
            scan_id=scan_id,
            started_at=datetime.now(UTC),
            total_hosts=len(targets),
        )
        self._emit(progress_callback)

        discovered: dict[str, DiscoveredHost] = {}

        # ── Phase 1: Protocol discovery (mDNS + SSDP) ──────────────
        if not self._cancelled:
            self._progress.current_phase = "protocol_discovery"
            self._emit(progress_callback)

            if ScanMethod.MDNS in self.config.methods:
                logger.info("Phase 1a: mDNS discovery…")
                for host in await self.mdns.discover(timeout=3.0):
                    if host.ip_address in targets:
                        discovered[host.ip_address] = host
                        yield host

            if ScanMethod.SSDP in self.config.methods:
                logger.info("Phase 1b: SSDP discovery…")
                for host in await self.ssdp.discover(timeout=3.0):
                    if host.ip_address in targets:
                        if host.ip_address in discovered:
                            discovered[host.ip_address].ssdp_info = host.ssdp_info
                            if "ssdp" not in discovered[host.ip_address].discovered_via:
                                discovered[host.ip_address].discovered_via.append("ssdp")
                        else:
                            discovered[host.ip_address] = host
                            yield host

            self._progress.phase_progress = 100.0
            self._emit(progress_callback)

        # ── Phase 2: Port scanning ──────────────────────────────────
        if not self._cancelled:
            self._progress.current_phase = "port_scanning"

            ports_to_scan = sorted(
                set(self.config.tcp_ports)
                | set(self.config.network_device_ports)
                | set(self.config.camera_ports)
            )

            target_list = sorted(targets)
            batch_size = self.config.max_concurrent_hosts

            for i in range(0, len(target_list), batch_size):
                if self._cancelled:
                    break
                batch = target_list[i : i + batch_size]
                tasks = [self._scan_host(ip, ports_to_scan) for ip in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for ip, result in zip(batch, results, strict=False):
                    if isinstance(result, Exception):
                        logger.debug("Scan failed for %s: %s", ip, result)
                        continue
                    if result and result.open_tcp_ports:
                        if ip in discovered:
                            existing = discovered[ip]
                            existing.open_tcp_ports = sorted(
                                set(existing.open_tcp_ports + result.open_tcp_ports)
                            )
                            existing.services.update(result.services)
                            if "tcp_scan" not in existing.discovered_via:
                                existing.discovered_via.append("tcp_scan")
                        else:
                            discovered[ip] = result
                            yield result

                self._progress.scanned_hosts = min(i + batch_size, len(target_list))
                self._progress.phase_progress = self._progress.progress_pct
                self._progress.discovered_hosts = len(discovered)
                self._progress.hosts_found = list(discovered.keys())
                self._emit(progress_callback)

        # ── Phase 3: Service probing ────────────────────────────────
        if not self._cancelled and self.config.probe_services:
            self._progress.current_phase = "service_probing"
            self._emit(progress_callback)

            for ip, host in discovered.items():
                if self._cancelled:
                    break
                if host.open_tcp_ports:
                    try:
                        probed = await self.service_prober.probe_host(ip, host.open_tcp_ports)
                        host.services.update(probed)

                        # Extract useful fields
                        for port_info in probed.values():
                            if isinstance(port_info, dict):
                                if port_info.get("title"):
                                    host.http_title = port_info["title"]
                                if port_info.get("server"):
                                    host.http_server = port_info["server"]

                        host.likely_device_types = self._classify_device(host)
                        host.vendor = host.vendor or self._detect_vendor(host)
                    except Exception as e:
                        logger.debug("Service probe failed for %s: %s", ip, e)

        # ── Phase 4: Hostname resolution ────────────────────────────
        if not self._cancelled and self.config.resolve_hostnames:
            self._progress.current_phase = "hostname_resolution"
            self._emit(progress_callback)

            tasks = [
                self._resolve_and_update(ip, host)
                for ip, host in discovered.items()
                if not host.hostname
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        # ── Finalize ────────────────────────────────────────────────
        self._progress.status = (
            ScanStatus.COMPLETED if not self._cancelled else ScanStatus.CANCELLED
        )
        self._progress.elapsed_seconds = (
            datetime.now(UTC) - self._progress.started_at
        ).total_seconds()
        self._progress.discovered_hosts = len(discovered)
        self._progress.hosts_found = list(discovered.keys())
        self._emit(progress_callback)

        logger.info(
            "Scan %s: discovered %d hosts out of %d targets in %.1fs",
            scan_id,
            len(discovered),
            len(targets),
            self._progress.elapsed_seconds,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _scan_host(self, ip: str, ports: list[int]) -> DiscoveredHost | None:
        port_results = await self.port_scanner.scan_tcp_ports(ip, ports)
        if not port_results:
            return None
        open_ports = sorted(p for p, info in port_results.items() if info.get("open"))
        return DiscoveredHost(
            ip_address=ip,
            open_tcp_ports=open_ports,
            services=port_results,
            discovered_via=["tcp_scan"],
            vendor=lookup_mac_vendor(None),
        )

    async def _resolve_and_update(self, ip: str, host: DiscoveredHost) -> None:
        hostname = await resolve_hostname(ip, timeout=2.0)
        if hostname:
            host.hostname = hostname

    def _classify_device(self, host: DiscoveredHost) -> list[str]:
        """Heuristic device type classification."""
        types: list[str] = []
        open_ports = set(host.open_tcp_ports)
        services = host.services

        # Controller detection
        controller_ports = {8043, 8443, 8080, 443}
        if open_ports & controller_ports:
            for port_info in services.values():
                if isinstance(port_info, dict):
                    lt = port_info.get("likely_type", "")
                    title = (port_info.get("title") or "").lower()
                    if "omada" in lt or "omada" in title:
                        types.append("omada_controller")
                    elif "unifi" in lt or "unifi" in title:
                        types.append("unifi_controller")
                    elif "mikrotik" in lt or "routeros" in title or "webfig" in title:
                        types.append("router")
                    elif (
                        "pfsense" in lt
                        or "opnsense" in lt
                        or "fortinet" in lt
                        or "fortigate" in title
                    ):
                        types.append("firewall")

        # Cameras
        if 554 in open_ports:
            types.append("camera")
            for port_info in services.values():
                if isinstance(port_info, dict):
                    server = (port_info.get("server") or "").lower()
                    if "hikvision" in server or "davinci" in server:
                        types.append("hikvision_camera")
                    elif "dahua" in server:
                        types.append("dahua_camera")

        # NVR (Hikvision SDK port)
        if 8000 in open_ports:
            types.append("nvr")

        # Managed network device (SSH/Telnet + web)
        if (22 in open_ports or 23 in open_ports) and (80 in open_ports or 443 in open_ports):
            if not any(t in types for t in ["camera", "omada_controller", "unifi_controller"]):
                types.append("managed_network_device")

        # Generic web device
        if (80 in open_ports or 443 in open_ports) and not types:
            types.append("web_device")

        return list(dict.fromkeys(types))  # de-dup preserving order

    def _detect_vendor(self, host: DiscoveredHost) -> str | None:
        """Detect vendor from service probe results."""
        for port_info in host.services.values():
            if isinstance(port_info, dict):
                lt = port_info.get("likely_type")
                if lt and lt not in ("generic_web",):
                    return lt
        return host.vendor

    def cancel(self) -> None:
        self._cancelled = True
        if self._progress:
            self._progress.status = ScanStatus.CANCELLED

    @property
    def progress(self) -> ScanProgress | None:
        return self._progress

    def _emit(self, cb: Callable[[ScanProgress], None] | None) -> None:
        if cb and self._progress:
            try:
                cb(self._progress)
            except Exception:
                logger.debug("Scan progress callback failed", exc_info=True)


# =============================================================================
# CONVENIENCE
# =============================================================================


async def quick_scan(targets: list[str], ports: list[int] | None = None) -> list[DiscoveredHost]:
    """Quick scan with default settings."""
    config = ScanConfig(targets=targets)
    if ports:
        config.tcp_ports = ports
    scanner = NetworkScanner(config)
    discovered = []
    async for host in scanner.scan():
        discovered.append(host)
    return discovered

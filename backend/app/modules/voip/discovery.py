# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - VoIP Network Discovery Scanner
=============================================

GDMS-style network device discovery engine.

Scans networks for VoIP devices using multiple methods:
  - ARP scan: Fast MAC-based discovery using subnet sweep
  - HTTP probe: Detect Grandstream/Yealink web UIs
  - SIP OPTIONS: Probe SIP endpoints for registration info
  - Combined full scan: All methods merged & deduplicated

Designed for enterprise safety:
  - Respects concurrency limits (semaphore-bounded)
  - Timeout-guarded per-host probes
  - Non-intrusive (read-only queries)
  - Results stored in DB for review before onboarding
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from app.core.http_client import build_aiohttp_session
from app.core.security_utils import is_ssrf_blocked_ip

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

# Maximum concurrent probes to avoid network saturation
_MAX_CONCURRENT_PROBES = 50

# Per-host probe timeout (seconds)
_PROBE_TIMEOUT = 4.0

# Known VoIP vendor OUI prefixes (first 3 octets of MAC)
_VOIP_OUI_MAP: dict[str, str] = {
    # Grandstream
    "000b82": "grandstream",
    "c074ad": "grandstream",
    "7c2f80": "grandstream",
    # Yealink
    "805ec0": "yealink",
    "001565": "yealink",
    "805e4a": "yealink",
    # Polycom / Poly
    "0004f2": "polycom",
    "64167f": "polycom",
    # Cisco / Linksys IP Phones
    "001bd4": "cisco",
    "fcfbfb": "cisco",
    "0023eb": "cisco",
    # Fanvil
    "0c383e": "fanvil",
    # Snom
    "000413": "snom",
    # Obihai / Obi
    "9cadef": "obihai",
    # Digium/Sangoma
    "001fc6": "sangoma",
}

# HTTP paths to probe for VoIP phone web UIs
_HTTP_PROBE_PATHS = [
    # Grandstream
    ("/cgi-bin/api.values.get?request=P35", "grandstream"),
    # Yealink
    ("/servlet?m=mod_data&p=status-dev&q=load", "yealink"),
    # Generic SIP phone
    ("/", None),
]

# SIP OPTIONS request template
_SIP_OPTIONS_TEMPLATE = (
    "OPTIONS sip:{host}:{port} SIP/2.0\r\n"
    "Via: SIP/2.0/UDP {local_ip}:5060;branch=z9hG4bK-freesdn-disc\r\n"
    "From: <sip:scanner@freesdn.local>;tag=freesdn-scan\r\n"
    "To: <sip:{host}:{port}>\r\n"
    "Call-ID: freesdn-discovery@{local_ip}\r\n"
    "CSeq: 1 OPTIONS\r\n"
    "Max-Forwards: 0\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class DiscoveredPhone:
    """Result from a single device probe."""

    ip_address: str
    mac_address: str | None = None
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    discovery_methods: list[str] = field(default_factory=list)
    sip_registered: bool = False
    sip_user_agent: str | None = None
    sip_account: str | None = None
    sip_registrar: str | None = None
    http_reachable: bool = False
    http_title: str | None = None
    authenticated: bool = False
    raw_data: dict[str, Any] = field(default_factory=dict)

    def merge(self, other: DiscoveredPhone) -> None:
        """Merge another probe result into this one (same IP)."""
        if other.mac_address and not self.mac_address:
            self.mac_address = other.mac_address
        if other.vendor and not self.vendor:
            self.vendor = other.vendor
        if other.model and not self.model:
            self.model = other.model
        if other.firmware_version and not self.firmware_version:
            self.firmware_version = other.firmware_version
        if other.serial_number and not self.serial_number:
            self.serial_number = other.serial_number
        if other.sip_registered:
            self.sip_registered = True
        if other.sip_user_agent:
            self.sip_user_agent = other.sip_user_agent
        if other.sip_account and not self.sip_account:
            self.sip_account = other.sip_account
        if other.sip_registrar and not self.sip_registrar:
            self.sip_registrar = other.sip_registrar
        if other.http_reachable:
            self.http_reachable = True
        if other.http_title:
            self.http_title = other.http_title
        if other.authenticated:
            self.authenticated = True
        for method in other.discovery_methods:
            if method not in self.discovery_methods:
                self.discovery_methods.append(method)
        self.raw_data.update(other.raw_data)


# =============================================================================
# OUI / Vendor Detection
# =============================================================================


def identify_vendor_by_mac(mac: str) -> str | None:
    """Identify VoIP vendor from MAC address OUI prefix."""
    clean = mac.replace(":", "").replace("-", "").replace(".", "").lower()
    if len(clean) < 6:
        return None
    oui = clean[:6]
    return _VOIP_OUI_MAP.get(oui)


def is_voip_device_mac(mac: str) -> bool:
    """Check if MAC address belongs to a known VoIP vendor."""
    return identify_vendor_by_mac(mac) is not None


# =============================================================================
# ARP Scanner
# =============================================================================


async def arp_scan_subnet(
    subnet: str,
    semaphore: asyncio.Semaphore | None = None,
) -> list[DiscoveredPhone]:
    """
    Scan a subnet for VoIP devices using ARP table inspection.

    Strategy:
    1. Ping-sweep the subnet to populate the ARP table
    2. Read ARP table and filter for known VoIP OUIs
    3. Return discovered phones

    This is cross-platform (uses subprocess for arp commands).
    """
    sem = semaphore or asyncio.Semaphore(_MAX_CONCURRENT_PROBES)
    results: list[DiscoveredPhone] = []

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        logger.error("Invalid subnet: %s", subnet)
        return results

    # Limit scan to /16 max (65534 hosts) to prevent abuse
    if network.num_addresses > 65536:
        logger.error("Subnet too large: %s (%d hosts)", subnet, network.num_addresses)
        return results

    # Step 1: Concurrent ping sweep to populate ARP cache
    logger.info("Starting ARP scan of %s (%d hosts)", subnet, network.num_addresses - 2)

    async def ping_host(ip: str) -> None:
        async with sem:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ping",
                    "-n",
                    "1",
                    "-w",
                    "500",
                    str(ip),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except (TimeoutError, OSError):
                pass

    # Ping all hosts concurrently
    # SSRF guard: drop loopback / link-local / metadata / multicast / reserved
    # IPs before any credentialed probe, even if a network slipped past the
    # schema validator. RFC1918 LAN hosts (the real targets) pass through.
    hosts = [str(h) for h in network.hosts() if not is_ssrf_blocked_ip(str(h))]
    # Process in batches to avoid overwhelming the system
    batch_size = 200
    for i in range(0, len(hosts), batch_size):
        batch = hosts[i : i + batch_size]
        await asyncio.gather(*[ping_host(ip) for ip in batch])

    # Step 2: Read ARP table
    arp_entries = await _read_arp_table()

    # Step 3: Filter for VoIP OUIs
    for ip, mac in arp_entries.items():
        # Only consider IPs in our target subnet
        try:
            if ipaddress.ip_address(ip) not in network:
                continue
        except ValueError:
            continue

        vendor = identify_vendor_by_mac(mac)
        if vendor:
            results.append(
                DiscoveredPhone(
                    ip_address=ip,
                    mac_address=_normalize_mac(mac),
                    vendor=vendor,
                    discovery_methods=["arp_scan"],
                )
            )

    logger.info("ARP scan of %s found %d VoIP devices", subnet, len(results))
    return results


async def _read_arp_table() -> dict[str, str]:
    """Read the system ARP table. Returns {ip: mac} dict."""
    entries: dict[str, str] = {}

    try:
        # Windows: arp -a
        proc = await asyncio.create_subprocess_exec(
            "arp",
            "-a",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        output = stdout.decode("utf-8", errors="replace")

        # Parse Windows ARP output: "  192.168.1.1     00-0b-82-xx-xx-xx     dynamic"
        for line in output.splitlines():
            match = re.match(
                r"\s*([\d.]+)\s+([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-]"
                r"[\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})\s+",
                line,
            )
            if match:
                ip_addr = match.group(1)
                mac_addr = match.group(2)
                if mac_addr.lower() not in ("ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00"):
                    entries[ip_addr] = mac_addr

    except (TimeoutError, OSError, FileNotFoundError) as exc:
        logger.warning("Failed to read ARP table: %s", exc)

    return entries


# =============================================================================
# HTTP Probe
# =============================================================================


async def http_probe_host(
    ip: str,
    semaphore: asyncio.Semaphore | None = None,
    timeout: float = _PROBE_TIMEOUT,
    credentials: dict[str, str] | None = None,
) -> DiscoveredPhone | None:
    """
    Probe a single IP for VoIP phone web UI via HTTP.

    Tries known vendor-specific paths and falls back to generic detection.

    Args:
        credentials: {"username": ..., "password": ...} for phone web UI login.
                     Defaults to admin/admin if not provided.
    """
    sem = semaphore or asyncio.Semaphore(_MAX_CONCURRENT_PROBES)
    creds = credentials or {"username": "admin", "password": "admin"}
    async with sem:
        conn = aiohttp.TCPConnector(ssl=False)
        client_timeout = aiohttp.ClientTimeout(total=timeout, connect=2.0)
        # CookieJar(unsafe=True) required for Grandstream phones — they set
        # session-role / session-identity cookies over plain HTTP and the
        # default safe jar rejects non-HTTPS Set-Cookie headers.
        jar = aiohttp.CookieJar(unsafe=True)

        async with build_aiohttp_session(
            connector=conn,
            timeout=client_timeout,
            cookie_jar=jar,
        ) as session:
            # Try Grandstream API first (most reliable detection)
            result = await _probe_grandstream(session, ip, creds)
            if result:
                return result

            # Try Yealink
            result = await _probe_yealink(session, ip, creds)
            if result:
                return result

            # Try generic HTTP (check page title for phone keywords)
            result = await _probe_generic_http(session, ip)
            if result:
                return result

    return None


async def _probe_grandstream(
    session: aiohttp.ClientSession,
    ip: str,
    credentials: dict[str, str] | None = None,
) -> DiscoveredPhone | None:
    """Probe for Grandstream phone web UI with full login support.

    Multi-phase discovery approach (based on reverse-engineered GWT/SJCL flow):

    Phase 1: Unauthenticated device identification
      - P67 = MAC address (always accessible)
      - P68 = firmware version (always accessible)
      - /cgi-bin/metaconfig_get = full config schema (model inference)

    Phase 2: Challenge-response login via /cgi-bin/access + /cgi-bin/dologin
      - Step 1: POST /cgi-bin/access  body=access=SHA256(username) → challenge token
      - Step 2: POST /cgi-bin/dologin body=username=<user>&password=SHA256(password+token) → SID
      - Session cookies (session-role, session-identity) stored via CookieJar

    Phase 3: Authenticated data retrieval
      - SIP account P-values (P35/userid, P47/server, P3/subscriber, P270/name)
      - /cgi-bin/api-get_accounts?registered=true for SIP registration

    Phase 4: GWT JavaScript fallback for model detection
    """
    import hashlib
    import json as _json

    creds = credentials or {"username": "admin", "password": "admin"}
    username = creds.get("username", "admin")
    password = creds.get("password", "admin")

    phone = DiscoveredPhone(
        ip_address=ip,
        vendor="grandstream",
        http_reachable=True,
        discovery_methods=["http_probe"],
    )

    # Correct P-value map (verified by /cgi-bin/metaconfig_get analysis):
    # P67  = MAC address (always accessible without auth)
    # P68  = firmware version (always accessible without auth)
    # P35  = account.1.sip.userid (SIP User ID for account 1)
    # P47  = account.1.sip.server.1.address (SIP server)
    # P3   = account.1.sip.subscriber.name
    # P270 = account.1.name (account display name)
    # P36  = account.1.sip.subscriber.userid
    # P34  = account.1.sip.subscriber.password
    # P31  = account.1.sip.registration (Yes/No)
    # P130 = account.1.sip.transport (UDP/TCP/TLS)
    _IDENTITY_PVALUES = "P67:P68"
    _SIP_PVALUES = "P35:P47:P3:P270:P271:P31:P130:P36"
    _ALL_PVALUES = f"{_IDENTITY_PVALUES}:{_SIP_PVALUES}"

    # Browser-like headers required by Grandstream lighttpd CGI
    _BROWSER_HEADERS = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"http://{ip}/",
        "Origin": f"http://{ip}",
        "User-Agent": "Mozilla/5.0 (FreeSDN VoIP Discovery)",
    }

    def _apply_pvalues(body_text: str) -> None:
        """Extract P-values from JSON or key=value format."""
        try:
            data = _json.loads(body_text)
            if isinstance(data, dict) and "body" in data:
                body_dict = data["body"]
                if isinstance(body_dict, dict):
                    for key, val in body_dict.items():
                        if not val:
                            continue
                        key_upper = key.strip().upper()
                        # Device identity
                        if key_upper == "P67":
                            phone.mac_address = _normalize_mac(val)
                        elif key_upper == "P68":
                            phone.firmware_version = val
                        # SIP account 1
                        elif key_upper == "P35":
                            # account.1.sip.userid
                            if not phone.sip_account:
                                phone.sip_account = val
                        elif key_upper == "P47":
                            # account.1.sip.server.1.address
                            phone.sip_registrar = val
                        elif key_upper in ("P3", "P270", "P271"):
                            # subscriber name / account name
                            if not phone.sip_account and val:
                                phone.sip_account = val
                        elif key_upper == "P31":
                            # account.1.sip.registration = "Yes"/"No"
                            if val.lower() == "yes":
                                phone.sip_registered = True
                        elif key_upper == "P36":
                            # subscriber userid — fallback for sip_account
                            if not phone.sip_account and val:
                                phone.sip_account = val
                        phone.raw_data[key_upper] = val
                    return
        except (ValueError, KeyError):
            pass

        # Fallback: line-based key=value (older firmware)
        for line in body_text.splitlines():
            line = line.strip()
            if "=" in line:
                key, _, val = line.partition("=")
                key, val = key.strip().upper(), val.strip()
                if not val:
                    continue
                if key == "P67":
                    phone.mac_address = _normalize_mac(val)
                elif key == "P68":
                    phone.firmware_version = val
                elif key == "P35":
                    if not phone.sip_account:
                        phone.sip_account = val
                elif key == "P47":
                    phone.sip_registrar = val
                elif key in ("P3", "P270", "P271"):
                    if not phone.sip_account and val:
                        phone.sip_account = val
                elif key == "P31" and val.lower() == "yes":
                    phone.sip_registered = True
                phone.raw_data[key] = val

    def _infer_model_from_metaconfig(mc_data: list[dict]) -> str | None:
        """Infer Grandstream model from metaconfig_get config schema.

        Different models expose different numbers of SIP accounts and features:
        - GXP2170: 6 accounts, 209 VPK entries, Bluetooth
        - GXP2160: 6 accounts, fewer VPKs, no Bluetooth
        - GXP2140: 4 accounts
        - GXP1625: 2 accounts
        - GRP2614: 4 accounts, Wi-Fi
        """
        if not mc_data:
            return None
        aliases = {item.get("alias", "") for item in mc_data}
        num_accounts = sum(1 for a in aliases if a.startswith("account.") and a.endswith(".name"))
        has_bluetooth = any("bluetooth" in a for a in aliases)
        has_vpk = sum(1 for a in aliases if a.startswith("pks.vpk"))
        has_wifi = any("wifi" in a.lower() for a in aliases)

        if num_accounts >= 6:
            if has_bluetooth and has_vpk > 200:
                return "GXP2170"
            return "GXP2160"
        elif num_accounts >= 4:
            if has_wifi:
                return "GRP2614"
            return "GXP2140"
        elif num_accounts >= 2:
            return "GXP1625"
        return "Grandstream"

    try:
        api_url = f"http://{ip}/cgi-bin/api.values.get"

        # ── Phase 1: Unauthenticated device identification ──────────────
        # P67 (MAC) and P68 (firmware) are always accessible
        async with session.get(api_url, params={"request": _IDENTITY_PVALUES}) as resp:
            if resp.status != 200:
                return None
            body = await resp.text()
            _apply_pvalues(body)

        if phone.mac_address:
            logger.debug(
                "Grandstream %s: MAC=%s FW=%s (unauthenticated P67/P68)",
                ip,
                phone.mac_address,
                phone.firmware_version,
            )

        # Try metaconfig_get for model inference (no auth required)
        try:
            async with session.get(f"http://{ip}/cgi-bin/metaconfig_get") as mc_resp:
                if mc_resp.status == 200:
                    mc_text = await mc_resp.text()
                    try:
                        mc_data = _json.loads(mc_text)
                        if isinstance(mc_data, list) and len(mc_data) > 100:
                            phone.model = _infer_model_from_metaconfig(mc_data)
                            phone.raw_data["_metaconfig_items"] = len(mc_data)
                            logger.debug(
                                "Grandstream %s: model=%s (inferred from %d config items)",
                                ip,
                                phone.model,
                                len(mc_data),
                            )
                    except (ValueError, KeyError):
                        pass
        except (TimeoutError, aiohttp.ClientError):
            pass

        # Try to get SIP P-values (may work without auth on some firmware)
        try:
            async with session.get(api_url, params={"request": _SIP_PVALUES}) as sip_resp:
                if sip_resp.status == 200:
                    sip_body = await sip_resp.text()
                    _apply_pvalues(sip_body)
        except (TimeoutError, aiohttp.ClientError):
            pass

        # If we have model and SIP info, we're done (no auth needed)
        if phone.model and phone.sip_account:
            return phone

        # ── Phase 2: Challenge-response login ───────────────────────
        # Reverse-engineered from GWT/SJCL JavaScript (SignInPresenter):
        # Step 1: POST /cgi-bin/access  body=access=SHA256(username)
        #         → {"response":"success","body":"<31-char-token>"}
        # Step 2: POST /cgi-bin/dologin body=username=<user>&password=SHA256(password+token)
        #         → {"response":"success","body":{"sid":"...","role":"admin",...}}
        # The phone also sets session-role + session-identity cookies via
        # Set-Cookie headers; subsequent authenticated requests rely on these.
        passwords_to_try = [password]
        if password != "admin":
            passwords_to_try.append("admin")

        sid = ""
        for pw in passwords_to_try:
            try:
                login_headers = {
                    **_BROWSER_HEADERS,
                    "Content-Type": "application/x-www-form-urlencoded",
                }

                # Step 1: Request challenge token from /cgi-bin/access
                access_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()
                async with session.post(
                    f"http://{ip}/cgi-bin/access",
                    data=f"access={access_hash}",
                    headers=login_headers,
                ) as access_resp:
                    if access_resp.status != 200:
                        continue
                    access_text = await access_resp.text()
                    access_data = _json.loads(access_text)
                    if access_data.get("response") != "success":
                        continue
                    token = access_data.get("body", "")
                    if not token or not isinstance(token, str):
                        continue

                # Step 2: Login with SHA256(password + token)
                login_hash = hashlib.sha256((pw + token).encode("utf-8")).hexdigest()
                login_body = f"username={username}&password={login_hash}"

                async with session.post(
                    f"http://{ip}/cgi-bin/dologin",
                    data=login_body,
                    headers=login_headers,
                ) as login_resp:
                    if login_resp.status != 200:
                        continue
                    login_text = await login_resp.text()
                    login_data = _json.loads(login_text)
                    if login_data.get("response") != "success":
                        continue
                    resp_body = login_data.get("body", {})
                    if isinstance(resp_body, dict):
                        sid = resp_body.get("sid", "")
                        # session cookies are set automatically by CookieJar

                if sid:
                    phone.authenticated = True
                    logger.debug("Grandstream %s: login success (sid=%s...)", ip, sid[:8])
                    break
            except (TimeoutError, aiohttp.ClientError, OSError, ValueError, KeyError):
                continue

        # ── Phase 3: Authenticated data retrieval ───────────────────────
        # Session cookies (session-role, session-identity) are already stored
        # in the CookieJar from the dologin Set-Cookie headers.
        if sid:
            # Fetch SIP P-values — cookies sent automatically by CookieJar
            try:
                async with session.get(
                    api_url,
                    params={"request": _ALL_PVALUES},
                    headers=_BROWSER_HEADERS,
                ) as auth_resp:
                    if auth_resp.status == 200:
                        auth_body = await auth_resp.text()
                        _apply_pvalues(auth_body)
            except (TimeoutError, aiohttp.ClientError):
                pass

            # Try api-get_accounts for SIP registration status
            try:
                async with session.get(
                    f"http://{ip}/cgi-bin/api-get_accounts",
                    params={"registered": "true"},
                    headers=_BROWSER_HEADERS,
                ) as acct_resp:
                    if acct_resp.status == 200:
                        acct_text = await acct_resp.text()
                        try:
                            acct_data = _json.loads(acct_text)
                            if isinstance(acct_data, dict):
                                acct_body = acct_data.get("body", {})
                                if isinstance(acct_body, list) and acct_body:
                                    phone.sip_registered = True
                                    phone.raw_data["_registered_accounts"] = acct_body
                                elif isinstance(acct_body, dict):
                                    phone.raw_data["_accounts_info"] = acct_body
                        except (ValueError, KeyError):
                            pass
            except (TimeoutError, aiohttp.ClientError):
                pass
        else:
            # No session — try HTTP Basic Auth as fallback
            for pw in passwords_to_try:
                try:
                    basic_auth = aiohttp.BasicAuth(username, pw)
                    async with session.get(
                        api_url,
                        params={"request": _ALL_PVALUES},
                        auth=basic_auth,
                    ) as auth_resp:
                        if auth_resp.status == 200:
                            auth_body = await auth_resp.text()
                            _apply_pvalues(auth_body)
                            if phone.sip_account:
                                phone.authenticated = True
                                break
                except (TimeoutError, aiohttp.ClientError):
                    pass

        if phone.model and (phone.mac_address or phone.sip_account):
            logger.debug(
                "Grandstream %s: model=%s mac=%s sip=%s auth=%s",
                ip,
                phone.model,
                phone.mac_address,
                phone.sip_account,
                phone.authenticated,
            )
            return phone

        # ── Phase 4: GWT JavaScript fallback for model detection ────────
        if not phone.model:
            try:
                async with session.get(f"http://{ip}/") as root_resp:
                    if root_resp.status == 200:
                        html = await root_resp.text()
                        import re as _re

                        # Check if this is a Grandstream GWT app
                        if "webapp.nocache.js" in html:
                            # Find the GWT permutation JS file
                            nocache_url = f"http://{ip}/webapp/webapp.nocache.js"
                            try:
                                async with session.get(nocache_url) as nc_resp:
                                    if nc_resp.status == 200:
                                        nc_text = await nc_resp.text()
                                        perm_match = _re.search(r"([A-F0-9]{32})", nc_text)
                                        if perm_match:
                                            perm_hash = perm_match.group(1)
                                            cache_url = f"http://{ip}/webapp/{perm_hash}.cache.js"
                                            async with session.get(cache_url) as cache_resp:
                                                if cache_resp.status == 200:
                                                    cache_text = await cache_resp.text()
                                                    model_match = _re.search(
                                                        r"\b(GXP\d{4}|GRP\d{4}"
                                                        r"|GXV\d{4}|DP\d{3,4}"
                                                        r"|WP\d{3,4}|HT\d{3})\b",
                                                        cache_text,
                                                    )
                                                    if model_match:
                                                        phone.model = model_match.group(1)
                            except (TimeoutError, aiohttp.ClientError):
                                pass

                        # Also check generic JS files
                        if not phone.model:
                            js_files = _re.findall(r'src="([^"]*\.js[^"]*)"', html)
                            for js_path in js_files[:3]:
                                js_url = (
                                    f"http://{ip}/{js_path}"
                                    if not js_path.startswith("/")
                                    else f"http://{ip}{js_path}"
                                )
                                try:
                                    async with session.get(js_url) as js_resp:
                                        if js_resp.status == 200:
                                            js_text = await js_resp.text()
                                            model_match = _re.search(
                                                r"\b(GXP\d{4}|GRP\d{4}"
                                                r"|GXV\d{4}|DP\d{3,4}"
                                                r"|WP\d{3,4}|HT\d{3})\b",
                                                js_text,
                                            )
                                            if model_match:
                                                phone.model = model_match.group(1)
                                                break
                                except (TimeoutError, aiohttp.ClientError):
                                    pass
            except (TimeoutError, aiohttp.ClientError, OSError):
                pass

        # Always return the phone — we at least know it's Grandstream
        if phone.model:
            logger.debug("Grandstream %s: model=%s (GWT JS fallback)", ip, phone.model)
        elif phone.mac_address or phone.firmware_version:
            logger.debug(
                "Grandstream %s: identified (MAC=%s, FW=%s) but model unknown",
                ip,
                phone.mac_address,
                phone.firmware_version,
            )
        else:
            logger.debug(
                "Grandstream %s: vendor detected but no details retrieved",
                ip,
            )

        return phone

    except (TimeoutError, aiohttp.ClientError, OSError):
        pass
    return None


async def _probe_yealink(
    session: aiohttp.ClientSession,
    ip: str,
    credentials: dict[str, str] | None = None,
) -> DiscoveredPhone | None:
    """Probe for Yealink phone web UI with auth support."""
    creds = credentials or {"username": "admin", "password": "admin"}
    try:
        url = f"http://{ip}/servlet"
        params = {"m": "mod_data", "p": "status-dev", "q": "load"}

        # Try unauthenticated first, then with basic auth
        for auth in [None, aiohttp.BasicAuth(creds["username"], creds["password"])]:
            try:
                async with session.get(url, params=params, auth=auth) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if "Yealink" in body or "yealink" in body:
                            phone = DiscoveredPhone(
                                ip_address=ip,
                                vendor="yealink",
                                http_reachable=True,
                                authenticated=auth is not None,
                                discovery_methods=["http_probe"],
                            )
                            # Try to extract model/firmware from response
                            model_match = re.search(r'"model"\s*:\s*"([^"]+)"', body)
                            if model_match:
                                phone.model = model_match.group(1)
                            fw_match = re.search(r'"firmware"\s*:\s*"([^"]+)"', body)
                            if fw_match:
                                phone.firmware_version = fw_match.group(1)
                            mac_match = re.search(r'"mac"\s*:\s*"([^"]+)"', body)
                            if mac_match:
                                phone.mac_address = _normalize_mac(mac_match.group(1))
                            # SIP registration status from Yealink servlet
                            sip_match = re.search(r'"sip_server"\s*:\s*"([^"]+)"', body)
                            if sip_match:
                                phone.sip_registrar = sip_match.group(1)
                            reg_match = re.search(r'"sip_register"\s*:\s*"([^"]+)"', body)
                            if reg_match and reg_match.group(1).lower() in (
                                "registered",
                                "yes",
                                "1",
                            ):
                                phone.sip_registered = True
                            acct_match = re.search(r'"sip_user"\s*:\s*"([^"]+)"', body)
                            if acct_match:
                                phone.sip_account = acct_match.group(1)
                            return phone
                    elif resp.status == 401 and auth is None:
                        continue  # Try with auth
                    else:
                        break
            except (TimeoutError, aiohttp.ClientError):
                break  # Network issue, don't retry
    except (TimeoutError, aiohttp.ClientError, OSError):
        pass
    return None


async def _probe_generic_http(session: aiohttp.ClientSession, ip: str) -> DiscoveredPhone | None:
    """Generic HTTP probe — check page title for VoIP keywords."""
    try:
        async with session.get(f"http://{ip}/", allow_redirects=True) as resp:
            if resp.status == 200:
                body = await resp.text(encoding="utf-8", errors="replace")
                body_lower = body.lower()

                # Check for phone-related keywords in title or body
                phone_keywords = [
                    "ip phone",
                    "sip phone",
                    "voip phone",
                    "grandstream",
                    "yealink",
                    "polycom",
                    "fanvil",
                    "cisco ip phone",
                    "snom",
                ]
                for keyword in phone_keywords:
                    if keyword in body_lower:
                        # Try to extract title
                        title_match = re.search(r"<title>([^<]+)</title>", body, re.I)
                        title = title_match.group(1).strip() if title_match else None

                        # Guess vendor from keyword
                        vendor = None
                        for v in ("grandstream", "yealink", "polycom", "fanvil", "cisco", "snom"):
                            if v in body_lower:
                                vendor = v
                                break

                        return DiscoveredPhone(
                            ip_address=ip,
                            vendor=vendor,
                            http_reachable=True,
                            http_title=title,
                            discovery_methods=["http_probe"],
                        )
    except (TimeoutError, aiohttp.ClientError, OSError):
        pass
    return None


# =============================================================================
# SIP OPTIONS Probe
# =============================================================================


async def sip_probe_host(
    ip: str,
    port: int = 5060,
    semaphore: asyncio.Semaphore | None = None,
    timeout: float = _PROBE_TIMEOUT,
) -> DiscoveredPhone | None:
    """
    Send SIP OPTIONS to a host and parse the response.

    Extracts User-Agent (device model/firmware) and contact info
    from the SIP response headers.
    """
    sem = semaphore or asyncio.Semaphore(_MAX_CONCURRENT_PROBES)
    async with sem:
        try:
            # Get local IP for Via header
            local_ip = await _get_local_ip()

            message = _SIP_OPTIONS_TEMPLATE.format(host=ip, port=port, local_ip=local_ip).encode(
                "utf-8"
            )

            transport, protocol = await asyncio.wait_for(
                asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: _SIPProbeProtocol(),
                    remote_addr=(ip, port),
                ),
                timeout=2.0,
            )
            try:
                transport.sendto(message)
                response = await asyncio.wait_for(protocol.response_future, timeout=timeout)
            finally:
                transport.close()

            if response:
                return _parse_sip_response(ip, response)

        except (TimeoutError, OSError, Exception) as exc:
            logger.debug("SIP probe failed for %s:%d: %s", ip, port, exc)

    return None


class _SIPProbeProtocol(asyncio.DatagramProtocol):
    """Simple UDP protocol for SIP OPTIONS probe."""

    def __init__(self) -> None:
        self.response_future: asyncio.Future[bytes | None] = (
            asyncio.get_running_loop().create_future()
        )

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.response_future.done():
            self.response_future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.response_future.done():
            self.response_future.set_result(None)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.response_future.done():
            self.response_future.set_result(None)


def _parse_sip_response(ip: str, data: bytes) -> DiscoveredPhone | None:
    """Parse a SIP response for device info and registration status.

    Extracts:
    - User-Agent (vendor/model/firmware)
    - Server header
    - Contact header (indicates SIP registration)
    - Allow header (supported SIP methods)
    - Response status code (200=responsive, 401=auth required, etc.)
    """
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")

        if not lines or not lines[0].startswith("SIP/2.0"):
            return None

        # Parse status code from first line: "SIP/2.0 200 OK"
        status_parts = lines[0].split(" ", 2)
        sip_status_code = int(status_parts[1]) if len(status_parts) >= 2 else 0

        phone = DiscoveredPhone(
            ip_address=ip,
            sip_registered=sip_status_code == 200,
            discovery_methods=["sip_probe"],
        )
        phone.raw_data["sip_status_code"] = sip_status_code

        for line in lines[1:]:
            if ":" not in line:
                continue
            header, _, value = line.partition(":")
            header = header.strip().lower()
            value = value.strip()

            if header == "user-agent":
                phone.sip_user_agent = value
                vendor, model, fw = _parse_sip_user_agent(value)
                if vendor:
                    phone.vendor = vendor
                if model:
                    phone.model = model
                if fw:
                    phone.firmware_version = fw
            elif header == "server":
                phone.raw_data["sip_server"] = value
                # Also parse server header for vendor/model if User-Agent missing
                if not phone.sip_user_agent:
                    phone.sip_user_agent = value
                    vendor, model, fw = _parse_sip_user_agent(value)
                    if vendor and not phone.vendor:
                        phone.vendor = vendor
                    if model and not phone.model:
                        phone.model = model
                    if fw and not phone.firmware_version:
                        phone.firmware_version = fw
            elif header == "contact":
                # Contact header shows registered URI
                # e.g. <sip:1001@192.0.2.10:5060>
                phone.raw_data["sip_contact"] = value
                contact_match = re.search(r"sip:([^@]+)@", value)
                if contact_match:
                    phone.sip_account = contact_match.group(1)
                    phone.sip_registered = True
            elif header == "allow":
                phone.raw_data["sip_allow"] = value

        return phone

    except Exception:
        return None


def _parse_sip_user_agent(ua: str) -> tuple[str | None, str | None, str | None]:
    """Extract vendor, model, firmware from SIP User-Agent header."""
    ua_lower = ua.lower()
    vendor = None
    model = None
    firmware = None

    # Grandstream: "Grandstream GXP2170 1.0.11.44"
    gs_match = re.match(r"grandstream\s+(\S+)\s+(\S+)", ua, re.I)
    if gs_match:
        return "grandstream", gs_match.group(1), gs_match.group(2)

    # Yealink: "Yealink SIP-T46U 108.86.0.30"
    yl_match = re.match(r"yealink\s+(\S+)\s+(\S+)", ua, re.I)
    if yl_match:
        return "yealink", yl_match.group(1), yl_match.group(2)

    # Polycom: "PolycomSoundPointIP-SPIP_550-UA/4.0.15.1009"
    poly_match = re.match(r"polycom\S*[\s/-]+(\S+)[\s/-]+(\S+)", ua, re.I)
    if poly_match:
        return "polycom", poly_match.group(1), poly_match.group(2)

    # Cisco: "Cisco-CP7841/12.7(1)"
    cisco_match = re.match(r"cisco[.-](\S+)/(\S+)", ua, re.I)
    if cisco_match:
        return "cisco", cisco_match.group(1), cisco_match.group(2)

    # Generic: try first word as vendor
    parts = ua.split()
    if parts:
        for known in ("grandstream", "yealink", "polycom", "cisco", "fanvil", "snom"):
            if known in ua_lower:
                vendor = known
                break
        if len(parts) >= 2:
            model = parts[1] if not vendor else parts[1]
        if len(parts) >= 3:
            firmware = parts[-1]

    return vendor, model, firmware


# =============================================================================
# Full Discovery Scan (Orchestrator)
# =============================================================================


async def run_discovery_scan(
    subnet: str,
    scan_type: str = "full",
    sip_ports: list[int] | None = None,
    on_progress: Any | None = None,
    credentials: dict[str, str] | None = None,
) -> list[DiscoveredPhone]:
    """
    Run a full network discovery scan combining multiple methods.

    Args:
        subnet: CIDR subnet to scan (e.g. "192.168.1.0/24")
        scan_type: "full", "arp", "sip", "http"
        sip_ports: SIP ports to probe (default: [5060])
        on_progress: Async callback(phase, detail_dict) for live progress
        credentials: {"username": ..., "password": ...} for phone web UI login.
                     Defaults to admin/admin if not provided.

    Returns:
        Deduplicated list of discovered phones, merged across methods.
    """
    start = time.monotonic()
    sip_ports = sip_ports or [5060]
    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_PROBES)

    async def _emit(phase: str, **kwargs: Any) -> None:
        if on_progress:
            with contextlib.suppress(Exception):
                await on_progress(phase, kwargs)

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        logger.error("Invalid subnet for discovery: %s", subnet)
        return []

    if network.num_addresses > 65536:
        logger.error("Subnet too large for discovery: %s", subnet)
        return []

    # SSRF guard: drop loopback / link-local / metadata / multicast / reserved
    # IPs before any credentialed probe, even if a network slipped past the
    # schema validator. RFC1918 LAN hosts (the real targets) pass through.
    hosts = [str(h) for h in network.hosts() if not is_ssrf_blocked_ip(str(h))]
    total_hosts = len(hosts)
    all_results: dict[str, DiscoveredPhone] = {}  # ip -> merged result

    await _emit("init", total_hosts=total_hosts, scan_type=scan_type, subnet=subnet)

    # --- ARP Scan ---
    if scan_type in ("full", "arp"):
        logger.info("Phase 1: ARP scan of %s", subnet)
        await _emit("arp_start", total_hosts=total_hosts)
        arp_results = await arp_scan_subnet(subnet, semaphore)
        for phone in arp_results:
            all_results[phone.ip_address] = phone
        await _emit(
            "arp_done",
            found=len(arp_results),
            total_devices=len(all_results),
            devices=[_phone_summary(p) for p in arp_results],
        )

    # --- HTTP Probe ---
    if scan_type in ("full", "http"):
        probe_ips = list(all_results.keys()) if all_results else hosts
        logger.info("Phase 2: HTTP probe of %d hosts", len(probe_ips))
        await _emit("http_start", hosts_to_probe=len(probe_ips))

        http_found = 0

        async def _http_task(ip: str) -> tuple[str, DiscoveredPhone | None]:
            result = await http_probe_host(ip, semaphore, _PROBE_TIMEOUT, credentials)
            return ip, result

        batch_size = 100
        for i in range(0, len(probe_ips), batch_size):
            batch = probe_ips[i : i + batch_size]
            tasks = [_http_task(ip) for ip in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for item in batch_results:
                if isinstance(item, Exception):
                    continue
                ip, phone = item
                if phone:
                    http_found += 1
                    if ip in all_results:
                        all_results[ip].merge(phone)
                    else:
                        all_results[ip] = phone
            await _emit(
                "http_progress",
                probed=min(i + batch_size, len(probe_ips)),
                total=len(probe_ips),
                found=http_found,
                total_devices=len(all_results),
            )

        await _emit(
            "http_done",
            found=http_found,
            total_devices=len(all_results),
        )

    # --- SIP Probe ---
    if scan_type in ("full", "sip"):
        probe_ips = list(all_results.keys()) if all_results else hosts
        logger.info("Phase 3: SIP OPTIONS probe")
        await _emit("sip_start", hosts_to_probe=len(probe_ips))

        sip_found = 0

        async def _sip_task(ip: str) -> tuple[str, DiscoveredPhone | None]:
            for port in sip_ports:
                result = await sip_probe_host(ip, port, semaphore, _PROBE_TIMEOUT)
                if result:
                    return ip, result
            return ip, None

        batch_size = 100
        for i in range(0, len(probe_ips), batch_size):
            batch = probe_ips[i : i + batch_size]
            tasks = [_sip_task(ip) for ip in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for item in batch_results:
                if isinstance(item, Exception):
                    continue
                ip, phone = item
                if phone:
                    sip_found += 1
                    if ip in all_results:
                        all_results[ip].merge(phone)
                    else:
                        all_results[ip] = phone
            await _emit(
                "sip_progress",
                probed=min(i + batch_size, len(probe_ips)),
                total=len(probe_ips),
                found=sip_found,
                total_devices=len(all_results),
            )

        await _emit(
            "sip_done",
            found=sip_found,
            total_devices=len(all_results),
        )

    elapsed = time.monotonic() - start
    logger.info(
        "Discovery scan completed: %d devices in %.1fs",
        len(all_results),
        elapsed,
    )
    await _emit(
        "complete",
        total_devices=len(all_results),
        elapsed=round(elapsed, 1),
        devices=[_phone_summary(p) for p in all_results.values()],
    )

    return list(all_results.values())


def _phone_summary(p: DiscoveredPhone) -> dict[str, Any]:
    """Compact summary dict for progress events."""
    return {
        "ip": p.ip_address,
        "mac": p.mac_address,
        "vendor": p.vendor,
        "model": p.model,
        "methods": p.discovery_methods,
        "sip_registered": p.sip_registered,
        "sip_account": p.sip_account,
        "sip_registrar": p.sip_registrar,
        "authenticated": p.authenticated,
    }


# =============================================================================
# Utilities
# =============================================================================


def _normalize_mac(mac: str) -> str:
    """Normalize MAC address to colon-separated lowercase."""
    clean = mac.replace("-", "").replace(":", "").replace(".", "").lower()
    if len(clean) != 12:
        return mac.lower()
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


async def _get_local_ip() -> str:
    """Get the local IP address for SIP Via headers."""
    try:
        # Create a UDP socket and connect to a remote address
        # to determine the local IP (no actual traffic is sent)
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=("8.8.8.8", 53),
        )
        try:
            local_addr = transport.get_extra_info("sockname")
            return local_addr[0] if local_addr else "127.0.0.1"
        finally:
            transport.close()
    except OSError:
        return "127.0.0.1"


# =============================================================================
# Phone Connection Test
# =============================================================================


async def test_phone_connection(
    ip: str,
    username: str = "admin",
    password: str = "admin",
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Test connectivity and login to a specific phone.

    Performs a comprehensive probe of a single phone:
    1. HTTP reachability check
    2. Unauthenticated device identification (MAC, firmware via P67/P68)
    3. Model inference via metaconfig_get
    4. Lockout status check
    5. Challenge-response login (access + dologin)
    6. Authenticated config read (network, SIP, system via config_get)
    7. SIP registration status via api-get_accounts

    Returns:
        dict with success, status, device info, and error details.
    """
    import hashlib
    import json as _json

    # ── P-value map (verified via config_get alias scan) ────────────────
    # Network addresses are stored as individual octets:
    #   IP:      P9.P10.P11.P12    (network.port.eth.1.address.1-4)
    #   Subnet:  P13.P14.P15.P16   (network.port.eth.1.mask.1-4)
    #   Gateway: P17.P18.P19.P20   (network.port.eth.1.gateway.1-4)
    #   DNS1:    P21.P22.P23.P24   (network.dns.1.ip.1-4)
    #   DNS2:    P25.P26.P27.P28   (network.dns.2.ip.1-4)
    # Other network:
    #   P8   = network.port.eth.1.type (0=Static, 1=DHCP, 2=PPPoE)
    #   P30  = NTP server
    #   P51  = VLAN tag
    #   P87  = VLAN priority
    #   P229 = PC port VLAN tag
    #   P244 = MTU
    # SIP Account 1:
    #   P271 = enable, P270 = name, P47 = sip server
    #   P35  = sip userid, P36 = auth userid, P3 = subscriber name
    #   P34  = subscriber password, P33 = voicemail number
    #   P31  = registration, P130 = transport, P40 = local SIP port
    #   P48  = outbound proxy
    # SIP Account 2:  P401=enable, P402=name(? check alias), P407=userid, ...
    # SIP Account 3:  P501, P502, P507, ...
    # SIP Account 4:  P601, P602, P607, ...

    # P-values for comprehensive authenticated config_get read
    _AUTH_CONFIG_PVALS = [
        # Device identity
        "67",
        "68",
        "89",
        # Network — IP octets
        "8",
        "9",
        "10",
        "11",
        "12",
        # Network — subnet octets
        "13",
        "14",
        "15",
        "16",
        # Network — gateway octets
        "17",
        "18",
        "19",
        "20",
        # Network — DNS1 octets
        "21",
        "22",
        "23",
        "24",
        # Network — DNS2 octets
        "25",
        "26",
        "27",
        "28",
        # Network — misc
        "30",
        "51",
        "87",
        "229",
        "244",
        # Network — preferred DNS
        "92",
        "93",
        "94",
        "95",
        # SIP Account 1
        "271",
        "270",
        "47",
        "35",
        "36",
        "3",
        "34",
        "33",
        "31",
        "130",
        "40",
        "48",
        # SIP Account 2
        "401",
        "402",
        "407",
        "405",
        "404",
        # SIP Account 3
        "501",
        "502",
        "507",
        "505",
        "504",
        # SIP Account 4
        "601",
        "602",
        "607",
        "605",
        "604",
        # System / provisioning
        "64",
        "148",
        "192",
        "276",
        # Named parameters (config_get supports these)
        "vendor_name",
        "phone_model",
    ]

    result: dict[str, Any] = {
        "success": False,
        "status": "unknown",
        "ip_address": ip,
        "mac_address": None,
        "model": None,
        "firmware_version": None,
        "vendor": None,
        "authenticated": False,
        "api_accessible": False,
        "sip_registered": False,
        "sip_account": None,
        "sip_registrar": None,
        "sip_accounts": [],
        "lockout_status": None,
        "config_items": None,
        "network_info": {},
        "auth_note": None,
        "error": None,
        "raw_data": {},
    }

    # SSRF guard: refuse credentialed probes to loopback / link-local / cloud
    # metadata / multicast / reserved targets before the host is interpolated
    # into any request URL. RFC1918 LAN phones (the real targets) pass through.
    # Mirrors the subnet-sweep guard above (arp_scan_subnet / run_discovery_scan).
    if is_ssrf_blocked_ip(ip):
        result["status"] = "blocked"
        result["error"] = "Target IP is not permitted (SSRF guard)"
        return result

    _BROWSER_HEADERS = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"http://{ip}/",
        "Origin": f"http://{ip}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }

    def _join_octets(*pvals: str, data: dict[str, str]) -> str:
        """Join P-value octets into a dotted address (e.g. 192.0.2.1)."""
        parts = [data.get(p, "") for p in pvals]
        if all(parts):
            return ".".join(parts)
        return ""

    def _extract_sip_account(
        data: dict[str, str],
        acct_num: int,
        p_enable: str,
        p_name: str,
        p_server: str,
        p_userid: str,
        p_authid: str,
        p_display: str,
    ) -> dict[str, str] | None:
        """Extract a SIP account from config_get data."""
        acct: dict[str, str] = {}
        enable = data.get(p_enable, "")
        name = data.get(p_name, "")
        server = data.get(p_server, "")
        userid = data.get(p_userid, "")
        authid = data.get(p_authid, "")
        display = data.get(p_display, "")

        if enable:
            acct["active"] = enable
        if name:
            acct["name"] = name
        if server:
            acct["server"] = server
        if userid:
            acct["user_id"] = userid
        if authid:
            acct["auth_id"] = authid
        if display:
            acct["display_name"] = display
        if acct:
            acct["account"] = str(acct_num)
        return acct if acct else None

    conn = aiohttp.TCPConnector(ssl=False)
    client_timeout = aiohttp.ClientTimeout(total=timeout, connect=3.0)
    jar = aiohttp.CookieJar(unsafe=True)

    try:
        async with build_aiohttp_session(
            connector=conn,
            timeout=client_timeout,
            cookie_jar=jar,
        ) as session:
            # Step 1: HTTP reachability
            try:
                async with session.get(f"http://{ip}/") as resp:
                    if resp.status != 200:
                        result["status"] = "unreachable"
                        result["error"] = f"HTTP {resp.status}"
                        return result
                    html = await resp.text()
                    if "webapp.nocache.js" in html:
                        result["vendor"] = "grandstream"
                    elif "yealink" in html.lower():
                        result["vendor"] = "yealink"
            except (TimeoutError, aiohttp.ClientError, OSError) as exc:
                result["status"] = "unreachable"
                result["error"] = f"Connection failed ({type(exc).__name__})"
                return result

            # Step 2: Unauthenticated P67/P68 (MAC + firmware — always accessible)
            try:
                async with session.get(
                    f"http://{ip}/cgi-bin/api.values.get",
                    params={"request": "P67:P68"},
                ) as pv_resp:
                    if pv_resp.status == 200:
                        pv_data = _json.loads(await pv_resp.text())
                        body = pv_data.get("body", {})
                        if isinstance(body, dict):
                            result["api_accessible"] = True
                            mac = body.get("P67", "")
                            fw = body.get("P68", "")
                            if mac:
                                result["mac_address"] = _normalize_mac(mac)
                            if fw:
                                result["firmware_version"] = fw
                            result["raw_data"].update({k: v for k, v in body.items() if v})
            except (TimeoutError, aiohttp.ClientError, ValueError):
                pass

            # Step 3: Metaconfig for model inference (no auth required)
            try:
                async with session.get(
                    f"http://{ip}/cgi-bin/metaconfig_get",
                ) as mc_resp:
                    if mc_resp.status == 200:
                        mc_text = await mc_resp.text()
                        mc_data = _json.loads(mc_text)
                        if isinstance(mc_data, list):
                            result["config_items"] = len(mc_data)
                            aliases = {item.get("alias", "") for item in mc_data}
                            num_accounts = sum(
                                1
                                for a in aliases
                                if a.startswith("account.") and a.endswith(".name")
                            )
                            has_bt = any("bluetooth" in a for a in aliases)
                            has_vpk = sum(1 for a in aliases if a.startswith("pks.vpk"))
                            if num_accounts >= 6:
                                result["model"] = (
                                    "GXP2170" if has_bt and has_vpk > 200 else "GXP2160"
                                )
                            elif num_accounts >= 4:
                                result["model"] = "GXP2140"
                            elif num_accounts >= 2:
                                result["model"] = "GXP1625"
                            else:
                                result["model"] = "Grandstream"
            except (TimeoutError, aiohttp.ClientError, ValueError):
                pass

            # Step 4: Lockout check
            try:
                async with session.get(
                    f"http://{ip}/cgi-bin/api-get_lockout",
                    headers=_BROWSER_HEADERS,
                ) as lock_resp:
                    if lock_resp.status == 200:
                        lock_data = _json.loads(await lock_resp.text())
                        lock_body = lock_data.get("body", "")
                        result["lockout_status"] = lock_body
                        if lock_body != "ok":
                            result["status"] = "locked_out"
                            result["error"] = f"Phone is locked out: {lock_body}"
                            result["success"] = True
                            return result
            except (TimeoutError, aiohttp.ClientError, ValueError):
                pass

            # Step 5: Challenge-response login
            sid = ""
            try:
                login_headers = {
                    **_BROWSER_HEADERS,
                    "Content-Type": "application/x-www-form-urlencoded",
                }
                access_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()
                async with session.post(
                    f"http://{ip}/cgi-bin/access",
                    data=f"access={access_hash}",
                    headers=login_headers,
                ) as access_resp:
                    if access_resp.status == 200:
                        access_data = _json.loads(await access_resp.text())
                        if access_data.get("response") == "success":
                            token = access_data.get("body", "")
                            if token and isinstance(token, str):
                                login_hash = hashlib.sha256(
                                    (password + token).encode("utf-8")
                                ).hexdigest()
                                async with session.post(
                                    f"http://{ip}/cgi-bin/dologin",
                                    data=f"username={username}&password={login_hash}",
                                    headers=login_headers,
                                ) as login_resp:
                                    if login_resp.status == 200:
                                        login_data = _json.loads(await login_resp.text())
                                        if login_data.get("response") == "success":
                                            body = login_data.get("body", {})
                                            if isinstance(body, dict):
                                                sid = body.get("sid", "")
            except (TimeoutError, aiohttp.ClientError, ValueError, KeyError):
                pass

            if sid:
                result["authenticated"] = True

            # Step 6: Authenticated config read via config_get
            # P-values require auth — only P67/P68 work without login.
            # config_get returns aliases that make the values self-documenting.
            if sid:
                try:
                    async with session.get(
                        f"http://{ip}/cgi-bin/config_get",
                        params={
                            "pvalues": ",".join(_AUTH_CONFIG_PVALS),
                            "sid": "",
                        },
                        headers=_BROWSER_HEADERS,
                    ) as cfg_resp:
                        if cfg_resp.status == 200:
                            cfg_data = _json.loads(await cfg_resp.text())
                            configs = cfg_data.get("configs", [])
                            # Build pvalue→value lookup (strip "P" prefix)
                            pv: dict[str, str] = {}
                            pv_with_alias: dict[str, dict] = {}
                            for item in configs:
                                pval = str(item.get("pvalue", ""))
                                val = str(item.get("value", ""))
                                alias = item.get("alias", "")
                                pv[pval] = val
                                if val:
                                    pv_with_alias[pval] = {
                                        "value": val,
                                        "alias": alias,
                                    }

                            # --- Device identity ---
                            if pv.get("67"):
                                result["mac_address"] = _normalize_mac(pv["67"])
                            if pv.get("68"):
                                result["firmware_version"] = pv["68"]
                            if pv.get("phone_model"):
                                result["model"] = pv["phone_model"]
                            if pv.get("vendor_name"):
                                result["vendor"] = pv["vendor_name"].lower()

                            # --- Network info (reconstruct from octets) ---
                            net = result["network_info"]
                            ip_addr = _join_octets("9", "10", "11", "12", data=pv)
                            if ip_addr:
                                net["ip_address"] = ip_addr
                            subnet = _join_octets("13", "14", "15", "16", data=pv)
                            if subnet:
                                net["subnet_mask"] = subnet
                            gateway = _join_octets("17", "18", "19", "20", data=pv)
                            if gateway:
                                net["gateway"] = gateway
                            dns1 = _join_octets("21", "22", "23", "24", data=pv)
                            if dns1:
                                net["dns_server_1"] = dns1
                            dns2 = _join_octets("25", "26", "27", "28", data=pv)
                            if dns2:
                                net["dns_server_2"] = dns2
                            pref_dns = _join_octets("92", "93", "94", "95", data=pv)
                            if pref_dns:
                                net["preferred_dns"] = pref_dns

                            ntp = pv.get("30", "")
                            if ntp:
                                net["ntp_server"] = ntp
                            vlan = pv.get("51", "")
                            if vlan:
                                net["vlan_id"] = vlan
                            vlan_pri = pv.get("87", "")
                            if vlan_pri:
                                net["vlan_priority"] = vlan_pri
                            pc_vlan = pv.get("229", "")
                            if pc_vlan:
                                net["pc_port_vlan"] = pc_vlan
                            mtu = pv.get("244", "")
                            if mtu:
                                net["mtu"] = mtu
                            eth_type_val = pv.get("8", "")
                            if eth_type_val:
                                eth_map = {"0": "Static", "1": "DHCP", "2": "PPPoE"}
                                net["address_type"] = eth_map.get(eth_type_val, eth_type_val)

                            # --- SIP accounts ---
                            acct1 = _extract_sip_account(
                                pv,
                                1,
                                p_enable="271",
                                p_name="270",
                                p_server="47",
                                p_userid="35",
                                p_authid="36",
                                p_display="3",
                            )
                            if acct1:
                                # Extra fields for account 1
                                for p, field in [
                                    ("33", "voicemail"),
                                    ("31", "registration"),
                                    ("130", "transport"),
                                    ("40", "local_port"),
                                    ("48", "outbound_proxy"),
                                ]:
                                    v = pv.get(p, "")
                                    if v:
                                        acct1[field] = v
                                result["sip_accounts"].append(acct1)
                                if acct1.get("user_id"):
                                    result["sip_account"] = acct1["user_id"]
                                if acct1.get("server"):
                                    result["sip_registrar"] = acct1["server"]

                            acct2 = _extract_sip_account(
                                pv,
                                2,
                                p_enable="401",
                                p_name="402",
                                p_server="407",
                                p_userid="405",
                                p_authid="404",
                                p_display="404",
                            )
                            if acct2:
                                result["sip_accounts"].append(acct2)

                            acct3 = _extract_sip_account(
                                pv,
                                3,
                                p_enable="501",
                                p_name="502",
                                p_server="507",
                                p_userid="505",
                                p_authid="504",
                                p_display="504",
                            )
                            if acct3:
                                result["sip_accounts"].append(acct3)

                            acct4 = _extract_sip_account(
                                pv,
                                4,
                                p_enable="601",
                                p_name="602",
                                p_server="607",
                                p_userid="605",
                                p_authid="604",
                                p_display="604",
                            )
                            if acct4:
                                result["sip_accounts"].append(acct4)

                            # --- System info ---
                            tz = pv.get("64", "")
                            if tz:
                                net["timezone"] = tz
                            dhcp_vendor = pv.get("148", "")
                            if dhcp_vendor:
                                result["raw_data"]["_dhcp_vendor_id"] = dhcp_vendor

                            # Store all non-empty config values in raw_data
                            result["raw_data"]["_config"] = pv_with_alias

                except (TimeoutError, aiohttp.ClientError, ValueError):
                    pass

            # Step 7: api-get_accounts for live SIP registration
            if sid:
                try:
                    async with session.get(
                        f"http://{ip}/cgi-bin/api-get_accounts",
                        params={"registered": "true"},
                        headers=_BROWSER_HEADERS,
                    ) as acct_resp:
                        if acct_resp.status == 200:
                            acct_data = _json.loads(await acct_resp.text())
                            acct_body = acct_data.get("body", {})
                            if isinstance(acct_body, list) and acct_body:
                                result["sip_registered"] = True
                                result["raw_data"]["_registered_accounts"] = acct_body
                                # Enrich sip_accounts with live registration data
                                for reg in acct_body:
                                    reg_id = reg.get("id")
                                    for sa in result["sip_accounts"]:
                                        if sa.get("account") == str(reg_id):
                                            sa["registered"] = str(reg.get("reg", 0))
                                            if reg.get("sip_id"):
                                                sa.setdefault("user_id", reg["sip_id"])
                                            if reg.get("sip_server"):
                                                sa.setdefault("server", reg["sip_server"])
                                            if reg.get("name"):
                                                sa.setdefault("display_name", reg["name"])
                                            break
                                    else:
                                        # Account from api-get_accounts not in config_get
                                        result["sip_accounts"].append(
                                            {
                                                "account": str(reg_id),
                                                "server": reg.get("sip_server", ""),
                                                "user_id": reg.get("sip_id", ""),
                                                "display_name": reg.get("name", ""),
                                                "registered": str(reg.get("reg", 0)),
                                            }
                                        )

                                # Set top-level SIP from first registered
                                if not result["sip_account"] and acct_body:
                                    first = acct_body[0]
                                    result["sip_account"] = first.get("sip_id", "")
                                    result["sip_registrar"] = first.get("sip_server", "")
                except (TimeoutError, aiohttp.ClientError, ValueError):
                    pass

            # Step 8: api-get_phone_status + api-get_line_status
            if sid:
                try:
                    async with session.get(
                        f"http://{ip}/cgi-bin/api-get_phone_status",
                        headers=_BROWSER_HEADERS,
                    ) as ps_resp:
                        if ps_resp.status == 200:
                            ps_data = _json.loads(await ps_resp.text())
                            ps_body = ps_data.get("body", "")
                            if ps_body:
                                result["raw_data"]["_phone_status"] = ps_body
                except (TimeoutError, aiohttp.ClientError, ValueError):
                    pass

                try:
                    async with session.get(
                        f"http://{ip}/cgi-bin/api-get_line_status",
                        headers=_BROWSER_HEADERS,
                    ) as ls_resp:
                        if ls_resp.status == 200:
                            ls_data = _json.loads(await ls_resp.text())
                            ls_body = ls_data.get("body", [])
                            if ls_body:
                                result["raw_data"]["_line_status"] = ls_body
                except (TimeoutError, aiohttp.ClientError, ValueError):
                    pass

            # Determine final status
            if result["authenticated"]:
                result["success"] = True
                result["status"] = "connected"
            elif result["mac_address"] or result["model"]:
                result["success"] = True
                result["status"] = "identified"
            else:
                result["success"] = True
                result["status"] = "reachable"

    except Exception as exc:
        result["status"] = "error"
        result["error"] = f"Connection test error ({type(exc).__name__})"

    return result

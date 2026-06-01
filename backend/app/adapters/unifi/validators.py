# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — UniFi adapter input validators.

Every UniFi API URL embeds at least one user-supplied path segment
(``site``, ``mac``, ``wlan_id``, ``network_id``, ``port_idx``). The
underlying ``httpx`` client interpolates without URL-encoding, so a
caller passing ``"../../api/self"`` as a site name could pivot off
the site path and hit privileged endpoints. The reference
pattern (MikroTik / Proxmox / Hikvision) is to validate every
segment at the adapter edge with a strict regex.

Patterns are deliberately conservative — better to reject a
legitimate-but-unusual ID than to admit a path-traversal payload.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.adapters.exceptions import AdapterError

# UniFi internal site names are short slugs (``default``, ``a1b2c3d4``).
# The controller normalises display names into a 1–32 char slug of
# lowercase alphanumerics + hyphen/underscore.
_SITE_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

# MongoDB ObjectID — 24 lowercase hex chars. UniFi uses this for
# every internal record ID (network, WLAN, firewall rule, port profile).
_MONGO_ID_RE = re.compile(r"^[a-f0-9]{24}$")

# MAC address — accept colon, dash, or dot separators; canonicalise
# to lowercase colon-form for the wire (UniFi expects ``aa:bb:cc:dd:ee:ff``).
_MAC_LOOSE_RE = re.compile(r"^[0-9A-Fa-f]{2}([-:.]?[0-9A-Fa-f]{2}){5}$")
_MAC_STRICT_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")

# Port index — UniFi switches top out at 52 ports today, but we
# allow up to 256 to cover hypothetical chassis hardware.
_PORT_MIN = 1
_PORT_MAX = 256

# PoE modes accepted by the UniFi ``port_overrides`` payload.
_VALID_POE_MODES = frozenset({"auto", "off", "passive24", "passthrough", "pasv24"})


def validate_site(site: str) -> str:
    """Reject anything that isn't a canonical UniFi site name.

    Raises :class:`AdapterError` (subclass of ``AdapterError`` so
    upstream handlers normalise to 400). Returns the input unchanged
    on success so callers can chain: ``site = validate_site(site)``.
    """
    if not isinstance(site, str) or not _SITE_RE.match(site):
        raise AdapterError(
            f"invalid UniFi site name: {site!r}",
            adapter_id="unifi",
        )
    return site


def validate_mac(mac: str) -> str:
    """Validate and canonicalise a MAC address to ``aa:bb:cc:dd:ee:ff``.

    Accepts colon, dash, dot-separated, or run-together hex pairs.
    Returns the lowercase colon-canonical form so every adapter
    method produces an identical wire value.
    """
    if not isinstance(mac, str) or not _MAC_LOOSE_RE.match(mac):
        raise AdapterError(
            f"invalid UniFi MAC address: {mac!r}",
            adapter_id="unifi",
        )
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac).lower()
    if len(digits) != 12:
        raise AdapterError(
            f"invalid UniFi MAC address: {mac!r}",
            adapter_id="unifi",
        )
    canon = ":".join(digits[i : i + 2] for i in range(0, 12, 2))
    if not _MAC_STRICT_RE.match(canon):
        raise AdapterError(
            f"invalid UniFi MAC address: {mac!r}",
            adapter_id="unifi",
        )
    return canon


def validate_object_id(value: str, *, label: str = "id") -> str:
    """Reject anything that isn't a 24-char hex MongoDB ObjectID.

    ``label`` is echoed in the error so the operator knows which
    field rejected (``network_id``, ``wlan_id``, ``rule_id``, etc.).
    """
    if not isinstance(value, str) or not _MONGO_ID_RE.match(value):
        raise AdapterError(
            f"invalid UniFi {label}: {value!r}",
            adapter_id="unifi",
        )
    return value


def validate_port_idx(port_idx: int) -> int:
    """Coerce to int and assert ``1 <= port_idx <= 256``, else raise."""
    try:
        idx = int(port_idx)
    except (TypeError, ValueError) as exc:
        raise AdapterError(
            f"invalid UniFi port index: {port_idx!r}",
            adapter_id="unifi",
        ) from exc
    if not (_PORT_MIN <= idx <= _PORT_MAX):
        raise AdapterError(
            f"UniFi port index out of range (1..{_PORT_MAX}): {idx}",
            adapter_id="unifi",
        )
    return idx


def validate_poe_mode(mode: str) -> str:
    """Reject any PoE mode the UniFi controller does not understand."""
    if not isinstance(mode, str) or mode.lower() not in _VALID_POE_MODES:
        raise AdapterError(
            f"invalid UniFi PoE mode: {mode!r} (expected one of {sorted(_VALID_POE_MODES)})",
            adapter_id="unifi",
        )
    return mode.lower()


# ─────────────────────────────────────────────────────────────────────
# SSRF host validation
# ─────────────────────────────────────────────────────────────────────

_ALWAYS_BLOCKED_HOSTNAMES = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "169.254.169.254",
    }
)


def validate_controller_host(
    host: str,
    *,
    allow_private: bool = True,
) -> str:
    """Reject controller hosts that resolve to loopback / metadata /
    link-local / multicast / IPv6 ULA.

    UniFi controllers virtually always live on private RFC1918 ranges
    (most are hosted on a UDM-Pro behind a NAT or on a small VM on
    the management LAN), so ``allow_private`` defaults to True. When
    ``ALLOW_PRIVATE_CONTROLLER_HOSTS`` is unset and the operator
    flips it to False, this validator additionally rejects RFC1918 +
    IPv6 ULA — useful for SaaS-style deployments that only manage
    public controllers.

    Returns the host string unchanged on success so callers can use
    it as an assignment-chain validator.
    """
    if not isinstance(host, str) or not host.strip():
        raise AdapterError(
            "UniFi controller host cannot be empty",
            adapter_id="unifi",
        )

    # Strip scheme + port if the caller handed us a full URL.
    clean = host.strip()
    if "://" in clean:
        parsed = urlparse(clean)
        clean = parsed.hostname or clean
    # Strip bare ``host:port`` form.
    elif clean.count(":") == 1 and not clean.startswith("["):
        clean = clean.rsplit(":", 1)[0]

    # De-bracket an IPv6 literal ([::1], [fd00:ec2::254], [::ffff:169.254.169.254])
    # so it parses as an IP below. Without this the ip_address() parse raises and
    # the value slips through the hostname branch (``return host``) unchecked —
    # an SSRF bypass. Mirrors the central validate_target_host guard.
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]

    if clean.lower() in _ALWAYS_BLOCKED_HOSTNAMES:
        raise AdapterError(
            f"UniFi controller host blocked: {clean}",
            adapter_id="unifi",
        )

    # IP-address path: walk every blocked range.
    try:
        addr = ipaddress.ip_address(clean)
    except ValueError:
        # Hostname — return as-is here (static/literal SSRF only). The IP-layer
        # check that MATTERS for a hostname is the connection-time PIN: UniFiClient
        # resolves it once via resolve_and_pin_host and connects to the validated IP
        # literal (carrying the hostname as Host header + SNI), so httpx cannot be
        # DNS-rebound to loopback/metadata between here and request time.
        return host

    # F5-sibling: central SSRF blocklist also covers the cloud-metadata literals
    # the per-property checks below miss (Alibaba 100.100.100.200, Oracle
    # 192.0.0.192, AWS IPv6 fd00:ec2::254) + reserved ranges. RFC1918 stays
    # allowed (handled by the per-property checks / ULA gate below).
    from app.core.security_utils import is_ssrf_blocked_ip

    if is_ssrf_blocked_ip(clean):
        raise AdapterError(
            f"UniFi controller host blocked (SSRF-unsafe): {addr}",
            adapter_id="unifi",
        )

    if addr.is_loopback:
        raise AdapterError(
            f"UniFi controller host blocked (loopback): {addr}",
            adapter_id="unifi",
        )
    if addr.is_link_local:
        raise AdapterError(
            f"UniFi controller host blocked (link-local): {addr}",
            adapter_id="unifi",
        )
    if addr.is_multicast:
        raise AdapterError(
            f"UniFi controller host blocked (multicast): {addr}",
            adapter_id="unifi",
        )
    if addr.is_unspecified:
        raise AdapterError(
            f"UniFi controller host blocked (unspecified): {addr}",
            adapter_id="unifi",
        )
    # IPv6 Unique Local Address (fc00::/7) is the IPv6 RFC1918 equivalent.
    if isinstance(addr, ipaddress.IPv6Address) and addr.is_private and not addr.is_loopback:
        # ``is_private`` for IPv6 covers ULA + a few odd ranges.
        if not allow_private:
            raise AdapterError(
                f"UniFi controller host blocked (IPv6 ULA): {addr}",
                adapter_id="unifi",
            )
    if not allow_private and addr.is_private:
        raise AdapterError(
            f"UniFi controller host blocked (RFC1918 private "
            f"address, ALLOW_PRIVATE_CONTROLLER_HOSTS=false): {addr}",
            adapter_id="unifi",
        )

    return host


__all__ = [
    "validate_site",
    "validate_mac",
    "validate_object_id",
    "validate_port_idx",
    "validate_poe_mode",
    "validate_controller_host",
]

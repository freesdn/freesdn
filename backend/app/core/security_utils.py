# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Security Utilities
==================================

Shared security helpers used across the backend:
- SSRF protection (private IP / DNS-rebinding blocking)
- URL validation for webhooks and outbound requests
- Regex safety (ReDoS prevention)
- Filename sanitization (path traversal prevention)
- IP / MAC address validation helpers
- Cron expression validation
- CSV formula-injection neutralization
"""

from __future__ import annotations

import ipaddress
import os
import re


def csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formula injection in a CSV cell.

    A cell whose text starts with ``= + - @`` (or tab / CR) is interpreted as a
    formula by Excel / LibreOffice / Sheets and can execute (DDE / exfil). Our
    exports carry attacker-influenceable values (device/host/user names, log
    messages). Prefix a single quote to force text; non-strings pass through.
    csv.writer still handles delimiter/quote escaping on top of this.
    """
    if not isinstance(value, str) or not value:
        return value
    return "'" + value if value[0] in ("=", "+", "-", "@", "\t", "\r") else value


import socket
import unicodedata
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

__all__ = [
    "is_private_ip",
    "validate_url_ssrf",
    "safe_http_request",
    "sign_webhook_payload",
    "validate_target_host",
    "safe_regex",
    "sanitize_filename",
    "validate_ip_address",
    "validate_mac_address",
    "validate_cron_expression",
    "validate_retention_days",
    "SSRF_BLOCKED_NETWORKS",
    # Webhook secret encryption
    "encrypt_webhook_secret",
    "decrypt_webhook_secret",
    # Generic field encryption
    "encrypt_field",
    "decrypt_field",
    # SQL LIKE escaping
    "escape_like",
]


# ═══════════════════════════════════════════════════════════════════════
# SSRF Protection
# ═══════════════════════════════════════════════════════════════════════

#: Networks that MUST be blocked for outbound requests (webhooks, etc.)
SSRF_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),  # "This" network
    ipaddress.ip_network("10.0.0.0/8"),  # RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),  # IANA special
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),  # Loopback
    ipaddress.ip_network("fc00::/7"),  # Unique-local
    ipaddress.ip_network("fe80::/10"),  # Link-local
    ipaddress.ip_network("ff00::/8"),  # Multicast
]

#: IP-literal cloud-metadata endpoints (no hostnames). Single source of truth,
#: shared by the scan SSRF guards (discovery.py / scanner.py) and
#: validate_target_host so the lists cannot drift (audit: Alibaba/Oracle gap).
CLOUD_METADATA_IP_LITERALS = frozenset(
    {
        "169.254.169.254",  # AWS/Azure/GCP IMDS (also link-local)
        "fd00:ec2::254",  # AWS IMDS over IPv6 (ULA → is_private)
        "100.100.100.200",  # Alibaba Cloud metadata (lives inside CGNAT 100.64/10)
        "192.0.0.192",  # Oracle Cloud OCI metadata (IETF-protocol range, not link-local)
    }
)
#: Additional cloud metadata endpoints to block (IP literals + the GCP hostname)
_METADATA_IPS = {*CLOUD_METADATA_IP_LITERALS, "metadata.google.internal"}


def sign_webhook_payload(secret: str, body: str | bytes, timestamp: int) -> str:
    """Replay-resistant HMAC over ``"{timestamp}.{body}"`` (Stripe-style).

    Binding the timestamp into the signed content lets a receiver reject a stale
    (replayed) delivery by checking the accompanying ``*-Timestamp`` header
    against a small clock-skew window BEFORE verifying — a captured request can
    no longer be replayed indefinitely. Returns ``"sha256=<hex>"``.
    """
    import hashlib
    import hmac

    raw = body.encode() if isinstance(body, str) else body
    signed = str(int(timestamp)).encode() + b"." + raw
    return "sha256=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private / reserved / loopback."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # Malformed → treat as private (block)

    return any(addr in net for net in SSRF_BLOCKED_NETWORKS)


def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses. Returns empty list on failure."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list({str(r[4][0]) for r in results})
    except (socket.gaierror, OSError):
        return []


def validate_url_ssrf(
    url: str,
    *,
    allow_private: bool = False,
    allowed_schemes: tuple[str, ...] = ("http", "https"),
) -> str:
    """
    DEPRECATED: This function is vulnerable to DNS rebinding (TOCTOU).

    It resolves the hostname ONCE and returns the original URL, so when the
    caller later passes the hostname to httpx / requests, the HTTP client
    performs its OWN DNS lookup and can be tricked into hitting a different
    IP (e.g. 127.0.0.1 or 169.254.169.254) by an attacker controlling a
    low-TTL DNS record.

    Use :func:`safe_http_request` instead, which resolves the hostname once,
    validates ALL returned IPs, and then makes the HTTP request pinned to
    the validated IP so no second DNS lookup can happen.

    This function is kept for backward compatibility (e.g. form-field
    validation where no request is actually issued) and WILL NOT protect
    against a determined attacker with control of a DNS server.
    """
    import warnings

    warnings.warn(
        "validate_url_ssrf is vulnerable to DNS rebinding (TOCTOU). "
        "Use safe_http_request() instead for any code path that actually "
        "issues an HTTP request.",
        DeprecationWarning,
        stacklevel=2,
    )

    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    parsed = urlparse(url)

    # Scheme check
    if parsed.scheme not in allowed_schemes:
        raise ValueError(f"URL scheme must be one of {allowed_schemes}, got '{parsed.scheme}'")

    # Hostname must exist
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must contain a valid hostname")

    # Block cloud metadata hostnames
    if hostname in _METADATA_IPS:
        raise ValueError("URL targets a cloud metadata endpoint (SSRF blocked)")

    # Block IPs in URL directly
    if not allow_private:
        # Try parsing hostname as IP first
        try:
            addr = ipaddress.ip_address(hostname)
            if is_private_ip(str(addr)):
                raise ValueError(f"URL resolves to private/reserved IP {addr} (SSRF blocked)")
        except ValueError as e:
            if "SSRF blocked" in str(e):
                raise
            # Not an IP literal – resolve DNS
            resolved = _resolve_hostname(hostname)
            if not resolved:
                raise ValueError(f"Cannot resolve hostname '{hostname}'")
            for ip in resolved:
                if is_private_ip(ip):
                    raise ValueError(
                        f"URL hostname '{hostname}' resolves to private IP {ip} (SSRF blocked)"
                    )

    return url


# ═══════════════════════════════════════════════════════════════════════
# DNS-rebinding-safe HTTP request helper
# ═══════════════════════════════════════════════════════════════════════
#
# `validate_url_ssrf` has a classic TOCTOU bug: it resolves DNS at validation
# time, then hands the *hostname* to httpx, which does another DNS lookup at
# request time. An attacker hosting `evil.example.com` with TTL=0 can serve
# a public IP to the validator (passing SSRF checks) and 127.0.0.1 or
# 169.254.169.254 microseconds later to httpx.
#
# `safe_http_request` closes the hole by:
#   1. Resolving the hostname ONCE via socket.getaddrinfo
#   2. Validating ALL returned IPs against a blocklist (reject-all-or-none)
#   3. Rewriting the URL to use the resolved IP directly
#   4. Setting the Host header to the original hostname so TLS SNI and
#      HTTP vhost routing still work
#   5. Disabling redirect following so the same trick can't happen at
#      Location: resolution time
#
# IP properties we consider unsafe:
# Properties that are NEVER safe — blocked even for an allow_hosts-trusted
# hostname. ``is_link_local`` (169.254/16) covers the IPv4 cloud-metadata
# endpoint; loopback/multicast/reserved/unspecified are never a legitimate
# webhook target. (``is_private`` is intentionally NOT here — a trusted LAN/
# tailnet host is allowed to resolve to RFC1918, see ``_ip_block_reason``.)
_NEVER_BYPASSABLE_PROPERTIES = (
    "is_loopback",  # 127.0.0.0/8 / ::1
    "is_link_local",  # 169.254.0.0/16 (incl. AWS/Azure/GCP IMDS) / fe80::/10
    "is_multicast",  # 224.0.0.0/4 / ff00::/8
    "is_reserved",  # IETF reserved
    "is_unspecified",  # 0.0.0.0 / ::
)

# CGNAT / RFC6598 shared address space — Tailscale's range. Treated like a
# private network: blocked for untrusted hosts, allowed for an allow_hosts
# -trusted tailnet host. (Python's ``is_private`` does not cover this on every
# version, so it is checked explicitly.)
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


def _ip_block_reason(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, trusted: bool = False
) -> str | None:
    """Return a reason string if ``ip`` must be blocked for outbound traffic, else None.

    The never-bypassable set (cloud-metadata/loopback/link-local/multicast/
    reserved/unspecified) is enforced even for an ``allow_hosts``-trusted
    hostname. Private (RFC1918) + CGNAT are blocked only for UNtrusted hosts —
    a deploy-owner-trusted LAN/tailnet host may resolve to them.
    """
    # Normalize an IPv4-mapped IPv6 address (``::ffff:a.b.c.d``) to its embedded
    # IPv4 first, so the metadata string-match + the IPv4-only CGNAT check below
    # cannot be evaded by the mapped form (e.g. ``::ffff:100.100.100.200`` →
    # Alibaba IMDS, ``::ffff:100.64.x.x`` → CGNAT).
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    # Always blocked — including the explicit metadata IPs, some of which live
    # in otherwise-bypassable ranges (e.g. Alibaba 100.100.100.200 in CGNAT,
    # AWS fd00:ec2::254 ULA), so a trusted hostname can never rebind to them.
    if str(ip) in _METADATA_IPS:
        return "cloud-metadata"
    for prop in _NEVER_BYPASSABLE_PROPERTIES:
        if getattr(ip, prop, False):
            return prop
    if not trusted:
        if getattr(ip, "is_private", False):
            return "is_private"
        if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_V4:
            return "cgnat(100.64.0.0/10)"
    return None


def _is_ip_safe(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True iff the IP is safe for outbound UNtrusted user-requested traffic."""
    return _ip_block_reason(ip, trusted=False) is None


def _resolve_and_validate(hostname: str, allow_hosts: frozenset[str] = frozenset()) -> str:
    """Resolve a hostname and return the first SAFE IP string.

    Validates ALL resolved addresses — if ANY one is unsafe the whole
    hostname is rejected. This prevents an attacker returning a mix of
    public and private IPs and relying on round-robin luck.

    ``allow_hosts`` is an explicit, deploy-owner-configured trust list (NOT
    per-request/operator input): a hostname in it bypasses the private/reserved
    IP block (so an operator can reach a self-hosted n8n/HA on the LAN or a
    tailnet) while STILL being DNS-resolved + IP-pinned + TLS-verified. The
    cloud-metadata block is never bypassed (handled by the caller).

    Raises:
        ValueError: if the hostname cannot be resolved, resolves to no
            addresses, or resolves to any blocked IP (when not trusted).
    """
    try:
        info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve hostname: {hostname}") from e

    if not info:
        raise ValueError(f"No addresses for hostname: {hostname}")

    trusted = hostname in allow_hosts
    resolved_ips: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in info:
        # sockaddr is tuple[str, int] for IPv4 or tuple[str, int, int, int] for IPv6;
        # the first element is always the IP address as a string.
        ip_raw = sockaddr[0]
        if not isinstance(ip_raw, str):
            continue
        ip_str: str = ip_raw
        # Strip IPv6 scope id ("fe80::1%eth0") if present
        if "%" in ip_str:
            ip_str = ip_str.split("%", 1)[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        reason = _ip_block_reason(ip_obj, trusted=trusted)
        if reason is not None:
            raise ValueError(f"Hostname {hostname!r} resolved to blocked IP {ip_str!r} ({reason})")
        resolved_ips.append(ip_str)

    if not resolved_ips:
        raise ValueError(f"No safe IPs for hostname: {hostname}")

    return resolved_ips[0]


async def safe_http_request(
    method: str,
    url: str,
    *,
    allowed_schemes: frozenset[str] = frozenset({"http", "https"}),
    timeout: float = 10.0,
    verify_tls: bool = True,
    follow_redirects: bool = False,
    allow_hosts: frozenset[str] = frozenset(),
    **kwargs: Any,
) -> Any:
    """Make an HTTP request with DNS-rebinding-safe SSRF protection.

    This function:
      1. Validates the URL scheme against ``allowed_schemes``.
      2. Resolves the hostname ONCE to an IP address.
      3. Verifies ALL resolved IPs are safe (not private/loopback/link-local/
         reserved/multicast/unspecified).
      4. Rewrites the request to use the resolved IP as the host, so httpx
         cannot perform a second DNS lookup that an attacker could poison.
      5. Sets the ``Host`` header to the original hostname so TLS SNI and
         HTTP vhost routing still work on the far end.

    Additional kwargs (json, content, data, params, ...) are forwarded to
    ``httpx.AsyncClient.request``.

    Args:
        method: HTTP method (GET, POST, ...).
        url: The full URL to fetch.
        allowed_schemes: Allowed URL schemes. Defaults to {http, https}.
        timeout: Total request timeout in seconds.
        verify_tls: Whether to verify TLS certificates.
        follow_redirects: Disabled by default — following redirects would
            re-introduce the DNS rebinding hole because the Location URL
            would be resolved again by httpx without our wrapping.

    Raises:
        ValueError: if the URL is malformed, uses a disallowed scheme,
            has no hostname, or resolves to a blocked IP.
    """
    from urllib.parse import urlparse, urlunparse

    import httpx  # local import — keeps module importable without httpx

    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    parsed = urlparse(url)

    if parsed.scheme not in allowed_schemes:
        raise ValueError(
            f"URL scheme {parsed.scheme!r} not in allowed set {sorted(allowed_schemes)}"
        )

    if not parsed.hostname:
        raise ValueError(f"URL has no hostname: {url!r}")

    # Block cloud-metadata hostnames outright before any DNS work. This is
    # NEVER bypassed, even by allow_hosts — there is no legitimate reason to
    # let an operator-authored webhook reach 169.254.169.254 et al.
    if parsed.hostname in _METADATA_IPS:
        raise ValueError("URL targets a cloud metadata endpoint (SSRF blocked)")

    # Deploy-owner trust list (e.g. a self-hosted n8n on the LAN/tailnet). An
    # exact host match bypasses the private/reserved IP block ONLY — DNS pinning
    # + TLS verification still apply.
    trusted = bool(parsed.hostname) and parsed.hostname in allow_hosts

    # If the URL already contains an IP literal, skip DNS but still validate.
    try:
        direct_ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        direct_ip = None

    if direct_ip is not None:
        reason = _ip_block_reason(direct_ip, trusted=trusted)
        if reason is not None:
            raise ValueError(f"URL targets blocked IP {parsed.hostname!r} ({reason})")
        resolved = str(direct_ip)
    else:
        resolved = _resolve_and_validate(parsed.hostname, allow_hosts=allow_hosts)

    # Build the IP-pinned URL. IPv6 literals must be bracketed in URLs.
    port = parsed.port
    is_ipv6 = ":" in resolved
    if is_ipv6:
        netloc_ip = f"[{resolved}]:{port}" if port else f"[{resolved}]"
    else:
        netloc_ip = f"{resolved}:{port}" if port else resolved

    ip_url = urlunparse(
        (
            parsed.scheme,
            netloc_ip,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )

    # Inject Host header so the remote server still routes by hostname
    # (TLS SNI + HTTP virtual hosts). httpx will use the URL host (the IP)
    # for the socket connection but this header tells the server who we
    # *meant* to talk to.
    headers = dict(kwargs.pop("headers", {}) or {})
    default_port = 443 if parsed.scheme == "https" else 80
    headers["Host"] = (
        parsed.hostname
        if parsed.port in (None, default_port)
        else f"{parsed.hostname}:{parsed.port}"
    )

    # Preserve TLS hostname verification while still pinning the TCP
    # connection to the validated IP. httpx forwards ``sni_hostname`` to
    # httpcore, which uses it for TLS SNI/certificate checks even though the
    # socket is opened against ``ip_url``. This closes the prior integration
    # bug where verified HTTPS requests would fail against valid public hosts.
    request_extensions = dict(kwargs.pop("extensions", {}) or {})
    if parsed.scheme == "https" and verify_tls:
        request_extensions.setdefault("sni_hostname", parsed.hostname)

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=verify_tls,
        follow_redirects=follow_redirects,
    ) as client:
        return await client.request(
            method,
            ip_url,
            headers=headers,
            extensions=request_extensions,
            **kwargs,
        )


def validate_target_host(
    host: str,
    *,
    allow_private: bool = True,
) -> str:
    """
    Validate a target host/IP for device management operations.

    Unlike webhook URLs, device targets are normally on private networks,
    but we still block loopback, link-local, and metadata IPs.
    """
    if not host:
        raise ValueError("Host must be a non-empty string")

    # Strip scheme if accidentally provided
    if "://" in host:
        host = urlparse(host).hostname or host

    # A bracketed IPv6 literal ([::1], [fd00:ec2::254], [::ffff:169.254.169.254])
    # MUST be de-bracketed before the IP parse below — otherwise
    # ipaddress.ip_address() raises, the value falls through to the hostname
    # branch, DNS resolution of the bracketed string returns nothing, and the
    # block-list is silently bypassed (SSRF to loopback / link-local / metadata).
    # Validate on the de-bracketed form; the ORIGINAL ``host`` is still returned
    # so the caller keeps a URL-valid ``[v6]:port`` literal.
    check_host = host[1:-1] if host.startswith("[") and host.endswith("]") else host

    ALWAYS_BLOCKED = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("fe80::/10"),  # IPv6 link-local (parity with v4 169.254)
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("0.0.0.0/32"),
    ]

    def _check_ip_literal(ip_text: str, *, resolved: bool = False) -> None:
        """Raise ValueError if ``ip_text`` is a blocked device target.

        Normalizes an IPv4-mapped IPv6 address (``::ffff:a.b.c.d``) to its embedded
        IPv4 FIRST, so the mapped form can't evade the metadata literal set or the
        IPv4 block ranges (e.g. ``::ffff:169.254.169.254`` → link-local metadata).
        """
        addr = ipaddress.ip_address(ip_text)
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:
            addr = mapped
        norm = str(addr)
        where = (
            f"'{host}' resolves to blocked IP {ip_text}"
            if resolved
            else f"{host} is a blocked address"
        )
        # Cloud-metadata literals not caught by the ranges below (Alibaba
        # 100.100.100.200 in CGNAT, Oracle 192.0.0.192, AWS IPv6 ULA fd00:ec2::254).
        if norm in CLOUD_METADATA_IP_LITERALS:
            raise ValueError(f"Target host {where}")
        for net in ALWAYS_BLOCKED:
            if addr in net:
                raise ValueError(f"Target host {where}")
        if not allow_private and is_private_ip(norm):
            raise ValueError(f"Target host {host} is a private address")

    try:
        _check_ip_literal(check_host)
    except ValueError as e:
        if "blocked" in str(e) or "private" in str(e):
            raise
        # Not an IP → hostname; resolve and check every A/AAAA record.
        for ip in _resolve_hostname(check_host):
            try:
                _check_ip_literal(ip, resolved=True)
            except ValueError as inner:
                if "blocked" in str(inner):
                    raise

    return host


def resolve_and_pin_host(host: str, *, allow_private: bool = True) -> str:
    """Resolve ``host`` to a validated IP literal and return it (SSRF pin).

    ``validate_target_host`` only *checks* the host and returns it unchanged, so a
    caller that then hands a HOSTNAME to httpx re-resolves it at request time — a
    DNS-rebinding TOCTOU (public IP at validate-time, 127.0.0.1/169.254.169.254 at
    request-time). This resolves ONCE, validates every candidate IP against the
    loopback/link-local/metadata block-list (plus the private-range gate when
    ``allow_private=False``), and returns the first safe IP *literal* — so the
    caller connects to a fixed address httpx cannot silently re-point. Use this
    (not validate_target_host) for multi-request probes that share an httpx client.
    """
    if not host:
        raise ValueError("Host must be a non-empty string")
    if "://" in host:
        host = urlparse(host).hostname or host

    # IP literal → validate and return as-is (httpx never re-resolves a literal).
    try:
        ipaddress.ip_address(host)
        validate_target_host(host, allow_private=allow_private)
        return host
    except ValueError as e:
        if "blocked" in str(e) or "private" in str(e):
            raise
        # Not an IP literal → fall through to hostname resolution.

    for ip in _resolve_hostname(host):
        try:
            validate_target_host(ip, allow_private=allow_private)
            return ip
        except ValueError:
            continue
    raise ValueError(f"Target host '{host}' did not resolve to any allowed IP")


def is_ssrf_blocked_ip(ip_str: str) -> bool:
    """True if ``ip_str`` is an SSRF-unsafe target.

    Blocks loopback / link-local (incl. cloud metadata) / multicast / reserved /
    unspecified addresses, plus the explicit cloud-metadata IPs in
    ``_METADATA_IPS`` (e.g. Alibaba 100.100.100.200, which lives inside CGNAT).
    RFC1918 private ranges are intentionally NOT blocked — scanning and probing
    on-prem gear is a legitimate use of the platform. Mirrors the inline guard in
    ``services/scanner.py`` so every subnet-scan path (VoIP discovery, …) drops
    the same dangerous hosts before issuing credentialed probes. Non-IP strings
    return False (callers validate hosts separately).
    """
    s = ip_str.strip()
    # De-bracket an IPv6 literal ([::1] / [::ffff:169.254.169.254]) so it parses
    # as an IP instead of returning False as an unrecognized "hostname".
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    try:
        ipobj = ipaddress.ip_address(s)
    except ValueError:
        return False
    # Normalize an IPv4-mapped IPv6 address to its embedded IPv4 so the mapped
    # form can't evade the metadata set / the v4 loopback+link-local checks.
    mapped = getattr(ipobj, "ipv4_mapped", None)
    if mapped is not None:
        ipobj = mapped
    if str(ipobj) in _METADATA_IPS:
        return True
    return bool(
        ipobj.is_loopback
        or ipobj.is_link_local
        or ipobj.is_multicast
        or ipobj.is_reserved
        or ipobj.is_unspecified
    )


# ═══════════════════════════════════════════════════════════════════════
# Regex Safety (ReDoS prevention)
# ═══════════════════════════════════════════════════════════════════════

#: Max length of a user-supplied regex pattern
_MAX_REGEX_LENGTH = 200

#: Patterns known to cause catastrophic backtracking. NOTE: this is a heuristic
#: blocklist, NOT a complete defense — callers that match against
#: attacker-influenceable input MUST also bound the input length (stdlib `re`
#: has no execution timeout). See automation.py MATCHES.
_DANGEROUS_PATTERNS = re.compile(
    r"(\.\*){3,}"  # Three or more .* in sequence
    r"|(\(.+\+\)){2,}"  # Nested quantifiers
    r"|\(\?\!.*\)\+"  # Negative lookahead with +
    # A quantifier applied to a group that itself contains an unbounded
    # quantifier — the classic (a+)+ / (a*)* / ([a-z]+)* / (\d+)* exponential
    # shapes that the original blocklist missed.
    r"|\([^)]*[+*][^)]*\)\s*[+*]"
    # Identical two-branch alternation under a quantifier — (a|a)* style.
    r"|\(([^)|]+)\|\1\)\s*[+*]"
)


def safe_regex(
    pattern: str,
    *,
    max_length: int = _MAX_REGEX_LENGTH,
    timeout_hint: str = "pattern",
) -> re.Pattern[str]:
    """
    Compile a user-supplied regex after safety checks.

    Raises ValueError if the pattern is too long, contains known
    catastrophic-backtracking constructs, or is syntactically invalid.
    """
    if not pattern or not isinstance(pattern, str):
        raise ValueError(f"Regex {timeout_hint} must be a non-empty string")

    if len(pattern) > max_length:
        raise ValueError(f"Regex {timeout_hint} exceeds max length ({len(pattern)} > {max_length})")

    if _DANGEROUS_PATTERNS.search(pattern):
        raise ValueError(
            f"Regex {timeout_hint} contains potentially unsafe constructs (ReDoS risk)"
        )

    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid regex {timeout_hint}: {exc}") from exc


# ═══════════════════════════════════════════════════════════════════════
# Filename Sanitization (path traversal prevention)
# ═══════════════════════════════════════════════════════════════════════

_FILENAME_UNSAFE = re.compile(r"[^\w\-.]")


def sanitize_filename(filename: str, max_length: int = 200) -> str:
    """
    Sanitize a user-supplied filename.

    - Strips directory components and path separators.
    - Removes null bytes and control characters.
    - Normalises unicode.
    - Enforces a maximum length.
    """
    if not filename:
        raise ValueError("Filename must not be empty")

    # Normalise unicode
    filename = unicodedata.normalize("NFKC", filename)

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Take only the basename (strip any directory components)
    filename = PurePosixPath(filename).name
    filename = os.path.basename(filename)

    # Remove control characters and path separators
    filename = re.sub(r"[\x00-\x1f\x7f/\\:]", "", filename)

    # Replace remaining unsafe chars with underscore
    filename = _FILENAME_UNSAFE.sub("_", filename)

    # Prevent hidden files
    filename = filename.lstrip(".")

    # Enforce length
    if len(filename) > max_length:
        # Preserve extension
        stem, _, ext = filename.rpartition(".")
        if ext and len(ext) < 20:
            filename = stem[: max_length - len(ext) - 1] + "." + ext
        else:
            filename = filename[:max_length]

    if not filename:
        raise ValueError("Filename is empty after sanitization")

    return filename


# ═══════════════════════════════════════════════════════════════════════
# Input Validation Helpers
# ═══════════════════════════════════════════════════════════════════════

_MAC_RE = re.compile(
    r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$"
    r"|^[0-9a-fA-F]{12}$"
)


def validate_ip_address(value: str | None) -> str | None:
    """Validate an IP address string (v4 or v6). Returns None if input is None."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        # Also allow CIDR notation
        try:
            ipaddress.ip_network(value, strict=False)
            return value
        except ValueError:
            raise ValueError(f"Invalid IP address: {value}")


def validate_mac_address(value: str | None) -> str | None:
    """Validate a MAC address string. Returns None if input is None."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if not _MAC_RE.match(value):
        raise ValueError(f"Invalid MAC address format: {value}")
    return value


# ═══════════════════════════════════════════════════════════════════════
# Cron Validation
# ═══════════════════════════════════════════════════════════════════════

_CRON_FIELD_RANGES = [
    (0, 59),  # minute
    (0, 23),  # hour
    (1, 31),  # day of month
    (1, 12),  # month
    (0, 7),  # day of week (0 and 7 = Sunday)
]


def validate_cron_expression(expr: str | None) -> str | None:
    """
    Basic validation of a 5-field cron expression.
    Returns None if input is None.
    """
    if expr is None:
        return None
    expr = expr.strip()
    if not expr:
        return None

    fields = expr.split()
    if len(fields) != 5:
        raise ValueError(f"Cron expression must have exactly 5 fields, got {len(fields)}")

    for i, (field_val, (lo, hi)) in enumerate(zip(fields, _CRON_FIELD_RANGES, strict=False)):
        if field_val == "*":
            continue
        # Handle step: */5
        if field_val.startswith("*/"):
            try:
                step = int(field_val[2:])
                if step < 1 or step > hi:
                    raise ValueError(f"Invalid step value in cron field {i}: {field_val}")
            except ValueError:
                raise ValueError(f"Invalid cron field {i}: {field_val}")
            continue
        # Handle range: 1-5
        if "-" in field_val and "," not in field_val:
            parts = field_val.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid range in cron field {i}: {field_val}")
            try:
                a, b = int(parts[0]), int(parts[1])
                if not (lo <= a <= hi and lo <= b <= hi):
                    raise ValueError(f"Cron field {i} out of range: {field_val}")
            except ValueError:
                raise ValueError(f"Invalid cron field {i}: {field_val}")
            continue
        # Handle list: 1,3,5
        for sub in field_val.split(","):
            sub = sub.strip()
            if sub == "*":
                continue
            try:
                n = int(sub)
                if not (lo <= n <= hi):
                    raise ValueError(f"Cron field {i} value {n} out of range [{lo}-{hi}]")
            except ValueError:
                raise ValueError(f"Invalid cron field {i}: {field_val}")

    return expr


def validate_retention_days(
    value: int | None, *, min_days: int = 1, max_days: int = 3650
) -> int | None:
    """Validate retention_days is within bounds."""
    if value is None:
        return None
    if not isinstance(value, int) or value < min_days or value > max_days:
        raise ValueError(f"retention_days must be between {min_days} and {max_days}")
    return value


# ═══════════════════════════════════════════════════════════════════════
# LDAP Injection Prevention
# ═══════════════════════════════════════════════════════════════════════


def escape_ldap_filter(value: str) -> str:
    """
    Escape special characters for safe use in LDAP search filters.
    Per RFC 4515 § 3.
    """
    replacements = {
        "\\": "\\5c",
        "*": "\\2a",
        "(": "\\28",
        ")": "\\29",
        "\x00": "\\00",
    }
    result = value
    # Backslash must be first
    for char, escaped in replacements.items():
        result = result.replace(char, escaped)
    return result


# ═══════════════════════════════════════════════════════════════════════
# SQL LIKE Escaping
# ═══════════════════════════════════════════════════════════════════════


def escape_like(value: str) -> str:
    """
    Escape SQL LIKE special characters (%, _) in user input.

    Prevents users from injecting wildcard patterns into LIKE/ILIKE
    queries.  The escape character is backslash, so callers should pass
    ``escape="\\\\"`` to SQLAlchemy's ``.like()`` / ``.ilike()`` when
    using the escaped value.

    Example::

        from app.core.security_utils import escape_like
        query = query.where(
            Model.name.ilike(f"%{escape_like(q)}%", escape="\\\\")
        )
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ═══════════════════════════════════════════════════════════════════════
# File Upload Limits
# ═══════════════════════════════════════════════════════════════════════

MAX_FIRMWARE_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB
MAX_BACKUP_IMPORT_BYTES = 200 * 1024 * 1024  # 200 MB
MAX_CONFIG_IMPORT_BYTES = 50 * 1024 * 1024  # 50 MB


# ═══════════════════════════════════════════════════════════════════════
# Webhook Secret Encryption (F-2)
# ═══════════════════════════════════════════════════════════════════════
#
# Webhook HMAC secrets are sensitive credentials — if the DB is compromised
# an attacker could forge signed payloads for any registered webhook endpoint.
# We encrypt secrets at rest using Fernet (AES-128-CBC + HMAC-SHA256) with a
# key derived from SECRET_KEY.
#
# Storage format: "fernet:<base64-fernet-token>"
# Legacy unencrypted values (no prefix) are transparently decrypted as
# plaintext so existing webhooks continue to work before a migration runs.

_FERNET_PREFIX = "fernet:"
_fernet_instance: Any | None = None  # module-level singleton, lazily initialised


def _get_fernet() -> Any:
    """
    Lazily build and cache a Fernet instance keyed from SECRET_KEY.

    Key derivation: PBKDF2-HMAC-SHA256 with 260 000 iterations.
    Using a domain-specific salt ensures this derived key cannot be confused with
    the JWT signing key even if someone reads both from memory.
    """
    import base64

    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    global _fernet_instance
    if _fernet_instance is None:
        from app.core.config import get_settings

        settings = get_settings()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            # IMPORTANT: this is a FIXED, internal salt - distinct
            # from app.core.crypto's operator-configurable ENCRYPTION_SALT. This
            # Fernet keys MFA TOTP secrets, SSO client secrets/keys, and webhook
            # HMAC secrets; crypto.py (ENCRYPTION_SALT) keys device/controller/
            # VoIP/AI credentials. The two classes are keyed independently:
            # rotating ENCRYPTION_SALT alone does NOT re-key these secrets (they
            # ride SECRET_KEY only). Any future key-rotation tooling must handle
            # BOTH derivations. Do not "unify" the salt without a re-encrypt
            # migration of the existing fernet: rows.
            salt=b"webhook-secret-salt-v1",
            iterations=260_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(settings.SECRET_KEY.encode()))
        _fernet_instance = Fernet(key)
    return _fernet_instance


def encrypt_webhook_secret(plaintext: str) -> str:
    """
    Encrypt a webhook HMAC secret for storage in the database.

    Returns a string with the ``fernet:`` prefix so
    :func:`decrypt_webhook_secret` can distinguish encrypted from legacy
    plaintext values.
    """
    if not plaintext:
        return plaintext
    token = _get_fernet().encrypt(plaintext.encode()).decode()
    return f"{_FERNET_PREFIX}{token}"


def decrypt_webhook_secret(stored: str) -> str:
    """
    Decrypt a stored webhook HMAC secret.

    Handles both:
    - ``fernet:<token>``  — encrypted (current format)
    - ``<plaintext>``     — legacy unencrypted (transparent backwards compat)
    """
    if not stored:
        return stored
    if stored.startswith(_FERNET_PREFIX):
        token = stored[len(_FERNET_PREFIX) :].encode()
        return str(_get_fernet().decrypt(token).decode())
    # Legacy plaintext — return as-is; the migration will encrypt these in bulk
    return stored


# ═══════════════════════════════════════════════════════════════════════
# Generic Field Encryption
# ═══════════════════════════════════════════════════════════════════════
#
# Reuses the same Fernet instance as webhook secrets.  These helpers are
# intended for any sensitive column (MFA secrets, SSO credentials, etc.)
# that needs at-rest encryption.  The storage format is identical:
# "fernet:<base64-fernet-token>", and legacy plaintext values are
# transparently returned on read.


def encrypt_field(plaintext: str) -> str:
    """Encrypt a sensitive field for storage. Returns 'fernet:...' prefixed string."""
    if not plaintext:
        return plaintext
    token = _get_fernet().encrypt(plaintext.encode()).decode()
    return f"{_FERNET_PREFIX}{token}"


def decrypt_field(stored: str) -> str:
    """Decrypt a stored sensitive field. Handles legacy plaintext transparently."""
    if not stored:
        return stored
    if stored.startswith(_FERNET_PREFIX):
        token = stored[len(_FERNET_PREFIX) :].encode()
        return str(_get_fernet().decrypt(token).decode())
    return stored

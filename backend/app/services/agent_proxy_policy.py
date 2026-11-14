# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""What the edge agent's HTTP proxy may be asked to reach, and what it may carry.

``AgentRegistryService.proxy_http_via_site`` has a site's agent fetch a URL on
its LAN and return the response. The agent sits on a network the controller
cannot reach, which is the point, and also what makes it the most valuable SSRF
pivot FreeSDN has: a caller that controls the URL can read anything the agent
can, including the agent host's own loopback services and cloud metadata, and
whatever credentials ride along go wherever the URL says. Nothing calls it from
an API path yet; this policy exists so that wiring it up later is safe.

* :func:`check_proxy_target` allows only ``http``/``https`` to a host the
  caller names in an explicit allow-list (the device it means to reach), never
  a URL with userinfo, never loopback, link-local, metadata, multicast, reserved
  or unspecified addresses (even if allow-listed), never ``localhost`` or a
  numeric host spelling such as ``2130706433`` that the agent's resolver would
  turn into one. The agent does not follow redirects (task_executor.py), so a
  3xx comes back here and a second hop goes through this check again.
* :func:`scrub_request_headers` removes hop-by-hop headers and anything that is
  FreeSDN's own credential (its session cookies, CSRF header, ``fsd_`` API keys
  and its own JWTs) so a caller that forwards an incoming request's headers
  cannot hand them to a device.
* :func:`scrub_response_headers` removes session and token headers from a
  response before it is returned to a caller outside the adapter, so a device's
  session cookie or token never reaches a browser or an API client.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit

__all__ = [
    "AgentProxyRefused",
    "check_proxy_target",
    "normalize_allowed_hosts",
    "scrub_request_headers",
    "scrub_response_headers",
]


class AgentProxyRefused(ValueError):
    """A proxied request the policy does not allow. Nothing was sent."""


_HOSTNAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*"
    r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
)
_BLOCKED_NAMES = {"localhost", "metadata", "metadata.google.internal", "instance-data"}

# Hop-by-hop (RFC 9110 7.6.1) and framing headers the agent sets itself.
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
_FREESDN_COOKIE_PREFIX = "freesdn_"
_FREESDN_API_KEY = re.compile(r"\bfsd_[0-9a-f]{64}\b", re.IGNORECASE)
_FREESDN_HEADERS = {"x-csrf-token"}

# Never returned to a caller outside the adapter.
_RESPONSE_SECRETS = {
    "set-cookie",
    "set-cookie2",
    "authorization",
    "proxy-authorization",
    "x-auth-token",
    "x-api-key",
    "x-csrf-token",
    "x-xsrf-token",
}


def _canonical_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped or addr)


def normalize_allowed_hosts(hosts: Iterable[str] | None) -> frozenset[str]:
    """The allow-list in the form :func:`check_proxy_target` compares against."""
    return frozenset(_canonical_host(h) for h in (hosts or ()) if h and str(h).strip())


def _refuse_dangerous_address(host: str) -> None:
    from app.core.security_utils import is_ssrf_blocked_ip

    if is_ssrf_blocked_ip(host):
        raise AgentProxyRefused(
            f"{host} is a loopback, link-local, metadata or reserved address; "
            "the agent proxy never reaches it"
        )


def check_proxy_target(url: str, allowed_hosts: Iterable[str] | None) -> str:
    """Return ``url`` if the agent may fetch it, else raise :class:`AgentProxyRefused`."""
    allowed = normalize_allowed_hosts(allowed_hosts)
    if not allowed:
        raise AgentProxyRefused(
            "no allowed hosts were given; the agent proxy only reaches the devices a caller names"
        )
    text = str(url or "").strip()
    if "\\" in text or any(ord(c) < 0x21 for c in text):
        raise AgentProxyRefused("URL contains a backslash, a space or a control character")
    try:
        parts = urlsplit(text)
        port = parts.port  # raises ValueError on a bad port
    except ValueError as exc:
        raise AgentProxyRefused(f"URL is malformed: {exc}") from exc
    if parts.scheme.lower() not in ("http", "https"):
        raise AgentProxyRefused("only http:// and https:// URLs can be proxied")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise AgentProxyRefused(
            "URL carries credentials; pass them as username/password so they "
            "are only ever sent to an allowed host"
        )
    if port == 0:
        raise AgentProxyRefused("port 0 is not a destination")
    raw_host = parts.hostname or ""
    if not raw_host:
        raise AgentProxyRefused("URL has no host")
    host = _canonical_host(raw_host)

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        _refuse_dangerous_address(host)
    else:
        last_label = host.rsplit(".", 1)[-1]
        if not _HOSTNAME_RE.fullmatch(host) or last_label.isdigit() or last_label.startswith("0x"):
            # 2130706433, 0x7f.1, 127.1: not DNS names, and a resolver turns
            # them into addresses this check never saw.
            raise AgentProxyRefused(f"{raw_host!r} is not a hostname or IP address")
        if host in _BLOCKED_NAMES or host.endswith(".localhost"):
            raise AgentProxyRefused(f"{host} is never proxied")

    if host not in allowed:
        raise AgentProxyRefused(
            f"{host} is not one of the hosts this request may reach ({sorted(allowed)})"
        )
    return text


def _is_freesdn_jwt(value: str) -> bool:
    token = value.split(None, 1)[-1].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except ValueError:
        return False
    return isinstance(claims, dict) and claims.get("iss") == "freesdn"


def _strip_freesdn_cookies(value: str) -> str:
    kept = [
        pair.strip()
        for pair in value.split(";")
        if pair.strip() and not pair.strip().lower().startswith(_FREESDN_COOKIE_PREFIX)
    ]
    return "; ".join(kept)


def scrub_request_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """The request headers that may be forwarded to the device."""
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        key = str(name).strip().lower()
        text = str(value)
        if key in _HOP_BY_HOP or key in _FREESDN_HEADERS:
            continue
        if _FREESDN_API_KEY.search(text):
            continue
        if key == "authorization" and _is_freesdn_jwt(text):
            continue
        if key == "cookie":
            text = _strip_freesdn_cookies(text)
            if not text:
                continue
        out[str(name)] = text
    return out


def scrub_response_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """The response headers that may be returned to a caller outside the adapter."""
    return {
        str(k): str(v)
        for k, v in (headers or {}).items()
        if str(k).strip().lower() not in _RESPONSE_SECRETS
        and str(k).strip().lower() not in _HOP_BY_HOP
    }

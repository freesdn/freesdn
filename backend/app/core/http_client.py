# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - central async HTTP client factory (overlay-aware)
===========================================================

A single chokepoint for constructing ``httpx.AsyncClient`` instances across the
adapters. Today most adapters call ``httpx.AsyncClient(...)`` inline, so the
controller can only reach a device if the *current network namespace* has a route
to it. That works in the privileged sidecar topology (the api shares the tunnel
netns) but NOT in the capless **userspace** overlay mode, where tailscaled/netbird
run in netstack and expose only a SOCKS5 proxy.

This factory injects that overlay SOCKS5 proxy transparently when, and only when,
the controller is in userspace-overlay mode (``VPN_MODE=userspace``). In every
other mode (the default ``off`` and the privileged ``sidecar``) it is a pure
pass-through to ``httpx.AsyncClient`` — so migrating an adapter onto it is a no-op
for existing deployments and unlocks overlay reach later. See
docs.freesdn.org (egress reach, P3).

NOTE: userspace SOCKS routing needs httpx's ``socks`` extra (socksio). Adapters
using ``aiohttp`` need ``aiohttp-socks`` separately — out of scope for this factory.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from app.core.config import settings

# kwargs that already define how the client connects — if an adapter set any of
# these we never override its routing.
_ROUTING_KWARGS = ("proxy", "proxies", "mounts", "transport")


def overlay_socks_proxy() -> str | None:
    """Return the overlay SOCKS5 proxy URL when (and only when) the controller is
    in userspace-overlay mode; otherwise ``None``.

    Default endpoint matches the ``tailscaled --socks5-server=127.0.0.1:1055``
    the userspace addon publishes; override with ``FREESDN_OVERLAY_SOCKS5``.
    """
    if settings.resolved_vpn_mode != "userspace":
        return None
    return os.environ.get("FREESDN_OVERLAY_SOCKS5", "socks5://127.0.0.1:1055")


# An unreachable device must fail FAST on the connect phase rather than hang up
# to the (often long) read timeout. Several adapters pass a single ``timeout``
# value (e.g. ``timeout=30.0``) which httpx applies to the connect phase too, so
# an offline box left a page hanging 20-35s+ before erroring. We cap ONLY the
# connect sub-timeout — healthy devices establish TCP in well under a second on a
# LAN/overlay, so this never affects a reachable device, only how fast an
# unreachable one surfaces as a clean 502/504. An explicitly-set connect is
# respected (e.g. a long-export client that deliberately wants connect=10).
_CONNECT_TIMEOUT = 8.0


def _cap_connect_timeout(timeout: Any) -> Any:
    """Return ``timeout`` with its connect phase bounded to ``_CONNECT_TIMEOUT``.

    - bare ``float``/``int`` -> Timeout whose read/write keep the value but connect
      is capped;
    - ``httpx.Timeout`` with no (or an over-long) connect -> connect capped, other
      phases preserved; an explicit connect <= cap is left untouched;
    - ``None`` (httpx "wait forever") -> infinite read/write but a bounded connect.
    """
    if timeout is None:
        return httpx.Timeout(None, connect=_CONNECT_TIMEOUT)
    if isinstance(timeout, (int, float)):
        return httpx.Timeout(float(timeout), connect=min(float(timeout), _CONNECT_TIMEOUT))
    if isinstance(timeout, httpx.Timeout):
        if timeout.connect is None or timeout.connect > _CONNECT_TIMEOUT:
            return httpx.Timeout(
                connect=_CONNECT_TIMEOUT,
                read=timeout.read,
                write=timeout.write,
                pool=timeout.pool,
            )
    return timeout


def build_async_client(**kwargs: Any) -> httpx.AsyncClient:
    """Drop-in replacement for ``httpx.AsyncClient(**kwargs)`` that routes through
    the overlay SOCKS5 proxy in userspace mode and is a pure pass-through otherwise.

    An explicit ``proxy``/``proxies``/``mounts``/``transport`` from the caller is
    always respected (never overridden). The connect phase of any caller-supplied
    ``timeout`` is bounded (see :func:`_cap_connect_timeout`) so an offline device
    fails fast instead of hanging; when no timeout is given httpx's own 5s default
    already bounds connect.
    """
    proxy = overlay_socks_proxy()
    if proxy and not any(k in kwargs for k in _ROUTING_KWARGS):
        kwargs["proxy"] = proxy
    if "timeout" in kwargs:
        kwargs["timeout"] = _cap_connect_timeout(kwargs["timeout"])
    return httpx.AsyncClient(**kwargs)


def build_aiohttp_session(**kwargs: Any):
    """``aiohttp`` equivalent of :func:`build_async_client`.

    In userspace-overlay mode, routes through the overlay SOCKS5 proxy via
    ``aiohttp-socks`` (a ``ProxyConnector``); a pure pass-through to
    ``aiohttp.ClientSession`` otherwise. A caller-provided ``connector`` is always
    respected. ``aiohttp`` (and ``aiohttp-socks`` for userspace mode) are imported
    lazily so this module carries no hard aiohttp dependency.
    """
    import aiohttp

    proxy = overlay_socks_proxy()
    if proxy and "connector" not in kwargs:
        try:
            from aiohttp_socks import ProxyConnector
        except ImportError as exc:  # pragma: no cover - only in userspace mode
            raise RuntimeError(
                "userspace overlay mode needs the 'aiohttp-socks' package to route "
                "aiohttp clients through the overlay SOCKS5 proxy"
            ) from exc
        kwargs["connector"] = ProxyConnector.from_url(proxy)
    return aiohttp.ClientSession(**kwargs)

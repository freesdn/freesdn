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

import importlib.util
import logging
import os
from typing import Any

import httpcore
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# kwargs that already define how the client connects — if an adapter set any of
# these we never override its routing.
_ROUTING_KWARGS = ("proxy", "proxies", "mounts", "transport")

#: SOCKS support packages already reported missing (logged once per process).
_MISSING_SOCKS_REPORTED: set[str] = set()


def _socks_support(package: str, client: str) -> bool:
    """Whether ``package`` (the SOCKS transport for ``client``) is installed.

    Neither httpx's ``socks`` extra (socksio) nor aiohttp-socks ships in the
    image, so with VPN_MODE=userspace every client this module built raised at
    construction (httpx: ImportError) or at the first request: every device
    became unreachable, LAN devices included, not only tailnet ones. Without
    the package the client now connects directly, as with VPN_MODE=off, and
    the gap is reported once at ERROR instead of failing every device.
    """
    if importlib.util.find_spec(package) is not None:
        return True
    if package not in _MISSING_SOCKS_REPORTED:
        _MISSING_SOCKS_REPORTED.add(package)
        logger.error(
            "VPN_MODE=userspace, but %s is not installed, so %s clients cannot use "
            "the overlay SOCKS5 proxy: they connect directly and tailnet addresses "
            "are unreachable",
            package,
            client,
        )
    return False


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


def _refuse_target(ip: str) -> bool:
    """True for an address FreeSDN never connects a device client to.

    Loopback, link-local (cloud metadata included), multicast, reserved and the
    explicit metadata addresses; RFC 1918 stays allowed (on-prem gear). A test
    that serves a device on loopback patches this.
    """
    from app.core.security_utils import is_ssrf_blocked_ip

    return is_ssrf_blocked_ip(ip)


def _refused(ip: str, *, allow_loopback: bool = False) -> bool:
    """``_refuse_target``, except that ``allow_loopback`` lets loopback through.

    Only loopback: a model server on this host is a real setup, but nothing
    FreeSDN talks to lives at a link-local or cloud-metadata address.
    """
    import ipaddress

    if allow_loopback:
        try:
            address = ipaddress.ip_address(ip.strip("[]").split("%", 1)[0])
        except ValueError:
            address = None
        if address is not None:
            mapped = getattr(address, "ipv4_mapped", None)
            if (mapped or address).is_loopback:
                return False
    return _refuse_target(ip)


def _is_ip_literal(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    return True


async def checked_addresses(host: str, port: int, *, allow_loopback: bool = False) -> list[str]:
    """Resolve ``host`` now and return its addresses, all of them checked.

    Raises ``OSError`` when the host does not resolve, or when it is, or any
    address it resolves to is, one FreeSDN does not connect to (loopback,
    link-local, cloud metadata). Connect to one of the returned addresses, not
    to the name, so a second lookup cannot answer differently (DNS rebinding).
    """
    import asyncio
    import socket

    bare = host.strip("[]")
    if _is_ip_literal(bare):
        if _refused(bare, allow_loopback=allow_loopback):
            raise OSError(f"connection to {bare} refused")
        return [bare]
    infos = await asyncio.get_running_loop().getaddrinfo(bare, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    if not addresses or any(_refused(ip, allow_loopback=allow_loopback) for ip in addresses):
        raise OSError(f"{bare} resolves to an address FreeSDN does not connect to")
    return addresses


async def checked_address(host: str, port: int, *, allow_loopback: bool = False) -> str:
    """The first address of :func:`checked_addresses` (for one raw connection)."""
    return (await checked_addresses(host, port, allow_loopback=allow_loopback))[0]


async def open_checked_connection(host: str, port: int, **kwargs: Any) -> Any:
    """``asyncio.open_connection`` to each checked address of ``host`` in turn.

    Like a normal client it moves on to the next address when one does not
    answer (a dual-stack host whose first address is unreachable), but only
    ever to an address that passed the check.
    """
    import asyncio

    failure: OSError | None = None
    for address in await checked_addresses(host, port):
        try:
            return await asyncio.open_connection(address, port, **kwargs)
        except OSError as exc:
            failure = exc
    assert failure is not None
    raise failure


class _CheckedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Opens every TCP connection to a checked address of the requested host.

    httpcore asks its network backend for each new connection, redirects
    included, with the host from the URL; the URL itself is left alone, so
    cookies, the connection pool, TLS (SNI and certificate) and the Host header
    all keep the name.
    """

    def __init__(self, inner: httpcore.AsyncNetworkBackend, *, allow_loopback: bool) -> None:
        self._inner = inner
        self._allow_loopback = allow_loopback

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        import asyncio

        try:
            addresses = await asyncio.wait_for(
                checked_addresses(host, port, allow_loopback=self._allow_loopback), timeout
            )
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout(f"{host} did not resolve in time") from exc
        except OSError as exc:
            raise httpcore.ConnectError(str(exc)) from exc
        failure: Exception | None = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                failure = exc
        assert failure is not None
        raise failure

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Any = None
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("unix sockets are not used for outbound requests")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _CheckedHostTransport(httpx.AsyncHTTPTransport):
    """A direct transport whose every connection goes to a checked address.

    A name checked when an adapter was set up could resolve elsewhere by the
    time it connects (DNS rebinding); the network backend checks the address
    each connection really uses (found in review of 26.11.3).
    """

    def __init__(self, *, allow_loopback: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        pool = self._pool
        if not hasattr(pool, "_network_backend"):  # pragma: no cover - httpcore changed
            raise RuntimeError("httpcore no longer exposes the connection pool's network backend")
        pool._network_backend = _CheckedNetworkBackend(
            pool._network_backend, allow_loopback=allow_loopback
        )


def _overlay_name(host: str) -> bool:
    """A MagicDNS name: only the overlay resolves it, to an overlay address."""
    return host.lower().rstrip(".").endswith(".ts.net")


class _CheckedProxyTransport(httpx.AsyncBaseTransport):
    """Sends requests through a proxy after checking where they are going.

    ``pin=True`` (the overlay SOCKS proxy): the name is resolved and checked
    here and the proxy is asked for that address, so it cannot resolve the
    name to somewhere else; the name stays in the Host header and TLS. Each
    host name gets its own connection pool, so a connection verified for one
    name is never reused for another name on the same address. A name only
    the overlay can resolve (MagicDNS) goes to the proxy by name.

    ``pin=False`` (an HTTP(S) proxy from the environment): the operator's proxy
    resolves names on its own network; a host that is, or resolves here to, a
    refused address is still refused.
    """

    def __init__(self, *, proxy: str, pin: bool, allow_loopback: bool, **kwargs: Any) -> None:
        self._proxy = proxy
        self._pin = pin
        self._allow_loopback = allow_loopback
        self._kwargs = kwargs
        self._by_host: dict[str, httpx.AsyncHTTPTransport] = {}

    def _inner(self, host: str) -> httpx.AsyncHTTPTransport:
        key = host if self._pin else ""
        transport = self._by_host.get(key)
        if transport is None:
            transport = httpx.AsyncHTTPTransport(proxy=self._proxy, **self._kwargs)
            self._by_host[key] = transport
        return transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        try:
            addresses = await checked_addresses(host, port, allow_loopback=self._allow_loopback)
        except OSError as exc:
            local_name_unknown = not _is_ip_literal(host) and "resolves to" not in str(exc)
            if not local_name_unknown or (self._pin and not _overlay_name(host)):
                raise httpx.ConnectError(str(exc), request=request) from exc
            addresses = []
        if not self._pin or not addresses or _is_ip_literal(host):
            return await self._inner(host).handle_async_request(request)
        pinned = httpx.Request(
            request.method,
            request.url.copy_with(host=addresses[0]),
            headers=request.headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": host},
        )
        return await self._inner(host).handle_async_request(pinned)

    async def aclose(self) -> None:
        for transport in self._by_host.values():
            await transport.aclose()


def _environment_proxies() -> dict[str, str | None]:
    """httpx's own reading of HTTP(S)_PROXY / ALL_PROXY / NO_PROXY."""
    from httpx import _utils

    return dict(_utils.get_environment_proxies())


def build_async_client(*, allow_loopback: bool = False, **kwargs: Any) -> httpx.AsyncClient:
    """Drop-in replacement for ``httpx.AsyncClient(**kwargs)`` whose connections
    go only to checked addresses, through the overlay SOCKS5 proxy in userspace
    mode and through an environment HTTP(S) proxy where one is configured.

    An explicit ``proxy``/``proxies``/``mounts``/``transport`` from the caller is
    always respected (never overridden). The connect phase of any caller-supplied
    ``timeout`` is bounded (see :func:`_cap_connect_timeout`) so an offline device
    fails fast instead of hanging; when no timeout is given httpx's own 5s default
    already bounds connect. ``allow_loopback`` is for a service on this host (a
    local model server), never for a device; link-local and cloud-metadata
    addresses stay refused even then.
    """
    if "timeout" in kwargs:
        kwargs["timeout"] = _cap_connect_timeout(kwargs["timeout"])
    if any(k in kwargs for k in _ROUTING_KWARGS):
        return httpx.AsyncClient(**kwargs)
    transport_kwargs: dict[str, Any] = {
        "verify": kwargs.get("verify", True),
        "cert": kwargs.get("cert"),
        "trust_env": kwargs.get("trust_env", True),
        "http2": kwargs.get("http2", False),
    }
    if "limits" in kwargs:
        transport_kwargs["limits"] = kwargs["limits"]
    overlay = overlay_socks_proxy()
    if overlay and _socks_support("socksio", "httpx"):
        kwargs["transport"] = _CheckedProxyTransport(
            proxy=overlay, pin=True, allow_loopback=allow_loopback, **transport_kwargs
        )
        return httpx.AsyncClient(**kwargs)
    kwargs["transport"] = _CheckedHostTransport(allow_loopback=allow_loopback, **transport_kwargs)
    if transport_kwargs["trust_env"]:
        # A transport of our own turns off httpx's environment proxies; mount
        # them again, each behind the same address check.
        mounts: dict[str, httpx.AsyncBaseTransport] = {}
        for pattern, proxy_url in _environment_proxies().items():
            mounts[pattern] = (
                _CheckedProxyTransport(
                    proxy=proxy_url, pin=False, allow_loopback=allow_loopback, **transport_kwargs
                )
                if proxy_url
                else _CheckedHostTransport(allow_loopback=allow_loopback, **transport_kwargs)
            )
        if mounts:
            kwargs["mounts"] = mounts
    return httpx.AsyncClient(**kwargs)


def checked_connector(*, allow_loopback: bool = False, **kwargs: Any) -> Any:
    """An ``aiohttp.TCPConnector`` that connects only to checked addresses.

    Every connection, redirects included, goes through ``_resolve_host``,
    which returns the address for an IP literal as well as for a name; any
    loopback, link-local or metadata result is refused (as the httpx transport
    does). For clients that talk to devices.
    """
    import aiohttp

    class _CheckedConnector(aiohttp.TCPConnector):
        async def _resolve_host(self, host: str, port: int, traces: Any = None) -> Any:
            infos = await super()._resolve_host(host, port, traces=traces)
            if not infos or any(
                _refused(str(info["host"]), allow_loopback=allow_loopback) for info in infos
            ):
                raise OSError(f"{host} resolves to an address FreeSDN does not connect to")
            return infos

    return _CheckedConnector(**kwargs)


def _same_host_redirects_only() -> Any:
    """An aiohttp trace config that refuses a redirect off the same origin.

    A device answering a probe could otherwise point FreeSDN at any address
    the probe's own address check excluded (an internal service, a cloud
    metadata endpoint), or move a login to plain HTTP or another port on the
    same host. A redirect on the same scheme, host and port keeps working, and
    so does the common upgrade from HTTP to HTTPS on the same host.
    """
    import aiohttp
    from yarl import URL

    async def _on_redirect(_session: Any, _ctx: Any, params: Any) -> None:
        location = params.response.headers.get("Location", "")
        target = params.url.join(URL(location)) if location else params.url
        same_host = (target.host or "").lower() == (params.url.host or "").lower()
        upgrade = params.url.scheme == "http" and target.scheme == "https"
        same_origin = (target.scheme, target.port) == (params.url.scheme, params.url.port)
        if not same_host or not (same_origin or upgrade):
            raise aiohttp.ClientError("redirect to another host, scheme or port refused")

    trace = aiohttp.TraceConfig()
    trace.on_request_redirect.append(_on_redirect)
    return trace


def build_aiohttp_session(*, same_host_redirects: bool = False, **kwargs: Any):
    """``aiohttp`` equivalent of :func:`build_async_client`.

    In userspace-overlay mode, routes through the overlay SOCKS5 proxy via
    ``aiohttp-socks`` (a ``ProxyConnector``); a pure pass-through to
    ``aiohttp.ClientSession`` otherwise. A caller-provided ``connector`` is always
    respected. ``aiohttp`` (and ``aiohttp-socks`` for userspace mode) are imported
    lazily so this module carries no hard aiohttp dependency.

    ``same_host_redirects`` refuses any redirect that leaves the host it came
    from (use it wherever the far end is a device, not a trusted service).
    """
    import aiohttp

    proxy = overlay_socks_proxy()
    if proxy and "connector" not in kwargs and _socks_support("aiohttp_socks", "aiohttp"):
        from aiohttp_socks import ProxyConnector

        kwargs["connector"] = ProxyConnector.from_url(proxy)
    if same_host_redirects:
        kwargs["trace_configs"] = [*kwargs.get("trace_configs", []), _same_host_redirects_only()]
    return aiohttp.ClientSession(**kwargs)

"""Fixed Dropbox reader: bounded control/body and SDK refresh in one child."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
import resource
import signal
import socket
import sys
from collections.abc import Callable, Generator
from typing import TYPE_CHECKING, Any, Protocol, cast
from urllib.parse import urlsplit

if TYPE_CHECKING:
    import urllib3.connection


class _TunnelMetadata(Protocol):
    # HTTPConnection inherits these private fields from http.client at runtime.
    _tunnel_host: str | None
    _tunnel_headers: dict[str, str]
    _tunnel_port: int | None


class _TunnelMethodSlot(Protocol):
    # This adapter deliberately replaces the class method only in its owned child.
    _tunnel: Callable[[urllib3.connection.HTTPConnection], None]


CONTROL = 65536
CHUNK = 65536
MAX_BYTES = 200 * 1024**2
METADATA = 16384
ERROR_BODY = 256 * 1024


def limit(kind: int, desired: int) -> None:
    _, hard = resource.getrlimit(kind)
    value = desired if hard == resource.RLIM_INFINITY else min(hard, desired)
    resource.setrlimit(kind, (value, value))


def host(value: str) -> str:
    return value.encode("idna").decode("ascii").lower()


def authority(endpoint: dict[str, Any]) -> str:
    name: str = endpoint["host"]
    return ("[" + name + "]" if ":" in name else name) + ":" + str(endpoint["port"])


def main() -> int:
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
    signal.alarm(61)
    for kind, size in (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_AS, 256 * 1024**2),
        (resource.RLIMIT_CPU, 20),
        (resource.RLIMIT_NOFILE, 64),
        (resource.RLIMIT_FSIZE, 0),
    ):
        limit(kind, size)
    raw = sys.stdin.buffer.read(CONTROL + 1)
    if len(raw) > CONTROL:
        return 2
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {
        "credentials",
        "verify",
        "api",
        "content",
        "path",
        "limit",
    }:
        return 2
    if type(value["limit"]) is not int or not 1 <= value["limit"] <= MAX_BYTES:
        return 2
    if (
        not isinstance(value["path"], str)
        or not 1 <= len(value["path"]) <= 16384
        or any(ord(c) < 32 for c in value["path"])
    ):
        return 2
    if value["verify"] is not True and (
        not isinstance(value["verify"], str) or not value["verify"]
    ):
        return 2
    credentials = value["credentials"]
    if (
        not isinstance(credentials, dict)
        or set(credentials)
        not in ({"oauth2_access_token"}, {"oauth2_refresh_token", "app_key", "app_secret"})
        or any(not isinstance(v, str) or len(v) > CONTROL for v in credentials.values())
    ):
        return 2
    pins: dict[str, str] = {}
    routes = {}
    for name, path in (("api", "/oauth2/token"), ("content", "/2/files/download")):
        endpoint = value[name]
        if not isinstance(endpoint, dict) or set(endpoint) != {"host", "port", "proxy", "pin"}:
            return 2
        if (
            not isinstance(endpoint["host"], str)
            or not endpoint["host"]
            or type(endpoint["port"]) is not int
            or not 1 <= endpoint["port"] <= 65535
        ):
            return 2
        hostname = host(endpoint["host"])
        pin = str(ipaddress.ip_address(endpoint["pin"]))
        if not ipaddress.ip_address(pin).is_global:
            return 2
        if hostname in pins and pins[hostname] != pin:
            return 2
        pins[hostname] = pin
        proxy = endpoint["proxy"]
        if proxy is not None:
            if not isinstance(proxy, dict) or set(proxy) != {"url", "host", "port", "pin"}:
                return 2
            parsed = urlsplit(proxy["url"])
            if (
                parsed.scheme not in {"http", "https"}
                or host(parsed.hostname or "") != host(proxy["host"])
                or (parsed.port or (443 if parsed.scheme == "https" else 80)) != proxy["port"]
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                return 2
            address = ipaddress.ip_address(proxy["pin"])
            normalized = (
                address.ipv4_mapped or address
                if isinstance(address, ipaddress.IPv6Address)
                else address
            )
            if (
                normalized.is_loopback
                or normalized.is_link_local
                or normalized.is_unspecified
                or normalized.is_multicast
                or str(normalized) in {"100.100.100.200", "192.0.0.192", "fd00:ec2::254"}
            ):
                return 2
            proxy_host, proxy_pin = host(proxy["host"]), str(address)
            if proxy_host in pins and pins[proxy_host] != proxy_pin:
                return 2
            pins[proxy_host] = proxy_pin
        routes[("https", hostname, endpoint["port"], path)] = (
            name,
            proxy["url"] if proxy else None,
        )

    # Imports happen only after the resource and input limits. The worker has
    # no process environment credentials and cannot consult application state.
    import dropbox
    import requests
    import urllib3.connection

    original_lookup = socket.getaddrinfo

    normalize_host = host

    def pinned_lookup(
        host: str | bytes | None,
        port: str | bytes | int | None,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[
        tuple[
            socket.AddressFamily,
            socket.SocketKind,
            int,
            str,
            tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
        ]
    ]:
        name = host
        if name is None:
            raise ValueError("Unprepared network destination")
        name = name.decode("ascii") if isinstance(name, bytes) else name
        normalized = normalize_host(name)
        pin = pins.get(normalized)
        if pin is None and normalized in pins.values():
            pin = normalized
        if pin is None:
            raise ValueError("Unprepared network destination")
        return original_lookup(pin, port, family, type, proto, flags)

    socket.getaddrinfo = pinned_lookup
    original_tunnel = urllib3.connection.HTTPConnection._tunnel

    def pinned_tunnel(connection: urllib3.connection.HTTPConnection) -> None:
        metadata = cast(_TunnelMetadata, connection)
        original = metadata._tunnel_host
        headers = metadata._tunnel_headers
        if original is None:
            raise ValueError("Unprepared proxy destination")
        pin = pins.get(host(original))
        if pin is None:
            raise ValueError("Unprepared proxy destination")
        try:
            metadata._tunnel_host = pin
            name = "[" + pin + "]" if ":" in pin else pin
            metadata._tunnel_headers = {
                **headers,
                "Host": name + ":" + str(metadata._tunnel_port),
            }
            return original_tunnel(connection)
        finally:
            # urllib3 selects SNI after _tunnel returns. Restore the actual
            # hostname so origin verification is not redirected to the pin.
            metadata._tunnel_host = original
            metadata._tunnel_headers = headers

    cast(_TunnelMethodSlot, urllib3.connection.HTTPConnection)._tunnel = pinned_tunnel

    class BoundedSession(requests.Session):
        def __init__(self) -> None:
            super().__init__()
            self.trust_env = False
            self.verify = value["verify"]
            self.active: set[requests.Response] = set()
            self.headers["Accept-Encoding"] = "identity"

        def resolve_redirects(self, *args: Any, **kwargs: Any) -> Generator[requests.Response]:
            # Requests otherwise consumes redirect bodies even with
            # allow_redirects=False while computing Response.next.
            yield from ()

        def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
            if not isinstance(request.url, str):
                raise ValueError("Unprepared request destination")
            parsed = urlsplit(request.url)
            route = (parsed.scheme, host(parsed.hostname or ""), parsed.port or 443, parsed.path)
            if (
                request.method != "POST"
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or route not in routes
            ):
                raise ValueError("Unprepared request destination")
            kind, proxy = routes[route]
            kwargs.update(
                stream=True,
                allow_redirects=False,
                verify=value["verify"],
                proxies={"https": proxy} if proxy else {},
            )
            response = super().send(request, **kwargs)
            self.active.add(response)
            try:
                if sum(len(k) + len(v) for k, v in response.headers.items()) > CONTROL:
                    raise ValueError("Response headers exceed bound")
                metadata = response.headers.get("Dropbox-API-Result", "")
                if len(metadata) > METADATA:
                    raise ValueError("Metadata exceeds bound")
                if kind == "content" and response.status_code == 200:
                    return response
                body, count = [], 0
                bound = CONTROL if kind == "api" else ERROR_BODY
                for chunk in response.iter_content(CHUNK):
                    count += len(chunk)
                    if count > bound:
                        raise ValueError("Control response exceeds bound")
                    body.append(chunk)
                response._content = b"".join(body)
                response._content_consumed = True
                # Token/error responses remain readable from their bounded
                # cache after physical transport closure, as expected by SDK.
                response.close()
                self.active.discard(response)
                if 300 <= response.status_code < 400:
                    raise ValueError("Download endpoint redirected")
                return response
            except BaseException:
                response.close()
                self.active.discard(response)
                raise

        def close(self) -> None:
            with contextlib.ExitStack() as closing:
                closing.callback(super().close)
                for response in self.active:
                    closing.callback(response.close)
                self.active.clear()

    with contextlib.ExitStack() as owned:
        session = BoundedSession()
        owned.callback(session.close)
        client = dropbox.Dropbox(session=session, **credentials)
        owned.callback(client.close)
        client._host_map["api"], client._host_map["content"] = (
            authority(value["api"]),
            authority(value["content"]),
        )
        original_refresh = client.refresh_access_token

        def refresh(*, scope: list[str] | None = None, host: str | None = None) -> Any:
            if host is not None and host != authority(value["api"]):
                raise ValueError("Refresh destination changed")
            return original_refresh(host=authority(value["api"]), scope=scope)

        client.refresh_access_token = refresh
        metadata, response = client.files_download(value["path"])
        owned.callback(response.close)
        expected_size = metadata.size
        if type(expected_size) is not int or not 1 <= expected_size <= value["limit"]:
            return 2
        expected_hash = getattr(metadata, "content_hash", None)
        if expected_hash is not None and (
            len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash)
        ):
            return 2
        count, block_bytes = 0, 0
        block_hash, total_hash = hashlib.sha256(), hashlib.sha256()
        for chunk in response.iter_content(CHUNK):
            if (
                not isinstance(chunk, bytes)
                or len(chunk) > CHUNK
                or len(chunk) > value["limit"] - count
            ):
                return 2
            count += len(chunk)
            data = memoryview(chunk)
            while data:
                n = min(len(data), 4 * 1024**2 - block_bytes)
                block_hash.update(data[:n])
                block_bytes += n
                data = data[n:]
                if block_bytes == 4 * 1024**2:
                    total_hash.update(block_hash.digest())
                    block_hash, block_bytes = hashlib.sha256(), 0
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        if block_bytes:
            total_hash.update(block_hash.digest())
        if (
            count != expected_size
            or not count
            or (
                expected_hash is not None
                and not hmac.compare_digest(total_hash.hexdigest(), expected_hash)
            )
        ):
            return 2
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        code = 2
    os._exit(code)

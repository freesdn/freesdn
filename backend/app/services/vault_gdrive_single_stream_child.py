"""Fixed Google single-response reader with actual SDK authentication and bounded streaming."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import resource
import signal
import socket
import sys
from collections.abc import Callable, Generator
from typing import TYPE_CHECKING, Any, Protocol, cast
from urllib.parse import parse_qsl, unquote, urlsplit

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


def limit(kind: int, desired: int) -> None:
    _, hard = resource.getrlimit(kind)
    value = desired if hard == resource.RLIM_INFINITY else min(hard, desired)
    resource.setrlimit(kind, (value, value))


def host(value: str) -> str:
    return value.encode("idna").decode("ascii").lower()


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
    if (
        not isinstance(value, dict)
        or not {"credentials", "verify", "drive", "path", "limit"} <= set(value)
        or set(value) - {"credentials", "verify", "drive", "token", "regional", "path", "limit"}
        or type(value["limit"]) is not int
        or not 1 <= value["limit"] <= MAX_BYTES
        or not isinstance(value["path"], str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,2048}", value["path"])
        or (
            value["verify"] is not True
            and (not isinstance(value["verify"], str) or not value["verify"])
        )
    ):
        return 2
    credentials = value["credentials"]
    if not isinstance(credentials, dict):
        return 2
    service = credentials.get("service_account")
    if service is not None:
        if (
            set(credentials) != {"service_account"}
            or not isinstance(service, dict)
            or set(service) != {"type", "client_email", "private_key", "token_uri"}
            or service["type"] != "service_account"
            or service["token_uri"] != "https://oauth2.googleapis.com/token"
            or not isinstance(service["client_email"], str)
            or not re.fullmatch(
                r"[A-Za-z0-9_.+-]{1,256}@[A-Za-z0-9.-]{1,253}", service["client_email"]
            )
            or not isinstance(service["private_key"], str)
            or not 1 <= len(service["private_key"]) <= 16384
        ):
            return 2
    elif (
        set(credentials) != {"access_token", "refresh_token", "client_id", "client_secret"}
        or any(
            v is not None
            and (not isinstance(v, str) or len(v) > 16384 or any(ord(c) < 32 for c in v))
            for v in credentials.values()
        )
        or not (
            credentials["access_token"]
            or all(credentials[k] for k in ("refresh_token", "client_id", "client_secret"))
        )
    ):
        return 2
    required = (
        {"drive"}
        | ({"token"} if service or credentials.get("refresh_token") else set())
        | ({"regional"} if service else set())
    )
    if {k for k in ("drive", "token", "regional") if k in value} != required:
        return 2
    names = {
        "drive": "www.googleapis.com",
        "token": "oauth2.googleapis.com",
        "regional": "iamcredentials.googleapis.com",
    }
    pins: dict[str, str] = {}
    routes = {}
    for name in required:
        endpoint = value[name]
        if (
            not isinstance(endpoint, dict)
            or set(endpoint) != {"host", "port", "proxy", "pin"}
            or endpoint["host"] != names[name]
            or endpoint["port"] != 443
        ):
            return 2
        address = ipaddress.ip_address(endpoint["pin"])
        if not address.is_global:
            return 2
        if endpoint["host"] in pins and pins[endpoint["host"]] != str(address):
            return 2
        pins[endpoint["host"]] = str(address)
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
        routes[endpoint["host"]] = (name, proxy["url"] if proxy else None)

    import google_auth_httplib2
    import httplib2
    import requests
    import urllib3.connection
    from google.oauth2 import credentials as user_credentials
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

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
        normalized = normalize_host(name.decode("ascii") if isinstance(name, bytes) else name)
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
            metadata._tunnel_host = original
            metadata._tunnel_headers = headers

    cast(_TunnelMethodSlot, urllib3.connection.HTTPConnection)._tunnel = pinned_tunnel

    class Session(requests.Session):
        def resolve_redirects(self, *args: Any, **kwargs: Any) -> Generator[requests.Response]:
            # Do not let Requests prefetch redirect bodies for Response.next.
            yield from ()

    class BoundedHttp:
        """Http-compatible wire transport; auth/refresh/discovery stay in SDK."""

        follow_redirects = False
        redirect_codes: frozenset[int] = frozenset()
        timeout = 10

        def __init__(self) -> None:
            self.session = Session()
            self.session.trust_env = False
            self.total: int | None = None
            self.sink: Sink | None = None
            self.connections: dict[str, Any] = {}
            self.failed = False

        def close(self) -> None:
            self.session.close()

        def request(self, *args: Any, **kwargs: Any) -> tuple[httplib2.Response, bytes]:
            if self.failed:
                raise ValueError("Transport previously refused a response")
            try:
                return self._request(*args, **kwargs)
            except Exception:
                # SDK regional-policy fail-soft handling cannot turn a size,
                # route or TLS violation into a subsequently usable transport.
                self.failed = True
                raise

        def _request(
            self,
            uri: str,
            method: str = "GET",
            body: str | bytes | None = None,
            headers: dict[str, str] | None = None,
            redirections: int = 0,
            connection_type: object = None,
            **kwargs: Any,
        ) -> tuple[httplib2.Response, bytes]:
            parsed = urlsplit(uri)
            if (
                parsed.scheme != "https"
                or (parsed.port or 443) != 443
                or parsed.username
                or parsed.password
                or parsed.fragment
                or parsed.hostname not in routes
                or connection_type is not None
                or kwargs
            ):
                raise ValueError("Unprepared request")
            kind, proxy = routes[parsed.hostname]
            if kind == "drive":
                if (
                    method != "GET"
                    or unquote(parsed.path) != "/drive/v3/files/" + value["path"]
                    or parse_qsl(parsed.query) != [("alt", "media")]
                    or body is not None
                ):
                    raise ValueError("Unprepared Drive resource")
            elif kind == "token":
                if method != "POST" or parsed.path != "/token" or parsed.query:
                    raise ValueError("Unprepared token endpoint")
            elif (
                service is None
                or method != "GET"
                or parsed.path
                != "/v1/projects/-/serviceAccounts/" + service["client_email"] + "/allowedLocations"
                or parsed.query
                or body is not None
            ):
                raise ValueError("Unprepared regional-policy endpoint")
            if body is not None and (not isinstance(body, (str, bytes)) or len(body) > CONTROL):
                raise ValueError("Request body exceeds bound")
            headers = dict(headers or {})
            if sum(len(k) + len(v) for k, v in headers.items()) > CONTROL:
                raise ValueError("Request headers exceed bound")
            headers["Accept-Encoding"] = "identity"
            if kind == "drive" and any(k.lower() in {"range", "if-match"} for k in headers):
                raise ValueError("Single-response request cannot contain range conditions")
            with self.session.request(
                method,
                uri,
                data=body,
                headers=headers,
                timeout=self.timeout,
                stream=True,
                allow_redirects=False,
                verify=value["verify"],
                proxies={"https": proxy} if proxy else {},
            ) as response:
                if sum(len(k) + len(v) for k, v in response.headers.items()) > CONTROL:
                    raise ValueError("Response headers exceed bound")
                if 300 <= response.status_code < 400:
                    raise ValueError("Read endpoint redirected")
                if response.headers.get("Content-Encoding", "identity").lower() not in {
                    "identity",
                    "gzip",
                }:
                    raise ValueError("Unsupported response encoding")
                result = httplib2.Response(
                    {**dict(response.headers), "status": str(response.status_code)}
                )
                if kind == "drive" and response.status_code in {200, 206}:
                    if (
                        response.status_code != 200
                        or "content-range" in result
                        or result.get("content-location", uri) != uri
                        or self.sink is None
                        or self.sink.size
                    ):
                        raise ValueError("Unexpected partial or changed resource")
                    length = result.get("content-length")
                    transfer = result.get("transfer-encoding")
                    if transfer is not None and (
                        transfer.lower() != "chunked" or length is not None
                    ):
                        raise ValueError("Ambiguous response length")
                    if length is not None and (
                        not re.fullmatch(r"[0-9]{1,12}", length) or int(length) < 1
                    ):
                        raise ValueError("Invalid response length")
                    decoded_length = (
                        int(length)
                        if length is not None
                        and result.get("content-encoding", "identity").lower() == "identity"
                        else None
                    )
                    if decoded_length is not None and decoded_length > value["limit"]:
                        raise ValueError("Declared archive exceeds bound")
                    for chunk in response.iter_content(CHUNK):
                        if chunk:
                            self.sink.write(chunk)
                    if not self.sink.size or (
                        decoded_length is not None and decoded_length != self.sink.size
                    ):
                        raise ValueError("Incomplete archive")
                    self.total = self.sink.size
                    # This private transport streams only successful media to
                    # the owned pipe. AuthorizedHttp still handles credentials,
                    # refresh and every bounded non-success/control response.
                    return result, b""
                chunks, size = [], 0
                for chunk in response.iter_content(CHUNK):
                    size += len(chunk)
                    if size > CONTROL:
                        raise ValueError("Decoded control response exceeds bound")
                    chunks.append(chunk)
                return result, b"".join(chunks)

    class Sink:
        def __init__(self) -> None:
            self.size = 0

        def write(self, data: bytes) -> int:
            if (
                not isinstance(data, bytes)
                or not data
                or len(data) > CHUNK
                or len(data) > value["limit"] - self.size
            ):
                raise ValueError("Archive exceeds bound")
            self.size += len(data)
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
            return len(data)

    with contextlib.ExitStack() as owned:
        creds: service_account.Credentials | user_credentials.Credentials
        if service is not None:
            creds = cast(
                Callable[..., service_account.Credentials],
                service_account.Credentials.from_service_account_info,
            )(service, scopes=["https://www.googleapis.com/auth/drive.file"])
            cast(Callable[[], None], creds._set_blocking_regional_access_boundary_lookup)()
        else:
            creds = cast(Callable[..., user_credentials.Credentials], user_credentials.Credentials)(
                token=credentials["access_token"],
                refresh_token=credentials["refresh_token"],
                token_uri="https://oauth2.googleapis.com/token",
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
            )
        http = BoundedHttp()
        owned.callback(http.close)
        resource_client = build(
            "drive",
            "v3",
            http=google_auth_httplib2.AuthorizedHttp(creds, http=http),
            cache_discovery=False,
        )
        owned.callback(resource_client.close)
        sink = Sink()
        http.sink = sink
        request = resource_client.files().get_media(fileId=value["path"])
        response, data = request.http.request(
            request.uri, method=request.method, headers=request.headers
        )
        if response.status != 200 or data or not sink.size or sink.size != http.total:
            return 2
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        code = 2
    os._exit(code)

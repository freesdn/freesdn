"""Fixed native TrueNAS archive reader; no application imports or credentials in argv."""

import contextlib
import http.client
import ipaddress
import json
import os
import resource
import signal
import socket
import ssl
import sys
import time
import zlib
from typing import Any
from urllib.parse import urlsplit

CONTROL = 65536
CHUNK = 65536
MAX_BYTES = 200 * 1024**2


def limit(kind: int, desired: int) -> None:
    _, hard = resource.getrlimit(kind)
    value = desired if hard == resource.RLIM_INFINITY else min(hard, desired)
    resource.setrlimit(kind, (value, value))


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate control field")
        result[key] = value
    return result


def _checked_input(raw: bytes) -> dict[str, Any]:
    if len(raw) > CONTROL:
        raise ValueError("Control limit")
    value = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict) or set(value) != {
        "host",
        "port",
        "pin",
        "username",
        "api_key",
        "verify_ssl",
        "trust",
        "path",
        "limit",
    }:
        raise ValueError("Control shape")
    for name, maximum in (("host", 253), ("username", 16384), ("api_key", 16384), ("path", 8192)):
        if not isinstance(value[name], str) or len(value[name].encode()) > maximum:
            raise ValueError("Control field")
    host = value["host"]
    if not host or any(ord(c) < 33 for c in host):
        raise ValueError("Host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if any(c in host for c in "/\\:@?#[]") or not host.isascii():
            raise ValueError("Host") from None
    ipaddress.ip_address(value["pin"])
    if (
        type(value["port"]) is not int
        or not 1 <= value["port"] <= 65535
        or type(value["verify_ssl"]) is not bool
    ):
        raise ValueError("Connection policy")
    if type(value["limit"]) is not int or not 1 <= value["limit"] <= MAX_BYTES:
        raise ValueError("Archive bound")
    path = value["path"]
    if (
        not path.startswith("/mnt/")
        or "\\" in path
        or any(ord(c) < 32 for c in path)
        or any(p in ("", ".", "..") for p in path.split("/")[1:])
    ):
        raise ValueError("Archive path")
    trust = value["trust"]
    if not isinstance(trust, dict) or set(trust) != {
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "FREESDN_DEVICE_CA_BUNDLE",
    }:
        raise ValueError("Trust policy")
    if any(
        v is not None and (not isinstance(v, str) or len(v) > 4096 or "\0" in v)
        for v in trust.values()
    ):
        raise ValueError("Trust path")
    return value


def _context(value: dict[str, Any]) -> ssl.SSLContext:
    # Only copied trust-store configuration enters the otherwise empty child
    # environment. An invalid configured extra bundle remains a hard refusal.
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        if value["trust"][name] is not None:
            os.environ[name] = value["trust"][name]
    context = ssl.create_default_context()
    bundle = value["trust"]["FREESDN_DEVICE_CA_BUNDLE"]
    if bundle:
        context.load_verify_locations(cafile=bundle)
    if not value["verify_ssl"]:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _raw_socket(value: dict[str, Any], seconds: float) -> socket.socket:
    address = ipaddress.ip_address(value["pin"])
    connection = socket.socket(
        socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM
    )
    try:
        connection.settimeout(seconds)
        connection.connect((str(address), value["port"]))
        return connection
    except BaseException:
        connection.close()
        raise


def _url(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 8192 or not value.isascii():
        raise ValueError("Download URL")
    if "\\" in value or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("Download URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or not parsed.path.startswith("/_download/")
    ):
        raise ValueError("Download URL")
    return value


def _copy_response(response: http.client.HTTPResponse, bound: int) -> None:
    if response.status != 200:
        raise ValueError("Download status")
    headers = response.getheaders()
    if sum(len(k) + len(v) for k, v in headers) > CONTROL:
        raise ValueError("Header bound")
    fields = {}
    for name, value in headers:
        name = name.lower()
        if name in fields and name in {"content-length", "transfer-encoding", "content-encoding"}:
            raise ValueError("Ambiguous framing")
        fields[name] = value.strip()
    length, encoding, transfer = (
        fields.get("content-length"),
        fields.get("content-encoding", "identity").lower(),
        fields.get("transfer-encoding"),
    )
    if transfer is not None and (transfer.lower() != "chunked" or length is not None):
        raise ValueError("Ambiguous transfer")
    if length is not None and (
        not length.isascii() or not length.isdecimal() or not 0 < int(length) <= bound + CHUNK
    ):
        raise ValueError("Body length")
    # Ask for identity; tolerate ordinary gzip responses without decompressing
    # a whole attacker-controlled block into application memory.
    if encoding not in {"identity", "gzip"}:
        raise ValueError("Unsupported content encoding")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
    wire = copied = 0

    def emit(chunk: bytes) -> None:
        nonlocal copied
        if len(chunk) > CHUNK or len(chunk) > bound - copied:
            raise ValueError("Archive exceeds bound")
        copied += len(chunk)
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()

    while chunk := response.read1(CHUNK):
        wire += len(chunk)
        if wire > bound + CHUNK:
            raise ValueError("Wire body exceeds bound")
        if decoder is None:
            emit(chunk)
        else:
            while chunk:
                emit(decoder.decompress(chunk, CHUNK))
                chunk = decoder.unconsumed_tail
                if decoder.unused_data:
                    raise ValueError("Trailing compressed data")
    if (
        not copied
        or (length is not None and wire != int(length))
        or (decoder is not None and not decoder.eof)
    ):
        raise ValueError("Incomplete archive")


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
    value = _checked_input(sys.stdin.buffer.read(CONTROL + 1))
    context = _context(value)
    from websockets.sync.client import reconnect

    class NoRedirect(reconnect):
        def process_redirect(self, exc: Exception) -> Exception:
            return exc

    class PinnedHTTPS(http.client.HTTPSConnection):
        def connect(self) -> None:
            raw = _raw_socket(value, 5)
            try:
                self.sock = context.wrap_socket(raw, server_hostname=value["host"])
            except BaseException:
                raw.close()
                raise

    hostname = "[" + value["host"] + "]" if ":" in value["host"] else value["host"]
    authority = hostname + ":" + str(value["port"])
    deadline = time.monotonic() + 55
    serial = 0
    with contextlib.ExitStack() as owned:
        raw = _raw_socket(value, 5)
        owned.callback(raw.close)
        ws = owned.enter_context(
            NoRedirect(
                "wss://" + authority + "/api/current",
                sock=raw,
                ssl=context,
                server_hostname=value["host"],
                proxy=None,
                compression=None,
                open_timeout=5,
                close_timeout=1,
                ping_interval=None,
                max_size=CONTROL,
                max_queue=2,
            )
        )

        def rpc(method: str, params: list[Any]) -> Any:
            nonlocal serial
            serial += 1
            ws.send(
                json.dumps({"jsonrpc": "2.0", "id": serial, "method": method, "params": params})
            )
            total = 0
            for _ in range(32):
                remaining = min(5, deadline - time.monotonic())
                if remaining <= 0:
                    raise TimeoutError("Control deadline")
                message = ws.recv(timeout=remaining)
                if not isinstance(message, str):
                    raise ValueError("Control frame")
                total += len(message.encode())
                if total > 4 * CONTROL:
                    raise ValueError("Control events bound")
                reply = json.loads(message, object_pairs_hook=_unique)
                if not isinstance(reply, dict):
                    raise ValueError("Control response")
                if reply.get("id") == serial:
                    if reply.get("jsonrpc") != "2.0" or "error" in reply or "result" not in reply:
                        raise ValueError("Control refusal")
                    return reply["result"]
            raise ValueError("Control event count")

        credentials = (
            {
                "mechanism": "API_KEY_PLAIN",
                "username": value["username"],
                "api_key": value["api_key"],
            }
            if value["api_key"]
            else {"mechanism": "PASSWORD_PLAIN", "username": value["username"], "password": ""}
        )
        result = rpc("auth.login_ex", [credentials])
        if not isinstance(result, dict) or result.get("response_type") != "SUCCESS":
            raise ValueError("Authentication refused")
        allocation = rpc(
            "core.download", ["filesystem.get", [value["path"]], value["path"].rsplit("/", 1)[-1]]
        )
        if (
            not isinstance(allocation, list)
            or len(allocation) != 2
            or type(allocation[0]) is not int
            or allocation[0] < 1
        ):
            raise ValueError("Download allocation")
        job_id = allocation[0]
        try:
            url = _url(allocation[1])
            connection = PinnedHTTPS(value["host"], value["port"], timeout=5, context=context)
            owned.callback(connection.close)
            connection.request(
                "GET",
                url,
                headers={"Host": authority, "Accept-Encoding": "identity", "Connection": "close"},
            )
            response = connection.getresponse()
            owned.callback(response.close)
            _copy_response(response, value["limit"])
            if time.monotonic() >= deadline:
                raise TimeoutError("Transfer deadline")
        except BaseException:
            # Best effort for this exact allocated job only. A refused abort,
            # broken channel, parent SIGKILL or process loss is not remote cleanup.
            deadline = min(deadline, time.monotonic() + 1)
            with contextlib.suppress(Exception):
                rpc("core.job_abort", [job_id])
            raise
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        code = 2
    os._exit(code)

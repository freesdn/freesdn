#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Disposable HTTP/WebSocket upstream and probe for the HA image smoke test."""

if not __debug__:
    raise RuntimeError("Qualification must run without Python optimization")

import base64
import hashlib
import json
import os
import socket
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def read_exact(stream, length):
    data = b""
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            raise EOFError("WebSocket frame ended early")
        data += chunk
    return data


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            assert self.headers.get("Connection", "").lower() == "upgrade"
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            first, second = read_exact(self.rfile, 2)
            assert first == 0x81 and second & 0x80 and second & 0x7F < 126
            mask = read_exact(self.rfile, 4)
            payload = read_exact(self.rfile, second & 0x7F)
            decoded = bytes(value ^ mask[i % 4] for i, value in enumerate(payload))
            self.wfile.write(bytes([0x81, len(decoded)]) + decoded)
            self.wfile.flush()
            self.close_connection = True
            return
        body = json.dumps(
            {
                "backend": os.environ["BACKEND_ID"],
                "path": self.path,
                "forwarded_proto": self.headers.get("X-Forwarded-Proto"),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def probe(host, expected_backends):
    # Do not inherit developer-machine HTTP proxies for the isolated network.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://{host}/health", timeout=5) as response:
        assert response.status == 200 and response.read() == b"ok\n"
    backends = set()
    for _ in range(12):
        with opener.open(f"http://{host}/api/v1/audit-probe?test=ha", timeout=8) as response:
            assert response.status == 200
            body = json.load(response)
            assert body["path"] == "/api/v1/audit-probe?test=ha"
            assert body["forwarded_proto"] == "http"
            backends.add(body["backend"])
    assert backends == set(expected_backends), backends
    for forwarded, expected in [("https", "https"), ("http", "http"), ("invalid", "http")]:
        request = urllib.request.Request(
            f"http://{host}/api/v1/audit-probe",
            headers={"X-Forwarded-Proto": forwarded},
        )
        with opener.open(request, timeout=8) as response:
            assert json.load(response)["forwarded_proto"] == expected
    key = base64.b64encode(os.urandom(16)).decode()
    with socket.create_connection((host, 80), timeout=8) as sock:
        sock.sendall(
            (
                f"GET /api/v1/ws HTTP/1.1\r\nHost: {host}\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        stream = sock.makefile("rb")
        assert b"101 Switching Protocols" in stream.readline()
        headers = {}
        while line := stream.readline().strip():
            name, value = line.decode().split(":", 1)
            headers[name.lower()] = value.strip()
        expected_accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        assert headers["sec-websocket-accept"] == expected_accept
        payload = b"freesdn-ha-websocket-echo"
        mask = os.urandom(4)
        sock.sendall(
            bytes([0x81, 0x80 | len(payload)])
            + mask
            + bytes(value ^ mask[i % 4] for i, value in enumerate(payload))
        )
        first, length = read_exact(stream, 2)
        assert first == 0x81 and length == len(payload)
        assert read_exact(stream, length) == payload
        stream.close()
    print(
        json.dumps(
            {
                "health": 200,
                "http_requests": 12,
                "backends": sorted(backends),
                "websocket": "handshake_and_echo_passed",
                "forwarded_scheme": "https_preserved_invalid_values_rejected",
            }
        )
    )


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
    elif sys.argv[1] == "probe":
        probe(sys.argv[2], sys.argv[3:])
    else:
        raise SystemExit("expected serve or probe")

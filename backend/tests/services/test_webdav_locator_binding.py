# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real HTTPX request/auth construction at an owned, non-network transport."""

import base64
import json
import socket
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx
import pytest

from app.services.backup import WebDAVStorageBackend

HOST = "webdav.example.test"
PIN = "93.184.216.34"
BODY = b"owned-webdav-locator-control"
OPERATIONS = ["load", "delete", "exists", "get_size"]
REFUSALS = {
    "foreign-host": "webdav://unrelated.example.test:8443/dav/backups/owned.fsdn",
    "loopback": "webdav://127.0.0.1:8443/dav/backups/owned.fsdn",
    "metadata": "webdav://169.254.169.254/dav/backups/owned.fsdn",
    "foreign-port": f"webdav://{PIN}:9443/dav/backups/owned.fsdn",
    "userinfo": f"webdav://unrelated-user@{PIN}:8443/dav/backups/owned.fsdn",
    "outside-root": f"webdav://{PIN}:8443/dav/unrelated/owned.fsdn",
    "relative-parent": "/backups/../unrelated/owned.fsdn",
    "encoded-parent": "/backups/%2e%2e/unrelated/owned.fsdn",
}
COMPATIBLE = {
    "relative-control": "/backups/owned.fsdn",
    "pinned-control": f"webdav://{PIN}:8443/dav/backups/owned.fsdn",
    "configured-hostname": f"webdav://{HOST}:8443/dav/backups/owned.fsdn",
}


@asynccontextmanager
async def owned_backend(monkeypatch, *, scheme="https", base_path="/dav"):
    """Keep actual endpoint validation, auth and URL building; no real socket."""
    requests, dns, clients = [], [], []
    files = {}
    username = "owned-locator-user"
    password = "owned-locator-synthetic-password"
    expected_auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()

    def address(host, port, *_args, **_kwargs):
        dns.append(host)
        assert host == HOST, "Unexpected DNS lookup in the owned construction fixture"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PIN, port or 443))]

    async def respond(request):
        requests.append({
            "method": request.method,
            "url": str(request.url),
            "scheme": request.url.scheme,
            "host": request.url.host,
            "port": request.url.port,
            "path": request.url.path,
            "Host_header": request.headers.get("host"),
            "SNI": request.extensions.get("sni_hostname"),
            "destination_credential_attached": request.headers.get("authorization") == expected_auth,
        })
        if request.method == "PUT":
            files[request.url.path] = await request.aread()
            return httpx.Response(201)
        if request.method == "MKCOL":
            return httpx.Response(201)
        if request.method == "DELETE":
            files.pop(request.url.path, None)
            return httpx.Response(204)
        # Destination assertions stay unchanged. Supply a valid streamed peer
        # representation so stricter metadata parsing can reach those assertions.
        from xml.sax.saxutils import escape

        data = files.get(request.url.path, BODY)
        if request.method == "PROPFIND":
            data = (f'<d:multistatus xmlns:d="DAV:"><d:response><d:href>{escape(request.url.raw_path.decode("ascii"))}</d:href>'
                    f'<d:propstat><d:prop><d:getcontentlength>{len(data)}</d:getcontentlength></d:prop>'
                    '<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>').encode()
        return httpx.Response(207 if request.method == "PROPFIND" else 200, stream=httpx.ByteStream(data))

    original_client = httpx.AsyncClient

    def client(*args, **kwargs):
        assert "transport" not in kwargs
        result = original_client(*args, transport=httpx.MockTransport(respond), **kwargs)
        clients.append(result)
        return result

    monkeypatch.setattr(socket, "getaddrinfo", address)
    monkeypatch.setattr(httpx, "AsyncClient", client)
    backend = WebDAVStorageBackend({"url": f"{scheme}://{HOST}:8443{base_path}",
                                    "path": "/backups", "username": username, "password": password})
    try:
        assert dns and all(host == HOST for host in dns)
        assert backend.base_url == f"{scheme}://{PIN}:8443{base_path}"
        yield SimpleNamespace(backend=backend, requests=requests, clients=clients, files=files, dns=dns)
    finally:
        await backend.close()
        # Lazy clients need not exist when admission refuses before transport.
        assert clients or not requests
        assert all(c.is_closed for c in clients)


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("case", REFUSALS)
async def test_webdav_refuses_unbound_locator_before_transport(monkeypatch, request, operation, case):
    async with owned_backend(monkeypatch) as f:
        error = None
        try:
            await getattr(f.backend, operation)(REFUSALS[case])
        except Exception as caught:
            error = caught
        observations = {
            "transport_boundary": "owned HTTPX MockTransport, no network peer",
            "actual_requests": json.dumps(f.requests, sort_keys=True),
            "request_count": len(f.requests),
            "destination_credential_request_count": sum(x["destination_credential_attached"] for x in f.requests),
            "exception_type": type(error).__name__ if error is not None else None,
            "controlled_refusal": isinstance(error, ValueError),
        }
        request.node.user_properties.extend(observations.items())
        assert isinstance(error, ValueError), "Unbound backup locator was not refused before request construction"
        assert not f.requests, "A rejected locator reached the HTTP transport with destination authority"


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("case", COMPATIBLE)
async def test_webdav_compatible_locator_preserves_configured_pin(monkeypatch, request, operation, case):
    async with owned_backend(monkeypatch) as f:
        result = await getattr(f.backend, operation)(COMPATIBLE[case])
        request.node.user_properties.extend({
            "transport_boundary": "owned HTTPX MockTransport, no network peer",
            "actual_requests": json.dumps(f.requests, sort_keys=True),
            "request_count": len(f.requests),
            "request_result_type": type(result).__name__,
        }.items())
        assert len(f.requests) == 1
        observed = f.requests[0]
        assert observed["url"] == f"https://{PIN}:8443/dav/backups/owned.fsdn"
        assert observed["Host_header"] == HOST + ":8443"
        assert observed["SNI"] == HOST and observed["destination_credential_attached"]
        assert observed["method"] == {"load": "GET", "delete": "DELETE", "exists": "PROPFIND", "get_size": "PROPFIND"}[operation]
        if operation == "load":
            assert result == BODY
        elif operation in {"delete", "exists"}:
            assert result is True


@pytest.mark.parametrize("scheme", ["https", "http"])
@pytest.mark.parametrize("base_path", ["", "/dav"])
async def test_webdav_own_saved_locator_preserves_configured_scheme(monkeypatch, request, scheme, base_path):
    async with owned_backend(monkeypatch, scheme=scheme, base_path=base_path) as f:
        locator = await f.backend.save("owned-id", BODY, "owned.fsdn")
        put = [x for x in f.requests if x["method"] == "PUT"]
        assert len(put) == 1
        original_path = put[0]["path"]
        f.requests.clear()
        result = await f.backend.load(locator)
        request.node.user_properties.extend({
            "transport_boundary": "owned HTTPX MockTransport, no network peer",
            "own_save_then_load": True,
            "actual_requests": json.dumps(f.requests, sort_keys=True),
            "exact_control_bytes": result == BODY,
            "configured_scheme_preserved": all(x["scheme"] == scheme for x in f.requests),
        }.items())
        assert len(f.requests) == 1 and result == BODY
        assert f.requests[0]["url"] == f"{scheme}://{PIN}:8443{original_path}"
        assert f.requests[0]["Host_header"] == HOST + ":8443"
        assert f.requests[0]["SNI"] == (HOST if scheme == "https" else None)
        assert f.requests[0]["destination_credential_attached"]

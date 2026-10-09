# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Boundary cases using actual HTTPX construction, without an external peer."""

import json
import socket

import httpx
import pytest

from app.services.backup import WebDAVStorageBackend
from tests.services.test_webdav_locator_binding import BODY, HOST, OPERATIONS, PIN, owned_backend

UNSAFE = {
    "network-path": "//unrelated.example.test/backups/file.fsdn",
    "http-url": f"http://{HOST}:8443/dav/backups/file.fsdn",
    "https-url": f"https://{HOST}:8443/dav/backups/file.fsdn",
    "empty-user": f"webdav://@{HOST}:8443/dav/backups/file.fsdn",
    "port-zero": f"webdav://{HOST}:0/dav/backups/file.fsdn",
    "missing-custom-port": f"webdav://{HOST}/dav/backups/file.fsdn",
    "malformed-port": f"webdav://{HOST}:invalid/dav/backups/file.fsdn",
    "root-sibling": "/backups-old/file.fsdn",
    "root-only": "/backups",
    "encoded-separator": "/backups/a%2fb.fsdn",
    "encoded-backslash": "/backups/a%5cb.fsdn",
    "nested-parent": "/backups/%252e%252e/file.fsdn",
    "nested-separator": "/backups/a%252fb.fsdn",
    "invalid-percent": "/backups/file%xx.fsdn",
    "invalid-utf8": "/backups/file%ff.fsdn",
    "encoded-control": "/backups/file%00.fsdn",
    "raw-control": "/backups/fi\nle.fsdn",
    "query": "/backups/file.fsdn?target=elsewhere",
    "empty-query": "/backups/file.fsdn?",
    "fragment": "/backups/file.fsdn#another",
    "path-parameter": "/backups/..;x/file.fsdn",
    "double-slash": "/backups//file.fsdn",
    "single-dot": "/backups/./file.fsdn",
    "encoded-single-dot": "/backups/%2e/file.fsdn",
    "trailing-slash": "/backups/file.fsdn/",
}


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("case", UNSAFE)
async def test_locator_edges_refuse_before_transport(monkeypatch, request, operation, case):
    async with owned_backend(monkeypatch) as f:
        error = None
        try:
            await getattr(f.backend, operation)(UNSAFE[case])
        except Exception as caught:
            error = caught
        request.node.user_properties.extend({
            "case": case, "actual_requests": json.dumps(f.requests, sort_keys=True),
            "exception_type": type(error).__name__ if error else None,
        }.items())
        assert isinstance(error, ValueError)
        assert not f.requests


@pytest.mark.parametrize("name", ["ordinary.fsdn", "report%20one.fsdn", "caf%C3%A9.fsdn", "100%25.fsdn"])
@pytest.mark.parametrize("operation", OPERATIONS)
async def test_encoded_filename_controls(monkeypatch, request, name, operation):
    async with owned_backend(monkeypatch) as f:
        result = await getattr(f.backend, operation)("/backups/" + name)
        request.node.user_properties.extend({"actual_requests": json.dumps(f.requests, sort_keys=True)}.items())
        assert len(f.requests) == 1
        assert f.requests[0]["url"] == f"https://{PIN}:8443/dav/backups/{name}"
        assert f.requests[0]["destination_credential_attached"]
        if operation == "load":
            assert result == BODY


@pytest.mark.parametrize("filename", ["../file", "dir/file", "file/", "%2f", "%252f", "..", "file?", "file#"])
async def test_save_refuses_unsafe_name_before_directory_creation(monkeypatch, request, filename):
    async with owned_backend(monkeypatch) as f:
        error = None
        try:
            await f.backend.save("owned", BODY, filename)
        except Exception as caught:
            error = caught
        request.node.user_properties.extend({
            "actual_requests": json.dumps(f.requests, sort_keys=True),
            "exception_type": type(error).__name__ if error else None,
        }.items())
        assert isinstance(error, ValueError)
        assert not f.requests


@pytest.mark.parametrize("filename", ["report%20one.fsdn", "caf%C3%A9.fsdn", "100%25.fsdn"])
async def test_encoded_save_names_round_trip(monkeypatch, request, filename):
    async with owned_backend(monkeypatch) as f:
        locator = await f.backend.save("owned", BODY, filename)
        puts = [r for r in f.requests if r["method"] == "PUT"]
        f.requests.clear()
        result = await f.backend.load(locator)
        request.node.user_properties.extend({
            "actual_requests": json.dumps(f.requests, sort_keys=True),
            "save_requests": json.dumps(puts, sort_keys=True), "exact_bytes": result == BODY,
        }.items())
        assert result == BODY and len(puts) == len(f.requests) == 1
        assert puts[0]["url"] == f.requests[0]["url"]
        assert f.requests[0]["url"].endswith("/owned_" + filename)


@pytest.mark.parametrize("config", [
    {"url": f"https://name@{HOST}/dav"},
    {"url": f"https://{HOST}:0/dav"},
    {"url": f"https://{HOST}/dav?"},
    {"url": f"https://{HOST}/dav#"},
    {"url": f"https://{HOST}/dav/%2e%2e/other"},
    {"url": f"https://{HOST}/dav//other"},
    {"url": f"https://{HOST}/dav", "path": "backups"},
    {"url": f"https://{HOST}/dav", "path": "/backups/../other"},
    {"url": f"https://{HOST}/dav", "path": "/backups/%252e%252e"},
    {"url": f"https://{HOST}/dav", "path": None},
])
def test_invalid_configuration_refused_before_client_creation(monkeypatch, request, config):
    creations = []

    def address(_host, port, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PIN, port or 443))]

    def client(*args, **kwargs):
        creations.append(True)
        raise AssertionError("Invalid configuration created a client")

    monkeypatch.setattr(socket, "getaddrinfo", address)
    monkeypatch.setattr(httpx, "AsyncClient", client)
    error = None
    try:
        WebDAVStorageBackend(config)
    except Exception as caught:
        error = caught
    request.node.user_properties.extend({"client_creations": len(creations), "exception_type": type(error).__name__ if error else None}.items())
    assert isinstance(error, ValueError) and not creations

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real owned TLS/HTTP WebDAV outcomes; no external server or SSRF admission proof."""

import json
import ssl

import httpx
import pytest

from app.services.backup import WebDAVStorageBackend
from tests.services import webdav_owned_peer

HOST = webdav_owned_peer.HOST
webdav_peer = webdav_owned_peer.webdav_peer
PATH = "/dav/backups/owned.fsdn"
BODY = b"owned-encrypted-backup-control\x00\xff" * 100


def observe(request, peer, **values):
    request.node.user_properties.extend({
        "boundary": "real owned loopback TLS peer after explicit test destination admission",
        "owned_peer_port": peer.port,
        "peer_requests": json.dumps(peer.requests, sort_keys=True),
        "peer_SNI": json.dumps(peer.sni), **values,
    }.items())


async def test_real_tls_save_load_delete_control(webdav_peer, request):
    peer = webdav_peer
    backend = WebDAVStorageBackend(peer.config())
    try:
        locator = await backend.save("owned-id", BODY, "saved.fsdn")
        loaded = await backend.load(locator)
        removed = await backend.delete(locator)
        observe(request, peer, exact_bytes=loaded == BODY, deletion_acknowledged=removed,
                stored_files_after_delete=len(peer.files))
        assert loaded == BODY and removed is True and not peer.files
        assert peer.requests and all(r["TLS"] and r["authorized"] and r["Host"] == f"{HOST}:{peer.port}" for r in peer.requests)
        assert peer.sni and set(peer.sni) == {HOST}
    finally:
        await backend.close()


@pytest.mark.parametrize("case", ["wrong-hostname", "untrusted"])
async def test_tls_failure_precedes_credentials(webdav_peer, monkeypatch, request, case):
    peer = webdav_peer
    if case == "untrusted":
        monkeypatch.delenv("SSL_CERT_FILE")
    backend = WebDAVStorageBackend(peer.config("wrong.webdav.test" if case == "wrong-hostname" else HOST))
    error = None
    try:
        try:
            await backend.load(peer.locator())
        except Exception as caught:
            error = caught
        causes, current = [], error
        while current is not None and len(causes) < 12 and current not in causes:
            causes.append(current)
            current = current.__cause__ or current.__context__
        certificate_failure = any(isinstance(item, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(item) for item in causes)
        observe(request, peer, exception_type=type(error).__name__ if error else None,
                certificate_verification_failed=certificate_failure)
        assert isinstance(error, httpx.ConnectError)
        assert certificate_failure and peer.sni and not peer.requests
    finally:
        await backend.close()


@pytest.mark.parametrize("size", [0, 1, 1048576])
async def test_propfind_size_matches_object_not_XML_response(webdav_peer, request, size):
    peer = webdav_peer
    peer.files[PATH] = b"x" * size
    backend = WebDAVStorageBackend(peer.config())
    try:
        observed = await backend.get_size(peer.locator())
        observe(request, peer, object_bytes=size, returned_size=observed,
                metadata_body_bytes=len(peer.metadata(PATH, size)))
        assert observed == size
        assert peer.requests[-1]["Depth"] == "0"
    finally:
        await backend.close()


@pytest.mark.parametrize("case", ["http-404", "response-404"])
async def test_propfind_missing_object_is_false(webdav_peer, request, case):
    peer = webdav_peer
    body = ('<d:multistatus xmlns:d="DAV:"><d:response><d:href>' + PATH +
            '</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response></d:multistatus>').encode()
    if case == "response-404":
        peer.override["PROPFIND"] = (207, body, {})
    backend = WebDAVStorageBackend(peer.config())
    try:
        exists = await backend.exists(peer.locator())
        observe(request, peer, returned_exists=exists)
        assert exists is False
    finally:
        await backend.close()


BAD_METADATA = ["forbidden", "malformed", "wrong-href", "foreign-href", "duplicate-href",
                "negative-size", "nonnumeric-size", "property-404", "entity", "oversized"]


def malformed_metadata(peer, case):
    if case == "forbidden":
        return 403, b"", {}
    if case == "malformed":
        return 207, b"<not-valid-xml", {}
    if case in {"wrong-href", "foreign-href"}:
        href = "/dav/backups/another.fsdn" if case == "wrong-href" else "https://unrelated.example.test" + PATH
        return 207, peer.metadata(href, len(BODY)), {}
    if case == "duplicate-href":
        body = peer.metadata(PATH, len(BODY)).decode()
        response = body[body.index("<d:response>"):body.index("</d:multistatus>")]
        return 207, body.replace("</d:multistatus>", response + "</d:multistatus>").encode(), {}
    if case in {"negative-size", "nonnumeric-size"}:
        return 207, peer.metadata(PATH, -1 if case == "negative-size" else "unknown"), {}
    if case == "property-404":
        return 207, peer.metadata(PATH, len(BODY), status="HTTP/1.1 404 Not Found"), {}
    if case == "entity":
        body = peer.metadata(PATH, "ENTITYVALUE").decode().replace("ENTITYVALUE", "&owned;")
        body = body.replace('?>', '?><!DOCTYPE d:multistatus [<!ENTITY owned "123">]>', 1)
        return 207, body.encode(), {}
    assert case == "oversized"
    body = peer.metadata(PATH, len(BODY)).replace(b"</d:multistatus>", b"<!--" + b"x" * 262144 + b"--></d:multistatus>")
    return 207, body, {}


@pytest.mark.parametrize("case", BAD_METADATA)
async def test_untrusted_metadata_does_not_report_a_size(webdav_peer, request, case):
    peer = webdav_peer
    peer.override["PROPFIND"] = malformed_metadata(peer, case)
    backend = WebDAVStorageBackend(peer.config())
    error = result = None
    try:
        try:
            result = await backend.get_size(peer.locator())
        except Exception as caught:
            error = caught
        observe(request, peer, returned_size=result, exception_type=type(error).__name__ if error else None,
                metadata_body_bytes=len(peer.override["PROPFIND"][1]))
        assert isinstance(error, (ValueError, httpx.HTTPStatusError)), "Untrusted metadata was reported as an object size"
    finally:
        await backend.close()


@pytest.mark.parametrize("operation", ["load", "delete", "exists", "get_size"])
async def test_redirect_is_not_followed_or_acknowledged(webdav_peer, request, operation):
    peer = webdav_peer
    method = {"load": "GET", "delete": "DELETE", "exists": "PROPFIND", "get_size": "PROPFIND"}[operation]
    peer.override[method] = (302, b"", {"Location": "/redirected-other-object"})
    backend = WebDAVStorageBackend(peer.config())
    error = result = None
    try:
        try:
            result = await getattr(backend, operation)(peer.locator())
        except Exception as caught:
            error = caught
        observe(request, peer, returned_type=type(result).__name__, returned_value=result,
                exception_type=type(error).__name__ if error else None)
        assert len(peer.requests) == 1 and peer.requests[0]["target"] == PATH
        assert isinstance(error, (ValueError, httpx.HTTPStatusError)) or (operation in {"delete", "exists"} and result is False)
    finally:
        await backend.close()


async def test_already_absent_delete_is_acknowledged(webdav_peer, request):
    peer = webdav_peer
    backend = WebDAVStorageBackend(peer.config())
    try:
        result = await backend.delete(peer.locator())
        observe(request, peer, deletion_acknowledged=result, stored_files=len(peer.files))
        assert result is True and not peer.files
    finally:
        await backend.close()


@pytest.mark.parametrize("framing", ["length", "chunked", "gzip"])
@pytest.mark.parametrize("oversized", [False, True])
async def test_remote_load_enforces_decoded_byte_limit(webdav_peer, monkeypatch, request, framing, oversized):
    peer = webdav_peer
    limit = 1024
    peer.files[PATH] = b"x" * (limit + 1 if oversized else limit)
    peer.chunked = framing == "chunked"
    peer.compress = framing == "gzip"
    monkeypatch.setattr("app.services.backup.MAX_BACKUP_IMPORT_BYTES", limit)
    backend = WebDAVStorageBackend(peer.config())
    error = result = None
    try:
        try:
            result = await backend.load(peer.locator())
        except Exception as caught:
            error = caught
        observe(request, peer, configured_test_limit=limit, source_bytes=len(peer.files[PATH]),
                returned_bytes=len(result) if isinstance(result, bytes) else None,
                exact_bytes=result == peer.files[PATH], exception_type=type(error).__name__ if error else None)
        if oversized:
            assert isinstance(error, ValueError), "Remote load exceeded the configured decoded-byte limit"
        else:
            assert error is None and result == peer.files[PATH]
    finally:
        await backend.close()

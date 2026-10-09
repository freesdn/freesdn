# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned TLS protocol edge cases; no external destination or vendor acceptance."""

import gzip

import httpx
import pytest

from app.services.backup import WebDAVStorageBackend
from tests.services.test_webdav_protocol_contract import BODY, PATH, observe
from tests.services.webdav_owned_peer import HOST, webdav_peer

assert webdav_peer  # Export the shared owned-peer fixture to pytest.


@pytest.mark.parametrize("href_kind", ["path", "configured-host", "pinned-ip"])
@pytest.mark.parametrize("prefix", ["d", "DAV_NAMESPACE"])
async def test_metadata_reference_and_namespace_controls(webdav_peer, request, href_kind, prefix):
    peer = webdav_peer
    href = PATH if href_kind == "path" else f"https://{HOST if href_kind == 'configured-host' else '127.0.0.1'}:{peer.port}{PATH}"
    payload = peer.metadata(href, len(BODY)).replace(b'd:', (prefix + ':').encode()).replace(b'xmlns:d=', ('xmlns:' + prefix + '=').encode())
    peer.override["PROPFIND"] = (207, payload, {})
    backend = WebDAVStorageBackend(peer.config())
    try:
        size = await backend.get_size(peer.locator())
        exists = await backend.exists(peer.locator())
        observe(request, peer, actual_size=size, actual_exists=exists, expected_size=len(BODY))
        assert size == len(BODY) and exists is True
        assert len(peer.requests) == 2 and all(r['Depth'] == '0' and r['authorized'] for r in peer.requests)
    finally:
        await backend.close()


INVALID_METADATA = ["wrong-root", "missing-href", "duplicate-href", "scheme", "port", "userinfo", "query", "collection",
                    "overflow", "unicode-number", "empty-size", "missing-size", "duplicate-size", "duplicate-propstat",
                    "missing-status", "invalid-status", "nested-size", "nested-href", "nested-status", "wrong-namespace"]


def altered_metadata(peer, case):
    payload = peer.metadata(PATH, 5).decode()
    if case == "wrong-root":
        return payload.replace("d:multistatus", "d:other")
    if case == "missing-href":
        return payload.replace(f"<d:href>{PATH}</d:href>", "")
    if case == "duplicate-href":
        return payload.replace("</d:href>", f"</d:href><d:href>{PATH}</d:href>")
    if case in {"scheme", "port", "userinfo", "query"}:
        href = {"scheme": f"http://{HOST}:{peer.port}{PATH}", "port": f"https://{HOST}:1{PATH}",
                "userinfo": f"https://user@{HOST}:{peer.port}{PATH}", "query": PATH + "?other=1"}[case]
        return peer.metadata(href, 5).decode()
    if case == "collection":
        return peer.metadata(PATH, 5, collection=True).decode()
    if case in {"overflow", "unicode-number", "empty-size", "nested-size"}:
        value = {"overflow": str(2**63), "unicode-number": "５", "empty-size": "", "nested-size": "5<d:other/>6"}[case]
        return payload.replace("<d:getcontentlength>5</d:getcontentlength>", f"<d:getcontentlength>{value}</d:getcontentlength>")
    if case == "missing-size":
        return payload.replace("<d:getcontentlength>5</d:getcontentlength>", "")
    if case == "duplicate-size":
        return payload.replace("</d:getcontentlength>", "</d:getcontentlength><d:getcontentlength>5</d:getcontentlength>")
    if case == "duplicate-propstat":
        stat = payload[payload.index("<d:propstat>"):payload.index("</d:propstat>") + len("</d:propstat>")]
        return payload.replace("</d:response>", stat + "</d:response>")
    if case == "missing-status":
        return payload.replace("<d:status>HTTP/1.1 200 OK</d:status>", "")
    if case == "invalid-status":
        return payload.replace("HTTP/1.1 200 OK", "not-an-http-status")
    if case == "nested-href":
        return payload.replace("</d:href>", "<d:other/>untrusted</d:href>")
    if case == "nested-status":
        return payload.replace("</d:status>", "<d:other/>500</d:status>")
    assert case == "wrong-namespace"
    return payload.replace('xmlns:d="DAV:"', 'xmlns:d="UNRELATED:"')


@pytest.mark.parametrize("case", INVALID_METADATA)
async def test_ambiguous_metadata_is_refused(webdav_peer, request, case):
    peer = webdav_peer
    peer.override["PROPFIND"] = (207, altered_metadata(peer, case).encode(), {})
    backend = WebDAVStorageBackend(peer.config())
    result = error = None
    try:
        try:
            result = await backend.get_size(peer.locator())
        except Exception as caught:
            error = caught
        observe(request, peer, returned_size=result, exception_type=type(error).__name__ if error else None)
        assert isinstance(error, ValueError), "Ambiguous metadata must not be reported as verified file properties"
    finally:
        await backend.close()


@pytest.mark.parametrize("case", ["truncated", "trailing", "concatenated", "bad-checksum", "unsupported", "valid-gzip", "valid-identity"])
async def test_compressed_representation_contract(webdav_peer, request, case):
    peer = webdav_peer
    encoded = gzip.compress(BODY)
    payload = {"truncated": encoded[:-1], "trailing": encoded + b"junk", "concatenated": encoded + encoded,
               "bad-checksum": encoded[:-8] + bytes([encoded[-8] ^ 1]) + encoded[-7:],
               "unsupported": BODY, "valid-gzip": encoded, "valid-identity": BODY}[case]
    encoding = "identity" if case == "valid-identity" else "unsupported" if case == "unsupported" else "gzip"
    peer.override["GET"] = (200, payload, {"Content-Encoding": encoding})
    backend = WebDAVStorageBackend(peer.config())
    result = error = None
    try:
        try:
            result = await backend.load(peer.locator())
        except Exception as caught:
            error = caught
        observe(request, peer, exact_bytes=result == BODY, exception_type=type(error).__name__ if error else None)
        if case.startswith("valid-"):
            assert error is None and result == BODY
        else:
            assert isinstance(error, ValueError)
    finally:
        await backend.close()


@pytest.mark.parametrize("operation,code", [("load",206),("load",204),("delete",202),("delete",207),("save",202),("exists",200)])
async def test_incomplete_operation_status_is_not_success(webdav_peer, request, operation, code):
    peer = webdav_peer
    method = {"load":"GET", "delete":"DELETE", "save":"PUT", "exists":"PROPFIND"}[operation]
    peer.override[method] = (code, b"", {})
    backend = WebDAVStorageBackend(peer.config())
    result = error = None
    try:
        try:
            result = await backend.save("owned", BODY, "probe.fsdn") if operation == "save" else await getattr(backend, operation)(peer.locator())
        except Exception as caught:
            error = caught
        observe(request, peer, returned_type=type(result).__name__, exception_type=type(error).__name__ if error else None)
        assert isinstance(error, (ValueError, httpx.HTTPStatusError))
    finally:
        await backend.close()

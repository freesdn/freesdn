"""Exercise the actual pinned-IP HTTP streaming path with a local transport."""

import io
import socket

import httpx
import pytest

from app.core.security_utils import safe_http_request


@pytest.mark.parametrize("payload,limit,expected", [(b"abc", 3, b"abc"), (b"abcd", 3, None)])
@pytest.mark.parametrize("declared_length", [None, "1", "actual"])
async def test_streamed_download_enforces_limit(
    monkeypatch, payload, limit, expected, declared_length
):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    real_client = httpx.AsyncClient

    def handler(request):
        assert request.url.host == "8.8.8.8"
        assert request.headers["host"] == "vendor.example"
        assert request.headers["accept-encoding"] == "identity"
        assert request.extensions["sni_hostname"] == "vendor.example"

        class Body(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield payload[:2]
                yield payload[2:]

        headers = (
            {}
            if declared_length is None
            else {
                "content-length": str(len(payload))
                if declared_length == "actual"
                else declared_length
            }
        )
        return httpx.Response(200, stream=Body(), headers=headers)

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: real_client(**kwargs, transport=httpx.MockTransport(handler)),
    )
    sink = io.BytesIO()
    if expected is None:
        with pytest.raises(ValueError, match="maximum size"):
            await safe_http_request(
                "GET", "https://vendor.example/file", download_to=sink, max_response_bytes=limit
            )
    else:
        await safe_http_request(
            "GET", "https://vendor.example/file", download_to=sink, max_response_bytes=limit
        )
        assert sink.getvalue() == expected


async def test_compressed_transfer_is_rejected_before_reading_body(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    real_client = httpx.AsyncClient

    class UnreadBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            raise AssertionError("Compressed body must not be read or expanded")
            yield b""  # pragma: no cover - declare an async iterator

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: real_client(
            **kwargs,
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    200, headers={"content-encoding": "gzip"}, stream=UnreadBody()
                )
            ),
        ),
    )
    with pytest.raises(ValueError, match="Compressed HTTP"):
        await safe_http_request(
            "GET", "https://vendor.example/file", download_to=io.BytesIO(), max_response_bytes=8
        )

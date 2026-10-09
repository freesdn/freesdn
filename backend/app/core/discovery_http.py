# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Bounded, credential-free device identification; never authenticates a device.

Unknown appliances often use self-signed certificates. These probes deliberately
retain unverified TLS, but never accept credentials, redirects, ambient proxies,
cookies or compressed bodies. Authenticated management must use its own client.
"""

from __future__ import annotations

import asyncio
import time
from types import TracebackType

import httpx

from app.core.http_client import build_async_client
from app.core.security_utils import resolve_and_pin_host

MAX_BYTES = 256 * 1024
MAX_REQUESTS = 16
TOTAL_SECONDS = 20.0
REQUEST_SECONDS = 5.0


class ProbeLimitError(ValueError):
    """Identification was incomplete; no raw remote diagnostics included."""


class DiscoveryProbe:
    def __init__(self, host: str) -> None:
        self.host = host
        self.pinned = ""
        self.requests = 0
        self.deadline = 0.0
        self.limited = False

    async def __aenter__(self) -> DiscoveryProbe:
        await self.prepare()
        return self

    async def prepare(self) -> None:
        """Resolve and validate the destination before any requests can dispatch."""
        self.deadline = time.monotonic() + TOTAL_SECONDS
        # Resolver work never blocks the event loop. A timed-out OS resolver
        # thread can finish later but cannot dispatch an HTTP request.
        self.pinned = await asyncio.wait_for(
            asyncio.to_thread(resolve_and_pin_host, self.host), timeout=3.0
        )

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        return None

    async def get(
        self, url: str, *, timeout: float = REQUEST_SECONDS, follow_redirects: bool = False
    ) -> httpx.Response:
        target = httpx.URL(url)
        if (
            not self.pinned
            or target.host not in {self.host, self.pinned}
            or target.scheme not in {"http", "https"}
            or target.userinfo
            or follow_redirects
        ):
            raise ValueError("Invalid discovery target")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.requests >= MAX_REQUESTS:
            self.limited = True
            raise ProbeLimitError("Discovery probe budget exhausted")
        self.requests += 1
        target = target.copy_with(host=self.pinned)
        try:
            async with asyncio.timeout(min(timeout, REQUEST_SECONDS, remaining)):
                # Fresh client per request prevents cookies being replayed across
                # ports, schemes or vendor probes. Explicit overlay routing from
                # the shared factory is retained; ambient HTTP_PROXY is ignored.
                async with build_async_client(
                    verify=False,
                    trust_env=False,
                    timeout=REQUEST_SECONDS,
                    follow_redirects=False,
                    headers={"Accept-Encoding": "identity", "User-Agent": "FreeSDN-discovery"},
                ) as client:
                    async with client.stream("GET", target) as response:
                        encoding = response.headers.get("content-encoding", "identity").lower()
                        if encoding not in ("", "identity"):
                            raise ProbeLimitError("Compressed discovery response rejected")
                        length = response.headers.get("content-length")
                        if length is not None and (
                            not length.isdecimal() or int(length) > MAX_BYTES
                        ):
                            raise ProbeLimitError("Discovery response exceeds size limit")
                        body = bytearray()
                        async for chunk in response.aiter_raw():
                            if len(body) + len(chunk) > MAX_BYTES:
                                raise ProbeLimitError("Discovery response exceeds size limit")
                            body.extend(chunk)
                        return httpx.Response(
                            response.status_code,
                            headers=response.headers,
                            content=bytes(body),
                            request=response.request,
                        )
        except (TimeoutError, ProbeLimitError):
            self.limited = True
            raise ProbeLimitError("Discovery observation incomplete or budget exceeded") from None

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN — Adapter response-size guard
=========================================================

httpx imposes NO default response-size limit: ``response.json()`` /
``response.text`` materialize the ENTIRE device-controlled body into memory.
A compromised or brownfield on-prem controller (the explicit adapter threat
model) can answer a routine, auto-polled request with a multi-hundred-MB body
and OOM the adapter / Celery worker — the same memory-exhaustion class confirmed
for the Hikvision XML path, but on every JSON adapter.

This helper enforces a hard ceiling via the ``Content-Length`` header BEFORE the
body is read, so an honest-but-huge (or naively hostile) response is rejected
without buffering. It is a defense-in-depth bound, not a complete solution: a
sophisticated attacker can omit Content-Length and stream chunked to evade the
header check — fully closing that requires a capped streaming read at each call
site. The cap is set generously (64 MB) so no legitimate controller response
(even thousands of clients ≈ a few MB of JSON) is ever rejected.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# 64 MB — far above any legitimate controller response, far below the
# hundreds-of-MB / GB needed to OOM a worker.
MAX_ADAPTER_RESPONSE_BYTES = 64 * 1024 * 1024


class ResponseTooLargeError(Exception):
    """A device response exceeded MAX_ADAPTER_RESPONSE_BYTES."""


def check_response_size(response: Any, limit: int = MAX_ADAPTER_RESPONSE_BYTES) -> None:
    """Raise ResponseTooLargeError if the response's declared body exceeds ``limit``.

    Safe to call on any object exposing ``.headers`` (httpx/aiohttp Response).
    A missing/uparseable Content-Length is tolerated (returns without raising) —
    the cap is best-effort defense-in-depth against the common honest-length
    flood, not a guarantee against chunked-transfer evasion.
    """
    headers = getattr(response, "headers", None)
    raw = None
    if headers:
        raw = headers.get("content-length") or headers.get("Content-Length")
    if raw:
        try:
            size = int(raw)
        except (TypeError, ValueError):
            size = -1
        if size > limit:
            logger.warning(
                "adapter response Content-Length %d exceeds cap %d — refusing to read",
                size,
                limit,
            )
            raise ResponseTooLargeError(f"response body {size} bytes exceeds {limit} cap")

    # a chunked response (or one that omits
    # Content-Length) evades the header check above. For a non-streaming httpx
    # Response the body is already materialized in ``.content`` by the time this
    # runs, so enforce on it too — this bounds the (larger) .json()/.text parse
    # step and surfaces the attack with a clean error instead of an OOM during
    # parsing. (aiohttp exposes ``.content`` as a StreamReader, not bytes — the
    # isinstance guard skips it there. A fully streamed, pre-read cap across
    # every adapter remains tracked as the complete fix.)
    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray)) and len(content) > limit:
        logger.warning(
            "adapter response body %d bytes exceeds cap %d — refusing to parse",
            len(content),
            limit,
        )
        raise ResponseTooLargeError(f"response body {len(content)} bytes exceeds {limit} cap")

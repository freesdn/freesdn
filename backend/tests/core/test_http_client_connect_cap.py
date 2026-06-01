# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Connect-timeout cap guard.

An unreachable device must fail FAST on the connect phase rather than hang up to
the (long) read timeout. The shared ``build_async_client`` factory bounds only
the connect phase of any caller-supplied timeout. A fuzz of every adapter
against an unreachable host showed this turns 20-35s+ hangs into ~8s clean
502/504s; these tests lock the normalisation logic so a future edit can't
silently restore the hang.
"""

from __future__ import annotations

import httpx

from app.core.http_client import (
    _CONNECT_TIMEOUT,
    _cap_connect_timeout,
    build_async_client,
)


def test_bare_float_caps_connect_keeps_read() -> None:
    t = _cap_connect_timeout(30.0)
    assert t.connect == _CONNECT_TIMEOUT
    assert t.read == 30.0


def test_overlong_explicit_connect_is_capped() -> None:
    t = _cap_connect_timeout(httpx.Timeout(600.0, connect=20.0))
    assert t.connect == _CONNECT_TIMEOUT
    assert t.read == 600.0


def test_short_explicit_connect_is_respected() -> None:
    t = _cap_connect_timeout(httpx.Timeout(30.0, connect=3.0))
    assert t.connect == 3.0


def test_none_timeout_bounds_connect_keeps_infinite_read() -> None:
    t = _cap_connect_timeout(None)
    assert t.connect == _CONNECT_TIMEOUT
    assert t.read is None


async def test_build_async_client_caps_a_float_timeout() -> None:
    client = build_async_client(timeout=45.0)
    try:
        assert client.timeout.connect == _CONNECT_TIMEOUT
        assert client.timeout.read == 45.0
    finally:
        await client.aclose()

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Behavioural proof that a mutation is transmitted exactly once.

This exists because a source-scanning ratchet could not do the job. The first
Hikvision retry guard read::

    if attempt < retries and _replay_safe:
        logger.warning(...)
        await asyncio.sleep(...)

which looks like a guard and is not one: the body held only the log and the
sleep, so with ``_replay_safe`` False the ``for`` simply advanced and re-sent the
request. The mutation still went out three times -- and because the sleep was
skipped for exactly that case, the two replays now left with no backoff, making
a double-reboot *faster* rather than preventing it.

``tests/adapters/test_retry_idempotency_ratchet.py`` pinned that exact line as
proof the guard existed, so it reported the adapter as guarded while a PUT was
transmitted three times.

The lesson: pin the BEHAVIOUR. These tests count transport calls.
"""

from __future__ import annotations

import httpx
import pytest


class _CountingTransport:
    """Records every request and always fails the way we ask it to."""

    def __init__(self, exc: Exception) -> None:
        self.calls: list[tuple[str, str]] = []
        self._exc = exc

    async def request(self, method: str, url: str, **_kwargs):
        self.calls.append((method.upper(), url))
        raise self._exc


def _hikvision_adapter(transport: _CountingTransport):
    from app.adapters.hikvision.adapter import HikvisionAdapter

    ad = HikvisionAdapter.__new__(HikvisionAdapter)  # skip __init__ side effects
    ad._client = object()  # non-None so the "not connected" guard passes

    class _Breaker:
        def allow_request(self) -> bool:
            return True

        def record_failure(self) -> None: ...

        def record_success(self) -> None: ...

    ad._breaker = _Breaker()
    # `_http` is a property on the class; bind the fake on the instance's type
    # would leak across tests, so patch via __dict__ of a throwaway subclass.
    ad.__class__ = type("_TestAdapter", (HikvisionAdapter,), {"_http": property(lambda _self: transport)})
    return ad


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["PUT", "POST", "DELETE", "PATCH"])
async def test_a_mutation_is_transmitted_once_on_read_timeout(method: str) -> None:
    """The core regression.

    A ReadTimeout means the request was already on the wire, so the camera may
    have applied it. Replaying a reboot or a config write is the harm this guard
    exists to stop.

    Fails before the fix with ``len(calls) == 3``.
    """
    from app.adapters.exceptions import AdapterConnectionError

    transport = _CountingTransport(httpx.ReadTimeout("no response"))
    adapter = _hikvision_adapter(transport)

    with pytest.raises(AdapterConnectionError):
        await adapter._request(method, "https://camera.example/ISAPI/System/reboot")

    assert len(transport.calls) == 1, (
        f"{method} was transmitted {len(transport.calls)} times after a ReadTimeout. "
        "The device may already have applied the first one."
    )


@pytest.mark.asyncio
async def test_a_read_still_retries_on_read_timeout() -> None:
    """The guard must not cost a legitimate read its retries."""
    from app.adapters.exceptions import AdapterConnectionError

    transport = _CountingTransport(httpx.ReadTimeout("no response"))
    adapter = _hikvision_adapter(transport)

    with pytest.raises(AdapterConnectionError):
        await adapter._request("GET", "https://camera.example/ISAPI/System/deviceInfo", retry_delay=0)

    assert len(transport.calls) == 3, (
        "a GET is safe to replay and must keep its retry budget; "
        f"got {len(transport.calls)} transmission(s)"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["PUT", "GET"])
async def test_connect_phase_failure_still_retries_for_any_method(method: str) -> None:
    """A ConnectError never left us, so replaying it is safe even for a write."""
    from app.adapters.exceptions import AdapterConnectionError

    transport = _CountingTransport(httpx.ConnectError("refused"))
    adapter = _hikvision_adapter(transport)

    with pytest.raises(AdapterConnectionError):
        await adapter._request(method, "https://camera.example/ISAPI/System/reboot", retry_delay=0)

    assert len(transport.calls) == 3, (
        f"{method} after a ConnectError should retry (nothing was sent); "
        f"got {len(transport.calls)}"
    )

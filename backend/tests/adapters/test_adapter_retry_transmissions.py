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
    ad.__class__ = type(
        "_TestAdapter", (HikvisionAdapter,), {"_http": property(lambda _self: transport)}
    )
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
async def test_a_read_is_not_retried_on_read_timeout() -> None:
    """io_policy: a timeout is never replayed, not even for a GET.

    This test used to assert the opposite (3 transmissions). An NVR that did not
    answer within the read timeout is slow or wedged; asking twice more only
    triples the wait and its load (2026-11 soak, see app/adapters/io_policy.py).
    """
    from app.adapters.exceptions import AdapterConnectionError

    transport = _CountingTransport(httpx.ReadTimeout("no response"))
    adapter = _hikvision_adapter(transport)

    with pytest.raises(AdapterConnectionError):
        await adapter._request(
            "GET", "https://camera.example/ISAPI/System/deviceInfo", retry_delay=0
        )

    assert len(transport.calls) == 1, (
        f"a timed-out GET must not be replayed; got {len(transport.calls)} transmission(s)"
    )


@pytest.mark.asyncio
async def test_a_read_still_retries_after_a_dropped_connection() -> None:
    """The guard must not cost a legitimate read the retry that can help it."""
    from app.adapters.exceptions import AdapterConnectionError

    transport = _CountingTransport(httpx.RemoteProtocolError("server disconnected"))
    adapter = _hikvision_adapter(transport)

    with pytest.raises(AdapterConnectionError):
        await adapter._request(
            "GET", "https://camera.example/ISAPI/System/deviceInfo", retry_delay=0
        )

    assert len(transport.calls) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["PUT", "POST"])
async def test_a_dropped_connection_on_a_mutation_is_sent_once_and_propagates(method) -> None:
    """Ambiguous: the camera may have acted. Unchanged, raw, for the staging path."""
    transport = _CountingTransport(httpx.RemoteProtocolError("server disconnected"))
    adapter = _hikvision_adapter(transport)

    with pytest.raises(httpx.RemoteProtocolError):
        await adapter._request(method, "https://camera.example/ISAPI/System/reboot", retry_delay=0)

    assert len(transport.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["PUT", "GET"])
async def test_connect_phase_failure_is_not_retried(method: str) -> None:
    """io_policy: a refused or unreachable camera will not recover in a second.

    This used to retry 3 times for any method ("nothing was sent", so it was
    safe) -- safe, but useless: 3 x the 8 s connect cap for a camera that is off.
    """
    from app.adapters.exceptions import AdapterConnectionError

    transport = _CountingTransport(httpx.ConnectError("refused"))
    adapter = _hikvision_adapter(transport)

    with pytest.raises(AdapterConnectionError):
        await adapter._request(method, "https://camera.example/ISAPI/System/reboot", retry_delay=0)

    assert len(transport.calls) == 1, (
        f"{method} after a ConnectError must not be retried; got {len(transport.calls)}"
    )

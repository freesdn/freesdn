"""Actual ASGI response exception/cancellation ownership, without SQL authority."""

import asyncio
from types import MethodType
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.services import agent_release_delivery as delivery
from tests.harness_wait import HARNESS_WAIT_SECONDS


class OwnedClosure:
    def __init__(self):
        self.closed = 0

    async def close(self):
        self.closed += 1


def response(run, started):
    # Exercise the real response lifetime without manufacturing a read authority.
    # _run is the explicit boundary; no download authorization is qualified here.
    value = object.__new__(delivery.ManagedReleaseResponse)
    value._used = value._completed = False
    value._started = started
    value._storage = OwnedClosure()
    value._run = MethodType(run, value)
    return value


def all_reader_slots_returned():
    acquired = 0
    try:
        while delivery._READERS.acquire(blocking=False):
            acquired += 1
        assert acquired == 8
    finally:
        for _ in range(acquired):
            delivery._READERS.release()


async def never_receive():
    await asyncio.Event().wait()


async def no_send(message):
    raise AssertionError("Failure contract must not manufacture response bytes")


@pytest.mark.parametrize("started", [False, True])
@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("kind", ["http", "storage", "os"])
async def test_response_keeps_error_mapping_and_owned_cleanup(started, wrapped, kind):
    failure = {
        "http": HTTPException(403, "Managed scope denied"),
        "storage": delivery.ArtifactUnavailable("synthetic-private-detail"),
        "os": OSError("synthetic-private-detail"),
    }[kind]

    async def run(self, scope, receive, send):
        if wrapped:
            raise ExceptionGroup("owned nested group", [ExceptionGroup("inner", [failure])])
        raise failure

    item = response(run, started)
    with pytest.raises(RuntimeError if started else HTTPException) as caught:
        await item({"type": "http", "method": "GET"}, never_receive, no_send)
    assert item._storage.closed == 1 and item._used
    assert "synthetic-private-detail" not in str(caught.value)
    if not started:
        assert caught.value.status_code == (403 if kind == "http" else 503)
    all_reader_slots_returned()


@pytest.mark.parametrize("started", [False, True])
async def test_multiple_independent_failures_are_preserved(started):
    failures = [ValueError("first-" + uuid4().hex), RuntimeError("second-" + uuid4().hex)]

    async def run(self, scope, receive, send):
        raise ExceptionGroup("owned simultaneous failures", failures)

    item = response(run, started)
    with pytest.raises(ExceptionGroup) as caught:
        await item({"type": "http", "method": "HEAD"}, never_receive, no_send)
    assert list(caught.value.exceptions) == failures
    assert item._storage.closed == 1
    all_reader_slots_returned()


@pytest.mark.parametrize("started", [False, True])
async def test_raw_cancellation_is_not_converted_to_completion(started):
    entered = asyncio.Event()

    async def run(self, scope, receive, send):
        entered.set()
        await asyncio.Event().wait()

    item = response(run, started)
    task = asyncio.create_task(item({"type": "http", "method": "GET"}, never_receive, no_send))
    await asyncio.wait_for(entered.wait(), HARNESS_WAIT_SECONDS)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, HARNESS_WAIT_SECONDS)
    assert item._storage.closed == 1 and not item._completed
    all_reader_slots_returned()

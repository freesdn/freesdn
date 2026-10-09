# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real filesystem/ASGI owner controls; these do not qualify authentication."""

import asyncio
import json
import threading
import time

import anyio
import pytest
from starlette.middleware.cors import CORSMiddleware

from app.core.backup_download_lifetime import SCOPE_KEY, DownloadLifetimeMiddleware
from app.core.backup_downloads import DownloadSnapshot
from tests.services.test_backup_download_response_lifetime import Sink, fixture, opened


def http_scope(origin=None):
    return {
        "type": "http", "method": "GET", "path": "/owned-download", "headers":
        [(b"origin", origin.encode())] if origin else [], "asgi": {"spec_version": "2.4"},
    }


@pytest.mark.parametrize("allowed", [False, True])
@pytest.mark.parametrize("verified", [False, True])
async def test_outer_preheader_deadline_preserves_CORS_and_closes_before_504(
    tmp_path, request, allowed, verified,
):
    response, _path, _identity = fixture(tmp_path, size=127, verified=verified, seconds=5)
    authority_entered = asyncio.Event()

    async def blocked_authority():
        authority_entered.set()
        # Measure expiry at this owned boundary, after real disk preparation.
        # Reaching it is not a 50 ms filesystem performance requirement.
        scope[SCOPE_KEY].deadline.deadline = anyio.current_time() + .05
        await asyncio.Event().wait()

    response.authorize = blocked_authority
    origin = "https://owned-ui.example" if allowed else "https://untrusted-ui.example"
    middleware = CORSMiddleware(DownloadLifetimeMiddleware(response),
                                allow_origins=["https://owned-ui.example"], allow_credentials=True)
    sink = Sink()
    scope = http_scope(origin)
    original_send = sink.send
    cleanup_at_headers = []

    async def send(message):
        if message["type"] == "http.response.start":
            cleanup_at_headers.append(not opened(tmp_path / "spool"))
            response.pool.acquire().close()
        await original_send(message)

    started = time.monotonic()
    await asyncio.wait_for(middleware(scope, sink.receive, send), 5)
    elapsed = time.monotonic() - started
    request.node.user_properties.extend([
        ("authority_entered", authority_entered.is_set()), ("elapsed_seconds", elapsed),
        ("HTTP_status", sink.status), ("cleanup_before_headers", cleanup_at_headers),
        ("CORS_origin", sink.headers.get(b"access-control-allow-origin")),
        ("request_scope_released", SCOPE_KEY not in scope),
    ])
    assert authority_entered.is_set() and elapsed >= .05
    assert sink.status == 504 and sink.completed and cleanup_at_headers == [True]
    assert sink.headers.get(b"access-control-allow-origin") == (origin.encode() if allowed else None)
    assert SCOPE_KEY not in scope and not opened(tmp_path / "spool")


@pytest.mark.parametrize("kind", ["task", "anyio", "deadline"])
@pytest.mark.parametrize("close_failure", [False, True])
async def test_outer_cleanup_owns_real_close_across_repeated_cancellation(
    tmp_path, monkeypatch, request, caplog, kind, close_failure,
):
    response, _path, _identity = fixture(tmp_path, size=127, seconds=.05 if kind == "deadline" else 5)
    entered, release = threading.Event(), threading.Event()
    original = DownloadSnapshot.close
    physical_closes = []

    def close(snapshot):
        entered.set()
        assert release.wait(10), "Owned close boundary was not released"
        original(snapshot)
        physical_closes.append(True)
        if close_failure:
            raise OSError("owned-private-close-error-never-log")

    monkeypatch.setattr(DownloadSnapshot, "close", close)
    sink = Sink(paused=kind == "deadline")
    middleware = DownloadLifetimeMiddleware(response)
    scope = http_scope()
    scopes = []
    outcome = []

    async def run():
        with anyio.CancelScope() as cancel_scope:
            scopes.append(cancel_scope)
            try:
                await middleware(scope, sink.receive, sink.send)
            except BaseException as error:
                outcome.append(error)
                raise

    task = asyncio.create_task(run())
    try:
        with anyio.fail_after(5):
            while not entered.is_set():
                await asyncio.sleep(.005)
        holds_resource = bool(opened(tmp_path / "spool"))
        for _ in range(3):
            if kind == "task":
                task.cancel()
            elif kind == "anyio":
                scopes[0].cancel()
            await asyncio.sleep(.005)
        owner_pending = not task.done()
        release.set()
        result = await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)
    finally:
        release.set()
        sink.release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    request.node.user_properties.extend([
        ("real_close_entered", entered.is_set()), ("resource_held_at_close", holds_resource),
        ("owner_pending_during_cleanup", owner_pending), ("physical_closes", len(physical_closes)),
        ("result_type", type(result[0]).__name__),
        ("inner_outcome_type", type(outcome[0]).__name__ if outcome else None),
        ("request_scope_released", SCOPE_KEY not in scope),
        ("private_cleanup_text_logged", "owned-private-close-error-never-log" in caplog.text),
    ])
    assert holds_resource and owner_pending and physical_closes == [True]
    assert not opened(tmp_path / "spool") and SCOPE_KEY not in scope
    assert "owned-private-close-error-never-log" not in caplog.text
    if kind == "deadline":
        assert isinstance(result[0], TimeoutError) and not sink.completed
    elif kind == "task":
        assert isinstance(result[0], asyncio.CancelledError)
    else:
        assert result == [None] and len(outcome) == 1 and isinstance(outcome[0], asyncio.CancelledError)
    # Restore the real close before the reuse check; do not hide owned failures.
    monkeypatch.setattr(DownloadSnapshot, "close", original)
    response.pool.acquire().close()


@pytest.mark.parametrize("headers_sent", [False, True])
async def test_unrelated_timeout_is_preserved_without_download_refusal(request, headers_sent):
    original = TimeoutError("owned-unrelated-application-timeout")
    messages = []

    async def app(scope, receive, send):
        if headers_sent:
            await send({"type": "http.response.start", "status": 202, "headers": []})
        raise original

    async def receive():
        raise AssertionError("Lifetime middleware must not read the request")

    async def send(message):
        messages.append(message)

    scope = http_scope()
    with pytest.raises(TimeoutError) as seen:
        await DownloadLifetimeMiddleware(app)(scope, receive, send)
    request.node.user_properties.extend([("same_exception", seen.value is original),
        ("messages", json.dumps(messages)), ("scope_released", SCOPE_KEY not in scope)])
    assert seen.value is original and SCOPE_KEY not in scope
    assert messages == ([{"type": "http.response.start", "status": 202, "headers": []}] if headers_sent else [])


@pytest.mark.parametrize("kind", ["websocket", "lifespan"])
async def test_non_HTTP_scope_receive_send_are_passed_through(request, kind):
    scope = {"type": kind}
    seen = []

    async def receive():
        return {"type": "websocket.connect" if kind == "websocket" else "lifespan.startup"}

    async def send(message):
        seen.append(message)

    async def app(actual, actual_receive, actual_send):
        assert actual is scope and actual_receive is receive and actual_send is send
        assert SCOPE_KEY not in actual
        await actual_receive()
        await actual_send({"type": "websocket.accept" if kind == "websocket" else "lifespan.startup.complete"})

    await DownloadLifetimeMiddleware(app)(scope, receive, send)
    request.node.user_properties.extend([("scope_unchanged", scope == {"type": kind}), ("messages", json.dumps(seen))])
    assert scope == {"type": kind} and len(seen) == 1

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real TLS client-close ownership with explicit controlled boundary pauses."""

import asyncio
import time

import anyio
import httpx
import pytest

from app.services.backup import BackupRecoveryError, WebDAVStorageBackend
from tests.services.test_webdav_protocol_contract import BODY, PATH, observe
from tests.services.webdav_owned_peer import webdav_peer

assert webdav_peer  # Export the shared fixture without changing its source.


@pytest.mark.parametrize("close_phase", ["before-close", "after-close"])
@pytest.mark.parametrize("mode", ["control", "direct-cancel", "scope-cancel", "repeated-mixed-cancel", "late-deadline"])
@pytest.mark.parametrize("close_error", [False, True])
async def test_owned_client_close_wait(monkeypatch, webdav_peer, request, caplog, close_phase, mode, close_error):
    peer = webdav_peer
    peer.files[PATH] = BODY
    entered, release = asyncio.Event(), asyncio.Event()
    clients, close_calls, physically_closed = [], [], []
    original_client = httpx.AsyncClient
    marker = "owned-synthetic-private-close-error"
    observed = {}
    if mode == "late-deadline":
        monkeypatch.setattr(WebDAVStorageBackend, "_OPERATION_SECONDS", 0.25)

    def make_client(*args, **kwargs):
        client = original_client(*args, **kwargs)
        clients.append(client)
        original_close = client.aclose

        async def controlled_close():
            close_calls.append(time.monotonic())
            if close_phase == "before-close":
                entered.set()
                await release.wait()
            await original_close()
            physically_closed.append(time.monotonic())
            if close_phase == "after-close":
                entered.set()
                await release.wait()
            if close_error:
                raise RuntimeError(marker)

        client.aclose = controlled_close
        return client

    monkeypatch.setattr(httpx, "AsyncClient", make_client)
    backend = WebDAVStorageBackend(peer.config())
    assert not clients, "Unused backend construction must not create an unowned client"

    async def operation():
        with anyio.CancelScope() as scope:
            observed["scope"] = scope
            try:
                observed["data"] = await backend.load(peer.locator())
            except BaseException as error:
                observed["error"] = error
                raise

    started = time.monotonic()
    owner = asyncio.create_task(operation())
    try:
        await asyncio.wait_for(entered.wait(), 5)
        assert len(clients) == len(close_calls) == 1, "Actual client close must be reached once"
        assert peer.requests and peer.requests[0]["TLS"] and peer.requests[0]["authorized"]
        if mode in {"direct-cancel", "repeated-mixed-cancel"}:
            owner.cancel()
        if mode in {"scope-cancel", "repeated-mixed-cancel"}:
            observed["scope"].cancel()
        await asyncio.sleep(0.025)
        if mode == "repeated-mixed-cancel":
            owner.cancel()
            await asyncio.sleep(0.025)
        if mode == "late-deadline":
            await asyncio.sleep(max(0, 0.35 - (time.monotonic() - started)))
        held = not owner.done()
        closed_while_paused = clients[0].is_closed
        pool_while_paused = len(clients[0]._transport._pool.connections)
        release.set()
        try:
            await asyncio.wait_for(owner, 5)
        except (asyncio.CancelledError, Exception):
            pass
        error = observed.get("error")
        observe(request, peer, close_phase=close_phase, mode=mode, close_error=close_error,
                owner_held_until_close_release=held, client_closed_while_paused=closed_while_paused,
                pool_connections_while_paused=pool_while_paused, close_calls=len(close_calls),
                actual_close_completions=len(physically_closed), client_closed_at_completion=clients[0].is_closed,
                pool_connections_at_completion=len(clients[0]._transport._pool.connections),
                returned_exact_bytes=observed.get("data") == BODY,
                exception_type=type(error).__name__ if error else None,
                private_marker_logged=marker in caplog.text, elapsed_seconds=time.monotonic() - started)
        assert held, "Operation detached mandatory client cleanup"
        assert closed_while_paused is (close_phase == "after-close")
        assert pool_while_paused == (1 if close_phase == "before-close" else 0)
        assert len(close_calls) == len(physically_closed) == 1
        assert clients[0].is_closed and not clients[0]._transport._pool.connections
        assert marker not in caplog.text
        if "cancel" in mode:
            assert isinstance(error, asyncio.CancelledError) and "data" not in observed
        elif close_error:
            assert isinstance(error, BackupRecoveryError) and marker not in str(error) and "data" not in observed
        elif mode == "late-deadline":
            assert isinstance(error, TimeoutError) and "data" not in observed, "Delivery must not succeed after its operation deadline during mandatory close"
        else:
            assert error is None and observed.get("data") == BODY
    finally:
        release.set()
        if not owner.done():
            owner.cancel()
        await asyncio.gather(owner, return_exceptions=True)
        await backend.close()

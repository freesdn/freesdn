# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real API/TLS/disk handoffs, with explicit pauses around actual operations.

Fault injection occurs only after real append/seal/close operations. Allocation
is paused before its return, without inventing an exception that would violate
the allocator's own cleanup contract. Scoped cancellation is observed without
an extra caller checkpoint which could hide a normal return from the response.
"""

import asyncio
import hashlib
import json
import logging
import threading
import time
from types import SimpleNamespace

import anyio
import httpx
import pytest

from app.core.backup_downloads import DownloadCapacityError, DownloadPool, DownloadSnapshot
from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES
from tests.services import webdav_owned_peer
from tests.services.test_backup_download_resource_lifetime import SlowBodySink
from tests.services.test_backup_download_response_lifetime import opened
from tests.services.test_webdav_service_client_ownership import remote_actor, seeded_archive

webdav_peer = webdav_owned_peer.webdav_peer
PRIVATE_MARKER = "owned-remote-lifecycle-private-error-marker"
PHASES = ["allocation", "append", "seal", "network-close", "snapshot-close"]
CASES = [(phase, kind, failure) for phase in PHASES
         for kind in ["control", "task", "scope"] for failure in [False, True]
         if phase != "allocation" or not failure]


class Gate:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.hits = 0
        self.escape = False
        self.at = None

    def pause_sync(self):
        self.hits += 1
        self.at = time.monotonic()
        self.entered.set()
        if not self.release.wait(15):
            self.escape = True
            raise AssertionError("Owned transfer gate was not released")

    async def pause_async(self):
        self.hits += 1
        self.at = time.monotonic()
        self.entered.set()
        deadline = time.monotonic() + 15
        while not self.release.is_set():
            if time.monotonic() >= deadline:
                self.escape = True
                raise AssertionError("Owned client-close gate was not released")
            await asyncio.sleep(0.005)


async def scenario(monkeypatch, tmp_path, peer, request, caplog, credential, phase, kind, failure):
    async with remote_actor(monkeypatch, tmp_path, peer, credential) as f:
        backup_id, saved = await seeded_archive(f, False)
        size, digest = len(saved), hashlib.sha256(saved).hexdigest()
        root = tmp_path / "owned-transfer-pool"
        settings = SimpleNamespace(BACKUP_DOWNLOAD_SPOOL=str(root), BACKUP_DOWNLOAD_SLOTS=1,
                                   BACKUP_DOWNLOAD_FREE_BYTES=0,
                                   BACKUP_DOWNLOAD_SECONDS=2.0 if kind == "deadline" else 10.0)
        pool = DownloadPool(root, slots=1, limit=MAX_BACKUP_IMPORT_BYTES, free_floor=0)
        gate = Gate()
        leases = []
        physical = {"append": 0, "seal": 0, "snapshot-close": 0, "network-close": 0}
        real_acquire = DownloadPool.acquire
        real_append = DownloadSnapshot.append
        real_seal = DownloadSnapshot.seal
        real_close = DownloadSnapshot.close
        client_type = type(f.actor.client)
        real_client_close = client_type.aclose

        def acquire(instance):
            lease = real_acquire(instance)
            leases.append(lease)
            if phase == "allocation":
                gate.pause_sync()
            return lease

        def append(lease, value):
            real_append(lease, value)
            physical["append"] += 1
            if phase == "append" and not gate.hits:
                gate.pause_sync()
                if failure:
                    raise OSError(PRIVATE_MARKER)

        def seal(lease, expected):
            result = real_seal(lease, expected)
            physical["seal"] += 1
            if phase == "seal":
                gate.pause_sync()
                if failure:
                    raise OSError(PRIVATE_MARKER)
            return result

        def close(lease):
            if phase == "snapshot-close" and not gate.hits:
                gate.pause_sync()
            real_close(lease)
            physical["snapshot-close"] += 1
            if phase == "snapshot-close" and failure:
                raise OSError(PRIVATE_MARKER)

        async def client_close(instance):
            if isinstance(instance._transport, httpx.ASGITransport):
                await real_client_close(instance)
                return
            if phase == "network-close":
                await gate.pause_async()
            await real_client_close(instance)
            physical["network-close"] += 1
            if phase == "network-close" and failure:
                raise OSError(PRIVATE_MARKER)

        sink = SlowBodySink()
        sink.release.set()
        state = {"returned_from_ASGI": False, "scope_cancelled_caught": False}
        scopes = []

        async def owner():
            scope = anyio.CancelScope()
            try:
                with scope:
                    scopes.append(scope)
                    await sink.run(f.actor, backup_id)
                    state["returned_from_ASGI"] = True
            finally:
                state["scope_cancelled_caught"] = scope.cancelled_caught

        with caplog.at_level(logging.WARNING), monkeypatch.context() as patch:
            patch.setattr("app.api.v1.endpoints.backups.get_settings", lambda: settings)
            patch.setattr(DownloadPool, "acquire", acquire)
            patch.setattr(DownloadSnapshot, "append", append)
            patch.setattr(DownloadSnapshot, "seal", seal)
            patch.setattr(DownloadSnapshot, "close", close)
            patch.setattr(client_type, "aclose", client_close)
            task = asyncio.create_task(owner())
            started = time.monotonic()
            try:
                with anyio.fail_after(10):
                    while not gate.entered.is_set() and not task.done():
                        await asyncio.sleep(0.005)
                reached = gate.entered.is_set() and not task.done()
                assert reached, "Actual owned lifecycle boundary was not reached"
                accepted = []
                if kind in {"task", "scope"}:
                    for _ in range(3):
                        if kind == "task":
                            accepted.append(task.cancel())
                        else:
                            scopes[0].cancel()
                        await asyncio.sleep(0.01)
                elif kind == "deadline":
                    while time.monotonic() - started < 2.3:
                        await asyncio.sleep(0.01)
                else:
                    await asyncio.sleep(0.03)
                observed = {
                    "actual_boundary_reached": reached, "owner_held_while_gate_paused": not task.done(),
                    "owned_descriptors_live_at_gate": bool(opened(root)),
                    "accepted_cancel_calls": json.dumps(accepted),
                    "status_at_gate": sink.status, "bytes_at_gate": sink.bytes,
                    "pause_seconds": time.monotonic() - gate.at,
                    "request_elapsed_before_release": time.monotonic() - started,
                }
            finally:
                gate.release.set()
                results = await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 10)
            observed.update(
                phase=phase, kind=kind, injected_error=failure, gate_hits=gate.hits,
                escape_fired=gate.escape, **state, HTTP_status=sink.status,
                body_bytes=sink.bytes, response_completed=sink.finished,
                exact_archive=sink.bytes == size and sink.digest.hexdigest() == digest,
                result_type=type(results[0]).__name__,
                physical_operations=json.dumps(physical, sort_keys=True),
                leases_allocated=len(leases),
                all_snapshot_descriptors_closed=all(lease._fd == lease._slot == -1 for lease in leases),
                no_owned_descriptors=not opened(root),
                network_clients_open=sum(not client.is_closed for client in f.clients),
                network_pool_connections=sum(len(client._transport._pool.connections) for client in f.clients),
                private_marker_logged=PRIVATE_MARKER in caplog.text,
                private_marker_returned=any(PRIVATE_MARKER in str(result) for result in results if isinstance(result, Exception)),
            )
        # Patches are removed before the independent post-cleanup capacity check.
        try:
            lease = pool.acquire()
        except DownloadCapacityError:
            observed["slot_available_after_cleanup"] = False
        else:
            lease.close()
            observed["slot_available_after_cleanup"] = True
        finally:
            # Retain any observed ownership failure, then close only test-owned
            # leaked descriptors so one failed probe cannot poison later cases.
            for lease in leases:
                if lease._fd >= 0 or lease._slot >= 0:
                    real_close(lease)
        request.node.user_properties.extend({**observed, "owned_peer_port": peer.port,
            "peer_requests": json.dumps(peer.requests, sort_keys=True),
            "scope": "actual API/PG/TLS/disk ownership after explicit loopback admission; instrumented handoffs, not stuck-kernel or process-loss proof"}.items())
        assert observed["actual_boundary_reached"] and observed["owner_held_while_gate_paused"]
        assert observed["owned_descriptors_live_at_gate"] and observed["gate_hits"] == 1
        assert not observed["escape_fired"] and observed["leases_allocated"] == 1
        assert observed["all_snapshot_descriptors_closed"] and observed["no_owned_descriptors"]
        assert observed["network_clients_open"] == observed["network_pool_connections"] == 0
        assert observed["slot_available_after_cleanup"]
        assert not observed["private_marker_logged"] and not observed["private_marker_returned"]
        if kind in {"task", "scope"}:
            if phase != "snapshot-close":
                assert observed["HTTP_status"] is None and observed["body_bytes"] == 0
            else:
                # Already-delivered bytes cannot be retracted by later cancellation.
                assert observed["exact_archive"] and observed["response_completed"]
            if kind == "task":
                assert accepted == [True, True, True]
                assert isinstance(results[0], asyncio.CancelledError)
            else:
                assert results == [None]
                assert observed["scope_cancelled_caught"]
            assert not observed["returned_from_ASGI"]
        elif kind == "deadline":
            assert observed["request_elapsed_before_release"] >= 2.3
            assert observed["HTTP_status"] == 504 and not observed["exact_archive"]
            assert results == [None]
        elif failure:
            if phase == "snapshot-close":
                assert observed["HTTP_status"] == 200 and observed["exact_archive"]
                assert isinstance(results[0], Exception)
            else:
                assert observed["HTTP_status"] == 500 and not observed["exact_archive"]
                assert results == [None]
        else:
            assert observed["HTTP_status"] == 200 and observed["exact_archive"] and observed["response_completed"]
            assert results == [None]


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize(("phase", "kind", "failure"), CASES)
async def test_real_remote_handoffs_keep_ownership_and_cancellation(
    monkeypatch, tmp_path, webdav_peer, request, caplog, credential, phase, kind, failure,
):
    await scenario(monkeypatch, tmp_path, webdav_peer, request, caplog, credential, phase, kind, failure)


@pytest.mark.parametrize("phase", ["allocation", "append", "seal", "network-close"])
async def test_real_remote_preparation_deadline_retains_cleanup(
    monkeypatch, tmp_path, webdav_peer, request, caplog, phase,
):
    await scenario(monkeypatch, tmp_path, webdav_peer, request, caplog, "jwt", phase, "deadline", False)

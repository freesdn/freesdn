# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real small archive delivery across the complete application middleware stack.

The proposed download admission contract includes middleware-owned body bytes,
not only the disk snapshot producer. This is not a global API connection cap.
All owned state and delivery observations precede the proposed assertions.
"""

import asyncio
import hashlib
import json
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace

import anyio
import pytest

from app.core.config import get_settings
from tests.services import webdav_owned_peer
from tests.services.test_backup_artifact_integrity_contract import (
    create_archive,
    owned_actor,
    recorded_download_headers,
)
from tests.services.test_backup_download_resource_lifetime import SlowBodySink
from tests.services.test_backup_download_response_lifetime import opened
from tests.services.test_webdav_service_client_ownership import remote_actor, seeded_archive

webdav_peer = webdav_owned_peer.webdav_peer


@asynccontextmanager
async def subject(monkeypatch, tmp_path, peer, backend, credential, secrets, seconds=20):
    root = tmp_path / "owned-outer-admission-pool"
    settings = get_settings().model_copy(update={
        "BACKUP_DOWNLOAD_SPOOL": str(root), "BACKUP_DOWNLOAD_SLOTS": 1,
        "BACKUP_DOWNLOAD_FREE_BYTES": 0, "BACKUP_DOWNLOAD_SECONDS": seconds,
    })
    monkeypatch.setattr("app.api.v1.endpoints.backups.get_settings", lambda: settings)
    monkeypatch.setattr("app.services.vault_export_public_download.get_settings", lambda: settings)
    if backend == "webdav":
        async with remote_actor(monkeypatch, tmp_path, peer, credential) as remote:
            backup_id, saved = await seeded_archive(remote, secrets)
            yield SimpleNamespace(actor=remote.actor, backup_id=backup_id, saved=saved,
                                  root=root, remote=remote, peer=peer, backend=backend)
    else:
        async with owned_actor(monkeypatch, tmp_path, credential) as actor:
            backup, _path, saved = await create_archive(actor, secrets)
            yield SimpleNamespace(actor=actor, backup_id=backup.id, saved=saved,
                                  root=root, remote=None, peer=peer, backend=backend)


def record(request, f, **observations):
    clients = f.remote.clients if f.remote else []
    values = {
        "backend": f.backend, "archive_bytes": len(f.saved),
        "no_snapshot_descriptors": not opened(f.root),
        "network_clients_open": sum(not c.is_closed for c in clients),
        "network_pool_connections": sum(len(c._transport._pool.connections) for c in clients),
        "provider_GETs": sum(r["method"] == "GET" for r in f.peer.requests),
        "peer_requests": json.dumps(f.peer.requests, sort_keys=True),
        "owned_peer_port": f.peer.port,
        "scope": "real API/PG/local-or-owned-TLS archive across complete middleware and paused outer ASGI send; not global API or production-container admission",
        **observations,
    }
    request.node.user_properties.extend(values.items())
    return values


async def release_owned(task, sink, ending):
    if ending == "task":
        task.cancel()
    elif ending == "send-error":
        sink.fail_send = True
    sink.release.set()
    return await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)


@pytest.mark.parametrize("backend", ["local", "webdav"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("ending", ["complete", "task", "send-error"])
async def test_small_outer_download_retains_admission_until_delivery_ends(
    monkeypatch, tmp_path, webdav_peer, request, backend, credential, secrets, ending,
):
    async with subject(monkeypatch, tmp_path, webdav_peer, backend, credential, secrets) as f:
        first_headers = await recorded_download_headers(f.actor, f.backup_id, secrets)
        blocked_headers = await recorded_download_headers(f.actor, f.backup_id, secrets)
        retry_headers = await recorded_download_headers(f.actor, f.backup_id, secrets)
        sink = SlowBodySink()
        task = asyncio.create_task(sink.run(f.actor, f.backup_id, headers=first_headers))
        try:
            with anyio.fail_after(10):
                await sink.entered.wait()
            assert 0 < len(f.saved) == sink.held_chunk <= 65536 and sink.status == 200
            outer_pending_before = not task.done() and not sink.release.is_set()
            gets_before = sum(r["method"] == "GET" for r in f.peer.requests)
            blocked = await f.actor.client.get(f"/api/v1/backups/{f.backup_id}/download", headers=blocked_headers)
            gets_after = sum(r["method"] == "GET" for r in f.peer.requests)
            outer_pending_after = not task.done() and not sink.release.is_set()
            results = await release_owned(task, sink, ending)
            retry = await f.actor.client.get(f"/api/v1/backups/{f.backup_id}/download", headers=retry_headers)
            observed = record(request, f, ending=ending,
                outer_pending_before=outer_pending_before, outer_pending_after=outer_pending_after,
                provider_GETs_before_second=gets_before, provider_GETs_after_second=gets_after,
                second_status=blocked.status_code, second_exact_archive=blocked.content == f.saved,
                second_integrity=blocked.headers.get("x-freesdn-artifact-integrity"),
                second_retry_after=blocked.headers.get("retry-after"),
                first_result_type=type(results[0]).__name__, first_complete=sink.finished,
                first_exact_archive=sink.bytes == len(f.saved) and sink.digest.hexdigest() == hashlib.sha256(f.saved).hexdigest(),
                retry_status=retry.status_code, retry_exact_archive=retry.content == f.saved)
            assert outer_pending_before and outer_pending_after
            assert observed["no_snapshot_descriptors"]
            assert observed["network_clients_open"] == observed["network_pool_connections"] == 0
            assert blocked.status_code == 503 and observed["second_retry_after"] == "5"
            assert not observed["second_exact_archive"] and observed["second_integrity"] is None
            assert gets_before == gets_after == (1 if backend == "webdav" else 0)
            assert retry.status_code == 200 and retry.content == f.saved
            if ending == "complete":
                assert results == [None] and observed["first_complete"] and observed["first_exact_archive"]
            elif ending == "task":
                assert isinstance(results[0], asyncio.CancelledError) and not observed["first_complete"]
            else:
                assert isinstance(results[0], Exception) and not observed["first_complete"]
        finally:
            sink.release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("backend", ["local", "webdav"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_small_outer_download_deadline_outlives_producer_completion(
    monkeypatch, tmp_path, webdav_peer, request, backend, credential, secrets,
):
    # Short enough to expire while the first chunk is held, long enough that the
    # authentication and preparation inside it finish first. At 2 s, one full
    # garbage collection during preparation (2.3 s in public CI) spent all of it.
    deadline = 6
    async with subject(monkeypatch, tmp_path, webdav_peer, backend, credential, secrets, seconds=deadline) as f:
        first_headers = await recorded_download_headers(f.actor, f.backup_id, secrets)
        retry_headers = await recorded_download_headers(f.actor, f.backup_id, secrets)
        sink = SlowBodySink()
        task = asyncio.create_task(sink.run(f.actor, f.backup_id, headers=first_headers))
        try:
            with anyio.fail_after(10):
                await sink.entered.wait()
            assert 0 < len(f.saved) == sink.held_chunk <= 65536 and sink.status == 200
            # Start at the actual held-body boundary, after authentication and preparation.
            started = time.monotonic()
            while time.monotonic() - started < deadline + .4:
                await asyncio.sleep(.01)
            ended_before_sink_release = task.done()
            sink_held_until_deadline = not sink.release.is_set()
            elapsed = time.monotonic() - started
            results = await release_owned(task, sink, "complete")
            retry = await f.actor.client.get(f"/api/v1/backups/{f.backup_id}/download", headers=retry_headers)
            observed = record(request, f, real_elapsed_seconds=elapsed,
                ended_before_sink_release=ended_before_sink_release,
                sink_not_released_during_wait=sink_held_until_deadline,
                first_result_type=type(results[0]).__name__, first_status=sink.status,
                first_bytes=sink.bytes, first_complete=sink.finished,
                retry_status=retry.status_code, retry_exact_archive=retry.content == f.saved)
            assert elapsed >= deadline + .4 and sink_held_until_deadline
            assert observed["no_snapshot_descriptors"]
            assert observed["network_clients_open"] == observed["network_pool_connections"] == 0
            assert ended_before_sink_release, "Request deadline stopped with the producer before outer delivery ended"
            # Headers were already sent. Abort the partial response rather than
            # fabricating a second HTTP status or retracting transmitted bytes.
            assert isinstance(results[0], TimeoutError) and not sink.finished
            assert retry.status_code == 200 and retry.content == f.saved
        finally:
            sink.release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("backend", ["local", "webdav"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_small_outer_download_without_backpressure_remains_usable(
    monkeypatch, tmp_path, webdav_peer, request, backend, credential, secrets,
):
    async with subject(monkeypatch, tmp_path, webdav_peer, backend, credential, secrets) as f:
        first_headers = await recorded_download_headers(f.actor, f.backup_id, secrets)
        second_headers = await recorded_download_headers(f.actor, f.backup_id, secrets)
        first = await f.actor.client.get(f"/api/v1/backups/{f.backup_id}/download", headers=first_headers)
        second = await f.actor.client.get(f"/api/v1/backups/{f.backup_id}/download", headers=second_headers)
        observed = record(request, f, first_status=first.status_code, second_status=second.status_code,
                          first_exact_archive=first.content == f.saved, second_exact_archive=second.content == f.saved)
        assert first.status_code == second.status_code == 200 and first.content == second.content == f.saved
        assert observed["no_snapshot_descriptors"]
        assert observed["network_clients_open"] == observed["network_pool_connections"] == 0

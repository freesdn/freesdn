# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real remote admission, response-integrity and capacity reuse probes."""

import asyncio
import fcntl
import gzip
import hashlib
import json
import os

import anyio
import pytest

from app.core.backup_downloads import DownloadPool
from app.core.config import get_settings
from app.core.security_utils import MAX_BACKUP_IMPORT_BYTES
from tests.services import webdav_owned_peer
from tests.services.test_backup_artifact_integrity_contract import recorded_download_headers
from tests.services.test_backup_download_resource_lifetime import SlowBodySink
from tests.services.test_backup_download_response_lifetime import opened
from tests.services.test_webdav_download_resource_lifetime import seeded_remote_bulk
from tests.services.test_webdav_service_client_ownership import remote_actor, seeded_archive

webdav_peer = webdav_owned_peer.webdav_peer
WIRE_CASES = ["valid", "gzip", "chunked", "missing", "HTTP500", "redirect",
              "digest-mismatch", "size-mismatch", "unknown-encoding", "trailing-gzip"]


def configured(monkeypatch, root, floor=0):
    settings = get_settings().model_copy(update={
        "BACKUP_DOWNLOAD_SPOOL": str(root), "BACKUP_DOWNLOAD_SLOTS": 1,
        "BACKUP_DOWNLOAD_FREE_BYTES": floor, "BACKUP_DOWNLOAD_SECONDS": 20.0,
    })
    monkeypatch.setattr("app.api.v1.endpoints.backups.get_settings", lambda: settings)
    monkeypatch.setattr("app.services.vault_export_public_download.get_settings", lambda: settings)
    return DownloadPool(root, slots=1, limit=MAX_BACKUP_IMPORT_BYTES, free_floor=floor)


def observe(request, f, root, **extra):
    data = {
        "no_snapshot_descriptors": not opened(root),
        "network_clients_open": sum(not c.is_closed for c in f.clients),
        "network_connections": sum(len(c._transport._pool.connections) for c in f.clients),
        "provider_GETs": sum(r["method"] == "GET" for r in f.peer.requests),
        "peer_requests": json.dumps(f.peer.requests, sort_keys=True),
        "owned_peer_port": f.peer.port,
        "scope": "actual API/PG/owned TLS/disk; explicit test loopback admission, no shipped UID/NFS/container-memory acceptance",
        **extra,
    }
    request.node.user_properties.extend(data.items())
    return data


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("scenario", WIRE_CASES)
async def test_remote_wire_refusal_cleans_snapshot_and_reuses_slot(
    monkeypatch, tmp_path, webdav_peer, request, credential, secrets, scenario,
):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        backup_id, saved = await seeded_archive(f, secrets)
        root = tmp_path / "owned-wire-pool"
        pool = configured(monkeypatch, root)
        first_headers = await recorded_download_headers(f.actor, backup_id, secrets)
        retry_headers = await recorded_download_headers(f.actor, backup_id, secrets)
        if scenario == "gzip":
            f.peer.compress = True
        elif scenario == "chunked":
            f.peer.chunked = True
        elif scenario == "missing":
            f.peer.override["GET"] = (404, b"", {})
        elif scenario == "HTTP500":
            f.peer.override["GET"] = (500, b"owned-private-provider-marker", {})
        elif scenario == "redirect":
            f.peer.override["GET"] = (302, b"", {"Location": "/owned-must-not-follow"})
        elif scenario == "digest-mismatch":
            f.peer.override["GET"] = (200, bytes([saved[0] ^ 1]) + saved[1:], {})
        elif scenario == "size-mismatch":
            f.peer.override["GET"] = (200, saved[:-1], {})
        elif scenario == "unknown-encoding":
            f.peer.override["GET"] = (200, saved, {"Content-Encoding": "owned-unsupported"})
        elif scenario == "trailing-gzip":
            f.peer.override["GET"] = (200, gzip.compress(saved) + b"owned-trailing-bytes", {"Content-Encoding": "gzip"})
        response = await f.actor.client.get(f"/api/v1/backups/{backup_id}/download", headers=first_headers)
        exact = response.content == saved
        # This actual acquire must succeed before either fixture cleanup or a
        # follow-up request; it detects a retained slot from a failed response.
        lease = pool.acquire()
        lease.close()
        initial = observe(request, f, root, scenario=scenario, HTTP_status=response.status_code,
                          exact_archive=exact, response_bytes=len(response.content),
                          integrity=response.headers.get("x-freesdn-artifact-integrity"),
                          slot_reacquired=True, private_marker_returned=b"owned-private-provider-marker" in response.content)
        f.peer.override.clear()
        f.peer.compress = False
        f.peer.chunked = False
        retry = await f.actor.client.get(f"/api/v1/backups/{backup_id}/download", headers=retry_headers)
        request.node.user_properties.extend({"retry_status": retry.status_code,
            "retry_exact_archive": retry.content == saved,
            "retry_no_snapshot_descriptors": not opened(root),
            "retry_network_clients_closed": all(c.is_closed for c in f.clients)}.items())
        assert initial["no_snapshot_descriptors"]
        assert initial["network_clients_open"] == initial["network_connections"] == 0
        assert initial["provider_GETs"] == 1 and not initial["private_marker_returned"]
        if scenario in {"valid", "gzip", "chunked"}:
            assert response.status_code == 200 and exact and initial["integrity"] == "verified"
        else:
            assert response.status_code in (409, 500) and not exact and initial["integrity"] is None
        assert retry.status_code == 200 and retry.content == saved
        assert not opened(root) and all(c.is_closed for c in f.clients)


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("scenario", ["free-floor", "policy-mismatch", "spool-symlink"])
async def test_remote_capacity_refuses_before_provider_GET(
    monkeypatch, tmp_path, webdav_peer, request, credential, secrets, scenario,
):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        backup_id, _saved = await seeded_archive(f, secrets)
        root = tmp_path / "owned-admission-pool"
        target = tmp_path / "owned-alias-target"
        policy_before = None
        headers = await recorded_download_headers(f.actor, backup_id, secrets)
        if scenario == "free-floor":
            space = os.statvfs(tmp_path)
            # Require more than all available bytes without consuming disk or
            # replacing the real kernel filesystem observation.
            configured(monkeypatch, root, floor=space.f_blocks * space.f_frsize + MAX_BACKUP_IMPORT_BYTES)
        elif scenario == "policy-mismatch":
            original = DownloadPool(root, slots=2, limit=MAX_BACKUP_IMPORT_BYTES, free_floor=0)
            lease = original.acquire()
            lease.close()
            policy_before = (root / "pool-policy.json").read_bytes()
            configured(monkeypatch, root)
        else:
            target.mkdir()
            (target / "owned-sentinel").write_bytes(b"unchanged-owned-target")
            root.symlink_to(target, target_is_directory=True)
            configured(monkeypatch, root)
        response = await f.actor.client.get(f"/api/v1/backups/{backup_id}/download", headers=headers)
        slot_free = True
        if scenario == "free-floor":
            fd = os.open(root / "slot-00", os.O_RDWR | os.O_NOFOLLOW)
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    slot_free = False
            finally:
                os.close(fd)
        policy_unchanged = policy_before is None or (root / "pool-policy.json").read_bytes() == policy_before
        alias_unchanged = (scenario != "spool-symlink" or
                           sorted(p.name for p in target.iterdir()) == ["owned-sentinel"] and
                           (target / "owned-sentinel").read_bytes() == b"unchanged-owned-target")
        observed = observe(request, f, root, scenario=scenario, HTTP_status=response.status_code,
                           integrity=response.headers.get("x-freesdn-artifact-integrity"),
                           original_policy_unchanged=policy_unchanged, alias_target_unchanged=alias_unchanged,
                           original_slot_lock_free=slot_free, retry_after=response.headers.get("retry-after"))
        assert observed["provider_GETs"] == 0 and observed["network_clients_open"] == 0
        assert observed["network_connections"] == 0 and observed["no_snapshot_descriptors"]
        assert policy_unchanged and alias_unchanged and slot_free and observed["integrity"] is None
        assert response.status_code == (503 if scenario == "free-floor" else 500)
        if scenario == "free-floor":
            assert observed["retry_after"] == "5"


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_remote_held_response_blocks_second_transfer_before_provider_IO(
    monkeypatch, tmp_path, webdav_peer, request, credential, secrets,
):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        backup_id, owned_path, archive_size, archive_digest = await seeded_remote_bulk(f, secrets)
        saved = f.peer.files[owned_path]
        assert len(saved) == archive_size and hashlib.sha256(saved).hexdigest() == archive_digest
        root = tmp_path / "owned-shared-pool"
        configured(monkeypatch, root)
        first_headers = await recorded_download_headers(f.actor, backup_id, secrets)
        blocked_headers = await recorded_download_headers(f.actor, backup_id, secrets)
        retry_headers = await recorded_download_headers(f.actor, backup_id, secrets)
        sink = SlowBodySink()
        task = asyncio.create_task(sink.run(f.actor, backup_id, headers=first_headers))
        try:
            with anyio.fail_after(10):
                await sink.entered.wait()
            before_second_task_pending = not task.done()
            before_second_snapshot_live = bool(opened(root))
            assert before_second_task_pending and before_second_snapshot_live
            first_GETs = sum(r["method"] == "GET" for r in f.peer.requests)
            refused = await f.actor.client.get(f"/api/v1/backups/{backup_id}/download", headers=blocked_headers)
            after_GETs = sum(r["method"] == "GET" for r in f.peer.requests)
            held = not task.done() and bool(opened(root))
            sink.release.set()
            await asyncio.wait_for(task, 5)
            retry = await f.actor.client.get(f"/api/v1/backups/{backup_id}/download", headers=retry_headers)
            observed = observe(request, f, root, held_response_retained=held, archive_bytes=archive_size,
                before_second_task_pending=before_second_task_pending, before_second_snapshot_live=before_second_snapshot_live,
                first_provider_GETs=first_GETs, GETs_after_refused_second=after_GETs,
                refusal_status=refused.status_code, retry_after=refused.headers.get("retry-after"),
                refusal_integrity=refused.headers.get("x-freesdn-artifact-integrity"),
                first_exact_archive=sink.bytes == len(saved) and sink.digest.hexdigest() == hashlib.sha256(saved).hexdigest(),
                first_complete=sink.finished, retry_status=retry.status_code, retry_exact_archive=retry.content == saved)
            assert held and first_GETs == after_GETs == 1
            assert refused.status_code == 503 and observed["retry_after"] == "5"
            assert observed["refusal_integrity"] is None and refused.content != saved
            assert observed["first_exact_archive"] and observed["first_complete"]
            assert retry.status_code == 200 and retry.content == saved and observed["provider_GETs"] == 2
            assert observed["no_snapshot_descriptors"] and observed["network_clients_open"] == observed["network_connections"] == 0
        finally:
            sink.release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

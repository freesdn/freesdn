# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned real TLS and authenticated ASGI downloads; no container-memory claim.

The peer admits only a test-owned loopback destination. Actual collection,
encryption, stored credentials, WebDAV I/O and catalogue identity checks run.
A paused ASGI send measures transfer chunks, not all retained Python buffers.
"""

import asyncio
import base64
import hashlib
import json
import os
from uuid import UUID

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.backup.models import Backup
from app.services.backup_contributors.protocol import ContributorPayload
from tests.services import webdav_owned_peer
from tests.services.test_backup_artifact_integrity_contract import recorded_download_headers
from tests.services.test_backup_download_resource_lifetime import (
    CHUNK_BUDGET,
    SlowBodySink,
    finish_owned,
    owned_open_files,
    resident_bytes,
    start_paused_downloads,
    wait_for_bodies,
)
from tests.services.test_webdav_service_client_ownership import remote_actor, seeded_archive

webdav_peer = webdav_owned_peer.webdav_peer


class OwnedRemoteContributor:
    contributor_id = "owned_remote_resource_probe"
    schema_version = "1.0.0"
    depends_on = ("core",)
    default_included = True

    def __init__(self, organization_id):
        self.organization_id = organization_id

    async def collect(self, session, organization_id, options):
        assert organization_id == self.organization_id
        # Keep real PUT input below the unchanged peer's 2 MiB safety cap.
        return ContributorPayload(
            schema_version=self.schema_version, counts={"owned_blobs": 1},
            data={"blob": base64.b64encode(os.urandom(1024 * 1024)).decode("ascii")},
        )

    async def restore(self, session, organization_id, payload, options):
        raise AssertionError("This resource fixture never restores contributors")


async def seeded_remote_bulk(f, secrets):
    import app.services.backup_contributors as contributors

    contributors.get_registry().register(OwnedRemoteContributor(f.actor.org_id))
    backup_id, saved = await seeded_archive(f, secrets)
    size, digest = len(saved), hashlib.sha256(saved).hexdigest()
    assert 1024**2 < size < 2 * 1024**2
    assert len(f.peer.files) == 1
    path = next(iter(f.peer.files))
    # Do not keep an extra client-side copy of the full archive in the probe.
    return backup_id, path, size, digest


def client_observations(f):
    return {
        "network_clients_created": len(f.clients),
        "network_clients_open": sum(not client.is_closed for client in f.clients),
        "client_pool_connections": sum(len(client._transport._pool.connections) for client in f.clients),
    }


def record(request, f, observed):
    request.node.user_properties.extend({
        **observed,
        "owned_peer_port": f.peer.port,
        "peer_requests": json.dumps(f.peer.requests, sort_keys=True),
        "peer_SNI": json.dumps(f.peer.sni),
        "scope": "owned TLS after explicit test destination admission; chunk observations are not aggregate memory acceptance",
    }.items())


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("parallel", [1, 4])
async def test_slow_webdav_downloads_hold_bounded_body_chunks(
    monkeypatch, tmp_path, webdav_peer, request, credential, secrets, parallel,
):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        backup_id, path, size, digest = await seeded_remote_bulk(f, secrets)
        before_rss = resident_bytes()
        sinks = [SlowBodySink() for _ in range(parallel)]
        confirmations = [await recorded_download_headers(f.actor, backup_id, secrets) for _ in sinks]
        tasks = await start_paused_downloads(f.actor, backup_id, sinks, confirmations, admit_before_next=secrets)
        try:
            await wait_for_bodies(sinks, tasks)
            ticks = 0
            for _ in range(5):
                await asyncio.sleep(0.005)
                ticks += 1
            observed = {
                "all_body_boundaries": all(s.entered.is_set() for s in sinks),
                "all_owners_live_while_paused": all(not t.done() for t in tasks),
                "concurrent_downloads": parallel, "archive_bytes": size,
                "HTTP_statuses_while_bodies_held": [sink.status for sink in sinks],
                "vault_admission_completed_before_next_start": secrets,
                "held_body_bytes": sum(s.held_chunk for s in sinks),
                "maximum_held_chunk": max(s.held_chunk for s in sinks),
                "event_loop_ticks": ticks,
                "RSS_before": before_rss, "RSS_paused": resident_bytes(),
                **client_observations(f),
            }
        finally:
            results = await finish_owned(sinks, tasks)
        observed.update(
            all_HTTP_200=all(s.status == 200 for s in sinks),
            all_verified=all(s.headers.get("x-freesdn-artifact-integrity") == "verified" for s in sinks),
            all_exact_bytes=all(s.bytes == size and s.digest.hexdigest() == digest for s in sinks),
            all_finished=all(s.finished for s in sinks),
            all_requests_completed=all(result is None for result in results),
            no_owned_file_descriptors=not owned_open_files(tmp_path),
            remote_source_unchanged=len(f.peer.files[path]) == size and hashlib.sha256(f.peer.files[path]).hexdigest() == digest,
            RSS_after=resident_bytes(),
        )
        record(request, f, observed)
        assert observed["all_body_boundaries"] and observed["all_owners_live_while_paused"]
        assert observed["all_HTTP_200"] and observed["all_verified"] and observed["all_exact_bytes"]
        assert observed["all_finished"] and observed["all_requests_completed"]
        assert observed["no_owned_file_descriptors"] and observed["remote_source_unchanged"]
        assert observed["network_clients_created"] == parallel
        assert observed["network_clients_open"] == observed["client_pool_connections"] == 0
        assert observed["event_loop_ticks"] == 5
        # Proposed transfer contract; does not prove whole-process bounded RSS.
        assert observed["maximum_held_chunk"] <= CHUNK_BUDGET
        assert observed["held_body_bytes"] <= parallel * CHUNK_BUDGET


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_started_webdav_download_preserves_verified_bytes_after_remote_replacement(
    monkeypatch, tmp_path, webdav_peer, request, credential, secrets,
):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        backup_id, path, size, digest = await seeded_remote_bulk(f, secrets)
        headers = await recorded_download_headers(f.actor, backup_id, secrets)
        sink = SlowBodySink()
        task = asyncio.create_task(sink.run(f.actor, backup_id, headers=headers))
        try:
            await wait_for_bodies([sink], [task])
            f.peer.files[path] = b"Owned remote object replaced after verified response began"
            observed = {"real_body_boundary": sink.entered.is_set(), **client_observations(f)}
        finally:
            results = await finish_owned([sink], [task])
        observed.update(
            HTTP_status=sink.status, response_finished=sink.finished,
            exact_preverified_bytes=sink.bytes == size and sink.digest.hexdigest() == digest,
            integrity_header=sink.headers.get("x-freesdn-artifact-integrity"),
            request_completed=results == [None],
            no_owned_file_descriptors=not owned_open_files(tmp_path),
            owned_remote_source_changed=hashlib.sha256(f.peer.files[path]).hexdigest() != digest,
        )
        record(request, f, observed)
        assert all(observed[k] for k in ("real_body_boundary", "response_finished", "exact_preverified_bytes", "request_completed", "no_owned_file_descriptors", "owned_remote_source_changed"))
        assert observed["HTTP_status"] == 200 and observed["integrity_header"] == "verified"
        assert observed["network_clients_created"] == 1
        assert observed["network_clients_open"] == observed["client_pool_connections"] == 0


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("ending", ["task-cancel", "send-error"])
async def test_interrupted_webdav_send_releases_request_resources(
    monkeypatch, tmp_path, webdav_peer, request, credential, ending,
):
    async with remote_actor(monkeypatch, tmp_path, webdav_peer, credential) as f:
        backup_id, path, size, digest = await seeded_remote_bulk(f, False)
        live_connections = 0
        checkouts = 0

        def checkout(*args):
            nonlocal live_connections, checkouts
            live_connections += 1
            checkouts += 1

        def checkin(*args):
            nonlocal live_connections
            live_connections -= 1

        event.listen(f.actor.engine.sync_engine, "checkout", checkout)
        event.listen(f.actor.engine.sync_engine, "checkin", checkin)
        sink = SlowBodySink()
        task = asyncio.create_task(sink.run(f.actor, backup_id))
        try:
            try:
                await wait_for_bodies([sink], [task])
                if ending == "task-cancel":
                    cancelled = task.cancel()
                else:
                    cancelled = False
                    sink.fail_send = True
            finally:
                results = await finish_owned([sink], [task])
            observed = {
                "real_body_boundary": sink.entered.is_set(), "HTTP_status": sink.status,
                "cancel_call_accepted": cancelled, "request_result_type": type(results[0]).__name__,
                "request_terminal": task.done(), "observed_database_checkouts": checkouts,
                "request_connections_remaining": live_connections,
                "no_owned_file_descriptors": not owned_open_files(tmp_path),
                "remote_source_unchanged": len(f.peer.files[path]) == size and hashlib.sha256(f.peer.files[path]).hexdigest() == digest,
                **client_observations(f),
            }
        finally:
            event.remove(f.actor.engine.sync_engine, "checkout", checkout)
            event.remove(f.actor.engine.sync_engine, "checkin", checkin)
        async with AsyncSession(f.actor.engine) as db:
            stored = await db.get(Backup, UUID(backup_id))
            observed["catalogue_remains_completed"] = stored is not None and stored.status == "completed"
        record(request, f, observed)
        assert observed["real_body_boundary"] and observed["HTTP_status"] == 200
        assert observed["request_terminal"] and observed["observed_database_checkouts"] > 0
        assert observed["request_connections_remaining"] == 0
        assert observed["no_owned_file_descriptors"] and observed["remote_source_unchanged"]
        assert observed["catalogue_remains_completed"]
        assert observed["network_clients_created"] == 1
        assert observed["network_clients_open"] == observed["client_pool_connections"] == 0
        if ending == "task-cancel":
            assert observed["cancel_call_accepted"] and isinstance(results[0], asyncio.CancelledError)
        else:
            assert isinstance(results[0], Exception)

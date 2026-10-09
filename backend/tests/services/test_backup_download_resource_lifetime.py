# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real owned archive/HTTP sends; bounded buffers are a proposed contract.

A synthetic contributor supplies bounded incompressible data through the actual
collector, encryption and storage path. No network appliance or restore plugin
is exercised. RSS is observed, not interpreted as an OOM or container guarantee.
"""

import asyncio
import base64
import hashlib
import os
from pathlib import Path

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.models.core import TokenRevocation
from app.modules.backup.models import Backup
from app.services import vault_export_download, vault_export_permission
from app.services.backup_contributors.protocol import ContributorPayload
from tests.services.test_backup_artifact_integrity_contract import (
    create_archive,
    owned_actor,
    recorded_download_headers,
    remember_owned_proof,
)

CHUNK_BUDGET = 64 * 1024


class OwnedBulkContributor:
    contributor_id = "owned_resource_probe"
    schema_version = "1.0.0"
    depends_on = ("core",)
    default_included = True

    def __init__(self, organization_id):
        self.organization_id = organization_id

    async def collect(self, session, organization_id, options):
        assert organization_id == self.organization_id
        return ContributorPayload(
            schema_version=self.schema_version, counts={"owned_blobs": 1},
            data={"blob": base64.b64encode(os.urandom(2 * 1024 * 1024)).decode("ascii")},
        )

    async def restore(self, session, organization_id, payload, options):
        raise AssertionError("This transport fixture must never restore a contributor")


async def bulk_archive(f):
    import app.services.backup_contributors as contributors

    contributors.get_registry().register(OwnedBulkContributor(f.org_id))
    backup, path, raw = await create_archive(f, f.resource_secrets)
    size, digest = len(raw), hashlib.sha256(raw).hexdigest()
    assert 2 * 1024 * 1024 < size < 4 * 1024 * 1024
    return backup, path, size, digest


def resident_bytes():
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    raise AssertionError("Linux RSS observation is required")


def owned_open_files(root):
    found = []
    for entry in Path("/proc/self/fd").iterdir():
        try:
            target = os.readlink(entry)
        except FileNotFoundError:
            continue
        if target.startswith(str(root) + "/"):
            found.append(target)
    return found


class SlowBodySink:
    def __init__(self):
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.disconnect = asyncio.Event()
        self.status = None
        self.headers = {}
        self.messages = 0
        self.bytes = 0
        self.max_chunk = 0
        self.held_chunk = 0
        self.digest = hashlib.sha256()
        self.fail_send = False
        self.finished = False

    async def send(self, message):
        if message["type"] == "http.response.start":
            self.status = message["status"]
            self.headers = {k.decode().lower(): v.decode() for k, v in message["headers"]}
        elif message["type"] == "http.response.body":
            body = message.get("body", b"")
            self.messages += 1
            self.max_chunk = max(self.max_chunk, len(body))
            if body and not self.entered.is_set():
                self.held_chunk = len(body)
                self.entered.set()
                try:
                    await self.release.wait()
                    if self.fail_send:
                        raise OSError("Owned client sink disconnected")
                finally:
                    self.held_chunk = 0
            self.bytes += len(body)
            self.digest.update(body)
            if not message.get("more_body", False):
                self.finished = True

    async def run(self, f, backup_id, *, headers=None):
        delivered = False

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await self.disconnect.wait()
            return {"type": "http.disconnect"}

        path = f"/api/v1/backups/{backup_id}/download"
        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1", "method": "GET", "scheme": "http",
            "path": path, "raw_path": path.encode(), "query_string": b"",
            "root_path": "", "headers": [(k.lower(), v) for k, v in f.client.build_request("GET", path, headers=headers).headers.raw],
            "client": ("127.0.0.1", 32001), "server": ("test", 80),
        }
        await app(scope, receive, self.send)


async def wait_for_bodies(sinks, tasks):
    async def wait_one(sink, task):
        ready = asyncio.create_task(sink.entered.wait())
        try:
            done, _ = await asyncio.wait({ready, task}, timeout=10, return_when=asyncio.FIRST_COMPLETED)
            assert ready in done and sink.entered.is_set(), "Real response-body boundary was not reached"
        finally:
            ready.cancel()
            await asyncio.gather(ready, return_exceptions=True)
    await asyncio.gather(*(wait_one(sink, task) for sink, task in zip(sinks, tasks, strict=True)))


async def finish_owned(sinks, tasks):
    for sink in sinks:
        sink.release.set()
    try:
        return await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 10)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def start_paused_downloads(f, backup_id, sinks, confirmations, *, admit_before_next):
    """Retain every body concurrently, without assuming unbounded admission."""
    tasks = []
    try:
        for sink, headers in zip(sinks, confirmations, strict=True):
            task = asyncio.create_task(sink.run(f, backup_id, headers=headers))
            tasks.append(task)
            if admit_before_next:
                await wait_for_bodies([sink], [task])
                assert sink.status == 200 and sink.headers.get("x-freesdn-artifact-integrity") == "verified"
                assert not task.done() and not sink.release.is_set()
        return tasks
    except BaseException:
        await finish_owned(sinks, tasks)
        raise


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("parallel", [1, 4])
async def test_slow_local_downloads_hold_bounded_body_chunks(
    monkeypatch, tmp_path, request, credential, secrets, parallel,
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        f.resource_secrets = secrets
        backup, _, size, digest = await bulk_archive(f)
        before_rss = resident_bytes()
        sinks = [SlowBodySink() for _ in range(parallel)]
        confirmations = [await recorded_download_headers(f, backup.id, secrets) for _ in sinks]
        tasks = await start_paused_downloads(f, backup.id, sinks, confirmations, admit_before_next=secrets)
        try:
            await wait_for_bodies(sinks, tasks)
            ticks = 0
            for _ in range(5):
                await asyncio.sleep(0.005)
                ticks += 1
            observed = {
                "all_real_body_boundaries": all(s.entered.is_set() for s in sinks),
                "all_owners_live_while_sends_paused": all(not t.done() for t in tasks),
                "concurrent_downloads": parallel, "archive_bytes": size,
                "HTTP_statuses_while_bodies_held": [sink.status for sink in sinks],
                "vault_admission_completed_before_next_start": secrets,
                "held_body_bytes": sum(s.held_chunk for s in sinks),
                "maximum_held_chunk": max(s.held_chunk for s in sinks),
                "event_loop_ticks_while_sends_paused": ticks,
                "RSS_before": before_rss, "RSS_paused": resident_bytes(),
            }
        finally:
            results = await finish_owned(sinks, tasks)
        observed.update(
            all_HTTP_200=all(s.status == 200 for s in sinks),
            all_downloads_verified=all(s.headers.get("x-freesdn-artifact-integrity") == "verified" for s in sinks),
            all_exact_bytes=all(s.bytes == size and s.digest.hexdigest() == digest for s in sinks),
            all_responses_finished=all(s.finished for s in sinks),
            all_requests_completed=all(result is None for result in results),
            no_owned_file_descriptors=not owned_open_files(tmp_path),
            RSS_after=resident_bytes(),
        )
        request.node.user_properties.extend(observed.items())
        assert observed["all_real_body_boundaries"] and observed["all_owners_live_while_sends_paused"]
        assert observed["all_HTTP_200"] and observed["all_downloads_verified"]
        assert observed["all_exact_bytes"] and observed["all_responses_finished"]
        assert observed["all_requests_completed"] and observed["no_owned_file_descriptors"]
        assert observed["event_loop_ticks_while_sends_paused"] == 5
        # Proposed transfer contract. This is not an assertion that a small
        # chunk by itself proves bounded application/process memory.
        assert observed["maximum_held_chunk"] <= CHUNK_BUDGET
        assert observed["held_body_bytes"] <= parallel * CHUNK_BUDGET


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
async def test_started_download_preserves_verified_bytes_after_source_replacement(
    monkeypatch, tmp_path, request, credential, secrets,
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        f.resource_secrets = secrets
        backup, path, size, digest = await bulk_archive(f)
        download_headers = await recorded_download_headers(f, backup.id, secrets)
        sink = SlowBodySink()
        task = asyncio.create_task(sink.run(f, backup.id, headers=download_headers))
        try:
            await wait_for_bodies([sink], [task])
            path.write_bytes(b"Owned file changed only after response began")
            changed = hashlib.sha256(path.read_bytes()).hexdigest() != digest
        finally:
            results = await finish_owned([sink], [task])
        observed = {
            "real_body_boundary": sink.entered.is_set(), "owned_source_changed": changed,
            "HTTP_status": sink.status, "response_finished": sink.finished,
            "exact_preverified_bytes": sink.bytes == size and sink.digest.hexdigest() == digest,
            "integrity_header": sink.headers.get("x-freesdn-artifact-integrity"),
            "request_completed": results == [None], "no_owned_file_descriptors": not owned_open_files(tmp_path),
        }
        request.node.user_properties.extend(observed.items())
        assert all(observed[k] for k in ("real_body_boundary", "owned_source_changed", "response_finished", "exact_preverified_bytes", "request_completed", "no_owned_file_descriptors"))
        assert observed["HTTP_status"] == 200 and observed["integrity_header"] == "verified"


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("ending", ["task-cancel", "send-error"])
async def test_interrupted_body_send_releases_request_files_and_database_connections(
    monkeypatch, tmp_path, request, credential, ending,
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        f.resource_secrets = False
        backup, path, size, digest = await bulk_archive(f)
        live_connections = 0
        checkouts = 0

        def checkout(*args):
            nonlocal live_connections, checkouts
            live_connections += 1
            checkouts += 1

        def checkin(*args):
            nonlocal live_connections
            live_connections -= 1

        event.listen(f.engine.sync_engine, "checkout", checkout)
        event.listen(f.engine.sync_engine, "checkin", checkin)
        sink = SlowBodySink()
        task = asyncio.create_task(sink.run(f, backup.id))
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
                "cancel_call_accepted": cancelled,
                "request_result_type": type(results[0]).__name__,
                "request_terminal": task.done(), "observed_database_checkouts": checkouts,
                "request_connections_remaining": live_connections,
                "no_owned_file_descriptors": not owned_open_files(tmp_path),
                "archive_unchanged": path.stat().st_size == size and hashlib.sha256(path.read_bytes()).hexdigest() == digest,
            }
        finally:
            event.remove(f.engine.sync_engine, "checkout", checkout)
            event.remove(f.engine.sync_engine, "checkin", checkin)
        async with AsyncSession(f.engine) as db:
            stored = await db.get(Backup, backup.id)
            observed["catalogue_remains_completed"] = stored is not None and stored.status == "completed"
        request.node.user_properties.extend(observed.items())
        assert observed["real_body_boundary"] and observed["HTTP_status"] == 200
        assert observed["request_terminal"] and observed["observed_database_checkouts"] > 0
        assert observed["request_connections_remaining"] == 0
        assert observed["no_owned_file_descriptors"] and observed["archive_unchanged"]
        assert observed["catalogue_remains_completed"]
        if ending == "task-cancel":
            assert observed["cancel_call_accepted"] and isinstance(results[0], asyncio.CancelledError)


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("boundary", ["redemption", "construction"])
async def test_full_vault_busy_admission_preserves_claim_and_recovery_contract(
    monkeypatch, tmp_path, request, credential, boundary,
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await create_archive(f, True)
        headers = [await recorded_download_headers(f, backup.id, True) for _ in range(3)]
        hashes = [hashlib.sha256(remember_owned_proof(f, value["X-FreeSDN-Vault-Proof"])["jti"].encode()).hexdigest()
                  for value in headers]
        assert len(set(hashes)) == 3
        entered, release = asyncio.Event(), asyncio.Event()
        paused = []

        async def hold(hash_value):
            if hash_value in hashes[:2]:
                paused.append(hash_value)
                if len(paused) == 2:
                    entered.set()
                await release.wait()

        if boundary == "redemption":
            original = vault_export_permission._claim_owned

            async def claimed(verified):
                await original(verified)
                await hold(hashlib.sha256(verified.jti.encode()).hexdigest())

            monkeypatch.setattr(vault_export_permission, "_claim_owned", claimed)
            limiter = vault_export_permission._REDEMPTION_WORK
        else:
            original = vault_export_download.VaultArchiveResponse._construct_thread_owned

            async def constructed(response):
                await original(response)
                await hold(hashlib.sha256(response.permission.verified.jti.encode()).hexdigest())

            monkeypatch.setattr(vault_export_download.VaultArchiveResponse, "_construct_thread_owned", constructed)
            limiter = vault_export_download._CONSTRUCTION_ADMISSION

        async def durable_claims():
            async with AsyncSession(f.engine) as db:
                return set(await db.scalars(select(TokenRevocation.jti_hash).where(
                    TokenRevocation.jti_hash.in_(hashes))))

        url = f"/api/v1/backups/{backup.id}/download"
        tasks = [asyncio.create_task(f.client.get(url, headers=value)) for value in headers[:2]]
        refused = None
        try:
            await asyncio.wait_for(entered.wait(), 10)
            assert set(paused) == set(hashes[:2]) and limiter.borrowed_tokens == 2
            assert all(not task.done() for task in tasks)
            claimed_before = await durable_claims()
            refused = await f.client.get(url, headers=headers[2])
            claimed_after = await durable_claims()
            request.node.user_properties.extend({
                "actual_paused_stage": boundary, "actual_admission_borrowed": limiter.borrowed_tokens,
                "two_original_durable_claims": claimed_before == set(hashes[:2]),
                "busy_HTTP_status": refused.status_code,
                "busy_archive_delivered": refused.content == raw,
                "third_proof_spent_at_refusal": hashes[2] in claimed_after,
            }.items())
            assert refused.status_code == 503 and refused.content != raw
            assert "x-freesdn-artifact-integrity" not in refused.headers
            assert claimed_before == set(hashes[:2])
            assert claimed_after == set(hashes[:2] if boundary == "redemption" else hashes)
        finally:
            release.set()
            outcomes = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 10)
        assert all(not isinstance(value, BaseException) and value.status_code == 200 and value.content == raw
                   for value in outcomes)
        assert limiter.borrowed_tokens == 0
        # This is an explicit test of durable claim state, never an automatic
        # retry in the product. Construction refusal has already spent its proof.
        original_third = await f.client.get(url, headers=headers[2])
        assert original_third.status_code == (200 if boundary == "redemption" else 401)
        if boundary == "construction":
            fresh_headers = await recorded_download_headers(f, backup.id, True)
            recovered = await f.client.get(url, headers=fresh_headers)
        else:
            recovered = original_third
        replay = await f.client.get(url, headers=headers[2])
        request.node.user_properties.extend({
            "explicit_original_proof_after_pressure_status": original_third.status_code,
            "recovery_HTTP_status": recovered.status_code, "recovery_exact_archive": recovered.content == raw,
            "third_proof_replay_status": replay.status_code,
            "all_original_proofs_spent_at_end": await durable_claims() == set(hashes),
            "limiter_released": limiter.borrowed_tokens == 0,
            "no_owned_source_descriptors": not owned_open_files(tmp_path),
        }.items())
        assert recovered.status_code == 200 and recovered.content == raw
        assert replay.status_code == 401 and await durable_claims() == set(hashes)
        assert limiter.borrowed_tokens == 0 and not owned_open_files(tmp_path)

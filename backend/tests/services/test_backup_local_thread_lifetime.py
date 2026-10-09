# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Owned real I/O boundaries and request cancellation; no deployment claim."""

import asyncio
import os
import stat
import threading
import time
from pathlib import Path

import anyio
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup_files import BackupFiles
from app.modules.backup.models import Backup, StorageLocation
from app.services.backup import LocalStorageBackend
from tests.services.test_backup_artifact_integrity_contract import (
    authorize_owned_vault,
    create_archive,
    create_request,
    owned_actor,
)


class OwnedBoundary:
    """Pause exactly one owned syscall; a five-second escape prevents a hang."""

    def __init__(self, root, operation):
        self.root = root
        self.operation = operation
        self.entered = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.thread_id = None
        self.escape_fired = False
        self.visits = 0

    def owned_fd(self, fd):
        try:
            return Path(os.readlink(f"/proc/self/fd/{fd}")).is_relative_to(self.root)
        except (OSError, TypeError):
            return False

    def pause(self):
        if self.entered.is_set():
            return
        self.visits += 1
        self.thread_id = threading.get_ident()
        self.entered.set()
        if not self.release.wait(5):
            self.escape_fired = True

    def install(self, patch):
        original = getattr(BackupFiles, self.operation)

        def observed(instance, *args, **kwargs):
            try:
                return original(instance, *args, **kwargs)
            finally:
                self.finished.set()

        patch.setattr(BackupFiles, self.operation, observed)
        if self.operation == "save":
            real = os.fsync

            def fsync(fd):
                if self.owned_fd(fd) and stat.S_ISREG(os.fstat(fd).st_mode):
                    self.pause()
                return real(fd)

            patch.setattr(os, "fsync", fsync)
        elif self.operation == "load":
            real = os.read

            def read(fd, size):
                if self.owned_fd(fd):
                    self.pause()
                return real(fd, size)

            patch.setattr(os, "read", read)
        elif self.operation == "delete":
            real = os.unlink

            def unlink(path, *, dir_fd=None):
                if dir_fd is not None and self.owned_fd(dir_fd):
                    self.pause()
                return real(path, dir_fd=dir_fd)

            patch.setattr(os, "unlink", unlink)
        else:
            real = os.stat

            def metadata(path, *args, **kwargs):
                if kwargs.get("dir_fd") is not None and self.owned_fd(kwargs["dir_fd"]):
                    self.pause()
                return real(path, *args, **kwargs)

            patch.setattr(os, "stat", metadata)


async def run_at_boundary(invoke, boundary, cancellation):
    scopes = []

    async def request_owner():
        value = None
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            value = await invoke()
            # Deliver a pending scope cancellation after a shielded operation.
            await anyio.lowlevel.checkpoint()
        return value

    task = asyncio.create_task(request_owner())
    ticks = 0
    accepted_cancels = []
    try:
        deadline = time.monotonic() + 10
        while not boundary.entered.is_set() and not task.done() and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        for _ in range(5):
            await asyncio.sleep(0.005)
            if boundary.entered.is_set() and not boundary.finished.is_set():
                ticks += 1
        if cancellation == "task":
            accepted_cancels.append(task.cancel())
            await asyncio.sleep(0.01)
            accepted_cancels.append(task.cancel())
        elif cancellation == "scope":
            scopes[0].cancel()
        await asyncio.sleep(0.02)
        observations = {
            "boundary_entered": boundary.entered.is_set(),
            "boundary_visits": boundary.visits,
            "different_worker_thread": boundary.thread_id != threading.get_ident(),
            "event_loop_ticks_while_worker_paused": ticks,
            "owner_finished_before_release": task.done(),
            "worker_finished_before_release": boundary.finished.is_set(),
            "requested_cancellation": cancellation,
            "accepted_task_cancel_calls": accepted_cancels,
            "escape_fired": boundary.escape_fired,
        }
    finally:
        boundary.release.set()
    result = (await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 10))[0]
    deadline = time.monotonic() + 5
    while not boundary.finished.is_set() and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    observations.update(
        worker_finished_after_release=boundary.finished.is_set(),
        caller_result_type=type(result).__name__,
        final_escape_fired=boundary.escape_fired,
    )
    return result, observations


def assert_owned_lifetime(observations):
    assert observations["boundary_entered"] and observations["boundary_visits"] == 1
    assert observations["different_worker_thread"]
    assert observations["event_loop_ticks_while_worker_paused"] == 5
    assert not observations["escape_fired"] and not observations["final_escape_fired"]
    assert not observations["worker_finished_before_release"]
    assert not observations["owner_finished_before_release"]
    assert observations["worker_finished_after_release"]


@pytest.mark.parametrize("operation", ["save", "load", "delete", "exists", "get_size"])
@pytest.mark.parametrize("cancellation", ["none", "task", "scope"])
async def test_local_io_remains_owned_and_event_loop_responsive(
    monkeypatch, tmp_path, request, operation, cancellation,
):
    payload = b"owned archive thread lifetime"
    target = tmp_path / "archive.fsdn"
    target.write_bytes(payload)
    target.chmod(0o600)
    backend = LocalStorageBackend({"path": str(tmp_path)})
    boundary = OwnedBoundary(tmp_path, operation)

    async def invoke():
        if operation == "save":
            return await backend.save("owned-operation", payload, "new.fsdn")
        return await getattr(backend, operation)(target.name)

    with monkeypatch.context() as patch:
        boundary.install(patch)
        result, observed = await run_at_boundary(invoke, boundary, cancellation)
    if operation == "save":
        saved = list(tmp_path.rglob("*_new.fsdn"))
        final_state_ok = len(saved) == 1 and saved[0].read_bytes() == payload
    elif operation == "delete":
        final_state_ok = not target.exists()
    else:
        final_state_ok = target.read_bytes() == payload
    observed["expected_final_filesystem_state"] = final_state_ok
    observed["no_owned_temporary_files"] = not list(tmp_path.rglob(".freesdn-archive-*.tmp"))
    request.node.user_properties.extend(observed.items())
    assert_owned_lifetime(observed)
    assert final_state_ok and observed["no_owned_temporary_files"]
    if cancellation == "task":
        assert isinstance(result, asyncio.CancelledError)
    elif cancellation == "none":
        assert not isinstance(result, BaseException)
        if operation == "load":
            assert result == payload
        elif operation in {"delete", "exists"}:
            assert result is True
        elif operation == "get_size":
            assert result == len(payload)


@pytest.mark.parametrize("operation", ["config", "vault", "probe", "delete"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("cancellation", ["none", "task", "scope"])
async def test_cancelled_http_storage_work_keeps_durable_file_accounting(
    monkeypatch, tmp_path, request, operation, credential, cancellation,
):
    async with owned_actor(monkeypatch, tmp_path, credential) as fixture:
        original_backup = None
        if operation == "delete":
            original_backup, original_path, _ = await create_archive(fixture, False)
        data = create_request(fixture, operation == "vault")
        headers = {}
        if operation == "vault":
            proof = await authorize_owned_vault(fixture, {"kind": "create", "backup": data})
            headers["X-FreeSDN-Vault-Proof"] = proof
        boundary = OwnedBoundary(tmp_path, "delete" if operation == "delete" else "save")

        async def invoke():
            if operation == "probe":
                return await fixture.client.post(
                    f"/api/v1/backups/storage-locations/{fixture.storage_id}/test"
                )
            if operation == "delete":
                return await fixture.client.delete(f"/api/v1/backups/{original_backup.id}")
            return await fixture.client.post(
                "/api/v1/backups/", json=data, headers=headers
            )

        with monkeypatch.context() as patch:
            boundary.install(patch)
            response, observed = await run_at_boundary(invoke, boundary, cancellation)
        async with AsyncSession(fixture.engine) as db:
            rows = list((await db.scalars(select(Backup).where(Backup.organization_id == fixture.org_id))).all())
            location = await db.get(StorageLocation, fixture.storage_id)
            probe_status = location.last_test_status
        stored = [p for p in tmp_path.rglob("*") if p.is_file()]
        catalogue_paths = {tmp_path / row.storage_path for row in rows if row.storage_path}
        exact_accounting = set(stored) == catalogue_paths
        observed.update(
            HTTP_status=getattr(response, "status_code", None),
            durable_backup_rows=len(rows),
            durable_backup_statuses=[row.status for row in rows],
            durable_probe_status=probe_status,
            stored_files=len(stored),
            exact_file_catalogue_accounting=exact_accounting,
            no_owned_temporary_files=not list(tmp_path.rglob(".freesdn-archive-*.tmp")),
        )
        if operation == "delete":
            observed["original_file_exists"] = original_path.exists()
        request.node.user_properties.extend(observed.items())
        assert_owned_lifetime(observed)
        assert observed["no_owned_temporary_files"]
        if operation == "probe":
            assert not stored and probe_status in {"success", "failed"}
        else:
            assert exact_accounting
        if cancellation == "none":
            assert observed["HTTP_status"] == {"config": 201, "vault": 201, "probe": 200, "delete": 204}[operation]
            if operation in {"config", "vault"}:
                assert len(rows) == len(stored) == 1 and rows[0].status == "completed"
            elif operation == "probe":
                assert probe_status == "success"
            else:
                assert not rows and not stored

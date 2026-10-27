# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Actual ASGI and independent PG-session close lifetime, no auth shortcut."""

import asyncio
import hashlib
import threading
from uuid import uuid4

import anyio
import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.backup_download_response import LocalDownloadSource as ConfigurationDownloadSource
from app.core.backup_downloads import DownloadPool
from app.db import session as sessions
from app.services.vault_snapshot_response import LocalDownloadSource as VaultDownloadSource
from tests.harness_wait import HARNESS_WAIT_SECONDS
from tests.services.test_backup_artifact_integrity_contract import (
    create_archive,
    owned_actor,
    recorded_download_headers,
)
from tests.services.test_backup_download_resource_lifetime import SlowBodySink


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("close_error", [False, True])
@pytest.mark.parametrize("cancellation", ["none", "task", "scope"])
async def test_download_drains_independent_checkpoint_close_before_owner_ends(
    tmp_path, monkeypatch, request, caplog, credential, secrets, close_error, cancellation
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await create_archive(f, secrets)
        download_headers = await recorded_download_headers(f, backup.id, secrets)
        source_type = VaultDownloadSource if secrets else ConfigurationDownloadSource
        expected_size, expected_sha = len(raw), hashlib.sha256(raw).hexdigest()
        del raw
        copied = threading.Event()
        entered, release, closed = asyncio.Event(), asyncio.Event(), asyncio.Event()
        selected = []
        leases = []
        original_factory = sessions.security_session_factory
        original_copy = source_type.copy_into
        original_acquire = DownloadPool.acquire
        marker = "OWNED-CHECKPOINT-PRIVATE-" + uuid4().hex

        def copy(source, snapshot):
            original_copy(source, snapshot)
            if source.files.root == f.root.absolute():
                assert snapshot.integrity == "verified" and snapshot.size == expected_size
                copied.set()

        def acquire(pool):
            lease = original_acquire(pool)
            leases.append(lease)
            return lease

        class ObservedSession(AsyncSession):
            async def __aenter__(self):
                await super().__aenter__()
                if copied.is_set() and not selected:
                    self.info["owned_close_probe"] = True
                    pid = await self.scalar(select(func.pg_backend_pid()))
                    selected.append((self, pid))
                return self

            async def close(self):
                if not self.info.get("owned_close_probe"):
                    return await super().close()
                # This is the real AsyncSession.close invoked by SQLAlchemy's
                # own __aexit__, after the real authority SELECT. Its physical
                # connection remains owned until released and actually closed.
                entered.set()
                await release.wait()
                try:
                    await super().close()
                finally:
                    closed.set()
                if close_error:
                    raise OSError(marker)

        monkeypatch.setattr(source_type, "copy_into", copy)
        monkeypatch.setattr(DownloadPool, "acquire", acquire)
        monkeypatch.setattr(sessions, "security_session_factory", async_sessionmaker(
            original_factory.kw["bind"], class_=ObservedSession,
            expire_on_commit=False, autoflush=False,
        ))
        sink = SlowBodySink()
        sink.release.set()
        scopes = []

        async def owner():
            if cancellation == "scope":
                with anyio.CancelScope() as scope:
                    scopes.append(scope)
                    await sink.run(f, backup.id, headers=download_headers)
            else:
                await sink.run(f, backup.id, headers=download_headers)

        async def backend_alive(pid):
            async with AsyncSession(f.engine) as observer:
                return bool(await observer.scalar(
                    text("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=:pid)"), {"pid": pid}
                ))

        task = asyncio.create_task(owner())
        observations = {}
        try:
            await asyncio.wait_for(entered.wait(), 10)
            assert copied.is_set() and len(selected) == 1 and len(leases) == 1
            db, pid = selected[0]
            alive_before = await backend_alive(pid)
            assert alive_before and not task.done() and sink.status is None
            pending = []
            for _ in range(3):
                if cancellation == "task":
                    task.cancel()
                elif cancellation == "scope":
                    assert len(scopes) == 1
                    scopes[0].cancel()
                await asyncio.sleep(.015)
                pending.append(not task.done())
            alive_paused = await backend_alive(pid)
            observations = {
                "actual_verified_copy": copied.is_set(),
                "actual_independent_session_close_boundary": entered.is_set(),
                "physical_backend_alive_before_cancellation": alive_before,
                "physical_backend_alive_while_close_paused": alive_paused,
                "owner_pending_after_each_signal": str(pending),
                "no_headers_while_close_paused": sink.status is None,
                "close_not_completed_while_paused": not closed.is_set(),
            }
        finally:
            release.set()
            if not task.done() and not observations:
                task.cancel()
            outcome = await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 10)
            if entered.is_set():
                await asyncio.wait_for(closed.wait(), 5)
            if selected:
                async with asyncio.timeout(HARNESS_WAIT_SECONDS):
                    while await backend_alive(selected[0][1]):
                        await asyncio.sleep(.01)
        observations.update(
            physical_backend_closed=not await backend_alive(pid),
            actual_session_transaction_closed=not db.in_transaction(),
            all_snapshots_and_slots_closed=all(x._fd == -1 and x._slot == -1 for x in leases),
            HTTP_status=sink.status,
            exact_archive_delivered=sink.bytes == expected_size and sink.digest.hexdigest() == expected_sha,
            private_error_absent_from_logs=marker not in caplog.text,
        )
        request.node.user_properties.extend(observations.items())
        assert all(pending), "Download owner ended while its physical authorization session was still open"
        assert observations["no_headers_while_close_paused"] and observations["close_not_completed_while_paused"]
        assert observations["physical_backend_closed"] and observations["actual_session_transaction_closed"]
        assert observations["all_snapshots_and_slots_closed"] and observations["private_error_absent_from_logs"]
        if cancellation == "none":
            assert outcome == [None]
            if close_error:
                assert sink.status == 503 and not observations["exact_archive_delivered"]
            else:
                assert sink.status == 200 and observations["exact_archive_delivered"]
        else:
            assert sink.status is None and not observations["exact_archive_delivered"]
            if cancellation == "task":
                assert isinstance(outcome[0], asyncio.CancelledError)
            else:
                assert outcome == [None]

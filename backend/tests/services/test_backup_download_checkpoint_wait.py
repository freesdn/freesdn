# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real PG waits during independent checkpoint acquisition, not provider proof."""

import asyncio
import hashlib
import threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.backup_download_response import LocalDownloadSource as ConfigurationDownloadSource
from app.core.security import create_access_token, verify_token
from app.db import session as sessions
from app.models.api_keys import APIKey
from app.models.core import User
from app.services.vault_snapshot_response import LocalDownloadSource as VaultDownloadSource
from tests.harness_wait import HARNESS_WAIT_SECONDS
from tests.services.test_backup_artifact_integrity_contract import (
    create_archive,
    owned_actor,
    recorded_download_headers,
)


@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("secrets", [False, True])
@pytest.mark.parametrize("transition", ["unchanged", "disabled", "expired"])
async def test_download_rechecks_after_real_checkpoint_database_wait(
    tmp_path, monkeypatch, request, credential, secrets, transition
):
    async with owned_actor(monkeypatch, tmp_path, credential) as f:
        backup, _path, raw = await create_archive(f, secrets)
        source_type = VaultDownloadSource if secrets else ConfigurationDownloadSource
        expected_size, expected_sha = len(raw), hashlib.sha256(raw).hexdigest()
        del raw
        claims = None
        if transition == "expired" and credential == "jwt":
            token = create_access_token(str(f.actor_id), token_version=17,
                                        expires_delta=timedelta(seconds=8))
            claims = await verify_token(token)
            assert claims is not None
            f.client.headers["Authorization"] = "Bearer " + token
        download_headers = await recorded_download_headers(f, backup.id, secrets)
        copied = threading.Event()
        release_copy = threading.Event()
        if claims is None:
            release_copy.set()
        real_copy = source_type.copy_into

        def copy(source, snapshot):
            real_copy(source, snapshot)
            if source.files.root == f.root.absolute():
                assert snapshot.integrity == "verified" and snapshot.size == expected_size
                copied.set()
                assert release_copy.wait(15), "Owned initial copy pause was not released"

        monkeypatch.setattr(source_type, "copy_into", copy)
        original_factory = sessions.security_session_factory
        entered = asyncio.Event()
        reader_pid = []
        lock_key = uuid4().int % (2**62)

        @asynccontextmanager
        async def guarded_factory():
            async with original_factory() as db:
                if copied.is_set() and not reader_pid:
                    reader_pid.append(await db.scalar(select(func.pg_backend_pid())))
                    entered.set()
                    # A real independently held PG lock delays this new security
                    # session BEFORE its original authority statement. No table
                    # lock is claimed; this is a connection-acquisition wait.
                    await db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
                yield db

        monkeypatch.setattr(sessions, "security_session_factory", guarded_factory)
        async with AsyncSession(f.engine) as holder:
            holder_pid = await holder.scalar(select(func.pg_backend_pid()))
            await holder.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
            task = asyncio.create_task(f.client.get(f"/api/v1/backups/{backup.id}/download", headers=download_headers))
            wait_proved = False
            try:
                if claims is not None:
                    async with asyncio.timeout(10):
                        while not copied.is_set():
                            assert not task.done(), "Actual completed copy was not reached"
                            await asyncio.sleep(.01)
                        # Leave a real, bounded expiry interval for the actual
                        # checkpoint wait; never change the app clock or JWT.
                        while datetime.now(UTC).timestamp() < claims["exp"] - 1.2:
                            await asyncio.sleep(.01)
                    release_copy.set()
                await asyncio.wait_for(entered.wait(), 10)
                async with asyncio.timeout(HARNESS_WAIT_SECONDS):
                    while not wait_proved:
                        async with AsyncSession(f.engine) as observer:
                            blocked_by = await observer.scalar(
                                text("SELECT pg_blocking_pids(:pid)"), {"pid": reader_pid[0]}
                            )
                        wait_proved = holder_pid in blocked_by
                        if not wait_proved:
                            await asyncio.sleep(.01)
                assert not task.done() and reader_pid[0] != holder_pid
                if transition == "disabled":
                    await holder.execute(update(User).where(User.id == f.actor_id).values(is_active=False))
                elif transition == "expired" and credential == "key":
                    await holder.execute(update(APIKey).where(APIKey.user_id == f.actor_id)
                                         .values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
                elif claims is not None:
                    async with asyncio.timeout(HARNESS_WAIT_SECONDS):
                        while datetime.now(UTC).timestamp() <= claims["exp"] + .05:
                            await asyncio.sleep(.01)
                await holder.commit()
                response = await asyncio.wait_for(task, 5)
                exact = (response.status_code == 200 and len(response.content) == expected_size
                         and hashlib.sha256(response.content).hexdigest() == expected_sha)
                fresh = await f.client.get("/api/v1/backups/stats")
                request.node.user_properties.extend({
                    "actual_verified_copy": copied.is_set(), "actual_PG_checkpoint_acquisition_wait": wait_proved,
                    "different_physical_connections": reader_pid[0] != holder_pid,
                    "HTTP_status": response.status_code, "fresh_request_status": fresh.status_code,
                    "exact_archive_delivered": exact,
                    "integrity_header": response.headers.get("x-freesdn-artifact-integrity"),
                }.items())
                if transition == "unchanged":
                    assert response.status_code == fresh.status_code == 200 and exact
                else:
                    assert response.status_code == fresh.status_code == 401 and not exact
                    assert "x-freesdn-artifact-integrity" not in response.headers
            finally:
                release_copy.set()
                await holder.rollback()
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

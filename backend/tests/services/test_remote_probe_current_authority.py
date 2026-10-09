"""Real protocol operations retain current authority across owned wait boundaries."""

import asyncio
import threading
from datetime import UTC, datetime, timedelta
from functools import partial

import anyio
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, verify_token
from app.models.api_keys import APIKey
from app.modules.backup.models import StorageLocation
from app.services.storage_probe_authority import StorageProbeAuthority
from tests.services.test_backup_artifact_integrity_contract import owned_actor
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_backup_transport_tls import ftps_peer as ftps_peer
from tests.services.test_remote_probe_authority_waits import mutate
from tests.services.test_remote_publication_acknowledgment import fixture
from tests.services.test_remote_write_coordination import configure, history


async def await_gate(task, gate):
    for _ in range(500):
        if gate.is_set() or task.done():
            break
        await asyncio.sleep(.01)
    assert gate.is_set() and not task.done(), "Actual owned wait prerequisite"


def observations(request, actor, remote, answer, rows, *, stage, credential, transition, gate):
    body = answer.json()
    values = {
        "stage": stage, "credential": credential, "transition": transition,
        "actual_owned_wait": gate.is_set(), "HTTP": answer.status_code,
        "success": body.get("success"), "authentications": remote.auths(),
        "renames": len([e for e in remote.state.events if e[0] == "rename"]),
        "deletes": len([e for e in remote.state.events if e[0] == "delete"]),
        "remaining_files": len(remote.files()), "history_rows": len(rows),
        "history_phases": ",".join(r.phase for r in rows),
        "response_candidates": "possible_storage_paths" in answer.text,
        "response_operation_id": any(str(r.operation_id) in answer.text for r in rows),
    }
    request.node.user_properties.extend(values.items())
    assert len(rows) == 1
    return values


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("stage", ["worker", "save", "exists", "load", "delete"])
@pytest.mark.parametrize("transition", ["unchanged", "revoked"])
async def test_probe_real_worker_and_protocol_waits(
    request, monkeypatch, tmp_path, protocol, credential, stage, transition,
):
    remote = fixture(request, monkeypatch, protocol)
    entered, release = threading.Event(), threading.Event()
    worker_ids = []
    main_thread = threading.get_ident()
    original_sync = anyio.to_thread.run_sync
    backend_class = type(remote.backend)
    original_native = backend_class._run

    def pause():
        worker_ids.append(threading.get_ident())
        entered.set()
        assert release.wait(12), "Owned worker release deadline"

    def worker_start(fn, *args):
        pause()
        return fn(*args)

    async def delayed_worker(fn, *args, **kwargs):
        if stage == "worker" and getattr(fn, "__name__", "") == "checked_target" and args[0] == "save":
            return await original_sync(partial(worker_start, fn), *args, **kwargs)
        return await original_sync(fn, *args, **kwargs)

    def completed_native(self, operation, *args, **kwargs):
        value = original_native(self, operation, *args, **kwargs)
        if operation == stage:
            pause()
        return value

    monkeypatch.setattr(anyio.to_thread, "run_sync", delayed_worker)
    monkeypatch.setattr(backend_class, "_run", completed_native)
    async with owned_actor(monkeypatch, tmp_path, credential) as actor:
        await configure(actor, remote, protocol)
        task = asyncio.create_task(actor.client.post(f"/api/v1/backups/storage-locations/{actor.storage_id}/test"))
        try:
            await await_gate(task, entered)
            auths_before = remote.auths()
            expected = {"worker": 0, "save": 1, "exists": 2, "load": 3, "delete": 4}[stage]
            assert auths_before == expected
            assert worker_ids and all(i != main_thread for i in worker_ids)
            if transition == "revoked":
                await mutate(actor, "revoked-jti" if credential == "jwt" else "key-disabled")
        finally:
            release.set()
            answer = await asyncio.wait_for(asyncio.shield(task), 15)
            await asyncio.gather(task, return_exceptions=True)
        rows = await history(actor)
        got = observations(request, actor, remote, answer, rows, stage=stage,
                           credential=credential, transition=transition, gate=entered)
        request.node.user_properties.extend({"real_distinct_worker": all(i != main_thread for i in worker_ids),
                                            "authentications_at_wait": auths_before}.items())
        if transition == "unchanged":
            assert answer.status_code == 200 and answer.json()["success"] is True
            assert got["authentications"] == 4 and got["deletes"] == 1 and got["remaining_files"] == 0
        else:
            assert answer.status_code in {401, 403}
            assert got["authentications"] == expected, "No connection after revocation boundary"
            assert not got["response_candidates"] and not got["response_operation_id"]
            assert got["remaining_files"] == (0 if stage in {"worker", "delete"} else 1)
            assert got["deletes"] == (1 if stage == "delete" else 0)
        assert rows[0].phase == ("dispatched" if stage == "worker" and transition == "revoked" else "acknowledged")


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
@pytest.mark.parametrize("transition", ["unchanged", "revoked"])
async def test_probe_actual_last_test_commit_does_not_authorize_late_response(
    request, monkeypatch, tmp_path, protocol, credential, transition,
):
    remote = fixture(request, monkeypatch, protocol)
    entered, release = asyncio.Event(), asyncio.Event()
    original = AsyncSession.commit
    committed = []
    async with owned_actor(monkeypatch, tmp_path, credential) as actor:
        await configure(actor, remote, protocol)

        async def commit(db):
            selected = any(isinstance(item, StorageLocation) and item.id == actor.storage_id
                           and item.last_test_status == "success" for item in db.dirty)
            value = await original(db)
            if selected:
                async with actor.engine.connect() as observer:
                    state = await observer.scalar(select(StorageLocation.last_test_status).where(StorageLocation.id == actor.storage_id))
                committed.append(state)
                entered.set()
                await asyncio.wait_for(release.wait(), 12)
            return value

        monkeypatch.setattr(AsyncSession, "commit", commit)
        task = asyncio.create_task(actor.client.post(f"/api/v1/backups/storage-locations/{actor.storage_id}/test"))
        try:
            await await_gate(task, entered)
            assert committed == ["success"] and remote.auths() == 4 and not remote.files()
            if transition == "revoked":
                await mutate(actor, "revoked-jti" if credential == "jwt" else "key-disabled")
        finally:
            release.set()
            answer = await asyncio.wait_for(asyncio.shield(task), 15)
            await asyncio.gather(task, return_exceptions=True)
        rows = await history(actor)
        got = observations(request, actor, remote, answer, rows, stage="commit",
                           credential=credential, transition=transition, gate=entered)
        request.node.user_properties.append(("actual_commit_independently_observed", committed == ["success"]))
        assert got["authentications"] == 4 and got["deletes"] == 1 and got["remaining_files"] == 0
        assert rows[0].phase == "acknowledged"
        if transition == "unchanged":
            assert answer.status_code == 200 and answer.json()["success"] is True
        else:
            assert answer.status_code in {401, 403}
            assert not got["response_candidates"] and not got["response_operation_id"]


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("credential", ["jwt", "key"])
async def test_probe_expiry_after_real_worker_authority_read_refuses_native_connection(
    request, monkeypatch, tmp_path, protocol, credential,
):
    remote = fixture(request, monkeypatch, protocol)
    entered, release = threading.Event(), threading.Event()
    original = anyio.from_thread.run
    completed_read = []

    def after_read(fn, *args, **kwargs):
        value = original(fn, *args, **kwargs)
        if isinstance(getattr(fn, "__self__", None), StorageProbeAuthority):
            completed_read.append(datetime.now(UTC).timestamp())
            entered.set()
            assert release.wait(12), "Owned native expiry gate deadline"
        return value

    monkeypatch.setattr(anyio.from_thread, "run", after_read)
    async with owned_actor(monkeypatch, tmp_path, credential) as actor:
        await configure(actor, remote, protocol)
        if credential == "jwt":
            token = create_access_token(str(actor.actor_id), token_version=17, expires_delta=timedelta(seconds=4))
            claims = await verify_token(token)
            assert claims is not None
            deadline = claims["exp"]
            actor.client.headers["Authorization"] = "Bearer " + token
        else:
            expires = datetime.now(UTC) + timedelta(seconds=3)
            deadline = expires.timestamp()
            async with actor.engine.begin() as db:
                changed = await db.execute(update(APIKey).where(APIKey.user_id == actor.actor_id).values(expires_at=expires))
                assert changed.rowcount == 1
        task = asyncio.create_task(actor.client.post(f"/api/v1/backups/storage-locations/{actor.storage_id}/test"))
        try:
            await await_gate(task, entered)
            assert len(completed_read) == 1 and completed_read[0] < deadline and remote.auths() == 0
            while datetime.now(UTC).timestamp() <= deadline:
                await asyncio.sleep(.02)
        finally:
            release.set()
            answer = await asyncio.wait_for(asyncio.shield(task), 15)
            await asyncio.gather(task, return_exceptions=True)
        rows = await history(actor)
        got = observations(request, actor, remote, answer, rows, stage="native-expiry",
                           credential=credential, transition="elapsed-expiry", gate=entered)
        request.node.user_properties.extend({"real_read_completed_before_expiry": completed_read[0] < deadline,
                                            "actual_clock_reached_expiry": datetime.now(UTC).timestamp() >= deadline}.items())
        assert answer.status_code in {401, 403}
        assert got["authentications"] == 0 and not remote.files() and not remote.state.events
        assert rows[0].phase == "dispatched"
        assert not got["response_candidates"] and not got["response_operation_id"]

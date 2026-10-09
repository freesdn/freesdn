"""Distinguish a completed ASGI response from a real in-flight disconnect."""

import asyncio
import hashlib

import pytest

from app.core import backup_download_response as core
from app.core.backup_downloads import DownloadPool
from app.services import vault_snapshot_response as vault


@pytest.mark.parametrize("module", ["core", "vault"])
@pytest.mark.parametrize("source", ["local", "remote"])
@pytest.mark.parametrize("disconnect_phase", ["complete", "in-flight"])
async def test_completed_send_stops_watcher_but_live_disconnect_cancels(
    tmp_path, module, source, disconnect_phase
):
    implementation = core if module == "core" else vault
    payload = b"Owned response boundary bytes" * 100
    root = tmp_path / "archive"
    root.mkdir(mode=0o700)
    file = root / "owned.fsdnvault"
    file.write_bytes(payload)
    file.chmod(0o600)
    expected = {"version": 1, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    pool = DownloadPool(tmp_path / "spool", slots=1, limit=65536, free_floor=0)
    if source == "local":
        response = implementation.LocalDownloadResponse(
            implementation.LocalDownloadSource(root, file.name, {"artifact_identity": expected}, pool.limit),
            pool, "owned.fsdnvault")
    else:
        async def copy(snapshot):
            snapshot.append(payload)
            snapshot.seal(expected)
        response = implementation.RemoteDownloadResponse(copy, pool, "owned.fsdnvault")
    disconnect = asyncio.Event()
    blocked_send = asyncio.Event()
    events = []

    async def receive():
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        events.append(dict(message))
        if message["type"] != "http.response.body":
            return
        if disconnect_phase == "complete" and not message["more_body"]:
            # The receiver becomes runnable at terminal body acceptance, as in
            # an ASGI transport. Successful send itself does not yield further.
            disconnect.set()
        elif disconnect_phase == "in-flight" and message["more_body"]:
            disconnect.set()
            await blocked_send.wait()

    task = asyncio.create_task(response({"type": "http"}, receive, send))
    if disconnect_phase == "complete":
        await asyncio.wait_for(task, timeout=5)
        assert b"".join(v.get("body", b"") for v in events) == payload
        assert events[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
        assert not task.cancelled()
    else:
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)
        assert task.cancelled()
        assert not any(v.get("type") == "http.response.body" and v.get("more_body") is False for v in events)
    assert response.snapshot is not None and response.snapshot._fd == -1
    recovered = pool.acquire()
    recovered.close()

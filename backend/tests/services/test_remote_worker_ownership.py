"""Owned real FTPS/SSH peers expose caller completion before worker cleanup."""

from __future__ import annotations

import asyncio
import contextlib
import threading
from dataclasses import dataclass, field

import anyio
import pytest

import app.services.backup as storage
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_backup_transport_tls import ftps_peer as ftps_peer

PAYLOAD = b"owned-backup-worker-payload\x00\xff"


@dataclass
class Gate:
    entered: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)
    finished: threading.Event = field(default_factory=threading.Event)
    worker_thread: int | None = None
    client_closed: bool = False
    real_authenticated_connection: bool = False

    def hold(self):
        self.worker_thread = threading.get_ident()
        self.entered.set()
        if not self.release.wait(5):
            raise AssertionError("Owned fixture gate was not released")


async def until(event):
    async with asyncio.timeout(5):
        while not event.is_set():
            await asyncio.sleep(0.001)


def prepare(request, protocol):
    if protocol == "sftp":
        peer = request.getfixturevalue("sftp_peer")
        root = peer.root / "backups"
        root.mkdir()
        (root / "file").write_bytes(PAYLOAD)
        return storage.SFTPStorageBackend(dict(peer.config)), peer
    peer = request.getfixturevalue("ftps_peer")
    peer.files["/backups/file"] = PAYLOAD
    return storage.FTPStorageBackend(
        {
            "host": "backup.test",
            "port": peer.port,
            "username": "test",
            "password": "test-only",
            "use_tls": True,
        }
    ), peer


def install_gate(monkeypatch, protocol, phase, gate, late_failure):
    name = "sftp_connection" if protocol == "sftp" else "ftps_connection"
    original = getattr(storage, name)

    @contextlib.contextmanager
    def owned_connection(*args, **kwargs):
        client = transport = None
        try:
            with original(*args, **kwargs) as client:
                if protocol == "sftp":
                    transport = client.get_channel().transport
                    gate.real_authenticated_connection = transport.is_authenticated()
                else:
                    gate.real_authenticated_connection = client.sock is not None
                if phase == "connected":
                    gate.hold()
                try:
                    yield client
                finally:
                    if phase == "closing":
                        gate.hold()
                    if late_failure:
                        raise RuntimeError("synthetic-provider-detail-must-not-leak")
        finally:
            gate.client_closed = (
                not transport.is_active() if transport is not None
                else client is not None and client.sock is None
            )
            gate.finished.set()

    monkeypatch.setattr(storage, name, owned_connection)


async def call(backend, operation):
    if operation == "save":
        return await backend.save("worker-owned", PAYLOAD, "archive.fsdn")
    return await getattr(backend, operation)("/backups/file")


async def exercise(request, monkeypatch, record_property, protocol, operation, phase,
                   cancellation, late_failure=False):
    backend, peer = prepare(request, protocol)
    gate = Gate()
    install_gate(monkeypatch, protocol, phase, gate, late_failure)
    outcome = {}

    async def invoke():
        with anyio.CancelScope() as scope:
            outcome["scope"] = scope
            try:
                outcome["value"] = await call(backend, operation)
            except Exception as exc:
                outcome["error_type"] = type(exc).__name__
            await anyio.lowlevel.checkpoint()
        outcome["scope_cancelled"] = scope.cancel_called

    task = asyncio.create_task(invoke())
    finished_before_release = None
    repeated_finished_before_release = None
    try:
        await until(gate.entered)
        if cancellation == "asyncio":
            task.cancel()
        elif cancellation == "anyio":
            outcome["scope"].cancel()
        await asyncio.sleep(0.025)
        finished_before_release = task.done()
        if cancellation == "asyncio":
            task.cancel()
        await asyncio.sleep(0.025)
        repeated_finished_before_release = task.done()
    finally:
        gate.release.set()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        await until(gate.finished)

    # Observe remote effects and close state before any contract assertion.
    if protocol == "sftp":
        files = {str(p.relative_to(peer.root)): p.read_bytes()
                 for p in peer.root.rglob("*") if p.is_file()}
        authentications = len(peer.authentications)
    else:
        files = dict(peer.files)
        authentications = peer.authenticated
    for name, value in {
        "real_authenticated_connection": gate.real_authenticated_connection,
        "authentication_count": authentications,
        "worker_off_event_loop": gate.worker_thread != threading.get_ident(),
        "caller_finished_before_release": finished_before_release,
        "caller_finished_after_repeat_before_release": repeated_finished_before_release,
        "actual_client_closed": gate.client_closed,
        "worker_finally_finished": gate.finished.is_set(),
        "remote_files_observed": len(files),
        "operation": operation,
        "phase": phase,
        "cancellation": cancellation,
        "late_failure": late_failure,
    }.items():
        record_property(name, value)
    assert gate.real_authenticated_connection and authentications == 1
    assert gate.worker_thread != threading.get_ident()
    assert gate.client_closed and gate.finished.is_set()
    assert not any(".partial-" in p for p in files)
    if operation == "save":
        assert len(files) == 2 and list(files.values()).count(PAYLOAD) == 2
    elif operation == "delete":
        assert not files
    else:
        assert list(files.values()) == [PAYLOAD]
    assert finished_before_release is False, "Caller detached from a live protocol worker"
    assert repeated_finished_before_release is False, "Repeated cancellation lost worker ownership"
    if cancellation == "none":
        assert "error_type" not in outcome
        if operation == "load":
            assert outcome["value"] == PAYLOAD
        elif operation == "get_size":
            assert outcome["value"] == len(PAYLOAD)
        elif operation in {"delete", "exists"}:
            assert outcome["value"] is True
    elif cancellation == "asyncio":
        assert task.cancelled()
    else:
        assert outcome["scope_cancelled"] is True


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("operation", ["save", "load", "delete", "exists", "get_size"])
@pytest.mark.parametrize("phase", ["connected", "closing"])
@pytest.mark.parametrize("cancellation", ["asyncio", "anyio"])
async def test_real_remote_worker_ownership(
    request, monkeypatch, record_property, protocol, operation, phase, cancellation
):
    await exercise(request, monkeypatch, record_property, protocol, operation, phase, cancellation)


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("operation", ["save", "load"])
@pytest.mark.parametrize("cancellation", ["asyncio", "anyio"])
async def test_late_protocol_error_still_closes_before_cancelled_owner(
    request, monkeypatch, record_property, protocol, operation, cancellation, caplog
):
    await exercise(request, monkeypatch, record_property, protocol, operation,
                   "closing", cancellation, late_failure=True)
    assert "synthetic-provider-detail-must-not-leak" not in caplog.text


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("operation", ["save", "load", "delete", "exists", "get_size"])
async def test_original_successful_protocol_controls(
    request, monkeypatch, record_property, protocol, operation
):
    await exercise(request, monkeypatch, record_property, protocol, operation, "closing", "none")

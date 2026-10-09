"""Real SSH/FTPS transfers retain two shared CRUD slots until their cleanup."""

from __future__ import annotations

import asyncio
import contextlib
import threading
from dataclasses import dataclass, field

import anyio
import pytest

import app.services.backup as storage
from app.services.backup_transport import StorageConfigurationError
from tests.services.test_backup_transport_sftp import sftp_peer as sftp_peer
from tests.services.test_backup_transport_tls import TLSPeer
from tests.services.test_backup_transport_tls import ftps_peer as ftps_peer

PAYLOAD = b"owned-two-slot-backup\x00\xff"


@dataclass
class Observation:
    release: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    entered: int = 0
    finished: int = 0
    authenticated: int = 0
    closed: int = 0
    off_loop: int = 0
    escape_fired: bool = False


async def until(predicate):
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(0.001)


@pytest.fixture
def destinations(sftp_peer, ftps_peer, tmp_path):
    folder = sftp_peer.root / "backups"
    folder.mkdir()
    (folder / "file").write_bytes(PAYLOAD)
    (folder / "probe-file").write_bytes(PAYLOAD)
    ftps_peer.files["/backups/file"] = PAYLOAD
    extra_ftps = TLSPeer(tmp_path / "ca.pem", tmp_path / "key.pem")
    extra_ftps.files["/backups/probe-file"] = PAYLOAD

    def ftp(peer):
        return storage.FTPStorageBackend({"host": "backup.test", "port": peer.port,
                                          "use_tls": True, "username": "test", "password": "test-only"})

    try:
        yield {
            "held": (storage.SFTPStorageBackend(dict(sftp_peer.config)), ftp(ftps_peer)),
            "probes": {"sftp": storage.SFTPStorageBackend(dict(sftp_peer.config)), "ftps": ftp(extra_ftps)},
            "peers": (sftp_peer, ftps_peer, extra_ftps),
        }
    finally:
        extra_ftps.close()


def gate_connections(monkeypatch, observation, *, late_failure=False):
    event_loop_thread = threading.get_ident()

    def replace(name, protocol):
        original = getattr(storage, name)

        @contextlib.contextmanager
        def connection(*args, **kwargs):
            client = transport = None
            try:
                with original(*args, **kwargs) as client:
                    transport = client.get_channel().transport if protocol == "sftp" else None
                    authenticated = transport.is_authenticated() if transport is not None else client.sock is not None
                    with observation.lock:
                        observation.authenticated += int(authenticated)
                        observation.off_loop += int(threading.get_ident() != event_loop_thread)
                        observation.entered += 1
                    if not observation.release.wait(5):
                        observation.escape_fired = True
                        raise AssertionError("Owned protocol gate was not released")
                    yield client
                    if late_failure:
                        raise OSError("synthetic remote detail must remain private")
            finally:
                closed = not transport.is_active() if transport is not None else client is not None and client.sock is None
                with observation.lock:
                    observation.closed += int(closed)
                    observation.finished += 1

        monkeypatch.setattr(storage, name, connection)

    replace("sftp_connection", "sftp")
    replace("ftps_connection", "ftps")


async def operation(backend, action):
    if action == "save":
        return await backend.save("admission-probe", PAYLOAD, "archive.fsdn")
    return await getattr(backend, action)("/backups/probe-file")


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
@pytest.mark.parametrize("action", ["save", "load", "delete", "exists", "get_size"])
@pytest.mark.parametrize("cancellation", ["none", "asyncio", "anyio"])
async def test_third_real_operation_refused_until_both_owned_workers_close(
    destinations, monkeypatch, request, protocol, action, cancellation,
):
    observed = Observation()
    gate_connections(monkeypatch, observed)
    scopes = []

    async def held(backend):
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            value = await backend.load("/backups/file")
            await anyio.lowlevel.checkpoint()
            return value

    holders = [asyncio.create_task(held(b)) for b in destinations["held"]]
    probe = None
    probe_before_release = None
    held_done_before_release = None
    try:
        await until(lambda: observed.entered == 2)
        if cancellation == "asyncio":
            for task in holders:
                task.cancel()
                task.cancel()
        elif cancellation == "anyio":
            for scope in scopes:
                scope.cancel()
        await asyncio.sleep(0.025)
        held_done_before_release = [t.done() for t in holders]
        probe = asyncio.create_task(operation(destinations["probes"][protocol], action))
        await until(lambda: probe.done() or observed.entered == 3)
        probe_before_release = probe.done()
        authenticated_before_release = observed.authenticated
    finally:
        observed.release.set()
        pending = holders + ([probe] if probe is not None else [])
        results = await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), 5)
        await until(lambda: observed.finished == observed.entered)
    probe_result = results[-1]
    # Capture real peer effects before the proposed admission assertions.
    ssh, tls, extra_tls = destinations["peers"]
    peer_auth_count = len(ssh.authentications) + tls.authenticated + extra_tls.authenticated
    sftp_probe_exists = (ssh.root / "backups/probe-file").exists()
    ftps_probe_exists = "/backups/probe-file" in extra_tls.files
    request.node.user_properties.extend({
        "action": action, "protocol": protocol, "cancellation": cancellation,
        "two_holders_done_before_release": held_done_before_release,
        "probe_completed_before_release": probe_before_release,
        "authenticated_before_release": authenticated_before_release,
        "actual_authenticated_peers": peer_auth_count,
        "actual_client_closed": observed.closed, "worker_finished": observed.finished,
        "worker_off_event_loop": observed.off_loop,
        "probe_result_type": type(probe_result).__name__,
        "actual_sftp_probe_file_exists": sftp_probe_exists,
        "actual_ftps_probe_file_exists": ftps_probe_exists,
        "escape_fired": observed.escape_fired,
    }.items())
    assert not observed.escape_fired
    assert observed.closed == observed.finished == observed.entered == observed.off_loop
    assert (ssh.root / "backups/file").read_bytes() == tls.files["/backups/file"] == PAYLOAD
    assert held_done_before_release == [False, False]
    assert probe_before_release, "Remote operation queued or connected while both slots were owned"
    assert isinstance(probe_result, StorageConfigurationError)
    assert str(probe_result) == "Remote backup operation capacity is busy; retry later"
    assert authenticated_before_release == peer_auth_count == 2
    assert sftp_probe_exists and ftps_probe_exists
    # Explicit caller retry after confirmed local cleanup, never automatic replay.
    retry = await destinations["probes"][protocol].load("/backups/probe-file")
    assert retry == PAYLOAD


@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
async def test_two_real_operations_complete_and_slots_recover_after_success_or_error(
    destinations, monkeypatch, request, failure, protocol,
):
    observed = Observation()
    with monkeypatch.context() as patch:
        gate_connections(patch, observed, late_failure=failure)
        tasks = [asyncio.create_task(b.load("/backups/file")) for b in destinations["held"]]
        try:
            await until(lambda: observed.entered == 2)
            pending_before_release = [not task.done() for task in tasks]
        finally:
            observed.release.set()
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 5)
            await until(lambda: observed.finished == observed.entered)
    retried = await destinations["probes"][protocol].load("/backups/probe-file")
    request.node.user_properties.extend({
        "both_accepted_before_release": pending_before_release,
        "real_authenticated_peers": observed.authenticated,
        "closed_clients": observed.closed, "workers_finished": observed.finished,
        "observed_result_types": [type(v).__name__ for v in results],
        "subsequent_explicit_read_succeeds": retried == PAYLOAD,
        "escape_fired": observed.escape_fired,
    }.items())
    assert not observed.escape_fired
    assert pending_before_release == [True, True]
    assert observed.authenticated == observed.closed == observed.finished == 2
    assert all(isinstance(v, OSError) for v in results) if failure else results == [PAYLOAD, PAYLOAD]
    assert retried == PAYLOAD


@pytest.mark.parametrize("protocol", ["sftp", "ftps"])
async def test_already_cancelled_caller_never_connects_and_later_read_is_usable(destinations, request, protocol):
    async def cancelled():
        asyncio.current_task().cancel()
        return await destinations["probes"][protocol].load("/backups/probe-file")

    result = (await asyncio.gather(asyncio.create_task(cancelled()), return_exceptions=True))[0]
    ssh, tls, extra_tls = destinations["peers"]
    before_retry = len(ssh.authentications) + tls.authenticated + extra_tls.authenticated
    value = await destinations["probes"][protocol].load("/backups/probe-file")
    request.node.user_properties.extend({
        "cancelled_result_type": type(result).__name__,
        "authentications_before_explicit_retry": before_retry,
        "subsequent_explicit_read_succeeds": value == PAYLOAD,
    }.items())
    assert isinstance(result, asyncio.CancelledError)
    assert before_retry == 0 and value == PAYLOAD

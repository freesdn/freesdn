"""Real copied model credentials, native child, TLS/WS/HTTP and disk snapshots.

Only DNS destination admission is replaced for the owned loopback protocol
peer. Separate controls retain production private/metadata address policy.
"""

import asyncio
import hashlib
import json
import os
import time
from uuid import uuid4

import anyio
import pytest

from app.core.backup_artifacts import BackupArtifactError
from app.core.backup_downloads import DownloadPool
from app.core.crypto import encrypt_credential
from app.services import vault_truenas_stream as native
from app.services.vault_native_resolution import _checked_addresses
from tests.services import truenas_owned_peer
from tests.services.truenas_owned_peer import API_KEY, HOST, USERNAME

truenas_peer = truenas_owned_peer.truenas_peer

KEY = "owned-id/2026/archive.fsdnvault"


@pytest.fixture
def owned_config(truenas_peer):
    org, ctrl, site = uuid4(), uuid4(), uuid4()
    config = {"controller_id": str(ctrl), "dataset_path": "tank/backups", "_organization_id": str(org)}
    values = {"id": str(ctrl), "site_id": str(site), "organization_id": str(org), "site_deleted_at": None,
              "controller_type": "truenas", "host": HOST, "port": truenas_peer.port, "use_ssl": True,
              "verify_ssl": True, "credential_id": None, "config": {"username": USERNAME, "password": encrypt_credential(API_KEY)},
              "is_active": True, "deleted_at": None}
    return config, values


@pytest.fixture
def owned_lifetime(monkeypatch, request):
    states, pins = [], []
    original = native._start_owned

    async def start(state):
        states.append(state)
        await original(state)

    async def pin(host, *, allow_private=False):
        assert host in {HOST, "wrong.truenas.test"} and allow_private is True
        pins.append(host)
        return "127.0.0.1"

    monkeypatch.setattr(native, "_start_owned", start)
    monkeypatch.setattr(native, "resolve_storage_host", pin)
    yield states, pins
    for state in states:
        assert state.process.raw.poll() is not None
        assert state.pidfd is None and state.process.pidfd is None
        assert state.process.raw.stdin.closed and state.process.raw.stdout.closed
        assert not os.path.exists(f"/proc/{state.process.pid}")
    assert native._ADMISSION.borrowed_tokens == native._PREP_ADMISSION.borrowed_tokens == 0
    request.node.user_properties.extend({"truenas_native_children_reaped": len(states),
        "truenas_owned_admission_released": True, "truenas_pin_calls": len(pins)}.items())


def identity(body):
    return {"version": 1, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def snapshot(tmp_path, bound=1024 * 1024):
    return DownloadPool(tmp_path / "spool", slots=1, limit=bound, free_floor=0).acquire()


async def prepare(config):
    return await native.prepare_truenas_download(config[0], json.dumps(config[1]))


@pytest.mark.parametrize("mode", ["normal", "chunked", "gzip"])
@pytest.mark.parametrize("recorded", [True, False])
async def test_native_exact_archive_and_tls_identity(truenas_peer, owned_config, owned_lifetime, tmp_path, mode, recorded):
    truenas_peer.mode = mode
    prepared = await prepare(owned_config)
    assert API_KEY not in repr(prepared)
    snap = snapshot(tmp_path)
    try:
        await prepared.copy_download_into(KEY, identity(truenas_peer.body) if recorded else None, snap)
        copied = b""
        while chunk := snap.read_chunk():
            copied += chunk
        assert copied == truenas_peer.body
        assert snap.integrity == ("verified" if recorded else "legacy_unverified")
        assert truenas_peer.sni == [HOST, HOST]
        assert len(truenas_peer.requests) == 2
        assert all(r["tls"] and r["headers"]["host"] == f"{HOST}:{truenas_peer.port}" for r in truenas_peer.requests)
        assert [c["method"] for c in truenas_peer.calls] == ["auth.login_ex", "core.download"]
        assert truenas_peer.requests[1]["headers"]["accept-encoding"] == "identity"
    finally:
        snap.close()


@pytest.mark.parametrize("mode", ["auth_refused", "ws_redirect", "event_flood", "oversized_control", "binary_control", "duplicate_control",
    "foreign_url", "backslash_url", "fragment_url", "bad_job", "http_redirect", "truncated", "duplicate_length", "ambiguous_transfer",
    "unknown_encoding", "huge_headers", "gzip_truncated", "gzip_trailing"])
async def test_native_refuses_protocol_failure_without_sealing(truenas_peer, owned_config, owned_lifetime, tmp_path, mode):
    truenas_peer.mode = mode
    prepared = await prepare(owned_config)
    snap = snapshot(tmp_path)
    try:
        with pytest.raises(native.RemoteTransferError, match="TrueNAS backup transfer failed") as error:
            await prepared.copy_download_into(KEY, identity(truenas_peer.body), snap)
        assert snap.integrity is None
        assert API_KEY not in str(error.value) and "owned-one-shot" not in str(error.value)
        assert all(r["headers"]["host"] == f"{HOST}:{truenas_peer.port}" for r in truenas_peer.requests)
        if mode in {"foreign_url", "backslash_url", "fragment_url", "http_redirect", "truncated", "duplicate_length",
                    "ambiguous_transfer", "unknown_encoding", "huge_headers", "gzip_truncated", "gzip_trailing"}:
            assert truenas_peer.calls[-1] == {"method": "core.job_abort", "params": [42]}
    finally:
        snap.close()


@pytest.mark.parametrize("mode", ["normal", "gzip_bomb"])
async def test_native_bounds_wire_and_decoded_bytes(truenas_peer, owned_config, owned_lifetime, tmp_path, mode):
    truenas_peer.mode = mode
    truenas_peer.body = b"a" * (3 * 1024 * 1024)
    prepared = await prepare(owned_config)
    snap = snapshot(tmp_path, 100000)
    try:
        with pytest.raises(native.RemoteTransferError):
            await prepared.copy_download_into(KEY, None, snap)
        assert snap.size <= snap.limit and snap.integrity is None
    finally:
        snap.close()


async def test_native_rejects_recorded_hash_mismatch(truenas_peer, owned_config, owned_lifetime, tmp_path):
    prepared = await prepare(owned_config)
    snap = snapshot(tmp_path)
    try:
        with pytest.raises(BackupArtifactError):
            await prepared.copy_download_into(KEY, identity(b"different"), snap)
        assert snap.integrity is None
    finally:
        snap.close()


@pytest.mark.parametrize("change", ["wrong_host", "missing_ca", "invalid_ca", "explicit_insecure"])
async def test_native_preserves_tls_policy(truenas_peer, owned_config, owned_lifetime, tmp_path, monkeypatch, change):
    if change == "wrong_host":
        owned_config[1]["host"] = "wrong.truenas.test"
    elif change == "missing_ca":
        monkeypatch.delenv("FREESDN_DEVICE_CA_BUNDLE")
    elif change == "invalid_ca":
        monkeypatch.setenv("FREESDN_DEVICE_CA_BUNDLE", str(tmp_path / "missing.pem"))
    else:
        owned_config[1]["verify_ssl"] = False
        monkeypatch.delenv("FREESDN_DEVICE_CA_BUNDLE")
    prepared = await prepare(owned_config)
    snap = snapshot(tmp_path)
    try:
        if change == "explicit_insecure":
            await prepared.copy_download_into(KEY, identity(truenas_peer.body), snap)
            assert snap.integrity == "verified"
        else:
            with pytest.raises(native.RemoteTransferError):
                await prepared.copy_download_into(KEY, None, snap)
            assert not truenas_peer.calls and snap.integrity is None
    finally:
        snap.close()


@pytest.mark.parametrize("phase", ["slow_control", "slow_body"])
@pytest.mark.parametrize("kind", ["asyncio", "anyio"])
async def test_native_cancellation_reaps_before_admission_release(truenas_peer, owned_config, owned_lifetime, tmp_path, phase, kind):
    truenas_peer.mode = phase
    prepared = await prepare(owned_config)
    snap = snapshot(tmp_path)
    try:
        async def wait_blocked():
            with anyio.fail_after(10):
                while not truenas_peer.blocked.is_set():
                    await anyio.sleep(.01)

        if kind == "asyncio":
            task = asyncio.create_task(prepared.copy_download_into(KEY, None, snap))
            await wait_blocked()
            for _ in range(5):
                task.cancel()
                await asyncio.sleep(0)
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            async with anyio.create_task_group() as group:
                group.start_soon(prepared.copy_download_into, KEY, None, snap)
                await wait_blocked()
                group.cancel_scope.cancel()
        assert native._ADMISSION.borrowed_tokens == 0 and snap.integrity is None
        assert all(state.process.raw.poll() is not None for state in owned_lifetime[0])
    finally:
        truenas_peer.release.set()
        snap.close()


@pytest.mark.parametrize("field", ["id", "organization_id", "site_deleted_at", "is_active", "deleted_at", "controller_type"])
async def test_copied_controller_scope_refused_before_network(truenas_peer, owned_config, owned_lifetime, field):
    owned_config[1][field] = {"site_deleted_at": "2026-10-01T00:00:00Z", "deleted_at": "2026-10-01T00:00:00Z",
                             "is_active": False, "controller_type": "unifi"}.get(field, str(uuid4()))
    with pytest.raises(native.RemoteTransferError):
        await prepare(owned_config)
    assert not truenas_peer.requests and not owned_lifetime[0] and not owned_lifetime[1]


async def test_copied_credentials_and_destination_do_not_follow_later_mutation(truenas_peer, owned_config, owned_lifetime, tmp_path):
    prepared = await prepare(owned_config)
    owned_config[1]["config"]["password"] = encrypt_credential("different synthetic credential")
    owned_config[1]["host"] = "external.invalid"
    owned_config[0]["dataset_path"] = "tank/different"
    snap = snapshot(tmp_path)
    try:
        await prepared.copy_download_into(KEY, identity(truenas_peer.body), snap)
        assert snap.integrity == "verified"
        assert truenas_peer.calls[0]["params"][0]["api_key"] == API_KEY
    finally:
        snap.close()


@pytest.mark.parametrize("after", [1, 2])
async def test_authority_revalidated_around_real_native_preparation(truenas_peer, owned_config, owned_lifetime, after):
    calls = 0

    async def check():
        nonlocal calls
        calls += 1
        if calls == after:
            raise PermissionError("owned authority changed")

    with pytest.raises(PermissionError, match="owned authority changed"):
        await native.prepare_truenas_download(owned_config[0], json.dumps(owned_config[1]), revalidate=check)
    assert calls == after and not truenas_peer.requests
    assert len(owned_lifetime[1]) == after - 1


@pytest.mark.parametrize("phase", ["slow_control", "slow_body"])
async def test_unresponsive_peer_refuses_under_original_transport_deadlines(truenas_peer, owned_config, owned_lifetime, tmp_path, phase):
    truenas_peer.mode = phase
    prepared = await prepare(owned_config)
    snap = snapshot(tmp_path)
    started = time.monotonic()
    try:
        with pytest.raises(native.RemoteTransferError):
            await prepared.copy_download_into(KEY, None, snap)
        assert truenas_peer.blocked.is_set() and snap.integrity is None
        assert 4 <= time.monotonic() - started < 12
    finally:
        truenas_peer.release.set()
        snap.close()


@pytest.mark.parametrize("key", ["owned-id/../archive.fsdnvault", "../archive.fsdnvault", "owned!id/archive.fsdnvault",
                                 "owned-id//archive.fsdnvault", "owned-id/archive\\.fsdnvault"])
async def test_invalid_locator_refused_before_native_start(truenas_peer, owned_config, owned_lifetime, tmp_path, key):
    prepared = await prepare(owned_config)
    snap = snapshot(tmp_path)
    try:
        with pytest.raises(native.RemoteTransferError):
            await prepared.copy_download_into(key, None, snap)
        assert not owned_lifetime[0] and not truenas_peer.requests and snap.integrity is None
    finally:
        snap.close()


@pytest.mark.parametrize("address,allowed", [("192.168.10.10", True), ("127.0.0.1", False), ("169.254.169.254", False),
                                            ("100.100.100.200", False), ("::1", False)])
def test_real_destination_admission_is_not_replaced_for_appliances(address, allowed):
    if allowed:
        assert _checked_addresses([address], allow_private=True) == address
    else:
        with pytest.raises(ValueError):
            _checked_addresses([address], allow_private=True)

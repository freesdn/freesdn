# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private disk-slot and snapshot ownership cases; no HTTP integration claim."""

import errno
import hashlib
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

import app.core.backup_downloads as module
from app.core.backup_artifacts import BackupArtifactError
from app.core.backup_downloads import (
    CHUNK_BYTES,
    DownloadCapacityError,
    DownloadPool,
    DownloadPoolError,
)


def pool(root, *, slots=1, limit=CHUNK_BYTES * 4, free_floor=0):
    return DownloadPool(root, slots=slots, limit=limit, free_floor=free_floor)


def identity(raw):
    return {"version": 1, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def fill(lease, raw):
    for offset in range(0, len(raw), CHUNK_BYTES):
        lease.append(raw[offset:offset + CHUNK_BYTES])


def consume(lease):
    chunks = []
    while chunk := lease.read_chunk():
        assert len(chunk) <= CHUNK_BYTES
        chunks.append(chunk)
    return b"".join(chunks)


def open_owned(root):
    result = []
    for fd in Path('/proc/self/fd').iterdir():
        try:
            if os.readlink(fd).startswith(str(root) + '/'):
                result.append(int(fd.name))
        except FileNotFoundError:
            continue
    return result


def force_named_fallback(monkeypatch):
    original = os.open

    def open_file(path, flags, *args, **kwargs):
        if hasattr(os, "O_TMPFILE") and flags & os.O_TMPFILE == os.O_TMPFILE:
            raise OSError(errno.EOPNOTSUPP, "Owned filesystem lacks unnamed files")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_file)


@pytest.mark.parametrize("verified", [False, True])
@pytest.mark.parametrize("fallback", [False, True])
def test_private_snapshot_exact_readback_and_slot_ownership(tmp_path, monkeypatch, request, verified, fallback):
    root = tmp_path / "transfers"
    if fallback:
        force_named_fallback(monkeypatch)
    lease = pool(root).acquire()
    raw = os.urandom(CHUNK_BYTES * 2 + 37)
    try:
        fill(lease, raw)
        result = lease.seal(identity(raw) if verified else None)
        observed = {
            "disk_filesystem": module._disk_filesystem(lease._fd),
            "snapshot_unlinked": os.fstat(lease._fd).st_nlink == 0,
            "snapshot_owner_only": os.fstat(lease._fd).st_mode & 0o777 == 0o600,
            "exact_readback": consume(lease) == raw,
            "integrity": result,
        }
        with pytest.raises(DownloadCapacityError):
            pool(root).acquire()
        observed["slot_remains_held_after_read"] = True
    finally:
        lease.close()
    observed["no_owned_descriptors"] = not open_owned(root)
    observed["only_pool_metadata_remains"] = {p.name for p in root.iterdir()} == {"pool-policy.json", "slot-00"}
    request.node.user_properties.extend(observed.items())
    assert observed["snapshot_unlinked"] and observed["snapshot_owner_only"] and observed["exact_readback"]
    assert observed["integrity"] == ("verified" if verified else "legacy_unverified")
    assert observed["no_owned_descriptors"] and observed["only_pool_metadata_remains"]
    next_lease = pool(root).acquire()
    next_lease.close()


@pytest.mark.parametrize("slots", [1, 2])
def test_slots_bound_independent_instances_and_release_once(tmp_path, slots):
    root = tmp_path / "transfers"
    owners = [pool(root, slots=slots).acquire() for _ in range(slots)]
    try:
        with pytest.raises(DownloadCapacityError):
            pool(root, slots=slots).acquire()
        owners[0].close()
        owners[0].close()
        replacement = pool(root, slots=slots).acquire()
        try:
            with pytest.raises(DownloadCapacityError):
                pool(root, slots=slots).acquire()
        finally:
            replacement.close()
    finally:
        for owner in owners:
            owner.close()
    assert not open_owned(root)


@pytest.mark.parametrize("slots", [1, 2])
def test_slots_apply_to_an_independent_process(tmp_path, request, slots):
    root = tmp_path / "transfers"
    owners = [pool(root, slots=slots).acquire() for _ in range(slots)]
    code = '''import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location("app.core.backup_downloads",sys.argv[1]);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
try: lease=m.DownloadPool(Path(sys.argv[2]),slots=int(sys.argv[3]),limit=262144,free_floor=0).acquire()
except m.DownloadCapacityError: print("OWNED_BUSY")
else:
 try: print("OWNED_ACQUIRED")
 finally: lease.close()
'''

    def child():
        result = subprocess.run([sys.executable, "-B", "-c", code, module.__file__, str(root), str(slots)], capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, "Owned child fixture failed; inspect its bounded output"
        return result.stdout.strip().splitlines()[-1]

    try:
        occupied = child()
        owners[0].close()
        released = child()
    finally:
        for owner in owners:
            owner.close()
    request.node.user_properties.extend([("independent_process_occupied", occupied), ("independent_process_after_release", released)])
    assert occupied == "OWNED_BUSY" and released == "OWNED_ACQUIRED"
    assert not open_owned(root)


@pytest.mark.parametrize("changed", [{"slots": 2}, {"limit": CHUNK_BYTES * 2}, {"free_floor": 1024}])
def test_conflicting_process_policies_do_not_create_extra_capacity(tmp_path, changed):
    root = tmp_path / "transfers"
    owner = pool(root).acquire()
    try:
        original = (root / "pool-policy.json").read_bytes()
        with pytest.raises(DownloadPoolError):
            pool(root, **changed).acquire()
        assert (root / "pool-policy.json").read_bytes() == original
    finally:
        owner.close()


@pytest.mark.parametrize("entry", ["pool-policy.json", "slot-00"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public-mode"])
def test_unsafe_pool_entries_are_refused_without_rewriting(tmp_path, entry, kind):
    root = tmp_path / "transfers"
    first = pool(root).acquire()
    first.close()
    target = root / entry
    target.unlink()
    outside = tmp_path / "owned-sentinel"
    outside.write_bytes(b"owned sentinel must not change")
    if kind == "symlink":
        target.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, target)
    else:
        target.write_bytes(b"owned invalid metadata")
        target.chmod(0o644)
    with pytest.raises(OSError):
        pool(root).acquire()
    assert outside.read_bytes() == b"owned sentinel must not change"
    if kind == "public-mode":
        assert target.stat().st_mode & 0o777 == 0o644
    assert not open_owned(root)


def test_low_free_space_refuses_before_snapshot_allocation(tmp_path, monkeypatch):
    root = tmp_path / "transfers"
    monkeypatch.setattr(os, "fstatvfs", lambda _fd: SimpleNamespace(f_bavail=1, f_frsize=1))
    with pytest.raises(DownloadCapacityError):
        pool(root).acquire()
    assert not open_owned(root)
    assert not list(root.glob(".empty-transfer-*"))


def test_actual_tmpfs_is_refused_before_pool_files_are_created(request):
    root = Path('/dev/shm') / ('freesdn-owned-transfer-' + uuid4().hex)
    root.mkdir(mode=0o700)
    try:
        with pytest.raises(DownloadPoolError):
            pool(root).acquire()
        observed = not list(root.iterdir()) and not open_owned(root)
        request.node.user_properties.append(("actual_tmpfs_refused_without_files", observed))
        assert observed
    finally:
        root.rmdir()


@pytest.mark.parametrize("kind", ["chunk", "total"])
def test_per_chunk_and_total_capacity_are_enforced(tmp_path, kind):
    owner = pool(tmp_path / "transfers", limit=CHUNK_BYTES).acquire()
    try:
        if kind == "total":
            owner.append(b"a" * CHUNK_BYTES)
            with pytest.raises(DownloadPoolError):
                owner.append(b"b")
            assert owner.size == CHUNK_BYTES
        else:
            with pytest.raises(DownloadPoolError):
                owner.append(b"a" * (CHUNK_BYTES + 1))
            assert owner.size == 0
    finally:
        owner.close()


@pytest.mark.parametrize("operation", ["read-before-seal", "append-after-seal", "seal-twice", "read-after-close"])
def test_snapshot_lifecycle_rejects_unowned_or_unverified_use(tmp_path, operation):
    owner = pool(tmp_path / "transfers").acquire()
    try:
        if operation == "read-before-seal":
            call = owner.read_chunk
        else:
            owner.append(b"owned data")
            owner.seal(None)
            if operation == "append-after-seal":
                def call():
                    return owner.append(b"more")
            elif operation == "seal-twice":
                def call():
                    return owner.seal(None)
            else:
                owner.close()
                call = owner.read_chunk
        with pytest.raises(DownloadPoolError):
            call()
    finally:
        owner.close()


@pytest.mark.parametrize("problem", ["empty", "digest", "bytes", "metadata", "readback"])
def test_snapshot_validation_refuses_mismatches(tmp_path, monkeypatch, problem):
    owner = pool(tmp_path / "transfers").acquire()
    try:
        raw = b"owned secret-bearing synthetic archive"
        if problem != "empty":
            owner.append(raw)
        expected = identity(raw)
        if problem == "digest":
            expected["sha256"] = "0" * 64
        elif problem == "bytes":
            expected["bytes"] += 1
        elif problem == "metadata":
            expected["version"] = 99
        elif problem == "readback":
            original = os.fsync

            def corrupt_after_sync(fd):
                result = original(fd)
                if fd == owner._fd:
                    os.pwrite(fd, b"X", 0)
                return result

            monkeypatch.setattr(os, "fsync", corrupt_after_sync)
        with pytest.raises((DownloadPoolError, BackupArtifactError)):
            owner.seal(expected)
        assert owner.integrity is None
    finally:
        owner.close()


@pytest.mark.parametrize("close_error", [False, True])
def test_parent_close_error_cannot_detach_a_new_snapshot(tmp_path, monkeypatch, request, close_error):
    root = tmp_path / "transfers"
    original_close = os.close
    original_allocate = DownloadPool._unlinked_snapshot
    allocated = []
    injected = []

    def allocate(directory):
        fd = original_allocate(directory)
        allocated.append(fd)
        return fd

    def close(fd):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except FileNotFoundError:
            target = ""
        original_close(fd)
        if close_error and allocated and target == str(root) and not injected:
            injected.append(True)
            raise OSError(errno.EIO, "Owned released directory close error")

    with monkeypatch.context() as patch:
        patch.setattr(DownloadPool, "_unlinked_snapshot", staticmethod(allocate))
        patch.setattr(os, "close", close)
        if close_error:
            with pytest.raises(OSError):
                pool(root).acquire()
        else:
            owner = pool(root).acquire()
            owner.close()
    request.node.user_properties.extend([("allocation_completed", len(allocated) == 1), ("close_failure_injected", bool(injected)), ("no_owned_descriptors", not open_owned(root))])
    assert len(allocated) == 1 and bool(injected) == close_error and not open_owned(root)
    retry = pool(root).acquire()
    retry.close()


@pytest.mark.parametrize("which", ["snapshot", "slot"])
def test_released_close_error_does_not_leak_slot_or_close_reused_number(tmp_path, monkeypatch, which):
    root = tmp_path / "transfers"
    owner = pool(root).acquire()
    fault = owner._fd if which == "snapshot" else owner._slot
    original = os.close
    injected = []

    def close(fd):
        original(fd)
        if fd == fault and not injected:
            injected.append(True)
            raise OSError(errno.EIO, "Owned descriptor released before close error")

    with monkeypatch.context() as patch:
        patch.setattr(os, "close", close)
        with pytest.raises(OSError):
            owner.close()
    opened = [os.open(tmp_path / f"reused-{number}", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600) for number in range(3)]
    try:
        assert fault in opened, "Fixture must actually reuse the released descriptor number"
        owner.close()
        assert all(os.fstat(fd) for fd in opened)
        retry = pool(root).acquire()
        retry.close()
    finally:
        for fd in opened:
            original(fd)
    assert injected and not open_owned(root)


def test_failed_fallback_unlink_cannot_leave_archive_bytes(tmp_path, monkeypatch):
    root = tmp_path / "transfers"
    original = os.unlink
    force_named_fallback(monkeypatch)

    def unlink(name, *args, **kwargs):
        if str(name).startswith(".empty-transfer-"):
            raise OSError(errno.EIO, "Owned unlink refusal")
        return original(name, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", unlink)
        with pytest.raises(OSError):
            pool(root).acquire()
    remaining = list(root.glob(".empty-transfer-*"))
    assert len(remaining) == 1 and remaining[0].stat().st_size == 0
    assert remaining[0].stat().st_mode & 0o777 == 0o600
    assert not open_owned(root)
    remaining[0].unlink()
    retry = pool(root).acquire()
    retry.close()

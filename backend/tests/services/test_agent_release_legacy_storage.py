# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Native, owned local-file compatibility cases; no DB/auth/HTTP acceptance."""

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from uuid import uuid4

import pytest

from app.core.agent_release_storage_root import ReleaseStorageUnavailable
from app.services import agent_release_legacy_storage as storage

REFUSAL = (storage.LegacyReleaseUnavailable, ReleaseStorageUnavailable, OSError)


@pytest.fixture
def legacy(tmp_path):
    root = tmp_path / "releases"
    root.mkdir(mode=0o755)
    data = b"owned original release\n" * 70
    expected = storage.LegacyReleaseFile(uuid4(), "free-sdn_linux+1.bin", hashlib.sha256(data).hexdigest(), len(data))
    path = root / (str(expected.release_id) + "-" + expected.filename)
    path.write_bytes(data)
    path.chmod(0o644)
    # A real release was written long before anyone reads it. The lease notices a
    # change by timestamps, which the kernel advances once per tick (1 to 4 ms),
    # so a change within the tick of the fixture's own writes is invisible: on
    # Linux 6.8 a second write left the directory's state unchanged 1,975 times
    # in 2,000.
    written = time.time_ns() - 60 * 10**9
    os.utime(path, ns=(written, written))
    os.utime(root, ns=(written, written))
    return root, expected, path, data


def descriptors():
    return set(os.listdir("/proc/self/fd"))


@pytest.mark.parametrize("mode", (0o600, 0o644, 0o700, 0o755))
@pytest.mark.parametrize("filename", (True, False))
def test_real_legacy_modes_and_null_filename_remain_readable_without_adoption(legacy, mode, filename):
    root, expected, path, data = legacy
    path.chmod(mode)
    requested = expected if filename else replace(expected, filename=None)
    before = path.stat()
    old = descriptors()
    with storage.LegacyReleaseLease.acquire(str(root), requested) as lease:
        assert lease.verified.filename == expected.filename
        assert lease.read(0, len(data)) == data
        assert lease.read(7, 13) == data[7:20]
        assert lease.read(len(data), 1) == b""
    assert descriptors() == old
    assert list(root.iterdir()) == [path]
    after = path.stat()
    assert (before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns,
    )
    assert path.read_bytes() == data


@pytest.mark.parametrize("size", (0, 1, 1048577))
def test_exact_empty_and_chunk_boundary_content(legacy, size):
    root, expected, path, _ = legacy
    data = b"x" * size
    path.write_bytes(data)
    expected = replace(expected, size=size, sha256=hashlib.sha256(data).hexdigest().upper())
    with storage.LegacyReleaseLease.acquire(str(root), expected) as lease:
        read = b"".join(lease.read(offset, 1048576) for offset in range(0, size, 1048576))
        assert read == data
        assert lease.read(size, 1) == b""


@pytest.mark.parametrize("field,value", (
    ("filename", "../outside"), ("filename", "a/b"), ("filename", "a\\b"),
    ("filename", "."), ("filename", ".."), ("filename", ""), ("filename", "a\x00b"),
    ("filename", "x" * 129), ("filename", "☃"), ("filename", 42),
    ("size", True), ("size", -1), ("size", 1.0), ("size", 524288001),
    ("sha256", "x" * 64), ("sha256", "a" * 63), ("sha256", None),
    ("release_id", "not-a-uuid"),
))
def test_invalid_metadata_is_refused_before_file_access(legacy, field, value):
    root, expected, path, data = legacy
    old = descriptors()
    with pytest.raises(storage.LegacyReleaseUnavailable):
        replace(expected, **{field: value})
    assert descriptors() == old and path.read_bytes() == data
    assert list(root.iterdir()) == [path]


@pytest.mark.parametrize("kind", (
    "root_symlink", "ancestor_symlink", "root_writable", "ancestor_writable",
    "file_symlink", "file_hardlink", "file_writable", "file_directory", "fifo",
    "missing", "checksum", "size", "ambiguous", "null_invalid_candidate",
))
def test_unsafe_or_unknown_old_file_is_preserved_and_refused(legacy, kind):
    root, expected, path, data = legacy
    acquisition_root = root
    if kind == "root_symlink":
        acquisition_root = root.parent / "link"
        acquisition_root.symlink_to(root, target_is_directory=True)
    elif kind == "ancestor_symlink":
        alias = root.parent.parent / (root.parent.name + "-link")
        alias.symlink_to(root.parent, target_is_directory=True)
        acquisition_root = alias / root.name
    elif kind == "root_writable":
        root.chmod(0o777)
    elif kind == "ancestor_writable":
        root.parent.chmod(0o777)
    elif kind in ("file_symlink", "file_hardlink"):
        outside = root.parent / "outside"
        outside.write_bytes(data)
        path.unlink()
        if kind == "file_symlink":
            path.symlink_to(outside)
        else:
            path.hardlink_to(outside)
    elif kind == "file_writable":
        path.chmod(0o666)
    elif kind in ("file_directory", "fifo", "missing"):
        path.unlink()
        if kind == "file_directory":
            path.mkdir()
        elif kind == "fifo":
            os.mkfifo(path)
    elif kind == "checksum":
        expected = replace(expected, sha256="0" * 64)
    elif kind == "size":
        expected = replace(expected, size=len(data) + 1)
    else:
        expected = replace(expected, filename=None)
        suffix = "other.bin" if kind == "ambiguous" else "invalid name"
        (root / (str(expected.release_id) + "-" + suffix)).write_bytes(data)
    original_entries = {p.name: (p.lstat().st_mode, p.lstat().st_ino) for p in root.iterdir()}
    old = descriptors()
    with pytest.raises(REFUSAL):
        storage.LegacyReleaseLease.acquire(str(acquisition_root), expected)
    assert descriptors() == old
    assert original_entries == {p.name: (p.lstat().st_mode, p.lstat().st_ino) for p in root.iterdir()}
    if kind not in ("file_directory", "fifo", "missing"):
        assert path.read_bytes() == data


def test_null_filename_scan_is_bounded_and_explicit_filename_does_not_scan(legacy):
    root, expected, path, data = legacy
    for i in range(10000):
        (root / f"unrelated-{i}").touch()
    old = descriptors()
    with pytest.raises(storage.LegacyReleaseUnavailable, match="scan"):
        storage.LegacyReleaseLease.acquire(str(root), replace(expected, filename=None))
    assert descriptors() == old
    with storage.LegacyReleaseLease.acquire(str(root), expected) as lease:
        assert lease.read(0, len(data)) == data
    assert len(list(root.iterdir())) == 10001 and path.read_bytes() == data


@pytest.mark.parametrize("change", (
    "replace_file", "unlink_file", "rewrite_file", "change_mode", "replace_root",
    "root_symlink", "root_writable", "null_selection_change",
))
def test_retained_descriptor_refuses_changed_path_or_contents(legacy, change):
    root, expected, path, data = legacy
    if change == "null_selection_change":
        expected = replace(expected, filename=None)
    old = descriptors()
    with storage.LegacyReleaseLease.acquire(str(root), expected) as lease:
        assert lease.read(0, 1) == data[:1]
        if change == "replace_file":
            path.unlink()
            path.write_bytes(data)
        elif change == "unlink_file":
            path.unlink()
        elif change == "rewrite_file":
            path.write_bytes(b"y" * len(data))
        elif change == "change_mode":
            path.chmod(0o666)
        elif change in ("replace_root", "root_symlink"):
            moved = root.with_name("retained-root")
            root.rename(moved)
            if change == "replace_root":
                root.mkdir()
                (root / path.name).write_bytes(data)
            else:
                root.symlink_to(moved, target_is_directory=True)
        elif change == "root_writable":
            root.chmod(0o777)
        else:
            (root / "unrelated-new-upload").write_bytes(b"new")
        with pytest.raises(REFUSAL):
            lease.read(0, 1)
        with pytest.raises(storage.LegacyReleaseUnavailable):
            lease.read(0, 1)
    assert descriptors() == old


@pytest.mark.parametrize("stage", ("verification", "delivery"))
def test_change_after_real_pread_cannot_escape_as_verified_bytes(legacy, monkeypatch, stage):
    root, expected, path, data = legacy
    old = descriptors()
    actual = os.pread
    changed = False

    def change_after_read(fd, count, offset):
        nonlocal changed
        value = actual(fd, count, offset)
        if not changed and count:
            changed = True
            path.write_bytes(b"z" * len(data))
        return value

    if stage == "verification":
        monkeypatch.setattr(storage.os, "pread", change_after_read)
        with pytest.raises(REFUSAL):
            storage.LegacyReleaseLease.acquire(str(root), expected)
    else:
        with storage.LegacyReleaseLease.acquire(str(root), expected) as lease:
            monkeypatch.setattr(storage.os, "pread", change_after_read)
            with pytest.raises(REFUSAL):
                lease.read(0, len(data))
    assert changed and descriptors() == old and path.read_bytes() == b"z" * len(data)


@pytest.mark.parametrize("offset,size", ((-1, 1), (0, 0), (0, 1048577), (True, 1), (0, True), (999999, 1)))
def test_invalid_reads_poison_the_lifetime(legacy, offset, size):
    root, expected, _, _ = legacy
    with storage.LegacyReleaseLease.acquire(str(root), expected) as lease:
        with pytest.raises(storage.LegacyReleaseUnavailable):
            lease.read(offset, size)
        with pytest.raises(storage.LegacyReleaseUnavailable):
            lease.read(0, 1)


def test_deadline_and_closed_lifetime_are_not_reusable(legacy, monkeypatch):
    root, expected, _, _ = legacy
    lease = storage.LegacyReleaseLease.acquire(str(root), expected)
    monkeypatch.setattr(storage.time, "monotonic", lambda: lease._deadline)
    with pytest.raises(storage.LegacyReleaseUnavailable):
        lease.read(0, 1)
    lease.close()
    lease.close()
    with pytest.raises(storage.LegacyReleaseUnavailable):
        lease.read(0, 1)


def test_admission_slots_and_descriptors_return_after_close_or_refusal(legacy):
    root, expected, _, data = legacy
    old = descriptors()
    leases = [storage.LegacyReleaseLease.acquire(str(root), expected) for _ in range(8)]
    try:
        with pytest.raises(storage.LegacyReleaseUnavailable, match="busy"):
            storage.LegacyReleaseLease.acquire(str(root), expected)
        leases.pop().close()
        with storage.LegacyReleaseLease.acquire(str(root), expected) as lease:
            assert lease.read(0, len(data)) == data
    finally:
        for lease in leases:
            lease.close()
    for _ in range(9):
        with pytest.raises(storage.LegacyReleaseUnavailable):
            storage.LegacyReleaseLease.acquire(str(root), replace(expected, sha256="0" * 64))
    with storage.LegacyReleaseLease.acquire(str(root), expected):
        pass
    assert descriptors() == old


def test_real_child_writer_lock_is_excluded_until_reader_closes(legacy):
    root, expected, path, data = legacy
    child = """import fcntl,json,os,sys
fd=os.open(sys.argv[1],os.O_RDWR|os.O_NOFOLLOW)
try:
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locked=True
    except BlockingIOError:locked=False
    print(json.dumps({'locked':locked}))
finally:os.close(fd)
"""

    def writer():
        process = subprocess.run([sys.executable, "-B", "-c", child, str(path)],
                                 check=True, capture_output=True, timeout=10)
        return json.loads(process.stdout)["locked"]

    old = descriptors()
    with storage.LegacyReleaseLease.acquire(str(root), expected) as lease:
        assert writer() is False
        assert lease.read(0, len(data)) == data
    assert writer() is True
    assert descriptors() == old and path.read_bytes() == data

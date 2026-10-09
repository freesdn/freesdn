# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Native local filesystem/process contracts; no Docker or network-FS claim."""

from __future__ import annotations

import json
import os
import select
import stat
import subprocess
import sys
import time

import pytest

from app.core.agent_release_storage_root import (
    ReleaseStorageUnavailable,
    canonical_release_storage_path,
    initialize_release_storage_root,
)

MARKER = ".freesdn-managed-artifacts-v1"


@pytest.fixture
def location(tmp_path):
    parent = tmp_path / "legacy-releases"
    parent.mkdir(mode=0o700)
    return parent / ".managed-v1"


def snapshot(path):
    result = {}
    for item in sorted(path.rglob("*")):
        value = item.lstat()
        result[str(item.relative_to(path))] = (
            value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
            item.read_bytes() if stat.S_ISREG(value.st_mode) else None,
            os.readlink(item) if stat.S_ISLNK(value.st_mode) else None,
        )
    return result


def test_first_start_and_reopen_preserve_existing_legacy_and_managed_bytes(location):
    legacy = location.parent / "existing-release.bin"
    legacy.write_bytes(b"synthetic existing legacy release")
    legacy.chmod(0o640)
    original = snapshot(location.parent)
    first = initialize_release_storage_root(str(location))
    assert first.created and (first.device, first.inode) == (location.stat().st_dev, location.stat().st_ino)
    assert stat.S_IMODE(location.stat().st_mode) == 0o700
    assert stat.S_IMODE((location / MARKER).stat().st_mode) == 0o600
    payload = location / "existing-owned-artifact"
    payload.mkdir(mode=0o700)
    (payload / "payload").write_bytes(b"synthetic managed bytes")
    before_reopen = snapshot(location.parent)
    again = initialize_release_storage_root(str(location))
    assert not again.created and again.inode == first.inode and again.device == first.device
    assert snapshot(location.parent) == before_reopen
    assert snapshot(location.parent)[legacy.name] == original[legacy.name]


@pytest.mark.parametrize("content", (None, b"legacy data"))
def test_existing_unmarked_directory_is_not_adopted_or_repaired(location, content):
    location.mkdir(mode=0o700)
    if content is not None:
        (location / "old").write_bytes(content)
    before = snapshot(location.parent)
    with pytest.raises(ReleaseStorageUnavailable):
        initialize_release_storage_root(str(location))
    assert snapshot(location.parent) == before


@pytest.mark.parametrize("entry", ("root_symlink", "root_file", "ancestor_symlink"))
def test_paths_never_follow_symlinks_or_replace_non_directories(location, entry):
    external = location.parent / "preserved"
    external.mkdir(mode=0o700)
    (external / "data").write_bytes(b"must not change")
    if entry == "root_symlink":
        location.symlink_to(external, target_is_directory=True)
        target = location
    elif entry == "root_file":
        location.write_bytes(b"not a directory")
        target = location
    else:
        alias = location.parent / "alias"
        alias.symlink_to(external, target_is_directory=True)
        target = alias / ".managed-v1"
    before = snapshot(location.parent)
    with pytest.raises(ReleaseStorageUnavailable):
        initialize_release_storage_root(str(target))
    assert snapshot(location.parent) == before


@pytest.mark.parametrize("mode", (0o750, 0o777, 0o1700, 0o4700))
def test_existing_root_modes_are_not_silently_changed(location, mode):
    initialize_release_storage_root(str(location))
    location.chmod(mode)
    before = snapshot(location.parent)
    with pytest.raises(ReleaseStorageUnavailable):
        initialize_release_storage_root(str(location))
    assert snapshot(location.parent) == before


@pytest.mark.parametrize("entry", (
    "wrong_purpose", "oversized", "empty", "mode", "special_bits",
    "symlink", "hardlink", "fifo", "directory",
))
def test_existing_marker_must_be_exact_and_owned_regular_private_file(location, entry):
    initialize_release_storage_root(str(location))
    marker = location / MARKER
    if entry == "wrong_purpose":
        value = marker.read_bytes().replace(b"freesdn", b"another", 1)
        assert len(value) == marker.stat().st_size
        marker.write_bytes(value)
    elif entry == "oversized":
        marker.write_bytes(marker.read_bytes() + b"x" * 4096)
    elif entry == "empty":
        marker.write_bytes(b"")
    elif entry in ("mode", "special_bits"):
        marker.chmod(0o640 if entry == "mode" else 0o4600)
    elif entry == "hardlink":
        os.link(marker, location / "retained-second-link")
    else:
        retained = location / "retained-marker"
        marker.rename(retained)
        if entry == "symlink":
            marker.symlink_to(retained)
        elif entry == "fifo":
            os.mkfifo(marker, 0o600)
        else:
            marker.mkdir(mode=0o700)
    before = snapshot(location.parent)
    started = time.monotonic()
    with pytest.raises(ReleaseStorageUnavailable):
        initialize_release_storage_root(str(location))
    assert time.monotonic() - started < 2
    assert snapshot(location.parent) == before


@pytest.mark.parametrize("mode", (0o770, 0o777))
def test_untrusted_parent_is_refused_before_any_creation(location, mode):
    location.parent.chmod(mode)
    before = snapshot(location.parent)
    with pytest.raises(ReleaseStorageUnavailable):
        initialize_release_storage_root(str(location))
    assert not location.exists() and snapshot(location.parent) == before


def test_missing_ancestor_is_not_created(location):
    target = location / "parent" / "child"
    with pytest.raises(ReleaseStorageUnavailable):
        initialize_release_storage_root(str(target))
    assert not location.exists()


@pytest.mark.parametrize("value", (
    None, 1, b"/tmp/path", "relative", "/", "/tmp//child", "/tmp/./child",
    "/tmp/../child", "/tmp/child/", "/tmp/nul\0child", "/tmp/" + "x" * 256,
    "/tmp/" + "é" * 128, "/" + "/".join(["a"] * 64), "/tmp/\udcff",
    "/" + "/".join(["x" * 255] * 17),
))
def test_malformed_paths_are_refused_without_normalization(value):
    with pytest.raises(ReleaseStorageUnavailable):
        canonical_release_storage_path(value)


@pytest.mark.parametrize("value", (True, -1, 5.1, float("nan"), float("inf"), "1", None))
def test_lock_wait_cannot_disable_bounds(location, value):
    with pytest.raises(ReleaseStorageUnavailable):
        initialize_release_storage_root(str(location), lock_seconds=value)
    assert not location.exists()


def test_refusals_and_success_do_not_leak_descriptors(location):
    before = set(os.listdir("/proc/self/fd"))
    for _ in range(40):
        initialize_release_storage_root(str(location))
    (location / MARKER).unlink()
    for _ in range(40):
        with pytest.raises(ReleaseStorageUnavailable):
            initialize_release_storage_root(str(location))
    assert set(os.listdir("/proc/self/fd")) == before


def test_two_native_processes_initialize_one_root_without_marker_race(location):
    program = """
import json,sys,time
from pathlib import Path
from app.core.agent_release_storage_root import initialize_release_storage_root
root,ready,go=sys.argv[1:]
Path(ready).write_text('ready')
deadline=time.monotonic()+10
while not Path(go).exists():
    if time.monotonic()>deadline: raise RuntimeError('start barrier expired')
    time.sleep(.01)
result=initialize_release_storage_root(root)
print(json.dumps({'created':result.created,'inode':result.inode,'device':result.device}))
"""
    gate = location.parent / "start"
    ready = [location.parent / f"ready-{number}" for number in range(2)]
    children = []
    try:
        for path in ready:
            children.append(subprocess.Popen(
                [sys.executable, "-B", "-c", program, str(location), str(path), str(gate)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ))
        deadline = time.monotonic() + 10
        while not all(path.exists() for path in ready):
            assert all(child.poll() is None for child in children)
            assert time.monotonic() < deadline
            time.sleep(0.01)
        gate.write_text("start")
        outcomes = []
        for child in children:
            output, error = child.communicate(timeout=10)
            assert child.returncode == 0, error
            outcomes.append(json.loads(output))
        assert sorted(item["created"] for item in outcomes) == [False, True]
        assert {(item["inode"], item["device"]) for item in outcomes} == {
            (location.stat().st_ino, location.stat().st_dev),
        }
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)


def test_real_parent_lock_contention_is_bounded_and_retry_preserves_data(location):
    program = """
import fcntl,os,sys
descriptor=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY)
fcntl.flock(descriptor,fcntl.LOCK_EX)
print('locked',flush=True)
sys.stdin.buffer.read(1)
os.close(descriptor)
"""
    child = subprocess.Popen(
        [sys.executable, "-B", "-c", program, str(location.parent)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert select.select([child.stdout], [], [], 5)[0], "holder did not become ready"
        assert child.stdout.readline() == "locked\n"
        before = snapshot(location.parent)
        started = time.monotonic()
        with pytest.raises(ReleaseStorageUnavailable, match="busy"):
            initialize_release_storage_root(str(location), lock_seconds=0.15)
        assert 0.14 <= time.monotonic() - started < 2
        assert not location.exists() and snapshot(location.parent) == before
        child.communicate(input="x", timeout=5)
        assert child.returncode == 0
        result = initialize_release_storage_root(str(location))
        assert result.created
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)

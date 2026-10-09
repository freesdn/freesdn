# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real filesystem checks for private handoff files and hostile pre-existing paths."""

import os
import stat
from pathlib import Path

import pytest

from app.core.private_files import (
    PrivateFileError,
    open_private,
    private_directory,
    read_private,
    touch_private,
    unlink_private,
    write_private,
)


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_restrictive_creation_even_with_permissive_umask(tmp_path):
    old = os.umask(0)
    try:
        path = tmp_path / "private" / "new.bin"
        write_private(path, b"sensitive fixture")
    finally:
        os.umask(old)
    assert mode(path.parent) == 0o700 and mode(path) == 0o600
    assert read_private(path, 100) == b"sensitive fixture"


def test_existing_safe_owner_directory_is_tightened(tmp_path):
    root = tmp_path / "legacy"
    root.mkdir(mode=0o755)
    path = root / "data"
    path.write_bytes(b"legacy")
    path.chmod(0o644)
    assert read_private(path, 100) == b"legacy"
    assert mode(root) == 0o700 and mode(path) == 0o600


@pytest.mark.parametrize("permission", [0o777, 0o775, 0o702])
def test_unsafe_directory_is_not_silently_adopted(tmp_path, permission):
    root = tmp_path / "unsafe"
    root.mkdir()
    root.chmod(permission)
    with pytest.raises(PrivateFileError):
        write_private(root / "data", b"no")
    assert mode(root) == permission and not (root / "data").exists()


@pytest.mark.parametrize("level", ["leaf", "ancestor"])
def test_symlink_directory_cannot_redirect_writes(tmp_path, level):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "link"
    link.symlink_to(outside, target_is_directory=True)
    target = link / "data" if level == "leaf" else link / "nested" / "data"
    with pytest.raises(OSError):
        write_private(target, b"no")
    assert list(outside.iterdir()) == []


def test_file_create_never_overwrites_existing_or_link_target(tmp_path):
    path = tmp_path / "original"
    write_private(path, b"keep")
    link = tmp_path / "link"
    link.symlink_to(path)
    for destination in (path, link):
        with pytest.raises(FileExistsError):
            write_private(destination, b"overwrite")
    assert path.read_bytes() == b"keep"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory", "world_writable"])
def test_reader_refuses_unsafe_file_types_and_aliases(tmp_path, kind):
    target = tmp_path / "target"
    target.write_bytes(b"keep")
    target.chmod(0o600)
    path = tmp_path / "input"
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, path)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"no")
        path.chmod(0o666)
    with pytest.raises(OSError):
        read_private(path, 100)
    assert target.read_bytes() == b"keep"


def test_oversize_read_is_rejected(tmp_path):
    path = tmp_path / "data"
    write_private(path, b"12345")
    with pytest.raises(PrivateFileError):
        read_private(path, 4)


def test_open_descriptor_survives_path_replacement_without_reading_replacement(tmp_path):
    path = tmp_path / "data"
    write_private(path, b"original")
    with open_private(path, 100) as handle:
        path.rename(tmp_path / "old")
        path.symlink_to("/etc/passwd")
        assert handle.read() == b"original"


def test_unlink_removes_link_without_touching_target(tmp_path):
    target = tmp_path / "keep"
    write_private(target, b"keep")
    link = tmp_path / "link"
    link.symlink_to(target)
    unlink_private(link)
    assert target.read_bytes() == b"keep" and not link.is_symlink()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_liveness_marker_does_not_modify_foreign_target(tmp_path, kind):
    target = tmp_path / "keep"
    write_private(target, b"keep")
    before = target.stat().st_mtime_ns
    path = tmp_path / "alive"
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, path)
    else:
        os.mkfifo(path)
    with pytest.raises(OSError):
        touch_private(path)
    assert target.read_bytes() == b"keep" and target.stat().st_mtime_ns == before


def test_heartbeat_is_private_and_does_not_truncate_existing_content(tmp_path):
    path = tmp_path / "alive"
    touch_private(path)
    assert mode(path) == 0o600
    path.write_bytes(b"alive")
    touch_private(path)
    assert path.read_bytes() == b"alive"


def test_parent_traversal_and_filesystem_root_are_refused(tmp_path):
    for path in [tmp_path / ".." / "unsafe", Path("/")]:
        with pytest.raises(PrivateFileError), private_directory(path):
            pass


def test_heartbeat_refuses_world_writable_existing_marker(tmp_path):
    path = tmp_path / "alive"
    path.write_bytes(b"keep")
    path.chmod(0o666)
    before = path.stat().st_mtime_ns
    with pytest.raises(PrivateFileError):
        touch_private(path)
    assert mode(path) == 0o666 and path.stat().st_mtime_ns == before

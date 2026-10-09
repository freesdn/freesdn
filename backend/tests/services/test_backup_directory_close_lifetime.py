# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private descriptor ownership checks, not a shipping-source defect baseline."""

import errno
import os
from pathlib import Path

import pytest

from app.core.backup_files import BackupFiles


@pytest.mark.parametrize("operation", ["save", "load", "delete", "exists", "get_size"])
def test_normal_nested_operation_keeps_its_original_contract(tmp_path, operation):
    child = tmp_path / "owned-child"
    child.mkdir()
    archive = child / "archive.fsdn"
    payload = b"owned original"
    archive.write_bytes(payload)
    files = BackupFiles(tmp_path, 32)
    if operation == "save":
        assert files.save("owned-child/archive.fsdn", b"owned replacement") == "owned-child/archive.fsdn"
        assert archive.read_bytes() == b"owned replacement"
    elif operation == "load":
        assert files.load("owned-child/archive.fsdn") == payload
    elif operation == "delete":
        assert files.delete("owned-child/archive.fsdn") is True
        assert not archive.exists()
    elif operation == "exists":
        assert files.exists("owned-child/archive.fsdn") is True
    else:
        assert files.get_size("owned-child/archive.fsdn") == len(payload)


@pytest.mark.parametrize("operation", ["save", "load", "delete", "exists", "get_size"])
def test_traversal_close_error_does_not_close_reused_number_or_leak_child(
    tmp_path, monkeypatch, request, operation,
):
    child = tmp_path / "owned-child"
    child.mkdir()
    archive = child / "archive.fsdn"
    archive.write_bytes(b"owned original")
    real_open, real_close = os.open, os.close
    opened = {}
    triggered = []
    closed = []
    error_close_index = []
    sentinel = []
    observation = {}

    def open_descriptor(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        info = os.fstat(fd)
        opened[fd] = (info.st_dev, info.st_ino)
        return fd

    def close_descriptor(fd):
        target = Path(os.readlink(f"/proc/self/fd/{fd}"))
        closed.append(fd)
        real_close(fd)
        if target == tmp_path and not triggered:
            triggered.append(fd)
            error_close_index.append(len(closed) - 1)
            # Simulate another user of a released descriptor number immediately
            # after a Linux post-close I/O error. The operation must not retry it.
            sentinel.append(real_open("/dev/null", os.O_RDONLY | os.O_CLOEXEC))
            raise OSError(errno.EIO, "owned traversal post-close error")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "open", open_descriptor)
            patch.setattr(os, "close", close_descriptor)
            with pytest.raises(OSError) as error:
                files = BackupFiles(tmp_path, 32)
                if operation == "save":
                    files.save("owned-child/archive.fsdn", b"owned replacement")
                else:
                    getattr(files, operation)("owned-child/archive.fsdn")
        live = {}
        for fd, identity in opened.items():
            try:
                info = os.fstat(fd)
            except OSError as exc:
                assert exc.errno == errno.EBADF
                continue
            if (info.st_dev, info.st_ino) == identity:
                live[fd] = identity
        sentinel_live = False
        if sentinel:
            try:
                sentinel_live = Path(os.readlink(f"/proc/self/fd/{sentinel[0]}")) == Path("/dev/null")
            except FileNotFoundError:
                pass
        observation = {
            "injected_close_error_count": len(triggered),
            "descriptor_number_reused": bool(sentinel and triggered and sentinel[0] == triggered[0]),
            "released_number_closed_once": bool(triggered) and closed[error_close_index[0]:].count(triggered[0]) == 1,
            "sentinel_still_open": sentinel_live,
            "owned_descriptor_leaks": len(live),
            "original_errno": error.value.errno,
            "archive_unchanged": archive.read_bytes() == b"owned original",
        }
        request.node.user_properties.extend(observation.items())
        assert observation["injected_close_error_count"] == 1
        assert observation["descriptor_number_reused"], "Owned fixture must demonstrate actual number reuse"
        assert observation["released_number_closed_once"] and observation["sentinel_still_open"]
        assert observation["owned_descriptor_leaks"] == 0
        assert observation["original_errno"] == errno.EIO and observation["archive_unchanged"]
    finally:
        # Preserve the result first, then clean only our descriptors that still
        # reference the exact opened inode or our owned /dev/null sentinel.
        for fd, identity in opened.items():
            try:
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == identity:
                    real_close(fd)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
        if sentinel:
            try:
                if Path(os.readlink(f"/proc/self/fd/{sentinel[0]}")) == Path("/dev/null"):
                    real_close(sentinel[0])
            except FileNotFoundError:
                pass

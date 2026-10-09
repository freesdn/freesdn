# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Private new-component checks; these are not an unchanged-source baseline."""

import errno
import os
import stat
import subprocess
import sys

import pytest

from app.core.backup_files import BackupFileError, BackupFiles


@pytest.mark.parametrize("failure", ["file_fsync", "directory_fsync", "replace", "close"])
def test_owned_write_failure_preserves_previous_or_published_file_and_closes_descriptors(
    tmp_path, monkeypatch, request, failure,
):
    target = tmp_path / "archive.fsdn"
    previous, replacement = b"owned previous", b"owned replacement"
    target.write_bytes(previous)
    target.chmod(0o600)
    files = BackupFiles(tmp_path, 32)
    real_fsync, real_replace, real_close = os.fsync, os.replace, os.close
    triggered = []
    closed_before = set(os.listdir("/proc/self/fd"))

    def fsync(fd):
        kind = "directory_fsync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file_fsync"
        if failure == kind:
            triggered.append(kind)
            raise OSError(errno.EIO, "owned injected fsync failure")
        return real_fsync(fd)

    def replace(*args, **kwargs):
        if failure == "replace":
            triggered.append(failure)
            raise OSError(errno.EIO, "owned injected replace failure")
        return real_replace(*args, **kwargs)

    def close(fd):
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
        real_close(fd)
        if failure == "close" and regular and not triggered:
            triggered.append(failure)
            # POSIX close errors cannot safely be handled by closing the same
            # numerical descriptor again; Linux may already have released it.
            raise OSError(errno.EIO, "owned post-close error")

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fsync)
        patch.setattr(os, "replace", replace)
        patch.setattr(os, "close", close)
        with pytest.raises(OSError):
            files.save(target.name, replacement)
    actual = target.read_bytes()
    expected = replacement if failure == "directory_fsync" else previous
    temporary = list(tmp_path.glob(".freesdn-archive-*.tmp"))
    closed_after = set(os.listdir("/proc/self/fd"))
    request.node.user_properties.extend([
        ("actual_failure_stage", triggered), ("expected_archive_preserved", actual == expected),
        ("owned_temporaries_removed", not temporary), ("no_descriptor_leak", closed_before == closed_after),
        ("uncertain_durability_is_not_rollback", failure == "directory_fsync"),
    ])
    assert triggered == [failure]
    assert actual == expected and not temporary and closed_before == closed_after


@pytest.mark.parametrize("write_shape", ["partial", "zero", "error_after_partial"])
def test_bounded_write_handles_partial_progress_without_publishing_partial_bytes(
    tmp_path, monkeypatch, request, write_shape,
):
    real_write = os.write
    calls = []
    payload = b"owned full archive buffer"

    def write(fd, data):
        calls.append(len(data))
        if write_shape == "zero":
            return 0
        if write_shape == "error_after_partial" and len(calls) > 1:
            raise OSError(errno.ENOSPC, "owned write-capacity failure")
        return real_write(fd, data[:3])

    files = BackupFiles(tmp_path, 32)
    with monkeypatch.context() as patch:
        patch.setattr(os, "write", write)
        if write_shape == "partial":
            assert files.save("archive.fsdn", payload) == "archive.fsdn"
        else:
            with pytest.raises(OSError):
                files.save("archive.fsdn", payload)
    target = tmp_path / "archive.fsdn"
    exact = target.exists() and target.read_bytes() == payload
    request.node.user_properties.extend([
        ("write_calls", len(calls)), ("published_exact", exact),
        ("partial_not_published", write_shape == "partial" or not target.exists()),
        ("no_owned_temporary", not list(tmp_path.glob(".freesdn-archive-*.tmp"))),
    ])
    assert exact if write_shape == "partial" else not target.exists()
    assert not list(tmp_path.glob(".freesdn-archive-*.tmp"))


def test_growth_after_initial_stat_is_bounded_on_the_open_descriptor(tmp_path, monkeypatch, request):
    target = tmp_path / "growing.fsdn"
    target.write_bytes(b"x" * 31)
    real_read = os.read
    calls = []

    def read(fd, amount):
        result = real_read(fd, amount)
        calls.append((amount, len(result)))
        if len(calls) == 1:
            with target.open("ab") as handle:
                handle.write(b"more than the remaining byte")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(os, "read", read)
        with pytest.raises(BackupFileError):
            BackupFiles(tmp_path, 32).load(target.name)
    request.node.user_properties.extend([
        ("actual_read_calls", calls), ("growth_committed", target.stat().st_size > 32),
        ("read_bytes_at_most_limit_plus_one", sum(length for _, length in calls) <= 33),
    ])
    assert len(calls) >= 2 and sum(length for _, length in calls) <= 33
    assert target.stat().st_size > 32


@pytest.mark.parametrize("operation", ["load", "delete", "exists", "get_size"])
def test_fifo_is_refused_without_open_block_or_removal(tmp_path, request, operation):
    target = tmp_path / "owned.fifo"
    os.mkfifo(target, mode=0o600)
    # A regression must fail within a bounded child process, not hang pytest.
    code = (
        "import sys; from pathlib import Path; "
        "from app.core.backup_files import BackupFiles, BackupFileError\n"
        "try: getattr(BackupFiles(Path(sys.argv[1]),32),sys.argv[2])('owned.fifo')\n"
        "except BackupFileError: print('controlled-refusal')\n"
        "else: raise SystemExit(3)\n"
    )
    result = subprocess.run([sys.executable, "-B", "-c", code, str(tmp_path), operation],
                            capture_output=True, text=True, timeout=5, check=False)
    still_fifo = stat.S_ISFIFO(target.lstat().st_mode)
    request.node.user_properties.extend([
        ("child_exit", result.returncode), ("owned_fifo_preserved", still_fifo),
        ("controlled_refusal", result.stdout.strip() == "controlled-refusal"),
    ])
    assert result.returncode == 0 and result.stdout.strip() == "controlled-refusal"
    assert still_fifo


@pytest.mark.parametrize("operation", ["load", "delete", "exists", "get_size"])
@pytest.mark.parametrize("path", ["../outside.fsdn", "/absolute.fsdn", "dir/../outside.fsdn", "dir//file.fsdn"])
def test_noncanonical_locator_is_refused_before_access(tmp_path, operation, path):
    with pytest.raises(BackupFileError):
        getattr(BackupFiles(tmp_path, 32), operation)(path)
    assert not any(tmp_path.iterdir())

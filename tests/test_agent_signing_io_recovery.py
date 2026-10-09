"""Unrun real-I/O failure/recovery probes; not power-loss or deployment proof."""
from __future__ import annotations

import errno
import os

import pytest
from test_agent_signing_boundaries import IDENTITY_NAME, _complete_snapshot, _mark
from test_agent_signing_identity import (
    OPERATIONS,
    PRIVATE_NAME,
    PUBLIC_NAME,
    _invoke,
    _new_pair,
    _verify,
    _write,
)
from test_agent_signing_identity import signer as signer


def _same_file(fd, path):
    try:
        opened, named = os.fstat(fd), path.lstat()
    except FileNotFoundError:
        return False
    return (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)


def _assert_value(operation, public, value):
    if operation == "public":
        assert value == public
    else:
        _verify(public, value)


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("depth", (0, 1, 2))
def test_existing_directory_after_failed_sync_is_not_treated_as_durable(
    signer, monkeypatch, record_property, operation, depth,
):
    module, owned = signer
    levels = [owned, owned / "level1", owned / "level1/level2"]
    root = owned / "level1/level2/keys"
    target_parent = levels[depth]
    target_child = (*levels[1:], root)[depth]
    monkeypatch.setenv("FREESDN_SIGNING_KEY_DIR", str(root))
    monkeypatch.setenv("FREESDN_AGENT_RELEASE_DIR", str(root))
    real_fsync = os.fsync
    events = []

    def fault(fd):
        if _same_file(fd, target_parent):
            events.append(target_child.is_dir())
            raise OSError(errno.EIO, "owned parent synchronization fault")
        return real_fsync(fd)

    with monkeypatch.context() as scope:
        scope.setattr(os, "fsync", fault)
        first_value, first_error = _invoke(module, operation)
        first_child_exists = target_child.is_dir()
        second_value, second_error = _invoke(module, operation)
        failed_state = _complete_snapshot(root)
    # Capture both refusals and the independent recovery before assertions. A
    # baseline that skips the second parent sync may actually accept the key.
    final_value, final_error = _invoke(module, operation)
    final_state = _complete_snapshot(root)
    public = (root / PUBLIC_NAME).read_bytes()
    record_property("owned_parent_faults", len(events))
    record_property("created_child_survived_first_refusal", first_child_exists)
    record_property("second_call_refused", second_error is not None)
    record_property("recovery_accepted", final_error is None)
    assert first_error is not None and first_value is None
    assert first_child_exists and events == [True, True]
    assert second_error is not None and second_value is None
    assert all(value is None for value in failed_state.values())
    assert final_error is None and final_state[PRIVATE_NAME] is not None
    _assert_value(operation, public, final_value)


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("existing_pair", (False, True))
def test_parent_sync_refusal_releases_every_opened_descriptor(
    signer, monkeypatch, record_property, operation, existing_pair,
):
    module, root = signer
    if existing_pair:
        private, public = _new_pair()
        _write(root, private, public)
        _mark(root, public)
    before = _complete_snapshot(root)
    real_open, real_close, real_fsync = os.open, os.close, os.fsync
    pending = set()
    counts = {"opens": 0, "closes": 0, "faults": 0}

    def opened(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        assert fd not in pending
        pending.add(fd)
        counts["opens"] += 1
        return fd

    def closed(fd):
        real_close(fd)
        if fd in pending:
            pending.remove(fd)
            counts["closes"] += 1

    def fault(fd):
        if _same_file(fd, root.parent):
            counts["faults"] += 1
            raise OSError(errno.EIO, "owned parent synchronization fault")
        return real_fsync(fd)

    with monkeypatch.context() as scope:
        scope.setattr(os, "open", opened)
        scope.setattr(os, "close", closed)
        scope.setattr(os, "fsync", fault)
        value, error = _invoke(module, operation)
        leaked = tuple(pending)
    # Preserve the leak observation before fixture cleanup. The source contract
    # must close both the current parent and a newly acquired child on refusal.
    for fd in leaked:
        real_close(fd)
    after = _complete_snapshot(root)
    for name, observed in counts.items():
        record_property(name, observed)
    record_property("opened_descriptors_left_live", len(leaked))
    assert error is not None and value is None and counts["faults"] == 1
    assert counts["opens"] > 0 and counts["opens"] == counts["closes"]
    assert not leaked and before == after
    recovery, recovery_error = _invoke(module, operation)
    assert recovery_error is None
    _assert_value(operation, (root / PUBLIC_NAME).read_bytes(), recovery)


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize("fault_mode", ("short_reads", "early_eof", "read_error", "close_error"))
def test_existing_key_io_failure_preserves_material_and_allows_safe_retry(
    signer, monkeypatch, record_property, operation, fault_mode,
):
    module, root = signer
    private, public = _new_pair()
    _write(root, private, public)
    _mark(root, public)
    before = _complete_snapshot(root)
    real_read, real_close = os.read, os.close
    reads = 0
    failed_closes = []
    sentinel = None

    def read(fd, count):
        nonlocal reads
        if not _same_file(fd, root / PRIVATE_NAME):
            return real_read(fd, count)
        reads += 1
        if fault_mode == "early_eof":
            return b""
        if fault_mode == "read_error":
            raise OSError(errno.EIO, "owned read fault")
        return real_read(fd, min(count, 7) if fault_mode == "short_reads" else count)

    def close(fd):
        nonlocal sentinel
        target = _same_file(fd, root / PRIVATE_NAME)
        real_close(fd)
        if fault_mode == "close_error" and target and not failed_closes:
            failed_closes.append(fd)
            # Linux releases the number before reporting late close errors.
            # Reuse it with an independently owned, harmless read descriptor;
            # blindly retrying close could invalidate this unrelated handle.
            sentinel = os.open(root / PUBLIC_NAME, os.O_RDONLY | os.O_CLOEXEC)
            raise OSError(errno.EIO, "owned late close fault")

    with monkeypatch.context() as scope:
        scope.setattr(os, "read", read)
        scope.setattr(os, "close", close)
        value, error = _invoke(module, operation)
        sentinel_live = sentinel is None
        if sentinel is not None:
            try:
                state, named = os.fstat(sentinel), (root / PUBLIC_NAME).stat()
            except OSError:
                sentinel_live = False
            else:
                sentinel_live = (state.st_dev, state.st_ino) == (named.st_dev, named.st_ino)
            if sentinel_live:
                real_close(sentinel)
    after = _complete_snapshot(root)
    retry, retry_error = _invoke(module, operation)
    record_property("target_reads", reads)
    record_property("late_close_errors", len(failed_closes))
    record_property("unrelated_descriptor_preserved", sentinel_live)
    assert before == after and reads > 0
    assert sentinel_live
    if fault_mode == "short_reads":
        assert reads > 2 and error is None
        _assert_value(operation, public, value)
    else:
        assert error is not None and value is None
    if fault_mode == "close_error":
        assert len(failed_closes) == 1 and sentinel == failed_closes[0]
    assert retry_error is None and before == _complete_snapshot(root)
    _assert_value(operation, public, retry)


@pytest.mark.parametrize("target", (PRIVATE_NAME, PUBLIC_NAME, IDENTITY_NAME))
@pytest.mark.parametrize("fault_mode", ("short_writes", "zero_after_partial", "close_error"))
def test_creation_io_retains_partial_failures_and_never_replaces_written_private_key(
    signer, monkeypatch, record_property, target, fault_mode,
):
    module, root = signer
    real_write, real_close = os.write, os.close
    counts = {"target_writes": 0, "bytes_written": 0, "late_close_errors": 0}

    def write(fd, data):
        if not _same_file(fd, root / target):
            return real_write(fd, data)
        counts["target_writes"] += 1
        if fault_mode == "zero_after_partial" and counts["bytes_written"]:
            return 0
        chunk = data[:7] if fault_mode in {"short_writes", "zero_after_partial"} else data
        count = real_write(fd, chunk)
        counts["bytes_written"] += count
        return count

    def close(fd):
        hit = _same_file(fd, root / target)
        real_close(fd)
        if fault_mode == "close_error" and hit and not counts["late_close_errors"]:
            counts["late_close_errors"] += 1
            raise OSError(errno.EIO, "owned late close fault")

    with monkeypatch.context() as scope:
        scope.setattr(os, "write", write)
        scope.setattr(os, "close", close)
        value, error = _invoke(module, "manifest")
    first_state = _complete_snapshot(root)
    retry, retry_error = _invoke(module, "manifest")
    after = _complete_snapshot(root)
    for name, observed in counts.items():
        record_property(name, observed)
    assert counts["target_writes"] > 0 and counts["bytes_written"] > 0
    assert first_state[PRIVATE_NAME] is not None
    assert first_state[PRIVATE_NAME] == after[PRIVATE_NAME]
    if fault_mode == "short_writes":
        assert counts["target_writes"] > 1 and error is None and retry_error is None
        _verify((root / PUBLIC_NAME).read_bytes(), value)
        _verify((root / PUBLIC_NAME).read_bytes(), retry)
    elif fault_mode == "zero_after_partial":
        assert error is not None and value is None
        assert retry_error is not None and retry is None and first_state == after
    else:
        assert counts["late_close_errors"] == 1
        assert error is not None and value is None and retry_error is None
        _verify((root / PUBLIC_NAME).read_bytes(), retry)

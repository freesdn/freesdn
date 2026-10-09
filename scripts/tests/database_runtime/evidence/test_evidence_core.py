"""Real private-file publication/fault contracts; no engine or application calls."""

import errno
import json
import os
import signal
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize(
    "seconds",
    [0, -1, True, False, float("nan"), float("inf"), 901, "1", None, 10**1000],
    ids=[
        "zero",
        "negative",
        "true",
        "false",
        "nan",
        "infinite",
        "over-limit",
        "string",
        "none",
        "huge-int",
    ],
)
def test_invalid_work_budget_refuses_before_any_files(evidence, tmp_path, seconds):
    before = len(list(Path("/proc/self/fd").iterdir()))
    with pytest.raises(ValueError):
        evidence.FixtureAttempt(tmp_path / "result.json", work_seconds=seconds)
    assert list(tmp_path.iterdir()) == []
    assert len(list(Path("/proc/self/fd").iterdir())) == before


@pytest.mark.parametrize(
    "kind",
    [
        "file",
        "symlink",
        "dangling",
        "directory",
        "fifo",
        "attempt-directory",
        "attempt-file",
        "attempt-symlink",
    ],
)
def test_existing_report_or_attempt_is_refused_without_descriptor_leak(evidence, tmp_path, kind):
    report = tmp_path / "result.json"
    target = (
        report if not kind.startswith("attempt-") else report.with_name(report.name + ".artifacts")
    )
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"preserve-existing")
    if kind in {"file", "attempt-file"}:
        target.write_bytes(b"previous")
    elif kind in {"symlink", "attempt-symlink"}:
        target.symlink_to(sentinel)
    elif kind == "dangling":
        target.symlink_to(tmp_path / "absent")
    elif kind == "fifo":
        os.mkfifo(target)
    else:
        target.mkdir()
    previous = target.lstat()
    fds = len(list(Path("/proc/self/fd").iterdir()))
    with pytest.raises(OSError):
        evidence.FixtureAttempt(report)
    assert sentinel.read_bytes() == b"preserve-existing"
    assert (target.lstat().st_ino, target.lstat().st_mode) == (previous.st_ino, previous.st_mode)
    assert len(list(Path("/proc/self/fd").iterdir())) == fds


@pytest.mark.parametrize(
    "kind", ["symlink-parent", "symlink-ancestor", "writable-group", "writable-world"]
)
def test_unsafe_parent_refuses_before_attempt_creation(evidence, tmp_path, kind):
    real = tmp_path / "real"
    real.mkdir()
    path = real / "result.json"
    if kind.startswith("symlink"):
        alias = tmp_path / "alias"
        alias.symlink_to(real, target_is_directory=True)
        if kind == "symlink-ancestor":
            (real / "child").mkdir()
            path = alias / "child/result.json"
        else:
            path = alias / "result.json"
    else:
        real.chmod(0o775 if kind == "writable-group" else 0o777)
    fds = len(list(Path("/proc/self/fd").iterdir()))
    with pytest.raises((OSError, ValueError)):
        evidence.FixtureAttempt(path)
    assert not list(tmp_path.rglob("*.artifacts"))
    assert len(list(Path("/proc/self/fd").iterdir())) == fds


@pytest.mark.parametrize(
    "timeout",
    [0, -1, True, float("nan"), float("inf"), 121, "1", 10**1000],
    ids=["zero", "negative", "bool", "nan", "inf", "over-limit", "text", "huge-int"],
)
def test_invalid_command_timeout_is_refused(attempt, timeout):
    with pytest.raises(ValueError):
        attempt.deadline(timeout)


def test_phase_budgets_never_renew_the_whole_fixture(evidence, tmp_path, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(evidence, "time", SimpleNamespace(monotonic=lambda: now[0]))
    item = evidence.FixtureAttempt(tmp_path / "result.json", work_seconds=10)
    try:
        assert item.deadline(120) == 110
        now[0] = 109
        assert item.deadline(120) == 110
        now[0] = 111
        with pytest.raises(TimeoutError):
            item.deadline()
        item.begin_evidence()
        assert item.deadline() == 170
        now[0] = 171
        with pytest.raises(TimeoutError):
            item.deadline()
        item.begin_cleanup()
        assert item.deadline() == 290
        now[0] = 290
        with pytest.raises(TimeoutError):
            item.deadline()
        with pytest.raises(RuntimeError):
            item.begin_evidence()
        with pytest.raises(RuntimeError):
            item.begin_cleanup()
    finally:
        item.close()


def test_normal_outcome_is_private_durable_and_cannot_be_republished(attempt):
    attempt.record("case", name="synthetic passed control")
    attempt.begin_evidence()
    attempt.begin_cleanup()
    report = {"passed": False, "qualification_complete": False}
    attempt.finish(report)
    internal = attempt.path / "outcome.json"
    assert attempt.report.read_bytes() == internal.read_bytes()
    assert attempt.report.stat().st_ino == internal.stat().st_ino
    assert attempt.report.stat().st_mode & 0o777 == 0o600
    previous = attempt.report.read_bytes()
    with pytest.raises(FileExistsError):
        attempt.finish({"passed": True})
    assert attempt.report.read_bytes() == previous


@pytest.mark.parametrize("kind", ["file", "symlink", "directory"])
def test_concurrent_report_publication_is_never_replaced(attempt, kind):
    if kind == "directory":
        attempt.report.mkdir()
    elif kind == "symlink":
        target = attempt.report.parent / "unrelated"
        target.write_bytes(b"keep")
        attempt.report.symlink_to(target)
    else:
        attempt.report.write_bytes(b"keep")
    before = attempt.report.lstat()
    with pytest.raises(FileExistsError):
        attempt.finish({"passed": False})
    assert (attempt.path / "outcome.json").is_file()
    assert attempt.report.lstat().st_ino == before.st_ino
    if kind != "directory":
        assert attempt.report.read_bytes() == b"keep"


@pytest.mark.parametrize("error_code", [errno.EIO, errno.ENOSPC], ids=["EIO", "ENOSPC"])
@pytest.mark.parametrize("partial", [False, True], ids=["before-bytes", "after-partial-write"])
def test_event_write_error_retains_partial_state_and_closes_file(
    attempt, replace_os, error_code, partial
):
    calls = []

    def write(fd, data):
        calls.append(len(data))
        if partial and len(calls) == 1:
            return os.write(fd, data[:17])
        raise OSError(error_code, "injected owned write failure")

    replace_os(write=write)
    fds = len(list(Path("/proc/self/fd").iterdir()))
    with pytest.raises(OSError) as raised:
        attempt.record("plan", resource={"planned_name": "synthetic"})
    assert raised.value.errno == error_code
    assert (attempt.path / "events/000-plan.json").stat().st_size == (17 if partial else 0)
    assert not attempt.report.exists()
    assert len(list(Path("/proc/self/fd").iterdir())) == fds


@pytest.mark.parametrize(
    "phase", ["event-file", "event-directory", "outcome-file", "report-parent"]
)
def test_fsync_failure_is_not_reported_as_success(attempt, replace_os, phase):
    def fsync(fd):
        name = os.readlink(f"/proc/self/fd/{fd}")
        selected = {
            "event-file": str(attempt.path / "events/000-plan.json"),
            "event-directory": str(attempt.path / "events"),
            "outcome-file": str(attempt.path / "outcome.json"),
            "report-parent": str(attempt.report.parent),
        }[phase]
        if name == selected:
            raise OSError(errno.EIO, "injected synchronization failure")
        return os.fsync(fd)

    replace_os(fsync=fsync)
    with pytest.raises(OSError):
        if phase.startswith("event"):
            attempt.record("plan", resource={"planned_name": "synthetic"})
        else:
            attempt.finish({"passed": False})
    assert attempt.report.exists() is (phase == "report-parent")
    if phase == "report-parent":
        assert attempt.report.read_bytes() == (attempt.path / "outcome.json").read_bytes()


def test_link_error_preserves_first_outcome_without_final_report(attempt, replace_os):
    def link(*args, **kwargs):
        raise OSError(errno.EIO, "injected link error")

    replace_os(link=link)
    with pytest.raises(OSError):
        attempt.finish({"passed": False})
    assert json.loads((attempt.path / "outcome.json").read_bytes())["passed"] is False
    assert not attempt.report.exists()


def test_real_signal_during_partial_write_preserves_uncertainty(attempt, replace_os):
    previous = signal.getsignal(signal.SIGUSR1)

    def cancelled(signum, frame):
        raise KeyboardInterrupt("owned cancellation probe")

    def write(fd, data):
        os.write(fd, data[:11])
        signal.raise_signal(signal.SIGUSR1)
        raise AssertionError("signal should interrupt the write")

    signal.signal(signal.SIGUSR1, cancelled)
    replace_os(write=write)
    fds = len(list(Path("/proc/self/fd").iterdir()))
    try:
        with pytest.raises(KeyboardInterrupt):
            attempt.finish({"passed": False})
    finally:
        signal.signal(signal.SIGUSR1, previous)
    assert (attempt.path / "outcome.json").stat().st_size == 11
    assert not attempt.report.exists()
    assert len(list(Path("/proc/self/fd").iterdir())) == fds


@pytest.mark.parametrize("change", ["rename-and-replace", "permissions"])
def test_attempt_identity_or_private_mode_change_stops_writes(attempt, change):
    if change == "rename-and-replace":
        attempt.path.rename(attempt.path.with_name("retained-original"))
        attempt.path.mkdir(mode=0o700)
    else:
        attempt.path.chmod(0o755)
    with pytest.raises(RuntimeError):
        attempt.record("case", name="must not write")
    assert not attempt.report.exists()

"""Native child/pipe/ownership contracts, with no Docker or application claims."""
import errno
import hashlib
import json
import os
import signal
import sys
import time
import traceback
from pathlib import Path

import bounded_command
import pytest
from bounded_command import CommandBoundaryError, capture_command

PEER = Path(__file__).with_name("native_peer.py")


def test_exact_frozen_component_is_loaded():
    source = Path(bounded_command.__file__).resolve()
    assert source == Path(__file__).with_name("bounded_command.py").resolve()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == os.environ["OWNED_COMPONENT_SHA256"]


def arguments(tmp_path, mode, *extra):
    marker = tmp_path / "child.json"
    return [sys.executable, "-B", str(PEER), mode, str(marker), *extra], marker


def invoke(argv, **kwargs):
    settings = {"deadline": time.monotonic() + 3, "max_output_bytes": 1024**2,
                "max_input_bytes": 256 * 1024}
    return capture_command(argv, **(settings | kwargs))


def verify_gone(marker, record_property, *, descendant=False):
    row = json.loads(marker.read_text())
    assert row["pid"] != os.getpid() and row["pgid"] != os.getpgrp()
    assert row["network"] == os.readlink("/proc/self/ns/net")
    path = Path(f"/proc/{row['pid']}/stat")
    until = time.monotonic() + 1
    while path.exists():
        try:
            stat = path.read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            break
        if stat[19] != row["starttime"]:
            break
        if descendant and stat[0] == "Z":
            # Only the namespace init can reap a reparented grandchild. The
            # outer runner must do that and independently prove an empty tree.
            assert int(stat[1]) == 1
            break
        assert time.monotonic() < until, "Owned command remains running/unreaped"
        time.sleep(0.01)
    record_property("owned_child", json.dumps(row, sort_keys=True))
    record_property("owned_child_not_running", True)


@pytest.mark.parametrize("payload", [None, b"", bytes(range(256)) * 512],
                         ids=["absent", "empty", "binary-large"])
def test_binary_channels_and_input_are_preserved(tmp_path, record_property, payload):
    argv, marker = arguments(tmp_path, "binary")
    result = invoke(argv, input_data=payload)
    assert result.returncode == 0
    assert result.stdout == b"\x00\xff" + (payload or b"")[::-1]
    assert result.stderr == b"\xfe\x00error\xff"
    verify_gone(marker, record_property)


def test_empty_and_shell_metacharacter_arguments_are_literal(tmp_path, record_property):
    side_effect = tmp_path / "must-not-exist"
    values = ["", "; touch " + str(side_effect), "$(false)", "a b"]
    argv, marker = arguments(tmp_path, "args", *values)
    result = invoke(argv)
    assert result.returncode == 0 and json.loads(result.stdout) == values
    assert not side_effect.exists()
    verify_gone(marker, record_property)


def test_nonzero_status_and_both_channels_are_returned(tmp_path, record_property):
    argv, marker = arguments(tmp_path, "nonzero")
    result = invoke(argv)
    assert (result.returncode, result.stdout, result.stderr) == (7, b"ordinary output", b"ordinary error")
    verify_gone(marker, record_property)


def test_exact_combined_output_limit_is_accepted(tmp_path, record_property):
    argv, marker = arguments(tmp_path, "cap")
    result = invoke(argv, max_output_bytes=32)
    assert result.returncode == 0 and result.stdout == b"a" * 16 and result.stderr == b"b" * 16
    verify_gone(marker, record_property)


@pytest.mark.parametrize("mode,limit", [("cap", 31), ("flood", 4096)],
                         ids=["aggregate-both-streams", "continuous-flood"])
def test_output_overflow_stops_owned_child_without_leaking_output(tmp_path, record_property, mode, limit):
    argv, marker = arguments(tmp_path, mode)
    with pytest.raises(CommandBoundaryError, match="output exceeds") as error:
        invoke(argv, max_output_bytes=limit)
    rendered = "".join(traceback.format_exception(error.value))
    assert "PRIVATE_SYNTHETIC_MARKER" not in rendered
    verify_gone(marker, record_property)


@pytest.mark.parametrize("mode,input_data", [("blocked-stdin", b"x" * 131072), ("slow", None),
                         ("closed-pipes", None), ("ignore-term", None)],
                         ids=["stdin-pressure", "continuous-output", "pipes-closed", "term-resistant"])
def test_absolute_deadline_includes_IO_and_child_completion(tmp_path, record_property, mode, input_data):
    argv, marker = arguments(tmp_path, mode)
    start = time.monotonic()
    with pytest.raises(CommandBoundaryError, match="deadline exceeded"):
        invoke(argv, deadline=start + 0.25, input_data=input_data)
    elapsed = time.monotonic() - start
    assert 0.20 <= elapsed < 2.5
    record_property("elapsed_monotonic_seconds", elapsed)
    row = json.loads(marker.read_text())
    assert row["mode"] == mode
    if mode == "ignore-term":
        assert row["term_ignored"] is True
    verify_gone(marker, record_property)


def test_short_valid_stream_is_not_refused(tmp_path, record_property):
    argv, marker = arguments(tmp_path, "slow-valid")
    result = invoke(argv)
    assert result.returncode == 0 and result.stdout == b"xxxx"
    verify_gone(marker, record_property)


def test_parent_exit_with_descendant_pipe_does_not_escape_deadline(tmp_path, record_property):
    argv, marker = arguments(tmp_path, "descendant-pipe")
    with pytest.raises(CommandBoundaryError, match="deadline exceeded"):
        invoke(argv, deadline=time.monotonic() + 0.4)
    child = json.loads(marker.read_text())
    descendant = json.loads(marker.with_suffix(".descendant").read_text())
    assert descendant["pgid"] == child["pgid"] == child["pid"]
    assert descendant["pid"] != child["pid"] and descendant["term_ignored"]
    verify_gone(marker, record_property)
    verify_gone(marker.with_suffix(".descendant"), record_property, descendant=True)


def test_cancellation_during_real_IO_reaps_the_owned_child(tmp_path, record_property):
    argv, marker = arguments(tmp_path, "cancel")
    previous = signal.getsignal(signal.SIGUSR1)

    def cancel(signum, frame):
        raise KeyboardInterrupt("owned cancellation")

    signal.signal(signal.SIGUSR1, cancel)
    try:
        with pytest.raises(KeyboardInterrupt, match="owned cancellation"):
            invoke(argv, input_data=b"x")
    finally:
        signal.signal(signal.SIGUSR1, previous)
    assert marker.with_suffix(".cancel-ready").exists()
    verify_gone(marker, record_property)


def test_signal_exit_is_returned_as_negative_status(tmp_path, record_property):
    argv, marker = arguments(tmp_path, "signal-exit")
    result = invoke(argv)
    assert result.returncode == -signal.SIGTERM
    verify_gone(marker, record_property)


def test_cwd_and_explicit_environment_are_honored(tmp_path, record_property):
    argv, marker = arguments(tmp_path, "cwd-env")
    result = invoke(argv, cwd=tmp_path, env={"OWNED_VALUE": "owned-value"})
    assert result.returncode == 0 and json.loads(result.stdout) == {"cwd": str(tmp_path), "value": "owned-value"}
    verify_gone(marker, record_property)


def test_inheritable_caller_descriptor_is_not_exposed(tmp_path, record_property):
    descriptor = os.open(tmp_path / "owned-file", os.O_CREAT | os.O_RDWR, 0o600)
    os.set_inheritable(descriptor, True)
    try:
        argv, marker = arguments(tmp_path, "fd-closed", str(descriptor))
        result = invoke(argv)
        assert result.returncode == 0 and result.stdout == b"closed"
    finally:
        os.close(descriptor)
    verify_gone(marker, record_property)


def test_child_closing_stdin_does_not_deadlock_parent(tmp_path, record_property):
    argv, marker = arguments(tmp_path, "close-stdin")
    result = invoke(argv, input_data=b"x" * 131072)
    assert result.returncode == 0 and result.stdout == b"done"
    verify_gone(marker, record_property)


def test_completed_commands_do_not_accumulate_descriptors(tmp_path, record_property):
    before = len(list(Path("/proc/self/fd").iterdir()))
    for i in range(8):
        root = tmp_path / str(i)
        root.mkdir()
        argv, marker = arguments(root, "cap")
        assert invoke(argv).returncode == 0
        verify_gone(marker, record_property)
    after = len(list(Path("/proc/self/fd").iterdir()))
    assert after == before
    record_property("descriptor_count_before_after", json.dumps([before, after]))


@pytest.mark.parametrize("field,value", [("max_output_bytes", 0), ("max_output_bytes", -1),
    ("max_output_bytes", True), ("max_output_bytes", 1.5), ("max_input_bytes", 0),
    ("max_input_bytes", -1), ("max_input_bytes", True), ("max_input_bytes", None)],
    ids=["output-zero", "output-negative", "output-bool", "output-float", "input-zero", "input-negative", "input-bool", "input-none"])
def test_invalid_byte_limits_refuse_before_dispatch(tmp_path, field, value):
    argv, marker = arguments(tmp_path, "cap")
    with pytest.raises(ValueError, match="positive integer"):
        invoke(argv, **{field: value})
    assert not marker.exists()


@pytest.mark.parametrize("value", [True, None, float("nan"), float("inf"), -float("inf"), 10**500],
                         ids=["bool", "none", "nan", "positive-infinity", "negative-infinity", "huge-integer"])
def test_invalid_deadlines_refuse_before_dispatch(tmp_path, value):
    argv, marker = arguments(tmp_path, "cap")
    with pytest.raises(ValueError, match="finite monotonic"):
        invoke(argv, deadline=value)
    assert not marker.exists()


def test_expired_deadline_refuses_without_starting_child(tmp_path):
    argv, marker = arguments(tmp_path, "cap")
    with pytest.raises(CommandBoundaryError, match="before dispatch"):
        invoke(argv, deadline=time.monotonic() - 1)
    assert not marker.exists()


def test_oversized_input_refuses_without_starting_child(tmp_path):
    argv, marker = arguments(tmp_path, "binary")
    with pytest.raises(CommandBoundaryError, match="input exceeds"):
        invoke(argv, input_data=b"xx", max_input_bytes=1)
    assert not marker.exists()


@pytest.mark.parametrize("value", ["not-an-argv", [], [""], ["/bin/true", None], ["/bin/true", "\0"]],
                         ids=["string", "empty-vector", "empty-executable", "non-string", "nul"])
def test_invalid_argument_vectors_are_refused(value):
    with pytest.raises(ValueError, match="argument vector"):
        invoke(value)


def test_non_bytes_input_is_refused_before_dispatch(tmp_path):
    argv, marker = arguments(tmp_path, "binary")
    with pytest.raises(ValueError, match="Input must be bytes"):
        invoke(argv, input_data="wrong type")
    assert not marker.exists()


def test_external_SIGCHLD_reaper_is_refused_before_dispatch(tmp_path):
    argv, marker = arguments(tmp_path, "cap")
    original = signal.getsignal(signal.SIGCHLD)
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    try:
        with pytest.raises(CommandBoundaryError, match="Exclusive child wait ownership"):
            invoke(argv)
    finally:
        signal.signal(signal.SIGCHLD, original)
    assert not marker.exists()


def test_exec_failure_diagnostic_does_not_expose_private_path(tmp_path):
    missing = tmp_path / "PRIVATE_SYNTHETIC_MARKER"
    with pytest.raises(CommandBoundaryError, match="Command execution failed") as error:
        invoke([str(missing)])
    assert "PRIVATE_SYNTHETIC_MARKER" not in str(error.value)
    assert "PRIVATE_SYNTHETIC_MARKER" not in "".join(traceback.format_exception(error.value))
    assert error.value.__suppress_context__


def test_caller_can_still_use_its_own_descriptor_after_child(tmp_path, record_property):
    descriptor = os.open(tmp_path / "caller-owned", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        argv, marker = arguments(tmp_path, "cap")
        assert invoke(argv).returncode == 0
        assert os.write(descriptor, b"retained") == 8
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, 8) == b"retained"
    except OSError as exc:
        assert exc.errno != errno.EBADF
        raise
    finally:
        os.close(descriptor)
    verify_gone(marker, record_property)

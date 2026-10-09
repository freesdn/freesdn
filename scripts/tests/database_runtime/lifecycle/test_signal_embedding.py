"""Signal-handler ownership, nested cancellation and repeated real signals.

The nominal-return stub tests only the main wrapper's late-signal refusal;
it does not represent successful SQL or final report publication.
"""

import importlib.util
import os
import signal
import sys
import time
from pathlib import Path

import pytest


def load_checker():
    path = Path(os.environ["FREESDN_CHECKER_SOURCE"])
    spec = importlib.util.spec_from_file_location("embedded_checker_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("custom_previous_handlers", [False, True])
def test_embedding_refusal_restores_signal_handlers_and_outer_context(
    tmp_path, monkeypatch, custom_previous_handlers
):
    tool = load_checker()
    report = tmp_path / "existing.json"
    report.write_bytes(b"preserve prior report")
    original = {kind: signal.getsignal(kind) for kind in (signal.SIGINT, signal.SIGTERM)}
    previous_calls = []

    def previous_handler(signum, _frame):
        previous_calls.append(signum)

    try:
        if custom_previous_handlers:
            for kind in original:
                signal.signal(kind, previous_handler)
        expected = {kind: signal.getsignal(kind) for kind in original}
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "checker",
                "--docker",
                "/must-not-be-contacted",
                "--source-postgres",
                "source-postgres",
                "--source-logdb",
                "source-logdb",
                "--target-postgres",
                "target-postgres",
                "--target-logdb",
                "target-logdb",
                "--report",
                str(report),
            ],
        )
        with tool.command_cancellation(lambda: True):
            with pytest.raises(FileExistsError):
                tool.main()
            assert all(signal.getsignal(kind) is value for kind, value in expected.items())
            with pytest.raises(tool.CommandBoundaryError, match="interrupted"):
                tool.capture_command(
                    [sys.executable, "-c", "print('must-not-run')"],
                    deadline=time.monotonic() + 2,
                    max_output_bytes=128,
                    max_input_bytes=1,
                )
        result = tool.capture_command(
            [sys.executable, "-c", "print('scope-restored')"],
            deadline=time.monotonic() + 2,
            max_output_bytes=128,
            max_input_bytes=1,
        )
        assert result.returncode == 0 and result.stdout == b"scope-restored\n"
        assert report.read_bytes() == b"preserve prior report" and previous_calls == []
    finally:
        for kind, handler in original.items():
            signal.signal(kind, handler)


@pytest.mark.parametrize("mode", ["volume-stall", "cleanup-stall"])
def test_two_distinct_real_signals_keep_failure_and_finish_client_cleanup(
    native_case, monkeypatch, mode
):
    original_kill = os.kill
    sent = []

    def deliver(pid, kind):
        sent.append((pid, kind))
        original_kill(pid, kind)
        if kind == signal.SIGTERM:
            original_kill(pid, signal.SIGINT)
            sent.append((pid, signal.SIGINT))

    monkeypatch.setattr(os, "kill", deliver)
    result = native_case(mode, interrupt=signal.SIGTERM)
    assert len(sent) == 2 and sent[0][0] == sent[1][0]
    assert (
        result["snapshot"]["exit"] != 0
        and result["snapshot"]["live_native_cli_before_fixture_cleanup"] == []
    )
    assert not result["report"]["passed"] and not result["report"]["qualification_complete"]
    assert set(result["report"]["interrupted_signals"]) == {"SIGINT", "SIGTERM"}
    assert result["report"]["owned_resources_removed"] is (mode != "cleanup-stall")


@pytest.mark.parametrize("kind", [signal.SIGINT, signal.SIGTERM])
def test_nominal_return_wrapper_refuses_late_signal_and_restores_handlers(
    monkeypatch, kind, capsys
):
    tool = load_checker()
    original = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}

    def nominal_return(interruption):
        interruption["cleanup"] = True
        os.kill(os.getpid(), kind)
        return {"passed": 1, "report": "controlled-nominal-return-no-real-publication"}

    monkeypatch.setattr(tool, "_main", nominal_return)
    try:
        with pytest.raises(tool.CommandBoundaryError, match="final publication"):
            tool.main()
        assert all(signal.getsignal(number) is value for number, value in original.items())
        assert capsys.readouterr().out == ""
    finally:
        for number, handler in original.items():
            signal.signal(number, handler)

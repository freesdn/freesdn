"""Opt-in timing evidence; never change a result, deadline, retry, or guard."""

from __future__ import annotations

import gc
import importlib
import json
import os
import resource
import time
from collections import deque
from functools import wraps
from pathlib import Path

import pytest

_clock = time.perf_counter
_events: deque[dict] = deque(maxlen=64)
_gc_started: dict[int, float] = {}
_node = ""
_output: Path | None = None


def _record(kind: str, **fields) -> None:
    if _output is None:
        return
    event = {"kind": kind, "monotonic": _clock(), "node": _node[:240], **fields}
    # Failure snapshots already contain recent events. Keep them in the output,
    # but never feed them back into later snapshots and recursively expand them.
    if kind != "test_failure":
        _events.append(event)
    with _output.open("a") as stream:
        stream.write(json.dumps(event) + "\n")


def _observe_gc(phase, info) -> None:
    generation = info["generation"]
    if phase == "start":
        _gc_started[generation] = _clock()
    elif generation in _gc_started:
        elapsed = _clock() - _gc_started.pop(generation)
        if elapsed >= .05:
            _record("gc_pause", generation=generation, seconds=elapsed,
                    collected=info["collected"], uncollectable=info["uncollectable"])


def pytest_sessionstart(session) -> None:
    global _output
    directory = os.environ.get("FREESDN_TEST_DIAGNOSTIC_DIR")
    if directory:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        _output = root / "timing.jsonl"
        _record("session_start", uid=os.getuid(), euid=os.geteuid(),
                gc_thresholds=gc.get_threshold(), cpu_count=os.cpu_count())
        gc.callbacks.append(_observe_gc)


def pytest_runtest_setup(item) -> None:
    global _node
    _node = item.nodeid


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if _output is None or not report.failed:
        return
    children = item.funcargs.get("owned_children", [])
    child_results = [state.process.raw.poll() if state.process else None for state in children]
    diagnostic = {"phase": report.when, "duration": report.duration,
                  "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                  "owned_child_exit_codes": child_results,
                  "recent_events": list(_events)[-12:]}
    _record("test_failure", **diagnostic)
    report.sections.append(("Qualification timing evidence", json.dumps(diagnostic)))


def pytest_sessionfinish(session, exitstatus) -> None:
    if _observe_gc in gc.callbacks:
        gc.callbacks.remove(_observe_gc)
    _record("session_finish", exitstatus=exitstatus,
            max_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


@pytest.fixture(autouse=True)
def trace_real_operations(request, monkeypatch):
    if _output is None:
        return
    targets = {
        "app.services.agent_signing_lifecycle": ["execute_signing_lifecycle"],
        "app.services.agent_release_reservation": ["_execute_owned"],
        "app.services.vault_s3_stream": ["_prepare_owned", "_start_owned"],
    }
    if not request.node.nodeid.startswith(("tests/services/", "tests/security/")):
        return
    for module_name, names in targets.items():
        module = importlib.import_module(module_name)
        for name in names:
            original = getattr(module, name)

            def wrap(function, label):
                @wraps(function)
                async def observed(*args, **kwargs):
                    started = _clock()
                    try:
                        result = await function(*args, **kwargs)
                    except BaseException as error:
                        chain, seen = [], set()
                        current = error
                        while current is not None and id(current) not in seen:
                            seen.add(id(current))
                            chain.append(type(current).__name__)
                            current = current.__cause__ or current.__context__
                        _record("operation_error", operation=label,
                                seconds=_clock() - started, exception_types=chain)
                        raise
                    elapsed = _clock() - started
                    if elapsed >= .5 or "vault_s3_stream" in label:
                        _record("operation_complete", operation=label, seconds=elapsed)
                    return result
                return observed

            monkeypatch.setattr(module, name, wrap(original, module_name + "." + name))

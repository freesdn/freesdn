"""One proposed actual-process first-use race. Not collected or executed."""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path

import pytest


def test_first_use_delivers_one_identity_across_real_processes(tmp_path, record_property):
    source = Path(os.environ["FREESDN_SIGNING_PROBE_SOURCE"])
    expected = os.environ["FREESDN_SIGNING_PROBE_SHA256"]
    assert source.is_absolute() and hashlib.sha256(source.read_bytes()).hexdigest() == expected
    root = tmp_path / "owned-shared-signing"
    root.mkdir(mode=0o700)
    env = dict(os.environ, FREESDN_SIGNING_KEY_DIR=str(root), FREESDN_AGENT_RELEASE_DIR=str(root))
    worker = Path(__file__).with_name("signing_race_worker.py")
    events = {"A": [], "B": []}
    pending = {}
    received = {}
    processes = {}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + 15

    def launch(label):
        child = subprocess.Popen(
            [sys.executable, "-B", str(worker), label],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        processes[label] = child
        assert child.stdout is not None
        selector.register(child.stdout, selectors.EVENT_READ, label)
        pending[label] = bytearray()
        received[label] = 0

    def poll_until(predicate):
        while not predicate():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                pytest.fail("owned signing race exceeded its fixture deadline")
            ready = selector.select(min(remaining, 0.1))
            for key, _ in ready:
                label = key.data
                block = os.read(key.fileobj.fileno(), 4096)
                if not block:
                    selector.unregister(key.fileobj)
                    if not any(e["event"] in {"completed", "refused"} for e in events[label]):
                        pytest.fail("owned signing child exited before an outcome event")
                    continue
                pending[label].extend(block)
                received[label] += len(block)
                if received[label] > 65536:
                    pytest.fail("owned signing child exceeded event budget")
                while b"\n" in pending[label]:
                    line, _, tail = pending[label].partition(b"\n")
                    pending[label] = bytearray(tail)
                    event = json.loads(line)
                    assert set(event) <= {"event", "pid", "public_sha256", "exception_type"}
                    events[label].append(event)

    def seen(label, event):
        return any(row["event"] == event for row in events[label])

    try:
        launch("A")
        poll_until(lambda: seen("A", "generation-paused"))
        launch("B")
        # Baseline B can finish while A remains paused; corrected B must show
        # a real EAGAIN/EACCES from flock. Neither branch relies on a fixed sleep.
        poll_until(lambda: any(seen("B", name) for name in ("actual-lock-busy", "completed", "refused")))
        assert processes["A"].stdin is not None
        processes["A"].stdin.write(b"release\n")
        processes["A"].stdin.flush()
        poll_until(lambda: all(any(seen(label, name) for name in ("completed", "refused")) for label in processes))
        exits = {label: child.wait(timeout=max(0.1, deadline - time.monotonic())) for label, child in processes.items()}
        public = (root / ".public-key.pem").read_bytes()
        actual = hashlib.sha256(public).hexdigest()
        identities = {
            label: [row["public_sha256"] for row in rows if row["event"] == "completed"]
            for label, rows in events.items()
        }
        record_property("different_processes", processes["A"].pid != processes["B"].pid)
        record_property("A_generation_paused", seen("A", "generation-paused"))
        record_property("B_real_flock_busy", seen("B", "actual-lock-busy"))
        record_property("delivered_identities", json.dumps(identities, sort_keys=True))
        record_property("persisted_public_sha256", actual)
        assert exits == {"A": 0, "B": 0}
        assert identities == {"A": [actual], "B": [actual]}
        assert seen("B", "actual-lock-busy")
    finally:
        selector.close()
        for child in processes.values():
            if child.poll() is None:
                child.kill()
        cleanup_errors = []
        for child in processes.values():
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cleanup_errors.append(child.pid)
            finally:
                for pipe in (child.stdin, child.stdout, child.stderr):
                    if pipe is not None:
                        pipe.close()
        assert not cleanup_errors, "owned signing child was not reaped"

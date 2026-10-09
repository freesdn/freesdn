"""Bounded real checker/CLI children, observed before explicit fixture cleanup."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest


def alive(pid, start):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return fields[19] == start and fields[0] != "Z"
    except (FileNotFoundError, ProcessLookupError):
        return False


@pytest.fixture
def native_case(tmp_path, record_property):
    engine = tmp_path / "synthetic-docker"
    source = Path(__file__).with_name("synthetic_engine.py")
    engine.write_text(
        "#!"
        + sys.executable
        + " -B\nimport runpy\nrunpy.run_path("
        + repr(str(source))
        + ',run_name="__main__")\n'
    )
    engine.chmod(0o700)
    report = tmp_path / "report.json"
    calls_path = tmp_path / "calls.jsonl"
    child = None

    def calls():
        return (
            [json.loads(line) for line in calls_path.read_text().splitlines()]
            if calls_path.exists()
            else []
        )

    def invoke(mode, *, work_seconds=5, interrupt=None):
        nonlocal child
        command = [
            sys.executable,
            "-B",
            os.environ["FREESDN_CHECKER_SOURCE"],
            "--docker",
            str(engine),
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
            "--timeout-seconds",
            str(work_seconds),
        ]
        started = time.monotonic()
        with (
            (tmp_path / "checker.stdout").open("xb") as out,
            (tmp_path / "checker.stderr").open("xb") as err,
        ):
            child = subprocess.Popen(
                command,
                env={**os.environ, "ENGINE_CASE_ROOT": str(tmp_path), "ENGINE_CASE_MODE": mode},
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
            if interrupt is not None:
                until = time.monotonic() + 3
                while (
                    not (tmp_path / "ready").exists()
                    and time.monotonic() < until
                    and child.poll() is None
                ):
                    time.sleep(0.005)
                assert (tmp_path / "ready").exists(), (
                    "fixture did not reach the native wait boundary"
                )
                os.kill(child.pid, interrupt)
            code = child.wait(timeout=9)
        elapsed = time.monotonic() - started
        observed = calls()
        peers = {row["pid"]: row for row in observed}
        live = [row["pid"] for row in peers.values() if alive(row["pid"], row["starttime"])]
        workers = {
            row["worker_pid"]: row for row in observed if row["kind"] == "database-worker-boundary"
        }
        live_workers = [pid for pid, row in workers.items() if alive(pid, row["worker_starttime"])]
        catalogue = (
            json.loads((tmp_path / "catalogue.json").read_bytes())
            if (tmp_path / "catalogue.json").exists()
            else None
        )
        state = json.loads(report.read_bytes()) if report.exists() else None
        snapshot = {
            "exit": code,
            "elapsed_seconds": elapsed,
            "report_present": report.exists(),
            "live_native_cli_before_fixture_cleanup": live,
            "live_database_worker_before_fixture_cleanup": live_workers,
            "actual_database_worker_boundaries": len(workers),
            "catalogue_volume_remains": bool(catalogue and catalogue["volume"]),
            "catalogue_container_remains": bool(catalogue and catalogue["container"]),
            "observed_calls": len(observed),
            "mode": mode,
            "signal": interrupt,
        }
        (tmp_path / "observation.json").write_text(json.dumps(snapshot, indent=2) + "\n")
        record_property("native_observation", json.dumps(snapshot, sort_keys=True))
        return {
            "report": state,
            "calls": observed,
            "snapshot": snapshot,
            "catalogue": catalogue,
            "artifact_path": report.with_name(report.name + ".artifacts"),
        }

    try:
        yield invoke
    finally:
        terminated = []
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
            terminated.append({"checker": child.pid})
        for row in {r["pid"]: r for r in calls()}.values():
            if alive(row["pid"], row["starttime"]):
                group = Path(f"/proc/{row['pgid']}/stat").read_text().rsplit(")", 1)[1].split()
                assert group[19] == row["pgid_starttime"] and os.getpgid(row["pid"]) == row["pgid"]
                if row["pid"] != row["pgid"]:
                    owner = next(
                        r
                        for r in calls()
                        if r["kind"] == "database-worker-boundary" and r["pid"] == row["pid"]
                    )
                    assert (
                        owner["worker_pid"] == row["pgid"]
                        and owner["worker_starttime"] == row["pgid_starttime"]
                    )
                try:
                    os.killpg(row["pgid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
                terminated.append({"native_cli": row["pid"]})
        until = time.monotonic() + 2
        while any(alive(r["pid"], r["starttime"]) for r in calls()) and time.monotonic() < until:
            time.sleep(0.005)
        assert not any(alive(r["pid"], r["starttime"]) for r in calls())
        (tmp_path / "fixture-cleanup.json").write_text(
            json.dumps({"explicit_fixture_terminated": terminated}) + "\n"
        )
        record_property("explicit_fixture_terminated", json.dumps(terminated))

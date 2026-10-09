"""Real checker → Database.sql → native worker/client interruption boundaries.

The native client is a controlled peer, not a SQL server or Docker daemon.
"""

import signal

import pytest


@pytest.mark.parametrize("kind", [signal.SIGINT, signal.SIGTERM, None])
def test_database_worker_interruption_or_deadline_preserves_failed_report_and_reconciles(
    native_case, kind
):
    result = native_case("database-stall", work_seconds=1 if kind is None else 5, interrupt=kind)
    observed = result["snapshot"]
    assert observed["actual_database_worker_boundaries"] == 1
    assert observed["exit"] != 0 and observed["report_present"]
    assert observed["live_native_cli_before_fixture_cleanup"] == []
    assert observed["live_database_worker_before_fixture_cleanup"] == []
    assert observed["elapsed_seconds"] < 3
    report = result["report"]
    assert not report["passed"] and not report["qualification_complete"]
    assert report["interrupted_signals"] == ([] if kind is None else [signal.Signals(kind).name])
    assert report["owned_resources_removed"]
    assert not observed["catalogue_volume_remains"] and not observed["catalogue_container_remains"]
    boundary = [row for row in result["calls"] if row["kind"] == "database-worker-boundary"]
    assert len(boundary) == 1 and boundary[0]["worker_pid"] == boundary[0]["pgid"]
    assert boundary[0]["worker_pid"] != boundary[0]["pid"]
    assert boundary[0]["worker_starttime"] == boundary[0]["pgid_starttime"]
    assert any(
        value.endswith("/qualification/migration_io_worker.py")
        for value in boundary[0]["worker_command"]
    )

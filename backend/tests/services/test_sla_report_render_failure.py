# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A storage failure while rendering an SLA report must surface, not degrade.

``generate_report`` used to render inside ``except Exception:
logger.exception(...)``. Any failure at the sink -- a full disk, a read-only
volume, a root-owned mountpoint -- left ``SLAReport.file_path`` NULL while the
row itself was already flushed, so:

  * ``POST /sla/reports/generate`` committed the row and returned 201, and
  * ``GET /sla/reports/{id}/download`` took its ``if report.file_path:`` else
    branch and returned ``report_data`` as application/json.

A caller that asked for ``format="csv"`` received JSON with a 200 and no
indication anything had failed. ``generate_scheduled`` made it worse: it
catches per schedule and continues, so the already-flushed phantom rode the
Celery task's ``session.commit()`` into the catalogue as a finished report that
can never be downloaded in the format it advertises.

Pure-unit: the DB session is mocked, so no database is required.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest


def _mock_session() -> MagicMock:
    """A session whose queries return no policies / no snapshots."""

    class _Result:
        def scalars(self):
            inner = MagicMock()
            inner.all.return_value = []
            return inner

        def one(self):
            return SimpleNamespace(
                avg_compliance=None,
                min_compliance=None,
                max_compliance=None,
                snapshot_count=0,
            )

        def scalar_one_or_none(self):
            return None

    db = MagicMock()
    db.execute = AsyncMock(return_value=_Result())
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.delete = AsyncMock()
    return db


async def _generate(gen, *, report_format: str = "csv"):
    now = datetime.now(UTC)
    return await gen.generate_report(
        org_id=uuid4(),
        period_start=now - timedelta(days=1),
        period_end=now,
        report_format=report_format,
    )


# ---------------------------------------------------------------------------
# The swallow itself
# ---------------------------------------------------------------------------


async def test_a_disk_full_render_raises_instead_of_returning_a_fileless_report():
    """ENOSPC at the sink must reach the caller.

    The renderer is stubbed to raise the raw OSError deliberately: the
    assertion is that ``generate_report`` swallows NOTHING, not merely that it
    re-raises its own wrapper type.
    """
    from app.services.sla_reports import SLAReportGenerator

    gen = SLAReportGenerator(_mock_session())

    async def _boom(report, data):
        raise OSError(28, "No space left on device")

    gen._render_to_file = _boom

    with pytest.raises(OSError, match="No space left on device"):
        await _generate(gen)


async def test_a_failed_render_adds_no_row_for_the_caller_to_commit():
    """The phantom row is the half that survives a commit.

    ``generate_scheduled`` catches per schedule and continues, and the Celery
    task then commits the session. If the row were added before the render, a
    failed schedule would publish a report with file_path NULL.
    """
    from app.services.sla_reports import SLAReportGenerator

    db = _mock_session()
    gen = SLAReportGenerator(db)

    async def _boom(report, data):
        raise OSError(30, "Read-only file system")

    gen._render_to_file = _boom

    with pytest.raises(OSError):
        await _generate(gen)

    assert db.add.call_count == 0, (
        "a report whose render failed was queued on the session; the caller's "
        "commit publishes it with file_path NULL"
    )


async def test_a_successful_render_still_persists_the_report():
    """The guard must not break the happy path."""
    from app.services.sla_reports import SLAReportGenerator

    db = _mock_session()
    gen = SLAReportGenerator(db)

    rendered: list[str] = []

    async def _ok(report, data):
        rendered.append(str(report.id))
        report.file_path = f"/data/sla_reports/{report.organization_id}/x.csv"
        report.file_size = 10

    gen._render_to_file = _ok

    report = await _generate(gen)

    assert db.add.call_count == 1
    assert report.file_path is not None
    # The render is named after the row id, so the id must exist before the
    # INSERT would have assigned it.
    assert report.id is not None
    assert rendered == [str(report.id)]


# ---------------------------------------------------------------------------
# The real sink, through the real filesystem
# ---------------------------------------------------------------------------


async def test_the_real_renderer_wraps_the_oserror_with_the_path(tmp_path, monkeypatch):
    """_render_to_file names the report, the format and the sink.

    A bare "[Errno 30] Read-only file system" does not tell an operator which
    mount to fix.
    """
    import app.services.sla_reports as mod

    # A FILE where the base directory should be: mkdir(parents=True) then fails
    # with FileExistsError / NotADirectoryError -- both OSError, both the shape
    # of a wrong mount.
    blocker = tmp_path / "sla_reports"
    blocker.write_text("not a directory")
    monkeypatch.setattr(mod, "REPORTS_BASE_DIR", str(blocker))

    gen = mod.SLAReportGenerator(_mock_session())
    with pytest.raises(mod.SLAReportRenderError) as excinfo:
        await _generate(gen)

    message = str(excinfo.value)
    assert "csv" in message
    assert str(blocker) in message
    assert isinstance(excinfo.value.__cause__, OSError)


async def test_a_partial_render_leaves_no_truncated_file_behind(tmp_path, monkeypatch):
    """ENOSPC part-way through a write leaves garbage under an unreferenced id."""
    import app.services.sla_reports as mod

    monkeypatch.setattr(mod, "REPORTS_BASE_DIR", str(tmp_path))

    gen = mod.SLAReportGenerator(_mock_session())

    def _half_written(filepath: Path, data):
        filepath.write_text("Report Period,partial")
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(gen, "_write_csv", _half_written)

    with pytest.raises(mod.SLAReportRenderError):
        await _generate(gen)

    leftovers = list(tmp_path.rglob("*.csv"))
    assert leftovers == [], f"partial renders left on disk: {leftovers}"


async def test_the_happy_path_writes_a_csv_the_download_endpoint_can_serve(tmp_path, monkeypatch):
    import app.services.sla_reports as mod

    monkeypatch.setattr(mod, "REPORTS_BASE_DIR", str(tmp_path))

    db = _mock_session()
    report = await _generate(mod.SLAReportGenerator(db), report_format="csv")

    assert report.file_path is not None
    written = Path(report.file_path)
    assert written.is_file()
    assert written.suffix == ".csv"
    assert report.file_size == written.stat().st_size
    assert db.add.call_count == 1


# ---------------------------------------------------------------------------
# Premise: why a NULL file_path is a content-type change and not just a gap
# ---------------------------------------------------------------------------


def test_the_download_endpoint_still_falls_back_to_json_on_a_null_file_path():
    """Pins the consequence, so the two cannot drift apart.

    If this ever stops holding -- e.g. the endpoint grows an explicit error for
    an unrendered report -- the fix above can be revisited. Until then, a NULL
    file_path IS a silent content-type change.
    """
    from app.api.v1.endpoints import sla_reports as endpoint

    src = inspect.getsource(endpoint.download_report)
    assert "if report.file_path:" in src
    assert '"report_data": report.report_data' in src


def test_the_scheduled_loop_does_not_advance_next_run_on_failure():
    """A failed period must retry, not be skipped in silence."""
    from app.services.sla_reports import SLAReportGenerator

    src = inspect.getsource(SLAReportGenerator.generate_scheduled)
    body = src.split("except Exception:")[1]
    assert "_compute_next_run" not in body

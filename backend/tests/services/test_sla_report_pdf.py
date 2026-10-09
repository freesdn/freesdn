# SPDX-License-Identifier: AGPL-3.0-only
"""Parse actual PDF output and exercise the download contract and failed renders."""

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from pypdf import PdfReader

from app.api.v1.endpoints import sla_reports as endpoint
from app.models.sla import SLAReport
from app.services.sla_report_pdf import write_sla_pdf
from app.services.sla_reports import SLAReportGenerator, SLAReportRenderError


@pytest.fixture
def report_data():
    return {
        "period_start": "2026-09-01T00:00:00+00:00",
        "period_end": "2026-09-02T00:00:00+00:00",
        "compliance": {
            "avg_compliance_percent": 0.0,
            "min_compliance_percent": 0.0,
            "max_compliance_percent": 0.0,
            "snapshot_count": 1,
        },
        "policies": [{"name": "Core <b>router</b> & internet", "scope": "site"}],
        "breaches": {"total": 1, "by_severity": {"critical": 1}},
    }


async def test_requested_pdf_is_parseable_and_preserves_measurements(tmp_path, monkeypatch, report_data):
    monkeypatch.setattr("app.services.sla_reports.REPORTS_BASE_DIR", str(tmp_path))
    report = SLAReport(id=uuid4(), organization_id=uuid4(), format="pdf", title="September review")
    await SLAReportGenerator(MagicMock())._render_to_file(report, report_data)
    path = Path(report.file_path)
    assert path.suffix == ".pdf"
    assert path.read_bytes().startswith(b"%PDF-")
    assert report.file_size == path.stat().st_size
    pdf = PdfReader(path)
    assert len(pdf.pages) == 1
    assert pdf.metadata.title == "September review"
    text = pdf.pages[0].extract_text()
    assert "Average: 0.0%" in text
    assert "Core <b>router</b> & internet" in text
    assert "Not measured" in text
    assert "Page 1" in text


def test_pdf_paginates_without_dropping_policies_and_retains_chinese(tmp_path, report_data):
    report_data["policies"] = [
        {"name": f"Policy {number:03d}", "scope": "site"} for number in range(120)
    ] + [{"name": "核心交换机", "scope": "site"}]
    path = tmp_path / "long.pdf"
    write_sla_pdf(path, report_data, "Large report")
    pdf = PdfReader(path)
    assert len(pdf.pages) > 5
    text = "\n".join(page.extract_text() for page in pdf.pages)
    assert all(f"Policy {number:03d}" in text for number in range(120))
    assert "核心交换机" in text
    assert f"Page {len(pdf.pages)}" in text


async def test_pdf_layout_failure_removes_partial_file(tmp_path, monkeypatch, report_data):
    monkeypatch.setattr("app.services.sla_reports.REPORTS_BASE_DIR", str(tmp_path))

    def broken_renderer(path, data, title):
        path.write_bytes(b"%PDF-partial")
        raise ValueError("layout failed")

    monkeypatch.setattr("app.services.sla_reports.write_sla_pdf", broken_renderer)
    report = SLAReport(id=uuid4(), organization_id=uuid4(), format="pdf", title="Review")
    with pytest.raises(SLAReportRenderError, match="layout failed"):
        await SLAReportGenerator(MagicMock())._render_to_file(report, report_data)
    assert report.file_path is None
    assert list(tmp_path.rglob("*.pdf")) == []


@pytest.fixture
def download(tmp_path, monkeypatch):
    org_id = uuid4()
    report = SimpleNamespace(
        id=uuid4(), organization_id=org_id, title="Review", format="pdf", file_path=None
    )
    monkeypatch.setattr(endpoint, "REPORTS_BASE_DIR", str(tmp_path))
    monkeypatch.setattr(endpoint, "_org_id", lambda _user: org_id)
    monkeypatch.setattr(endpoint.SLAReportGenerator, "get_report", AsyncMock(return_value=report))
    folder = tmp_path / str(org_id)
    folder.mkdir()
    return report, folder


@pytest.mark.parametrize("content", [None, b"SLA COMPLIANCE REPORT", b"%PD"])
async def test_unrendered_or_legacy_text_pdf_download_requires_regeneration(download, content):
    report, folder = download
    if content is not None:
        path = folder / "old.txt"
        path.write_bytes(content)
        report.file_path = str(path)
    with pytest.raises(HTTPException) as exc:
        await endpoint.download_report(report.id, db=MagicMock(), user=MagicMock())
    assert exc.value.status_code == 409
    assert "regenerate" in exc.value.detail


async def test_pdf_download_keeps_content_type_and_filename(download, report_data):
    report, folder = download
    path = folder / "report.pdf"
    write_sla_pdf(path, report_data, report.title)
    report.file_path = str(path)
    response = await endpoint.download_report(report.id, db=MagicMock(), user=MagicMock())
    assert response.media_type == "application/pdf"
    assert response.filename == "Review.pdf"
    assert Path(response.path).read_bytes().startswith(b"%PDF-")


async def test_report_path_cannot_point_into_another_organization(download, tmp_path):
    report, _ = download
    other_folder = tmp_path / str(uuid4())
    other_folder.mkdir()
    path = other_folder / "other.pdf"
    path.write_bytes(b"%PDF-")
    report.file_path = str(path)
    with pytest.raises(HTTPException) as exc:
        await endpoint.download_report(report.id, db=MagicMock(), user=MagicMock())
    assert exc.value.status_code == 403


def test_report_title_cannot_exceed_database_column():
    with pytest.raises(ValueError, match="255"):
        endpoint.SLAReportGenerateRequest(
            period_start=datetime(2026, 9, 1, tzinfo=UTC),
            period_end=datetime(2026, 9, 2, tzinfo=UTC),
            title="x" * 256,
        )


def test_mixed_period_offsets_are_normalized_instead_of_causing_server_error():
    request = endpoint.SLAReportGenerateRequest(
        period_start="2026-09-01T00:00:00",
        period_end="2026-09-02T03:00:00+03:00",
    )
    assert request.period_start.tzinfo is UTC
    assert request.period_end == datetime(2026, 9, 2, tzinfo=UTC)


def test_report_period_bound_does_not_round_away_extra_hours():
    with pytest.raises(ValueError, match="1 year"):
        endpoint.SLAReportGenerateRequest(
            period_start="2026-01-01T00:00:00Z",
            period_end="2027-01-02T01:00:00Z",
        )

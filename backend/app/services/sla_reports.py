# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - SLA Report Generation Service
=============================================

Generates on-demand and scheduled SLA compliance reports.
Queries SLA policies, breaches, and snapshots to build
summary data.  Optionally renders to PDF/CSV.
"""

import csv
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.site_access import site_ids_for_request
from app.models.sla import (
    SLABreach,
    SLAPolicy,
    SLAPolicyScope,
    SLAReport,
    SLAReportSchedule,
    SLASnapshot,
)

logger = logging.getLogger(__name__)

REPORTS_BASE_DIR = os.environ.get("SLA_REPORTS_DIR", "/data/sla_reports")


class SLAReportGenerator:
    """Generates and manages SLA reports."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ──────────────────────────────────────────────────────────────────────
    # On-Demand Report Generation
    # ──────────────────────────────────────────────────────────────────────

    async def generate_report(
        self,
        org_id: UUID,
        period_start: datetime,
        period_end: datetime,
        *,
        policy_ids: list[UUID] | None = None,
        report_format: str = "pdf",
        generated_by: UUID | None = None,
        title: str | None = None,
    ) -> SLAReport:
        """
        Generate an SLA compliance report for the given period.

        Steps:
          1. Query SLA policies in scope.
          2. Gather breaches within the period.
          3. Gather compliance snapshots within the period.
          4. Compute summary metrics.
          5. Persist the report record.

        Parameters
        ----------
        org_id : UUID
            Organisation scope.
        period_start, period_end : datetime
            Report time range.
        policy_ids : list[UUID] | None
            Optional filter to specific SLA policies.
        report_format : str
            "pdf" or "csv".
        generated_by : UUID | None
            User who requested the report.
        title : str | None
            Custom report title; auto-generated if omitted.

        Returns
        -------
        SLAReport
            The persisted report record with ``report_data`` populated.
        """
        # 1. Resolve policies
        policy_q = select(SLAPolicy).where(
            SLAPolicy.organization_id == org_id,
        )
        if policy_ids:
            policy_q = policy_q.where(SLAPolicy.id.in_(policy_ids))

        # Per-user site grant: a site-limited caller may only report on policies
        # that are org-level or anchored to a site they were granted. Without
        # this, passing a sibling-site ``policy_ids`` would exfiltrate that
        # site's compliance + breach history. ``site_ids_for_request()`` reads
        # the request contextvar (no-op for unrestricted / scheduled runs).
        _granted = site_ids_for_request()
        if _granted is not None:
            _ids = list(_granted)
            policy_q = policy_q.where(
                or_(
                    SLAPolicy.scope != SLAPolicyScope.SITE.value,
                    SLAPolicy.scope_id.in_(_ids) if _ids else SLAPolicy.scope_id.in_([]),
                )
            )

        policies = list((await self.db.execute(policy_q)).scalars().all())

        if not policies:
            policy_summary = []
        else:
            policy_summary = [
                {
                    "id": str(p.id),
                    "name": p.name,
                    "status": p.status,
                    "scope": p.scope,
                    "current_compliance_percent": p.current_compliance_percent,
                }
                for p in policies
            ]

        resolved_policy_ids = [p.id for p in policies]

        # 2. Breaches in period
        breach_q = select(SLABreach).where(
            SLABreach.organization_id == org_id,
            SLABreach.started_at >= period_start,
            SLABreach.started_at <= period_end,
        )
        if resolved_policy_ids:
            breach_q = breach_q.where(SLABreach.policy_id.in_(resolved_policy_ids))
        elif _granted is not None:
            # a site-limited caller whose accessible
            # policy set is EMPTY (no policies on granted sites, or an explicit
            # sibling-site ``policy_ids`` that the grant filter dropped) must NOT
            # fall through to an org-wide breach read. Constrain to the accessible
            # policy subquery so the empty grant yields ZERO breaches, never all
            # of the org's. Mirrors the snapshot constraint below.
            _ids = list(_granted)
            accessible_policy_subq = select(SLAPolicy.id).where(
                SLAPolicy.organization_id == org_id,
                or_(
                    SLAPolicy.scope != SLAPolicyScope.SITE.value,
                    SLAPolicy.scope_id.in_(_ids) if _ids else SLAPolicy.scope_id.in_([]),
                ),
            )
            breach_q = breach_q.where(SLABreach.policy_id.in_(accessible_policy_subq))

        breaches = list((await self.db.execute(breach_q)).scalars().all())

        breach_summary: dict[str, Any] = {
            "total": len(breaches),
            "by_severity": {},
            "by_status": {},
        }
        for b in breaches:
            breach_summary["by_severity"][b.severity] = (
                breach_summary["by_severity"].get(b.severity, 0) + 1
            )
            breach_summary["by_status"][b.status] = breach_summary["by_status"].get(b.status, 0) + 1

        # 3. Compliance snapshots — scoped to org-owned policies
        org_policy_subq = select(SLAPolicy.id).where(SLAPolicy.organization_id == org_id)
        if resolved_policy_ids:
            org_policy_subq = org_policy_subq.where(SLAPolicy.id.in_(resolved_policy_ids))
        elif _granted is not None:
            # Site-limited caller with no explicit policy filter and no accessible
            # policies must not fall through to an org-wide snapshot aggregate.
            _ids = list(_granted)
            org_policy_subq = org_policy_subq.where(
                or_(
                    SLAPolicy.scope != SLAPolicyScope.SITE.value,
                    SLAPolicy.scope_id.in_(_ids) if _ids else SLAPolicy.scope_id.in_([]),
                )
            )

        snapshot_q = select(
            func.avg(SLASnapshot.compliance_percent).label("avg_compliance"),
            func.min(SLASnapshot.compliance_percent).label("min_compliance"),
            func.max(SLASnapshot.compliance_percent).label("max_compliance"),
            func.count().label("snapshot_count"),
        ).where(
            SLASnapshot.recorded_at >= period_start,
            SLASnapshot.recorded_at <= period_end,
            SLASnapshot.policy_id.in_(org_policy_subq),
        )

        snap_row = (await self.db.execute(snapshot_q)).one()

        compliance_summary = {
            "avg_compliance_percent": (
                round(snap_row.avg_compliance, 2) if snap_row.avg_compliance else None
            ),
            "min_compliance_percent": (
                round(snap_row.min_compliance, 2) if snap_row.min_compliance else None
            ),
            "max_compliance_percent": (
                round(snap_row.max_compliance, 2) if snap_row.max_compliance else None
            ),
            "snapshot_count": snap_row.snapshot_count or 0,
        }

        # 4. Build report data
        report_data = {
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "policies": policy_summary,
            "breaches": breach_summary,
            "compliance": compliance_summary,
        }

        # 5. Persist
        if not title:
            start_str = period_start.strftime("%Y-%m-%d")
            end_str = period_end.strftime("%Y-%m-%d")
            title = f"SLA Report {start_str} to {end_str}"

        report = SLAReport(
            organization_id=org_id,
            title=title,
            period_start=period_start,
            period_end=period_end,
            format=report_format,
            report_data=report_data,
            generated_by=generated_by,
            generated_at=datetime.now(UTC),
        )
        self.db.add(report)
        await self.db.flush()

        # 6. Render to file (CSV or text-based report)
        try:
            await self._render_to_file(report, report_data)
            await self.db.flush()
        except Exception:
            logger.exception(
                "Failed to render report %s to file — report data is still "
                "available in the database",
                report.id,
            )

        logger.info(
            "Generated SLA report '%s' (%s) for org %s — %d policies, %d breaches",
            title,
            report_format,
            org_id,
            len(policies),
            len(breaches),
        )
        return report

    # ──────────────────────────────────────────────────────────────────────
    # File Rendering
    # ──────────────────────────────────────────────────────────────────────

    async def _render_to_file(self, report: SLAReport, report_data: dict[str, Any]) -> None:
        """Render report data to a file (CSV or text-based PDF alternative)."""
        base = Path(REPORTS_BASE_DIR)
        base.mkdir(parents=True, exist_ok=True)

        org_dir = base / str(report.organization_id)
        org_dir.mkdir(parents=True, exist_ok=True)

        filename = f"sla_report_{report.id}"

        if report.format == "csv":
            filepath = org_dir / f"{filename}.csv"
            self._write_csv(filepath, report_data)
        else:
            # Text-based report (PDF placeholder — can be upgraded to
            # weasyprint or similar later without changing the public API)
            filepath = org_dir / f"{filename}.txt"
            self._write_text_report(filepath, report_data)

        report.file_path = str(filepath)
        report.file_size = filepath.stat().st_size

    def _write_csv(self, filepath: Path, data: dict[str, Any]) -> None:
        """Write SLA report data as CSV."""
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            # Header
            writer.writerow(
                [
                    "Report Period",
                    f"{data['period_start']} to {data['period_end']}",
                ]
            )
            writer.writerow([])

            # Policies
            # INJ-04: the policy name (and status/scope) are operator-set text;
            # neutralize spreadsheet formula injection before writing.
            from app.core.security_utils import csv_safe

            writer.writerow(["Policy Name", "Status", "Scope", "Current Compliance %"])
            for p in data.get("policies", []):
                writer.writerow(
                    [
                        csv_safe(p.get("name", "")),
                        csv_safe(p.get("status", "")),
                        csv_safe(p.get("scope", "")),
                        p.get("current_compliance_percent", ""),
                    ]
                )
            writer.writerow([])

            # Compliance summary
            compliance = data.get("compliance", {})
            writer.writerow(["Compliance Metric", "Value"])
            writer.writerow(
                ["Average Compliance %", compliance.get("avg_compliance_percent", "N/A")]
            )
            writer.writerow(
                ["Minimum Compliance %", compliance.get("min_compliance_percent", "N/A")]
            )
            writer.writerow(
                ["Maximum Compliance %", compliance.get("max_compliance_percent", "N/A")]
            )
            writer.writerow(["Snapshot Count", compliance.get("snapshot_count", 0)])
            writer.writerow([])

            # Breach summary
            breaches = data.get("breaches", {})
            writer.writerow(["Breach Summary", ""])
            writer.writerow(["Total Breaches", breaches.get("total", 0)])
            writer.writerow([])
            writer.writerow(["By Severity", "Count"])
            for sev, count in breaches.get("by_severity", {}).items():
                writer.writerow([sev, count])
            writer.writerow([])
            writer.writerow(["By Status", "Count"])
            for status, count in breaches.get("by_status", {}).items():
                writer.writerow([status, count])

    def _write_text_report(self, filepath: Path, data: dict[str, Any]) -> None:
        """Write SLA report as formatted text (portable, no dependencies)."""
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("SLA COMPLIANCE REPORT")
        lines.append("=" * 60)
        lines.append(f"Period: {data['period_start']} to {data['period_end']}")
        lines.append("")

        # Compliance summary
        compliance = data.get("compliance", {})
        lines.append("-" * 40)
        lines.append("COMPLIANCE SUMMARY")
        lines.append("-" * 40)
        lines.append(f"  Average: {compliance.get('avg_compliance_percent', 'N/A')}%")
        lines.append(f"  Minimum: {compliance.get('min_compliance_percent', 'N/A')}%")
        lines.append(f"  Maximum: {compliance.get('max_compliance_percent', 'N/A')}%")
        lines.append(f"  Snapshots: {compliance.get('snapshot_count', 0)}")
        lines.append("")

        # Policies
        policies = data.get("policies", [])
        if policies:
            lines.append("-" * 40)
            lines.append("SLA POLICIES")
            lines.append("-" * 40)
            for p in policies:
                lines.append(f"  {p.get('name', 'Unknown')}")
                lines.append(f"    Status: {p.get('status', 'N/A')}")
                lines.append(f"    Scope: {p.get('scope', 'N/A')}")
                lines.append(f"    Compliance: {p.get('current_compliance_percent', 'N/A')}%")
                lines.append("")

        # Breaches
        breaches = data.get("breaches", {})
        lines.append("-" * 40)
        lines.append("BREACH SUMMARY")
        lines.append("-" * 40)
        lines.append(f"  Total: {breaches.get('total', 0)}")

        by_sev = breaches.get("by_severity", {})
        if by_sev:
            lines.append("  By Severity:")
            for sev, count in by_sev.items():
                lines.append(f"    {sev}: {count}")

        by_status = breaches.get("by_status", {})
        if by_status:
            lines.append("  By Status:")
            for st, count in by_status.items():
                lines.append(f"    {st}: {count}")

        lines.append("")
        lines.append("=" * 60)
        lines.append("Generated by FreeSDN SLA Reporting Engine")
        lines.append("=" * 60)

        with open(filepath, "w") as f:
            f.write("\n".join(lines))

    # ──────────────────────────────────────────────────────────────────────
    # Report Listing
    # ──────────────────────────────────────────────────────────────────────

    async def list_reports(
        self,
        org_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SLAReport], int]:
        """List generated reports for the organisation."""
        base = select(SLAReport).where(SLAReport.organization_id == org_id)
        total = (
            await self.db.execute(select(func.count()).select_from(base.subquery()))
        ).scalar() or 0

        q = base.order_by(SLAReport.generated_at.desc()).offset(offset).limit(limit)
        result = await self.db.execute(q)
        return list(result.scalars().all()), total

    async def get_report(self, report_id: UUID) -> SLAReport | None:
        result = await self.db.execute(select(SLAReport).where(SLAReport.id == report_id))
        return result.scalar_one_or_none()

    # ──────────────────────────────────────────────────────────────────────
    # Schedule Management
    # ──────────────────────────────────────────────────────────────────────

    async def list_schedules(
        self,
        org_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SLAReportSchedule], int]:
        base = select(SLAReportSchedule).where(
            SLAReportSchedule.organization_id == org_id,
        )
        total = (
            await self.db.execute(select(func.count()).select_from(base.subquery()))
        ).scalar() or 0

        q = base.order_by(SLAReportSchedule.created_at.desc()).offset(offset).limit(limit)
        result = await self.db.execute(q)
        return list(result.scalars().all()), total

    async def get_schedule(
        self, schedule_id: UUID, org_id: UUID | None = None
    ) -> SLAReportSchedule | None:
        filters = [SLAReportSchedule.id == schedule_id]
        if org_id is not None:
            filters.append(SLAReportSchedule.organization_id == org_id)
        result = await self.db.execute(select(SLAReportSchedule).where(*filters))
        return result.scalar_one_or_none()

    async def create_schedule(
        self,
        org_id: UUID,
        data: dict[str, Any],
        *,
        created_by: UUID | None = None,
    ) -> SLAReportSchedule:
        schedule = SLAReportSchedule(
            organization_id=org_id,
            name=data["name"],
            frequency=data.get("frequency", "monthly"),
            day_of_week=data.get("day_of_week"),
            day_of_month=data.get("day_of_month"),
            recipients=data.get("recipients", []),
            sla_policy_ids=data.get("sla_policy_ids", []),
            enabled=data.get("enabled", True),
            next_run_at=data.get("next_run_at"),
        )
        # Give it a first fire time.
        #
        # ``generate_scheduled`` selects on ``next_run_at <= now`` and skips
        # NULL, and the API does not collect next_run_at -- so every schedule
        # ever created was born NULL and could never come due. It appeared in
        # the list, said "enabled", and generated nothing. ``_compute_next_run``
        # already existed but only ran AFTER a report, which never happened.
        if schedule.next_run_at is None:
            schedule.next_run_at = self._compute_next_run(schedule, datetime.now(UTC))
        if created_by and hasattr(schedule, "created_by"):
            schedule.created_by = created_by
        self.db.add(schedule)
        await self.db.flush()
        return schedule

    async def update_schedule(
        self,
        schedule_id: UUID,
        data: dict[str, Any],
        org_id: UUID | None = None,
    ) -> SLAReportSchedule | None:
        schedule = await self.get_schedule(schedule_id, org_id=org_id)
        if not schedule:
            return None

        allowed_fields = {
            "name",
            "frequency",
            "day_of_week",
            "day_of_month",
            "recipients",
            "sla_policy_ids",
            "enabled",
            "next_run_at",
        }
        retimed = any(k in {"frequency", "day_of_week", "day_of_month"} for k in data)
        for key, value in data.items():
            if key in allowed_fields:
                setattr(schedule, key, value)

        # Changing the cadence has to move the next fire time, or the edit is
        # cosmetic. Also recompute when a schedule is re-enabled or has never
        # had one -- the second case heals rows created before schedules got a
        # first fire time at all.
        if schedule.next_run_at is None or retimed or data.get("enabled") is True:
            schedule.next_run_at = self._compute_next_run(schedule, datetime.now(UTC))

        await self.db.flush()
        return schedule

    async def delete_schedule(self, schedule_id: UUID, org_id: UUID) -> bool:
        schedule = await self.get_schedule(schedule_id, org_id=org_id)
        if not schedule:
            return False
        await self.db.delete(schedule)
        await self.db.flush()
        return True

    # ──────────────────────────────────────────────────────────────────────
    # Scheduled Report Generation (cron / task runner)
    # ──────────────────────────────────────────────────────────────────────

    async def generate_scheduled(self) -> list[SLAReport]:
        """
        Check all report schedules whose ``next_run_at`` is in the past
        and generate the corresponding reports.

        Called by a periodic task (e.g. Celery beat, APScheduler).

        Returns the list of newly generated reports.
        """
        now = datetime.now(UTC)

        q = select(SLAReportSchedule).where(
            SLAReportSchedule.enabled.is_(True),
            SLAReportSchedule.next_run_at.isnot(None),
            SLAReportSchedule.next_run_at <= now,
        )
        due_schedules = list((await self.db.execute(q)).scalars().all())

        reports: list[SLAReport] = []

        for schedule in due_schedules:
            try:
                # Determine period based on frequency
                if schedule.frequency == "weekly":
                    period_start = now - timedelta(weeks=1)
                elif schedule.frequency == "quarterly":
                    period_start = now - timedelta(days=90)
                else:  # monthly (default)
                    period_start = now - timedelta(days=30)

                # Convert stored policy IDs (strings in JSONB) to UUIDs
                policy_ids = None
                if schedule.sla_policy_ids:
                    from uuid import UUID as _UUID

                    try:
                        policy_ids = [_UUID(str(pid)) for pid in schedule.sla_policy_ids]
                    except (ValueError, TypeError):
                        policy_ids = None

                report = await self.generate_report(
                    org_id=schedule.organization_id,
                    period_start=period_start,
                    period_end=now,
                    policy_ids=policy_ids,
                    title=f"{schedule.name} — {now.strftime('%Y-%m-%d')}",
                )
                reports.append(report)

                # Update schedule timestamps
                schedule.last_generated_at = now
                schedule.next_run_at = self._compute_next_run(schedule, now)
            except Exception:
                logger.exception("Failed to generate scheduled report %s", schedule.id)
                continue

        if reports:
            await self.db.flush()
            logger.info("Generated %d scheduled SLA reports", len(reports))

        return reports

    @staticmethod
    def _compute_next_run(
        schedule: SLAReportSchedule,
        from_dt: datetime,
    ) -> datetime:
        """Compute the next run timestamp based on frequency."""
        if schedule.frequency == "weekly":
            return from_dt + timedelta(weeks=1)
        elif schedule.frequency == "quarterly":
            return from_dt + timedelta(days=90)
        else:  # monthly
            return from_dt + timedelta(days=30)

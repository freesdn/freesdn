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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core.dependencies import CurrentUser
from app.core.site_access import current_user_var, site_ids_for_request
from app.models.sla import (
    SLABreach,
    SLAPolicy,
    SLAPolicyScope,
    SLAReport,
    SLAReportSchedule,
    SLASnapshot,
)
from app.services.sla import SLAMonitoringService
from app.services.sla_calendar import ReportCalendar, ScheduleTimingError
from app.services.sla_report_delivery import (
    ReportDeliveryError,
    authorize_delivery_epoch,
    capture_delivery_approval,
    enqueue_notices,
)
from app.services.sla_report_pdf import write_sla_pdf
from app.services.sla_schedule_authorization import (
    ScheduleAuthorizationError,
    authorize_schedule,
    capture_schedule_approval,
)

logger = logging.getLogger(__name__)

REPORTS_BASE_DIR = os.environ.get("SLA_REPORTS_DIR", "/data/sla_reports")


class SLAReportRenderError(RuntimeError):
    """The report data was computed but could not be written to disk.

    Raised instead of publishing a report record whose file is missing or
    incomplete. See ``generate_report`` step 6.
    """


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
          5. Build the report record.
          6. Render it to disk, then persist the record.

        Raises ``SLAReportRenderError`` if the render fails: nothing is written
        to the session, so a storage failure cannot leave a downloadable-looking
        report behind that serves JSON in place of the format it advertises.

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
        if policy_ids is not None:
            policy_q = policy_q.where(SLAPolicy.id.in_(policy_ids))

        # Per-user site grant: a site-limited caller may only report on policies
        # that are org-level or anchored to a site they were granted. Without
        # this, passing a sibling-site ``policy_ids`` would exfiltrate that
        # site's compliance + breach history. ``site_ids_for_request()`` reads
        # the request contextvar (no-op for unrestricted / scheduled runs).
        predicate = SLAMonitoringService._policy_grant_predicate()
        if predicate is not None:
            policy_q = policy_q.where(predicate)

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

        # Use the exact resolved policy query even when it selects nothing.
        # An explicit unmatched filter must never widen into all org policies.
        policy_subquery = policy_q.with_only_columns(SLAPolicy.id)

        # Breaches overlap the half-open reporting interval. An outage that
        # started earlier but continued into this period still belongs here.
        # Aggregate in PostgreSQL. Loading every breach also loads its notes and
        # context JSON into the API/worker just to count two small categories.
        # Historical reporting must not make application memory grow with all
        # matching incident payloads. Keep the same tenant, grant and interval
        # predicates on the grouped query.
        breach_q = (
            select(SLABreach.severity, SLABreach.status, func.count().label("breach_count"))
            .where(
                SLABreach.organization_id == org_id,
                SLABreach.policy_id.in_(policy_subquery),
                SLABreach.started_at < period_end,
                or_(SLABreach.resolved_at.is_(None), SLABreach.resolved_at > period_start),
            )
            .group_by(SLABreach.severity, SLABreach.status)
        )
        breach_counts = (await self.db.execute(breach_q)).all()
        breach_summary: dict[str, Any] = {
            "total": 0,
            "by_severity": {},
            "by_status": {},
        }
        for b in breach_counts:
            breach_summary["total"] += b.breach_count
            breach_summary["by_severity"][b.severity] = (
                breach_summary["by_severity"].get(b.severity, 0) + b.breach_count
            )
            breach_summary["by_status"][b.status] = (
                breach_summary["by_status"].get(b.status, 0) + b.breach_count
            )

        snapshot_q = select(
            func.avg(SLASnapshot.compliance_percent).label("avg_compliance"),
            func.min(SLASnapshot.compliance_percent).label("min_compliance"),
            func.max(SLASnapshot.compliance_percent).label("max_compliance"),
            func.count().label("snapshot_count"),
        ).where(
            SLASnapshot.recorded_at >= period_start,
            SLASnapshot.recorded_at < period_end,
            SLASnapshot.policy_id.in_(policy_subquery),
        )

        snap_row = (await self.db.execute(snapshot_q)).one()

        compliance_summary = {
            "avg_compliance_percent": (
                round(snap_row.avg_compliance, 2) if snap_row.avg_compliance is not None else None
            ),
            "min_compliance_percent": (
                round(snap_row.min_compliance, 2) if snap_row.min_compliance is not None else None
            ),
            "max_compliance_percent": (
                round(snap_row.max_compliance, 2) if snap_row.max_compliance is not None else None
            ),
            "snapshot_count": snap_row.snapshot_count or 0,
        }

        # 4. Build report data
        report_data = {
            # A stored aggregate cannot be narrowed later. Capture its original
            # site scope so readers with reduced grants cannot retrieve it.
            "access_scope": {
                "version": 1,
                "site_ids": await self._report_site_scope(policies),
            },
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "policies": policy_summary,
            "breaches": breach_summary,
            "compliance": compliance_summary,
        }

        # 5. Build the row (persisted at step 6, only if the render succeeds)
        if not title:
            start_str = period_start.strftime("%Y-%m-%d")
            end_str = period_end.strftime("%Y-%m-%d")
            title = f"SLA Report {start_str} to {end_str}"

        report = SLAReport(
            # Assigned here rather than by the column default at INSERT, because
            # step 6 renders the file NAMED after this id and must run before the
            # row exists — see below.
            id=uuid4(),
            organization_id=org_id,
            title=title,
            period_start=period_start,
            period_end=period_end,
            format=report_format,
            report_data=report_data,
            generated_by=generated_by,
            generated_at=datetime.now(UTC),
        )

        # 6. Render to file (CSV or PDF) BEFORE the row is added.
        #
        # This used to be `db.add()` + `flush()` and then a render wrapped in
        # `except Exception: logger.exception(...)`. Any storage failure at the
        # sink — a full disk, a read-only volume, a root-owned mountpoint — was
        # swallowed, so the row was committed with file_path NULL and the
        # download endpoint's `if report.file_path:` branch fell through to
        # `return {... "report_data": ...}`: a request for `format="csv"` got
        # application/json with a 200 and no error anywhere. Worse in
        # `generate_scheduled`, which catches per schedule and continues: the
        # already-flushed row rode the caller's commit into the catalogue as a
        # finished report that can never be downloaded as the format it claims.
        #
        # Rendering first means a failed render adds nothing to the session, so
        # neither caller can publish a phantom report, and the error reaches the
        # operator instead of the log.
        await self._render_to_file(report, report_data)
        try:
            self.db.add(report)
            await self.db.flush()
        except Exception:
            if report.file_path:
                Path(report.file_path).unlink(missing_ok=True)
            raise

        logger.info(
            "Generated SLA report '%s' (%s) for org %s — %d policies, %d breaches",
            title,
            report_format,
            org_id,
            len(policies),
            breach_summary["total"],
        )
        return report

    # ──────────────────────────────────────────────────────────────────────
    # File Rendering
    # ──────────────────────────────────────────────────────────────────────

    async def _render_to_file(self, report: SLAReport, report_data: dict[str, Any]) -> None:
        """Render report data to a real CSV or PDF file.

        Raises ``SLAReportRenderError`` on any storage failure. The bare OSError
        the standard library raises here says only "[Errno 30] Read-only file
        system"; wrapping it names the report, the format and the sink, which is
        what an operator needs to fix the mount.
        """
        base = Path(REPORTS_BASE_DIR)
        org_dir = base / str(report.organization_id)
        filename = f"sla_report_{report.id}"
        if report.format not in {"csv", "pdf"}:
            raise SLAReportRenderError(f"Unsupported SLA report format: {report.format}")
        filepath = org_dir / f"{filename}.{report.format}"

        try:
            base.mkdir(parents=True, exist_ok=True)
            org_dir.mkdir(parents=True, exist_ok=True)

            if report.format == "csv":
                await run_in_threadpool(self._write_csv, filepath, report_data)
            else:
                await run_in_threadpool(write_sla_pdf, filepath, report_data, report.title)

            file_size = filepath.stat().st_size
            report.file_path = str(filepath)
            report.file_size = file_size
        except Exception as exc:
            # A write that died part-way (ENOSPC is the common one) leaves a
            # truncated file under an id no row will ever reference, on a disk
            # that is by definition already short. Best-effort sweep; never let
            # the cleanup mask the real error.
            try:
                filepath.unlink(missing_ok=True)
            except OSError:
                logger.debug("could not remove partial SLA render %s", filepath)
            raise SLAReportRenderError(
                f"could not write the {report.format} render of SLA report "
                f"{report.id} to {filepath}: {exc}"
            ) from exc

    def _write_csv(self, filepath: Path, data: dict[str, Any]) -> None:
        """Write SLA report data as CSV."""
        with open(filepath, "w", newline="", encoding="utf-8") as f:
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
        granted = site_ids_for_request()
        if granted is not None:
            scope = SLAReport.report_data["access_scope"]
            base = base.where(
                scope.contains({"version": 1}),
                func.jsonb_typeof(scope["site_ids"]) == "array",
                scope["site_ids"].contained_by([str(site_id) for site_id in granted]),
            )
        total = (
            await self.db.execute(select(func.count()).select_from(base.subquery()))
        ).scalar() or 0

        q = base.order_by(SLAReport.generated_at.desc()).offset(offset).limit(limit)
        result = await self.db.execute(q)
        return list(result.scalars().all()), total

    async def get_report(self, report_id: UUID) -> SLAReport | None:
        result = await self.db.execute(select(SLAReport).where(SLAReport.id == report_id))
        report = result.scalar_one_or_none()
        granted = site_ids_for_request()
        if report is not None and granted is not None:
            scope = report.report_data.get("access_scope", {})
            if not isinstance(scope, dict) or scope.get("version") != 1:
                return None  # Legacy aggregates have no trustworthy scope; regenerate.
            site_ids = scope.get("site_ids")
            if not isinstance(site_ids, list) or any(
                not isinstance(site_id, str) or site_id not in {str(s) for s in granted}
                for site_id in site_ids
            ):
                return None
        return report

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
        accessible = await self._accessible_schedule_policy_ids(org_id)
        if accessible is not None:
            base = base.where(
                func.jsonb_typeof(SLAReportSchedule.sla_policy_ids) == "array",
                SLAReportSchedule.sla_policy_ids != [],
                SLAReportSchedule.sla_policy_ids.contained_by(accessible),
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
        accessible = await self._accessible_schedule_policy_ids(org_id)
        if accessible is not None:
            filters.extend(
                [
                    func.jsonb_typeof(SLAReportSchedule.sla_policy_ids) == "array",
                    SLAReportSchedule.sla_policy_ids != [],
                    SLAReportSchedule.sla_policy_ids.contained_by(accessible),
                ]
            )
        result = await self.db.execute(select(SLAReportSchedule).where(*filters))
        return result.scalar_one_or_none()

    async def create_schedule(
        self,
        org_id: UUID,
        data: dict[str, Any],
        *,
        created_by: UUID | None = None,
        current_user: CurrentUser | None = None,
    ) -> SLAReportSchedule:
        schedule = SLAReportSchedule(
            organization_id=org_id,
            name=data["name"],
            frequency=data.get("frequency", "monthly"),
            day_of_week=data.get("day_of_week"),
            day_of_month=data.get("day_of_month"),
            timezone=data.get("timezone", "UTC"),
            time_of_day=data.get("time_of_day", "09:00"),
            recipients=data.get("recipients", []),
            delivery_enabled=data.get("delivery_enabled", False),
            delivery_provider_id=data.get("delivery_provider_id"),
            sla_policy_ids=[str(pid) for pid in data.get("sla_policy_ids", [])],
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
        if current_user is not None:
            schedule.execution_scope = await capture_schedule_approval(
                self.db, current_user, org_id, schedule.sla_policy_ids
            )
        self.db.add(schedule)
        await self.db.flush()
        await capture_delivery_approval(self.db, schedule)
        await self.db.flush()
        return schedule

    async def update_schedule(
        self,
        schedule_id: UUID,
        data: dict[str, Any],
        org_id: UUID | None = None,
        *,
        current_user: CurrentUser | None = None,
    ) -> SLAReportSchedule | None:
        schedule = await self.get_schedule(schedule_id, org_id=org_id)
        if not schedule:
            return None

        allowed_fields = {
            "name",
            "frequency",
            "day_of_week",
            "day_of_month",
            "timezone",
            "time_of_day",
            "recipients",
            "delivery_enabled",
            "delivery_provider_id",
            "sla_policy_ids",
            "enabled",
            "next_run_at",
        }
        retimed = any(
            k in {"frequency", "day_of_week", "day_of_month", "timezone", "time_of_day"}
            for k in data
        )
        for key, value in data.items():
            if key in allowed_fields:
                if key == "sla_policy_ids":
                    value = [str(pid) for pid in value]
                setattr(schedule, key, value)

        # Changing the cadence has to move the next fire time, or the edit is
        # cosmetic. Also recompute when a schedule is re-enabled or has never
        # had one -- the second case heals rows created before schedules got a
        # first fire time at all.
        if data.get("next_run_at") is None and (
            schedule.next_run_at is None or retimed or data.get("enabled") is True
        ):
            schedule.next_run_at = self._compute_next_run(schedule, datetime.now(UTC))

        if current_user is not None:
            schedule.execution_scope = await capture_schedule_approval(
                self.db, current_user, schedule.organization_id, schedule.sla_policy_ids
            )
            schedule.execution_error = None
            schedule.updated_by = current_user.id
        if schedule.delivery_enabled and current_user is None:
            raise ReportDeliveryError("delivery_approval_required")
        await capture_delivery_approval(self.db, schedule)
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

        q = (
            select(SLAReportSchedule)
            .where(
                SLAReportSchedule.enabled.is_(True),
                SLAReportSchedule.next_run_at.isnot(None),
                SLAReportSchedule.next_run_at <= now,
            )
            .order_by(SLAReportSchedule.next_run_at, SLAReportSchedule.id)
            .limit(100)
            .with_for_update(skip_locked=True)
        )
        due_schedules = list((await self.db.execute(q)).scalars().all())
        reports: list[SLAReport] = []

        for schedule in due_schedules:
            schedule_id = schedule.id
            token = current_user_var.set(None)
            try:
                # Roll back this schedule's DB error before continuing. Row locks
                # remain held until the caller commits report + next-run together.
                async with self.db.begin_nested():
                    authorize_delivery_epoch(schedule)
                    actor = await authorize_schedule(self.db, schedule)
                    current_user_var.set(actor)
                    calendar = ReportCalendar.from_schedule(schedule)
                    period_start, period_end = calendar.report_period(now)
                    next_run = calendar.next_run(now)
                    policy_ids = (
                        [UUID(str(pid)) for pid in schedule.sla_policy_ids]
                        if schedule.sla_policy_ids
                        else None
                    )
                    report = await self.generate_report(
                        org_id=schedule.organization_id,
                        period_start=period_start,
                        period_end=period_end,
                        policy_ids=policy_ids,
                        title=f"{schedule.name[:242]} — {now.strftime('%Y-%m-%d')}",
                        generated_by=actor.id,
                    )
                    await enqueue_notices(self.db, schedule, report)
                    schedule.last_generated_at = now
                    schedule.next_run_at = next_run
                    schedule.execution_error = None
                reports.append(report)
            except (ScheduleAuthorizationError, ScheduleTimingError, ReportDeliveryError) as exc:
                # A disabled account or lost scope is not a transient render
                # error. Pause until an authorized operator reviews and enables.
                await self.db.refresh(schedule)
                schedule.enabled = False
                schedule.execution_error = str(exc)
                await self.db.flush()
                logger.warning("SLA schedule %s paused: %s", schedule_id, exc)
            except Exception:
                await self.db.refresh(schedule)
                schedule.execution_error = "generation_failed"
                await self.db.flush()
                logger.exception("Failed to generate scheduled report %s", schedule_id)
            finally:
                current_user_var.reset(token)

        if reports:
            logger.info("Generated %d scheduled SLA reports", len(reports))
        return reports

    @staticmethod
    def _compute_next_run(
        schedule: SLAReportSchedule,
        from_dt: datetime,
    ) -> datetime:
        """Compute the next occurrence in the configured local calendar."""
        return ReportCalendar.from_schedule(schedule).next_run(from_dt)

    async def _report_site_scope(self, policies: list[SLAPolicy]) -> list[str]:
        """Capture owning sites now; later resource moves must not widen access."""
        from app.models.enterprise import DeviceGroup
        from app.modules.cameras.models import NVR, Camera

        sites = {str(p.scope_id) for p in policies if p.scope == SLAPolicyScope.SITE.value}
        supported = {"organization", "ssid", "site", "device_group", "camera", "nvr"}
        if any(p.scope not in supported for p in policies):
            sites.add("unresolved")  # Multi-site or unknown scope: admin-only archive.
        models: list[tuple[str, type[DeviceGroup] | type[Camera] | type[NVR]]] = [
            ("device_group", DeviceGroup),
            ("camera", Camera),
            ("nvr", NVR),
        ]
        for scope, model in models:
            ids = {p.scope_id for p in policies if p.scope == scope}
            if not ids:
                continue
            rows = (
                await self.db.execute(select(model.id, model.site_id).where(model.id.in_(ids)))
            ).all()
            sites.update(str(row.site_id) for row in rows)
            if len(rows) != len(ids):
                sites.add("unresolved")
        return sorted(sites)

    async def _accessible_schedule_policy_ids(self, org_id: UUID | None) -> list[str] | None:
        predicate = SLAMonitoringService._policy_grant_predicate()
        if predicate is None:
            return None
        query = select(SLAPolicy.id).where(SLAPolicy.organization_id == org_id, predicate)
        return [str(policy_id) for policy_id in (await self.db.execute(query)).scalars().all()]

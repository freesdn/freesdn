# mypy: ignore-errors
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Security Audit Celery Tasks
===========================================

Background tasks for the enhanced security audit module:
- scan_brute_force: Detect brute-force attempts and auto-block IPs
- expire_ip_blocks: Expire old IP blocks
- cleanup_audit_data: Purge old audit/security data per retention policy
- generate_anomaly_report: Periodic anomaly detection sweep
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import CelerySessionLocal as AsyncSessionLocal
from app.tasks.base import FreeSDNTask

logger = logging.getLogger(__name__)


# =============================================================================
# Brute-Force Detection
# =============================================================================


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="security.scan_brute_force",
    soft_time_limit=120,
    time_limit=180,
)
def scan_brute_force(self) -> dict[str, Any]:
    """
    Scan recent failed logins and auto-block IPs that exceed the threshold.
    Runs every 5 minutes.
    """

    async def _run() -> dict[str, Any]:
        from sqlalchemy import func, select

        from app.models.security_audit import FailedLoginRecord
        from app.services.security_audit import (
            BRUTE_FORCE_MAX_ATTEMPTS,
            BRUTE_FORCE_WINDOW_MINUTES,
        )
        from app.services.security_audit import (
            PersistentSecurityAuditService as svc,
        )

        blocked_count = 0
        checked_count = 0

        async with AsyncSessionLocal() as session:
            try:
                # Get IPs with recent failed logins
                since = datetime.now(UTC) - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
                ip_rows = (
                    await session.execute(
                        select(
                            FailedLoginRecord.ip_address,
                            func.count(FailedLoginRecord.id).label("cnt"),
                        )
                        .where(FailedLoginRecord.timestamp >= since)
                        .group_by(FailedLoginRecord.ip_address)
                        .having(func.count(FailedLoginRecord.id) >= BRUTE_FORCE_MAX_ATTEMPTS)
                    )
                ).all()

                checked_count = len(ip_rows)

                # Batch-fetch top targeted username per IP in a single query
                # to avoid N+1 sequential queries inside the loop.
                top_user_sub = (
                    select(
                        FailedLoginRecord.ip_address,
                        FailedLoginRecord.username,
                        func.count(FailedLoginRecord.id).label("cnt"),
                        func.row_number()
                        .over(
                            partition_by=FailedLoginRecord.ip_address,
                            order_by=func.count(FailedLoginRecord.id).desc(),
                        )
                        .label("rn"),
                    )
                    .where(FailedLoginRecord.timestamp >= since)
                    .group_by(
                        FailedLoginRecord.ip_address,
                        FailedLoginRecord.username,
                    )
                    .subquery()
                )
                top_user_rows = (
                    await session.execute(
                        select(top_user_sub.c.ip_address, top_user_sub.c.username).where(
                            top_user_sub.c.rn == 1
                        )
                    )
                ).all()
                ip_to_top_user: dict[str, str | None] = {r[0]: r[1] for r in top_user_rows}

                for row in ip_rows:
                    ip = row[0]
                    # Check if already blocked
                    if await svc.is_ip_blocked(session, ip):
                        continue

                    user_row = ip_to_top_user.get(ip)

                    block = await svc.auto_block_brute_force(session, ip, username=user_row)
                    if block:
                        blocked_count += 1

                await session.commit()
                logger.info(
                    "Brute force scan: checked %d IPs, blocked %d",
                    checked_count,
                    blocked_count,
                )
            except Exception as e:
                await session.rollback()
                logger.error("Brute force scan error: %s", e)
                return {"checked": checked_count, "blocked": blocked_count, "error": str(e)}

        return {
            "checked": checked_count,
            "blocked": blocked_count,
        }

    return asyncio.run(_run())


# =============================================================================
# IP Block Expiry
# =============================================================================


@celery_app.task(
    bind=True, base=FreeSDNTask, name="security.expire_ip_blocks", soft_time_limit=60, time_limit=90
)
def expire_ip_blocks(self) -> dict[str, Any]:
    """
    Expire IP blocks that have passed their expiry time.
    Runs every 15 minutes.
    """

    async def _run() -> dict[str, Any]:
        from app.services.security_audit import PersistentSecurityAuditService as svc

        async with AsyncSessionLocal() as session:
            try:
                expired = await svc.expire_ip_blocks(session)
                await session.commit()
                if expired:
                    logger.info("Expired %d IP blocks", expired)
                return {"expired": expired}
            except Exception as e:
                await session.rollback()
                logger.error("IP block expiry error: %s", e)
                return {"expired": 0, "error": str(e)}

    return asyncio.run(_run())


# =============================================================================
# Audit Data Cleanup
# =============================================================================


class AuditCleanupTask(FreeSDNTask):
    """A completed batch may still leave actionable retention work."""

    abstract = True

    def _success_message(self, retval: Any) -> str:
        progress = retval.get("retention") if isinstance(retval, dict) else None
        if not isinstance(progress, dict):
            return "Cleanup batch finished; retention status unavailable"
        if progress.get("blocked_prefix") is True:
            return "Cleanup batch committed; audit retention blocked. Review the retained prefix."
        if progress.get("more_available") is True:
            return "Cleanup batch committed; retention work remaining for the next scheduled batch"
        if progress.get("complete") is True:
            return "Cleanup batch committed; no eligible retention work remained at the check"
        return "Cleanup batch finished; retention status unavailable"


@celery_app.task(
    bind=True,
    base=AuditCleanupTask,
    name="security.cleanup_audit_data",
    soft_time_limit=120,
    time_limit=180,
)
def cleanup_audit_data(self) -> dict[str, Any]:
    """Commit one bounded batch; report remaining work for the next Beat tick.

    A successful batch is not necessarily completed retention. Repeated worker
    deliveries operate on committed database state, with no chained broker
    message required for continuation. A commit transport error can be uncertain;
    do not infer that an exception proves nothing committed.
    """

    async def _run() -> dict[str, Any]:
        from sqlalchemy import text

        from app.core.metrics import audit_retention_batches_total
        from app.services.audit_retention import retention_progress
        from app.services.security_audit import PersistentSecurityAuditService as svc

        async with AsyncSessionLocal() as session:
            try:
                async with asyncio.timeout(90):
                    await session.execute(text("SET LOCAL lock_timeout = '5s'"))
                    await session.execute(text("SET LOCAL statement_timeout = '10s'"))
                    cutoff = datetime.now(UTC) - timedelta(days=90)
                    totals = await svc.cleanup_old_entries(session, cutoff=cutoff)
                    progress = await retention_progress(session, cutoff)
                    await session.commit()
            except Exception as exc:
                await session.rollback()
                audit_retention_batches_total.labels(outcome="failed").inc()
                logger.error("Audit cleanup batch failed (%s)", type(exc).__name__)
                raise RuntimeError(
                    "Audit cleanup did not complete; inspect the last committed batch"
                ) from None
            outcome = (
                "blocked"
                if progress["blocked_prefix"]
                else "incomplete"
                if progress["more_available"]
                else "complete"
            )
            audit_retention_batches_total.labels(outcome=outcome).inc()
            log = logger.info if progress["complete"] else logger.warning
            log("Audit cleanup batch %s: deleted=%s retention=%s", outcome, totals, progress)
            return {**totals, "retention": progress}

    return asyncio.run(_run())


# =============================================================================
# Anomaly Detection Sweep
# =============================================================================


@celery_app.task(
    bind=True,
    base=FreeSDNTask,
    name="security.detect_anomalies",
    soft_time_limit=120,
    time_limit=180,
)
def detect_anomalies(self) -> dict[str, Any]:
    """
    Periodic anomaly detection sweep.
    Looks for unusual patterns in recent security events.
    Runs every 30 minutes.
    """

    async def _run() -> dict[str, Any]:
        from sqlalchemy import func, select

        from app.models.security_audit import (
            FailedLoginRecord,
            SecurityEventRecord,
        )
        from app.services.security_audit import PersistentSecurityAuditService as svc

        anomalies_created = 0

        async with AsyncSessionLocal() as session:
            try:
                now = datetime.now(UTC)
                check_window = now - timedelta(hours=1)

                # --- Check 1: Unusual number of failed logins per user ---
                user_fail_rows = (
                    await session.execute(
                        select(
                            FailedLoginRecord.username,
                            func.count(FailedLoginRecord.id).label("cnt"),
                        )
                        .where(FailedLoginRecord.timestamp >= check_window)
                        .group_by(FailedLoginRecord.username)
                        .having(func.count(FailedLoginRecord.id) >= 5)
                    )
                ).all()

                for row in user_fail_rows:
                    username, count = row[0], row[1]
                    await svc.create_anomaly(
                        session,
                        anomaly_type="excessive_failed_logins",
                        title=f"Excessive failed logins for {username}",
                        severity="medium" if count < 10 else "high",
                        description=(
                            f"{count} failed login attempts for user '{username}' in the last hour."
                        ),
                        evidence={
                            "username": username,
                            "attempt_count": count,
                            "window_minutes": 60,
                        },
                        risk_score=min(90, 40 + count * 5),
                    )
                    anomalies_created += 1

                # --- Check 2: High-risk events without review ---
                unreviewed_high = (
                    await session.execute(
                        select(func.count(SecurityEventRecord.id)).where(
                            SecurityEventRecord.timestamp >= check_window,
                            SecurityEventRecord.severity.in_(["high", "critical"]),
                            SecurityEventRecord.reviewed == False,  # noqa: E712
                        )
                    )
                ).scalar_one()

                if unreviewed_high >= 5:
                    await svc.create_anomaly(
                        session,
                        anomaly_type="configuration_tampering",
                        title="Multiple unreviewed high-severity events",
                        severity="medium",
                        description=(
                            f"{unreviewed_high} high/critical security events "
                            f"in the last hour remain unreviewed."
                        ),
                        evidence={"unreviewed_count": unreviewed_high},
                        risk_score=60,
                    )
                    anomalies_created += 1

                # --- Check 3: Multiple IPs per user in short window ---
                multi_ip_rows = (
                    await session.execute(
                        select(
                            SecurityEventRecord.user_email,
                            func.count(func.distinct(SecurityEventRecord.ip_address)).label(
                                "ip_cnt"
                            ),
                        )
                        .where(
                            SecurityEventRecord.timestamp >= check_window,
                            SecurityEventRecord.user_email.isnot(None),
                            SecurityEventRecord.event_type == "login_success",
                        )
                        .group_by(SecurityEventRecord.user_email)
                        .having(func.count(func.distinct(SecurityEventRecord.ip_address)) >= 3)
                    )
                ).all()

                for row in multi_ip_rows:
                    email, ip_count = row[0], row[1]
                    await svc.create_anomaly(
                        session,
                        anomaly_type="impossible_travel",
                        title=f"Multiple IPs for {email}",
                        severity="medium",
                        user_email=email,
                        description=(
                            f"User '{email}' logged in from {ip_count} "
                            f"different IPs in the last hour."
                        ),
                        evidence={
                            "user_email": email,
                            "ip_count": ip_count,
                            "window_minutes": 60,
                        },
                        risk_score=55,
                    )
                    anomalies_created += 1

                await session.commit()
                logger.info("Anomaly detection: created %d anomalies", anomalies_created)
            except Exception as e:
                await session.rollback()
                logger.error("Anomaly detection error: %s", e)
                return {"anomalies_created": anomalies_created, "error": str(e)}

        return {"anomalies_created": anomalies_created}

    return asyncio.run(_run())

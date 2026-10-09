#!/usr/bin/env python3
"""Internal synthetic probe for check_report_recovery.py, never a repair CLI."""

if not __debug__:
    raise RuntimeError("Qualification must run without Python optimization")

import asyncio
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from pathlib import Path
from uuid import UUID, uuid4

from app.core.dependencies import CurrentUser
from app.db.session import async_session_factory, engine
from app.models.core import Organization, User
from app.models.notification import NotificationProviderRecord
from app.models.sla import SLAReport, SLAReportDelivery, SLAReportSchedule
from app.services import sla_reports
from app.services.sla_report_delivery import enqueue_notices, process_one
from app.services.sla_reports import SLAReportGenerator
from report_smtp_peer import start_peer
from sqlalchemy import select

STATE = Path("/tmp/report-recovery-state.json")
ARCHIVES = Path("/tmp/report-recovery-archives")
sla_reports.REPORTS_BASE_DIR = str(ARCHIVES)


async def seed():
    async with async_session_factory() as db:
        org = Organization(name="Synthetic recovery", slug=uuid4().hex)
        db.add(org)
        await db.flush()
        actor = User(
            organization_id=org.id,
            username=uuid4().hex,
            email="reader@example.test",
            hashed_password="not-a-login",
            role="org_admin",
            is_active=True,
        )
        provider = NotificationProviderRecord(
            organization_id=org.id,
            name="Private loopback TLS fixture",
            channel="email",
            provider_type="smtp",
            is_enabled=True,
            is_verified=True,
            rate_limit_per_hour=0,
            rate_limit_per_day=0,
            config={
                "host": "localhost",
                "port": 1587,
                "use_tls": True,
                "from_email": "sender@example.test",
            },
        )
        db.add_all([actor, provider])
        await db.flush()
        generator = SLAReportGenerator(db)
        schedule = await generator.create_schedule(
            org.id,
            {
                "name": "Synthetic report",
                "delivery_enabled": True,
                "delivery_provider_id": provider.id,
                "recipients": [actor.email],
            },
            current_user=CurrentUser(actor, ["*"]),
        )
        report = await generator.generate_report(
            org.id,
            datetime.now(UTC) - timedelta(days=1),
            datetime.now(UTC),
            report_format="csv",
        )
        await enqueue_notices(db, schedule, report)
        notice = await db.scalar(
            select(SLAReportDelivery).where(SLAReportDelivery.report_id == report.id)
        )
        assert notice.state == "pending" and notice.attempts == 0
        await db.commit()
        state = {
            "org": str(org.id),
            "actor": str(actor.id),
            "schedule": str(schedule.id),
            "report": str(report.id),
            "delivery": str(notice.id),
            "archive_sha256": hashlib.sha256(
                Path(report.file_path).read_bytes()
            ).hexdigest(),
            "approval_revision": notice.approval_revision,
        }
        STATE.write_text(json.dumps(state))
        STATE.chmod(0o600)


async def assert_original(state, expected, attempts):
    async with async_session_factory() as db:
        row = await db.get(SLAReportDelivery, UUID(state["delivery"]))
        assert row.state == expected and row.attempts == attempts
        assert row.approval_revision == state["approval_revision"]
        assert str(row.report_id) == state["report"]
        if expected == "unknown":
            assert row.error_code == "delivery_recovery_review_required"
        report = await db.get(SLAReport, row.report_id)
        assert (
            hashlib.sha256(Path(report.file_path).read_bytes()).hexdigest()
            == state["archive_sha256"]
        )


async def main():
    mode = sys.argv[1]
    peer = start_peer(Path("/tmp"))
    try:
        if mode == "seed":
            await seed()
        else:
            state = json.loads(STATE.read_text())
            if mode == "send":
                await assert_original(state, "pending", 0)
                assert await process_one(async_session_factory)
                await assert_original(state, "accepted", 1)
                assert len(peer.messages) == 1
                message = BytesParser(policy=policy.default).parsebytes(
                    peer.messages[0]
                )
                assert (
                    message["Message-ID"]
                    == f"<sla-report-{state['delivery']}@freesdn.invalid>"
                )
            elif mode == "quarantine":
                await assert_original(state, "pending", 0)
                assert await process_one(async_session_factory)
                await assert_original(state, "unknown", 0)
                assert not peer.messages
                async with async_session_factory() as db:
                    schedule = await db.get(SLAReportSchedule, UUID(state["schedule"]))
                    schedule.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
                    await db.commit()
                    assert await SLAReportGenerator(db).generate_scheduled() == []
                    assert not schedule.enabled
                    assert schedule.execution_error in {
                        "delivery_reapproval_required",
                        "delivery_epoch_required",
                    }
                    await db.commit()
            elif mode == "reapprove":
                await assert_original(state, "unknown", 0)
                async with async_session_factory() as db:
                    actor = await db.get(User, UUID(state["actor"]))
                    generator = SLAReportGenerator(db)
                    schedule = await generator.update_schedule(
                        UUID(state["schedule"]),
                        {"enabled": True},
                        org_id=UUID(state["org"]),
                        current_user=CurrentUser(actor, ["*"]),
                    )
                    report = await generator.generate_report(
                        UUID(state["org"]),
                        datetime.now(UTC) - timedelta(days=1),
                        datetime.now(UTC),
                        report_format="csv",
                    )
                    await enqueue_notices(db, schedule, report)
                    await db.commit()
                assert await process_one(async_session_factory)
                assert len(peer.messages) == 1
                message = BytesParser(policy=policy.default).parsebytes(
                    peer.messages[0]
                )
                assert (
                    message["Message-ID"]
                    != f"<sla-report-{state['delivery']}@freesdn.invalid>"
                )
                await assert_original(state, "unknown", 0)
            elif mode == "restart":
                await assert_original(state, "unknown", 0)
                assert not await process_one(async_session_factory)
                assert not peer.messages
            else:
                raise ValueError("Unknown synthetic probe mode")
        print(
            "REPORT_RECOVERY_RESULT="
            + json.dumps(
                {
                    "passed": True,
                    "mode": mode,
                    "smtp_accepted": len(peer.messages),
                    "transport": "real loopback SMTP with verified STARTTLS",
                }
            )
        )
    finally:
        peer.close()
        await engine.dispose()


asyncio.run(main())

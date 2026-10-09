# SPDX-License-Identifier: AGPL-3.0-only
"""Authorized, opt-in SLA report notices backed by a PostgreSQL outbox."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.dependencies import CurrentUser, _load_user_permissions
from app.models.core import User
from app.models.notification import NotificationPreference, NotificationProviderRecord
from app.models.sla import SLAPolicy, SLAReport, SLAReportDelivery, SLAReportSchedule
from app.services.notification import (
    NotificationPreferences,
    NotificationService,
    SMTPProvider,
    _validate_email_address,
)
from app.services.sla_report_mail import send_notice
from app.services.sla_schedule_authorization import ScheduleAuthorizationError, authorize_schedule


class ReportDeliveryError(ValueError):
    """A fixed, non-sensitive operator error code."""


def configured_delivery_epoch() -> UUID | None:
    value = settings.SLA_REPORT_DELIVERY_EPOCH
    return UUID(value) if value else None


def require_delivery_epoch() -> UUID:
    epoch = configured_delivery_epoch()
    if epoch is None:
        raise ReportDeliveryError("delivery_epoch_required")
    return epoch


def authorize_delivery_epoch(schedule: SLAReportSchedule) -> UUID | None:
    if not schedule.delivery_enabled:
        return None
    epoch = require_delivery_epoch()
    approval = schedule.delivery_approval
    if (
        not isinstance(approval, dict)
        or approval.get("version") != 2
        or approval.get("delivery_epoch") != str(epoch)
    ):
        raise ReportDeliveryError("delivery_reapproval_required")
    return epoch


def report_origin() -> str:
    value = settings.FRONTEND_URL
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
            or any(c.isspace() or ord(c) < 32 for c in value)
        ):
            raise ValueError
        _ = parsed.port  # Reject malformed ports.
    except ValueError:
        raise ReportDeliveryError("https_frontend_origin_required") from None
    return value.rstrip("/")


def provider_fingerprint(record: NotificationProviderRecord) -> str:
    # Store only a digest, never provider configuration in approvals/outbox.
    return hashlib.sha256(
        json.dumps(
            [record.provider_type, record.config], sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


async def approved_provider(
    db: AsyncSession, schedule: SLAReportSchedule
) -> tuple[NotificationProviderRecord, SMTPProvider]:
    record = await db.scalar(
        select(NotificationProviderRecord)
        .where(
            NotificationProviderRecord.id == schedule.delivery_provider_id,
            NotificationProviderRecord.organization_id == schedule.organization_id,
            NotificationProviderRecord.channel == "email",
            NotificationProviderRecord.provider_type.in_(["smtp", "gmail_smtp"]),
            NotificationProviderRecord.is_enabled.is_(True),
            NotificationProviderRecord.is_verified.is_(True),
        )
        .execution_options(populate_existing=True)
    )
    if record is None:
        raise ReportDeliveryError("verified_smtp_provider_required")
    provider = NotificationService(db)._build_runtime_provider(record)
    if not isinstance(provider, SMTPProvider) or provider.use_tls is not True:
        raise ReportDeliveryError("verified_tls_required")
    try:
        _validate_email_address(provider.from_email or "")
    except ValueError:
        raise ReportDeliveryError("smtp_sender_invalid") from None
    return record, provider


async def recipient_principal(db: AsyncSession, org_id: UUID, user_id: UUID) -> CurrentUser:
    user = await db.scalar(
        select(User)
        .options(selectinload(User.site_access))
        .where(
            User.id == user_id,
            User.organization_id == org_id,
            User.is_active.is_(True),
            User.deleted_at.is_(None),
        )
        .execution_options(populate_existing=True)
    )
    if user is None:
        raise ReportDeliveryError("recipient_unavailable")
    principal = CurrentUser(
        user,
        await _load_user_permissions(user),
        accessible_site_ids={g.site_id for g in user.site_access},
    )
    if not principal.has_permission("config:read"):
        raise ReportDeliveryError("recipient_permission_revoked")
    return principal


def covers_sites(principal: CurrentUser, sites: list[str], ceiling: list[str] | None) -> bool:
    # For unattended email, removing the last grant must not restore unrestricted
    # authority through the interactive application's legacy zero-grant convention.
    live = None if principal.is_org_admin else {str(s) for s in principal.accessible_site_ids}
    return (ceiling is None or set(sites) <= set(ceiling)) and (live is None or set(sites) <= live)


async def capture_delivery_approval(db: AsyncSession, schedule: SLAReportSchedule) -> None:
    if not schedule.delivery_enabled or not schedule.enabled:
        schedule.delivery_approval = None
        return
    from app.services.sla_reports import SLAReportGenerator

    epoch = require_delivery_epoch()
    origin = report_origin()
    record, _ = await approved_provider(db, schedule)
    actor = await authorize_schedule(db, schedule)
    if not actor.has_permission("config:read"):
        raise ReportDeliveryError("actor_read_permission_required")
    addresses = schedule.recipients
    if not addresses or len(addresses) > 50:
        raise ReportDeliveryError("one_to_fifty_recipients_required")
    try:
        normalized = {_validate_email_address(a).casefold() for a in addresses}
    except (TypeError, ValueError):
        raise ReportDeliveryError("recipient_invalid") from None
    from sqlalchemy import func

    users = list(
        (
            await db.scalars(
                select(User).where(
                    User.organization_id == schedule.organization_id,
                    func.lower(User.email).in_(normalized),
                    User.is_active.is_(True),
                    User.deleted_at.is_(None),
                )
            )
        ).all()
    )
    if len(users) != len(normalized):
        # Deliberately does not identify which account is absent or inaccessible.
        raise ReportDeliveryError("recipients_must_be_authorized_org_users")
    policies_query = select(SLAPolicy).where(SLAPolicy.organization_id == schedule.organization_id)
    if schedule.sla_policy_ids:
        policies_query = policies_query.where(
            SLAPolicy.id.in_([UUID(p) for p in schedule.sla_policy_ids])
        )
    sites = await SLAReportGenerator(db)._report_site_scope(
        list((await db.scalars(policies_query)).all())
    )
    recipients: dict[str, Any] = {}
    for user in users:
        principal = await recipient_principal(db, schedule.organization_id, user.id)
        ceiling = (
            None
            if principal.is_org_admin
            else sorted(str(s) for s in principal.accessible_site_ids)
        )
        if not covers_sites(principal, sites, ceiling):
            raise ReportDeliveryError("recipients_must_be_authorized_org_users")
        recipients[str(user.id)] = {"email": user.email, "site_ids": ceiling}
    schedule.recipients = sorted(item["email"] for item in recipients.values())
    schedule.delivery_approval = {
        "version": 2,
        "delivery_epoch": str(epoch),
        "revision": str(uuid4()),
        "origin": origin,
        "provider_id": str(record.id),
        "provider_fingerprint": provider_fingerprint(record),
        "recipients": recipients,
    }


async def enqueue_notices(db: AsyncSession, schedule: SLAReportSchedule, report: SLAReport) -> None:
    if not schedule.delivery_enabled:
        return
    epoch = authorize_delivery_epoch(schedule)
    approval = schedule.delivery_approval
    if not isinstance(approval, dict):
        raise ReportDeliveryError("delivery_approval_required")
    for user_id, recipient in approval["recipients"].items():
        db.add(
            SLAReportDelivery(
                organization_id=schedule.organization_id,
                schedule_id=schedule.id,
                report_id=report.id,
                recipient_id=UUID(user_id),
                recipient_email=recipient["email"],
                approval_revision=approval["revision"],
                delivery_epoch=epoch,
            )
        )
    await db.flush()


async def authorize_notice(
    db: AsyncSession, delivery: SLAReportDelivery
) -> tuple[SMTPProvider, str]:
    schedule = await db.scalar(
        select(SLAReportSchedule)
        .where(
            SLAReportSchedule.id == delivery.schedule_id,
            SLAReportSchedule.organization_id == delivery.organization_id,
        )
        .execution_options(populate_existing=True)
    )
    if schedule is None or not schedule.enabled or not schedule.delivery_enabled:
        raise ReportDeliveryError("schedule_unavailable")
    authorize_delivery_epoch(schedule)
    approval = schedule.delivery_approval
    if (
        not isinstance(approval, dict)
        or approval.get("version") != 2
        or approval.get("revision") != delivery.approval_revision
    ):
        raise ReportDeliveryError("delivery_approval_changed")
    record, provider = await approved_provider(db, schedule)
    if str(record.id) != approval.get("provider_id") or provider_fingerprint(
        record
    ) != approval.get("provider_fingerprint"):
        raise ReportDeliveryError("provider_changed")
    origin = report_origin()
    if origin != approval.get("origin"):
        raise ReportDeliveryError("frontend_origin_changed")
    actor = await authorize_schedule(db, schedule)
    if not actor.has_permission("config:read"):
        raise ReportDeliveryError("actor_read_permission_required")
    report = await db.scalar(
        select(SLAReport).where(
            SLAReport.id == delivery.report_id,
            SLAReport.organization_id == delivery.organization_id,
        )
    )
    if report is None:
        raise ReportDeliveryError("report_unavailable")
    from app.services.sla_reports import REPORTS_BASE_DIR

    try:
        archive = Path(report.file_path or "").resolve()
        directory = (Path(REPORTS_BASE_DIR) / str(delivery.organization_id)).resolve()
        if (
            not archive.is_relative_to(directory)
            or not archive.is_file()
            or archive.stat().st_size != report.file_size
        ):
            raise ReportDeliveryError("report_file_unavailable")
    except OSError:
        raise ReportDeliveryError("report_file_unavailable") from None
    scope = report.report_data.get("access_scope", {})
    sites = scope.get("site_ids") if isinstance(scope, dict) and scope.get("version") == 1 else None
    if not isinstance(sites, list) or not all(isinstance(s, str) for s in sites):
        raise ReportDeliveryError("report_scope_invalid")
    if actor.is_site_limited and not set(sites) <= {str(s) for s in actor.accessible_site_ids}:
        raise ReportDeliveryError("actor_scope_revoked")
    recipient = approval.get("recipients", {}).get(str(delivery.recipient_id))
    if (
        not recipient
        or recipient.get("email") != delivery.recipient_email
        or delivery.recipient_id is None
    ):
        raise ReportDeliveryError("recipient_approval_changed")
    principal = await recipient_principal(db, delivery.organization_id, delivery.recipient_id)
    if principal.user.email != delivery.recipient_email or not covers_sites(
        principal, sites, recipient["site_ids"]
    ):
        raise ReportDeliveryError("recipient_scope_or_address_changed")
    return provider, f"{origin}/sla/reports?report={report.id}"


async def preference_action(db: AsyncSession, user_id: UUID | None, now: datetime) -> str | None:
    record = await db.scalar(
        select(NotificationPreference).where(NotificationPreference.user_id == user_id)
    )
    if record is None:
        return None
    # An explicitly empty channel list disables all email for this recipient.
    if "email" not in (record.enabled_channels or []):
        return "skipped"
    quiet = record.quiet_hours or {}
    prefs = NotificationPreferences(
        user_id=record.user_id,
        category_settings=record.category_settings or {},
        quiet_hours=(quiet["start"], quiet["end"]) if "start" in quiet and "end" in quiet else None,
    )
    if prefs.is_category_muted("reports")[0]:
        return "skipped"
    if prefs.is_in_quiet_hours(now):
        return "defer"
    return None


async def process_one(factory: async_sessionmaker[AsyncSession]) -> bool:
    """Commit before SMTP; report progress for claims or epoch quarantine batches."""
    now = datetime.now(UTC)
    async with factory() as db:
        epoch = configured_delivery_epoch()
        # Bound recovery work and skip concurrent claims. A restored pending row
        # may already have been accepted after the snapshot, even with attempts=0.
        # Do not call it cancelled, expired or safe to retry. Preserve its identity.
        untrusted = list(
            (
                await db.scalars(
                    select(SLAReportDelivery)
                    .where(
                        SLAReportDelivery.state.in_(["pending", "retry", "sending"]),
                        or_(
                            SLAReportDelivery.delivery_epoch.is_(None),
                            SLAReportDelivery.delivery_epoch != epoch,
                        )
                        if epoch
                        else true(),
                    )
                    .order_by(SLAReportDelivery.created_at, SLAReportDelivery.id)
                    .limit(100)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for row in untrusted:
            row.state, row.error_code = "unknown", "delivery_recovery_review_required"
            row.lease_expires_at = None
        await db.flush()
        if epoch is None:
            await db.commit()
            return bool(untrusted)
        # A crash at any point after claim may have submitted DATA. Never reclaim
        # these as retries; explicit reconciliation is required.
        interrupted = list(
            (
                await db.scalars(
                    select(SLAReportDelivery)
                    .where(
                        SLAReportDelivery.state == "sending",
                        SLAReportDelivery.delivery_epoch == epoch,
                        SLAReportDelivery.lease_expires_at <= now,
                    )
                    .order_by(SLAReportDelivery.lease_expires_at, SLAReportDelivery.id)
                    .limit(100)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for row in interrupted:
            row.state, row.error_code = "unknown", "worker_interrupted"
            row.lease_expires_at = None
        await db.flush()
        delivery = await db.scalar(
            select(SLAReportDelivery)
            .where(
                SLAReportDelivery.state.in_(["pending", "retry"]),
                SLAReportDelivery.delivery_epoch == epoch,
                SLAReportDelivery.next_attempt_at <= now,
            )
            .order_by(SLAReportDelivery.next_attempt_at, SLAReportDelivery.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if delivery is None:
            await db.commit()
            return bool(untrusted)
        delivery_id = delivery.id
        if delivery.attempts >= 5 or delivery.created_at < now - timedelta(days=7):
            delivery.state, delivery.error_code = "failed", "delivery_expired_or_exhausted"
            await db.commit()
            return True
        try:
            async with db.begin_nested():
                provider, url = await authorize_notice(db, delivery)
                action = await preference_action(db, delivery.recipient_id, now)
        except (ReportDeliveryError, ScheduleAuthorizationError) as exc:
            delivery.state, delivery.error_code = "cancelled", str(exc)
            await db.commit()
            return True
        except Exception:
            # A corrupt provider/approval/preference must not permanently block
            # every tenant behind this row. The savepoint also repairs DB errors.
            await db.refresh(delivery)
            delivery.state, delivery.error_code = "failed", "delivery_configuration_invalid"
            await db.commit()
            return True
        if action:
            delivery.state = "skipped" if action == "skipped" else "retry"
            delivery.error_code = "recipient_preferences"
            delivery.next_attempt_at = now + timedelta(minutes=15)
            await db.commit()
            return True
        limited = await NotificationService(db)._rate_limit_exceeded(provider, fail_closed=True)
        if limited:
            delivery.state, delivery.error_code = "retry", "provider_rate_limit_or_unavailable"
            delivery.next_attempt_at = now + timedelta(minutes=15)
            await db.commit()
            return True
        recipient = delivery.recipient_email
        delivery.attempts += 1
        delivery.state, delivery.error_code = "sending", None
        delivery.lease_expires_at = now + timedelta(minutes=10)
        await db.commit()

    outcome = await send_notice(
        provider, recipient, url, f"<sla-report-{delivery_id}@freesdn.invalid>"
    )
    async with factory() as db:
        delivery = await db.scalar(
            select(SLAReportDelivery)
            .where(
                SLAReportDelivery.id == delivery_id,
                SLAReportDelivery.state == "sending",
            )
            .with_for_update()
        )
        if delivery is not None:
            delivery.state, delivery.error_code = outcome.state, outcome.error_code
            delivery.lease_expires_at = None
            if outcome.state == "accepted":
                delivery.accepted_at = datetime.now(UTC)
            elif outcome.state == "retry":
                if delivery.attempts >= 5:
                    delivery.state, delivery.error_code = "failed", "retry_exhausted"
                else:
                    delivery.next_attempt_at = datetime.now(UTC) + timedelta(
                        minutes=15 * 2 ** (delivery.attempts - 1)
                    )
            await db.commit()
    return True

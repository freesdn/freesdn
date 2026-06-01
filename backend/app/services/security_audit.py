# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Persistent Security Audit Service
=================================================

DB-backed security audit service with:
- Audit log persistence and querying
- Security event persistence with risk scoring
- Failed login tracking and brute-force detection
- IP blocking management
- Security anomaly detection
- User/IP activity analysis
- Compliance report generation
- Data export (CSV/JSON)
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select, update

from app.core.security_utils import escape_like

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.security_audit import (
        AuditLogRecord,
        FailedLoginRecord,
        IPBlockRecord,
        SecurityAnomalyRecord,
        SecurityEventRecord,
    )

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

# Brute-force detection: max failed attempts in a time window
BRUTE_FORCE_MAX_ATTEMPTS = 10
BRUTE_FORCE_WINDOW_MINUTES = 15
# Default IP block duration (hours)
DEFAULT_BLOCK_DURATION_HOURS = 24
# Account lockout after N failed attempts per user
ACCOUNT_LOCKOUT_THRESHOLD = 5
ACCOUNT_LOCKOUT_WINDOW_MINUTES = 30


class PersistentSecurityAuditService:
    """
    DB-backed security audit service providing full audit logging,
    security event tracking, brute-force detection, IP blocking,
    anomaly detection, and compliance reporting.
    """

    # =========================================================================
    # Audit Logs
    # =========================================================================

    @staticmethod
    async def create_audit_log(
        session: AsyncSession,
        *,
        action: str,
        resource_type: str,
        timestamp: datetime | None = None,
        resource_id: str | None = None,
        resource_name: str | None = None,
        actor_id: str | None = None,
        actor_type: str = "user",
        actor_name: str | None = None,
        actor_email: str | None = None,
        organization_id: UUID | None = None,
        site_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        request_method: str | None = None,
        request_path: str | None = None,
        status: str = "success",
        response_code: int | None = None,
        response_time_ms: float | None = None,
        error_message: str | None = None,
        changes: dict[str, Any] | None = None,
        previous_state: dict[str, Any] | None = None,
        new_state: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLogRecord:
        """Create and persist an audit log entry."""
        from app.models.security_audit import AuditLogRecord

        record = AuditLogRecord(
            timestamp=timestamp or datetime.now(UTC),
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            actor_id=actor_id,
            actor_type=actor_type,
            actor_name=actor_name,
            actor_email=actor_email,
            organization_id=organization_id,
            site_id=site_id,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            request_id=request_id,
            request_method=request_method,
            request_path=request_path,
            status=status,
            response_code=response_code,
            response_time_ms=response_time_ms,
            error_message=error_message,
            changes=changes,
            previous_state=previous_state,
            new_state=new_state,
            tags=tags or [],
            metadata=metadata or {},
        )
        session.add(record)
        await session.flush()
        return record

    @staticmethod
    async def query_audit_logs(
        session: AsyncSession,
        *,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        actions: list[str] | None = None,
        resource_types: list[str] | None = None,
        resource_id: str | None = None,
        actor_id: str | None = None,
        status: str | None = None,
        organization_id: UUID | None = None,
        site_id: UUID | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[AuditLogRecord], int]:
        """Query audit logs with filters and pagination."""
        from app.models.security_audit import AuditLogRecord

        base = select(AuditLogRecord)
        count_base = select(func.count(AuditLogRecord.id))

        conditions = []
        if start_date:
            conditions.append(AuditLogRecord.timestamp >= start_date)
        if end_date:
            conditions.append(AuditLogRecord.timestamp <= end_date)
        if actions:
            conditions.append(AuditLogRecord.action.in_(actions))
        if resource_types:
            conditions.append(AuditLogRecord.resource_type.in_(resource_types))
        if resource_id:
            conditions.append(AuditLogRecord.resource_id == resource_id)
        if actor_id:
            conditions.append(AuditLogRecord.actor_id == actor_id)
        if status:
            conditions.append(AuditLogRecord.status == status)
        if organization_id:
            conditions.append(AuditLogRecord.organization_id == organization_id)
        if site_id:
            conditions.append(AuditLogRecord.site_id == site_id)
        if search:
            escaped = escape_like(search)
            like = f"%{escaped}%"
            conditions.append(
                or_(
                    AuditLogRecord.resource_name.ilike(like, escape="\\"),
                    AuditLogRecord.actor_name.ilike(like, escape="\\"),
                    AuditLogRecord.actor_email.ilike(like, escape="\\"),
                    AuditLogRecord.request_path.ilike(like, escape="\\"),
                )
            )

        if conditions:
            base = base.where(and_(*conditions))
            count_base = count_base.where(and_(*conditions))

        # Count
        total = (await session.execute(count_base)).scalar_one()

        # Paginated results
        offset = (page - 1) * page_size
        base = base.order_by(AuditLogRecord.timestamp.desc())
        base = base.offset(offset).limit(page_size)

        result = await session.execute(base)
        return list(result.scalars().all()), total

    @staticmethod
    async def get_audit_log(
        session: AsyncSession,
        log_id: UUID,
        *,
        organization_id: UUID | None = None,
    ) -> AuditLogRecord | None:
        """Get a single audit log by ID."""
        from app.models.security_audit import AuditLogRecord

        conditions = [AuditLogRecord.id == log_id]
        if organization_id:
            conditions.append(AuditLogRecord.organization_id == organization_id)
        result = await session.execute(select(AuditLogRecord).where(and_(*conditions)))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_resource_audit_logs(
        session: AsyncSession,
        resource_type: str,
        resource_id: str,
        limit: int = 50,
    ) -> list[AuditLogRecord]:
        """Get audit logs for a specific resource."""
        from app.models.security_audit import AuditLogRecord

        result = await session.execute(
            select(AuditLogRecord)
            .where(
                AuditLogRecord.resource_type == resource_type,
                AuditLogRecord.resource_id == resource_id,
            )
            .order_by(AuditLogRecord.timestamp.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_user_audit_logs(
        session: AsyncSession,
        user_id: str,
        limit: int = 50,
    ) -> list[AuditLogRecord]:
        """Get audit logs for a specific user/actor."""
        from app.models.security_audit import AuditLogRecord

        result = await session.execute(
            select(AuditLogRecord)
            .where(AuditLogRecord.actor_id == user_id)
            .order_by(AuditLogRecord.timestamp.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    # =========================================================================
    # Security Events
    # =========================================================================

    @staticmethod
    async def create_security_event(
        session: AsyncSession,
        *,
        event_type: str,
        category: str = "system",
        severity: str = "info",
        timestamp: datetime | None = None,
        user_id: UUID | None = None,
        user_email: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        success: bool = True,
        outcome: str = "success",
        risk_score: int = 0,
        risk_factors: list[str] | None = None,
        details: dict[str, Any] | None = None,
        source: str | None = None,
        geo_location: dict[str, Any] | None = None,
        organization_id: UUID | None = None,
    ) -> SecurityEventRecord:
        """Create and persist a security event."""
        from app.models.security_audit import SecurityEventRecord

        record = SecurityEventRecord(
            timestamp=timestamp or datetime.now(UTC),
            event_type=event_type,
            category=category,
            severity=severity,
            user_id=user_id,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            outcome=outcome,
            risk_score=risk_score,
            risk_factors=risk_factors or [],
            details=details or {},
            source=source,
            geo_location=geo_location,
            organization_id=organization_id,
        )
        session.add(record)
        await session.flush()
        return record

    @staticmethod
    async def query_security_events(
        session: AsyncSession,
        *,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        event_types: list[str] | None = None,
        severities: list[str] | None = None,
        categories: list[str] | None = None,
        user_id: UUID | None = None,
        ip_address: str | None = None,
        success: bool | None = None,
        reviewed: bool | None = None,
        min_risk_score: int | None = None,
        search: str | None = None,
        organization_id: UUID | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[SecurityEventRecord], int]:
        """Query security events with filters and pagination."""
        from app.models.security_audit import SecurityEventRecord

        base = select(SecurityEventRecord)
        count_base = select(func.count(SecurityEventRecord.id))

        conditions = []
        if organization_id:
            conditions.append(SecurityEventRecord.organization_id == organization_id)
        if start_date:
            conditions.append(SecurityEventRecord.timestamp >= start_date)
        if end_date:
            conditions.append(SecurityEventRecord.timestamp <= end_date)
        if event_types:
            conditions.append(SecurityEventRecord.event_type.in_(event_types))
        if severities:
            conditions.append(SecurityEventRecord.severity.in_(severities))
        if categories:
            conditions.append(SecurityEventRecord.category.in_(categories))
        if user_id:
            conditions.append(SecurityEventRecord.user_id == user_id)
        if ip_address:
            conditions.append(SecurityEventRecord.ip_address == ip_address)
        if success is not None:
            conditions.append(SecurityEventRecord.success == success)
        if reviewed is not None:
            conditions.append(SecurityEventRecord.reviewed == reviewed)
        if min_risk_score is not None:
            conditions.append(SecurityEventRecord.risk_score >= min_risk_score)
        if search:
            escaped = escape_like(search)
            like = f"%{escaped}%"
            conditions.append(
                or_(
                    SecurityEventRecord.user_email.ilike(like, escape="\\"),
                    SecurityEventRecord.ip_address.ilike(like, escape="\\"),
                    SecurityEventRecord.event_type.ilike(like, escape="\\"),
                )
            )

        if conditions:
            base = base.where(and_(*conditions))
            count_base = count_base.where(and_(*conditions))

        total = (await session.execute(count_base)).scalar_one()

        offset = (page - 1) * page_size
        base = base.order_by(SecurityEventRecord.timestamp.desc())
        base = base.offset(offset).limit(page_size)

        result = await session.execute(base)
        return list(result.scalars().all()), total

    @staticmethod
    async def get_security_event(
        session: AsyncSession,
        event_id: UUID,
        *,
        organization_id: UUID | None = None,
    ) -> SecurityEventRecord | None:
        """Get a single security event by ID."""
        from app.models.security_audit import SecurityEventRecord

        conditions = [SecurityEventRecord.id == event_id]
        if organization_id:
            conditions.append(SecurityEventRecord.organization_id == organization_id)
        result = await session.execute(select(SecurityEventRecord).where(and_(*conditions)))
        return result.scalar_one_or_none()

    @staticmethod
    async def review_security_event(
        session: AsyncSession,
        event_id: UUID,
        reviewer_id: UUID,
        review_notes: str | None = None,
        *,
        organization_id: UUID | None = None,
    ) -> SecurityEventRecord | None:
        """Mark a security event as reviewed."""
        from app.models.security_audit import SecurityEventRecord

        conditions = [SecurityEventRecord.id == event_id]
        if organization_id:
            conditions.append(SecurityEventRecord.organization_id == organization_id)
        result = await session.execute(select(SecurityEventRecord).where(and_(*conditions)))
        record = result.scalar_one_or_none()
        if not record:
            return None

        record.reviewed = True
        record.reviewed_by = reviewer_id
        record.reviewed_at = datetime.now(UTC)
        record.review_notes = review_notes
        await session.flush()
        return record

    # =========================================================================
    # Security Summary
    # =========================================================================

    @staticmethod
    async def get_security_summary(
        session: AsyncSession,
        *,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        organization_id: UUID | None = None,
        is_super_admin: bool = False,
    ) -> dict[str, Any]:
        """Get aggregated security summary.

        ``failed_logins`` and ``blocked_ips`` are counted from
        ``FailedLoginRecord`` / ``IPBlockRecord``, neither of which carries an
        ``organization_id`` — they are platform-wide records (a failed login is
        recorded before any tenant context exists; an IP block is global, with a
        unique constraint on the address). Returning those platform counts inside
        an org-scoped summary leaked cross-tenant volume to org-scoped callers, so
        they are now exposed only to ``super_admin`` (``is_super_admin``); every
        org-scoped caller sees ``0``. ``active_anomalies`` *does* carry an
        ``organization_id`` and is now scoped to it (previously global — a
        cross-org count leak).
        """
        from app.models.security_audit import (
            FailedLoginRecord,
            IPBlockRecord,
            SecurityAnomalyRecord,
            SecurityEventRecord,
        )

        now = datetime.now(UTC)
        if not start_date:
            start_date = now - timedelta(days=7)
        if not end_date:
            end_date = now

        conditions = [
            SecurityEventRecord.timestamp >= start_date,
            SecurityEventRecord.timestamp <= end_date,
        ]
        if organization_id:
            conditions.append(SecurityEventRecord.organization_id == organization_id)

        # Total events
        total = (
            await session.execute(
                select(func.count(SecurityEventRecord.id)).where(and_(*conditions))
            )
        ).scalar_one()

        # Failed logins — platform-wide (no org column); super_admin only.
        if is_super_admin:
            failed_logins = (
                await session.execute(
                    select(func.count(FailedLoginRecord.id)).where(
                        FailedLoginRecord.timestamp >= start_date,
                        FailedLoginRecord.timestamp <= end_date,
                    )
                )
            ).scalar_one()
        else:
            failed_logins = 0

        # Successful logins
        successful_logins = (
            await session.execute(
                select(func.count(SecurityEventRecord.id)).where(
                    and_(
                        *conditions,
                        SecurityEventRecord.event_type == "login_success",
                        SecurityEventRecord.success == True,  # noqa: E712
                    )
                )
            )
        ).scalar_one()

        # By severity
        severity_rows = (
            await session.execute(
                select(SecurityEventRecord.severity, func.count(SecurityEventRecord.id))
                .where(and_(*conditions))
                .group_by(SecurityEventRecord.severity)
            )
        ).all()
        by_severity = {row[0]: row[1] for row in severity_rows}

        # By category
        category_rows = (
            await session.execute(
                select(SecurityEventRecord.category, func.count(SecurityEventRecord.id))
                .where(and_(*conditions))
                .group_by(SecurityEventRecord.category)
            )
        ).all()
        by_category = {row[0]: row[1] for row in category_rows}

        # By event type
        type_rows = (
            await session.execute(
                select(SecurityEventRecord.event_type, func.count(SecurityEventRecord.id))
                .where(and_(*conditions))
                .group_by(SecurityEventRecord.event_type)
            )
        ).all()
        by_event_type = {row[0]: row[1] for row in type_rows}

        # Active blocked IPs — platform-wide (no org column); super_admin only.
        if is_super_admin:
            blocked_ips = (
                await session.execute(
                    select(func.count(IPBlockRecord.id)).where(IPBlockRecord.is_active == True)  # noqa: E712
                )
            ).scalar_one()
        else:
            blocked_ips = 0

        # Active anomalies — org-scoped (SecurityAnomalyRecord carries an
        # organization_id); fold the org filter so a tenant never sees siblings'
        # anomaly counts.
        anomaly_conditions: list[Any] = [SecurityAnomalyRecord.resolved.is_(False)]
        if organization_id:
            anomaly_conditions.append(SecurityAnomalyRecord.organization_id == organization_id)
        active_anomalies = (
            await session.execute(
                select(func.count(SecurityAnomalyRecord.id)).where(and_(*anomaly_conditions))
            )
        ).scalar_one()

        # High-risk events
        high_risk = by_severity.get("high", 0) + by_severity.get("critical", 0)

        return {
            "total_events": total,
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "account_lockouts": by_event_type.get("account_locked", 0),
            "suspicious_activities": by_category.get("anomaly", 0),
            "high_risk_events": high_risk,
            "critical_events": by_severity.get("critical", 0),
            "blocked_ips": blocked_ips,
            "active_anomalies": active_anomalies,
            "by_severity": by_severity,
            "by_category": by_category,
            "by_event_type": by_event_type,
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
            },
        }

    @staticmethod
    async def get_activity_summary(
        session: AsyncSession,
        *,
        organization_id: UUID,
        start_date: datetime,
        end_date: datetime,
    ) -> dict[str, Any]:
        """Get activity summary for an organization."""
        from app.models.security_audit import AuditLogRecord

        conditions = [
            AuditLogRecord.timestamp >= start_date,
            AuditLogRecord.timestamp <= end_date,
            AuditLogRecord.organization_id == organization_id,
        ]

        total = (
            await session.execute(select(func.count(AuditLogRecord.id)).where(and_(*conditions)))
        ).scalar_one()

        by_action: dict[str, int] = dict(
            (
                await session.execute(  # type: ignore[arg-type]
                    select(AuditLogRecord.action, func.count(AuditLogRecord.id))
                    .where(and_(*conditions))
                    .group_by(AuditLogRecord.action)
                )
            ).all()
        )

        by_resource: dict[str, int] = dict(
            (
                await session.execute(  # type: ignore[arg-type]
                    select(AuditLogRecord.resource_type, func.count(AuditLogRecord.id))
                    .where(and_(*conditions))
                    .group_by(AuditLogRecord.resource_type)
                )
            ).all()
        )

        by_actor: dict[str, int] = dict(
            (
                await session.execute(  # type: ignore[arg-type]
                    select(AuditLogRecord.actor_name, func.count(AuditLogRecord.id))
                    .where(and_(*conditions))
                    .group_by(AuditLogRecord.actor_name)
                )
            ).all()
        )

        by_status: dict[str, int] = dict(
            (
                await session.execute(  # type: ignore[arg-type]
                    select(AuditLogRecord.status, func.count(AuditLogRecord.id))
                    .where(and_(*conditions))
                    .group_by(AuditLogRecord.status)
                )
            ).all()
        )

        return {
            "total_events": total,
            "by_action": by_action,
            "by_resource_type": by_resource,
            "by_actor": by_actor,
            "by_status": by_status,
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
            },
        }

    # =========================================================================
    # Failed Login Tracking & Brute-Force Detection
    # =========================================================================

    @staticmethod
    async def record_failed_login(
        session: AsyncSession,
        *,
        username: str,
        ip_address: str,
        user_agent: str | None = None,
        reason: str = "invalid_credentials",
        geo_location: dict[str, Any] | None = None,
        request_metadata: dict[str, Any] | None = None,
    ) -> FailedLoginRecord:
        """Record a failed login attempt and check for brute-force."""
        from app.models.security_audit import FailedLoginRecord

        record = FailedLoginRecord(
            timestamp=datetime.now(UTC),
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            reason=reason,
            geo_location=geo_location,
            request_metadata=request_metadata,
        )
        session.add(record)
        await session.flush()
        return record

    @staticmethod
    async def check_brute_force(
        session: AsyncSession,
        ip_address: str,
        window_minutes: int = BRUTE_FORCE_WINDOW_MINUTES,
        max_attempts: int = BRUTE_FORCE_MAX_ATTEMPTS,
    ) -> tuple[bool, int]:
        """
        Check if an IP has exceeded the brute-force threshold.

        Returns:
            Tuple of (is_brute_force, attempt_count)
        """
        from app.models.security_audit import FailedLoginRecord

        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        count = (
            await session.execute(
                select(func.count(FailedLoginRecord.id)).where(
                    FailedLoginRecord.ip_address == ip_address,
                    FailedLoginRecord.timestamp >= since,
                )
            )
        ).scalar_one()

        return count >= max_attempts, count

    @staticmethod
    async def check_account_lockout(
        session: AsyncSession,
        username: str,
        window_minutes: int = ACCOUNT_LOCKOUT_WINDOW_MINUTES,
        max_attempts: int = ACCOUNT_LOCKOUT_THRESHOLD,
    ) -> tuple[bool, int]:
        """
        Check if a user account should be locked out.

        Returns:
            Tuple of (is_locked_out, attempt_count)
        """
        from app.models.security_audit import FailedLoginRecord

        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        count = (
            await session.execute(
                select(func.count(FailedLoginRecord.id)).where(
                    FailedLoginRecord.username == username,
                    FailedLoginRecord.timestamp >= since,
                )
            )
        ).scalar_one()

        return count >= max_attempts, count

    @staticmethod
    async def get_failed_logins(
        session: AsyncSession,
        *,
        ip_address: str | None = None,
        username: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[FailedLoginRecord], int]:
        """Query failed login attempts."""
        from app.models.security_audit import FailedLoginRecord

        base = select(FailedLoginRecord)
        count_base = select(func.count(FailedLoginRecord.id))

        conditions = []
        if ip_address:
            conditions.append(FailedLoginRecord.ip_address == ip_address)
        if username:
            conditions.append(FailedLoginRecord.username == username)
        if start_date:
            conditions.append(FailedLoginRecord.timestamp >= start_date)
        if end_date:
            conditions.append(FailedLoginRecord.timestamp <= end_date)

        if conditions:
            base = base.where(and_(*conditions))
            count_base = count_base.where(and_(*conditions))

        total = (await session.execute(count_base)).scalar_one()

        offset = (page - 1) * page_size
        base = base.order_by(FailedLoginRecord.timestamp.desc())
        base = base.offset(offset).limit(page_size)

        result = await session.execute(base)
        return list(result.scalars().all()), total

    # =========================================================================
    # IP Blocking
    # =========================================================================

    @staticmethod
    async def block_ip(
        session: AsyncSession,
        *,
        ip_address: str,
        reason: str,
        failed_attempts: int = 0,
        blocked_username: str | None = None,
        duration_hours: int = DEFAULT_BLOCK_DURATION_HOURS,
        details: dict[str, Any] | None = None,
    ) -> IPBlockRecord:
        """Block an IP address."""
        from app.models.security_audit import IPBlockRecord

        now = datetime.now(UTC)

        # Check if already blocked
        existing = (
            await session.execute(
                select(IPBlockRecord).where(
                    IPBlockRecord.ip_address == ip_address,
                    IPBlockRecord.is_active == True,  # noqa: E712
                )
            )
        ).scalar_one_or_none()

        if existing:
            existing.failed_attempts = max(existing.failed_attempts, failed_attempts)
            existing.expires_at = now + timedelta(hours=duration_hours)
            await session.flush()
            return existing

        record = IPBlockRecord(
            ip_address=ip_address,
            reason=reason,
            blocked_at=now,
            expires_at=now + timedelta(hours=duration_hours),
            is_active=True,
            failed_attempts=failed_attempts,
            blocked_username=blocked_username,
            details=details or {},
        )
        session.add(record)
        await session.flush()
        return record

    @staticmethod
    async def unblock_ip(
        session: AsyncSession,
        ip_address: str,
        unblocked_by: UUID | None = None,
        reason: str | None = None,
    ) -> IPBlockRecord | None:
        """Unblock an IP address."""
        from app.models.security_audit import IPBlockRecord

        result = await session.execute(
            select(IPBlockRecord).where(
                IPBlockRecord.ip_address == ip_address,
                IPBlockRecord.is_active == True,  # noqa: E712
            )
        )
        record = result.scalar_one_or_none()
        if not record:
            return None

        record.is_active = False
        record.unblocked_at = datetime.now(UTC)
        record.unblocked_by = unblocked_by
        record.unblock_reason = reason
        await session.flush()
        return record

    @staticmethod
    async def is_ip_blocked(
        session: AsyncSession,
        ip_address: str,
    ) -> bool:
        """Check if an IP is currently blocked."""
        from app.models.security_audit import IPBlockRecord

        now = datetime.now(UTC)
        result = await session.execute(
            select(func.count(IPBlockRecord.id)).where(
                IPBlockRecord.ip_address == ip_address,
                IPBlockRecord.is_active == True,  # noqa: E712
                or_(
                    IPBlockRecord.expires_at.is_(None),
                    IPBlockRecord.expires_at > now,
                ),
            )
        )
        return bool(result.scalar_one() > 0)

    @staticmethod
    async def get_blocked_ips(
        session: AsyncSession,
        active_only: bool = True,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[IPBlockRecord], int]:
        """List blocked IPs."""
        from app.models.security_audit import IPBlockRecord

        base = select(IPBlockRecord)
        count_base = select(func.count(IPBlockRecord.id))

        if active_only:
            base = base.where(IPBlockRecord.is_active == True)  # noqa: E712
            count_base = count_base.where(IPBlockRecord.is_active == True)  # noqa: E712

        total = (await session.execute(count_base)).scalar_one()

        offset = (page - 1) * page_size
        base = base.order_by(IPBlockRecord.blocked_at.desc())
        base = base.offset(offset).limit(page_size)

        result = await session.execute(base)
        return list(result.scalars().all()), total

    @staticmethod
    async def expire_ip_blocks(session: AsyncSession) -> int:
        """Expire IP blocks that have passed their expiry time."""
        from app.models.security_audit import IPBlockRecord

        now = datetime.now(UTC)
        result = await session.execute(
            update(IPBlockRecord)
            .where(
                IPBlockRecord.is_active == True,  # noqa: E712
                IPBlockRecord.expires_at.isnot(None),
                IPBlockRecord.expires_at <= now,
            )
            .values(
                is_active=False,
                unblocked_at=now,
                unblock_reason="expired",
            )
        )
        await session.flush()
        return int(result.rowcount or 0)  # type: ignore[attr-defined]

    # =========================================================================
    # Anomaly Detection
    # =========================================================================

    @staticmethod
    async def create_anomaly(
        session: AsyncSession,
        *,
        anomaly_type: str,
        title: str,
        severity: str = "medium",
        description: str | None = None,
        user_id: UUID | None = None,
        user_email: str | None = None,
        ip_address: str | None = None,
        evidence: dict[str, Any] | None = None,
        risk_score: int = 50,
        related_event_ids: list[str] | None = None,
        organization_id: UUID | None = None,
    ) -> SecurityAnomalyRecord:
        """Create a security anomaly record."""
        from app.models.security_audit import SecurityAnomalyRecord

        record = SecurityAnomalyRecord(
            detected_at=datetime.now(UTC),
            anomaly_type=anomaly_type,
            severity=severity,
            user_id=user_id,
            user_email=user_email,
            ip_address=ip_address,
            title=title,
            description=description,
            evidence=evidence or {},
            risk_score=risk_score,
            related_event_ids=related_event_ids or [],
            organization_id=organization_id,
        )
        session.add(record)
        await session.flush()
        return record

    @staticmethod
    async def get_anomalies(
        session: AsyncSession,
        *,
        resolved: bool | None = None,
        severity: str | None = None,
        anomaly_type: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        organization_id: UUID | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[SecurityAnomalyRecord], int]:
        """Query security anomalies."""
        from app.models.security_audit import SecurityAnomalyRecord

        base = select(SecurityAnomalyRecord)
        count_base = select(func.count(SecurityAnomalyRecord.id))

        conditions = []
        if organization_id:
            conditions.append(SecurityAnomalyRecord.organization_id == organization_id)
        if resolved is not None:
            conditions.append(SecurityAnomalyRecord.resolved == resolved)
        if severity:
            conditions.append(SecurityAnomalyRecord.severity == severity)
        if anomaly_type:
            conditions.append(SecurityAnomalyRecord.anomaly_type == anomaly_type)
        if start_date:
            conditions.append(SecurityAnomalyRecord.detected_at >= start_date)
        if end_date:
            conditions.append(SecurityAnomalyRecord.detected_at <= end_date)

        if conditions:
            base = base.where(and_(*conditions))
            count_base = count_base.where(and_(*conditions))

        total = (await session.execute(count_base)).scalar_one()

        offset = (page - 1) * page_size
        base = base.order_by(SecurityAnomalyRecord.detected_at.desc())
        base = base.offset(offset).limit(page_size)

        result = await session.execute(base)
        return list(result.scalars().all()), total

    @staticmethod
    async def resolve_anomaly(
        session: AsyncSession,
        anomaly_id: UUID,
        resolved_by: UUID,
        resolution_notes: str | None = None,
        *,
        organization_id: UUID | None = None,
    ) -> SecurityAnomalyRecord | None:
        """Mark an anomaly as resolved."""
        from app.models.security_audit import SecurityAnomalyRecord

        conditions = [SecurityAnomalyRecord.id == anomaly_id]
        if organization_id:
            conditions.append(SecurityAnomalyRecord.organization_id == organization_id)
        result = await session.execute(select(SecurityAnomalyRecord).where(and_(*conditions)))
        record = result.scalar_one_or_none()
        if not record:
            return None

        record.resolved = True
        record.resolved_at = datetime.now(UTC)
        record.resolved_by = resolved_by
        record.resolution_notes = resolution_notes
        await session.flush()
        return record

    # =========================================================================
    # User & IP Activity
    # =========================================================================

    @staticmethod
    async def get_user_activity(
        session: AsyncSession,
        user_id: UUID,
        *,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        organization_id: UUID | None = None,
    ) -> dict[str, Any]:
        """Get activity summary for a specific user."""
        from app.models.security_audit import (
            AuditLogRecord,
            SecurityEventRecord,
        )

        now = datetime.now(UTC)
        if not start_date:
            start_date = now - timedelta(days=30)
        if not end_date:
            end_date = now

        uid_str = str(user_id)

        # Audit actions
        audit_conditions = [
            AuditLogRecord.actor_id == uid_str,
            AuditLogRecord.timestamp >= start_date,
            AuditLogRecord.timestamp <= end_date,
        ]
        if organization_id:
            audit_conditions.append(AuditLogRecord.organization_id == organization_id)

        total_actions = (
            await session.execute(
                select(func.count(AuditLogRecord.id)).where(and_(*audit_conditions))
            )
        ).scalar_one()

        # Build org-scoped security event base conditions
        sec_base = [SecurityEventRecord.user_id == user_id]
        if organization_id:
            sec_base.append(SecurityEventRecord.organization_id == organization_id)

        # Logins
        login_count = (
            await session.execute(
                select(func.count(SecurityEventRecord.id)).where(
                    and_(
                        *sec_base,
                        SecurityEventRecord.event_type == "login_success",
                        SecurityEventRecord.timestamp >= start_date,
                    )
                )
            )
        ).scalar_one()

        # Failed logins – join by email since FailedLoginRecord uses username
        failed_count = (
            await session.execute(
                select(func.count(SecurityEventRecord.id)).where(
                    and_(
                        *sec_base,
                        SecurityEventRecord.event_type == "login_failure",
                        SecurityEventRecord.timestamp >= start_date,
                    )
                )
            )
        ).scalar_one()

        # Last login
        last_login_row = (
            await session.execute(
                select(SecurityEventRecord.timestamp)
                .where(
                    and_(
                        *sec_base,
                        SecurityEventRecord.event_type == "login_success",
                    )
                )
                .order_by(SecurityEventRecord.timestamp.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        # Last activity
        audit_last_conds = [AuditLogRecord.actor_id == uid_str]
        if organization_id:
            audit_last_conds.append(AuditLogRecord.organization_id == organization_id)
        last_activity_row = (
            await session.execute(
                select(AuditLogRecord.timestamp)
                .where(and_(*audit_last_conds))
                .order_by(AuditLogRecord.timestamp.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        # IP addresses used
        ip_rows = (
            await session.execute(
                select(SecurityEventRecord.ip_address)
                .where(
                    and_(
                        *sec_base,
                        SecurityEventRecord.ip_address.isnot(None),
                        SecurityEventRecord.timestamp >= start_date,
                    )
                )
                .distinct()
            )
        ).all()
        ip_addresses = [r[0] for r in ip_rows if r[0]]

        # Recent security events
        recent_events_result = await session.execute(
            select(SecurityEventRecord)
            .where(and_(*sec_base))
            .order_by(SecurityEventRecord.timestamp.desc())
            .limit(10)
        )
        recent_events = list(recent_events_result.scalars().all())

        # Recent audit actions
        recent_actions_result = await session.execute(
            select(AuditLogRecord)
            .where(and_(*audit_last_conds))
            .order_by(AuditLogRecord.timestamp.desc())
            .limit(10)
        )
        recent_actions = list(recent_actions_result.scalars().all())

        return {
            "user_id": user_id,
            "total_actions": total_actions,
            "login_count": login_count,
            "failed_login_count": failed_count,
            "last_login": last_login_row,
            "last_activity": last_activity_row,
            "ip_addresses": ip_addresses,
            "recent_events": recent_events,
            "recent_actions": recent_actions,
        }

    @staticmethod
    async def get_ip_activity(
        session: AsyncSession,
        ip_address: str,
        *,
        start_date: datetime | None = None,
        organization_id: UUID | None = None,
        is_super_admin: bool = False,
    ) -> dict[str, Any]:
        """Get activity summary for an IP address.

        ``FailedLoginRecord`` and ``IPBlockRecord`` are platform-wide
        (no ``organization_id``). Their figures (``failed_logins`` and the
        block state ``is_blocked`` / ``block_info``) are therefore returned only
        for ``super_admin``; an org-scoped admin gets ``0`` / ``False`` /
        ``None`` so the response never reflects sibling-tenant posture. The
        org-scoped event fields below remain available to org admins.
        """
        from app.models.security_audit import (
            FailedLoginRecord,
            IPBlockRecord,
            SecurityEventRecord,
        )

        now = datetime.now(UTC)
        if not start_date:
            start_date = now - timedelta(days=30)

        # Build org-scoped base conditions for SecurityEventRecord
        sec_base = [
            SecurityEventRecord.ip_address == ip_address,
            SecurityEventRecord.timestamp >= start_date,
        ]
        if organization_id:
            sec_base.append(SecurityEventRecord.organization_id == organization_id)

        # Total events
        total = (
            await session.execute(select(func.count(SecurityEventRecord.id)).where(and_(*sec_base)))
        ).scalar_one()

        # Failed logins (FailedLoginRecord is platform-wide / no org_id;
        # super_admin only — org callers get 0 and the table is not queried).
        if is_super_admin:
            failed = (
                await session.execute(
                    select(func.count(FailedLoginRecord.id)).where(
                        FailedLoginRecord.ip_address == ip_address,
                        FailedLoginRecord.timestamp >= start_date,
                    )
                )
            ).scalar_one()
        else:
            failed = 0

        # Successful logins
        success = (
            await session.execute(
                select(func.count(SecurityEventRecord.id)).where(
                    and_(
                        *sec_base,
                        SecurityEventRecord.event_type == "login_success",
                    )
                )
            )
        ).scalar_one()

        # Block status (IPBlockRecord is platform-wide / no org_id;
        # super_admin only — org callers get is_blocked=False / block_info=None
        # and the table is not queried).
        if is_super_admin:
            block = (
                await session.execute(
                    select(IPBlockRecord).where(
                        IPBlockRecord.ip_address == ip_address,
                        IPBlockRecord.is_active == True,  # noqa: E712
                    )
                )
            ).scalar_one_or_none()
        else:
            block = None

        # Last seen
        sec_last = [SecurityEventRecord.ip_address == ip_address]
        if organization_id:
            sec_last.append(SecurityEventRecord.organization_id == organization_id)
        last_seen_row = (
            await session.execute(
                select(SecurityEventRecord.timestamp)
                .where(and_(*sec_last))
                .order_by(SecurityEventRecord.timestamp.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        # Associated users
        user_rows = (
            await session.execute(
                select(SecurityEventRecord.user_email)
                .where(
                    and_(
                        *sec_base,
                        SecurityEventRecord.user_email.isnot(None),
                    )
                )
                .distinct()
            )
        ).all()
        associated_users = [r[0] for r in user_rows if r[0]]

        # Recent events
        recent_result = await session.execute(
            select(SecurityEventRecord)
            .where(and_(*sec_base))
            .order_by(SecurityEventRecord.timestamp.desc())
            .limit(10)
        )
        recent_events = list(recent_result.scalars().all())

        return {
            "ip_address": ip_address,
            "total_events": total,
            "failed_logins": failed,
            "successful_logins": success,
            "security_events": total,
            "is_blocked": block is not None,
            "block_info": block,
            "last_seen": last_seen_row,
            "associated_users": associated_users,
            "recent_events": recent_events,
        }

    # =========================================================================
    # Compliance Report
    # =========================================================================

    @staticmethod
    async def generate_compliance_report(
        session: AsyncSession,
        *,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        organization_id: UUID | None = None,
        is_super_admin: bool = False,
    ) -> dict[str, Any]:
        """Generate a compliance report with aggregated security data.

        ``IPBlockRecord`` and ``FailedLoginRecord`` are platform-wide
        (no ``organization_id``); their counts (``total_ip_blocks`` and the
        failed-login total in ``login_summary``) are therefore included only for
        ``super_admin``. Every org-scoped report shows ``0`` for those two so it
        never reflects sibling-tenant volume, and the compliance score no longer
        deducts based on platform-wide noise an org operator cannot see.
        """
        from app.models.security_audit import (
            AuditLogRecord,
            FailedLoginRecord,
            IPBlockRecord,
            SecurityAnomalyRecord,
            SecurityEventRecord,
        )

        now = datetime.now(UTC)
        if not start_date:
            start_date = now - timedelta(days=30)
        if not end_date:
            end_date = now

        # ---------- Audit entries ----------
        audit_conditions = [
            AuditLogRecord.timestamp >= start_date,
            AuditLogRecord.timestamp <= end_date,
        ]
        if organization_id:
            audit_conditions.append(AuditLogRecord.organization_id == organization_id)

        total_audit = (
            await session.execute(
                select(func.count(AuditLogRecord.id)).where(and_(*audit_conditions))
            )
        ).scalar_one()

        # ---------- Security events ----------
        sec_conditions = [
            SecurityEventRecord.timestamp >= start_date,
            SecurityEventRecord.timestamp <= end_date,
        ]
        if organization_id:
            sec_conditions.append(SecurityEventRecord.organization_id == organization_id)

        total_security = (
            await session.execute(
                select(func.count(SecurityEventRecord.id)).where(and_(*sec_conditions))
            )
        ).scalar_one()

        # ---------- Anomalies ----------
        anom_conditions = [
            SecurityAnomalyRecord.detected_at >= start_date,
            SecurityAnomalyRecord.detected_at <= end_date,
        ]
        if organization_id:
            anom_conditions.append(SecurityAnomalyRecord.organization_id == organization_id)

        total_anomalies = (
            await session.execute(
                select(func.count(SecurityAnomalyRecord.id)).where(and_(*anom_conditions))
            )
        ).scalar_one()

        # ---------- IP blocks (platform-wide; super_admin only) ----------
        if is_super_admin:
            total_blocks = (
                await session.execute(
                    select(func.count(IPBlockRecord.id)).where(
                        IPBlockRecord.blocked_at >= start_date,
                        IPBlockRecord.blocked_at <= end_date,
                    )
                )
            ).scalar_one()
        else:
            total_blocks = 0

        # ---------- Login summary (failed logins platform-wide; super_admin only) ----------
        if is_super_admin:
            failed_logins = (
                await session.execute(
                    select(func.count(FailedLoginRecord.id)).where(
                        FailedLoginRecord.timestamp >= start_date,
                        FailedLoginRecord.timestamp <= end_date,
                    )
                )
            ).scalar_one()
        else:
            failed_logins = 0

        successful_logins = (
            await session.execute(
                select(func.count(SecurityEventRecord.id)).where(
                    and_(
                        *sec_conditions,
                        SecurityEventRecord.event_type == "login_success",
                    )
                )
            )
        ).scalar_one()

        # ---------- Config changes ----------
        config_changes = (
            await session.execute(
                select(func.count(AuditLogRecord.id)).where(
                    and_(
                        *audit_conditions,
                        AuditLogRecord.action.in_(["configure", "update", "enable", "disable"]),
                    )
                )
            )
        ).scalar_one()

        # ---------- High-severity incidents ----------
        incidents_result = await session.execute(
            select(SecurityEventRecord)
            .where(
                and_(
                    *sec_conditions,
                    SecurityEventRecord.severity.in_(["high", "critical"]),
                )
            )
            .order_by(SecurityEventRecord.timestamp.desc())
            .limit(50)
        )
        incidents = [
            {
                "id": str(r.id),
                "timestamp": r.timestamp.isoformat(),
                "event_type": r.event_type,
                "severity": r.severity,
                "user_email": r.user_email,
                "ip_address": r.ip_address,
                "details": r.details,
            }
            for r in incidents_result.scalars().all()
        ]

        # ---------- Compliance scoring ----------
        # Simple scoring: start at 100, deduct for security issues
        score = 100
        if failed_logins > 50:
            score -= 10
        if total_anomalies > 5:
            score -= 15
        if total_blocks > 10:
            score -= 10
        unreviewed = (
            await session.execute(
                select(func.count(SecurityEventRecord.id)).where(
                    and_(
                        *sec_conditions,
                        SecurityEventRecord.reviewed == False,  # noqa: E712
                        SecurityEventRecord.severity.in_(["high", "critical"]),
                    )
                )
            )
        ).scalar_one()
        if unreviewed > 0:
            score -= min(20, unreviewed * 2)
        score = max(0, score)

        return {
            "generated_at": now.isoformat(),
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
            "organization_id": str(organization_id) if organization_id else None,
            "total_audit_entries": total_audit,
            "total_security_events": total_security,
            "total_anomalies": total_anomalies,
            "total_ip_blocks": total_blocks,
            "login_summary": {
                "successful": successful_logins,
                "failed": failed_logins,
                "total": successful_logins + failed_logins,
            },
            "access_summary": {
                "total_access_events": total_audit,
            },
            "config_changes": config_changes,
            "data_access_summary": {},
            "incidents": incidents,
            "compliance_score": score,
            "compliance_details": {
                "unreviewed_high_severity": unreviewed,
                "active_ip_blocks": total_blocks,
                "anomalies_detected": total_anomalies,
            },
        }

    # =========================================================================
    # Export
    # =========================================================================

    @staticmethod
    async def export_security_data(
        session: AsyncSession,
        *,
        export_type: str = "events",
        format: str = "csv",
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        max_rows: int = 10000,
        organization_id: UUID | None = None,
    ) -> tuple[bytes, str, int]:
        """
        Export security data.

        Returns:
            Tuple of (data_bytes, content_type, row_count)
        """
        from app.models.security_audit import (
            AuditLogRecord,
            SecurityAnomalyRecord,
            SecurityEventRecord,
        )

        now = datetime.now(UTC)
        if not start_date:
            start_date = now - timedelta(days=30)
        if not end_date:
            end_date = now

        if export_type == "audit_logs":
            audit_conds = [
                AuditLogRecord.timestamp >= start_date,
                AuditLogRecord.timestamp <= end_date,
            ]
            if organization_id:
                audit_conds.append(AuditLogRecord.organization_id == organization_id)
            result = await session.execute(
                select(AuditLogRecord)
                .where(and_(*audit_conds))
                .order_by(AuditLogRecord.timestamp.desc())
                .limit(max_rows)
            )
            records: list[Any] = list(result.scalars().all())
            fields = [
                "timestamp",
                "action",
                "resource_type",
                "resource_id",
                "actor_id",
                "actor_name",
                "status",
                "ip_address",
                "request_method",
                "request_path",
            ]
            rows = [
                {
                    "timestamp": r.timestamp.isoformat(),
                    "action": r.action,
                    "resource_type": r.resource_type,
                    "resource_id": r.resource_id or "",
                    "actor_id": r.actor_id or "",
                    "actor_name": r.actor_name or "",
                    "status": r.status,
                    "ip_address": r.ip_address or "",
                    "request_method": r.request_method or "",
                    "request_path": r.request_path or "",
                }
                for r in records
            ]
        elif export_type == "anomalies":
            anom_conds = [
                SecurityAnomalyRecord.detected_at >= start_date,
                SecurityAnomalyRecord.detected_at <= end_date,
            ]
            if organization_id:
                anom_conds.append(SecurityAnomalyRecord.organization_id == organization_id)
            result = await session.execute(
                select(SecurityAnomalyRecord)
                .where(and_(*anom_conds))
                .order_by(SecurityAnomalyRecord.detected_at.desc())
                .limit(max_rows)
            )
            records = list(result.scalars().all())
            fields = [
                "detected_at",
                "anomaly_type",
                "severity",
                "title",
                "user_email",
                "ip_address",
                "risk_score",
                "resolved",
            ]
            rows = [
                {
                    "detected_at": r.detected_at.isoformat(),
                    "anomaly_type": r.anomaly_type,
                    "severity": r.severity,
                    "title": r.title,
                    "user_email": r.user_email or "",
                    "ip_address": r.ip_address or "",
                    "risk_score": str(r.risk_score),
                    "resolved": str(r.resolved),
                }
                for r in records
            ]
        else:
            # Default: security events
            sec_conds = [
                SecurityEventRecord.timestamp >= start_date,
                SecurityEventRecord.timestamp <= end_date,
            ]
            if organization_id:
                sec_conds.append(SecurityEventRecord.organization_id == organization_id)
            result = await session.execute(
                select(SecurityEventRecord)
                .where(and_(*sec_conds))
                .order_by(SecurityEventRecord.timestamp.desc())
                .limit(max_rows)
            )
            records = list(result.scalars().all())
            fields = [
                "timestamp",
                "event_type",
                "category",
                "severity",
                "user_email",
                "ip_address",
                "success",
                "risk_score",
                "outcome",
                "reviewed",
            ]
            rows = [
                {
                    "timestamp": r.timestamp.isoformat(),
                    "event_type": r.event_type,
                    "category": r.category,
                    "severity": r.severity,
                    "user_email": r.user_email or "",
                    "ip_address": r.ip_address or "",
                    "success": str(r.success),
                    "risk_score": str(r.risk_score),
                    "outcome": r.outcome,
                    "reviewed": str(r.reviewed),
                }
                for r in records
            ]

        if format == "csv":
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            # neutralize CSV formula injection on every cell.
            from app.core.security_utils import csv_safe

            writer.writerows([{k: csv_safe(v) for k, v in r.items()} for r in rows])
            data = output.getvalue().encode("utf-8")
            content_type = "text/csv"
        else:
            data = json.dumps(rows, indent=2).encode("utf-8")
            content_type = "application/json"

        return data, content_type, len(rows)

    # =========================================================================
    # Cleanup / Retention
    # =========================================================================

    @staticmethod
    async def cleanup_old_entries(
        session: AsyncSession,
        retention_days: int = 90,
    ) -> dict[str, int]:
        """Delete entries older than retention period."""
        from app.models.security_audit import (
            AuditLogRecord,
            FailedLoginRecord,
            SecurityAnomalyRecord,
            SecurityEventRecord,
        )

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)

        audit_deleted = (
            await session.execute(delete(AuditLogRecord).where(AuditLogRecord.timestamp < cutoff))
        ).rowcount  # type: ignore[attr-defined]

        events_deleted = (
            await session.execute(
                delete(SecurityEventRecord).where(SecurityEventRecord.timestamp < cutoff)
            )
        ).rowcount  # type: ignore[attr-defined]

        logins_deleted = (
            await session.execute(
                delete(FailedLoginRecord).where(FailedLoginRecord.timestamp < cutoff)
            )
        ).rowcount  # type: ignore[attr-defined]

        anomalies_deleted = (
            await session.execute(
                delete(SecurityAnomalyRecord).where(
                    SecurityAnomalyRecord.detected_at < cutoff,
                    SecurityAnomalyRecord.resolved == True,  # noqa: E712
                )
            )
        ).rowcount  # type: ignore[attr-defined]

        await session.flush()

        totals = {
            "audit_logs": audit_deleted,
            "security_events": events_deleted,
            "failed_logins": logins_deleted,
            "anomalies": anomalies_deleted,
        }
        logger.info("Security audit cleanup: %s", totals)
        return totals

    # =========================================================================
    # Brute-Force Auto-Block
    # =========================================================================

    @staticmethod
    async def auto_block_brute_force(
        session: AsyncSession,
        ip_address: str,
        username: str | None = None,
    ) -> IPBlockRecord | None:
        """
        Check for brute force and auto-block if threshold exceeded.
        Call this after each failed login.
        """
        is_brute_force, count = await PersistentSecurityAuditService.check_brute_force(
            session, ip_address
        )
        if not is_brute_force:
            return None

        # Block the IP
        block = await PersistentSecurityAuditService.block_ip(
            session,
            ip_address=ip_address,
            reason="brute_force",
            failed_attempts=count,
            blocked_username=username,
            details={"auto_blocked": True, "attempt_count": count},
        )

        # Create security event for the block
        await PersistentSecurityAuditService.create_security_event(
            session,
            event_type="ip_blocked",
            category="authentication",
            severity="high",
            ip_address=ip_address,
            success=False,
            outcome="blocked",
            risk_score=80,
            risk_factors=["brute_force_detected", f"{count}_failed_attempts"],
            details={
                "reason": "brute_force",
                "attempt_count": count,
                "blocked_username": username,
            },
        )

        # Create anomaly
        await PersistentSecurityAuditService.create_anomaly(
            session,
            anomaly_type="excessive_failed_logins",
            title=f"Brute force detected from {ip_address}",
            severity="high",
            ip_address=ip_address,
            evidence={
                "failed_attempts": count,
                "window_minutes": BRUTE_FORCE_WINDOW_MINUTES,
                "threshold": BRUTE_FORCE_MAX_ATTEMPTS,
                "username": username,
            },
            risk_score=80,
        )

        logger.warning(f"Brute force auto-block: {ip_address} ({count} attempts, user={username})")
        return block

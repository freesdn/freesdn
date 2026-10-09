# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded security-row deletion and coherent, payload-free retention progress.

Caller owns commit/rollback. Delete domain rows before acquiring any audit-chain
lock; never loop back to these deletes while retaining a chain transaction lock.
"""

from datetime import datetime
from typing import Any, TypedDict, cast

from sqlalchemy import delete, exists, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.models.security_audit import (
    AuditLogRecord,
    FailedLoginRecord,
    SecurityAnomalyRecord,
    SecurityEventRecord,
)


class RetentionProgress(TypedDict):
    complete: bool
    more_available: bool
    blocked_prefix: bool
    remaining: list[str]


async def delete_security_batch(db: AsyncSession, kind: str, cutoff: datetime) -> int:
    """Delete at most 1000 eligible rows in deterministic row-lock order."""
    model: type[SecurityEventRecord] | type[FailedLoginRecord] | type[SecurityAnomalyRecord]
    predicates: tuple[ColumnElement[bool], ...]
    if kind == "security_events":
        model, column = SecurityEventRecord, SecurityEventRecord.timestamp
        predicates = (column < cutoff,)
    elif kind == "failed_logins":
        model, column = FailedLoginRecord, FailedLoginRecord.timestamp
        predicates = (column < cutoff,)
    elif kind == "anomalies":
        model, column = SecurityAnomalyRecord, SecurityAnomalyRecord.detected_at
        predicates = (column < cutoff, SecurityAnomalyRecord.resolved.is_(True))
    else:
        raise ValueError("Unknown security retention table")
    selected = (
        (
            select(model.id)
            .where(*predicates)
            .order_by(column, model.id)
            .limit(1000)
            .with_for_update()
        )
        .cte("retention_batch")
        .prefix_with("MATERIALIZED")
    )
    # A nested-loop semi-join can rescan a plain locking subquery as rows
    # disappear, admitting additional rows beyond LIMIT. Freeze the selected
    # batch once, while retaining row locks and eligibility rechecks after waits.
    result = await db.execute(
        delete(model)
        .where(model.id.in_(select(selected.c.id)))
        .execution_options(synchronize_session=False)
    )
    return cast(CursorResult[Any], result).rowcount or 0


async def retention_progress(db: AsyncSession, cutoff: datetime) -> RetentionProgress:
    """One MVCC statement; only table names/flags, never a historical guarantee."""
    head_expired = (
        select(AuditLogRecord.timestamp < cutoff)
        .order_by(
            func.coalesce(AuditLogRecord.append_sequence, 0),
            AuditLogRecord.timestamp,
            AuditLogRecord.id,
        )
        .limit(1)
        .scalar_subquery()
    )
    statement = select(
        exists().where(AuditLogRecord.timestamp < cutoff).label("audit_logs"),
        func.coalesce(head_expired, False).label("audit_prefix_ready"),
        exists().where(SecurityEventRecord.timestamp < cutoff).label("security_events"),
        exists().where(FailedLoginRecord.timestamp < cutoff).label("failed_logins"),
        exists()
        .where(SecurityAnomalyRecord.detected_at < cutoff, SecurityAnomalyRecord.resolved.is_(True))
        .label("anomalies"),
    )
    row = (await db.execute(statement)).one()
    names = ("audit_logs", "security_events", "failed_logins", "anomalies")
    remaining = [name for name in names if getattr(row, name)]
    blocked = bool(row.audit_logs and not row.audit_prefix_ready)
    more = bool(row.audit_prefix_ready or row.security_events or row.failed_logins or row.anomalies)
    return {
        "complete": not remaining,
        "more_available": more,
        "blocked_prefix": blocked,
        "remaining": remaining,
    }

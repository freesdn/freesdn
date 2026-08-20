# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Audit Service
============================

Comprehensive audit logging for compliance and security.

Features:
- API operation logging
- Security event tracking
- Change tracking (before/after states)
- Query and reporting capabilities
- Data retention policies
"""

import hashlib
import hmac
import json
import logging
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import and_, desc, func, or_, select, text
from sqlalchemy import delete as sa_delete
from sqlalchemy import true as sa_true
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security_utils import escape_like
from app.models.security_audit import AuditLogRecord, SecurityEventRecord

logger = logging.getLogger(__name__)


# =============================================================================
# Tamper-evidence chain helpers
# =============================================================================
#
# Each AuditLogRecord stores a SHA-256 HMAC over the prev row's HMAC plus
# this row's canonical JSON. Validation walks the chain forward from any
# start id and confirms each link. See ``AuditLogRecord.prev_hash`` and
# ``AuditLogRecord.row_hmac`` in ``models/security_audit.py`` for column
# definitions.
#
# Threat model: this catches surgical UPDATEs to a single row (the most
# common audit-tampering vector — "edit my login row to look like someone
# else's"). It does NOT prevent a DB admin from deleting the entire table
# or re-keying the chain end-to-end if they hold AUDIT_HMAC_KEY. For full
# tamper-prevention, ship rows to an append-only external store (WORM
# bucket, immudb, etc).
#
# Postgres transaction-level advisory lock serialising all writers of the
# single global audit tamper-evidence chain. ``with_for_update()`` alone
# does NOT guard the genesis / empty-window case — a LIMIT 1 select over
# an empty (or empty-after-filter) tail locks no row, so two concurrent
# writers both read prev_hash=NULL and branch the chain. Taking this
# advisory lock first serialises the read-tail/insert critical section
# regardless of whether a prior row exists. It auto-releases at
# transaction end. (Arbitrary constant within signed bigint.)
_AUDIT_CHAIN_LOCK_KEY = 779_001_439


def _resolve_hmac_key() -> bytes:
    """Return the HMAC key bytes used to chain audit rows.

    Falls back to a SECRET_KEY-derived key if AUDIT_HMAC_KEY is unset so
    the chain still works on a fresh deployment without operator setup.
    """
    raw = settings.AUDIT_HMAC_KEY or settings.SECRET_KEY or ""
    if not raw:
        # No secret at all — chain is purely informational. Use a
        # well-known constant so the chain at least links to itself; we
        # log loudly because this should never happen in prod (config
        # validation would have refused to start with an empty key).
        logger.error(
            "AUDIT_HMAC_KEY and SECRET_KEY are both empty; audit chain "
            "HMAC is effectively public. This is a misconfiguration."
        )
        raw = "freesdn-audit-fallback-key"
    # Domain-separate from any other HMAC use of SECRET_KEY.
    return hashlib.sha256(f"freesdn.audit.v1::{raw}".encode()).digest()


def _canonical_row_json(record: "AuditLogRecord") -> bytes:
    """Serialize an AuditLogRecord to canonical JSON for HMAC input.

    Sorted keys + compact separators so the encoding is deterministic
    across Python runs / DB drivers. Excludes the chain columns
    themselves (``prev_hash``, ``row_hmac``) — otherwise computing the
    HMAC would be a chicken-and-egg problem.
    """
    payload = {
        "id": str(record.id),
        "timestamp": record.timestamp.isoformat() if record.timestamp else None,
        "action": record.action,
        "resource_type": record.resource_type,
        "resource_id": record.resource_id,
        "resource_name": record.resource_name,
        "actor_id": record.actor_id,
        "actor_type": record.actor_type,
        "actor_name": record.actor_name,
        "actor_email": record.actor_email,
        "organization_id": str(record.organization_id) if record.organization_id else None,
        "site_id": str(record.site_id) if record.site_id else None,
        "ip_address": record.ip_address,
        "user_agent": record.user_agent,
        "session_id": record.session_id,
        "request_id": record.request_id,
        "request_method": record.request_method,
        "request_path": record.request_path,
        "status": record.status,
        "response_code": record.response_code,
        "response_time_ms": record.response_time_ms,
        "error_message": record.error_message,
        "changes": record.changes,
        "previous_state": record.previous_state,
        "new_state": record.new_state,
        "tags": record.tags,
        "extra_metadata": record.extra_metadata,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _compute_row_hmac(prev_hash: str | None, record: "AuditLogRecord") -> str:
    """Compute the HMAC for a single audit row.

    Input is ``prev_hash || canonical_json(record)`` so any change to a
    row body OR any reordering / insertion in the chain breaks the link.
    """
    key = _resolve_hmac_key()
    msg = (prev_hash or "").encode("utf-8") + _canonical_row_json(record)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# Context variable for request tracking
request_context: ContextVar[dict[str, Any]] = ContextVar("request_context")


# =============================================================================
# Enums
# =============================================================================


class AuditAction(StrEnum):
    """Standard audit actions."""

    # CRUD
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"

    # Authentication
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"

    # MFA
    MFA_ENABLE = "mfa_enable"
    MFA_DISABLE = "mfa_disable"
    MFA_VERIFY = "mfa_verify"
    MFA_FAILED = "mfa_failed"

    # Administrative
    ENABLE = "enable"
    DISABLE = "disable"
    APPROVE = "approve"
    REJECT = "reject"
    ASSIGN = "assign"
    UNASSIGN = "unassign"
    INVITE = "invite"

    # Device Operations
    ADOPT = "adopt"
    PROVISION = "provision"
    REBOOT = "reboot"
    UPGRADE = "upgrade"
    LOCATE = "locate"

    # Backup/Restore
    BACKUP = "backup"
    RESTORE = "restore"

    # Data
    EXPORT = "export"
    IMPORT = "import"
    SYNC = "sync"

    # Plugins
    INSTALL = "install"
    UNINSTALL = "uninstall"


class ResourceType(StrEnum):
    """Resource types for audit logging."""

    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    ORGANIZATION = "organization"
    SITE = "site"
    DEVICE = "device"
    CONTROLLER = "controller"
    NETWORK = "network"
    CLIENT = "client"
    ALERT = "alert"
    ALERT_RULE = "alert_rule"
    AUTOMATION = "automation"
    INTEGRATION = "integration"
    WEBHOOK = "webhook"
    API_KEY = "api_key"
    SESSION = "session"
    CONFIG = "config"
    FIRMWARE = "firmware"
    BACKUP = "backup"
    SETTINGS = "settings"
    # Camera & NVR resources
    CAMERA = "camera"
    NVR = "nvr"
    RECORDING = "recording"
    CAMERA_EVENT = "camera_event"
    CAMERA_VIEW = "camera_view"
    CAMERA_GROUP = "camera_group"
    # Plugin resources
    PLUGIN = "plugin"


class SecurityEventType(StrEnum):
    """Security-specific event types."""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_FAILED = "mfa_failed"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_USED = "api_key_used"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    PERMISSION_ESCALATION = "permission_escalation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"


def _safe_event_type(raw: str) -> SecurityEventType:
    """Convert a raw event_type string to the enum, falling back gracefully."""
    try:
        return SecurityEventType(raw)
    except ValueError:
        return SecurityEventType.SUSPICIOUS_ACTIVITY


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class AuditEntry:
    """Audit log entry."""

    id: UUID
    timestamp: datetime
    action: str
    resource_type: str
    resource_id: UUID | None
    resource_name: str | None
    actor_id: UUID | None
    actor_type: str
    actor_name: str | None
    actor_email: str | None
    session_id: str | None
    organization_id: UUID | None
    site_id: UUID | None
    ip_address: str | None
    user_agent: str | None
    status: str
    changes: dict[str, Any] | None = None
    previous_state: dict[str, Any] | None = None
    new_state: dict[str, Any] | None = None
    error_message: str | None = None
    request_id: str | None = None
    request_method: str | None = None
    request_path: str | None = None
    response_code: int | None = None
    response_time_ms: int | None = None
    tags: list[str] = field(default_factory=list)
    extra_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityEvent:
    """Security event record."""

    id: UUID
    timestamp: datetime
    event_type: SecurityEventType
    user_id: UUID | None
    user_email: str | None
    ip_address: str | None
    user_agent: str | None
    success: bool
    details: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0


@dataclass
class AuditQuery:
    """Query parameters for audit logs."""

    start_date: datetime | None = None
    end_date: datetime | None = None
    actions: list[str] | None = None
    resource_types: list[str] | None = None
    resource_id: UUID | None = None
    actor_id: UUID | None = None
    organization_id: UUID | None = None
    site_id: UUID | None = None
    status: str | None = None
    search: str | None = None
    limit: int = 100
    offset: int = 0


# =============================================================================
# Audit Service
# =============================================================================


class AuditService:
    """
    Comprehensive audit logging service.

    Usage:
        audit = AuditService(db)
        await audit.log(
            action=AuditAction.CREATE,
            resource_type=ResourceType.USER,
            resource_id=user.id,
            changes={"email": {"old": None, "new": "user@example.com"}},
        )
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        # SECURITY: no buffering. Previously audit entries were
        # accumulated in ``self._buffer`` and only flushed once 100 entries
        # had been collected — in practice this meant a single request's
        # audit entries were never persisted, and a flush failure silently
        # dropped the buffer. Each ``log()`` call now writes directly to
        # the database within the current transaction. The attribute is
        # kept as an always-empty list for compatibility with any caller
        # that still inspects it.
        self._buffer: list[AuditEntry] = []
        self._buffer_size = 0

    # =========================================================================
    # Main Logging
    # =========================================================================

    async def log(
        self,
        action: str | AuditAction,
        resource_type: str | ResourceType,
        resource_id: UUID | None = None,
        resource_name: str | None = None,
        organization_id: UUID | None = None,
        site_id: UUID | None = None,
        actor_id: UUID | None = None,
        actor_type: str = "user",
        actor_name: str | None = None,
        actor_email: str | None = None,
        session_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        changes: dict[str, Any] | None = None,
        previous_state: dict[str, Any] | None = None,
        new_state: dict[str, Any] | None = None,
        request_id: str | None = None,
        request_method: str | None = None,
        request_path: str | None = None,
        response_code: int | None = None,
        response_time_ms: int | None = None,
        status: str = "success",
        error_message: str | None = None,
        tags: list[str] | None = None,
        extra_metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """
        Create an audit log entry.

        Args:
            action: The action performed
            resource_type: Type of resource affected
            resource_id: ID of the affected resource
            resource_name: Human-readable name
            organization_id: Organization context
            site_id: Site context
            actor_id: User/system that performed the action
            actor_type: Type of actor (user, system, api_key)
            actor_name: Display name of actor
            actor_email: Email of actor
            session_id: Session ID if applicable
            ip_address: Client IP address
            user_agent: Client user agent
            changes: Dictionary of changed fields {field: {old, new}}
            previous_state: Full state before change
            new_state: Full state after change
            request_id: Correlation ID
            request_method: HTTP method
            request_path: Request path
            response_code: HTTP response code
            response_time_ms: Request duration
            status: success, failure, error
            error_message: Error details
            tags: Tags for categorization
            extra_metadata: Additional metadata

        Returns:
            Created AuditEntry
        """
        # Get context from request if available
        ctx = request_context.get({})

        # Create entry
        entry = AuditEntry(
            id=uuid4(),
            timestamp=datetime.now(UTC),
            action=action.value if isinstance(action, Enum) else action,
            resource_type=resource_type.value if isinstance(resource_type, Enum) else resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            actor_id=actor_id or ctx.get("user_id"),
            actor_type=actor_type,
            actor_name=actor_name or ctx.get("user_name"),
            actor_email=actor_email or ctx.get("user_email"),
            session_id=str(session_id) if session_id else ctx.get("session_id"),
            organization_id=organization_id or ctx.get("organization_id"),
            site_id=site_id,
            ip_address=ip_address or ctx.get("ip_address"),
            user_agent=user_agent or ctx.get("user_agent"),
            status=status,
            changes=changes,
            previous_state=previous_state,
            new_state=new_state,
            error_message=error_message,
            request_id=request_id or ctx.get("request_id"),
            request_method=request_method or ctx.get("method"),
            request_path=request_path or ctx.get("path"),
            response_code=response_code,
            response_time_ms=response_time_ms,
            tags=tags or [],
            extra_metadata=extra_metadata or {},
        )

        # Sanitize sensitive data
        self._sanitize_entry(entry)

        # Store
        await self._store_entry(entry)

        logger.debug(
            f"Audit: {entry.action} {entry.resource_type} "
            f"by {entry.actor_type}:{entry.actor_id} - {entry.status}"
        )

        return entry

    def _sanitize_entry(self, entry: AuditEntry) -> None:
        """Remove sensitive data from audit entry.

        NOTE: the previous implementation only recursed into nested
        dicts and treated lists as opaque values — so payloads like
        ``{"keys": ["sk-...", "..."]}`` or ``{"users": [{"password": "..."}]}``
        leaked secrets into the audit trail verbatim. We now:

          * redact a list when its parent key matches a sensitive field
            (e.g. ``keys`` / ``tokens`` / ``secrets`` plural forms),
          * otherwise recurse element-wise so nested dicts inside the list
            still get scrubbed.
        """
        sensitive_fields = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "credential",
            "private_key",
            "access_key",
            "secret_key",
            # NOTE: plural forms commonly keyed to lists of
            # secrets in agent/automation payloads. These must redact the
            # entire value (incl. list-of-strings) not just nested dicts.
            "keys",
            "tokens",
            "secrets",
            "passwords",
        }

        def _is_sensitive_key(key: str) -> bool:
            kl = key.lower()
            return any(s in kl for s in sensitive_fields)

        def sanitize_value(value: Any) -> Any:
            if isinstance(value, dict):
                return sanitize_dict(value)
            if isinstance(value, list):
                # NOTE: preserve list structure but scrub nested
                # dicts / lists; leaf scalars (strings of arbitrary
                # provenance) are passed through unchanged unless the
                # parent key flagged the entire list as sensitive (handled
                # at the dict level below).
                return [sanitize_value(item) for item in value]
            return value

        def sanitize_dict(d: dict[str, Any] | None) -> dict[str, Any] | None:
            if not d:
                return d
            sanitized: dict[str, Any] = {}
            for key, value in d.items():
                if _is_sensitive_key(key):
                    # Redact entire value regardless of type (string, list
                    # of strings, nested dict). This catches the common
                    # pluralised cases like ``"keys": [...]`` or
                    # ``"tokens": [...]``.
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = sanitize_value(value)
            return sanitized

        entry.changes = sanitize_dict(entry.changes)
        entry.previous_state = sanitize_dict(entry.previous_state)
        entry.new_state = sanitize_dict(entry.new_state)
        entry.extra_metadata = sanitize_dict(entry.extra_metadata) or {}

    async def _store_entry(self, entry: AuditEntry) -> None:
        """Persist a single audit entry to the database immediately.

        SECURITY: entries are written directly (not buffered) so
        that an audit record lives inside the same transaction as the action
        that produced it — they commit together or roll back together.

        Audit-write failures are *loud* (ERROR log + metric) but never bubble
        up to the caller. If we re-raised here, a transient DB hiccup or a
        schema drift could crash a user-facing action that has already been
        executed (the side effect has happened, the audit row hasn't). The
        correct trade-off is: record the action, make the failure visible to
        operators, but don't crash the request.
        """
        record = AuditLogRecord(
            id=entry.id,
            timestamp=entry.timestamp,
            action=entry.action,
            resource_type=entry.resource_type,
            resource_id=str(entry.resource_id) if entry.resource_id else None,
            resource_name=entry.resource_name,
            actor_id=str(entry.actor_id) if entry.actor_id else None,
            actor_type=entry.actor_type,
            actor_name=entry.actor_name,
            actor_email=entry.actor_email,
            session_id=entry.session_id,
            organization_id=entry.organization_id,
            site_id=entry.site_id,
            ip_address=entry.ip_address,
            user_agent=entry.user_agent,
            request_id=entry.request_id,
            request_method=entry.request_method,
            request_path=entry.request_path,
            response_code=entry.response_code,
            response_time_ms=entry.response_time_ms,
            status=entry.status,
            error_message=entry.error_message,
            changes=entry.changes,
            previous_state=entry.previous_state,
            new_state=entry.new_state,
            tags=entry.tags,
            extra_metadata=entry.extra_metadata,
        )

        # SECURITY / ROBUSTNESS: wrap the audit write in a
        # SAVEPOINT (``begin_nested``) so a failure here — schema drift,
        # constraint violation, transient DB hiccup — rolls back ONLY
        # the audit row, not the caller's pending mutations. Without this,
        # a failed ``flush()`` leaves the session in PendingRollbackError
        # state and the outer commit on ``get_session`` cleanup will fail,
        # effectively undoing a user action that already returned 200.
        #
        # NOTE: inside the savepoint, lock the most-recent
        # existing audit row FOR UPDATE so concurrent inserts cannot both
        # compute the same ``prev_hash`` and end up branching the chain.
        # Postgres's row-level lock is held until the savepoint commits.
        # If we cannot acquire the lock or there is no prior row, we
        # treat this as a genesis row (``prev_hash=None``).
        try:
            async with self.db.begin_nested():
                # Lock the latest audit row to serialise chain extension.
                # ``with_for_update(skip_locked=False)`` blocks until the
                # conflicting writer commits / rolls back. The select is
                # ordered by ``timestamp DESC, id DESC`` so we deterministically
                # pick the same prev row across replicas.
                # SECURITY (chain genesis race): ``with_for_update()`` on a
                # ``LIMIT 1`` tail read locks NOTHING when the table (or the
                # filtered window) is empty, so two concurrent genesis writers
                # would both observe prev_hash=NULL and branch the chain. Take
                # a transaction-level advisory lock FIRST to serialise the
                # whole read-tail/insert critical section even when no prior
                # row exists. Best-effort: suppressed on non-PostgreSQL
                # backends (e.g. SQLite tests), which are single-threaded and
                # therefore cannot branch anyway.
                import contextlib

                from sqlalchemy.exc import OperationalError, ProgrammingError

                with contextlib.suppress(Exception):
                    await self.db.execute(
                        text("SELECT pg_advisory_xact_lock(:k)"),
                        {"k": _AUDIT_CHAIN_LOCK_KEY},
                    )

                prev_hmac: str | None = None
                try:
                    latest_result = await self.db.execute(
                        select(AuditLogRecord.row_hmac)
                        .order_by(
                            desc(AuditLogRecord.timestamp),
                            desc(AuditLogRecord.id),
                        )
                        .limit(1)
                        .with_for_update()
                    )
                    prev_hmac = latest_result.scalar_one_or_none()
                except (OperationalError, ProgrammingError):
                    # Column may not exist yet (migration not run) — fall
                    # back to an unchained row and continue. The validator
                    # treats NULL prev_hash/row_hmac as "pre-chain".
                    prev_hmac = None

                record.prev_hash = prev_hmac
                try:
                    record.row_hmac = _compute_row_hmac(prev_hmac, record)
                except Exception:
                    # If HMAC computation blows up for any reason, do not
                    # block the audit write — record it unchained and log.
                    logger.exception("audit chain HMAC computation failed")
                    record.row_hmac = None

                self.db.add(record)
                # flush is implicit on savepoint commit but we force it
                # here so any IntegrityError is raised inside the nested
                # transaction and caught below.
                await self.db.flush()
        except Exception:
            logger.exception(
                "CRITICAL: audit log write failed — audit trail incomplete "
                "(action=%s resource_type=%s actor_id=%s)",
                entry.action,
                entry.resource_type,
                entry.actor_id,
            )
            try:
                from app.core.metrics import audit_write_failures_total

                audit_write_failures_total.labels(
                    resource_type=str(entry.resource_type),
                ).inc()
            except Exception:  # pragma: no cover - metrics optional
                pass
            # Do NOT re-raise: the action has already happened; the failure
            # must be visible to ops but must not break the user request.
            # The savepoint has already rolled back so the outer
            # transaction remains viable for its final commit.

    async def _flush_buffer(self) -> None:
        """No-op: audit entries are persisted immediately in ``_store_entry``.

        Kept for backward compatibility with callers that still invoke
        ``_flush_buffer()`` (e.g. the :func:`audit_action` decorator and the
        ``query()`` / ``get_activity_summary()`` helpers that used to need
        a pre-query flush).
        """
        return

    # =========================================================================
    # Security Events
    # =========================================================================

    async def log_security_event(
        self,
        event_type: SecurityEventType,
        user_id: UUID | None = None,
        user_email: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        success: bool = True,
        details: dict[str, Any] | None = None,
        risk_score: int = 0,
    ) -> SecurityEvent:
        """
        Log a security event.

        Args:
            event_type: Type of security event
            user_id: Affected user ID
            user_email: User email
            ip_address: Source IP
            user_agent: Client user agent
            success: Whether operation succeeded
            details: Additional details
            risk_score: Calculated risk score (0-100)

        Returns:
            Created SecurityEvent
        """
        event = SecurityEvent(
            id=uuid4(),
            timestamp=datetime.now(UTC),
            event_type=event_type,
            user_id=user_id,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details=details or {},
            risk_score=risk_score,
        )

        # Persist to database
        record = SecurityEventRecord(
            id=event.id,
            timestamp=event.timestamp,
            event_type=event_type.value,
            user_id=user_id,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            outcome="success" if success else "failure",
            risk_score=risk_score,
            details=details or {},
        )
        try:
            self.db.add(record)
            await self.db.flush()
        except Exception as exc:
            logger.error("Failed to persist security event: %s", exc)

        logger.info(
            f"Security event: {event_type.value} "
            f"user={user_email} ip={ip_address} success={success}"
        )

        # High-risk events trigger alerts
        if risk_score >= 70:
            await self._trigger_security_alert(event)

        return event

    async def _trigger_security_alert(self, event: SecurityEvent) -> None:
        """Trigger alert for high-risk security events."""
        from app.core.events import event_bus

        await event_bus.publish(
            "security.alert",
            {
                "event_type": event.event_type.value,
                "user_id": str(event.user_id) if event.user_id else None,
                "ip_address": event.ip_address,
                "risk_score": event.risk_score,
                "details": event.details,
            },
        )

    # =========================================================================
    # Querying
    # =========================================================================

    async def query(
        self,
        query: AuditQuery,
    ) -> tuple[list[AuditEntry], int]:
        """
        Query audit logs.

        Args:
            query: Query parameters

        Returns:
            Tuple of (entries, total_count)
        """
        # Ensure buffer is flushed before querying
        await self._flush_buffer()

        conditions = []
        if query.start_date:
            conditions.append(AuditLogRecord.timestamp >= query.start_date)
        if query.end_date:
            conditions.append(AuditLogRecord.timestamp <= query.end_date)
        if query.actions:
            conditions.append(AuditLogRecord.action.in_(query.actions))
        if query.resource_types:
            conditions.append(AuditLogRecord.resource_type.in_(query.resource_types))
        if query.resource_id:
            conditions.append(AuditLogRecord.resource_id == str(query.resource_id))
        if query.actor_id:
            conditions.append(AuditLogRecord.actor_id == str(query.actor_id))
        if query.organization_id:
            conditions.append(AuditLogRecord.organization_id == query.organization_id)
        if query.site_id:
            conditions.append(AuditLogRecord.site_id == query.site_id)
        if query.status:
            conditions.append(AuditLogRecord.status == query.status)
        if query.search:
            escaped = escape_like(query.search)
            like = f"%{escaped}%"
            conditions.append(
                or_(
                    AuditLogRecord.action.ilike(like, escape="\\"),
                    AuditLogRecord.resource_type.ilike(like, escape="\\"),
                    AuditLogRecord.resource_name.ilike(like, escape="\\"),
                    AuditLogRecord.actor_name.ilike(like, escape="\\"),
                    AuditLogRecord.actor_email.ilike(like, escape="\\"),
                    AuditLogRecord.ip_address.ilike(like, escape="\\"),
                )
            )

        where_clause = and_(*conditions) if conditions else sa_true()

        # Count total
        count_result = await self.db.execute(
            select(func.count(AuditLogRecord.id)).where(where_clause)
        )
        total = count_result.scalar() or 0

        # Fetch entries
        result = await self.db.execute(
            select(AuditLogRecord)
            .where(where_clause)
            .order_by(desc(AuditLogRecord.timestamp))
            .offset(query.offset)
            .limit(query.limit)
        )
        rows = result.scalars().all()

        entries = [
            AuditEntry(
                id=r.id,
                timestamp=r.timestamp,
                action=r.action,
                resource_type=r.resource_type,
                resource_id=UUID(r.resource_id) if r.resource_id else None,
                resource_name=r.resource_name,
                actor_id=UUID(r.actor_id) if r.actor_id else None,
                actor_type=r.actor_type,
                actor_name=r.actor_name,
                actor_email=r.actor_email,
                session_id=r.session_id,
                organization_id=r.organization_id,
                site_id=r.site_id,
                ip_address=r.ip_address,
                user_agent=r.user_agent,
                status=r.status,
                changes=r.changes,
                previous_state=r.previous_state,
                new_state=r.new_state,
                error_message=r.error_message,
                request_id=r.request_id,
                request_method=r.request_method,
                request_path=r.request_path,
                response_code=r.response_code,
                response_time_ms=int(r.response_time_ms) if r.response_time_ms else None,
                tags=r.tags or [],
                extra_metadata=r.extra_metadata or {},
            )
            for r in rows
        ]

        return entries, total

    async def get_by_resource(
        self,
        resource_type: str | ResourceType,
        resource_id: UUID,
        organization_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEntry], int]:
        """Get audit logs for a specific resource, scoped to an organization.

                CRITICAL: ``organization_id`` is required to prevent IDOR attacks
        . Callers MUST pass the authenticated user's
                ``organization_id``, never a user-supplied value. A SUPER_ADMIN
                caller still must pass *some* org; if truly unscoped access is
                needed, use :meth:`query` directly.

                NOTE: now returns ``(entries, total)`` so the
                endpoint layer can build a ``PaginatedResponse`` without issuing
                a second count query. Previously this returned a bare list and
                the frontend could not display "page N of M".
        """
        query = AuditQuery(
            resource_types=[
                resource_type.value if isinstance(resource_type, Enum) else resource_type
            ],
            resource_id=resource_id,
            organization_id=organization_id,
            limit=max(1, min(limit, 500)),
            offset=max(0, offset),
        )
        return await self.query(query)

    async def get_by_actor(
        self,
        actor_id: UUID,
        organization_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEntry], int]:
        """Get audit logs for a specific actor, scoped to an organization.

                CRITICAL: ``organization_id`` is required to prevent IDOR attacks
        . Callers MUST pass the authenticated user's
                ``organization_id``, never a user-supplied value.

                NOTE: now returns ``(entries, total)`` — see
                :meth:`get_by_resource` for the same rationale.
        """
        query = AuditQuery(
            actor_id=actor_id,
            organization_id=organization_id,
            start_date=start_date,
            end_date=end_date,
            limit=max(1, min(limit, 500)),
            offset=max(0, offset),
        )
        return await self.query(query)

    async def get_security_events(
        self,
        user_id: UUID | None = None,
        event_types: list[SecurityEventType] | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        organization_id: UUID | None = None,
        risk_min: int | None = None,
        risk_max: int | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SecurityEvent], int]:
        """Get security events with optional filters.

        NOTE: now returns ``(events, total)`` so callers
        can build a ``PaginatedResponse``. ``offset`` was added at the
        same time for proper pagination beyond the first page.

        NOTE: ``risk_min`` / ``risk_max`` apply an inclusive
        ``risk_score`` range filter. ``SecurityEventRecord`` has no
        ``severity`` column — the endpoint maps a severity label
        (critical|high|medium|low) to a risk_score band and passes the
        bounds here.

        ``search`` applies a case-insensitive LIKE across the sensible
        free-text columns (``event_type``, ``user_email``, ``ip_address``).
        The pattern is LIKE-escaped via :func:`escape_like` so user input
        cannot inject ``%``/``_`` wildcards, matching how every other
        search in the codebase is escaped.

        SECURITY: ``organization_id`` MUST be passed by non-super_admin
        callers. Without it, an org_admin sees security events from
        every other org on the platform (failed logins, MFA failures,
        suspicious activity). Pass ``None`` only for super_admin
        platform-wide views.
        """
        conditions = []
        if organization_id:
            conditions.append(SecurityEventRecord.organization_id == organization_id)
        if user_id:
            conditions.append(SecurityEventRecord.user_id == user_id)
        if event_types:
            conditions.append(SecurityEventRecord.event_type.in_([e.value for e in event_types]))
        if start_date:
            conditions.append(SecurityEventRecord.timestamp >= start_date)
        if end_date:
            conditions.append(SecurityEventRecord.timestamp <= end_date)
        if risk_min is not None:
            conditions.append(SecurityEventRecord.risk_score >= risk_min)
        if risk_max is not None:
            conditions.append(SecurityEventRecord.risk_score <= risk_max)
        if search:
            escaped = escape_like(search)
            like = f"%{escaped}%"
            conditions.append(
                or_(
                    SecurityEventRecord.event_type.ilike(like, escape="\\"),
                    SecurityEventRecord.user_email.ilike(like, escape="\\"),
                    SecurityEventRecord.ip_address.ilike(like, escape="\\"),
                )
            )

        where_clause = and_(*conditions) if conditions else sa_true()

        # Count total matching rows before paginating.
        count_result = await self.db.execute(
            select(func.count(SecurityEventRecord.id)).where(where_clause)
        )
        total = count_result.scalar() or 0

        result = await self.db.execute(
            select(SecurityEventRecord)
            .where(where_clause)
            .order_by(desc(SecurityEventRecord.timestamp))
            .offset(max(0, offset))
            .limit(max(1, min(limit, 500)))
        )
        rows = result.scalars().all()

        events = [
            SecurityEvent(
                id=r.id,
                timestamp=r.timestamp,
                event_type=_safe_event_type(r.event_type),
                user_id=r.user_id,
                user_email=r.user_email,
                ip_address=r.ip_address,
                user_agent=r.user_agent,
                success=r.success,
                details=r.details or {},
                risk_score=r.risk_score,
            )
            for r in rows
        ]
        return events, total

    # =========================================================================
    # Analytics
    # =========================================================================

    async def get_activity_summary(
        self,
        organization_id: UUID,
        start_date: datetime,
        end_date: datetime,
        site_id: UUID | None = None,
    ) -> dict[str, Any]:
        """
        Get activity summary for an organization.

        Returns counts of actions by type, resource, and actor.
        """
        await self._flush_buffer()

        base_conditions = [
            AuditLogRecord.organization_id == organization_id,
            AuditLogRecord.timestamp >= start_date,
            AuditLogRecord.timestamp <= end_date,
        ]
        if site_id:
            base_conditions.append(AuditLogRecord.site_id == site_id)
        base_where = and_(*base_conditions)

        # Total count
        total_result = await self.db.execute(
            select(func.count(AuditLogRecord.id)).where(base_where)
        )
        total = total_result.scalar() or 0

        # By action
        action_result = await self.db.execute(
            select(AuditLogRecord.action, func.count(AuditLogRecord.id))
            .where(base_where)
            .group_by(AuditLogRecord.action)
        )
        by_action = {row[0]: row[1] for row in action_result.all()}

        # By resource type
        resource_result = await self.db.execute(
            select(AuditLogRecord.resource_type, func.count(AuditLogRecord.id))
            .where(base_where)
            .group_by(AuditLogRecord.resource_type)
        )
        by_resource = {row[0]: row[1] for row in resource_result.all()}

        # By status
        status_result = await self.db.execute(
            select(AuditLogRecord.status, func.count(AuditLogRecord.id))
            .where(base_where)
            .group_by(AuditLogRecord.status)
        )
        by_status = {row[0]: row[1] for row in status_result.all()}

        return {
            "total_events": total,
            "by_action": by_action,
            "by_resource_type": by_resource,
            "by_actor": {},
            "by_status": by_status,
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
            },
        }

    async def get_security_summary(
        self,
        organization_id: UUID | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Get security event summary."""
        conditions = []
        if organization_id:
            conditions.append(SecurityEventRecord.organization_id == organization_id)
        if start_date:
            conditions.append(SecurityEventRecord.timestamp >= start_date)
        if end_date:
            conditions.append(SecurityEventRecord.timestamp <= end_date)

        where_clause = and_(*conditions) if conditions else sa_true()

        total_result = await self.db.execute(
            select(func.count(SecurityEventRecord.id)).where(where_clause)
        )
        total = total_result.scalar() or 0

        failed_logins_result = await self.db.execute(
            select(func.count(SecurityEventRecord.id)).where(
                where_clause,
                SecurityEventRecord.event_type.in_(
                    [
                        SecurityEventType.LOGIN_FAILED.value,
                        SecurityEventType.BRUTE_FORCE_ATTEMPT.value,
                    ]
                ),
            )
        )
        failed_logins = failed_logins_result.scalar() or 0

        successful_logins_result = await self.db.execute(
            select(func.count(SecurityEventRecord.id)).where(
                where_clause,
                SecurityEventRecord.event_type == SecurityEventType.LOGIN_SUCCESS.value,
            )
        )
        successful_logins = successful_logins_result.scalar() or 0

        lockouts_result = await self.db.execute(
            select(func.count(SecurityEventRecord.id)).where(
                where_clause,
                SecurityEventRecord.event_type == SecurityEventType.ACCOUNT_LOCKED.value,
            )
        )
        lockouts = lockouts_result.scalar() or 0

        suspicious_result = await self.db.execute(
            select(func.count(SecurityEventRecord.id)).where(
                where_clause,
                SecurityEventRecord.event_type == SecurityEventType.SUSPICIOUS_ACTIVITY.value,
            )
        )
        suspicious = suspicious_result.scalar() or 0

        high_risk_result = await self.db.execute(
            select(func.count(SecurityEventRecord.id)).where(
                where_clause,
                SecurityEventRecord.risk_score >= 70,
            )
        )
        high_risk = high_risk_result.scalar() or 0

        return {
            "total_events": total,
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "account_lockouts": lockouts,
            "suspicious_activities": suspicious,
            "high_risk_events": high_risk,
        }

    # =========================================================================
    # Tamper-Evidence Chain Validation
    # =========================================================================

    async def validate_audit_chain(
        self,
        start_id: UUID | None = None,
        end_id: UUID | None = None,
        limit: int = 10000,
    ) -> dict[str, Any]:
        """Walk the audit hash chain and verify each row's HMAC.

        Rows are visited in (timestamp, id) ascending order — same order
        used when extending the chain in :meth:`_store_entry`. The walker
        recomputes ``HMAC(prev_hash || canonical_json)`` for each row and
        compares against the stored ``row_hmac``.

        Rows written before the chain was introduced (``row_hmac IS NULL``)
        are tolerated and reported as ``unchained`` but do not break the
        verdict for chained rows.

        Returns::

            {
                "valid": bool,                # True iff no broken links
                "checked": int,               # rows examined
                "unchained": int,             # rows with NULL row_hmac
                "broken_at": str | None,      # first row id that failed
                "broken_reason": str | None,  # human-readable cause
            }

        ``limit`` caps the walk so a malicious or huge table can't lock
        up the admin endpoint. Callers can paginate by passing
        ``start_id``.
        """
        await self._flush_buffer()

        conditions = []
        if start_id is not None:
            # Resolve the row to its timestamp so we filter by a
            # totally-ordered key (timestamp + id) rather than a UUID.
            start_row = await self.db.execute(
                select(AuditLogRecord.timestamp, AuditLogRecord.id).where(
                    AuditLogRecord.id == start_id
                )
            )
            start_pair = start_row.first()
            if start_pair is not None:
                conditions.append(AuditLogRecord.timestamp >= start_pair[0])
        if end_id is not None:
            end_row = await self.db.execute(
                select(AuditLogRecord.timestamp, AuditLogRecord.id).where(
                    AuditLogRecord.id == end_id
                )
            )
            end_pair = end_row.first()
            if end_pair is not None:
                conditions.append(AuditLogRecord.timestamp <= end_pair[0])

        where_clause = and_(*conditions) if conditions else sa_true()

        result = await self.db.execute(
            select(AuditLogRecord)
            .where(where_clause)
            .order_by(AuditLogRecord.timestamp.asc(), AuditLogRecord.id.asc())
            .limit(max(1, min(limit, 100000)))
        )
        rows = result.scalars().all()

        checked = 0
        unchained = 0
        # We can't easily fetch the row immediately preceding the window,
        # so we accept the first row's prev_hash as-is (we only verify the
        # row body links to the stored hash from that point forward).
        last_seen_hmac: str | None = None
        # SECURITY (NULL-row tamper): legitimately-NULL ``row_hmac`` rows only
        # exist at the START of the table — rows written BEFORE the chain
        # migration ran. Once the chain has begun (we have seen at least one
        # chained row), every subsequent row is written with a populated
        # ``row_hmac``; a NULL after that point is not a benign pre-chain row
        # but a surgical tamper (an attacker NULLing a row to hide an edit /
        # break a link). Treat it as a chain break rather than resetting the
        # prev-link check.
        seen_chained = False
        for row in rows:
            checked += 1
            if row.row_hmac is None:
                if seen_chained:
                    # NULL row_hmac after the chain has begun => tampering.
                    return {
                        "valid": False,
                        "checked": checked,
                        "unchained": unchained,
                        "broken_at": str(row.id),
                        "broken_reason": (
                            "row_hmac is NULL on a post-genesis row "
                            "(chain link removed — possible tampering)"
                        ),
                    }
                # Pre-chain row (before the chain existed) — note and continue.
                unchained += 1
                last_seen_hmac = None
                continue
            seen_chained = True

            # If we already saw a chained row, the next row's prev_hash
            # MUST equal it. (We allow the very first chained row in the
            # window to have any prev_hash since it may legitimately point
            # to a row outside the queried range.)
            if last_seen_hmac is not None and row.prev_hash != last_seen_hmac:
                return {
                    "valid": False,
                    "checked": checked,
                    "unchained": unchained,
                    "broken_at": str(row.id),
                    "broken_reason": (
                        f"prev_hash mismatch: expected {last_seen_hmac!r} got {row.prev_hash!r}"
                    ),
                }

            expected = _compute_row_hmac(row.prev_hash, row)
            if not hmac.compare_digest(expected, row.row_hmac):
                return {
                    "valid": False,
                    "checked": checked,
                    "unchained": unchained,
                    "broken_at": str(row.id),
                    "broken_reason": "row_hmac mismatch (row body modified)",
                }
            last_seen_hmac = row.row_hmac

        return {
            "valid": True,
            "checked": checked,
            "unchained": unchained,
            "broken_at": None,
            "broken_reason": None,
        }

    # =========================================================================
    # Data Retention
    # =========================================================================

    async def cleanup_old_entries(
        self,
        retention_days: int = 90,
    ) -> int:
        """
        Delete audit entries older than retention period.

        Args:
            retention_days: Number of days to retain

        Returns:
            Number of entries deleted
        """
        from datetime import timedelta

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)

        # Delete old audit logs
        result = await self.db.execute(
            sa_delete(AuditLogRecord).where(AuditLogRecord.timestamp < cutoff)
        )
        audit_deleted = result.rowcount or 0  # type: ignore[attr-defined]

        # Delete old security events
        sec_result = await self.db.execute(
            sa_delete(SecurityEventRecord).where(SecurityEventRecord.timestamp < cutoff)
        )
        sec_deleted = sec_result.rowcount or 0  # type: ignore[attr-defined]

        total_deleted = audit_deleted + sec_deleted
        logger.info(
            f"Audit cleanup: removed {audit_deleted} audit logs and "
            f"{sec_deleted} security events older than {retention_days} days"
        )
        return total_deleted

    async def export(
        self,
        query: AuditQuery,
        format: str = "json",
    ) -> bytes:
        """
        Export audit logs.

        Args:
            query: Query parameters
            format: Export format (json, csv)

        Returns:
            Exported data as bytes
        """
        entries, _ = await self.query(query)

        if format == "csv":
            import csv
            import io

            output = io.StringIO()
            writer = csv.DictWriter(
                output,
                fieldnames=[
                    "timestamp",
                    "action",
                    "resource_type",
                    "resource_id",
                    "actor_id",
                    "actor_name",
                    "status",
                    "ip_address",
                ],
            )
            writer.writeheader()
            # INJ-04: neutralize CSV/spreadsheet formula injection — actor_name,
            # action, resource_type/id, ip_address can carry attacker-influenced
            # text that Excel/Sheets would execute (=cmd|/=HYPERLINK DDE/exfil).
            from app.core.security_utils import csv_safe

            for entry in entries:
                writer.writerow(
                    {
                        "timestamp": entry.timestamp.isoformat(),
                        "action": csv_safe(entry.action),
                        "resource_type": csv_safe(entry.resource_type),
                        "resource_id": csv_safe(
                            str(entry.resource_id) if entry.resource_id else ""
                        ),
                        "actor_id": str(entry.actor_id) if entry.actor_id else "",
                        "actor_name": csv_safe(entry.actor_name or ""),
                        "status": csv_safe(entry.status),
                        "ip_address": csv_safe(entry.ip_address or ""),
                    }
                )
            return output.getvalue().encode()
        else:
            import json

            data = [
                {
                    "id": str(entry.id),
                    "timestamp": entry.timestamp.isoformat(),
                    "action": entry.action,
                    "resource_type": entry.resource_type,
                    "resource_id": str(entry.resource_id) if entry.resource_id else None,
                    "resource_name": entry.resource_name,
                    "actor_id": str(entry.actor_id) if entry.actor_id else None,
                    "actor_name": entry.actor_name,
                    "status": entry.status,
                    "changes": entry.changes,
                    "extra_metadata": entry.extra_metadata,
                }
                for entry in entries
            ]
            return json.dumps(data, indent=2).encode()


# =============================================================================
# Decorators
# =============================================================================


def audit_action(
    action: str | AuditAction,
    resource_type: str | ResourceType,
    resource_id_param: str | None = None,
    include_request_body: bool = False,
) -> Any:
    """
    Decorator for automatic audit logging of endpoint functions.

    Usage:
        @audit_action(AuditAction.CREATE, ResourceType.USER)
        async def create_user(user_data: UserCreate, db: Session):
            ...
    """

    def decorator(func: Any) -> Any:
        import functools
        import inspect

        # NOTE: the previous implementation looked up the session
        # only as ``kwargs.get("session") or kwargs.get("db")`` — so an
        # endpoint that named its session parameter anything else (e.g.
        # ``logdb``, ``primary_session``, ``async_session``) would silently
        # skip its audit row entirely. We resolve the session at decoration
        # time by walking the wrapped function's signature and remembering
        # which parameter name is annotated as ``AsyncSession`` (or a
        # subclass thereof). At call time we read that parameter from
        # ``kwargs`` first, then from positional ``args``.
        sig = inspect.signature(func)
        session_param_name: str | None = None
        session_param_index: int | None = None
        try:
            for idx, (pname, param) in enumerate(sig.parameters.items()):
                annotation = param.annotation
                # Unwrap Annotated[AsyncSession, Depends(...)] form used
                # widely by FastAPI endpoints.
                try:
                    from typing import get_args, get_origin

                    if get_origin(annotation) is not None:
                        annotated_args = get_args(annotation)
                        if annotated_args:
                            annotation = annotated_args[0]
                except Exception:
                    pass
                try:
                    if isinstance(annotation, type) and issubclass(annotation, AsyncSession):
                        session_param_name = pname
                        session_param_index = idx
                        break
                except TypeError:
                    continue
        except Exception:
            session_param_name = None

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            import time

            start_time = time.time()

            try:
                result = await func(*args, **kwargs)

                db: AsyncSession | None = None
                if session_param_name is not None:
                    db = kwargs.get(session_param_name)
                    if (
                        db is None
                        and session_param_index is not None
                        and session_param_index < len(args)
                    ):
                        candidate = args[session_param_index]
                        if isinstance(candidate, AsyncSession):
                            db = candidate
                # Fallback to legacy names for back-compat.
                if db is None:
                    db = kwargs.get("session") or kwargs.get("db")

                if db is None:
                    logger.warning(
                        "audit_action(%s, %s): no AsyncSession parameter found "
                        "in %s%s — audit row skipped. Add an AsyncSession-typed "
                        "parameter to enable audit logging.",
                        action,
                        resource_type,
                        getattr(func, "__qualname__", func.__name__),
                        tuple(sig.parameters.keys()),
                    )
                    return result

                audit_svc = AuditService(db)
                elapsed_ms = int((time.time() - start_time) * 1000)

                # Resolve resource_id from kwargs if configured
                rid = None
                if resource_id_param and resource_id_param in kwargs:
                    rid = kwargs[resource_id_param]

                ctx = request_context.get({})
                await audit_svc.log(
                    action=action,
                    resource_type=resource_type,
                    resource_id=rid,
                    actor_id=ctx.get("user_id"),
                    request_method=ctx.get("method"),
                    request_path=ctx.get("path"),
                    ip_address=ctx.get("ip_address"),
                    user_agent=ctx.get("user_agent"),
                    response_time_ms=elapsed_ms,
                    status="success",
                )
                await audit_svc._flush_buffer()

                return result
            except Exception:
                raise

        return wrapper

    return decorator


# =============================================================================
# Context Manager
# =============================================================================


def set_audit_context(
    user_id: UUID | None = None,
    user_name: str | None = None,
    organization_id: UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_id: str | None = None,
    method: str | None = None,
    path: str | None = None,
) -> None:
    """Set audit context for the current request."""
    request_context.set(
        {
            "user_id": user_id,
            "user_name": user_name,
            "organization_id": organization_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "request_id": request_id,
            "method": method,
            "path": path,
        }
    )


def clear_audit_context() -> None:
    """Clear audit context."""
    request_context.set({})

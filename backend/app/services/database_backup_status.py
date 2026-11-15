# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Database (pg-backup) backup status
============================================

The ``pg-backup`` container dumps both databases, encrypted to an operator's
OpenPGP public key, and refuses to write plaintext without one. On a fresh install
no key exists, so there are NO database backups -- and before this module the only
places that said so were the container's own log and an unhealthy marker in
``docker compose ps``.

pg-backup publishes its state as small files in ``<pg_backups>/.metrics/``:

* ``pg_backup.prom`` -- exactly four Prometheus samples (enabled, encryption,
  last attempt failed, last success timestamp);
* ``pg_backup.last_success`` -- ``<epoch> <batch> <extension>`` for the last
  completed dump pair;
* ``pg_backup.reason`` -- why encryption is (not) in use: ``encrypted``,
  ``plaintext_opt_in``, ``no_key``, ``key_path_is_directory``, ``no_public_key``,
  ``import_failed``, ``ambiguous_key`` or ``recipient_unusable``.

The api and worker mount that volume READ-ONLY. This module reads the files with
the same strictness as ``docker/backup_metrics.py`` (bounded, no symlinks, exact
fields) and turns them into one state the UI, ``/health/detail`` and the alert
task share. It never reads, lists or serves a dump.
"""

from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_STATUS_DIR = "/var/lib/freesdn/pg-backups/.metrics"
PREFIX = "freesdn_pg_backup_"
FIELDS = ("enabled", "encryption_enabled", "last_attempt_failed", "last_success_timestamp")
REASONS = frozenset(
    {
        "encrypted",
        "plaintext_opt_in",
        "no_key",
        "key_path_is_directory",
        "no_public_key",
        "import_failed",
        "ambiguous_key",
        "recipient_unusable",
    }
)
_MAX_STATUS_BYTES = 4096

# state -> severity. "critical" means there is no recent restorable backup.
SEVERITY = {
    "healthy": "ok",
    "unencrypted": "warning",
    "pending": "warning",
    "unknown": "warning",
    "disabled": "critical",
    "failing": "critical",
    "stale": "critical",
}

SETUP_COMMAND = "./scripts/backup-keygen.sh > /path/off/this/host/freesdn-backup-private.asc"


@dataclass
class DatabaseBackupStatus:
    state: str
    severity: str
    enabled: bool | None = None
    encrypted: bool | None = None
    reason: str | None = None
    last_success_at: datetime | None = None
    max_age_seconds: int | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    setup_command: str | None = None

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("last_success_at", "checked_at"):
            if data[key] is not None:
                data[key] = data[key].isoformat()
        return data


def status_dir() -> Path:
    return Path(os.environ.get("PG_BACKUP_STATUS_DIR") or DEFAULT_STATUS_DIR)


def _positive_env(name: str, default: int, maximum: int) -> int:
    value = os.environ.get(name, "")
    if re.fullmatch(r"[0-9]{1,9}", value) and 0 < int(value) <= maximum:
        return int(value)
    return default


def _read_small(path: Path) -> str:
    """Bounded read that refuses symlinks, FIFOs and anything but a regular file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("status is not a regular file")
        data = stream.read(_MAX_STATUS_BYTES + 1)
    if len(data) > _MAX_STATUS_BYTES:
        raise ValueError("status exceeds limit")
    return data.decode("ascii")


def _read_metrics(path: Path, now: int) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in _read_small(path).splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ValueError("malformed sample")
        name, value = parts
        if not name.startswith(PREFIX) or name[len(PREFIX) :] not in FIELDS or name in values:
            raise ValueError("unexpected or duplicate sample")
        if not re.fullmatch(r"[0-9]{1,12}", value):
            raise ValueError("invalid sample value")
        number = int(value)
        if number > (now if name.endswith("timestamp") else 1):
            raise ValueError("sample outside range")
        values[name] = number
    if len(values) != len(FIELDS):
        raise ValueError("incomplete status")
    return {name[len(PREFIX) :]: number for name, number in values.items()}


def _pair_present(directory: Path, last_success: int) -> bool:
    """The completion pointer must name a non-empty dump pair from that run."""
    try:
        success, batch, extension = _read_small(directory / "pg_backup.last_success").split()
    except (OSError, ValueError, UnicodeError):
        return False
    if (
        not re.fullmatch(r"[0-9]{1,12}", success)
        or int(success) != last_success
        or not re.fullmatch(r"[0-9]{8}_[0-9]{6}", batch)
        or extension not in ("sql.gz", "sql.gz.gpg")
    ):
        return False
    for database in ("freesdn", "logdb"):
        try:
            info = (directory.parent / f"{database}_{batch}.{extension}").lstat()
        except OSError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
            return False
    return True


def read_database_backup_status(
    directory: Path | None = None, *, now: float | None = None
) -> DatabaseBackupStatus:
    """Classify pg-backup's published state. Never raises."""
    directory = directory or status_dir()
    current = int(now if now is not None else time.time())
    interval = _positive_env("BACKUP_INTERVAL_SECONDS", 86400, 31536000)
    grace = _positive_env("BACKUP_FRESHNESS_GRACE_SECONDS", 7200, 31536000)
    max_age = interval + grace

    try:
        metrics = _read_metrics(directory / "pg_backup.prom", current)
    except (OSError, ValueError, UnicodeError):
        # Not mounted (non-Compose runs), pg-backup never started, or a damaged
        # file: say we cannot tell rather than guessing either way.
        return DatabaseBackupStatus(
            state="unknown", severity=SEVERITY["unknown"], max_age_seconds=max_age
        )

    reason: str | None = None
    try:
        candidate = _read_small(directory / "pg_backup.reason").strip()
        reason = candidate if candidate in REASONS else None
    except (OSError, ValueError, UnicodeError):
        reason = None

    enabled = metrics["enabled"] == 1
    encrypted = metrics["encryption_enabled"] == 1
    last_success = metrics["last_success_timestamp"]
    last_success_at = datetime.fromtimestamp(last_success, UTC) if last_success else None
    base: dict[str, Any] = {
        "enabled": enabled,
        "encrypted": encrypted,
        "reason": reason,
        "last_success_at": last_success_at,
        "max_age_seconds": max_age,
    }

    if not enabled:
        state = "disabled"
    elif metrics["last_attempt_failed"] == 1:
        state = "failing"
    elif not last_success:
        state = "pending"
    elif current - last_success > max_age or not _pair_present(directory, last_success):
        state = "stale"
    elif not encrypted:
        state = "unencrypted"
    else:
        state = "healthy"
    return DatabaseBackupStatus(
        state=state,
        severity=SEVERITY[state],
        setup_command=SETUP_COMMAND if state == "disabled" else None,
        **base,
    )


# ---------------------------------------------------------------------------
# Alerting: tell the instance's super admins, in the notification bell
# ---------------------------------------------------------------------------

NOTICE_KIND = "database_backup_status"
REMIND_AFTER_SECONDS = 86400


def _notice_text(status: DatabaseBackupStatus) -> tuple[str, str]:
    last = status.last_success_at.strftime("%Y-%m-%d %H:%M UTC") if status.last_success_at else None
    if status.state == "disabled":
        title = "Database backups are OFF"
        if status.reason == "key_path_is_directory":
            body = (
                "pg-backup cannot read its public key: the key path is a directory that "
                "Docker created because the file was missing. On the host remove it "
                "(sudo rmdir <BACKUP_GPG_PUBLIC_KEY_PATH>), run ./scripts/backup-keygen.sh, "
                "then recreate the pg-backup container."
            )
        elif status.reason in (None, "no_key"):
            body = (
                "pg-backup will not write unencrypted dumps and no GPG public key is "
                "installed, so this FreeSDN has NO database backups. On the host run: "
                + SETUP_COMMAND
                + " -- keep the private key it hands you OFF this host."
            )
        else:
            body = (
                f"The installed backup key cannot be used ({status.reason}), so no "
                "database backups are being written. See `docker compose logs pg-backup`."
            )
    elif status.state == "failing":
        title = "Database backup failed"
        body = (
            "The last pg-backup run failed. The newest restorable dump is "
            + (f"from {last}." if last else "missing: there has never been one.")
            + " See `docker compose logs pg-backup`."
        )
    else:  # stale
        title = "Database backups are stale"
        body = (
            f"No completed database backup since {last or 'install'}; one is expected at "
            f"least every {round((status.max_age_seconds or 0) / 3600)} hours. Is the "
            "pg-backup container running?"
        )
    return title, body


async def notify_database_backup_state(
    session: Any, status: DatabaseBackupStatus, *, now: datetime | None = None
) -> int:
    """Notify each active super admin of a bad state, once per state and day.

    A recovered state is announced once to whoever was last told it was bad, so a
    stale alarm never lingers as the newest word on the subject. ``unknown`` (the
    status volume is not mounted) is never announced. Returns notices created;
    the caller commits.
    """
    from sqlalchemy import select

    from app.models.core import User, UserRole
    from app.models.notification import InAppNotification
    from app.services.notification import (
        NotificationCategory,
        NotificationService,
        NotificationSeverity,
    )

    if status.state == "unknown":
        return 0
    current = now or datetime.now(UTC)
    bad = status.severity == "critical"
    service = NotificationService(session)
    admins = (
        await session.execute(
            select(User.id).where(
                User.role == UserRole.SUPER_ADMIN.value,
                User.is_active.is_(True),
                User.deleted_at.is_(None),
            )
        )
    ).scalars()
    created = 0
    for user_id in list(admins):
        latest = (
            await session.execute(
                select(InAppNotification.data, InAppNotification.created_at)
                .where(
                    InAppNotification.user_id == user_id,
                    InAppNotification.data["kind"].astext == NOTICE_KIND,
                )
                .order_by(InAppNotification.created_at.desc())
                .limit(1)
            )
        ).first()
        last_state = (latest[0] or {}).get("state") if latest else None
        last_bad = last_state is not None and SEVERITY.get(last_state) == "critical"
        if bad:
            if (
                latest is not None
                and last_state == status.state
                and (current - latest[1]).total_seconds() < REMIND_AFTER_SECONDS
            ):
                continue
            title, body = _notice_text(status)
            severity = NotificationSeverity.CRITICAL
        elif last_bad and status.state in ("healthy", "unencrypted"):
            title = "Database backups are working again"
            body = "pg-backup completed a database backup" + (
                " (unencrypted, by explicit opt-in)." if status.state == "unencrypted" else "."
            )
            severity = NotificationSeverity.INFO
        else:
            continue
        await service.create_in_app(
            user_id=user_id,
            title=title,
            body=body,
            category=NotificationCategory.SYSTEM,
            severity=severity,
            action_url="/backup",
            data={"kind": NOTICE_KIND, "state": status.state, "reason": status.reason},
            commit=False,
        )
        created += 1
    return created

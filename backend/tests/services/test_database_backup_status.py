# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""pg-backup's state reaches the app: Backups page, /health/detail and the bell.

A fresh install has no GPG key, so pg-backup (correctly) writes nothing. Before
this, only the container log said so. These tests pin how the published status
files are read and when super admins are told.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import yaml
from fastapi import HTTPException
from sqlalchemy import select

from app.services.database_backup_status import (
    NOTICE_KIND,
    notify_database_backup_state,
    read_database_backup_status,
)

NOW = 1_800_000_000
COMPOSE = Path(__file__).resolve().parents[3] / "docker-compose.yml"


def _publish(
    root: Path,
    *,
    enabled: int = 1,
    encrypted: int = 1,
    failed: int = 0,
    success: int = NOW - 600,
    reason: str | None = "encrypted",
    pair: bool = True,
    extra: str = "",
) -> Path:
    metrics = root / ".metrics"
    metrics.mkdir(parents=True, exist_ok=True)
    (metrics / "pg_backup.prom").write_text(
        f"freesdn_pg_backup_enabled {enabled}\n"
        f"freesdn_pg_backup_encryption_enabled {encrypted}\n"
        f"freesdn_pg_backup_last_attempt_failed {failed}\n"
        f"freesdn_pg_backup_last_success_timestamp {success}\n" + extra
    )
    if reason is not None:
        (metrics / "pg_backup.reason").write_text(reason + "\n")
    extension = "sql.gz.gpg" if encrypted else "sql.gz"
    if success:
        (metrics / "pg_backup.last_success").write_text(f"{success} 20270115_080000 {extension}\n")
        if pair:
            for database in ("freesdn", "logdb"):
                (root / f"{database}_20270115_080000.{extension}").write_bytes(b"\x85dump")
    return metrics


def _state(metrics: Path) -> object:
    return read_database_backup_status(metrics, now=NOW)


def test_fresh_install_without_a_key_reads_disabled_with_the_setup_command(tmp_path):
    status = _state(_publish(tmp_path, enabled=0, encrypted=0, success=0, reason="no_key"))
    assert (status.state, status.severity, status.reason) == ("disabled", "critical", "no_key")
    assert "backup-keygen.sh" in status.setup_command
    assert status.last_success_at is None


def test_recent_encrypted_pair_is_healthy(tmp_path):
    status = _state(_publish(tmp_path))
    assert (status.state, status.severity, status.encrypted) == ("healthy", "ok", True)
    assert status.last_success_at == datetime.fromtimestamp(NOW - 600, UTC)
    assert status.setup_command is None


@pytest.mark.parametrize(
    ("kwargs", "state"),
    [
        ({"failed": 1}, "failing"),
        ({"success": 0}, "pending"),
        ({"success": NOW - 86400 - 7200 - 1}, "stale"),
        ({"pair": False}, "stale"),
        ({"encrypted": 0, "reason": "plaintext_opt_in"}, "unencrypted"),
    ],
)
def test_each_published_condition_maps_to_one_state(tmp_path, kwargs, state):
    assert _state(_publish(tmp_path, **kwargs)).state == state


def test_freshness_follows_the_configured_interval(tmp_path, monkeypatch):
    monkeypatch.setenv("BACKUP_INTERVAL_SECONDS", "3600")
    monkeypatch.setenv("BACKUP_FRESHNESS_GRACE_SECONDS", "600")
    status = _state(_publish(tmp_path, success=NOW - 5000))
    assert (status.state, status.max_age_seconds) == ("stale", 4200)


@pytest.mark.parametrize(
    "damage",
    ["missing", "duplicate", "unknown_sample", "future", "symlink", "oversized"],
)
def test_damaged_or_absent_status_is_unknown_not_guessed(tmp_path, damage):
    metrics = _publish(tmp_path)
    prom = metrics / "pg_backup.prom"
    if damage == "missing":
        prom.unlink()
    elif damage == "duplicate":
        prom.write_text(prom.read_text() + "freesdn_pg_backup_enabled 1\n")
    elif damage == "unknown_sample":
        prom.write_text(prom.read_text() + "freesdn_pg_backup_surprise 1\n")
    elif damage == "future":
        prom.write_text(prom.read_text().replace(str(NOW - 600), str(NOW + 600)))
    elif damage == "symlink":
        real = tmp_path / "elsewhere.prom"
        real.write_text(prom.read_text())
        prom.unlink()
        os.symlink(real, prom)
    else:
        prom.write_text(prom.read_text() + "#" * 5000 + "\n")
    status = _state(metrics)
    assert (status.state, status.severity) == ("unknown", "warning")


def test_unrecognised_reason_is_dropped(tmp_path):
    status = _state(_publish(tmp_path, enabled=0, reason="<script>"))
    assert status.state == "disabled" and status.reason is None


def test_health_detail_component_degrades_only_when_no_backup_is_restorable(tmp_path, monkeypatch):
    from app.api.v1.endpoints.health import HealthStatus, _database_backup_component

    monkeypatch.setenv("PG_BACKUP_STATUS_DIR", str(tmp_path / "absent"))
    assert _database_backup_component().status == HealthStatus.HEALTHY
    metrics = _publish(tmp_path, enabled=0, encrypted=0, success=0, reason="no_key")
    monkeypatch.setenv("PG_BACKUP_STATUS_DIR", str(metrics))
    component = _database_backup_component()
    assert component.status == HealthStatus.DEGRADED
    assert component.details["state"] == "disabled"
    assert component.details["reason"] == "no_key"


async def test_database_status_endpoint_is_for_unscoped_admins_only(tmp_path, monkeypatch):
    from app.api.v1.endpoints.backups import get_database_backup_status

    monkeypatch.setenv(
        "PG_BACKUP_STATUS_DIR",
        str(_publish(tmp_path, enabled=0, encrypted=0, success=0, reason="no_key")),
    )
    viewer = SimpleNamespace(role="viewer", is_superuser=False, is_org_admin=False)
    with pytest.raises(HTTPException) as denied:
        await get_database_backup_status(current_user=viewer)
    assert denied.value.status_code == 403
    scoped_key = SimpleNamespace(role="super_admin", is_superuser=True, _scoped=True)
    with pytest.raises(HTTPException):
        await get_database_backup_status(current_user=scoped_key)
    admin = SimpleNamespace(role="super_admin", is_superuser=True, is_org_admin=True)
    body = await get_database_backup_status(current_user=admin)
    assert body["state"] == "disabled" and body["reason"] == "no_key"


def test_api_and_worker_mount_the_status_read_only_and_share_the_cadence():
    if not COMPOSE.is_file():
        pytest.skip("requires the shipped Compose file")
    services = yaml.safe_load(COMPOSE.read_text())["services"]
    for name in ("api", "worker"):
        assert "pg_backups:/var/lib/freesdn/pg-backups:ro" in services[name]["volumes"], name
        env = services[name]["environment"]
        assert env["BACKUP_INTERVAL_SECONDS"] == "${BACKUP_INTERVAL_SECONDS:-86400}"
    # The writer and the readers agree on where the status lives.
    assert "pg_backups:/backups" in services["pg-backup"]["volumes"]


# ── notifications ────────────────────────────────────────────────────────────


async def _admins(db_session):
    from app.models.core import Organization, User

    org = uuid4()
    db_session.add(Organization(id=org, name="Backup alert fixture", slug="bak-" + org.hex))
    await db_session.flush()
    users = {}
    for role in ("super_admin", "viewer"):
        identity = uuid4()
        db_session.add(
            User(
                id=identity,
                organization_id=org,
                email=identity.hex + "@example.invalid",
                username=identity.hex,
                hashed_password="synthetic-not-a-login-password",
                role=role,
            )
        )
        users[role] = identity
    await db_session.flush()
    return users


async def _notices(db_session, user_id):
    from app.models.notification import InAppNotification

    rows = await db_session.execute(
        select(InAppNotification)
        .where(
            InAppNotification.user_id == user_id,
            InAppNotification.data["kind"].astext == NOTICE_KIND,
        )
        .order_by(InAppNotification.created_at)
    )
    return list(rows.scalars())


async def _backdate(db_session, user_id, hours):
    from sqlalchemy import update

    from app.models.notification import InAppNotification

    await db_session.execute(
        update(InAppNotification)
        .where(InAppNotification.user_id == user_id)
        .values(created_at=InAppNotification.created_at - timedelta(hours=hours))
    )
    await db_session.flush()


async def test_super_admins_are_told_once_a_day_and_when_it_recovers(db_session, tmp_path):
    users = await _admins(db_session)
    admin, viewer = users["super_admin"], users["viewer"]
    off = _state(_publish(tmp_path / "a", enabled=0, encrypted=0, success=0, reason="no_key"))

    assert await notify_database_backup_state(db_session, off) >= 1
    first = await _notices(db_session, admin)
    assert len(first) == 1
    assert first[0].title == "Database backups are OFF"
    assert first[0].severity == "critical"
    assert "backup-keygen.sh" in first[0].body
    assert first[0].action_url == "/backup"
    assert await _notices(db_session, viewer) == []

    # Same state within a day: no repeat.
    await notify_database_backup_state(db_session, off)
    assert len(await _notices(db_session, admin)) == 1

    # A day later: one reminder.
    await _backdate(db_session, admin, 25)
    await notify_database_backup_state(db_session, off)
    assert len(await _notices(db_session, admin)) == 2

    # A new bad state is news immediately.
    failing = _state(_publish(tmp_path / "b", failed=1))
    await notify_database_backup_state(db_session, failing)
    notices = await _notices(db_session, admin)
    assert notices[-1].title == "Database backup failed"

    # "pending" (key just installed, first dump not finished) is not recovery.
    pending = _state(_publish(tmp_path / "c", success=0))
    await notify_database_backup_state(db_session, pending)
    assert len(await _notices(db_session, admin)) == len(notices)

    healthy = _state(_publish(tmp_path / "d"))
    await notify_database_backup_state(db_session, healthy)
    notices = await _notices(db_session, admin)
    assert notices[-1].title == "Database backups are working again"
    assert notices[-1].severity == "info"
    # ...and only once.
    await notify_database_backup_state(db_session, healthy)
    assert len(await _notices(db_session, admin)) == len(notices)


async def test_unknown_status_never_alarms(db_session, tmp_path):
    users = await _admins(db_session)
    status = read_database_backup_status(tmp_path / "absent", now=time.time())
    assert status.state == "unknown"
    assert await notify_database_backup_state(db_session, status) == 0
    assert await _notices(db_session, users["super_admin"]) == []

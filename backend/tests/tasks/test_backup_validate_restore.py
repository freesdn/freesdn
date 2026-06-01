# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for ``backup._validate_restore_async`` — the body of the monthly
backup→dry-run-restore validation task.

The Celery task itself is a one-line wrapper around the async body
(``return asyncio.run(_validate_restore_async())``), so we test the
body directly. Side-stepping Celery's bind/self machinery keeps the
tests fast and free of broker config.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.tasks import backup as backup_tasks


def _backup(*, status: str = "completed",
            age_days: int = 5,
            org_id: Any = None) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid4(),
        organization_id=org_id or uuid4(),
        status=status,
        completed_at=datetime.now(UTC) - timedelta(days=age_days),
    )


def _org() -> SimpleNamespace:
    return SimpleNamespace(id=uuid4())


class _FakeSessionCtx:
    """async-with session that returns canned rows.

    First execute() → orgs list, subsequent → per-org backup lookup,
    walking the orgs in order. Matches the task's own access pattern.
    """

    def __init__(self, orgs: list[Any], backup_for_org: dict[Any, Any]) -> None:
        self._orgs = orgs
        self._backup_for_org = backup_for_org
        self._call = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return None

    async def execute(self, _query):
        self._call += 1
        result = MagicMock()
        if self._call == 1:
            scalars = MagicMock()
            scalars.all.return_value = self._orgs
            result.scalars.return_value = scalars
        else:
            org = self._orgs[self._call - 2] if self._call - 2 < len(self._orgs) else None
            result.scalar_one_or_none.return_value = (
                self._backup_for_org.get(org.id) if org else None
            )
        return result


@pytest.fixture
def patched(monkeypatch):
    """Wire monkeypatch slots used by every test."""
    emitted: list[dict[str, Any]] = []

    async def _fake_emit(**kw):
        emitted.append(kw)

    monkeypatch.setattr(backup_tasks, "_emit_validation_failure", _fake_emit)
    return monkeypatch, emitted


def _patch_session(monkeypatch, orgs: list[Any], backups: dict[Any, Any]) -> None:
    monkeypatch.setattr(
        backup_tasks, "AsyncSessionLocal",
        lambda: _FakeSessionCtx(orgs, backups),
    )


def _patch_service(monkeypatch, restore_side_effect) -> MagicMock:
    """Make ``BackupService(...)`` return a mock whose
    ``restore_from_backup`` is driven by ``restore_side_effect``."""
    import app.services.backup as svc_mod
    svc_instance = MagicMock()
    svc_instance.restore_from_backup = AsyncMock(side_effect=restore_side_effect)
    monkeypatch.setattr(svc_mod, "BackupService", lambda _s: svc_instance)
    return svc_instance


@pytest.mark.asyncio
async def test_warn_when_no_recent_backup(patched) -> None:
    monkeypatch, emitted = patched
    org = _org()
    _patch_session(monkeypatch, [org], {org.id: None})

    result = await backup_tasks._validate_restore_async()

    assert result["warn"] == 1
    assert result["ok"] == 0
    assert result["error"] == 0
    assert emitted == []  # warnings do NOT page ops


@pytest.mark.asyncio
async def test_warn_when_only_stale_backup(patched) -> None:
    """A completed backup older than 60d is still "no recent" — warn."""
    monkeypatch, emitted = patched
    org = _org()
    stale = _backup(org_id=org.id, age_days=90)
    _patch_session(monkeypatch, [org], {org.id: stale})

    result = await backup_tasks._validate_restore_async()

    assert result["warn"] == 1
    assert result["ok"] == 0


@pytest.mark.asyncio
async def test_ok_when_dry_run_completes(patched) -> None:
    monkeypatch, emitted = patched
    org = _org()
    backup = _backup(org_id=org.id)
    _patch_session(monkeypatch, [org], {org.id: backup})

    fake_job = SimpleNamespace(id=uuid4(), status="completed")
    svc = _patch_service(monkeypatch, restore_side_effect=lambda **kw: fake_job)

    # AsyncMock with a return value via side_effect=callable doesn't await;
    # use return_value for the happy path instead.
    svc.restore_from_backup = AsyncMock(return_value=fake_job)

    result = await backup_tasks._validate_restore_async()

    assert result["ok"] == 1
    assert result["error"] == 0
    assert emitted == []
    # dry_run=True is non-negotiable — a real restore would destroy data.
    kw = svc.restore_from_backup.await_args.kwargs
    assert kw["dry_run"] is True
    assert kw["organization_id"] == org.id


@pytest.mark.asyncio
async def test_error_emits_validation_failure(patched) -> None:
    """Raised exception → error AND a critical event is emitted."""
    monkeypatch, emitted = patched
    org = _org()
    backup = _backup(org_id=org.id)
    _patch_session(monkeypatch, [org], {org.id: backup})

    _patch_service(monkeypatch, restore_side_effect=ValueError("checksum mismatch"))

    result = await backup_tasks._validate_restore_async()

    assert result["error"] == 1
    assert result["ok"] == 0
    assert len(emitted) == 1
    assert emitted[0]["org_id"] == org.id
    assert emitted[0]["backup_id"] == backup.id
    assert "checksum mismatch" in emitted[0]["reason"]


@pytest.mark.asyncio
async def test_failed_job_status_also_pages(patched) -> None:
    """If the dry-run completes without raising but ends in a
    non-'completed' status, we still page — the backup was unreadable
    even though no exception bubbled up."""
    monkeypatch, emitted = patched
    org = _org()
    backup = _backup(org_id=org.id)
    _patch_session(monkeypatch, [org], {org.id: backup})

    failed_job = SimpleNamespace(id=uuid4(), status="failed")
    svc = _patch_service(monkeypatch, restore_side_effect=None)
    svc.restore_from_backup = AsyncMock(return_value=failed_job)

    result = await backup_tasks._validate_restore_async()

    assert result["error"] == 1
    assert len(emitted) == 1
    assert "status=failed" in emitted[0]["reason"]


@pytest.mark.asyncio
async def test_error_in_one_org_does_not_skip_others(patched) -> None:
    """One failing org must NOT abort the entire validation run."""
    monkeypatch, emitted = patched
    org_a = _org()
    org_b = _org()
    backup_a = _backup(org_id=org_a.id)
    backup_b = _backup(org_id=org_b.id)
    _patch_session(
        monkeypatch, [org_a, org_b],
        {org_a.id: backup_a, org_b.id: backup_b},
    )

    fake_job = SimpleNamespace(id=uuid4(), status="completed")
    call_count = {"n": 0}

    async def _restore(*_a, **_kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("boom")
        return fake_job

    import app.services.backup as svc_mod
    svc_instance = MagicMock()
    svc_instance.restore_from_backup = AsyncMock(side_effect=_restore)
    monkeypatch.setattr(svc_mod, "BackupService", lambda _s: svc_instance)

    result = await backup_tasks._validate_restore_async()

    assert result["ok"] == 1
    assert result["error"] == 1
    # Only the failing org paged ops.
    assert len(emitted) == 1


# ── per-org timeout (readiness) ────────────────────────


@pytest.mark.asyncio
async def test_per_org_timeout_emits_failure_and_continues(
    patched, monkeypatch,
) -> None:
    """A hung restore for one org must:
      1. trigger ``asyncio.wait_for(timeout=...)``
      2. produce a ``status: "timeout"`` result row
      3. emit ``_emit_validation_failure`` with a "timed out" reason
      4. NOT block validation of the next org
    """
    import asyncio as _asyncio

    monkeypatch, emitted = patched

    org_hung = _org()
    org_ok = _org()
    backup_hung = _backup(org_id=org_hung.id)
    backup_ok = _backup(org_id=org_ok.id)
    _patch_session(
        monkeypatch, [org_hung, org_ok],
        {org_hung.id: backup_hung, org_ok.id: backup_ok},
    )

    # Shrink the per-org budget so the test runs in <1s, not the
    # production 60s. The original constant is restored automatically
    # by pytest's monkeypatch teardown.
    monkeypatch.setattr(
        backup_tasks, "_PER_ORG_VALIDATE_TIMEOUT_SECONDS", 0.1,
    )

    fake_job = SimpleNamespace(id=uuid4(), status="completed")
    call_count = {"n": 0}

    async def _restore(*_a, **_kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # First call (org_hung) hangs past the per-org budget.
            await _asyncio.sleep(2.0)
            return fake_job
        # Second call (org_ok) returns immediately.
        return fake_job

    import app.services.backup as svc_mod
    svc_instance = MagicMock()
    svc_instance.restore_from_backup = AsyncMock(side_effect=_restore)
    monkeypatch.setattr(svc_mod, "BackupService", lambda _s: svc_instance)

    result = await backup_tasks._validate_restore_async()

    # 1 timeout (org_hung) + 1 ok (org_ok) — the loop did NOT abort
    # after the hung org.
    assert result["timeout"] == 1, result
    assert result["ok"] == 1, result
    assert result["error"] == 0, result

    # The timeout row carries the failing org's id + a "timed out"
    # reason field.
    timeout_rows = [r for r in result["results"] if r["status"] == "timeout"]
    assert len(timeout_rows) == 1
    assert timeout_rows[0]["organization_id"] == str(org_hung.id)
    assert "timeout" in timeout_rows[0]["reason"].lower()

    # Critical event was emitted for the hung org (so ops gets paged
    # the same way as any other validation failure).
    assert len(emitted) == 1
    assert emitted[0]["org_id"] == org_hung.id
    assert "timed out" in emitted[0]["reason"].lower()


@pytest.mark.asyncio
async def test_per_org_timeout_constant_matches_production_default() -> None:
    """Guard against accidentally committing a too-short timeout.

    60s is the documented production default — generous enough for a
    dry-run restore of large backups, tight enough that one hung org
    costs at most 1 minute of the 30-minute Celery soft_time_limit.
    """
    assert backup_tasks._PER_ORG_VALIDATE_TIMEOUT_SECONDS == 60.0


# ── alerts.yml integration (readiness) ─────────────────


def test_alerts_yml_ships_backup_alerts() -> None:
    """The ``freesdn.backups`` alert group must:
      - parse as valid YAML
      - contain BOTH FreeSDNBackupStale + FreeSDNBackupUnencrypted
      - tag each alert with a component label = ``backup``
      - include a ``runbook_url`` annotation so paged ops gets a link

    Validates from the operator-visible artifact (the actual YAML
    file) rather than mocking the alert engine — if a future refactor
    rewrites the alerts in code, this test fails loudly so we
    rebuild it.
    """
    import pathlib

    import yaml

    # tests/tasks/ → backend/ → freesdn/ → observability/prometheus/alerts.yml
    here = pathlib.Path(__file__).resolve()
    alerts_yml = here.parents[3] / "observability" / "prometheus" / "alerts.yml"
    assert alerts_yml.is_file(), f"missing alerts.yml at {alerts_yml}"

    data = yaml.safe_load(alerts_yml.read_text(encoding="utf-8"))
    groups = data.get("groups", [])
    backup_group = next(
        (g for g in groups if g.get("name") == "freesdn.backups"), None,
    )
    assert backup_group is not None, "freesdn.backups group missing"

    alerts_by_name = {r["alert"]: r for r in backup_group.get("rules", [])}
    assert "FreeSDNBackupStale" in alerts_by_name
    assert "FreeSDNBackupUnencrypted" in alerts_by_name

    stale = alerts_by_name["FreeSDNBackupStale"]
    assert stale["labels"]["severity"] == "critical"
    assert stale["labels"]["component"] == "backup"
    assert "runbook_url" in stale["annotations"], (
        "FreeSDNBackupStale must carry a runbook_url so 3am paging "
        "links straight at the recovery procedure"
    )
    assert "freesdn_pg_backup_last_success_timestamp" in stale["expr"]

    unenc = alerts_by_name["FreeSDNBackupUnencrypted"]
    assert unenc["labels"]["severity"] == "warning"
    assert "freesdn_pg_backup_encryption_enabled" in unenc["expr"]

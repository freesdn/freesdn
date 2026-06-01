# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Tests for the interactive scan endpoint and its report-mirror handler.

Covers:
- ``InteractiveScanRequest`` validation (scan_type cap, timeout bounds,
  target list cap).
- ``AgentRegistryService._update_interactive_task`` mirroring of
  scan_progress, scan_result, action_result, and error reports into
  the AgentTask row.
- The handler ignores reports whose command_id isn't in the interactive
  registry (so scheduled-scan reports don't accidentally clobber
  unrelated tasks).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession


# =============================================================================
# Schema validation
# =============================================================================

class TestInteractiveScanRequest:
    def test_defaults(self) -> None:
        from app.schemas.agents import InteractiveScanRequest

        req = InteractiveScanRequest()
        assert req.scan_type == "quick"
        assert req.targets is None
        assert req.timeout_seconds == 300

    def test_scan_type_too_long_rejected(self) -> None:
        from app.schemas.agents import InteractiveScanRequest

        with pytest.raises(ValidationError):
            InteractiveScanRequest(scan_type="x" * 33)

    def test_target_list_capped(self) -> None:
        from app.schemas.agents import InteractiveScanRequest

        too_many = [f"10.0.0.{i}" for i in range(300)]
        with pytest.raises(ValidationError):
            InteractiveScanRequest(targets=too_many)

    def test_timeout_min(self) -> None:
        from app.schemas.agents import InteractiveScanRequest

        with pytest.raises(ValidationError):
            InteractiveScanRequest(timeout_seconds=5)

    def test_timeout_max(self) -> None:
        from app.schemas.agents import InteractiveScanRequest

        with pytest.raises(ValidationError):
            InteractiveScanRequest(timeout_seconds=3600)

    def test_valid_full(self) -> None:
        from app.schemas.agents import InteractiveScanRequest

        req = InteractiveScanRequest(
            scan_type="full",
            targets=["192.168.1.0/24", "10.0.0.0/24"],
            timeout_seconds=600,
        )
        assert req.scan_type == "full"
        assert req.timeout_seconds == 600
        assert req.targets == ["192.168.1.0/24", "10.0.0.0/24"]


# =============================================================================
# Report handler — DB-backed
# =============================================================================

@pytest_asyncio.fixture
async def scan_task_fixture(db_session: AsyncSession):
    """One agent + one pending interactive AgentTask for handler tests."""
    from app.models.agents import AgentTask, RemoteAgent
    from app.models.core import Organization, Site

    org = Organization(
        name=f"iscan-{uuid4()}",
        slug=f"iscan-{uuid4().hex[:8]}",
    )
    db_session.add(org)
    await db_session.flush()

    site = Site(
        organization_id=org.id,
        name="HQ",
        slug=f"hq-{uuid4().hex[:6]}",
    )
    db_session.add(site)
    await db_session.flush()

    agent = RemoteAgent(
        site_id=site.id,
        organization_id=org.id,
        name="iscan-agent",
        agent_key=f"k-{uuid4().hex}",
        status="online",
        is_approved=True,
        is_enabled=True,
        capabilities={"scan_types": ["quick", "full"]},
    )
    db_session.add(agent)
    await db_session.flush()

    task = AgentTask(
        agent_id=agent.id,
        task_type="scan_network",
        task_data={"scan_type": "quick", "interactive": True},
        status="running",
        progress=0,
        started_at=datetime.now(UTC),
        priority=3,
    )
    db_session.add(task)
    await db_session.commit()
    await db_session.refresh(task)

    return {"agent": agent, "task": task, "org_id": org.id}


class TestUpdateInteractiveTaskHandler:
    """Exercise the pure DB logic through ``_apply_interactive_report``.

    We avoid ``_update_interactive_task`` (which opens its own session
    via ``async_session_factory``) because that fresh session lands on
    a different asyncio event loop than the test fixture, which trips
    asyncpg's loop-binding check. The split inside the service keeps
    both paths covered without needing a cross-loop bridge.
    """

    @pytest.mark.asyncio
    async def test_progress_report_updates_progress(
        self, db_session: AsyncSession, scan_task_fixture
    ) -> None:
        from sqlalchemy import select as _sel
        from app.models.agents import AgentTask
        from app.services.remote_agent import (
            AgentRegistryService,
            AgentReport,
            AgentReportType,
        )

        task = scan_task_fixture["task"]
        registry = AgentRegistryService(db_session)
        registry.register_interactive_task(str(task.id))

        report = AgentReport(
            type=AgentReportType.SCAN_PROGRESS,
            payload={
                "scanner": "arp_scanner",
                "status": "running",
                "progress": 42,
                "devices_found": 7,
            },
            command_id=str(task.id),
        )
        report.agent_id = str(scan_task_fixture["agent"].id)

        await registry._apply_interactive_report(db_session, task.id, report)
        await db_session.commit()

        refreshed = (await db_session.execute(
            _sel(AgentTask).where(AgentTask.id == task.id)
        )).scalar_one()
        assert refreshed.progress == 42
        assert refreshed.status == "running"
        assert refreshed.result is not None
        assert refreshed.result.get("scanner") == "arp_scanner"
        assert refreshed.result.get("devices_found") == 7

    @pytest.mark.asyncio
    async def test_scan_result_marks_completed(
        self, db_session: AsyncSession, scan_task_fixture
    ) -> None:
        from sqlalchemy import select as _sel
        from app.models.agents import AgentTask
        from app.services.remote_agent import (
            AgentRegistryService,
            AgentReport,
            AgentReportType,
        )

        task = scan_task_fixture["task"]
        registry = AgentRegistryService(db_session)
        registry.register_interactive_task(str(task.id))

        devices = [
            {"ip_address": "10.0.0.5", "mac_address": "aa:bb:cc:dd:ee:01"},
            {"ip_address": "10.0.0.6"},
        ]
        report = AgentReport(
            type=AgentReportType.SCAN_RESULT,
            payload={"devices": devices, "total": 2},
            command_id=str(task.id),
        )
        report.agent_id = str(scan_task_fixture["agent"].id)

        await registry._apply_interactive_report(db_session, task.id, report)
        await db_session.commit()

        refreshed = (await db_session.execute(
            _sel(AgentTask).where(AgentTask.id == task.id)
        )).scalar_one()
        assert refreshed.status == "completed"
        assert refreshed.progress == 100
        assert refreshed.completed_at is not None
        assert refreshed.result is not None
        assert refreshed.result["total"] == 2
        assert len(refreshed.result["devices"]) == 2

        assert str(task.id) not in registry._interactive_tasks

    @pytest.mark.asyncio
    async def test_action_result_terminal_fallback(
        self, db_session: AsyncSession, scan_task_fixture
    ) -> None:
        from sqlalchemy import select as _sel
        from app.models.agents import AgentTask
        from app.services.remote_agent import (
            AgentRegistryService,
            AgentReport,
            AgentReportType,
        )

        task = scan_task_fixture["task"]
        registry = AgentRegistryService(db_session)
        registry.register_interactive_task(str(task.id))

        report = AgentReport(
            type=AgentReportType.ACTION_RESULT,
            payload={"status": "completed", "result": {"total_devices": 3}},
            command_id=str(task.id),
        )
        report.agent_id = str(scan_task_fixture["agent"].id)

        await registry._apply_interactive_report(db_session, task.id, report)
        await db_session.commit()

        refreshed = (await db_session.execute(
            _sel(AgentTask).where(AgentTask.id == task.id)
        )).scalar_one()
        assert refreshed.status == "completed"
        assert refreshed.progress == 100
        assert refreshed.result is not None
        assert refreshed.result.get("total_devices") == 3

    @pytest.mark.asyncio
    async def test_error_report_marks_failed(
        self, db_session: AsyncSession, scan_task_fixture
    ) -> None:
        from sqlalchemy import select as _sel
        from app.models.agents import AgentTask
        from app.services.remote_agent import (
            AgentRegistryService,
            AgentReport,
            AgentReportType,
        )

        task = scan_task_fixture["task"]
        registry = AgentRegistryService(db_session)
        registry.register_interactive_task(str(task.id))

        report = AgentReport(
            type=AgentReportType.ERROR,
            payload={"message": "scapy not available"},
            command_id=str(task.id),
        )
        report.agent_id = str(scan_task_fixture["agent"].id)

        await registry._apply_interactive_report(db_session, task.id, report)
        await db_session.commit()

        refreshed = (await db_session.execute(
            _sel(AgentTask).where(AgentTask.id == task.id)
        )).scalar_one()
        assert refreshed.status == "failed"
        assert refreshed.error_message == "scapy not available"
        assert refreshed.completed_at is not None
        assert str(task.id) not in registry._interactive_tasks

    @pytest.mark.asyncio
    async def test_progress_doesnt_clobber_terminal(
        self, db_session: AsyncSession, scan_task_fixture
    ) -> None:
        """If a late scan_progress arrives after scan_result already
        marked the task completed, it must not roll the status back."""
        from sqlalchemy import select as _sel
        from app.models.agents import AgentTask
        from app.services.remote_agent import (
            AgentRegistryService,
            AgentReport,
            AgentReportType,
        )

        task = scan_task_fixture["task"]
        registry = AgentRegistryService(db_session)
        registry.register_interactive_task(str(task.id))

        # Pretend scan_result already landed: pre-mark as completed
        task.status = "completed"
        task.progress = 100
        task.completed_at = datetime.now(UTC)
        task.result = {"devices": [{"ip_address": "10.1.1.1"}], "total": 1}
        await db_session.commit()

        late = AgentReport(
            type=AgentReportType.SCAN_PROGRESS,
            payload={"progress": 80, "scanner": "snmp", "devices_found": 3},
            command_id=str(task.id),
        )
        late.agent_id = str(scan_task_fixture["agent"].id)

        await registry._apply_interactive_report(db_session, task.id, late)
        await db_session.commit()

        refreshed = (await db_session.execute(
            _sel(AgentTask).where(AgentTask.id == task.id)
        )).scalar_one()
        assert refreshed.status == "completed"
        assert refreshed.progress == 100
        assert refreshed.result["total"] == 1

    @pytest.mark.asyncio
    async def test_short_circuits_when_not_registered(
        self, db_session: AsyncSession, scan_task_fixture
    ) -> None:
        """Top-level _update_interactive_task must skip the DB entirely
        when command_id isn't in the interactive registry — that's the
        whole point of the registry (saves a per-tick DB round-trip
        for scheduled-scan progress reports)."""
        from app.services.remote_agent import (
            AgentRegistryService,
            AgentReport,
            AgentReportType,
        )

        registry = AgentRegistryService(db_session)
        report = AgentReport(
            type=AgentReportType.SCAN_PROGRESS,
            payload={"progress": 50},
            command_id=str(uuid4()),  # not registered
        )
        # Should return cleanly without hitting the DB — if it tried,
        # async_session_factory would error on event-loop mismatch.
        await registry._update_interactive_task(report)


class TestInteractiveTaskRegistry:
    def test_register_unregister(self) -> None:
        from app.services.remote_agent import AgentRegistryService

        # Pass None for db — only testing the set semantics
        registry = AgentRegistryService(None)  # type: ignore[arg-type]
        tid = str(uuid4())

        assert tid not in registry._interactive_tasks
        registry.register_interactive_task(tid)
        assert tid in registry._interactive_tasks
        registry.unregister_interactive_task(tid)
        assert tid not in registry._interactive_tasks

    def test_unregister_unknown_is_noop(self) -> None:
        from app.services.remote_agent import AgentRegistryService

        registry = AgentRegistryService(None)  # type: ignore[arg-type]
        # Should not raise
        registry.unregister_interactive_task(str(uuid4()))

# SPDX-License-Identifier: AGPL-3.0-only
"""Edge-agent device changes obey read-only mode, are audited first, and are not scheduled.

``POST /agents/{id}/tasks`` sent a confirmed ``push_config`` or
``execute_action`` straight over the agent socket: read-only mode was never
consulted, nothing recorded who sent it, and a task scheduled for a maintenance
window went out at once. A device change now leaves (over the socket, or to a
polling agent) only after its audit record is committed, and a task scheduled
for later is refused: nothing would send it when its time came.
Real PostgreSQL; the agent socket is a double.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api.v1.endpoints import agents as agents_mod
from app.core.dependencies import CurrentUser
from app.models.agents import AgentTask, AgentTaskType, RemoteAgent
from app.models.core import Organization, Site, User, UserRole
from app.schemas.agents import TaskCreate
from app.services.adapter_staging import AdapterStagingService
from app.services.audit import AuditService
from app.services.remote_agent import REQUESTED_BY_KEY, PersistentAgentService


@pytest.fixture
async def world(db_session, monkeypatch):
    org = Organization(id=uuid4(), name="Agent gate", slug="agent-gate-" + uuid4().hex[:10])
    db_session.add(org)
    await db_session.flush()
    site = Site(id=uuid4(), organization_id=org.id, name="Edge", slug=uuid4().hex)
    user = User(
        id=uuid4(),
        organization_id=org.id,
        email=f"{uuid4().hex}@example.invalid",
        username=uuid4().hex,
        hashed_password="not-a-login",
        role=UserRole.ORG_ADMIN,
        is_active=True,
    )
    db_session.add_all([site, user])
    await db_session.flush()
    agent = RemoteAgent(
        id=uuid4(),
        agent_key=hashlib.sha256(uuid4().bytes).hexdigest(),
        name="edge-1",
        site_id=site.id,
        organization_id=org.id,
        is_enabled=True,
        is_approved=True,
    )
    db_session.add(agent)
    await db_session.commit()

    connection = SimpleNamespace(
        info=SimpleNamespace(agent_id=str(agent.id)), send_command=AsyncMock()
    )
    registry = SimpleNamespace(
        get_connection_for_site=lambda _site: connection,
        register_interactive_task=lambda _id: None,
        unregister_interactive_task=lambda _id: None,
    )
    monkeypatch.setattr(agents_mod, "get_agent_registry", AsyncMock(return_value=registry))
    audited: list[dict[str, Any]] = []

    async def _log(self: Any, **kwargs: Any) -> None:
        audited.append(kwargs)

    monkeypatch.setattr(AuditService, "log", _log)
    state = SimpleNamespace(read_only=False)
    monkeypatch.setattr(
        AdapterStagingService, "is_read_only", staticmethod(lambda: state.read_only)
    )
    yield SimpleNamespace(
        db=db_session,
        agent=agent,
        user=user,
        principal=CurrentUser(user=user, permissions=["*"]),
        connection=connection,
        audited=audited,
        state=state,
    )


async def _create(w, task_type=AgentTaskType.PUSH_CONFIG, scheduled_at=None):
    return await agents_mod.create_task(
        agent_id=w.agent.id,
        data=TaskCreate(
            task_type=task_type, task_data={"confirmed": True}, scheduled_at=scheduled_at
        ),
        current_user=w.principal,
        session=w.db,
    )


async def _tasks(w) -> list[AgentTask]:
    rows = await w.db.execute(select(AgentTask).where(AgentTask.agent_id == w.agent.id))
    return list(rows.scalars().all())


@pytest.mark.parametrize("task_type", [AgentTaskType.PUSH_CONFIG, AgentTaskType.EXECUTE_ACTION])
async def test_a_device_task_is_refused_while_read_only(world, task_type):
    """Fails on the old endpoint: it created and sent the confirmed task."""
    world.state.read_only = True
    with pytest.raises(HTTPException) as exc:
        await _create(world, task_type)
    assert exc.value.status_code == 403
    world.connection.send_command.assert_not_awaited()
    assert await _tasks(world) == []


async def test_a_scan_is_not_refused_while_read_only(world):
    world.state.read_only = True
    await _create(world, AgentTaskType.SCAN_NETWORK)
    world.connection.send_command.assert_awaited_once()
    assert world.audited == []


async def test_a_sent_device_task_is_audited(world):
    """Fails on the old endpoint: nothing recorded who changed the device."""
    response = await _create(world)
    world.connection.send_command.assert_awaited_once()
    (entry,) = world.audited
    assert entry["actor_id"] == world.user.id and entry["resource_id"] == world.agent.id
    assert entry["extra_metadata"]["task_id"] == str(response.id)
    assert entry["extra_metadata"]["channel"] == "websocket" and entry["strict"] is True
    assert "confirmed" not in repr(entry)
    # The command carries the caller's own payload, not the recorded requester.
    command = world.connection.send_command.await_args.args[0]
    assert command.payload == {"confirmed": True}


async def _fail_audit(self: Any, **kwargs: Any) -> None:
    raise RuntimeError("audit store unavailable")


async def test_a_device_task_is_not_sent_without_its_audit_record(world, monkeypatch):
    """Fails on the old endpoint: it sent first and audited best effort after."""
    monkeypatch.setattr(AuditService, "log", _fail_audit)
    with pytest.raises(HTTPException) as exc:
        await _create(world)
    assert exc.value.status_code == 503
    world.connection.send_command.assert_not_awaited()
    (task,) = await _tasks(world)
    await world.db.refresh(task)
    assert task.status == "failed"


async def test_a_task_scheduled_for_later_is_refused(world):
    """Fails on the old endpoint (sent at once) and on a pending-only fix (never sent)."""
    with pytest.raises(HTTPException) as exc:
        await _create(world, scheduled_at=datetime.now(UTC) + timedelta(hours=2))
    assert exc.value.status_code == 400
    world.connection.send_command.assert_not_awaited()
    assert await _tasks(world) == []
    assert world.audited == []


async def _due_task(w) -> AgentTask:
    """A device change left pending (the agent was offline when it was sent)."""
    task = await PersistentAgentService(w.db).create_task(
        agent_id=w.agent.id,
        task_type=AgentTaskType.PUSH_CONFIG,
        task_data={"confirmed": True, REQUESTED_BY_KEY: str(w.user.id)},
    )
    await w.db.commit()
    return task


async def test_a_polled_device_task_is_audited_before_it_is_handed_out(world):
    task = await _due_task(world)
    handed_out = await PersistentAgentService(world.db).get_pending_tasks(world.agent.id)
    assert [t.id for t in handed_out] == [task.id]
    (entry,) = world.audited
    assert entry["actor_id"] == world.user.id and entry["resource_id"] == world.agent.id
    assert entry["extra_metadata"]["task_id"] == str(task.id)
    assert entry["extra_metadata"]["channel"] == "poll"
    assert entry["strict"] is True


async def test_a_polled_device_task_without_its_audit_record_stays_pending(world, monkeypatch):
    task = await _due_task(world)
    monkeypatch.setattr(AuditService, "log", _fail_audit)
    assert await PersistentAgentService(world.db).get_pending_tasks(world.agent.id) == []
    await world.db.refresh(task)
    assert task.status == "pending"


async def test_a_due_device_task_is_refused_when_read_only_came_on(world):
    task = await _due_task(world)
    world.state.read_only = True
    assert await PersistentAgentService(world.db).get_pending_tasks(world.agent.id) == []
    await world.db.refresh(task)
    assert task.status == "failed" and "Read-only" in (task.error_message or "")


async def test_a_due_task_is_refused_when_its_requester_can_no_longer_act(world):
    task = await _due_task(world)
    world.user.is_active = False
    await world.db.commit()
    assert await PersistentAgentService(world.db).get_pending_tasks(world.agent.id) == []
    await world.db.refresh(task)
    assert task.status == "failed"


async def test_a_cancelled_task_is_not_handed_out(world):
    task = await _due_task(world)
    task.status = "cancelled"
    await world.db.commit()
    assert await PersistentAgentService(world.db).get_pending_tasks(world.agent.id) == []


async def test_a_read_only_site_grant_cannot_send_an_agent_task(world):
    """Fails on the old endpoint: only visibility of the site was checked."""
    reader = User(
        id=uuid4(),
        organization_id=world.user.organization_id,
        email=f"{uuid4().hex}@example.invalid",
        username=uuid4().hex,
        hashed_password="not-a-login",
        role=UserRole.SITE_ADMIN,
        is_active=True,
    )
    principal = CurrentUser(
        user=reader,
        permissions=["*"],
        accessible_site_ids={world.agent.site_id},
        site_access_levels={world.agent.site_id: "read"},
    )
    with pytest.raises(HTTPException) as exc:
        await agents_mod.create_task(
            agent_id=world.agent.id,
            data=TaskCreate(task_type=AgentTaskType.PUSH_CONFIG, task_data={"confirmed": True}),
            current_user=principal,
            session=world.db,
        )
    assert exc.value.status_code == 403
    world.connection.send_command.assert_not_awaited()
    assert await _tasks(world) == []


def _audit_then_read_only(world):
    """An audit write that returns only after read-only was switched on."""

    async def _log(self: Any, **kwargs: Any) -> None:
        world.audited.append(kwargs)
        world.state.read_only = True

    return _log


async def test_read_only_switched_on_during_the_audit_write_stops_the_send(world, monkeypatch):
    """Fails without the re-check after the audit: the push was sent anyway."""
    monkeypatch.setattr(AuditService, "log", _audit_then_read_only(world))
    with pytest.raises(HTTPException) as exc:
        await _create(world)
    assert exc.value.status_code == 403
    world.connection.send_command.assert_not_awaited()
    (task,) = await _tasks(world)
    await world.db.refresh(task)
    assert task.status == "failed"


async def test_read_only_switched_on_during_a_polled_audit_write_stops_the_hand_out(
    world, monkeypatch
):
    task = await _due_task(world)
    monkeypatch.setattr(AuditService, "log", _audit_then_read_only(world))
    assert await PersistentAgentService(world.db).get_pending_tasks(world.agent.id) == []
    await world.db.refresh(task)
    assert task.status == "failed" and "Read-only" in (task.error_message or "")

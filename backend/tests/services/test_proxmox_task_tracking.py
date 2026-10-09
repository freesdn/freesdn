# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real PostgreSQL persistence, concurrent observers, and no replay after loss."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.adapters.base import AdapterResult
from app.adapters.proxmox.models import ProxmoxTaskDetail
from app.db.session import create_test_engine
from app.models.core import Controller, Organization, Site
from app.models.staging import AdapterPendingChange
from app.schemas.gateway_vpn import PendingChangeResponse
from app.services import proxmox_task_tracking as tracking
from app.services.adapter_staging import AdapterStagingService
from tests.adapters.test_proxmox_write_outcomes import UPID, connected


@pytest_asyncio.fixture
async def records(monkeypatch):
    engine = create_test_engine()
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    org_id, site_id, controller_id, change_id = [uuid4() for _ in range(4)]
    async with sessions() as session:
        session.add(Organization(id=org_id, name="Task observation test", slug=str(org_id)))
        await session.flush()
        session.add(
            Site(id=site_id, organization_id=org_id, name="Fixture site", slug=str(site_id))
        )
        await session.flush()
        session.add(
            Controller(
                id=controller_id,
                site_id=site_id,
                name="Fixture Proxmox",
                controller_type="proxmox",
                host="192.0.2.1",
                port=8006,
            )
        )
        await session.flush()
        session.add(
            AdapterPendingChange(
                id=change_id,
                organization_id=org_id,
                site_id=site_id,
                controller_id=controller_id,
                feature="proxmox.vm.start",
                operation="create",
                status="pending",
                payload={"node": "pve1", "vmid": 101},
            )
        )
        await session.commit()
    monkeypatch.setattr(tracking, "CelerySessionLocal", sessions)
    monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: False))
    monkeypatch.setattr("app.services.adapter_staging._publish_change_event", AsyncMock())
    try:
        yield sessions, change_id, controller_id
    finally:
        async with sessions() as session:
            await session.execute(delete(Organization).where(Organization.id == org_id))
            await session.commit()
        await engine.dispose()


async def accept(sessions, change_id):
    async with sessions() as session:
        return await AdapterStagingService(session).apply_change(
            change_id, force=True, applier=AsyncMock(return_value=AdapterResult.ok({"upid": UPID}))
        )


def observer(monkeypatch, status="running", exitstatus=""):
    adapter = AsyncMock()
    adapter.get_task_status.return_value = AdapterResult.ok(
        ProxmoxTaskDetail(
            upid=UPID, node="pve1", task_type="qmstart", status=status, exitstatus=exitstatus
        )
    )
    builder = AsyncMock(return_value=adapter)
    monkeypatch.setattr(tracking, "build_proxmox_adapter", builder)
    return adapter, builder


@pytest.mark.asyncio
async def test_acceptance_and_completion_survive_new_sessions(records, monkeypatch):
    sessions, cid, _ = records
    accepted = await accept(sessions, cid)
    assert accepted.status == "applied"
    assert accepted.provider_task == {"id": UPID, "node": "pve1", "status": "pending"}
    assert PendingChangeResponse.from_model(accepted).provider_task.status == "pending"
    adapter, _ = observer(monkeypatch, "stopped", "OK")
    assert await tracking.poll_due_tasks() == {"polled": 1}
    async with sessions() as session:
        saved = await session.get(AdapterPendingChange, cid)
        assert saved.provider_task["status"] == "succeeded"
        assert saved.provider_task["finished_at"]
        assert saved.provider_task_next_poll_at is None
        with pytest.raises(HTTPException) as caught:
            await AdapterStagingService(session).apply_change(cid, force=True, applier=AsyncMock())
        assert caught.value.status_code == 409
    assert await tracking.poll_due_tasks() == {"polled": 0}
    adapter.get_task_status.assert_awaited_once_with("pve1", UPID)
    adapter.disconnect.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,exitstatus,expected",
    [
        ("running", "OK", "running"),
        ("stopped", "OK", "succeeded"),
        ("stopped", "WARNINGS: 2", "warnings"),
        ("stopped", "private-url-secret", "failed"),
        ("stopped", "", "unknown"),
        ("stopped", "unexpected status", "unknown"),
        ("stopped", "unable to get last line from task log - private-url-secret", "unknown"),
        ("other", "OK", "unknown"),
    ],
)
async def test_only_verified_terminal_result_is_completion(
    records, monkeypatch, status, exitstatus, expected
):
    sessions, cid, _ = records
    await accept(sessions, cid)
    observer(monkeypatch, status, exitstatus)
    await tracking.poll_due_tasks()
    async with sessions() as session:
        row = await session.get(AdapterPendingChange, cid)
        assert row.status == "applied"  # dispatch history never rewritten
        assert row.provider_task["status"] == expected
        assert "private-url-secret" not in str(row.provider_task)
        assert (row.provider_task_next_poll_at is None) == (expected in tracking._TERMINAL)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("is_active", False),
        ("sync_enabled", False),
        ("deleted_at", datetime(2026, 1, 1, tzinfo=UTC)),
        ("controller_type", "unifi"),
        ("site_id", None),
        ("site_inactive", False),
        ("organization_id", None),
    ],
)
async def test_scope_or_controller_changes_prevent_network_access(
    records, monkeypatch, field, value
):
    sessions, cid, controller_id = records
    await accept(sessions, cid)
    async with sessions() as session:
        row = await session.get(AdapterPendingChange, cid)
        if field == "site_inactive":
            site = await session.get(Site, row.site_id)
            site.is_active = False
        elif field == "site_id":
            row.site_id = None
        elif field == "organization_id":
            other = Organization(id=uuid4(), name="Other tenant", slug=str(uuid4()))
            session.add(other)
            await session.flush()
            row.organization_id = other.id
        else:
            ctrl = await session.get(Controller, controller_id)
            setattr(ctrl, field, value)
        await session.commit()
        other_id = row.organization_id if field == "organization_id" else None
    _, builder = observer(monkeypatch)
    try:
        await tracking.poll_due_tasks()
        builder.assert_not_awaited()
        async with sessions() as session:
            row = await session.get(AdapterPendingChange, cid)
            assert row.provider_task["status"] == "unknown"
            assert row.provider_task["detail"] == "target_unavailable_or_scope_changed"
    finally:
        if other_id:
            async with sessions() as session:
                await session.execute(delete(Organization).where(Organization.id == other_id))
                await session.commit()


@pytest.mark.asyncio
async def test_workers_skip_locked_task_and_resume_after_cancel(records, monkeypatch):
    sessions, cid, _ = records
    await accept(sessions, cid)
    entered, release = asyncio.Event(), asyncio.Event()
    adapter, _ = observer(monkeypatch)

    async def read(node, upid):
        entered.set()
        await release.wait()
        return AdapterResult.ok(
            ProxmoxTaskDetail(
                upid=upid, node=node, task_type="qmstart", status="stopped", exitstatus="OK"
            )
        )

    adapter.get_task_status.side_effect = read
    worker = asyncio.create_task(tracking.poll_due_tasks())
    try:
        await asyncio.wait_for(entered.wait(), 3)
        assert await asyncio.wait_for(tracking.poll_due_tasks(), 3) == {"polled": 0}
        worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker
        async with sessions() as session:
            row = await session.get(AdapterPendingChange, cid)
            assert row.provider_task["status"] == "pending"
        release.set()
        assert await tracking.poll_due_tasks() == {"polled": 1}
        assert adapter.get_task_status.await_count == 2  # only GETs repeated
    finally:
        release.set()
        if not worker.done():
            worker.cancel()
            with pytest.raises(asyncio.CancelledError):
                await worker


@pytest.mark.asyncio
async def test_read_failure_is_unknown_and_can_recover(records, monkeypatch):
    sessions, cid, _ = records
    await accept(sessions, cid)
    adapter, _ = observer(monkeypatch)
    adapter.get_task_status.side_effect = httpx.ConnectError("sensitive upstream failure")
    await tracking.poll_due_tasks()
    async with sessions() as session:
        row = await session.get(AdapterPendingChange, cid)
        assert row.provider_task["status"] == "unknown"
        assert "sensitive" not in str(row.provider_task)
        row.provider_task_next_poll_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    adapter.get_task_status.side_effect = None
    adapter.get_task_status.return_value = AdapterResult.ok(
        ProxmoxTaskDetail(
            upid=UPID, node="pve1", task_type="qmstart", status="stopped", exitstatus="OK"
        )
    )
    await tracking.poll_due_tasks()
    async with sessions() as session:
        assert (await session.get(AdapterPendingChange, cid)).provider_task["status"] == "succeeded"


@pytest.mark.asyncio
async def test_lost_write_acknowledgement_persists_reconciliation_not_failed(records):
    sessions, cid, _ = records
    calls = []

    def dispatch(request):
        calls.append(request.method)
        raise httpx.ReadTimeout("fixture lost response", request=request)

    adapter, client = connected(dispatch)
    try:
        async with sessions() as session:
            with pytest.raises(HTTPException):
                await AdapterStagingService(session).apply_change(
                    cid,
                    force=True,
                    applier=lambda _change: adapter.start_vm("pve1", 101, force=True),
                )
        async with sessions() as session:
            row = await session.get(AdapterPendingChange, cid)
            assert row.status == "reconciliation_required"
            with pytest.raises(HTTPException) as caught:
                await AdapterStagingService(session).apply_change(
                    cid, force=True, applier=AsyncMock()
                )
            assert caught.value.status_code == 409
        assert calls == ["POST"]
    finally:
        await client._http.aclose()


def test_task_extraction_does_not_mistake_guest_output_for_a_task():
    assert tracking.accepted_task("proxmox.vm.start", {"data": UPID})["status"] == "pending"
    assert tracking.accepted_task("unifi.test", {"data": {"upid": UPID}}) is None
    assert tracking.accepted_task("proxmox.vm.guest_exec", {"data": {"stdout": UPID}}) is None
    assert tracking.accepted_task("proxmox.vm.config", {"data": None}) is None
    assert tracking.accepted_task("proxmox.vm.start", {"data": {"upid": "UPID:../../bad"}}) == {
        "status": "unknown",
        "detail": "invalid_task_id",
    }


@pytest.mark.asyncio
async def test_failed_terminal_commit_recovers_task_handle_without_replay(records):
    sessions, cid, _ = records
    applier = AsyncMock(return_value=AdapterResult.ok({"upid": UPID}))
    async with sessions() as session:
        real_commit = session.commit
        commits = 0

        async def fail_once():
            nonlocal commits
            commits += 1
            if commits == 2:
                raise RuntimeError("simulated terminal commit loss")
            await real_commit()

        session.commit = fail_once
        with pytest.raises(RuntimeError, match="terminal commit loss"):
            await AdapterStagingService(session).apply_change(cid, force=True, applier=applier)
    async with sessions() as session:
        row = await session.get(AdapterPendingChange, cid)
        assert row.status == "applied"
        assert row.applied_response["data"]["upid"] == UPID
        assert row.provider_task["id"] == UPID
        assert row.provider_task["status"] == "pending"
        assert row.provider_task_next_poll_at is not None
    applier.assert_awaited_once()


@pytest.mark.asyncio
async def test_invalid_handle_is_visible_but_never_used_in_a_url(records, monkeypatch):
    sessions, cid, _ = records
    async with sessions() as session:
        await AdapterStagingService(session).apply_change(
            cid,
            force=True,
            applier=AsyncMock(
                return_value=AdapterResult.ok({"upid": "UPID:../../admin?token=secret"})
            ),
        )
    _, builder = observer(monkeypatch)
    assert await tracking.poll_due_tasks() == {"polled": 1}
    builder.assert_not_awaited()
    async with sessions() as session:
        row = await session.get(AdapterPendingChange, cid)
        assert row.provider_task["status"] == "unknown"
        assert row.provider_task["id"] is None
        assert row.provider_task_next_poll_at is None


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_status,expected_poll", [("running", True), ("missing", False)])
async def test_old_missing_history_stays_unknown_without_polling_forever(
    records, monkeypatch, provider_status, expected_poll
):
    sessions, cid, _ = records
    await accept(sessions, cid)
    async with sessions() as session:
        row = await session.get(AdapterPendingChange, cid)
        row.applied_at = datetime.now(UTC) - timedelta(days=8)
        await session.commit()
    adapter, _ = observer(monkeypatch)
    if provider_status == "missing":
        adapter.get_task_status.return_value = AdapterResult.fail("task history pruned")
    await tracking.poll_due_tasks()
    async with sessions() as session:
        row = await session.get(AdapterPendingChange, cid)
        assert (row.provider_task_next_poll_at is not None) == expected_poll
        assert row.provider_task["status"] == ("running" if expected_poll else "unknown")
        if not expected_poll:
            assert row.provider_task["detail"] == "manual_verification_required"


@pytest.mark.parametrize(
    "feature",
    [
        "proxmox.backup.run",
        "proxmox.backup.restore",
        "proxmox.snapshot.create",
        "proxmox.snapshot.delete",
        "proxmox.snapshot.rollback",
    ],
)
@pytest.mark.parametrize("response", [None, "OK", {}, 123])
def test_async_backup_and_snapshot_cannot_claim_completion_without_a_task(feature, response):
    assert tracking.accepted_task(feature, {"data": response})["status"] == "unknown"


@pytest.mark.asyncio
async def test_old_unresolved_task_remains_visible_in_bounded_listing(records):
    sessions, cid, controller_id = records
    await accept(sessions, cid)
    async with sessions() as session:
        row = await session.get(AdapterPendingChange, cid)
        row.created_at = datetime.now(UTC) - timedelta(days=2)
        session.add(
            AdapterPendingChange(
                organization_id=row.organization_id,
                site_id=row.site_id,
                controller_id=controller_id,
                feature="proxmox.vm.config",
                operation="update",
                payload={},
                status="applied",
            )
        )
        await session.commit()
        visible = await AdapterStagingService(session).list_pending(
            organization_id=row.organization_id,
            controller_id=controller_id,
            status_filter=None,
            limit=1,
        )
        assert visible[0].id == cid


@pytest.mark.asyncio
async def test_real_socket_disconnect_after_server_acceptance_never_replays(records):
    sessions, cid, _ = records
    accepted = []

    async def provider(reader, writer):
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            content_length = next(
                (
                    int(line.split(b":", 1)[1])
                    for line in headers.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                ),
                0,
            )
            await reader.readexactly(content_length)
            # The server records the dispatched write, then loses the connection
            # before acknowledging it. This is a real socket, not a raised mock.
            accepted.append(headers.split(b" ", 1)[0])
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(provider, "127.0.0.1", 0)
    adapter, client = connected(lambda _request: httpx.Response(500))
    await client._http.aclose()
    client._http = httpx.AsyncClient(
        base_url=f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}", timeout=2
    )
    try:
        async with sessions() as session:
            with pytest.raises(HTTPException):
                await AdapterStagingService(session).apply_change(
                    cid,
                    force=True,
                    applier=lambda _change: adapter.start_vm("pve1", 101, force=True),
                )
        async with sessions() as session:
            assert (
                await session.get(AdapterPendingChange, cid)
            ).status == "reconciliation_required"
        assert accepted == [b"POST"]
    finally:
        await client._http.aclose()
        server.close()
        await server.wait_closed()

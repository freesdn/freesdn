# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real PostgreSQL claims through the HTTP/service path; no hardware writes."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.site_access import current_user_var
from app.db.session import create_test_engine
from app.models.core import Controller, Organization, Site, User, UserRole
from app.models.staging import AdapterPendingChange
from app.modules.hypervisor import api
from app.modules.hypervisor.schemas import BulkActionRequest, VMActionRequest
from app.services import proxmox_task_tracking as tracking
from app.services.adapter_proxmox_container import GatewayProxmoxContainerService
from app.services.adapter_proxmox_vm import GatewayProxmoxVmService
from app.services.adapter_staging import AdapterStagingService
from app.services.hypervisor_power import HypervisorPowerService
from tests.adapters.test_proxmox_write_outcomes import UPID, connected


@pytest.fixture
async def power(monkeypatch):
    engine = create_test_engine()
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    oid, sid, cid, uid = [uuid4() for _ in range(4)]
    async with sessions() as db:
        db.add(Organization(id=oid, name="Power claim fixture", slug=str(oid)))
        await db.flush()
        db.add(Site(id=sid, organization_id=oid, name="Power site", slug=str(sid)))
        user = User(
            id=uid,
            organization_id=oid,
            email=f"{uid}@example.invalid",
            username=str(uid),
            hashed_password="not-a-login",
            role=UserRole.ORG_ADMIN,
        )
        db.add(user)
        await db.flush()
        db.add(
            Controller(
                id=cid,
                site_id=sid,
                name="Fixture",
                controller_type="proxmox",
                host="192.0.2.1",
                port=8006,
            )
        )
        await db.commit()
    c = SimpleNamespace(
        sessions=sessions,
        org=oid,
        site=sid,
        controller=cid,
        user=CurrentUser(user, ["*"]),
        calls=[],
        request=uuid4(),
        handler=None,
    )

    async def builder(_):
        async def dispatch(request):
            c.calls.append((request.method, request.url.path))
            if request.method == "GET" and request.url.path == "/cluster/resources":
                return httpx.Response(200, json={"data": [{"vmid": 101, "status": "running"}]})
            if c.handler:
                return await c.handler(request)
            return httpx.Response(200, json={"data": UPID})

        adapter = connected(dispatch)[0]
        if getattr(c, "disconnect_failure", False):
            close = adapter.disconnect

            async def broken_close():
                await close()
                if c.disconnect_failure == "timeout":
                    await asyncio.Future()
                raise RuntimeError("private transport cleanup details")

            adapter.disconnect = broken_close
        return adapter

    monkeypatch.setattr(GatewayProxmoxVmService, "_get_proxmox_adapter", staticmethod(builder))
    monkeypatch.setattr(
        GatewayProxmoxContainerService, "_get_proxmox_adapter", staticmethod(builder)
    )
    monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: False))
    monkeypatch.setattr("app.services.adapter_staging._publish_change_event", AsyncMock())
    monkeypatch.setattr(tracking, "CelerySessionLocal", sessions)
    try:
        yield c
    finally:
        async with sessions() as db:
            await db.execute(delete(Organization).where(Organization.id == oid))
            await db.commit()
        await engine.dispose()


async def submit(
    c,
    *,
    request_id=None,
    action="start",
    vm_type="qemu",
    node="pve1",
    vmid=101,
    force=True,
    user=None,
):
    async with c.sessions() as db:
        return await api.vm_action(
            c.controller,
            VMActionRequest(action=action, request_id=request_id or c.request, force=force),
            node,
            vm_type,
            vmid,
            db,
            user or c.user,
        )


async def rows(c):
    async with c.sessions() as db:
        return list(
            (
                await db.scalars(
                    select(AdapterPendingChange).where(
                        AdapterPendingChange.organization_id == c.org
                    )
                )
            ).all()
        )


@pytest.mark.parametrize(
    "vm_type,action",
    [
        ("qemu", "start"),
        ("qemu", "stop"),
        ("qemu", "shutdown"),
        ("qemu", "reboot"),
        ("qemu", "suspend"),
        ("qemu", "resume"),
        ("lxc", "start"),
        ("lxc", "stop"),
        ("lxc", "shutdown"),
        ("lxc", "reboot"),
    ],
)
async def test_power_endpoint_persists_actor_task_and_replays_receipt(power, vm_type, action):
    first = await submit(power, vm_type=vm_type, action=action)
    second = await submit(power, vm_type=vm_type, action=action)
    assert first.change_id == second.change_id
    assert first.status == second.status == "applied"
    assert first.provider_task.status == "pending"
    expected = [("POST", f"/nodes/pve1/{vm_type}/101/status/{action}")]
    if vm_type == "qemu" and action in {"stop", "shutdown"}:
        expected.insert(0, ("GET", "/cluster/resources"))
    assert power.calls == expected
    (row,) = await rows(power)
    assert row.created_by == power.user.id and row.updated_by == power.user.id
    assert row.site_id == power.site and row.organization_id == power.org
    assert row.provider_task_next_poll_at is not None


async def test_concurrent_first_requests_have_one_dispatch(power):
    entered, release = asyncio.Event(), asyncio.Event()

    async def hold(_):
        entered.set()
        await release.wait()
        return httpx.Response(200, json={"data": UPID})

    power.handler = hold
    first = asyncio.create_task(submit(power))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        others = await asyncio.wait_for(asyncio.gather(*(submit(power) for _ in range(5))), 5)
        assert all(r.status == "applying" for r in others)
        release.set()
        final = await first
        assert all(r.change_id == final.change_id for r in others)
        assert len(power.calls) == 1
    finally:
        release.set()
        await first


async def test_insert_race_uses_unique_key_without_expiring_principal(power, monkeypatch):
    original = AdapterStagingService.stage_change
    both = asyncio.Event()
    arrivals = 0

    async def synchronized(self, **kwargs):
        nonlocal arrivals
        arrivals += 1
        if arrivals == 2:
            both.set()
        await asyncio.wait_for(both.wait(), 5)
        return await original(self, **kwargs)

    monkeypatch.setattr(AdapterStagingService, "stage_change", synchronized)

    async def request():
        async with power.sessions() as db:
            # Deliberately attach the principal to the SAME session to detect
            # unsafe whole-transaction rollback on a duplicate-key race.
            actor = await db.get(User, power.user.id)
            return await HypervisorPowerService(db, CurrentUser(actor, ["*"])).execute(
                power.controller, "pve1", 101, "start", "qemu", request_id=power.request, force=True
            )

    receipts = await asyncio.wait_for(asyncio.gather(request(), request()), 10)
    assert receipts[0].change_id == receipts[1].change_id
    assert len(power.calls) == 1 and len(await rows(power)) == 1


@pytest.mark.parametrize(
    "changed", [{"action": "reboot"}, {"vmid": 102}, {"node": "pve2"}, {"vm_type": "lxc"}]
)
async def test_reused_key_cannot_change_intent(power, changed):
    await submit(power)
    with pytest.raises(HTTPException) as caught:
        await submit(power, **changed)
    assert caught.value.status_code == 409
    assert len(power.calls) == 1


@pytest.mark.parametrize(
    "failure,state",
    [("timeout", "reconciliation_required"), ("reject", "failed"), ("missing_task", "applied")],
)
async def test_failed_or_unknown_request_is_not_redispatched(power, failure, state):
    async def dispatch(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("private upstream details", request=request)
        return httpx.Response(403 if failure == "reject" else 200, json={"data": None})

    power.handler = dispatch
    first = await submit(power)
    replay = await submit(power)
    assert first.status == replay.status == state
    assert len(power.calls) == 1
    assert "private upstream details" not in first.model_dump_json()
    if failure == "missing_task":
        assert replay.provider_task.status == "unknown"


async def test_cancelled_dispatch_is_durable_and_cannot_replay(power):
    entered = asyncio.Event()

    async def hang(_):
        entered.set()
        await asyncio.Future()

    power.handler = hang
    task = asyncio.create_task(submit(power))
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    receipt = await submit(power)
    assert receipt.status == "applying" and len(power.calls) == 1
    async with power.sessions() as db:
        row = await db.get(AdapterPendingChange, receipt.change_id)
        row.updated_at = datetime.now(UTC) - timedelta(days=1)
        await db.commit()
        await AdapterStagingService(db)._recover_stale_applying(power.org)
    assert (await submit(power)).status == "reconciliation_required"
    assert len(power.calls) == 1


@pytest.mark.parametrize(
    "guard",
    [
        "read_only",
        "force",
        "foreign_org",
        "site_grant",
        "scoped",
        "role",
        "disabled",
        "sync_disabled",
        "deleted",
        "site_disabled",
        "site_deleted",
        "unsupported",
    ],
)
async def test_refusals_never_dispatch_or_stage(power, monkeypatch, guard):
    user = power.user
    if guard == "read_only":
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
    if guard in {"foreign_org", "site_grant", "scoped", "role"}:
        user = CurrentUser(
            User(
                id=power.user.id,
                organization_id=uuid4() if guard == "foreign_org" else power.org,
                role="viewer" if guard == "role" else "site_admin",
            ),
            ["*"],
            scoped=guard == "scoped",
            accessible_site_ids={uuid4()} if guard == "site_grant" else set(),
        )
    if guard in {"disabled", "sync_disabled", "deleted", "site_disabled", "site_deleted"}:
        async with power.sessions() as db:
            row = await db.get(
                Site if guard.startswith("site_") else Controller,
                power.site if guard.startswith("site_") else power.controller,
            )
            if guard.endswith("deleted"):
                row.deleted_at = datetime.now(UTC)
            elif guard == "sync_disabled":
                row.sync_enabled = False
            else:
                row.is_active = False
            await db.commit()
    with pytest.raises(HTTPException):
        await submit(
            power,
            force=guard != "force",
            user=user,
            vm_type="lxc" if guard == "unsupported" else "qemu",
            action="suspend" if guard == "unsupported" else "start",
        )
    assert not power.calls and not await rows(power)


async def test_target_move_between_stage_and_apply_blocks_network(power, monkeypatch):
    original = AdapterStagingService.stage_change

    async def move(self, **kwargs):
        change = await original(self, **kwargs)
        async with power.sessions() as db:
            sid = uuid4()
            db.add(Site(id=sid, organization_id=power.org, name="Moved", slug=str(sid)))
            await db.flush()
            ctrl = await db.get(Controller, power.controller)
            ctrl.site_id = sid
            await db.commit()
        return change

    monkeypatch.setattr(AdapterStagingService, "stage_change", move)
    receipt = await submit(power)
    assert receipt.status == "failed" and not power.calls


async def test_bulk_power_has_per_target_receipts_and_safe_partial_retry(power):
    targets = [
        {"node": "pve1", "vm_type": "qemu", "vmid": vmid, "request_id": uuid4()}
        for vmid in (101, 102)
    ]

    async def dispatch(request):
        if "/102/" in request.url.path:
            raise httpx.ReadTimeout("lost acknowledgement", request=request)
        return httpx.Response(200, json={"data": UPID})

    power.handler = dispatch

    async def bulk():
        async with power.sessions() as db:
            return await api.bulk_action(
                power.controller,
                BulkActionRequest(targets=targets, action="reboot", force=True),
                False,
                db,
                power.user,
            )

    first, replay = await bulk(), await bulk()
    assert [r.success for r in first] == [True, False]
    assert [r.status for r in replay] == ["applied", "reconciliation_required"]
    assert [r.change_id for r in first] == [r.change_id for r in replay]
    assert len(power.calls) == 2 and len(await rows(power)) == 2


@pytest.mark.parametrize("kind", ["missing", "duplicate_id", "duplicate_guest"])
def test_bulk_contract_rejects_ambiguous_power_targets(kind):
    key = uuid4()
    targets = [
        {"node": "pve1", "vm_type": "qemu", "vmid": 101, "request_id": key},
        {"node": "pve1", "vm_type": "qemu", "vmid": 102, "request_id": uuid4()},
    ]
    if kind == "missing":
        del targets[1]["request_id"]
    elif kind == "duplicate_id":
        targets[1]["request_id"] = key
    else:
        targets[1]["vmid"] = 101
    with pytest.raises(ValidationError):
        BulkActionRequest(targets=targets, action="start", force=True)


async def test_real_http_contract_and_read_only_gate(power, monkeypatch):
    app = FastAPI()
    app.include_router(api.router, prefix="/hypervisor")

    async def auth():
        token = current_user_var.set(power.user)
        try:
            yield power.user
        finally:
            current_user_var.reset(token)

    async def session():
        async with power.sessions() as db:
            yield db

    app.dependency_overrides[get_current_active_user] = auth
    app.dependency_overrides[api.get_db] = session
    url = f"/hypervisor/controllers/{power.controller}/nodes/pve1/qemu/101/action"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.post(url, json={"action": "start"})).status_code == 422
        body = {"action": "start", "request_id": str(power.request), "force": True}
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
        assert (await client.post(url, json=body)).status_code == 403
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: False))
        first = await client.post(url, json=body)
        assert first.status_code == 202
        assert first.json()["provider_task"]["status"] == "pending"
        second = await client.post(url, json=body)
        assert UUID(first.json()["change_id"]) == UUID(second.json()["change_id"])
    assert len(power.calls) == 1


@pytest.mark.parametrize("controller_type", ["proxmox", "pve"])
async def test_direct_receipt_is_completed_by_read_only_observer(
    power, monkeypatch, controller_type
):
    async with power.sessions() as db:
        ctrl = await db.get(Controller, power.controller)
        ctrl.controller_type = controller_type
        await db.commit()
    first = await submit(power)
    reads = []

    async def build(_):
        def dispatch(request):
            reads.append(request.method)
            return httpx.Response(
                200,
                json={
                    "data": {
                        "upid": UPID,
                        "node": "pve1",
                        "status": "stopped",
                        "exitstatus": "OK",
                    }
                },
            )

        return connected(dispatch)[0]

    monkeypatch.setattr(tracking, "build_proxmox_adapter", build)
    assert await tracking.poll_due_tasks() == {"polled": 1}
    replay = await submit(power)
    assert replay.change_id == first.change_id
    assert replay.provider_task.status == "succeeded"
    assert reads == ["GET"] and len(power.calls) == 1


@pytest.mark.parametrize("vm_type", ["qemu", "lxc"])
@pytest.mark.parametrize("cleanup", ["error", "timeout"])
async def test_cleanup_failure_cannot_erase_acknowledged_task(power, vm_type, cleanup):
    power.disconnect_failure = cleanup
    receipt = await asyncio.wait_for(submit(power, vm_type=vm_type), 5)
    assert receipt.status == "applied"
    assert receipt.provider_task.id == UPID
    assert receipt.provider_task.status == "pending"
    assert (await submit(power, vm_type=vm_type)).change_id == receipt.change_id
    assert len(power.calls) == 1


@pytest.mark.parametrize("vm_type", ["qemu", "lxc"])
async def test_cleanup_failure_cannot_replace_ambiguous_write(power, vm_type):
    power.disconnect_failure = "error"

    async def lost(request):
        raise httpx.ReadTimeout("acknowledgement lost", request=request)

    power.handler = lost
    receipt = await submit(power, vm_type=vm_type)
    assert receipt.status == "reconciliation_required"
    assert (await submit(power, vm_type=vm_type)).change_id == receipt.change_id
    assert len(power.calls) == 1

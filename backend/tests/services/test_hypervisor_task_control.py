# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real SQL claims and adapter HTTP transport; no production task is stopped."""

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.site_access import current_user_var
from app.models.core import Controller, Site, User
from app.models.staging import AdapterPendingChange
from app.modules.hypervisor import api
from app.modules.hypervisor.schemas import TaskStopRequest, TaskStopTarget
from app.services import hypervisor_task_control as control
from app.services import proxmox_task_tracking as tracking
from app.services.adapter_proxmox_cluster import GatewayProxmoxClusterService
from app.services.adapter_staging import AdapterStagingService
from tests.adapters.test_proxmox_write_outcomes import UPID, connected
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows


@pytest.fixture
async def system(power, monkeypatch):
    c = power
    c.upid = UPID
    c.state = SimpleNamespace(
        task={"upid": UPID, "node": "pve1", "type": "qmstart", "status": "running"},
        permissions={"/nodes/pve1": {"Sys.Audit": 1, "Sys.Modify": 1}},
        writes=[],
        mode="accepted",
        ack=None,
        unavailable=False,
        entered=asyncio.Event(),
        release=asyncio.Event(),
    )

    async def dispatch(request):
        s = c.state
        c.calls.append((request.method, request.url.path))
        if request.method == "DELETE":
            assert request.url.path == f"/nodes/pve1/tasks/{c.upid}"
            s.writes.append(request)
            s.entered.set()
            if s.mode == "wait":
                await s.release.wait()
            if s.mode == "reject":
                return httpx.Response(403, json={"errors": {"private": "diagnostic"}})
            if s.mode == "timeout":
                raise httpx.ReadTimeout("private diagnostic", request=request)
            if s.mode == "500":
                return httpx.Response(500, json={"errors": {"private": "diagnostic"}})
            return httpx.Response(200, json={"data": s.ack})
        if request.url.path == "/access/permissions":
            assert request.url.params["path"] == "/nodes/pve1"
            return httpx.Response(200, json={"data": s.permissions})
        assert request.url.path == f"/nodes/pve1/tasks/{c.upid}/status"
        if s.unavailable:
            return httpx.Response(403, json={"errors": {"private": "diagnostic"}})
        return httpx.Response(200, json={"data": s.task})

    async def builder(_):
        return connected(dispatch)[0]

    monkeypatch.setattr(control, "build_proxmox_adapter", builder)
    monkeypatch.setattr(tracking, "build_proxmox_adapter", builder)
    yield c


async def reviewed(c):
    async with c.sessions() as db:
        result = await control.HypervisorTaskControlService(db, c.user).review(
            c.controller, "pve1", c.upid
        )
    return TaskStopRequest(
        request_id=c.request, expected_digest=result["expected_digest"], force=True, confirmed=True
    )


async def submit(c, body):
    async with c.sessions() as db:
        return await control.HypervisorTaskControlService(db, c.user).submit(
            c.controller, "pve1", c.upid, body
        )


@pytest.mark.parametrize(
    "exitstatus", ["OK", "interrupted by signal", "ERROR: private details", ""]
)
async def test_receipt_and_observed_termination_do_not_claim_original_work_succeeded(
    system, exitstatus
):
    c = system
    body = await reviewed(c)
    receipt = await submit(c, body)
    assert receipt.status == "applied" and receipt.provider_task.status == "pending"
    assert (await submit(c, body)).change_id == receipt.change_id
    assert len(c.state.writes) == 1
    c.state.task.update(status="stopped", exitstatus=exitstatus)
    await tracking.poll_due_tasks()
    row = (await rows(c))[0]
    assert row.provider_task["status"] == "succeeded"
    assert row.provider_task["detail"] == "task_no_longer_running_effects_unverified"
    assert "private details" not in str(row.provider_task)
    assert len(c.state.writes) == 1


async def test_acknowledgement_while_running_does_not_mean_stopped(system):
    c = system
    await submit(c, await reviewed(c))
    await tracking.poll_due_tasks()
    row = (await rows(c))[0]
    assert row.provider_task["status"] == "running"
    assert row.provider_task["detail"] == "task_stop_requested_worker_still_running"
    assert row.provider_task_next_poll_at is not None


@pytest.mark.parametrize(
    "failure", ["unavailable", "identity", "node", "malformed", "state", "ack"]
)
async def test_missing_or_wrong_observation_remains_unknown(system, failure):
    c = system
    receipt = await submit(c, await reviewed(c))
    if failure == "unavailable":
        c.state.unavailable = True
    elif failure == "identity":
        c.state.task["upid"] = UPID.replace("101:", "102:")
    elif failure == "node":
        c.state.task["node"] = "pve2"
    elif failure == "malformed":
        c.state.task = []
    elif failure == "state":
        c.state.task["status"] = "unrecognized"
    else:
        async with c.sessions() as db:
            row = await db.get(AdapterPendingChange, receipt.change_id)
            row.applied_response = {"data": {"task_stop": "other", "node": "pve1"}}
            await db.commit()
    await tracking.poll_due_tasks()
    row = (await rows(c))[0]
    assert row.provider_task["status"] == "unknown"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("mode", ["timeout", "500", "bad_ack", "reject"])
async def test_write_failure_is_durable_and_never_redispatched(system, mode):
    c = system
    body = await reviewed(c)
    c.state.mode = mode
    if mode == "bad_ack":
        c.state.ack = "OK"
    first = await submit(c, body)
    assert first.status == ("failed" if mode == "reject" else "reconciliation_required")
    assert (await submit(c, body)).change_id == first.change_id
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("change", ["stopped", "permissions", "unavailable", "digest"])
async def test_pre_dispatch_recheck_refuses_changed_review(system, change):
    c = system
    body = await reviewed(c)
    if change == "stopped":
        c.state.task["status"] = "stopped"
    elif change == "permissions":
        c.state.permissions["/nodes/pve1"].pop("Sys.Modify")
    elif change == "unavailable":
        c.state.unavailable = True
    else:
        body = body.model_copy(update={"expected_digest": "0" * 64})
    result = await submit(c, body)
    assert result.status != "applied" and not c.state.writes


@pytest.mark.parametrize(
    "permissions",
    [
        {},
        {"/": {"Sys.Audit": 1, "Sys.Modify": 1}},
        {"/nodes/pve1": {}},
        {"/nodes/pve1": {"Sys.Audit": 1, "Sys.Modify": "false"}},
        None,
    ],
)
async def test_review_requires_explicit_provider_node_privileges(system, permissions):
    system.state.permissions = permissions
    with pytest.raises(HTTPException):
        await reviewed(system)
    assert not system.state.writes and not await rows(system)


async def test_concurrent_duplicate_requests_only_dispatch_once(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "wait"
    first = asyncio.create_task(submit(c, body))
    try:
        await asyncio.wait_for(c.state.entered.wait(), 10)
        second = await asyncio.wait_for(submit(c, body), 10)
        assert second.status == "applying"
    finally:
        c.state.release.set()
    assert (await first).change_id == second.change_id
    assert len(c.state.writes) == 1


async def test_cancelled_request_retains_claim_and_cannot_replay(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "wait"
    first = asyncio.create_task(submit(c, body))
    await asyncio.wait_for(c.state.entered.wait(), 10)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert (await submit(c, body)).status == "applying"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("original", ["matching", "different", "other_stop", "claiming"])
async def test_stop_allows_only_the_exact_original_worker_conflict(system, original):
    c = system
    body = await reviewed(c)
    async with c.sessions() as db:
        db.add(
            AdapterPendingChange(
                id=uuid4(),
                organization_id=c.org,
                site_id=c.site,
                controller_id=c.controller,
                feature=control.FEATURE if original == "other_stop" else "proxmox.storage.upload",
                operation="create",
                target_id="fixture",
                payload={},
                status="applying" if original == "claiming" else "applied",
                provider_task={
                    "id": UPID if original != "different" else UPID.replace("101:", "102:"),
                    "node": "pve1",
                    "status": "running",
                },
            )
        )
        await db.commit()
    if original == "matching":
        assert (await submit(c, body)).status == "applied" and len(c.state.writes) == 1
    else:
        with pytest.raises(HTTPException) as exc:
            await submit(c, body)
        assert exc.value.status_code == 409 and not c.state.writes


@pytest.mark.parametrize("field", ["force", "confirmed", "read_only"])
async def test_explicit_write_gates(system, field, monkeypatch):
    c = system
    body = await reviewed(c)
    if field == "read_only":
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
    else:
        body = body.model_copy(update={field: False})
    with pytest.raises(HTTPException):
        await submit(c, body)
    assert not await rows(c) and not c.state.writes


@pytest.mark.parametrize(
    "field,value",
    [("force", "true"), ("confirmed", 1), ("extra", True), ("expected_digest", "bad")],
)
def test_strict_request(field, value):
    with pytest.raises(ValidationError):
        TaskStopRequest(**{"request_id": uuid4(), "expected_digest": "a" * 64, field: value})


@pytest.mark.parametrize(
    "node,upid",
    [
        ("pve2", UPID),
        ("pve1", UPID + "/status"),
        ("pve1", UPID.replace("root", "../root")),
        ("pve1", "UPID:bad"),
    ],
)
def test_exact_task_identity(node, upid):
    with pytest.raises(ValidationError):
        TaskStopTarget(node=node, upid=upid)


@pytest.mark.parametrize("version", [None, True, 2])
async def test_legacy_intent_is_refused_before_credentials(system, version):
    c = system
    change = SimpleNamespace(
        feature=control.FEATURE,
        operation="create",
        target_id=UPID,
        payload={"node": "pve1", "task_stop_version": version},
    )
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await GatewayProxmoxClusterService(db).build_applier(change)(change)
    assert not c.calls


async def test_generic_staging_cannot_bypass_review(system):
    c = system
    body = await reviewed(c)
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await AdapterStagingService(db).stage_change(
                organization_id=c.org,
                site_id=c.site,
                controller_id=c.controller,
                actor_id=c.user.id,
                feature=control.FEATURE,
                operation="create",
                target_id=control.target_id(UPID),
                payload={
                    "task_stop_version": 1,
                    "node": "pve1",
                    "upid": UPID,
                    "expected_digest": body.expected_digest,
                },
            )
    assert not await rows(c)


async def test_request_identity_cannot_be_reused_for_another_review(system):
    c = system
    body = await reviewed(c)
    await submit(c, body)
    with pytest.raises(HTTPException) as exc:
        await submit(c, body.model_copy(update={"expected_digest": "b" * 64}))
    assert exc.value.status_code == 409 and len(c.state.writes) == 1


async def test_unknown_stop_can_be_resolved_without_fabricating_success(system):
    c = system
    receipt = await submit(c, await reviewed(c))
    c.state.unavailable = True
    await tracking.poll_due_tasks()
    async with c.sessions() as db:
        await AdapterStagingService(db).discard(
            receipt.change_id, organization_id=c.org, actor_id=c.user.id, force=True
        )
    row = (await rows(c))[0]
    assert row.status == "discarded" and row.provider_task["status"] == "unknown"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("method", ["get_tasks", "get_task_log"])
async def test_service_propagates_read_failure_instead_of_empty_list(method, monkeypatch):
    from unittest.mock import AsyncMock

    from app.adapters.base import AdapterResult
    from app.modules.hypervisor.service import HypervisorService

    service = HypervisorService(None)
    adapter, _ = connected(lambda _: httpx.Response(403))
    monkeypatch.setattr(adapter, "connect", AsyncMock())
    monkeypatch.setattr(adapter, method, AsyncMock(return_value=AdapterResult.fail("unavailable")))
    monkeypatch.setattr(service, "_get_adapter", AsyncMock(return_value=adapter))
    with pytest.raises(ConnectionError):
        await getattr(service, method)(None, "pve1", *([UPID] if method == "get_task_log" else []))


async def test_long_native_identity_is_not_truncated(system):
    c = system
    c.upid = UPID.replace("root@pam!audit", "operator@pve!" + "a" * 140)
    c.state.task["upid"] = c.upid
    await submit(c, await reviewed(c))
    row = (await rows(c))[0]
    assert len(row.target_id) <= 128 and row.payload["upid"] == c.upid
    assert row.provider_task["id"] == c.upid


@pytest.mark.parametrize("guard", ["accepted", "foreign_org", "site_grant", "scoped", "role"])
async def test_http_contract_authorization_and_legacy_refusal(system, guard):
    c = system
    body = await reviewed(c)
    c.calls.clear()
    user = (
        c.user
        if guard == "accepted"
        else CurrentUser(
            User(
                id=c.user.id,
                organization_id=uuid4() if guard == "foreign_org" else c.org,
                role="viewer" if guard == "role" else "site_admin",
            ),
            ["*"],
            scoped=guard == "scoped",
            accessible_site_ids={uuid4()} if guard == "site_grant" else set(),
        )
    )

    async def auth():
        token = current_user_var.set(user)
        try:
            yield user
        finally:
            current_user_var.reset(token)

    async def session():
        async with c.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(api.router, prefix="/hypervisor")
    app.dependency_overrides[get_current_active_user] = auth
    app.dependency_overrides[api.get_db] = session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        url = f"/hypervisor/controllers/{c.controller}/nodes/pve1/tasks/{UPID}"
        review = await client.post(url + "/stop-review")
        response = await client.request("DELETE", url, json=body.model_dump(mode="json"))
        if guard == "accepted":
            assert review.status_code == 200 and response.status_code == 202
            assert response.json()["provider_task"]["status"] == "pending"
            assert (await client.delete(url)).status_code == 422
            assert (
                await client.post(url.replace("nodes/pve1", "nodes/pve2") + "/stop-review")
            ).status_code == 422
        else:
            assert review.status_code in {403, 404} and response.status_code in {403, 404}
            assert not c.calls


@pytest.mark.parametrize("field", ["sync_enabled", "is_active", "site_active"])
async def test_disabled_target_is_refused_before_credentials(system, field):
    c = system
    body = await reviewed(c)
    c.calls.clear()
    async with c.sessions() as db:
        row = await db.get(
            Site if field == "site_active" else Controller,
            c.site if field == "site_active" else c.controller,
        )
        setattr(row, "is_active" if field == "site_active" else field, False)
        await db.commit()
    with pytest.raises(HTTPException):
        await submit(c, body)
    assert not c.calls


async def test_task_inventory_includes_active_workers_and_normalizes_running():
    async def dispatch(request):
        assert request.url.params["source"] == "all"
        return httpx.Response(
            200, json={"data": [{"upid": UPID, "status": "RUNNING", "type": "qmstart"}]}
        )

    adapter, _ = connected(dispatch)
    try:
        result = await adapter.get_tasks("pve1")
        assert result.success and result.data[0].is_running
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize(
    "method,data",
    [("get_tasks", {}), ("get_tasks", [None]), ("get_task_log", {}), ("get_task_log", [{}])],
)
async def test_malformed_task_reads_do_not_look_empty(method, data):
    adapter, _ = connected(lambda _: httpx.Response(200, json={"data": data}))
    try:
        result = await getattr(adapter, method)(
            "pve1", *([UPID] if method == "get_task_log" else [])
        )
        assert not result.success
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize("flag", [0, False, "0", "1"])
async def test_nonpropagating_node_grants_allow_reviewed_task_stop(system, flag):
    c = system
    c.state.permissions["/nodes/pve1"] = {"Sys.Audit": flag, "Sys.Modify": flag}
    receipt = await submit(c, await reviewed(c))
    assert receipt.status == "applied" and len(c.state.writes) == 1
    c.state.task.update(status="stopped", exitstatus="interrupted")
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "succeeded"


@pytest.mark.parametrize("privilege", ["Sys.Audit", "Sys.Modify"])
async def test_nonpropagating_task_grant_revoked_after_review_blocks_write(system, privilege):
    c = system
    c.state.permissions["/nodes/pve1"] = {"Sys.Audit": 0, "Sys.Modify": 0}
    body = await reviewed(c)
    c.state.permissions["/nodes/pve1"].pop(privilege)
    assert (await submit(c, body)).status == "failed"
    assert not c.state.writes


async def test_task_propagation_change_does_not_revoke_exact_node_grant(system):
    c = system
    body = await reviewed(c)
    c.state.permissions["/nodes/pve1"] = {"Sys.Audit": 0, "Sys.Modify": 0}
    assert (await submit(c, body)).status == "applied"
    assert len(c.state.writes) == 1

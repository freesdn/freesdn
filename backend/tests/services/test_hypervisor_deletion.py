# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Deletion through real PostgreSQL claims and real adapter HTTP; no hardware writes."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from app.adapters.exceptions import AdapterConfirmationRequiredError
from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.site_access import current_user_var
from app.models.core import User
from app.models.staging import AdapterPendingChange
from app.modules.hypervisor import api
from app.modules.hypervisor.schemas import BulkActionRequest, DeleteVMRequest
from app.services import proxmox_task_tracking as tracking
from app.services.adapter_proxmox_container import GatewayProxmoxContainerService
from app.services.adapter_proxmox_vm import GatewayProxmoxVmService
from app.services.adapter_staging import AdapterStagingService
from tests.adapters.test_proxmox_write_outcomes import connected
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows

DIGEST = "a" * 40


def task(kind="qemu", vmid=101, node="pve1"):
    return f"UPID:{node}:00000001:00000001:66000000:{'qmdestroy' if kind == 'qemu' else 'vzdestroy'}:{vmid}:root@pam:"


@pytest.fixture
async def deletion(power, monkeypatch):
    state = SimpleNamespace(
        kind="qemu",
        node="pve1",
        status="stopped",
        config={"digest": DIGEST},
        writes=[],
        mode="accepted",
        unused=True,
        task_status="stopped",
        task_exit="OK",
        entered=asyncio.Event(),
        release=asyncio.Event(),
        ack=None,
        read_params=[],
    )

    async def dispatch(request):
        power.calls.append((request.method, request.url.path))
        if request.method == "DELETE":
            state.writes.append(request)
            if state.mode == "wait":
                state.entered.set()
                await state.release.wait()
            if state.mode == "timeout":
                raise httpx.ReadTimeout("private-secret", request=request)
            if state.mode == "crash":
                raise asyncio.CancelledError()
            if state.mode == "reject":
                return httpx.Response(400, json={"errors": "private-secret"})
            return httpx.Response(
                200, json={"data": state.ack if state.ack is not None else task(state.kind)}
            )
        if request.url.path == "/cluster/resources":
            if state.mode == "inventory_failure":
                return httpx.Response(403, json={})
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "vmid": 101,
                            "node": state.node,
                            "type": state.kind,
                            "status": state.status,
                        }
                    ]
                },
            )
        if request.url.path.endswith("/config"):
            if state.mode == "config_failure":
                return httpx.Response(403, json={})
            return httpx.Response(200, json={"data": state.config})
        if request.url.path == "/cluster/nextid":
            state.read_params.append(dict(request.url.params))
            if state.unused == "error":
                return httpx.Response(403, json={})
            return httpx.Response(200, json={"data": 101 if state.unused is True else state.unused})
        if "/tasks/" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "upid": task(state.kind),
                        "node": "pve1",
                        "status": state.task_status,
                        "exitstatus": state.task_exit,
                    }
                },
            )
        raise AssertionError(str(request.url))

    async def builder(_):
        return connected(dispatch)[0]

    for cls in [GatewayProxmoxVmService, GatewayProxmoxContainerService]:
        monkeypatch.setattr(cls, "_get_proxmox_adapter", staticmethod(builder))
    monkeypatch.setattr(tracking, "build_proxmox_adapter", builder)
    power.deletion = state
    return power


async def submit(
    c, *, request_id=None, kind=None, force=True, confirmed=True, expected_digest=DIGEST
):
    async with c.sessions() as db:
        return await api.delete_vm(
            c.controller,
            DeleteVMRequest(
                request_id=request_id or c.request,
                force=force,
                confirmed=confirmed,
                expected_digest=expected_digest,
            ),
            "pve1",
            kind or c.deletion.kind,
            101,
            db,
            c.user,
        )


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
async def test_acceptance_replay_and_verified_completion(deletion, kind):
    c = deletion
    c.deletion.kind = kind
    first = await submit(c)
    again = await submit(c)
    assert first.status == "applied" and first.provider_task.status == "pending"
    assert first.change_id == again.change_id and len(c.deletion.writes) == 1
    write = c.deletion.writes[0]
    assert write.url.path == f"/nodes/pve1/{kind}/101"
    assert not write.url.query and not write.content  # no provider force/purge/skiplock
    assert await tracking.poll_due_tasks() == {"polled": 1}
    row = (await rows(c))[0]
    assert row.provider_task["status"] == "succeeded"
    assert row.provider_task["detail"] == "guest_deletion_verified"
    assert c.deletion.read_params == [{"vmid": "101"}]
    assert row.created_by == c.user.id and row.payload["expected_digest"] == DIGEST
    await submit(c)
    assert len(c.deletion.writes) == 1


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
@pytest.mark.parametrize(
    "guard",
    [
        "digest",
        "running",
        "type",
        "node",
        "lock",
        "protection",
        "inventory_failure",
        "config_failure",
    ],
)
async def test_preflight_fails_closed(deletion, kind, guard):
    c = deletion
    s = c.deletion
    s.kind = kind
    if guard == "digest":
        s.config["digest"] = "b" * 40
    elif guard == "running":
        s.status = "running"
    elif guard == "type":
        s.kind = "lxc" if kind == "qemu" else "qemu"
    elif guard == "node":
        s.node = "pve2"
    elif guard in {"lock", "protection"}:
        s.config[guard] = "backup" if guard == "lock" else 1
    else:
        s.mode = guard
    result = await submit(c, kind=kind)
    assert result.status == "failed" and not s.writes
    assert (await submit(c, kind=kind)).change_id == result.change_id
    assert not s.writes


@pytest.mark.parametrize(
    "mode,expected", [("timeout", "reconciliation_required"), ("reject", "failed")]
)
async def test_lost_or_rejected_response_never_replays(deletion, mode, expected):
    deletion.deletion.mode = mode
    first = await submit(deletion)
    second = await submit(deletion)
    assert first.status == second.status == expected
    assert len(deletion.deletion.writes) == 1
    assert "private-secret" not in first.model_dump_json()
    assert "private-secret" not in ((await rows(deletion))[0].failure_reason or "")


@pytest.mark.parametrize("ack", ["OK", task(vmid=102), task(node="pve2"), task("lxc"), "UPID:evil"])
async def test_unusable_or_wrong_task_requires_reconciliation(deletion, ack):
    deletion.deletion.ack = ack
    assert (await submit(deletion)).status == "reconciliation_required"
    await submit(deletion)
    assert len(deletion.deletion.writes) == 1


@pytest.mark.parametrize("unused", [False, 102, "101", "error", None])
async def test_provider_ok_does_not_prove_guest_absence(deletion, unused):
    deletion.deletion.unused = unused
    await submit(deletion)
    await tracking.poll_due_tasks()
    row = (await rows(deletion))[0]
    assert row.provider_task["status"] == "unknown"
    assert row.provider_task_next_poll_at is not None
    assert len(deletion.deletion.writes) == 1


@pytest.mark.parametrize(
    "exitstatus,status",
    [
        ("WARNINGS: 1", "warnings"),
        ("ERROR", "failed"),
        ("unable to get last line from task log", "unknown"),
    ],
)
async def test_task_outcomes_are_not_success(deletion, exitstatus, status):
    deletion.deletion.task_exit = exitstatus
    await submit(deletion)
    await tracking.poll_due_tasks()
    assert (await rows(deletion))[0].provider_task["status"] == status
    assert not deletion.deletion.read_params


async def test_confirmation_read_only_and_force_are_separate(deletion, monkeypatch):
    with pytest.raises(AdapterConfirmationRequiredError):
        await submit(deletion, confirmed=False)
    with pytest.raises(HTTPException) as exc:
        await submit(deletion, force=False)
    assert exc.value.status_code == 403
    monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
    with pytest.raises(HTTPException) as exc:
        await submit(deletion)
    assert exc.value.status_code == 403 and not deletion.calls and not await rows(deletion)


async def test_request_id_cannot_switch_review(deletion):
    await submit(deletion)
    with pytest.raises(HTTPException) as exc:
        await submit(deletion, expected_digest="b" * 40)
    assert exc.value.status_code == 409 and len(deletion.deletion.writes) == 1


async def test_distinct_concurrent_requests_cannot_delete_twice(deletion):
    s = deletion.deletion
    s.mode = "wait"
    first = asyncio.create_task(submit(deletion))
    try:
        await asyncio.wait_for(s.entered.wait(), 5)
        with pytest.raises(HTTPException) as exc:
            await submit(deletion, request_id=uuid4())
        assert exc.value.status_code == 409
    finally:
        s.release.set()
        await first
    assert len(s.writes) == 1


async def test_crash_claim_survives_and_is_not_replayed(deletion):
    deletion.deletion.mode = "crash"
    with pytest.raises(asyncio.CancelledError):
        await submit(deletion)
    assert (await rows(deletion))[0].status == "applying"
    async with deletion.sessions() as db:
        row = await db.get(AdapterPendingChange, (await rows(deletion))[0].id)
        row.updated_at = datetime.now(UTC) - timedelta(hours=2)
        await db.commit()
    await submit(deletion)
    assert len(deletion.deletion.writes) == 1


@pytest.mark.parametrize(
    "tamper", ["version", "extra", "kind", "target", "operation", "bool_version"]
)
async def test_generic_stage_cannot_bypass_review(deletion, tamper):
    plan = {
        "deletion_version": 1,
        "node": "pve1",
        "vmid": 101,
        "vm_type": "qemu",
        "expected_digest": DIGEST,
        "confirmed": True,
    }
    c = SimpleNamespace(
        payload=plan,
        feature="proxmox.vm.destroy",
        operation="delete",
        target_id="101",
        controller_id=deletion.controller,
        organization_id=deletion.org,
    )
    if tamper == "version":
        plan.pop("deletion_version")
    elif tamper == "bool_version":
        plan["deletion_version"] = True
    elif tamper == "extra":
        plan["purge"] = True
    elif tamper == "kind":
        plan["vm_type"] = "lxc"
    elif tamper == "operation":
        c.operation = "create"
    else:
        c.target_id = "102"
    async with deletion.sessions() as db:
        with pytest.raises(HTTPException):
            await GatewayProxmoxVmService(db).build_applier(c)(c)
    assert not deletion.calls


@pytest.mark.parametrize("guard", ["accepted", "foreign_org", "site_grant", "scoped", "role"])
async def test_http_contract_and_authorization(deletion, guard):
    c = deletion
    user = c.user
    if guard != "accepted":
        user = CurrentUser(
            User(
                id=c.user.id,
                organization_id=uuid4() if guard == "foreign_org" else c.org,
                role="viewer" if guard == "role" else "site_admin",
            ),
            ["*"],
            scoped=guard == "scoped",
            accessible_site_ids={uuid4()} if guard == "site_grant" else set(),
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
    body = {
        "request_id": str(c.request),
        "expected_digest": DIGEST,
        "force": True,
        "confirmed": True,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        url = f"/hypervisor/controllers/{c.controller}/nodes/pve1/qemu/101"
        response = await client.request("DELETE", url, json=body)
        if guard == "accepted":
            assert response.status_code == 202
            for missing in ["request_id", "expected_digest"]:
                assert (
                    await client.request(
                        "DELETE", url, json={k: v for k, v in body.items() if k != missing}
                    )
                ).status_code == 422
            assert (await client.delete(url, params={"confirmed": True})).status_code == 422
        else:
            assert response.status_code in {403, 404} and not c.calls


@pytest.mark.parametrize(
    "field,value",
    [("confirmed", "true"), ("purge", True), ("skiplock", True), ("expected_digest", "bad")],
)
def test_strict_delete_contract(field, value):
    with pytest.raises(ValidationError):
        DeleteVMRequest(**{"request_id": uuid4(), "expected_digest": DIGEST, field: value})


def test_bulk_delete_requires_distinct_reviewed_intents():
    target = {
        "node": "pve1",
        "vm_type": "qemu",
        "vmid": 101,
        "request_id": uuid4(),
        "expected_digest": DIGEST,
    }
    assert BulkActionRequest(action="delete", targets=[target])
    for missing in ["request_id", "expected_digest"]:
        with pytest.raises(ValidationError):
            BulkActionRequest(
                action="delete", targets=[{k: v for k, v in target.items() if k != missing}]
            )
    with pytest.raises(ValidationError):
        BulkActionRequest(
            action="delete", targets=[target, {**target, "vm_type": "lxc", "request_id": uuid4()}]
        )


async def test_bulk_delete_receipts_replay_without_duplicate_writes(deletion):
    c = deletion
    body = BulkActionRequest(
        action="delete",
        force=True,
        targets=[
            {
                "node": "pve1",
                "vm_type": "qemu",
                "vmid": 101,
                "request_id": c.request,
                "expected_digest": DIGEST,
            }
        ],
    )
    async with c.sessions() as db:
        first = await api.bulk_action(c.controller, body, True, db, c.user)
    async with c.sessions() as db:
        again = await api.bulk_action(c.controller, body, True, db, c.user)
    assert first[0].change_id == again[0].change_id and first[0].success
    assert len(c.deletion.writes) == 1


async def test_unknown_observation_can_be_resolved_but_not_replayed(deletion):
    c = deletion
    c.deletion.unused = False
    receipt = await submit(c)
    await tracking.poll_due_tasks()
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await AdapterStagingService(db).discard(receipt.change_id, organization_id=c.org)
    async with c.sessions() as db:
        await AdapterStagingService(db).discard(
            receipt.change_id, organization_id=c.org, force=True
        )
    assert (await submit(c)).status == "discarded"
    assert len(c.deletion.writes) == 1


async def test_same_concurrent_request_gets_one_claim(deletion):
    state = deletion.deletion
    state.mode = "wait"
    first = asyncio.create_task(submit(deletion))
    try:
        await asyncio.wait_for(state.entered.wait(), 5)
        replay = await submit(deletion)
        assert replay.status == "applying"
    finally:
        state.release.set()
        result = await first
    assert result.change_id == replay.change_id and len(state.writes) == 1


async def test_running_task_cannot_be_manually_cleared(deletion):
    deletion.deletion.task_status = "running"
    receipt = await submit(deletion)
    await tracking.poll_due_tasks()
    async with deletion.sessions() as db:
        with pytest.raises(HTTPException) as exc:
            await AdapterStagingService(db).discard(
                receipt.change_id, organization_id=deletion.org, force=True
            )
    assert exc.value.status_code == 409


async def test_expired_observation_stops_without_claiming_success(deletion):
    deletion.deletion.unused = "error"
    receipt = await submit(deletion)
    async with deletion.sessions() as db:
        row = await db.get(AdapterPendingChange, receipt.change_id)
        row.applied_at = datetime.now(UTC) - timedelta(days=8)
        await db.commit()
    await tracking.poll_due_tasks()
    row = (await rows(deletion))[0]
    assert row.provider_task["status"] == "unknown"
    assert row.provider_task["detail"] == "manual_verification_required"
    assert row.provider_task_next_poll_at is None


async def test_bulk_partial_conflict_does_not_change_or_replay_first_intent(deletion):
    c = deletion
    first = await submit(c)
    body = BulkActionRequest(
        action="delete",
        force=True,
        targets=[
            {
                "node": "pve1",
                "vm_type": "qemu",
                "vmid": 101,
                "request_id": uuid4(),
                "expected_digest": DIGEST,
            },
            {
                "node": "pve1",
                "vm_type": "qemu",
                "vmid": 102,
                "request_id": uuid4(),
                "expected_digest": DIGEST,
            },
        ],
    )
    async with c.sessions() as db:
        results = await api.bulk_action(c.controller, body, True, db, c.user)
    assert not results[0].success and results[0].change_id is None
    assert results[1].status == "failed" and results[1].change_id is not None
    assert len(c.deletion.writes) == 1
    assert (await submit(c)).change_id == first.change_id

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Cloning/migration at the real DB and HTTP boundaries, without hardware writes."""

import asyncio
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from app.core.dependencies import get_current_active_user
from app.core.site_access import current_user_var
from app.modules.hypervisor import api
from app.modules.hypervisor.schemas import BulkMigrateRequest, CloneRequest, MigrateRequest
from app.services.adapter_staging import AdapterStagingService
from tests.adapters.test_proxmox_write_outcomes import UPID, connected
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows
from tests.services.test_hypervisor_power import submit as submit_power


async def submit(c, operation="migrate", vm_type="qemu", *, request_id=None, **options):
    values = {"request_id": request_id or c.request, "force": True}
    values.update({"newid": 202} if operation == "clone" else {"target": "pve2"})
    values.update(options)
    body = (CloneRequest if operation == "clone" else MigrateRequest)(**values)
    async with c.sessions() as db:
        return await getattr(api, operation + "_vm")(
            c.controller, body, "pve1", vm_type, 101, db, c.user
        )


@pytest.mark.parametrize("vm_type", ["qemu", "lxc"])
@pytest.mark.parametrize("operation", ["clone", "migrate"])
async def test_operation_receipt_is_durable_and_replay_does_not_dispatch(power, operation, vm_type):
    first = await submit(power, operation, vm_type)
    replay = await submit(power, operation, vm_type)
    assert first.change_id == replay.change_id
    assert first.status == replay.status == "applied"
    assert first.provider_task.id == UPID and first.provider_task.status == "pending"
    assert [p for method, p in power.calls if method == "POST"] == [
        f"/nodes/pve1/{vm_type}/101/{operation}"
    ]
    (row,) = await rows(power)
    assert row.created_by == power.user.id and row.site_id == power.site
    assert row.provider_task_next_poll_at is not None


@pytest.mark.parametrize(
    "vm_type,operation,options,expected",
    [
        (
            "qemu",
            "clone",
            {"name": "copied", "full": True, "target": "pve2", "storage": "local-lvm"},
            {
                "newid": ["202"],
                "name": ["copied"],
                "full": ["1"],
                "target": ["pve2"],
                "storage": ["local-lvm"],
            },
        ),
        (
            "lxc",
            "clone",
            {"name": "copied", "full": True},
            {"newid": ["202"], "hostname": ["copied"], "full": ["1"]},
        ),
        ("qemu", "migrate", {"online": True}, {"target": ["pve2"], "online": ["1"]}),
        ("qemu", "migrate", {"online": False}, {"target": ["pve2"]}),
        ("lxc", "migrate", {"restart": True}, {"target": ["pve2"], "restart": ["1"]}),
        ("lxc", "migrate", {}, {"target": ["pve2"]}),
    ],
)
async def test_provider_receives_exact_clone_and_migration_options(
    power, vm_type, operation, options, expected
):
    bodies = []

    async def dispatch(request):
        bodies.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json={"data": UPID})

    power.handler = dispatch
    result = await submit(power, operation, vm_type, **options)
    assert result.status == "applied"
    assert bodies == [expected]


@pytest.mark.parametrize(
    "operation,vm_type,options",
    [
        ("clone", "qemu", {"newid": 203}),
        ("clone", "qemu", {"full": False}),
        ("clone", "qemu", {"name": "different"}),
        ("clone", "qemu", {"storage": "different"}),
        ("clone", "qemu", {"target": "pve3"}),
        ("clone", "qemu", {"description": "different"}),
        ("clone", "lxc", {"name": "different"}),
        ("migrate", "qemu", {"target": "pve3"}),
        ("migrate", "qemu", {"online": True}),
        ("migrate", "lxc", {"restart": True}),
    ],
)
async def test_request_key_binds_every_write_option(power, operation, vm_type, options):
    await submit(power, operation, vm_type)
    with pytest.raises(HTTPException) as exc:
        await submit(power, operation, vm_type, **options)
    assert exc.value.status_code == 409
    assert len([method for method, _ in power.calls if method == "POST"]) == 1


@pytest.mark.parametrize("operation", ["clone", "migrate"])
async def test_power_and_other_operations_share_one_request_namespace(power, operation):
    await submit_power(power)
    with pytest.raises(HTTPException) as exc:
        await submit(power, operation)
    assert exc.value.status_code == 409
    assert len(power.calls) == 1 and len(await rows(power)) == 1


@pytest.mark.parametrize("operation", ["clone", "migrate"])
@pytest.mark.parametrize(
    "failure,status",
    [
        ("timeout", "reconciliation_required"),
        ("rejected", "failed"),
        ("missing_task", "applied"),
    ],
)
async def test_failure_and_missing_task_never_cause_a_second_dispatch(
    power, operation, failure, status
):
    async def dispatch(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("private provider credential", request=request)
        if failure == "rejected":
            return httpx.Response(400, json={"errors": "private provider credential"})
        return httpx.Response(200, json={"data": None})

    power.handler = dispatch
    first = await submit(power, operation)
    replay = await submit(power, operation)
    assert first.status == replay.status == status
    assert "private provider credential" not in first.model_dump_json()
    if failure == "missing_task":
        assert first.provider_task.status == "unknown"
        assert first.upid is None
    assert len([m for m, _ in power.calls if m == "POST"]) == 1


@pytest.mark.parametrize("operation", ["clone", "migrate"])
async def test_concurrent_lifecycle_submissions_share_the_claim(power, operation):
    entered, release = asyncio.Event(), asyncio.Event()

    async def hold(_):
        entered.set()
        await release.wait()
        return httpx.Response(200, json={"data": UPID})

    power.handler = hold
    first = asyncio.create_task(submit(power, operation))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        replies = await asyncio.wait_for(
            asyncio.gather(*(submit(power, operation) for _ in range(4))), 5
        )
        assert all(r.status == "applying" for r in replies)
        release.set()
        final = await first
        assert all(r.change_id == final.change_id for r in replies)
        assert len([m for m, _ in power.calls if m == "POST"]) == 1
    finally:
        release.set()
        await first


@pytest.mark.parametrize("operation", ["clone", "migrate"])
async def test_interrupted_write_stays_uncertain_after_claim_recovery(power, operation):
    async def cancelled(_):
        raise asyncio.CancelledError()

    power.handler = cancelled
    with pytest.raises(asyncio.CancelledError):
        await submit(power, operation)
    (row,) = await rows(power)
    assert row.status == "applying"
    async with power.sessions() as db:
        stale = await db.get(type(row), row.id)
        stale.updated_at = datetime.now(UTC) - timedelta(minutes=6)
        await db.commit()
        await AdapterStagingService(db)._recover_stale_applying()
    replay = await submit(power, operation)
    assert replay.status == "reconciliation_required"
    assert len([m for m, _ in power.calls if m == "POST"]) == 1


@pytest.mark.parametrize(
    "operation,vm_type,options",
    [
        ("clone", "qemu", {"newid": 101}),
        ("clone", "lxc", {"target": "../bad"}),
        ("clone", "qemu", {"storage": "../bad"}),
        ("migrate", "qemu", {"target": "pve1"}),
        ("migrate", "qemu", {"target": "../bad"}),
        ("migrate", "qemu", {"restart": True}),
        ("migrate", "lxc", {"online": True}),
    ],
)
async def test_invalid_or_unsupported_intents_never_reach_provider(
    power, operation, vm_type, options
):
    with pytest.raises((HTTPException, ValueError)):
        await submit(power, operation, vm_type, **options)
    assert not power.calls and not await rows(power)


async def test_container_adapter_also_refuses_unsupported_live_mode():
    calls = []
    adapter, _ = connected(lambda request: calls.append(request))
    try:
        result = await adapter.migrate_container("pve1", 101, "pve2", online=True, force=True)
        assert not result.success and not calls
    finally:
        await adapter.disconnect()


async def test_partial_bulk_retry_retains_receipts_and_uses_guest_specific_modes(power):
    targets = [
        {"node": "pve1", "vm_type": kind, "vmid": vmid, "request_id": uuid4()}
        for kind, vmid in [("qemu", 101), ("lxc", 102), ("qemu", 103)]
    ]
    bodies = []

    async def dispatch(request):
        bodies.append(parse_qs(request.content.decode()))
        if "/102/" in request.url.path:
            raise httpx.ReadTimeout("lost acknowledgement", request=request)
        return httpx.Response(200, json={"data": UPID})

    power.handler = dispatch

    async def bulk():
        async with power.sessions() as db:
            return await api.bulk_migrate(
                power.controller,
                BulkMigrateRequest(
                    targets=targets, target_node="pve2", online=True, restart=True, force=True
                ),
                db,
                power.user,
            )

    first, replay = await bulk(), await bulk()
    assert [r.success for r in first] == [True, False, True]
    assert [r.status for r in replay] == ["applied", "reconciliation_required", "applied"]
    assert [r.change_id for r in first] == [r.change_id for r in replay]
    assert bodies == [
        {"target": ["pve2"], "online": ["1"]},
        {"target": ["pve2"], "restart": ["1"]},
        {"target": ["pve2"], "online": ["1"]},
    ]
    assert len(await rows(power)) == 3


@pytest.mark.parametrize("kind", ["missing", "duplicate_id", "duplicate_guest"])
def test_bulk_contract_rejects_ambiguous_migration_targets(kind):
    targets = [
        {"node": "pve1", "vm_type": "qemu", "vmid": vmid, "request_id": uuid4()}
        for vmid in (101, 102)
    ]
    if kind == "missing":
        del targets[1]["request_id"]
    elif kind == "duplicate_id":
        targets[1]["request_id"] = targets[0]["request_id"]
    else:
        targets[1]["vmid"] = 101
    with pytest.raises(ValidationError):
        BulkMigrateRequest(targets=targets, target_node="pve2", force=True)


@pytest.mark.parametrize("operation", ["clone", "migrate"])
async def test_real_http_contract_guards_and_receipts(power, monkeypatch, operation):
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
    url = f"/hypervisor/controllers/{power.controller}/nodes/pve1/qemu/101/{operation}"
    body = {"newid": 202} if operation == "clone" else {"target": "pve2"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        assert (await client.post(url, json=body)).status_code == 422
        body["request_id"] = str(power.request)
        assert (await client.post(url, json=body)).status_code == 403
        body["force"] = True
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
        assert (await client.post(url, json=body)).status_code == 403
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: False))
        first = await client.post(url, json=body)
        assert first.status_code == 202
        assert first.json()["provider_task"]["status"] == "pending"
        second = await client.post(url, json=body)
        assert first.json()["change_id"] == second.json()["change_id"]
    assert len([m for m, _ in power.calls if m == "POST"]) == 1

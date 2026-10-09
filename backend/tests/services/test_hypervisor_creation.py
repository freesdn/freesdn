# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Creation through real DB claims and adapter HTTP; no hardware writes."""

import asyncio
import json
from types import SimpleNamespace
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.redaction import redact_secrets
from app.core.site_access import current_user_var
from app.models.core import User
from app.modules.hypervisor import api
from app.modules.hypervisor.schemas import CreateContainerRequest, CreateVMRequest
from app.services import proxmox_task_tracking as tracking
from app.services.adapter_proxmox_container import GatewayProxmoxContainerService
from app.services.adapter_proxmox_vm import GatewayProxmoxVmService
from app.services.adapter_staging import AdapterStagingService
from tests.adapters.test_proxmox_write_outcomes import connected
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows

PASSWORD = "fixture-only-container-password"


def task(kind="qemu", vmid=101, node="pve1", worker=None):
    return f"UPID:{node}:00000001:00000001:66000000:{worker or ('qmcreate' if kind == 'qemu' else 'vzcreate')}:{vmid}:root@pam:"


@pytest.fixture
async def creation(power, monkeypatch):
    state = SimpleNamespace(
        kind="qemu",
        writes=[],
        mode="accepted",
        available=101,
        ack=None,
        config={},
        inventory=None,
        task_exit="OK",
        task_status="stopped",
        entered=asyncio.Event(),
        release=asyncio.Event(),
    )

    async def dispatch(request):
        power.calls.append((request.method, request.url.path))
        if request.method == "POST":
            state.writes.append(request)
            values = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            state.config = {
                **values,
                "cores": int(values["cores"]),
                "memory": int(values["memory"]),
            }
            disk = "scsi0" if state.kind == "qemu" else "rootfs"
            state.config[disk] = f"local-lvm:vm-101-disk-0,size={values[disk].split(':')[1]}G"
            if state.mode == "wait":
                state.entered.set()
                await state.release.wait()
            if state.mode == "timeout":
                raise httpx.ReadTimeout("private provider secret", request=request)
            if state.mode == "crash":
                raise asyncio.CancelledError()
            if state.mode == "reject":
                return httpx.Response(400, json={"errors": PASSWORD})
            return httpx.Response(
                200, json={"data": state.ack if state.ack is not None else task(state.kind)}
            )
        if request.url.path == "/cluster/nextid":
            assert dict(request.url.params) == {"vmid": "101"}
            return httpx.Response(200, json={"data": state.available})
        if request.url.path == "/cluster/resources":
            return httpx.Response(
                200,
                json={
                    "data": state.inventory
                    if state.inventory is not None
                    else [{"vmid": 101, "node": "pve1", "type": state.kind, "status": "stopped"}]
                },
            )
        if request.url.path.endswith("/config"):
            if state.mode == "observation_error":
                raise RuntimeError("unavailable readback")
            return httpx.Response(200, json={"data": state.config})
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
    power.creation = state
    return power


def body(c, **options):
    common = {"vmid": 101, "node": "pve1", "request_id": c.request, "force": True}
    if c.creation.kind == "qemu":
        return CreateVMRequest(**(common | {"name": "reviewed-vm"} | options))
    return CreateContainerRequest(
        **(
            common
            | {
                "hostname": "reviewed-ct",
                "ostemplate": "local:vztmpl/debian.tar.zst",
                "password": PASSWORD,
            }
            | options
        )
    )


async def submit(c, **options):
    async with c.sessions() as db:
        method = api.create_vm if c.creation.kind == "qemu" else api.create_container
        return await method(c.controller, body(c, **options), db, c.user)


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
async def test_acceptance_replay_and_readback(creation, kind):
    c = creation
    c.creation.kind = kind
    first = await submit(c)
    again = await submit(c)
    assert first.change_id == again.change_id and first.status == "applied"
    assert first.provider_task.status == "pending" and len(c.creation.writes) == 1
    request = c.creation.writes[0]
    assert request.url.path == f"/nodes/pve1/{kind}"
    sent = parse_qs(request.content.decode())
    assert not {"force", "restore", "skiplock", "purge"} & sent.keys()
    assert sent["scsi0" if kind == "qemu" else "rootfs"] == [
        "local-lvm:32" if kind == "qemu" else "local-lvm:8"
    ]
    if kind == "qemu":
        assert sent["balloon"] == ["0"]
    else:
        assert sent["password"] == [PASSWORD]
        row = (await rows(c))[0]
        assert PASSWORD not in json.dumps(row.payload)
        assert row.payload["password"] and row.payload["password"] not in json.dumps(
            redact_secrets(row.payload)
        )
        assert PASSWORD not in repr(body(c))
    assert await tracking.poll_due_tasks() == {"polled": 1}
    assert (await rows(c))[0].provider_task["detail"] == "guest_creation_verified"
    await submit(c)
    assert len(c.creation.writes) == 1


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
@pytest.mark.parametrize("mode", ["timeout", "reject", "crash"])
async def test_uncertain_failed_and_crashed_writes_never_replay(creation, kind, mode):
    c = creation
    c.creation.kind, c.creation.mode = kind, mode
    if mode == "crash":
        with pytest.raises(asyncio.CancelledError):
            await submit(c)
    else:
        result = await submit(c)
        assert result.status == ("failed" if mode == "reject" else "reconciliation_required")
    await submit(c)
    assert len(c.creation.writes) == 1
    assert PASSWORD not in json.dumps((await rows(c))[0].payload)


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
@pytest.mark.parametrize("ack", ["OK", task(vmid=102), task(node="pve2"), task(worker="qmstart")])
async def test_mismatched_ack_requires_reconciliation(creation, kind, ack):
    c = creation
    c.creation.kind, c.creation.ack = kind, ack
    assert (await submit(c)).status == "reconciliation_required"
    await submit(c)
    assert len(c.creation.writes) == 1


@pytest.mark.parametrize("available", [None, 102, True, "101"])
async def test_no_write_when_allocation_cannot_be_verified(creation, available):
    creation.creation.available = available
    assert (await submit(creation)).status == "failed"
    assert not creation.creation.writes


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
@pytest.mark.parametrize(
    "case", ["missing", "wrong_node", "wrong_type", "marker", "memory", "disk", "locked", "start"]
)
async def test_task_ok_is_not_sufficient(creation, kind, case):
    c = creation
    c.creation.kind = kind
    await submit(c, **({"start_after_create": True} if case == "start" else {}))
    if case == "missing":
        c.creation.inventory = []
    elif case in {"wrong_node", "wrong_type"}:
        c.creation.inventory = [
            {
                "vmid": 101,
                "node": "other" if case == "wrong_node" else "pve1",
                "type": "other" if case == "wrong_type" else kind,
            }
        ]
    else:
        key, value = {
            "marker": ("description", "replacement"),
            "memory": ("memory", 16),
            "disk": ("scsi0" if kind == "qemu" else "rootfs", "local-lvm:other,size=1G"),
            "locked": ("lock", "create"),
            "start": ("irrelevant", 1),
        }[case]
        c.creation.config[key] = value
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "unknown"
    assert len(c.creation.writes) == 1


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
async def test_changed_intent_conflicts_and_same_key_concurrent_is_single_write(creation, kind):
    c = creation
    c.creation.kind = kind
    first, second = await asyncio.gather(submit(c), submit(c))
    assert first.change_id == second.change_id and len(c.creation.writes) == 1
    with pytest.raises(HTTPException) as e:
        await submit(c, memory=4096)
    assert e.value.status_code == 409
    if kind == "lxc":
        with pytest.raises(HTTPException) as e:
            await submit(c, password="different-password")
        assert e.value.status_code == 409


async def test_distinct_intents_cannot_dispatch_same_unresolved_id(creation):
    c = creation
    c.creation.mode = "wait"
    first = asyncio.create_task(submit(c))
    await asyncio.wait_for(c.creation.entered.wait(), 5)
    try:
        with pytest.raises(HTTPException) as e:
            await submit(c, request_id=uuid4())
        assert e.value.status_code == 409
    finally:
        c.creation.release.set()
        await first
    assert len(c.creation.writes) == 1


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
@pytest.mark.parametrize(
    "tamper", ["legacy", "unknown_option", "target", "version", "plaintext", "foreign_token"]
)
async def test_generic_create_cannot_bypass_plan_validation(creation, kind, tamper):
    c = creation
    c.creation.kind = kind
    await submit(c)
    row = (await rows(c))[0]
    if tamper == "legacy":
        row.payload = {"node": "pve1", "vmid": 101}
    elif tamper == "unknown_option":
        row.payload["options"]["hookscript"] = "local:snippets/script"
    elif tamper == "target":
        row.target_id = "102"
    elif tamper == "version":
        row.payload["creation_version"] = True
    elif tamper == "plaintext":
        row.payload["password"] = PASSWORD
    else:
        row.id = uuid4()
        if kind == "qemu":
            row.payload["password"] = "foreign"
    c.calls.clear()
    domain = (
        GatewayProxmoxVmService(None) if kind == "qemu" else GatewayProxmoxContainerService(None)
    )
    with pytest.raises(HTTPException) as e:
        await domain.build_applier(row)(row)
    assert e.value.status_code == 400 and not c.calls


@pytest.mark.parametrize(
    "options",
    [
        {"force": False},
        {"storage": "local,force=1"},
        {"disk_size": "32G,discard=on"},
        {"iso": "local:iso/../secret"},
        {"net_bridge": "vmbr0,tag=1"},
    ],
)
async def test_invalid_requests_never_dispatch(creation, options):
    with pytest.raises(HTTPException):
        await submit(creation, **options)
    assert not creation.calls and not await rows(creation)


def test_creation_requires_fixed_id_and_strict_force():
    for options in [{"vmid": None}, {"force": "true"}, {"vmid": True}, {"extra": 1}]:
        with pytest.raises(ValidationError):
            CreateVMRequest(**({"request_id": uuid4(), "node": "pve1", "vmid": 101} | options))


async def test_read_only_blocks_before_credentials(creation, monkeypatch):
    monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
    with pytest.raises(HTTPException) as e:
        await submit(creation)
    assert e.value.status_code == 403 and not creation.calls


async def test_http_contract_202_and_legacy_body_rejected(creation):
    c = creation
    app = FastAPI()
    app.include_router(api.router, prefix="/api/v1/hypervisor")

    async def db():
        async with c.sessions() as session:
            yield session

    app.dependency_overrides[api.get_db] = db
    app.dependency_overrides[get_current_active_user] = lambda: c.user
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        url = f"/api/v1/hypervisor/controllers/{c.controller}/vms"
        rejected = await client.post(url, json={"node": "pve1", "name": "old"})
        assert rejected.status_code == 422 and not c.calls
        response = await client.post(url, json=body(c).model_dump(mode="json"))
        assert (
            response.status_code == 202 and response.json()["provider_task"]["status"] == "pending"
        )


@pytest.mark.parametrize("guard", ["foreign_org", "site_grant", "scoped", "role"])
async def test_http_authorization_before_provider_access(creation, guard):
    c = creation
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

    async def db():
        async with c.sessions() as session:
            yield session

    app = FastAPI()
    app.include_router(api.router, prefix="/hypervisor")
    app.dependency_overrides[get_current_active_user] = auth
    app.dependency_overrides[api.get_db] = db
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            f"/hypervisor/controllers/{c.controller}/vms", json=body(c).model_dump(mode="json")
        )
    assert response.status_code in {403, 404} and not c.calls and not await rows(c)


@pytest.mark.parametrize("with_id", [False, True])
async def test_generic_staging_never_persists_plaintext_creation_password(creation, with_id):
    c = creation
    async with c.sessions() as db:
        with pytest.raises(HTTPException) as e:
            await AdapterStagingService(db).stage_change(
                organization_id=c.org,
                controller_id=c.controller,
                site_id=c.site,
                actor_id=c.user.id,
                feature="proxmox.container.create",
                operation="create",
                target_id="101",
                payload={"node": "pve1", "vmid": 101, "password": PASSWORD},
                change_id=uuid4() if with_id else None,
            )
        assert e.value.status_code == 400
    assert not await rows(c)


async def test_unknown_readback_manual_resolution_retains_receipt_and_never_replays(creation):
    c = creation
    receipt = await submit(c)
    c.creation.inventory = []
    await tracking.poll_due_tasks()
    async with c.sessions() as db:
        await AdapterStagingService(db).discard(
            receipt.change_id, organization_id=c.org, force=True
        )
    replay = await submit(c)
    assert replay.status == "discarded" and replay.change_id == receipt.change_id
    assert len(c.creation.writes) == 1


@pytest.mark.parametrize(
    "status,exitstatus,expected", [("running", "OK", "running"), ("stopped", "ERROR", "failed")]
)
async def test_provider_failure_and_running_are_not_creation_success(
    creation, status, exitstatus, expected
):
    c = creation
    await submit(c)
    c.creation.task_status, c.creation.task_exit = status, exitstatus
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == expected
    assert len(c.creation.writes) == 1


@pytest.mark.parametrize("kind", ["qemu", "lxc"])
async def test_readback_exception_resets_task_success_to_unknown(creation, kind):
    c = creation
    c.creation.kind = kind
    await submit(c)
    c.creation.mode = "observation_error"
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "unknown"
    assert len(c.creation.writes) == 1


@pytest.mark.parametrize(
    "value,success",
    [(101, True), (None, False), (True, False), ("101", False), (0, False), (1000000000, False)],
)
async def test_next_id_is_validated_not_guessed(value, success):
    async def dispatch(request):
        return httpx.Response(200, json={"data": value})

    adapter, _ = connected(dispatch)
    try:
        result = await adapter.get_next_vmid()
        assert result.success is success
    finally:
        await adapter.disconnect()

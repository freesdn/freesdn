# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real database claims through the real adapter HTTP client; no hardware writes."""

import asyncio
from types import SimpleNamespace
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from app.core.dependencies import CurrentUser, get_current_active_user
from app.core.site_access import current_user_var
from app.models.core import Controller, Site, User
from app.modules.hypervisor import api
from app.modules.hypervisor.schemas import (
    BackupJobOperationRequest,
    BackupJobReviewRequest,
    BackupJobSettings,
)
from app.services import hypervisor_backup_jobs as jobs
from app.services import proxmox_task_tracking as tracking
from app.services.adapter_proxmox_backup import GatewayProxmoxBackupService
from app.services.adapter_staging import AdapterStagingService
from tests.adapters.test_proxmox_write_outcomes import connected
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows
from tests.services.test_hypervisor_power import submit as submit_guest


@pytest.fixture
async def system(power, monkeypatch):
    c = power
    c.state = SimpleNamespace(
        jobs=[],
        config={
            "storage": "local",
            "type": "dir",
            "content": "backup,iso",
            "prune-backups": "keep-last=3",
        },
        status={"active": 1, "enabled": 1},
        cluster=[{"type": "node", "name": "pve1", "online": 1}],
        guests=[{"vmid": 101, "type": "qemu", "node": "pve1", "name": "database"}],
        defaults={"storage": "local", "prune-backups": "keep-last=3", "compress": "0"},
        permissions={
            "/": {"Sys.Audit": 1, "Sys.Modify": 1},
            "/nodes/pve1": {"Sys.Audit": 1},
            "/storage/local": {"Datastore.Audit": 1, "Datastore.Allocate": 1},
            "/vms/101": {"VM.Audit": 1, "VM.Backup": 1},
        },
        writes=[],
        mode="accepted",
        unavailable=None,
        ack=None,
        entered=asyncio.Event(),
        release=asyncio.Event(),
    )

    async def dispatch(request):
        s = c.state
        path = request.url.path
        c.calls.append((request.method, path))
        if request.method != "GET":
            s.writes.append(request)
            s.entered.set()
            if s.mode == "wait":
                await s.release.wait()
            if s.mode == "reject":
                return httpx.Response(400, json={"errors": {"private": "diagnostic"}})
            options = {
                k: v[0]
                for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()
            }
            if s.mode != "unchanged":
                if request.method == "POST":
                    assert not any(j["id"] == options["id"] for j in s.jobs)
                    if "prune-backups" in options:
                        options["prune-backups"] = {"keep-all": 1}
                    s.jobs.append(options)
                elif request.method == "PUT":
                    next(j for j in s.jobs if j["id"] == path.rsplit("/", 1)[1]).update(options)
                else:
                    s.jobs = [j for j in s.jobs if j["id"] != path.rsplit("/", 1)[1]]
            if s.mode == "timeout":
                raise httpx.ReadTimeout("private upstream diagnostic", request=request)
            return httpx.Response(200, json={"data": s.ack})
        if path == s.unavailable:
            return httpx.Response(403, json={"errors": {"private": "diagnostic"}})
        values = {
            "/cluster/backup": s.jobs,
            "/access/permissions": {
                request.url.params["path"]: s.permissions[request.url.params["path"]]
            }
            if request.url.params.get("path") in s.permissions
            else {},
            "/cluster/status": s.cluster,
            "/cluster/resources": s.guests,
            "/storage/local": s.config,
            "/nodes/pve1/storage/local/status": s.status,
            "/nodes/pve1/vzdump/defaults": s.defaults,
        }
        assert path in values, path
        return httpx.Response(200, json={"data": values[path]})

    async def builder(_):
        return connected(dispatch)[0]

    c.builder = builder
    monkeypatch.setattr(jobs, "build_proxmox_adapter", builder)
    monkeypatch.setattr(tracking, "build_proxmox_adapter", builder)
    yield c


def intent(action="create", **changes):
    return BackupJobReviewRequest(
        action=action,
        job_id="nightly",
        settings=None
        if action == "delete"
        else {
            "node": "pve1",
            "storage": "local",
            "schedule": "sat 02:00",
            "vmid": "101",
            "enabled": False,
            **changes,
        },
    )


async def reviewed(c, action="create", **changes):
    body = intent(action, **changes)
    if action != "create" and not c.state.jobs:
        c.state.jobs = [
            {
                "id": "nightly",
                "node": "pve1",
                "storage": "local",
                "schedule": "01:00",
                "vmid": "101",
                "enabled": 1,
                "prune-backups": {"keep-last": 3},
                "mailto": "fixture@example.invalid",
                "mailnotification": "failure",
            }
        ]
    async with c.sessions() as db:
        review = await jobs.HypervisorBackupJobService(db, c.user).review(c.controller, body)
    return BackupJobOperationRequest(
        **body.model_dump(),
        request_id=c.request,
        expected_digest=review["expected_digest"],
        force=True,
        confirmed=True,
    )


async def submit(c, body):
    async with c.sessions() as db:
        return await jobs.HypervisorBackupJobService(db, c.user).submit(c.controller, body)


@pytest.mark.parametrize("action", ["create", "update", "delete"])
async def test_durable_replay_and_configuration_readback(system, action):
    c = system
    body = await reviewed(c, action)
    receipt = await submit(c, body)
    assert receipt.status == "applied" and receipt.provider_task.status == "pending"
    assert (await submit(c, body)).change_id == receipt.change_id
    assert len(c.state.writes) == 1 and len(await rows(c)) == 1
    await tracking.poll_due_tasks()
    saved = (await rows(c))[0]
    assert saved.provider_task["status"] == "succeeded"
    assert saved.provider_task["detail"] == "backup_job_configuration_verified"
    if action == "create":
        wire = parse_qs(c.state.writes[0].content.decode())
        assert (
            wire["id"] == ["nightly"]
            and wire["prune-backups"] == ["keep-all=1"]
            and wire["enabled"] == ["0"]
        )
    if action == "update":
        assert c.state.jobs[0]["prune-backups"] == {"keep-last": 3}
        assert c.state.jobs[0]["mailto"] == "fixture@example.invalid"
        assert c.state.jobs[0]["mailnotification"] == "failure"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("action", ["create", "update", "delete"])
async def test_acknowledgement_without_matching_configuration_remains_unknown(system, action):
    c = system
    body = await reviewed(c, action)
    c.state.mode = "unchanged"
    await submit(c, body)
    await tracking.poll_due_tasks()
    saved = (await rows(c))[0]
    assert saved.provider_task["status"] == "unknown"
    assert saved.provider_task["detail"] == "backup_job_configuration_not_verified"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize(
    "changed",
    ["retention", "enabled", "schedule", "guest_node", "storage", "defaults", "permissions"],
)
async def test_stale_review_never_writes(system, changed):
    c = system
    body = await reviewed(c, "update")
    if changed == "retention":
        c.state.jobs[0]["prune-backups"] = {"keep-last": 1}
    elif changed in ("enabled", "schedule"):
        c.state.jobs[0][changed] = 0 if changed == "enabled" else "03:00"
    elif changed == "guest_node":
        c.state.guests[0]["node"] = "other"
    elif changed == "storage":
        c.state.config["path"] = "/new/path"
    elif changed == "defaults":
        c.state.defaults["mailto"] = "changed@example.invalid"
    else:
        c.state.permissions["/vms/101"]["VM.Backup"] = 0
    receipt = await submit(c, body)
    assert receipt.status == "failed" and not c.state.writes


@pytest.mark.parametrize(
    "problem",
    [
        "missing_privilege",
        "missing_node_audit",
        "hidden_guest",
        "template",
        "offline",
        "storage_disabled",
        "malformed_jobs",
        "duplicate_jobs",
        "duplicate_guest",
        "defaults_missing",
        "hook",
        "fleecing",
        "advanced_selector",
        "advanced_option",
    ],
)
async def test_review_refusals_are_fail_closed(system, problem):
    c = system
    body = await reviewed(c, "update")
    if problem == "missing_privilege":
        c.state.permissions["/"].pop("Sys.Modify")
    elif problem == "missing_node_audit":
        c.state.permissions["/nodes/pve1"] = {}
    elif problem == "hidden_guest":
        c.state.guests = []
    elif problem == "template":
        c.state.guests[0]["template"] = 1
    elif problem == "offline":
        c.state.cluster[0]["online"] = 0
    elif problem == "storage_disabled":
        c.state.status["enabled"] = 0
    elif problem == "malformed_jobs":
        c.state.jobs = {}
    elif problem == "duplicate_jobs":
        c.state.jobs *= 2
    elif problem == "duplicate_guest":
        c.state.guests *= 2
    elif problem == "defaults_missing":
        c.state.defaults = None
    elif problem == "hook":
        c.state.defaults["script"] = "/private/hook"
    elif problem == "fleecing":
        c.state.defaults["fleecing"] = "1,storage=unchecked"
    elif problem == "advanced_selector":
        c.state.jobs[0]["all"] = 1
    else:
        c.state.jobs[0]["script"] = "/private/hook"
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await jobs.HypervisorBackupJobService(db, c.user).review(
                c.controller, BackupJobReviewRequest(**body.model_dump(exclude=jobs._CONTROL))
            )
    assert not c.state.writes and not await rows(c)


@pytest.mark.parametrize("mode", ["timeout", "reject", "unexpected_ack"])
async def test_lost_or_invalid_acknowledgement_never_replays(system, mode):
    c = system
    body = await reviewed(c)
    c.state.mode = mode
    if mode == "unexpected_ack":
        c.state.ack = "UPID:pve1:00000000:00000000:00000000:vzdump:101:root@pam:"
    receipt = await submit(c, body)
    assert receipt.status == ("failed" if mode == "reject" else "reconciliation_required")
    assert (await submit(c, body)).change_id == receipt.change_id
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("gate", ["force", "confirmed", "read_only"])
async def test_gates_before_recording(system, monkeypatch, gate):
    body = await reviewed(system)
    if gate == "read_only":
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
    else:
        body = body.model_copy(update={gate: False})
    with pytest.raises(HTTPException):
        await submit(system, body)
    assert not await rows(system) and not system.state.writes


async def test_concurrent_replay_dispatches_once(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "wait"
    first = asyncio.create_task(submit(c, body))
    await asyncio.wait_for(c.state.entered.wait(), 5)
    try:
        second = await submit(c, body)
        assert second.status == "applying" and len(c.state.writes) == 1
    finally:
        c.state.release.set()
    assert (await first).change_id == second.change_id


async def test_cancelled_dispatch_keeps_claim(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "wait"
    first = asyncio.create_task(submit(c, body))
    await asyncio.wait_for(c.state.entered.wait(), 5)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert (await submit(c, body)).status == "applying"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("direction", ["backup_then_guest", "guest_then_backup"])
async def test_unresolved_cross_feature_claim_blocks_dispatch(system, direction):
    c = system
    body = await reviewed(c)
    if direction == "backup_then_guest":
        await submit(c, body)
        with pytest.raises(HTTPException) as exc:
            await submit_guest(c, request_id=uuid4())
    else:
        await submit_guest(c)
        with pytest.raises(HTTPException) as exc:
            await submit(c, body.model_copy(update={"request_id": uuid4()}))
    assert exc.value.status_code == 409
    assert len(c.state.writes) == (1 if direction == "backup_then_guest" else 0)


@pytest.mark.parametrize("guard", ["inactive", "sync_disabled", "site_inactive", "reassigned"])
async def test_scope_rechecked_in_applier_before_credentials(system, guard):
    c = system
    body = await reviewed(c)
    c.calls.clear()
    async with c.sessions() as db:
        controller = await db.get(Controller, c.controller)
        site = await db.get(Site, c.site)
        if guard == "inactive":
            controller.is_active = False
        elif guard == "sync_disabled":
            controller.sync_enabled = False
        elif guard == "site_inactive":
            site.is_active = False
        change = SimpleNamespace(
            feature=jobs.FEATURE,
            operation="create",
            target_id="nightly",
            controller_id=c.controller,
            organization_id=uuid4() if guard == "reassigned" else c.org,
            site_id=c.site,
            payload={"backup_job_version": 1, **body.model_dump(exclude={"request_id", "force"})},
        )
        await db.flush()
        with pytest.raises(HTTPException):
            await GatewayProxmoxBackupService(db).build_applier(change)(change)
    assert not c.calls


@pytest.mark.parametrize(
    "payload",
    [{"confirmed": True}, {"backup_job_version": True}, {"script": "/bin/sh", "confirmed": True}],
)
async def test_legacy_applier_refuses_before_credentials(system, payload):
    c = system
    change = SimpleNamespace(
        feature=jobs.FEATURE, operation="create", target_id="nightly", payload=payload
    )
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await GatewayProxmoxBackupService(db).build_applier(change)(change)
    assert not c.calls


async def test_generic_staging_cannot_persist_even_forged_review(system):
    c = system
    body = await reviewed(c)
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await AdapterStagingService(db).stage_change(
                organization_id=c.org,
                controller_id=c.controller,
                site_id=c.site,
                feature=jobs.FEATURE,
                operation="create",
                target_id="nightly",
                actor_id=c.user.id,
                payload={
                    "backup_job_version": 1,
                    **body.model_dump(exclude={"request_id", "force", "confirmed"}),
                },
            )
    assert not await rows(c) and not c.state.writes


@pytest.mark.parametrize("guard", ["accepted", "foreign_org", "site_grant", "scoped", "role"])
async def test_http_contract_and_authorization(system, guard):
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
        url = f"/hypervisor/controllers/{c.controller}/backup/jobs"
        response = await client.post(url, json=body.model_dump(mode="json"))
        if guard == "accepted":
            assert (
                response.status_code == 202
                and response.json()["provider_task"]["status"] == "pending"
            )
            assert (
                await client.post(url, json={"storage": "local", "schedule": "01:00"})
            ).status_code == 422
            assert (
                await client.delete(url + "/nightly", params={"confirmed": True})
            ).status_code == 422
        else:
            assert response.status_code in {403, 404} and not c.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("vmid", ""),
        ("vmid", "all"),
        ("vmid", "101,101"),
        ("vmid", "99"),
        ("vmid", "101;102"),
        ("node", "../pve1"),
        ("schedule", "25:00"),
        ("enabled", "true"),
        ("script", "/bin/sh"),
        ("compress", "none"),
    ],
)
def test_strict_explicit_settings(field, value):
    with pytest.raises(ValidationError):
        BackupJobSettings(**{**intent().settings.model_dump(), field: value})


async def test_volatile_next_run_does_not_invalidate_review(system):
    c = system
    before = await reviewed(c, "update")
    c.state.jobs[0]["next-run"] = 2000000000
    c.state.guests[0]["cpu"] = 0.8
    assert (await reviewed(c, "update")).expected_digest == before.expected_digest


async def test_readback_permission_failure_stays_unknown(system):
    c = system
    await submit(c, await reviewed(c))
    c.state.unavailable = "/cluster/backup"
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "unknown"


async def test_advanced_delete_redacts_hook_but_binds_its_digest(system):
    c = system
    await reviewed(c, "delete")
    c.state.jobs[0]["script"] = "/private/secret-hook"
    async with c.sessions() as db:
        review = await jobs.HypervisorBackupJobService(db, c.user).review(
            c.controller, intent("delete")
        )
    assert "secret-hook" not in str(review)
    body = await reviewed(c, "delete")
    assert (await submit(c, body)).status == "applied"
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "succeeded"


@pytest.mark.parametrize("changed", ["retention", "hook", "disabled"])
async def test_readback_covers_more_than_job_presence(system, changed):
    c = system
    await submit(c, await reviewed(c, enabled=True))
    if changed == "retention":
        c.state.jobs[0]["prune-backups"] = {"keep-last": 1}
    elif changed == "hook":
        c.state.jobs[0]["script"] = "/unexpected/hook"
    else:
        c.state.jobs[0]["enabled"] = 0
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "unknown"


async def test_request_id_conflicts_on_different_settings(system):
    c = system
    body = await reviewed(c)
    await submit(c, body)
    other = body.model_copy(
        update={"settings": body.settings.model_copy(update={"schedule": "03:00"})}
    )
    with pytest.raises(HTTPException) as exc:
        await submit(c, other)
    assert exc.value.status_code == 409 and len(c.state.writes) == 1


async def test_unknown_can_be_resolved_without_forging_success_or_redispatch(system):
    c = system
    c.state.mode = "unchanged"
    receipt = await submit(c, await reviewed(c))
    await tracking.poll_due_tasks()
    async with c.sessions() as db:
        resolved = await AdapterStagingService(db).discard(
            receipt.change_id, organization_id=c.org, actor_id=c.user.id, force=True
        )
        assert resolved.provider_task["status"] == "unknown"
        assert resolved.status == "discarded"
        assert resolved.provider_task["detail"] == "operator_resolved_unknown_outcome"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize(
    "value",
    [None, {}, [{"id": "nightly", "enabled": "false"}], [{"id": "nightly"}, {"id": "nightly"}]],
)
async def test_bad_inventory_is_not_an_empty_schedule_list(system, value):
    c = system
    c.state.jobs = value
    adapter = await c.builder(None)
    try:
        result = await adapter.get_backup_jobs()
        assert result.success is False
    finally:
        await adapter.disconnect()


async def test_disabled_wire_flag_is_not_truthy(system):
    c = system
    c.state.jobs = [{"id": "nightly", "enabled": "0"}]
    adapter = await c.builder(None)
    try:
        result = await adapter.get_backup_jobs()
        assert result.success and result.data[0].enabled is False
        assert result.data[0].compress == ""  # inherited, not invented zstd
    finally:
        await adapter.disconnect()


async def test_schedule_read_failure_reaches_module_error_state(system, monkeypatch):
    from app.modules.hypervisor.service import HypervisorService

    c = system
    c.state.unavailable = "/cluster/backup"
    service = HypervisorService(None)
    monkeypatch.setattr(service, "_get_adapter", c.builder)
    # Real adapter connect is already established; context entry normally connects.
    adapter = await c.builder(None)
    from unittest.mock import AsyncMock

    monkeypatch.setattr(adapter, "connect", AsyncMock())
    monkeypatch.setattr(service, "_get_adapter", AsyncMock(return_value=adapter))
    with pytest.raises(ConnectionError):
        await service.get_backup_jobs(None)


@pytest.mark.parametrize("action", ["update", "delete"])
async def test_legacy_native_job_ids_are_supported(system, action):
    c = system
    await reviewed(c, action)
    legacy_id = "a" * 40 + ":1"
    c.state.jobs[0]["id"] = legacy_id
    request = intent(action).model_copy(update={"job_id": legacy_id})
    async with c.sessions() as db:
        review = await jobs.HypervisorBackupJobService(db, c.user).review(c.controller, request)
    body = BackupJobOperationRequest(
        **request.model_dump(),
        request_id=c.request,
        expected_digest=review["expected_digest"],
        confirmed=True,
        force=True,
    )
    assert (await submit(c, body)).status == "applied"
    assert c.state.writes[0].url.path.endswith(legacy_id)
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "succeeded"


@pytest.mark.parametrize(
    "endpoint,action,path_id",
    [
        ("create", "update", "nightly"),
        ("update", "delete", "nightly"),
        ("delete", "create", "nightly"),
        ("update", "update", "other"),
        ("delete", "delete", "other"),
    ],
)
async def test_endpoint_action_and_identity_must_match(system, endpoint, action, path_id):
    c = system
    body = await reviewed(c, action)
    async with c.sessions() as db:
        with pytest.raises(HTTPException) as exc:
            if endpoint == "create":
                await api.create_backup_job(c.controller, body, db, c.user)
            elif endpoint == "update":
                await api.update_backup_job(c.controller, body, path_id, db, c.user)
            else:
                await api.delete_backup_job(c.controller, body, path_id, db, c.user)
    assert exc.value.status_code == 400 and not c.state.writes and not await rows(c)


@pytest.mark.parametrize("action", ["create", "update", "delete"])
@pytest.mark.parametrize("flag", [0, False, "0"])
async def test_explicit_backup_paths_allow_nonpropagating_grants(system, action, flag):
    c = system
    c.state.permissions = {
        path: dict.fromkeys(grants, flag) for path, grants in c.state.permissions.items()
    }
    receipt = await submit(c, await reviewed(c, action))
    assert receipt.status == "applied" and len(c.state.writes) == 1
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "succeeded"


@pytest.mark.parametrize(
    "path,privilege",
    [
        ("/", "Sys.Audit"),
        ("/", "Sys.Modify"),
        ("/nodes/pve1", "Sys.Audit"),
        ("/storage/local", "Datastore.Audit"),
        ("/storage/local", "Datastore.Allocate"),
        ("/vms/101", "VM.Audit"),
        ("/vms/101", "VM.Backup"),
    ],
)
async def test_nonpropagating_backup_grant_revoked_after_review_blocks_write(
    system, path, privilege
):
    c = system
    c.state.permissions = {p: dict.fromkeys(grants, 0) for p, grants in c.state.permissions.items()}
    body = await reviewed(c)
    c.state.permissions[path].pop(privilege)
    assert (await submit(c, body)).status == "failed"
    assert not c.state.writes

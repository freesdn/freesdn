# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real DB claims and adapter HTTP boundaries; no hardware mutations."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs
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
from app.modules.hypervisor.schemas import (
    ResizeDiskRequest,
    TemplateConversionRequest,
    UpdateConfigRequest,
)
from app.services import proxmox_task_tracking as tracking
from app.services.adapter_proxmox_vm import GatewayProxmoxVmService
from app.services.adapter_staging import AdapterStagingService
from app.services.hypervisor_guest_changes import validated_plan
from tests.adapters.test_proxmox_write_outcomes import UPID
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows

DIGEST = "a" * 40
BASE = 32 * 1024**3


@pytest.fixture
async def guest(power, monkeypatch):
    state = SimpleNamespace(
        config={
            "digest": DIGEST,
            "scsi0": "local:vm-101-disk-0,size=32G",
            "rootfs": "local:vm-101-disk-0,size=32G",
            "cores": 2,
            "memory": 512,
        },
        current=None,
        writes=[],
        mode="sync",
        task_status="stopped",
        task_exit="OK",
        entered=asyncio.Event(),
        release=asyncio.Event(),
    )

    async def dispatch(request):
        if request.method == "GET":
            if "/tasks/" in request.url.path:
                return httpx.Response(
                    200,
                    json={
                        "data": {
                            "upid": UPID,
                            "node": "pve1",
                            "status": state.task_status,
                            "exitstatus": state.task_exit,
                        }
                    },
                )
            if state.mode == "readback_failure" and state.writes:
                raise httpx.ConnectError("private-secret", request=request)
            current = request.url.params.get("current") == "1"
            return httpx.Response(
                200,
                json={
                    "data": state.current if current and state.current is not None else state.config
                },
            )
        body = parse_qs(request.content.decode(), keep_blank_values=True)
        state.writes.append((request.url.path, body))
        if state.mode == "hold":
            state.entered.set()
            await state.release.wait()
        if state.mode == "cancel":
            raise asyncio.CancelledError()
        if state.mode == "timeout":
            raise httpx.ReadTimeout("private-secret", request=request)
        if state.mode == "reject":
            return httpx.Response(400, json={"errors": "private-secret"})
        if state.mode != "no_effect":
            if request.url.path.endswith("/resize"):
                state.config[body["disk"][0]] = "local:vm-101-disk-0,size=" + body["size"][0]
            elif request.url.path.endswith("/template"):
                state.config["template"] = 1
            else:
                state.current = dict(state.config) if state.mode == "pending_restart" else None
                for key, value in body.items():
                    if key != "digest":
                        state.config[key] = value[0]
            state.config["digest"] = "b" * 40
        return httpx.Response(200, json={"data": UPID if state.mode == "task" else None})

    power.handler = dispatch
    power.guest = state
    monkeypatch.setattr(
        tracking, "build_proxmox_adapter", GatewayProxmoxVmService._get_proxmox_adapter
    )
    return power


async def submit(c, action="resize", vm_type="qemu", *, request_id=None, **options):
    common = {"request_id": request_id or c.request, "force": True, "expected_digest": DIGEST}
    if action == "resize":
        values = {
            "disk": "rootfs" if vm_type == "lxc" else "scsi0",
            "size": "+10G",
            "current_size_bytes": BASE,
        }
        model, handler = ResizeDiskRequest, api.resize_disk
    elif action == "config":
        values = {"cores": 4}
        model, handler = UpdateConfigRequest, api.update_config
    else:
        values = {"confirmed": True}
        model, handler = TemplateConversionRequest, api.convert_to_template
    body = model(**{**common, **values, **options})
    async with c.sessions() as db:
        return await handler(c.controller, body, "pve1", vm_type, 101, db, c.user)


@pytest.mark.parametrize("vm_type", ["qemu", "lxc"])
@pytest.mark.parametrize("action", ["resize", "config", "template"])
async def test_verified_receipt_survives_replay(guest, action, vm_type):
    first = await submit(guest, action, vm_type)
    replay = await submit(guest, action, vm_type)
    assert first.change_id == replay.change_id
    assert first.status == "applied" and first.provider_task.status == "succeeded"
    assert replay.provider_task.detail == "guest_state_verified"
    assert len(guest.guest.writes) == 1
    (row,) = await rows(guest)
    assert row.created_by == guest.user.id and row.payload["expected_digest"] == DIGEST
    if action == "resize":
        assert guest.guest.writes[0][1] == {
            "disk": ["rootfs" if vm_type == "lxc" else "scsi0"],
            "size": ["44040192K"],
            "digest": [DIGEST],
        }
        assert row.payload["target_size_bytes"] == 42 * 1024**3
    if action == "config":
        assert guest.guest.writes[0][1] == {"cores": ["4"], "digest": [DIGEST]}


@pytest.mark.parametrize("action", ["resize", "config", "template"])
async def test_reviewed_digest_is_checked_before_write(guest, action):
    guest.guest.config["digest"] = "c" * 40
    result = await submit(guest, action)
    assert result.status == "failed"
    assert not guest.guest.writes
    assert "changed since review" in (await rows(guest))[0].failure_reason


@pytest.mark.parametrize("action", ["resize", "config", "template"])
@pytest.mark.parametrize(
    "mode,expected",
    [
        ("timeout", "reconciliation_required"),
        ("reject", "failed"),
        ("no_effect", "reconciliation_required"),
        ("readback_failure", "reconciliation_required"),
    ],
)
async def test_rejection_and_uncertainty_are_not_replayed(guest, action, mode, expected):
    guest.guest.mode = mode
    first = await submit(guest, action)
    second = await submit(guest, action)
    assert first.status == second.status == expected
    assert len(guest.guest.writes) == 1
    assert "private-secret" not in first.model_dump_json()
    assert "private-secret" not in ((await rows(guest))[0].failure_reason or "")


@pytest.mark.parametrize("action", ["resize", "config", "template"])
async def test_provider_task_completion_requires_readback(guest, action):
    guest.guest.mode = "task"
    receipt = await submit(guest, action)
    assert receipt.provider_task.status == "pending"
    assert receipt.upid == UPID
    assert await tracking.poll_due_tasks() == {"polled": 1}
    (row,) = await rows(guest)
    assert row.provider_task["status"] == "succeeded"
    assert row.provider_task["detail"] == "guest_state_verified"
    assert len(guest.guest.writes) == 1


async def test_provider_ok_does_not_hide_failed_readback(guest):
    guest.guest.mode = "task"
    await submit(guest)
    guest.guest.mode = "readback_failure"
    await tracking.poll_due_tasks()
    (row,) = await rows(guest)
    assert row.provider_task["status"] == "unknown"
    assert row.provider_task_next_poll_at is not None


async def test_saved_config_is_pending_until_current_values_match(guest):
    guest.guest.mode = "pending_restart"
    receipt = await submit(guest, "config")
    assert receipt.provider_task.status == "pending"
    assert receipt.provider_task.detail == "configuration_pending_restart"
    guest.guest.current = None
    await tracking.poll_due_tasks()
    (row,) = await rows(guest)
    assert row.provider_task["status"] == "succeeded"
    assert len(guest.guest.writes) == 1


async def test_lxc_name_maps_to_hostname_and_balloon_is_rejected(guest):
    with pytest.raises(HTTPException):
        await submit(guest, "config", "lxc", balloon=512)
    assert not await rows(guest)
    result = await submit(guest, "config", "lxc", name="new-host")
    assert result.provider_task.status == "succeeded"
    assert guest.guest.writes[0][1] == {
        "hostname": ["new-host"],
        "cores": ["4"],
        "digest": [DIGEST],
    }


@pytest.mark.parametrize(
    "options",
    [
        {"disk": "rootfs"},
        {"disk": "efidisk0"},
        {"size": "-1G"},
        {"size": "31G"},
        {"size": "32G"},
        {"size": "99999999999999999T"},
        {"current_size_bytes": True},
        {"expected_digest": "bad"},
    ],
)
async def test_invalid_resize_is_refused_without_writing(guest, options):
    try:
        result = await submit(guest, **options)
        assert result.status == "failed"
    except (HTTPException, ValidationError):
        pass
    assert not guest.guest.writes


async def test_size_baseline_and_provider_lock_are_checked(guest):
    guest.guest.config["scsi0"] = "local:vm-101-disk-0,size=33G"
    assert (await submit(guest)).status == "failed"
    guest.guest.config["lock"] = "backup"
    assert (await submit(guest, "config", request_id=uuid4())).status == "failed"
    assert not guest.guest.writes


@pytest.mark.parametrize("action", ["resize", "config", "template"])
async def test_read_only_and_explicit_force_prevent_dispatch(guest, action, monkeypatch):
    with pytest.raises(HTTPException):
        await submit(guest, action, force=False)
    monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
    with pytest.raises(HTTPException):
        await submit(guest, action)
    assert not guest.calls and not await rows(guest)


async def test_template_requires_explicit_confirmation(guest):
    with pytest.raises(AdapterConfirmationRequiredError):
        await submit(guest, "template", confirmed=False)
    assert not guest.calls and not await rows(guest)


async def test_same_request_concurrency_and_different_request_conflict(guest):
    guest.guest.mode = "hold"
    first = asyncio.create_task(submit(guest))
    try:
        await asyncio.wait_for(guest.guest.entered.wait(), 5)
        replay = await asyncio.wait_for(submit(guest), 5)
        assert replay.status == "applying"
        with pytest.raises(HTTPException) as conflict:
            await asyncio.wait_for(submit(guest, "config", request_id=uuid4()), 5)
        assert conflict.value.status_code == 409
        guest.guest.release.set()
        assert (await first).status == "applied"
        assert len(guest.guest.writes) == 1
    finally:
        guest.guest.release.set()
        await first


async def test_unresolved_write_blocks_a_new_relative_resize(guest):
    guest.guest.mode = "timeout"
    await submit(guest)
    with pytest.raises(HTTPException) as exc:
        await submit(guest, request_id=uuid4())
    assert exc.value.status_code == 409 and len(guest.guest.writes) == 1


async def test_worker_death_keeps_claim_and_never_resizes_twice(guest):
    guest.guest.mode = "cancel"
    with pytest.raises(asyncio.CancelledError):
        await submit(guest)
    (row,) = await rows(guest)
    async with guest.sessions() as db:
        row = await db.get(AdapterPendingChange, row.id)
        row.updated_at = datetime.now(UTC) - timedelta(minutes=6)
        await db.commit()
        await AdapterStagingService(db)._recover_stale_applying()
    assert (await submit(guest)).status == "reconciliation_required"
    assert len(guest.guest.writes) == 1


async def test_reused_id_cannot_change_size_digest_or_configuration(guest):
    await submit(guest)
    for options in [
        {"size": "+11G"},
        {"expected_digest": "b" * 40},
        {"current_size_bytes": BASE + 1024},
    ]:
        with pytest.raises(HTTPException) as exc:
            await submit(guest, **options)
        assert exc.value.status_code == 409
    assert len(guest.guest.writes) == 1


@pytest.mark.parametrize("tamper", ["config", "target", "feature", "size", "node"])
async def test_generic_staging_cannot_smuggle_a_different_write(guest, tamper):
    await submit(guest, "config" if tamper == "config" else "resize")
    (row,) = await rows(guest)
    row.payload = dict(row.payload)
    if tamper == "config":
        row.payload["config"] = {"hookscript": "evil"}
    elif tamper == "target":
        row.target_id = "202"
    elif tamper == "feature":
        row.feature = "proxmox.vm.destroy"
    elif tamper == "size":
        row.payload["target_size_bytes"] += 1024
    else:
        row.payload["node"] = "../other"
    with pytest.raises(HTTPException):
        validated_plan(row)


@pytest.mark.parametrize("terminal", ["failed", "warnings"])
async def test_terminal_provider_result_allows_a_freshly_reviewed_intent(guest, terminal):
    guest.guest.mode = "task"
    receipt = await submit(guest)
    guest.guest.task_exit = "WARNINGS: 1" if terminal == "warnings" else "disk error"
    await tracking.poll_due_tasks()
    assert (await rows(guest))[0].provider_task["status"] == terminal
    # A replay never writes again, even after a terminal provider error.
    assert (await submit(guest)).change_id == receipt.change_id
    assert len(guest.guest.writes) == 1
    guest.guest.mode = "sync"
    fresh = await submit(
        guest, request_id=uuid4(), expected_digest="b" * 40, current_size_bytes=42 * 1024**3
    )
    assert fresh.provider_task.status == "succeeded"
    assert guest.guest.writes[-1][1]["size"] == ["54525952K"]


async def test_unknown_observation_requires_explicit_resolution_and_preserves_receipt(guest):
    guest.guest.mode = "task"
    first = await submit(guest)
    guest.guest.mode = "readback_failure"
    await tracking.poll_due_tasks()
    async with guest.sessions() as db:
        service = AdapterStagingService(db)
        with pytest.raises(HTTPException):
            await service.discard(first.change_id, organization_id=guest.org)
        await db.rollback()
        resolved = await service.discard(
            first.change_id, organization_id=guest.org, actor_id=guest.user.id, force=True
        )
        assert resolved.status == "discarded"
        assert resolved.applied_at is not None and resolved.applied_response
        assert resolved.provider_task["status"] == "unknown"
        assert resolved.provider_task["detail"] == "operator_resolved_unknown_outcome"
        assert resolved.provider_task_next_poll_at is None
    assert await tracking.poll_due_tasks() == {"polled": 0}
    assert (await submit(guest)).status == "discarded"
    guest.guest.mode = "sync"
    assert (
        await submit(guest, "config", request_id=uuid4(), expected_digest="b" * 40)
    ).provider_task.status == "succeeded"
    assert len(guest.guest.writes) == 2


async def test_active_task_cannot_be_resolved_or_overlapped(guest):
    guest.guest.mode = "task"
    first = await submit(guest)
    async with guest.sessions() as db:
        with pytest.raises(HTTPException) as exc:
            await AdapterStagingService(db).discard(
                first.change_id, organization_id=guest.org, force=True
            )
        assert exc.value.status_code == 409
    with pytest.raises(HTTPException) as exc:
        await submit(guest, "config", request_id=uuid4(), expected_digest="b" * 40)
    assert exc.value.status_code == 409
    assert len(guest.guest.writes) == 1


@pytest.mark.parametrize("options", [{"hookscript": "evil"}, {"confirmed": "true"}])
async def test_unknown_fields_and_non_boolean_confirmation_are_rejected(guest, options):
    with pytest.raises(ValidationError):
        await submit(guest, "template", **options)
    assert not guest.calls


@pytest.mark.parametrize("action", ["resize", "config", "template"])
@pytest.mark.parametrize("guard", ["accepted", "foreign_org", "site_grant", "scoped", "role"])
async def test_http_review_contract_and_authorization(guest, action, guard):
    app = FastAPI()
    app.include_router(api.router, prefix="/hypervisor")
    user = guest.user
    if guard != "accepted":
        user = CurrentUser(
            User(
                id=guest.user.id,
                organization_id=uuid4() if guard == "foreign_org" else guest.org,
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
        async with guest.sessions() as db:
            yield db

    app.dependency_overrides[get_current_active_user] = auth
    app.dependency_overrides[api.get_db] = session
    body = {
        "request_id": str(guest.request),
        "force": True,
        "expected_digest": DIGEST,
        **(
            {"disk": "scsi0", "size": "+10G", "current_size_bytes": BASE}
            if action == "resize"
            else {"cores": 4}
            if action == "config"
            else {"confirmed": True}
        ),
    }
    url = f"/hypervisor/controllers/{guest.controller}/nodes/pve1/qemu/101/{action}"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        method = client.post if action == "template" else client.put
        response = await method(url, json=body)
        if guard == "accepted":
            assert response.status_code == 202
            assert response.json()["provider_task"]["status"] == "succeeded"
            assert (await method(url, json=body)).json()["change_id"] == response.json()[
                "change_id"
            ]
            for required in ["request_id", "expected_digest"]:
                assert (
                    await method(url, json={k: v for k, v in body.items() if k != required})
                ).status_code == 422
            assert len(guest.guest.writes) == 1
        else:
            assert response.status_code in {403, 404}
            assert not guest.calls and not await rows(guest)


async def test_expired_pending_restart_can_be_manually_resolved(guest):
    guest.guest.mode = "pending_restart"
    receipt = await submit(guest, "config")
    async with guest.sessions() as db:
        row = await db.get(AdapterPendingChange, receipt.change_id)
        row.applied_at = datetime.now(UTC) - timedelta(days=8)
        await db.commit()
    await tracking.poll_due_tasks()
    (row,) = await rows(guest)
    assert row.provider_task["status"] == "unknown"
    assert row.provider_task["detail"] == "manual_verification_required"
    assert row.provider_task_next_poll_at is None
    async with guest.sessions() as db:
        assert (
            await AdapterStagingService(db).discard(
                row.id, organization_id=guest.org, actor_id=guest.user.id, force=True
            )
        ).status == "discarded"
    assert len(guest.guest.writes) == 1

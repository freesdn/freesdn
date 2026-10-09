# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Recovery intent claims, confirmations and provider wire behavior on real PostgreSQL."""

import asyncio
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from app.adapters.exceptions import AdapterConfirmationRequiredError
from app.api.v1.endpoints import adapter_omada_vpn as apply_api
from app.api.v1.endpoints import adapter_proxmox_backup as backup_api
from app.core.dependencies import get_current_active_user
from app.core.site_access import current_user_var
from app.models.core import Controller, Site
from app.models.staging import AdapterPendingChange
from app.modules.hypervisor import api
from app.modules.hypervisor.schemas import (
    BackupRunRequest,
    HypervisorIntentRequest,
    SnapshotCreateRequest,
)
from app.schemas.gateway_vpn import ApplyPendingChangeRequest
from app.services.adapter_proxmox_backup import GatewayProxmoxBackupService, _validate_archive
from app.services.adapter_proxmox_snapshot import GatewayProxmoxSnapshotService
from app.services.adapter_proxmox_vm import GatewayProxmoxVmService
from app.services.adapter_staging import AdapterStagingService
from tests.adapters.test_proxmox_write_outcomes import UPID
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows
from tests.services.test_hypervisor_power import submit as submit_power


@pytest.fixture
async def recovery(power, monkeypatch):
    builder = GatewayProxmoxVmService._get_proxmox_adapter
    monkeypatch.setattr(
        GatewayProxmoxSnapshotService, "_get_proxmox_adapter", staticmethod(builder)
    )
    monkeypatch.setattr(GatewayProxmoxBackupService, "_build_adapter", staticmethod(builder))
    return power


async def submit(
    c,
    action="create",
    vm_type="qemu",
    *,
    request_id=None,
    confirmed=True,
    snapname="safe",
    **options,
):
    intent = {"request_id": request_id or c.request, "force": True}
    if "force" in options:
        intent["force"] = options.pop("force")
    async with c.sessions() as db:
        common = {
            "node": "pve1",
            "vm_type": vm_type,
            "vmid": 101,
            "session": db,
            "current_user": c.user,
        }
        if action == "backup":
            return await api.run_backup(
                c.controller,
                BackupRunRequest(**intent, **{"storage": "local", **options}),
                **common,
            )
        if action == "create":
            return await api.create_snapshot(
                c.controller,
                SnapshotCreateRequest(**intent, snapname=snapname, **options),
                **common,
            )
        if action == "rollback":
            return await api.rollback_snapshot(
                c.controller,
                HypervisorIntentRequest(**intent),
                snapname=snapname,
                confirmed=confirmed,
                **common,
            )
        return await api.delete_snapshot(
            c.controller, snapname=snapname, confirmed=confirmed, **intent, **common
        )


async def stage_restore(c, vm_type="qemu", *, request_id=None, **options):
    payload = {
        "node": "pve1",
        "vm_type": vm_type,
        "vmid": 202,
        "archive": "pbs:backup/"
        + ("ct" if vm_type == "lxc" else "vm")
        + "/101/2026-09-16T03:04:05Z",
        **options,
    }
    async with c.sessions() as db:
        return await backup_api.stage_proxmox_backup_change(
            c.controller,
            "proxmox.backup.restore",
            "create",
            backup_api.ProxmoxBackupChangeRequest(
                request_id=request_id or c.request, payload=payload, target_id=str(payload["vmid"])
            ),
            c.user,
            db,
        )


async def apply_restore(c, change_id, *, confirmed=True, force=True):
    async with c.sessions() as db:
        return await apply_api.apply_change(
            change_id, ApplyPendingChangeRequest(force=force, confirmed=confirmed), c.user, db
        )


@pytest.mark.parametrize("action", ["create", "rollback", "delete", "backup"])
@pytest.mark.parametrize("vm_type", ["qemu", "lxc"])
async def test_recovery_operations_have_durable_receipts_and_one_write(recovery, action, vm_type):
    first = await submit(recovery, action, vm_type)
    replay = await submit(recovery, action, vm_type)
    assert first.status == replay.status == "applied"
    assert first.change_id == replay.change_id
    assert first.provider_task.status == "pending" and first.provider_task.id == UPID
    assert len([m for m, _ in recovery.calls if m in {"POST", "DELETE"}]) == 1
    (row,) = await rows(recovery)
    assert row.created_by == recovery.user.id and row.site_id == recovery.site
    assert row.payload["vm_type"] == vm_type and "confirmed" not in row.payload
    assert row.operation == ("delete" if action == "delete" else "create")
    assert row.target_id == ("101" if action == "backup" else "safe")


@pytest.mark.parametrize(
    "action,options,expected_path,expected_body",
    [
        (
            "create",
            {"description": "before upgrade", "vmstate": True},
            "/nodes/pve1/qemu/101/snapshot",
            {"snapname": ["safe"], "description": ["before upgrade"], "vmstate": ["1"]},
        ),
        (
            "backup",
            {"mode": "stop", "compress": "gzip"},
            "/nodes/pve1/vzdump",
            {"vmid": ["101"], "storage": ["local"], "mode": ["stop"], "compress": ["gzip"]},
        ),
        ("rollback", {}, "/nodes/pve1/qemu/101/snapshot/safe/rollback", {}),
        ("delete", {}, "/nodes/pve1/qemu/101/snapshot/safe", {}),
    ],
)
async def test_recovery_wire_paths_preserve_options_and_do_not_leak_apply_flags(
    recovery, action, options, expected_path, expected_body
):
    seen = []

    async def handler(request):
        seen.append((request.url.path, parse_qs(request.content.decode())))
        return httpx.Response(200, json={"data": UPID})

    recovery.handler = handler
    assert (await submit(recovery, action, **options)).status == "applied"
    assert seen == [(expected_path, expected_body)]


@pytest.mark.parametrize("action", ["rollback", "delete"])
async def test_destructive_confirmation_is_independent_of_force(recovery, action):
    with pytest.raises(AdapterConfirmationRequiredError):
        await submit(recovery, action, confirmed=False)
    with pytest.raises(HTTPException) as exc:
        await submit(recovery, action, force=False)
    assert exc.value.status_code == 403
    assert not recovery.calls and not await rows(recovery)


@pytest.mark.parametrize("action", ["create", "rollback", "delete", "backup"])
@pytest.mark.parametrize(
    "failure,expected",
    [("timeout", "reconciliation_required"), ("reject", "failed"), ("missing_task", "applied")],
)
async def test_provider_failures_and_missing_handles_are_not_replayed(
    recovery, action, failure, expected
):
    async def handler(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("private provider details", request=request)
        return httpx.Response(403 if failure == "reject" else 200, json={"data": None})

    recovery.handler = handler
    first, replay = await submit(recovery, action), await submit(recovery, action)
    assert first.status == replay.status == expected
    assert (
        first.change_id == replay.change_id
        and "private provider details" not in first.model_dump_json()
    )
    if failure == "missing_task":
        assert replay.provider_task.status == "unknown"
    assert len(recovery.calls) == 1


@pytest.mark.parametrize("action", ["create", "rollback", "delete", "backup"])
async def test_concurrent_recovery_submissions_share_one_claim(recovery, action):
    entered, release = asyncio.Event(), asyncio.Event()

    async def hold(_):
        entered.set()
        await release.wait()
        return httpx.Response(200, json={"data": UPID})

    recovery.handler = hold
    first = asyncio.create_task(submit(recovery, action))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        others = await asyncio.wait_for(
            asyncio.gather(*(submit(recovery, action) for _ in range(3))), 5
        )
        assert all(r.status == "applying" for r in others)
        release.set()
        final = await first
        assert all(r.change_id == final.change_id for r in others)
        assert len(recovery.calls) == 1
    finally:
        release.set()
        await first


@pytest.mark.parametrize("action", ["create", "rollback", "delete", "backup"])
async def test_interrupted_recovery_stays_uncertain_after_restart(recovery, action):
    async def interrupted(_):
        raise asyncio.CancelledError()

    recovery.handler = interrupted
    with pytest.raises(asyncio.CancelledError):
        await submit(recovery, action)
    (row,) = await rows(recovery)
    assert row.status == "applying"
    async with recovery.sessions() as db:
        stale = await db.get(AdapterPendingChange, row.id)
        stale.updated_at = datetime.now(UTC) - timedelta(minutes=6)
        await db.commit()
        await AdapterStagingService(db)._recover_stale_applying(recovery.org)
    assert (await submit(recovery, action)).status == "reconciliation_required"
    assert len(recovery.calls) == 1


@pytest.mark.parametrize(
    "action,options",
    [
        ("create", {"snapname": "changed"}),
        ("create", {"vmstate": True}),
        ("create", {"description": "changed"}),
        ("backup", {"storage": "different"}),
        ("backup", {"mode": "stop"}),
        ("backup", {"compress": "gzip"}),
    ],
)
async def test_recovery_intent_is_bound_to_all_options(recovery, action, options):
    await submit(recovery, action)
    with pytest.raises(HTTPException) as exc:
        await submit(recovery, action, **options)
    assert exc.value.status_code == 409 and len(recovery.calls) == 1


async def test_recovery_cannot_reuse_a_power_request_id(recovery):
    await submit_power(recovery)
    with pytest.raises(HTTPException) as exc:
        await submit(recovery)
    assert exc.value.status_code == 409 and len(recovery.calls) == 1


@pytest.mark.parametrize("action", ["create", "backup", "restore"])
@pytest.mark.parametrize("failure", ["error", "timeout"])
async def test_disconnect_failure_preserves_provider_acknowledgement(recovery, action, failure):
    recovery.disconnect_failure = failure
    if action == "restore":
        record = await stage_restore(recovery)
        first = await apply_restore(recovery, record.id)
        replay = await stage_restore(recovery)
        assert first.id == replay.id
    else:
        first, replay = await submit(recovery, action), await submit(recovery, action)
    assert first.status == replay.status == "applied"
    assert first.provider_task.id == UPID and len(recovery.calls) == 1


@pytest.mark.parametrize("action", ["create", "backup", "restore"])
async def test_disconnect_failure_cannot_mask_a_lost_acknowledgement(recovery, action):
    recovery.disconnect_failure = "error"

    async def lost(request):
        raise httpx.ReadTimeout("private response", request=request)

    recovery.handler = lost
    if action == "restore":
        record = await stage_restore(recovery)
        with pytest.raises(HTTPException):
            await apply_restore(recovery, record.id)
        replay = await stage_restore(recovery)
    else:
        await submit(recovery, action)
        replay = await submit(recovery, action)
    assert replay.status == "reconciliation_required" and len(recovery.calls) == 1


@pytest.mark.parametrize("vm_type", ["qemu", "lxc"])
async def test_restore_is_stage_only_and_replay_safe_before_and_after_confirmed_apply(
    recovery, vm_type, monkeypatch
):
    monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
    first, replay = await stage_restore(recovery, vm_type), await stage_restore(recovery, vm_type)
    assert first.id == replay.id and first.status == "pending" and not recovery.calls
    with pytest.raises(HTTPException) as exc:
        await apply_restore(recovery, first.id)
    assert exc.value.status_code == 403
    monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: False))
    with pytest.raises(HTTPException) as exc:
        await apply_restore(recovery, first.id, confirmed=False)
    assert exc.value.status_code == 409 and not recovery.calls
    result = await apply_restore(recovery, first.id)
    assert result.status == "applied" and result.provider_task.status == "pending"
    with pytest.raises(HTTPException) as exc:
        await apply_restore(recovery, first.id)
    assert exc.value.status_code == 409
    assert (await stage_restore(recovery, vm_type)).id == first.id
    assert len(recovery.calls) == 1 and "confirmed" not in (await rows(recovery))[0].payload


async def test_concurrent_restore_staging_keeps_one_pending_record(recovery):
    results = await asyncio.gather(*(stage_restore(recovery) for _ in range(5)))
    assert len({r.id for r in results}) == 1
    assert len(await rows(recovery)) == 1 and not recovery.calls


@pytest.mark.parametrize(
    "options",
    [
        {"vmid": 203},
        {"start": True},
        {"unique": False},
        {"storage": "local-lvm"},
        {"archive": "local:backup/other.vma.zst"},
    ],
)
async def test_restore_intent_cannot_change_payload_on_replay(recovery, options):
    await stage_restore(recovery)
    with pytest.raises(HTTPException) as exc:
        await stage_restore(recovery, **options)
    assert exc.value.status_code == 409 and not recovery.calls


@pytest.mark.parametrize("field", ["is_active", "sync_enabled", "site", "ownership"])
async def test_restore_target_is_rechecked_after_review(recovery, field):
    staged = await stage_restore(recovery)
    async with recovery.sessions() as db:
        ctrl = await db.get(Controller, recovery.controller)
        if field == "site":
            site = await db.get(Site, recovery.site)
            site.is_active = False
        elif field == "ownership":
            site = Site(id=uuid4(), name="Moved", slug=str(uuid4()), organization_id=recovery.org)
            db.add(site)
            await db.flush()
            ctrl.site_id = site.id
        else:
            setattr(ctrl, field, False)
        await db.commit()
    with pytest.raises(HTTPException):
        await apply_restore(recovery, staged.id)
    assert not recovery.calls


@pytest.mark.parametrize(
    "payload",
    [
        {"start": "false"},
        {"unique": "false"},
        {"force": True},
        {"confirmed": True},
        {"archive": "local:backup/../../etc/shadow"},
        {"archive": "https://example.invalid/a"},
    ],
)
async def test_unsafe_restore_inputs_do_not_create_an_intent(recovery, payload):
    with pytest.raises(HTTPException) as exc:
        await stage_restore(recovery, **payload)
    assert exc.value.status_code in {400, 422}
    assert not recovery.calls and not await rows(recovery)


@pytest.mark.parametrize(
    "archive",
    [
        "pbs:backup/vm/101/2026-09-16T03:04:05Z",
        "pbs:backup/ct/101/2026-09-16T03:04:05Z",
        "local:backup/vzdump-qemu-101.vma.zst",
    ],
)
def test_documented_pbs_and_file_archives_are_accepted(archive):
    assert _validate_archive(archive) == archive


@pytest.mark.parametrize(
    "archive",
    [
        "pbs:backup/vm/101/2026-99-16T03:04:05Z",
        "pbs:backup/vm/101/2026-09-16T03:04:05Z/../../etc/shadow",
        "pbs:backup/vm/101/2026-09-16T03:04:05Z\n",
        "pbs:backup/vm/101/2026-09-16T03%3A04%3A05Z",
        "local:backup/file\n",
        "local:backup/./file",
        "local:backup//file",
        "http://host/file",
    ],
)
def test_archive_allowlist_still_blocks_traversal_encoding_and_noncanonical_values(archive):
    with pytest.raises(HTTPException):
        _validate_archive(archive)


async def test_http_contract_requires_ids_force_and_returns_typed_receipts(recovery, monkeypatch):
    app = FastAPI()
    app.include_router(api.router, prefix="/hypervisor")

    async def auth():
        token = current_user_var.set(recovery.user)
        try:
            yield recovery.user
        finally:
            current_user_var.reset(token)

    async def session():
        async with recovery.sessions() as db:
            yield db

    app.dependency_overrides[get_current_active_user] = auth
    app.dependency_overrides[api.get_db] = session
    base = f"/hypervisor/controllers/{recovery.controller}/nodes/pve1/qemu/101"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        for suffix, extra in [
            ("snapshots", {"snapname": "safe"}),
            ("backup", {"storage": "local"}),
        ]:
            assert (await client.post(base + "/" + suffix, json=extra)).status_code == 422
            body = {**extra, "request_id": str(uuid4())}
            assert (await client.post(base + "/" + suffix, json=body)).status_code == 403
            body["force"] = True
            first = await client.post(base + "/" + suffix, json=body)
            assert first.status_code == 202 and first.json()["provider_task"]["status"] == "pending"
            replay = await client.post(base + "/" + suffix, json=body)
            assert replay.json()["change_id"] == first.json()["change_id"]
    assert len(recovery.calls) == 2


@pytest.mark.parametrize("confirmed", [False, True])
async def test_confirmation_view_never_changes_durable_payload_or_reaches_other_vendors(
    recovery, confirmed
):
    seen = []
    for feature in ["proxmox.backup.run", "unifi.network"]:
        async with recovery.sessions() as db:
            staging = AdapterStagingService(db)
            record = await staging.stage_change(
                organization_id=recovery.org,
                controller_id=recovery.controller,
                site_id=recovery.site,
                feature=feature,
                operation="create",
                target_id="101",
                payload={"node": "pve1", "vmid": 101, "confirmed": not confirmed},
                actor_id=recovery.user.id,
            )

            async def inspect(change):
                seen.append(dict(change.payload))
                if change.feature.startswith("proxmox."):
                    change.payload["node"] = "applier-local-change"
                return {"success": True}

            result = await staging.apply_change(
                record.id,
                force=True,
                confirmed=confirmed,
                applier=inspect,
                actor_id=recovery.user.id,
            )
            assert result.status == "applied"
            await db.refresh(record)
            assert record.payload == {"node": "pve1", "vmid": 101}
    assert seen[0] == {"node": "pve1", "vmid": 101, "confirmed": confirmed}
    assert seen[1] == {"node": "pve1", "vmid": 101}

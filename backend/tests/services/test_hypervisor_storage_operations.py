# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real PostgreSQL claims and files with native HTTP contracts; no hardware writes."""

import asyncio
import hashlib
import io
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException, UploadFile

from app.core.config import settings
from app.modules.hypervisor.schemas import StorageOperationRequest, StorageReviewRequest
from app.services import hypervisor_storage_operations as storage
from app.services import hypervisor_upload_blobs as blobs
from app.services import proxmox_task_tracking as tracking
from tests.adapters.test_proxmox_write_outcomes import connected
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows

DELETE_UPID = "UPID:pve1:00001234:00ABCDEF:00000000:imgdel:local:root@pam!audit:"
UPLOAD_UPID = "UPID:pve1:00001234:00ABCDEF:00000000:imgcopy::root@pam!audit:"
PAYLOAD = b"fixture ISO bytes"


@pytest.fixture
async def system(power, monkeypatch, tmp_path):
    c = power
    monkeypatch.setattr(settings, "PROXMOX_UPLOAD_DIR", str(tmp_path))
    c.state = SimpleNamespace(
        config={
            "storage": "local",
            "type": "dir",
            "path": "/var/lib/vz",
            "content": "iso,vztmpl,backup",
        },
        status={"active": 1, "enabled": 1, "avail": 1000000},
        permissions={
            "/storage/local": {
                "Datastore.Audit": 1,
                "Datastore.Allocate": 1,
                "Datastore.AllocateTemplate": 1,
            },
            "/": {"VM.Audit": 1},
        },
        content=[{"volid": "local:iso/old.iso", "format": "iso", "size": 1024}],
        guests=[],
        configs={"digest": "a" * 40},
        snapshots=[],
        writes=[],
        mode="accepted",
        exitstatus="OK",
        unavailable=None,
        bad_task=False,
        upid=None,
        entered=asyncio.Event(),
        release=asyncio.Event(),
    )

    async def dispatch(request):
        s = c.state
        c.calls.append((request.method, request.url.path))
        path = request.url.path
        if request.method != "GET":
            s.writes.append(request)
            s.entered.set()
            if s.mode == "wait":
                await s.release.wait()
            if s.mode == "timeout":
                raise httpx.ReadTimeout("private diagnostic", request=request)
            if s.mode == "reject":
                return httpx.Response(403, json={"errors": {"secret": "private diagnostic"}})
            if s.mode == "bad_ack":
                return httpx.Response(200, json={"data": None})
            upload = request.method == "POST"
            s.upid = UPLOAD_UPID if upload else DELETE_UPID
            if s.bad_task:
                s.upid = s.upid.replace("pve1", "other")
            if s.mode != "unchanged":
                s.content.append(
                    {"volid": "local:iso/new.iso", "format": "iso", "size": len(PAYLOAD)}
                ) if upload else s.content.clear()
            return httpx.Response(200, json={"data": s.upid})
        if path == s.unavailable:
            return httpx.Response(403, json={"errors": {"secret": "private diagnostic"}})
        if "/tasks/" in path:
            return httpx.Response(
                200,
                json={
                    "data": {
                        "upid": s.upid,
                        "node": "pve1",
                        "status": "stopped",
                        "exitstatus": s.exitstatus,
                    }
                },
            )
        if path.endswith("/config") and "/qemu/" in path:
            return httpx.Response(200, json={"data": s.configs})
        if path.endswith("/snapshot"):
            return httpx.Response(200, json={"data": s.snapshots})
        values = {
            "/cluster/status": [{"type": "node", "name": "pve1", "local": 1, "online": 1}],
            "/storage/local": s.config,
            "/nodes/pve1/storage/local/status": s.status,
            "/nodes/pve1/storage/local/content": s.content,
            "/access/permissions": {
                request.url.params["path"]: s.permissions[request.url.params["path"]]
            }
            if request.url.params.get("path") in s.permissions
            else {},
            "/cluster/resources": s.guests,
        }
        assert path in values, path
        return httpx.Response(200, json={"data": values[path]})

    async def builder(_):
        return connected(dispatch)[0]

    c.builder = builder
    monkeypatch.setattr(storage, "build_proxmox_adapter", builder)
    monkeypatch.setattr(tracking, "build_proxmox_adapter", builder)
    yield c


def options(action="delete", **extra):
    return StorageReviewRequest(
        action=action,
        **(
            {"volume": "local:iso/old.iso"}
            if action == "delete"
            else {"filename": "new.iso", "content": "iso", "size": len(PAYLOAD)}
        ),
        **extra,
    )


async def reviewed(c, action="delete"):
    body = options(action)
    async with c.sessions() as db:
        review = await storage.HypervisorStorageOperationService(db, c.user).review(
            c.controller, "pve1", "local", body
        )
    return StorageOperationRequest(
        **body.model_dump(),
        expected_digest=review["expected_digest"],
        request_id=c.request,
        force=True,
        confirmed=True,
    )


async def submit(c, body, data=PAYLOAD):
    async with c.sessions() as db:
        return await storage.HypervisorStorageOperationService(db, c.user).submit(
            c.controller,
            "pve1",
            "local",
            body,
            UploadFile(filename=body.filename, file=io.BytesIO(data))
            if body.action == "upload"
            else None,
        )


@pytest.mark.parametrize("action", storage.ACTIONS)
async def test_replay_and_independent_readback(system, action):
    c = system
    body = await reviewed(c, action)
    receipt = await submit(c, body)
    assert receipt.status == "applied" and receipt.provider_task.status == "pending"
    assert (await submit(c, body)).change_id == receipt.change_id
    assert len(c.state.writes) == 1 and len(await rows(c)) == 1
    if action == "upload":
        wire = c.state.writes[0].content
        assert (
            hashlib.sha256(PAYLOAD).hexdigest().encode() in wire
            and b"sha256" in wire
            and PAYLOAD in wire
        )
        assert not list(blobs._root().glob("*.blob"))
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "succeeded"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("action", storage.ACTIONS)
@pytest.mark.parametrize(
    "mode,expected",
    [
        ("timeout", "reconciliation_required"),
        ("bad_ack", "reconciliation_required"),
        ("reject", "failed"),
    ],
)
async def test_uncertain_and_rejected_writes_never_replay(system, action, mode, expected):
    c = system
    body = await reviewed(c, action)
    c.state.mode = mode
    result = await submit(c, body)
    assert result.status == expected
    assert (await submit(c, body)).change_id == result.change_id and len(c.state.writes) == 1
    assert "private diagnostic" not in result.model_dump_json()


@pytest.mark.parametrize("action", storage.ACTIONS)
@pytest.mark.parametrize(
    "fault",
    ["unchanged", "failed_task", "bad_task", "changed_storage", "missing_inventory", "wrong_size"],
)
async def test_no_false_completion(system, action, fault):
    c = system
    body = await reviewed(c, action)
    if fault == "unchanged":
        c.state.mode = "unchanged"
    if fault == "bad_task":
        c.state.bad_task = True
    result = await submit(c, body)
    if fault == "failed_task":
        c.state.exitstatus = "ERROR: private diagnostic"
    if fault == "changed_storage":
        c.state.config["path"] = "/different"
    if fault == "missing_inventory":
        c.state.content = None
    if fault == "wrong_size":
        c.state.content = [{"volid": body.volume or "local:iso/new.iso", "size": 999}]
    await tracking.poll_due_tasks()
    saved = (await rows(c))[0]
    assert saved.status == "reconciliation_required" or saved.provider_task["status"] == "unknown"
    assert len(c.state.writes) == 1
    assert result.change_id == saved.id


@pytest.mark.parametrize(
    "fault",
    [
        "path",
        "protected",
        "size",
        "content",
        "duplicate",
        "unavailable",
        "permission",
        "inactive",
        "reference",
    ],
)
async def test_stale_review_or_unavailable_state_refuses_dispatch(system, fault):
    c = system
    body = await reviewed(c)
    if fault == "path":
        c.state.config["path"] = "/elsewhere"
    if fault == "protected":
        c.state.content[0]["protected"] = 1
    if fault == "size":
        c.state.content[0]["size"] = 2048
    if fault == "content":
        c.state.content = {}
    if fault == "duplicate":
        c.state.content *= 2
    if fault == "unavailable":
        c.state.unavailable = "/storage/local"
    if fault == "permission":
        c.state.permissions = {}
    if fault == "inactive":
        c.state.status["active"] = 0
    if fault == "reference":
        c.state.guests = [{"vmid": 101, "node": "pve1", "type": "qemu"}]
        c.state.configs["ide2"] = "local:iso/old.iso,media=cdrom"
    with pytest.raises(HTTPException):
        await submit(c, body)
    assert not c.state.writes


@pytest.mark.parametrize(
    "volume",
    [
        "other:iso/x.iso",
        "local-lvm:vm-100-disk-0",
        "local:iso/../x.iso",
        "local:iso//x.iso",
        "local:iso/x.iso?delete=1",
        "local:rootdir/subvol-100-disk-0",
    ],
)
async def test_invalid_or_guest_disk_target_never_reads(system, volume):
    c = system
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await storage.HypervisorStorageOperationService(db, c.user).review(
                c.controller, "pve1", "local", StorageReviewRequest(action="delete", volume=volume)
            )
    assert not c.calls


@pytest.mark.parametrize(
    "filename", ["../x.iso", "foo..iso", "x.ISO", "x.img", "file name.iso", "x.iso\n", "a.tar.gz"]
)
async def test_upload_filename_policy(system, filename):
    c = system
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await storage.HypervisorStorageOperationService(db, c.user).review(
                c.controller,
                "pve1",
                "local",
                StorageReviewRequest(action="upload", filename=filename, size=12),
            )
    assert not c.calls


async def test_upload_never_overwrites_existing_file(system):
    c = system
    c.state.content.append({"volid": "local:iso/new.iso", "size": 1, "format": "iso"})
    with pytest.raises(HTTPException, match="overwrite"):
        await reviewed(c, "upload")
    assert not c.state.writes


@pytest.mark.parametrize("data", [b"", b"x" * (len(PAYLOAD) + 1)])
async def test_upload_size_mismatch_leaves_no_source_or_write(system, data):
    c = system
    body = await reviewed(c, "upload")
    with pytest.raises(HTTPException):
        await submit(c, body, data)
    assert not c.state.writes and not list(blobs._root().iterdir())


async def test_replay_different_bytes_conflicts(system):
    c = system
    body = await reviewed(c, "upload")
    await submit(c, body)
    with pytest.raises(HTTPException) as error:
        await submit(c, body, b"x" * len(PAYLOAD))
    assert error.value.status_code == 409 and len(c.state.writes) == 1


@pytest.mark.parametrize("attack", ["symlink", "hardlink", "changed", "mode", "missing"])
async def test_changed_source_never_uploads(system, attack, tmp_path):
    c = system
    identifier = uuid4()
    checksum = await blobs.spool(
        UploadFile(filename="new.iso", file=io.BytesIO(PAYLOAD)), identifier, len(PAYLOAD)
    )
    path = blobs._path(identifier, checksum)
    if attack == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "outside")
    if attack == "hardlink":
        import os

        os.link(path, tmp_path / "another")
    if attack == "changed":
        path.write_bytes(b"x" * len(PAYLOAD))
    if attack == "mode":
        path.chmod(0o644)
    if attack == "missing":
        path.unlink()
    with pytest.raises(HTTPException):
        blobs.open_verified(identifier, checksum, len(PAYLOAD))
    assert not c.state.writes


@pytest.mark.parametrize("action", storage.ACTIONS)
async def test_read_only_and_confirmation_before_device_reads(system, action):
    c = system
    body = await reviewed(c, action)
    c.calls.clear()
    with pytest.raises(HTTPException):
        await submit(c, body.model_copy(update={"force": False}))
    with pytest.raises(HTTPException):
        await submit(c, body.model_copy(update={"confirmed": False}))
    assert not c.calls


async def test_legacy_staging_cannot_persist_server_file_path(system):
    from app.services.adapter_staging import AdapterStagingService

    c = system
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await AdapterStagingService(db).stage_change(
                organization_id=c.org,
                controller_id=c.controller,
                site_id=c.site,
                feature="proxmox.storage.upload",
                operation="create",
                payload={
                    "node": "pve1",
                    "storage": "local",
                    "filename": "new.iso",
                    "content_type": "iso",
                    "file_path": "/etc/passwd",
                },
                actor_id=c.user.id,
            )
    assert not await rows(c) and not c.calls


@pytest.mark.parametrize("action", storage.ACTIONS)
async def test_concurrent_request_claim_dispatches_once(system, action):
    c = system
    body = await reviewed(c, action)
    c.state.mode = "wait"
    first = asyncio.create_task(submit(c, body))
    await asyncio.wait_for(c.state.entered.wait(), 5)
    second = asyncio.create_task(submit(c, body))
    await asyncio.sleep(0.05)
    c.state.release.set()
    results = await asyncio.gather(first, second)
    assert results[0].change_id == results[1].change_id
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("action", storage.ACTIONS)
async def test_cancelled_dispatch_is_never_replayed(system, action):
    c = system
    body = await reviewed(c, action)
    c.state.mode = "wait"
    task = asyncio.create_task(submit(c, body))
    await asyncio.wait_for(c.state.entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    again = await submit(c, body)
    assert again.status in {"applying", "reconciliation_required"}
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("field", ["filename", "expected_digest", "size", "request_id"])
async def test_frozen_request_rejects_changed_identity(system, field):
    c = system
    body = await reviewed(c, "upload")
    await submit(c, body)
    values = {
        "filename": "another.iso",
        "expected_digest": "b" * 64,
        "size": len(PAYLOAD) - 1,
        "request_id": uuid4(),
    }
    with pytest.raises(HTTPException):
        await submit(c, body.model_copy(update={field: values[field]}))
    assert len(c.state.writes) == 1


async def test_pending_blob_survives_service_restart_and_generic_apply(system):
    from uuid import uuid5

    from app.services.adapter_proxmox_storage import GatewayProxmoxStorageService
    from app.services.adapter_staging import AdapterStagingService
    from app.services.hypervisor_operations import _REQUEST_NAMESPACE

    c = system
    body = await reviewed(c, "upload")
    identifier = uuid5(_REQUEST_NAMESPACE, f"{c.org}:{c.user.id}:{body.request_id}")
    checksum = await blobs.spool(
        UploadFile(filename=body.filename, file=io.BytesIO(PAYLOAD)), identifier, body.size
    )
    async with c.sessions() as db:
        service = storage.HypervisorStorageOperationService(db, c.user)
        review = await service.review(c.controller, "pve1", "local", body)
        plan = {
            "storage_version": 1,
            "node": "pve1",
            "storage": "local",
            "options": body.model_dump(exclude=storage.CONTROL),
            "expected_digest": body.expected_digest,
            "baseline": review["snapshot"],
            "checksum": checksum,
        }
        change = await service.ops._record(
            c.controller,
            body.request_id,
            storage.ACTIONS["upload"][0],
            "create",
            storage._digest({"node": "pve1", "storage": "local", "volume": "local:iso/new.iso"}),
            plan,
        )
        identifier = change.id
    async with c.sessions() as db:
        domain = GatewayProxmoxStorageService(db)
        change = await AdapterStagingService(db).apply_change(
            identifier,
            force=True,
            confirmed=True,
            actor_id=c.user.id,
            applier=domain.build_applier(None),
        )
        assert change.status == "applied"
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "succeeded"
    assert len(c.state.writes) == 1


async def test_stale_review_rechecked_after_durable_claim(system, monkeypatch):
    from app.services.hypervisor_operations import HypervisorOperationService

    c = system
    body = await reviewed(c)
    original = HypervisorOperationService._record

    async def changed(self, *args, **kwargs):
        record = await original(self, *args, **kwargs)
        c.state.config["path"] = "/different"
        return record

    monkeypatch.setattr(HypervisorOperationService, "_record", changed)
    result = await submit(c, body)
    assert result.status == "failed" and not c.state.writes


@pytest.mark.parametrize("inactive", ["controller", "site"])
async def test_inactive_ownership_after_claim_uses_no_credentials(system, monkeypatch, inactive):
    from app.models.core import Controller, Site
    from app.services.hypervisor_operations import HypervisorOperationService

    c = system
    body = await reviewed(c)
    original = HypervisorOperationService._record

    async def changed(self, *args, **kwargs):
        record = await original(self, *args, **kwargs)
        row = await self.db.get(
            Controller if inactive == "controller" else Site,
            c.controller if inactive == "controller" else c.site,
        )
        row.is_active = False
        await self.db.commit()
        c.calls.clear()
        return record

    monkeypatch.setattr(HypervisorOperationService, "_record", changed)
    result = await submit(c, body)
    assert result.status == "failed" and not c.calls


async def test_native_backup_task_owner_is_accepted_only_for_reviewed_owner(system):
    c = system
    body = await reviewed(c)
    await submit(c, body)
    plan = (await rows(c))[0].payload
    plan["baseline"]["owner"] = 101
    assert storage.matches_task(DELETE_UPID.replace(":local:", ":101@local:"), plan)
    assert not storage.matches_task(DELETE_UPID.replace(":local:", ":102@local:"), plan)


async def test_upload_task_runs_at_connected_endpoint_not_destination(system):
    c = system
    body = await reviewed(c, "upload")
    await submit(c, body)
    plan = (await rows(c))[0].payload
    plan["node"] = "destination"
    assert storage.matches_task(UPLOAD_UPID, plan)
    assert not storage.matches_task(UPLOAD_UPID.replace("pve1", "destination"), plan)


async def test_http_multipart_contract_keeps_content_task_and_receipt(system):
    from fastapi import FastAPI

    from app.core.dependencies import get_current_active_user
    from app.core.middleware import setup_exception_handlers
    from app.modules.hypervisor import api

    c = system
    body = await reviewed(c, "upload")
    app = FastAPI()
    app.include_router(api.router, prefix="/hypervisor")
    setup_exception_handlers(app)

    async def db():
        async with c.sessions() as session:
            yield session

    app.dependency_overrides[api.get_db] = db
    app.dependency_overrides[get_current_active_user] = lambda: c.user
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            f"/hypervisor/controllers/{c.controller}/nodes/pve1/storage/local/upload",
            data={
                k: str(v).lower() if isinstance(v, bool) else str(v)
                for k, v in body.model_dump().items()
                if k not in {"action", "filename", "volume"}
            },
            files={"file": ("new.iso", PAYLOAD, "application/octet-stream")},
        )
        assert response.status_code == 202, response.text
        assert response.json()["provider_task"]["id"] == UPLOAD_UPID
        assert response.json()["checksum"] == hashlib.sha256(PAYLOAD).hexdigest()
        legacy = await client.post(
            f"/hypervisor/controllers/{c.controller}/nodes/pve1/storage/local/upload",
            files={"file": ("new.iso", PAYLOAD)},
        )
        assert legacy.status_code == 422
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("action", ["delete", "upload"])
@pytest.mark.parametrize("flag", [0, False, "0"])
async def test_exact_storage_nonpropagating_grants_allow_reviewed_write(system, action, flag):
    c = system
    c.state.permissions["/storage/local"] = dict.fromkeys(
        c.state.permissions["/storage/local"], flag
    )
    receipt = await submit(c, await reviewed(c, action))
    assert receipt.status == "applied" and len(c.state.writes) == 1
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "succeeded"


@pytest.mark.parametrize("flag", [0, False, "0", 1.0, "true", None])
async def test_iso_delete_still_requires_propagating_fleet_visibility(system, flag):
    c = system
    c.state.permissions["/"]["VM.Audit"] = flag
    with pytest.raises(HTTPException):
        await reviewed(c)
    assert not c.state.writes and not await rows(c)


@pytest.mark.parametrize("action", ["delete", "upload"])
@pytest.mark.parametrize("revoke_audit", [True, False])
async def test_nonpropagating_storage_grant_revoked_after_review_blocks_write(
    system, action, revoke_audit
):
    c = system
    c.state.permissions["/storage/local"] = dict.fromkeys(c.state.permissions["/storage/local"], 0)
    body = await reviewed(c, action)
    privilege = (
        "Datastore.Audit"
        if revoke_audit
        else ("Datastore.Allocate" if action == "delete" else "Datastore.AllocateTemplate")
    )
    c.state.permissions["/storage/local"].pop(privilege)
    with pytest.raises(HTTPException) as exc:
        await submit(c, body)
    assert exc.value.status_code == 403
    assert not c.state.writes and not await rows(c)


async def test_iso_fleet_visibility_revoked_after_review_blocks_delete(system):
    c = system
    body = await reviewed(c)
    c.state.permissions["/"]["VM.Audit"] = 0
    with pytest.raises(HTTPException) as exc:
        await submit(c, body)
    assert exc.value.status_code == 403
    assert not c.state.writes and not await rows(c)


async def test_upload_does_not_require_guest_inventory_visibility(system):
    c = system
    c.state.permissions["/"] = {}
    assert (await submit(c, await reviewed(c, "upload"))).status == "applied"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("action", ["delete", "upload"])
async def test_storage_grant_revoked_after_claim_is_checked_before_dispatch(
    system, monkeypatch, action
):
    from app.services.hypervisor_operations import HypervisorOperationService

    c = system
    c.state.permissions["/storage/local"] = dict.fromkeys(c.state.permissions["/storage/local"], 0)
    body = await reviewed(c, action)
    original = HypervisorOperationService._record

    async def revoke(self, *args, **kwargs):
        change = await original(self, *args, **kwargs)
        c.state.permissions["/storage/local"].pop("Datastore.Audit")
        return change

    monkeypatch.setattr(HypervisorOperationService, "_record", revoke)
    receipt = await submit(c, body)
    assert receipt.status == "failed" and not c.state.writes
    assert len(await rows(c)) == 1

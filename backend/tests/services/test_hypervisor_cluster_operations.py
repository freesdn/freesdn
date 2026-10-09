# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Cluster safety through real PostgreSQL claims and provider HTTP contracts."""

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
from app.models.core import User
from app.modules.hypervisor import api
from app.modules.hypervisor.schemas import (
    ClusterOperationRequest,
    HAGroupCreateRequest,
    HAResourceCreateRequest,
)
from app.services import hypervisor_cluster_operations as cluster
from app.services import proxmox_task_tracking as tracking
from app.services.adapter_proxmox_ha import GatewayProxmoxHaService
from app.services.adapter_staging import AdapterStagingService
from tests.adapters.test_proxmox_write_outcomes import connected
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows
from tests.services.test_hypervisor_power import submit as submit_guest


@pytest.fixture
async def system(power, monkeypatch):
    c = power
    c.state = SimpleNamespace(
        status=[
            {"id": "cluster", "type": "cluster", "name": "fixture", "quorate": 1},
            {"id": "node/pve1", "type": "node", "name": "pve1", "online": 1},
            {"id": "node/pve2", "type": "node", "name": "pve2", "online": 1},
        ],
        guests=[
            {"vmid": 101, "type": "qemu", "node": "pve1", "name": "database", "status": "running"},
            {"vmid": 102, "type": "lxc", "node": "pve2", "name": "service", "status": "stopped"},
        ],
        resources=[],
        groups=[],
        permissions={"/vms": {"VM.Audit": 1}},
        mode="accepted",
        writes=[],
        unavailable=None,
        entered=asyncio.Event(),
        release=asyncio.Event(),
        ack=None,
    )

    async def dispatch(request):
        c.calls.append((request.method, request.url.path))
        state = c.state
        if request.method != "GET":
            state.writes.append(request)
            state.entered.set()
            if state.mode == "wait":
                await state.release.wait()
            if state.mode == "timeout":
                raise httpx.ReadTimeout("private upstream diagnostic", request=request)
            if state.mode == "reject":
                return httpx.Response(400, json={"errors": {"purge": "unsupported parameter"}})
            values = {
                k: v[0]
                for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()
            }
            kind = "resources" if "/resources" in request.url.path else "groups"
            if "/ha/" in request.url.path and state.mode != "unchanged":
                key = "sid" if kind == "resources" else "group"
                if request.method == "POST":
                    getattr(state, kind).append(values)
                else:
                    setattr(
                        state,
                        kind,
                        [
                            row
                            for row in getattr(state, kind)
                            if row[key] != request.url.path.rsplit("/", 1)[1]
                        ],
                    )
            return httpx.Response(200, json={"data": state.ack})
        values = {
            "/access/permissions": state.permissions,
            "/cluster/status": state.status,
            "/cluster/resources": state.guests,
            "/cluster/ha/resources": state.resources,
            "/cluster/ha/groups": state.groups,
        }
        if request.url.path == state.unavailable:
            return httpx.Response(403, json={"errors": {"scope": "private diagnostic"}})
        assert request.url.path in values, request.url.path
        return httpx.Response(200, json={"data": values[request.url.path]})

    async def builder(_):
        return connected(dispatch)[0]

    monkeypatch.setattr(cluster, "build_proxmox_adapter", builder)
    monkeypatch.setattr(tracking, "build_proxmox_adapter", builder)
    yield c


def target_for(action):
    return (
        "pve1"
        if action.startswith("node.")
        else "vm:101"
        if action.startswith("ha.resource.")
        else "primary"
    )


async def reviewed(c, action="node.reboot", **options):
    target = options.pop("target", target_for(action))
    if action == "ha.resource.delete":
        c.state.resources = [{"sid": target, "state": "started"}]
    elif action == "ha.group.delete":
        c.state.groups = [{"group": target, "nodes": "pve1,pve2"}]
    async with c.sessions() as db:
        review = await cluster.HypervisorClusterOperationService(db, c.user).review(
            c.controller,
            action,
            target,
            options.get("group", "") if action == "ha.resource.create" else "",
        )
    controls = {
        "request_id": c.request,
        "expected_digest": review["expected_digest"],
        "force": True,
        "confirmed": True,
    }
    body = (
        HAResourceCreateRequest(**controls, sid=target, **options)
        if action == "ha.resource.create"
        else HAGroupCreateRequest(**controls, group=target, **{"nodes": "pve1:2,pve2:1", **options})
        if action == "ha.group.create"
        else ClusterOperationRequest(**controls)
    )
    return body


async def submit(c, body, action="node.reboot", *, target=None):
    async with c.sessions() as db:
        return await cluster.HypervisorClusterOperationService(db, c.user).submit(
            c.controller, action, target or target_for(action), body
        )


@pytest.mark.parametrize("action", cluster.ACTIONS)
async def test_claim_receipt_replay_and_honest_completion(system, action):
    c = system
    body = await reviewed(c, action)
    receipt = await submit(c, body, action)
    assert receipt.status == "applied" and receipt.provider_task.id is None
    assert (await submit(c, body, action)).change_id == receipt.change_id
    assert len(c.state.writes) == 1
    assert len(await rows(c)) == 1
    write = c.state.writes[0]
    if action == "ha.resource.delete":
        assert write.url.params["purge"] == "0"
    if action.startswith("node."):
        assert parse_qs(write.content.decode()) == {"command": [action.split(".")[1]]}
    await tracking.poll_due_tasks()
    saved = (await rows(c))[0]
    assert saved.provider_task["status"] == (
        "unknown" if action.startswith("node.") else "succeeded"
    )
    assert saved.provider_task["detail"] == (
        "node_power_requires_manual_verification"
        if action.startswith("node.")
        else "ha_configuration_verified"
    )
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("action", cluster.ACTIONS)
@pytest.mark.parametrize(
    "mode,expected", [("timeout", "reconciliation_required"), ("reject", "failed")]
)
async def test_write_failure_never_replays_or_falls_back(system, action, mode, expected):
    c = system
    body = await reviewed(c, action)
    c.state.mode = mode
    receipt = await submit(c, body, action)
    assert receipt.status == expected
    assert (await submit(c, body, action)).change_id == receipt.change_id
    assert len(c.state.writes) == 1
    assert "private" not in str((await rows(c))[0].failure_reason)


@pytest.mark.parametrize("mutation", ["guest", "ha", "membership", "quorum", "permissions"])
async def test_fresh_review_change_refuses_dispatch(system, mutation):
    c = system
    body = await reviewed(c)
    if mutation == "guest":
        c.state.guests[0]["node"] = "pve2"
    if mutation == "ha":
        c.state.resources.append({"sid": "vm:101"})
    if mutation == "membership":
        c.state.status[2]["online"] = 0
    if mutation == "quorum":
        c.state.status[0]["quorate"] = 0
    if mutation == "permissions":
        c.state.permissions = {}
    receipt = await submit(c, body)
    assert receipt.status == "failed" and not c.state.writes


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("permissions", {"/vms": {"VM.Audit": 0}}),
        ("permissions", []),
        ("guests", None),
        ("guests", [{"vmid": "101"}]),
        ("resources", {}),
        ("resources", [{"sid": "vm:101"}, {"sid": "vm:101"}]),
        ("status", []),
        ("status", [{"id": "node/pve1", "type": "node", "name": "pve1"}]),
    ],
)
async def test_review_fail_closed_for_incomplete_inventory(system, attribute, value):
    setattr(system.state, attribute, value)
    with pytest.raises(HTTPException):
        await reviewed(system)
    assert not system.state.writes and not await rows(system)


@pytest.mark.parametrize(
    "path",
    [
        "/access/permissions",
        "/cluster/status",
        "/cluster/resources",
        "/cluster/ha/resources",
        "/cluster/ha/groups",
    ],
)
async def test_read_errors_do_not_become_empty_impact(system, path):
    system.state.unavailable = path
    with pytest.raises(HTTPException):
        await reviewed(system, "ha.group.create")
    assert not system.state.writes


@pytest.mark.parametrize("action", [a for a in cluster.ACTIONS if a.startswith("ha.")])
async def test_ha_readback_must_match_intent(system, action):
    c = system
    body = await reviewed(c, action)
    c.state.mode = "unchanged"
    assert (await submit(c, body, action)).status == "applied"
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "unknown"


async def test_observation_unavailable_does_not_claim_shutdown(system):
    c = system
    body = await reviewed(c, "node.shutdown")
    await submit(c, body, "node.shutdown")
    c.state.unavailable = "/cluster/status"
    await tracking.poll_due_tasks()
    saved = (await rows(c))[0]
    assert saved.provider_task["status"] == "unknown"
    async with c.sessions() as db:
        await AdapterStagingService(db).discard(
            saved.id, organization_id=c.org, actor_id=c.user.id, force=True
        )
    assert (await rows(c))[0].status == "discarded" and len(c.state.writes) == 1


@pytest.mark.parametrize("action", cluster.ACTIONS)
async def test_unknown_acknowledgement_requires_reconciliation(system, action):
    body = await reviewed(system, action)
    system.state.ack = "OK"
    assert (await submit(system, body, action)).status == "reconciliation_required"
    assert len(system.state.writes) == 1


@pytest.mark.parametrize(
    "action,options",
    [
        ("ha.group.create", {"nodes": "pve1,pve1"}),
        ("ha.group.create", {"nodes": "pve9"}),
        ("ha.group.create", {"nodes": "pve1:bad"}),
        ("ha.resource.create", {"target": "ct:101"}),
        ("ha.resource.create", {"target": "vm:999"}),
    ],
)
async def test_invalid_ha_targets_never_dispatch(system, action, options):
    body = await reviewed(system, action, **options)
    receipt = await submit(system, body, action, target=options.get("target"))
    assert receipt.status == "failed" and not system.state.writes


async def test_group_delete_refuses_references(system):
    c = system
    c.state.resources = [{"sid": "vm:101", "group": "primary"}]
    body = await reviewed(c, "ha.group.delete")
    assert (await submit(c, body, "ha.group.delete")).status == "failed"
    assert not c.state.writes


@pytest.mark.parametrize("gate", ["force", "confirmed", "read_only"])
async def test_explicit_gates_before_record_or_write(system, monkeypatch, gate):
    c = system
    body = await reviewed(c)
    if gate == "read_only":
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
    else:
        body = body.model_copy(update={gate: False})
    with pytest.raises(HTTPException):
        await submit(c, body)
    assert not await rows(c) and not c.state.writes


async def test_concurrent_same_intent_dispatches_once(system):
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


@pytest.mark.parametrize(
    "direction", ["cluster_then_guest", "guest_then_cluster", "cluster_then_cluster"]
)
async def test_unresolved_conflict_blocks_other_requests(system, direction):
    c = system
    body = await reviewed(c)
    if direction == "guest_then_cluster":
        await submit_guest(c)
        with pytest.raises(HTTPException) as exc:
            await submit(c, body.model_copy(update={"request_id": uuid4()}))
    else:
        await submit(c, body)
        with pytest.raises(HTTPException) as exc:
            if direction == "cluster_then_guest":
                await submit_guest(c, request_id=uuid4())
            else:
                await submit(c, body.model_copy(update={"request_id": uuid4()}))
    assert exc.value.status_code == 409
    assert len(c.state.writes) == (0 if direction == "guest_then_cluster" else 1)


@pytest.mark.parametrize(
    "field,value",
    [
        ("target", "pve2"),
        ("expected_digest", "b" * 64),
        ("cluster_operation_version", True),
        ("options", {"purge": 1}),
    ],
)
async def test_tampered_or_unreviewed_generic_plan_cannot_reach_credentials(system, field, value):
    c = system
    body = await reviewed(c)
    plan = {
        "cluster_operation_version": 1,
        "action": "node.reboot",
        "target": "pve1",
        "expected_digest": body.expected_digest,
        "options": {},
        "confirmed": True,
    }
    # A syntactically valid changed digest is caught by the final fresh read.
    plan[field] = value
    change = SimpleNamespace(
        feature="proxmox.node.reboot",
        operation="create",
        target_id="pve1",
        payload=plan,
        controller_id=c.controller,
        organization_id=c.org,
        site_id=c.site,
    )
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await cluster.apply_cluster_operation(GatewayProxmoxHaService(db), change)
    assert not c.state.writes


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
        url = f"/hypervisor/controllers/{c.controller}/nodes/pve1/reboot"
        response = await client.post(url, json=body.model_dump(mode="json"))
        if guard == "accepted":
            assert (
                response.status_code == 202
                and response.json()["provider_task"]["status"] == "unknown"
            )
            assert (await client.post(url, params={"confirmed": True})).status_code == 422
        else:
            assert response.status_code in {403, 404} and not c.calls


@pytest.mark.parametrize(
    "field,value",
    [("confirmed", "true"), ("force", "true"), ("purge", 1), ("expected_digest", "bad")],
)
def test_strict_control_contract(field, value):
    with pytest.raises(ValidationError):
        ClusterOperationRequest(
            **{"request_id": uuid4(), "expected_digest": "a" * 64, field: value}
        )


async def test_digest_ignores_volatile_usage_but_covers_ha_configuration(system):
    c = system
    before = await reviewed(c)
    c.state.guests[0]["cpu"] = 0.87
    c.state.guests.reverse()
    after = await reviewed(c)
    assert before.expected_digest == after.expected_digest
    c.state.resources.append({"sid": "vm:101", "state": "started"})
    assert (await reviewed(c)).expected_digest != before.expected_digest


async def test_distinct_intents_cannot_dispatch_concurrently(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "wait"
    first = asyncio.create_task(submit(c, body))
    await asyncio.wait_for(c.state.entered.wait(), 5)
    try:
        with pytest.raises(HTTPException) as exc:
            await submit(c, body.model_copy(update={"request_id": uuid4()}))
        assert exc.value.status_code == 409
        assert len(c.state.writes) == 1
    finally:
        c.state.release.set()
        await first


async def test_cancelled_dispatch_preserves_durable_claim(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "wait"
    operation = asyncio.create_task(submit(c, body))
    await asyncio.wait_for(c.state.entered.wait(), 5)
    operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation
    assert (await submit(c, body)).status == "applying"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("unavailable", [False, True])
async def test_ha_observation_failure_remains_unknown(system, unavailable):
    c = system
    body = await reviewed(c, "ha.resource.create")
    await submit(c, body, "ha.resource.create")
    if unavailable:
        c.state.unavailable = "/cluster/ha/resources"
    else:
        c.state.resources = [{"sid": "vm:101"}, {"sid": "vm:101"}]
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "unknown"


@pytest.mark.parametrize("action", cluster.ACTIONS)
async def test_http_routes_dispatch_only_reviewed_contracts(system, action):
    c = system
    body = await reviewed(c, action)

    async def auth():
        return c.user

    async def session():
        async with c.sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(api.router, prefix="/hypervisor")
    app.dependency_overrides[get_current_active_user] = auth
    app.dependency_overrides[api.get_db] = session
    target = target_for(action)
    suffix = (
        f"nodes/{target}/{action.split('.')[1]}"
        if action.startswith("node.")
        else f"ha/{'resources' if action.startswith('ha.resource.') else 'groups'}"
        + (f"/{target}" if action.endswith("delete") else "")
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        base = f"/hypervisor/controllers/{c.controller}"
        review = await client.get(
            base + "/cluster-operations/review", params={"action": action, "target": target}
        )
        assert (
            review.status_code == 200 and review.json()["expected_digest"] == body.expected_digest
        )
        method = "DELETE" if action.endswith("delete") else "POST"
        response = await client.request(
            method, base + "/" + suffix, json=body.model_dump(mode="json")
        )
        assert response.status_code == 202, response.text
        assert response.json()["status"] == "applied" and len(c.state.writes) == 1


@pytest.mark.parametrize("flag", [0, False, "0", 1.0, "true", None])
async def test_cluster_review_still_requires_propagating_guest_visibility(system, flag):
    c = system
    c.state.permissions["/vms"]["VM.Audit"] = flag
    with pytest.raises(HTTPException):
        await reviewed(c)
    assert not c.state.writes and not await rows(c)


async def test_guest_visibility_stops_propagating_after_review_blocks_cluster_write(system):
    c = system
    body = await reviewed(c)
    c.state.permissions["/vms"]["VM.Audit"] = 0
    assert (await submit(c, body)).status == "failed"
    assert not c.state.writes

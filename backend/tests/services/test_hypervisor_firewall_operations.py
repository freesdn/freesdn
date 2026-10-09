# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real SQL claims with a stateful native HTTP boundary; never production writes."""

import asyncio
from types import SimpleNamespace
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.models.staging import AdapterPendingChange
from app.modules.hypervisor.firewall_schemas import FirewallOperationRequest, FirewallReviewRequest
from app.services import hypervisor_firewall_operations as control
from app.services import proxmox_task_tracking as tracking
from app.services.adapter_proxmox_firewall import GatewayProxmoxFirewallService
from app.services.adapter_staging import AdapterStagingService
from tests.adapters.test_proxmox_write_outcomes import connected
from tests.services.test_hypervisor_power import power as power
from tests.services.test_hypervisor_power import rows

TARGETS = [
    {"scope": "cluster"},
    {"scope": "node", "node": "pve1"},
    {"scope": "guest", "node": "pve1", "vm_type": "qemu", "vmid": 101},
    {"scope": "guest", "node": "pve1", "vm_type": "lxc", "vmid": 101},
]


@pytest.fixture
async def system(power, monkeypatch):
    c = power
    c.state = SimpleNamespace(
        rules=[
            {"action": "ACCEPT", "type": "in", "enable": 1, "dport": "22", "proto": "tcp"},
            {"action": "DROP", "type": "in", "enable": 0},
        ],
        options={"enable": 0},
        identity={"digest": "d" * 40, "cipassword": "never-expose-config-secret"},
        privileges={"Sys.Audit": 1, "Sys.Modify": 1, "VM.Audit": 1, "VM.Config.Network": 1},
        writes=[],
        mode="accepted",
        ack=None,
        unavailable=False,
        malformed=None,
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
            if s.mode in ("reject", "500"):
                return httpx.Response(
                    403 if s.mode == "reject" else 500, json={"errors": {"private": "diagnostic"}}
                )
            data = (
                dict(request.url.params)
                if request.method == "DELETE"
                else {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            )
            for k in control.FLAGS:
                if k in data:
                    data[k] = int(data[k])
            if s.mode == "race":
                s.rules.insert(0, {"action": "REJECT", "type": "out", "enable": 1})
            actual = control.digest(s.options if path.endswith("/options") else s.rules)[:40]
            if request.method != "POST" and data.pop("digest", None) != actual:
                return httpx.Response(409, json={"errors": {"digest": "modified"}})
            if s.mode != "no_effect":
                if path.endswith("/options"):
                    s.options.update(data)
                elif request.method == "POST":
                    s.rules.insert(0, data)
                elif request.method == "DELETE":
                    del s.rules[int(path.rsplit("/", 1)[1])]
                else:
                    pos = int(path.rsplit("/", 1)[1])
                    if "moveto" in data:
                        # Model the provider's original-index insertion semantics.
                        moveto = int(data["moveto"])
                        rule = s.rules.pop(pos)
                        s.rules.insert(moveto - (pos < moveto), rule)
                    else:
                        s.rules[pos].update(data)
            return httpx.Response(200, json={"data": s.ack})
        if s.unavailable:
            return httpx.Response(403, json={"errors": {"private": "diagnostic"}})
        if path == "/access/permissions":
            data = {request.url.params["path"]: s.privileges}
        elif path.endswith("/rules"):
            data = [
                {**r, "pos": i, "digest": control.digest(s.rules)[:40]}
                for i, r in enumerate(s.rules)
            ]
            if s.malformed == "rules":
                data = {}
            if s.malformed == "positions":
                data[0]["pos"] = 4
            if s.malformed == "digests":
                data[0]["digest"] = "x"
            if s.malformed == "flag":
                data[0]["enable"] = "false"
        elif path.endswith("/options"):
            data = {**s.options, "digest": control.digest(s.options)[:40]}
            if s.malformed == "options":
                data = []
        elif path.endswith("/config"):
            data = s.identity
        else:
            raise AssertionError(path)
        return httpx.Response(200, json={"data": data})

    async def builder(_):
        return connected(dispatch)[0]

    monkeypatch.setattr(control, "build_proxmox_adapter", builder)
    monkeypatch.setattr(tracking, "build_proxmox_adapter", builder)
    yield c


def intent(action="delete", target=None):
    data = {"target": target or TARGETS[0], "action": action}
    if action in ("delete", "update", "move"):
        data["pos"] = 0 if action != "move" else 1
    if action == "move":
        data["moveto"] = 0
    if action in ("create", "update"):
        data["rule"] = {"action": "REJECT", "type": "in", "enable": False, "comment": "reviewed"}
    if action == "options":
        data["options"] = {"enable": True}
    return FirewallReviewRequest(**data)


async def reviewed(c, request=None):
    request = request or intent()
    async with c.sessions() as db:
        result = await control.HypervisorFirewallOperationService(db, c.user).review(
            c.controller, request
        )
    assert "never-expose-config-secret" not in str(result)
    return FirewallOperationRequest(
        **request.model_dump(),
        request_id=c.request,
        expected_digest=result["expected_digest"],
        force=True,
        confirmed=True,
        recovery_confirmed=True,
    )


async def submit(c, body):
    async with c.sessions() as db:
        return await control.HypervisorFirewallOperationService(db, c.user).submit(
            c.controller, body
        )


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("action", ["create", "update", "delete", "move", "options"])
async def test_scope_bound_write_claim_and_independent_readback(system, target, action):
    c = system
    body = await reviewed(c, intent(action, target))
    receipt = await submit(c, body)
    assert receipt.status == "applied" and receipt.provider_task.status == "pending"
    assert (await submit(c, body)).change_id == receipt.change_id
    assert len(c.state.writes) == 1
    request = c.state.writes[0]
    base = "/cluster" if target["scope"] == "cluster" else "/nodes/pve1"
    if target["scope"] == "guest":
        base += f"/{target['vm_type']}/101"
    assert request.url.path.startswith(base + "/firewall/")
    if action != "create":
        assert "digest=" in (str(request.url) + request.content.decode())
    if action in ("create", "update"):
        assert "enable=0" in request.content.decode()
    await tracking.poll_due_tasks()
    row = (await rows(c))[0]
    assert row.provider_task["status"] == "succeeded"
    assert (
        row.provider_task["detail"] == "firewall_configuration_verified_effective_policy_unverified"
    )
    assert len(c.state.writes) == 1


@pytest.mark.parametrize(
    "problem", ["unavailable", "no_effect", "other_rule", "options", "ack", "identity"]
)
async def test_false_success_is_not_inferred_from_acknowledgement(system, problem):
    c = system
    body = await reviewed(c, intent(target=TARGETS[2]))
    if problem == "no_effect":
        c.state.mode = "no_effect"
    receipt = await submit(c, body)
    if problem == "unavailable":
        c.state.unavailable = True
    if problem == "other_rule":
        c.state.rules[0]["comment"] = "external edit"
    if problem == "options":
        c.state.options["enable"] = 1
    if problem == "identity":
        c.state.identity["digest"] = "e" * 40
    if problem == "ack":
        async with c.sessions() as db:
            row = await db.get(AdapterPendingChange, receipt.change_id)
            row.applied_response = {"data": {"firewall_operation": "delete"}}
            await db.commit()
    await tracking.poll_due_tasks()
    row = (await rows(c))[0]
    assert row.provider_task["status"] == "unknown"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("mode", ["timeout", "500", "bad_ack", "reject"])
async def test_uncertain_write_is_never_redispatched(system, mode):
    c = system
    body = await reviewed(c)
    c.state.mode = mode
    if mode == "bad_ack":
        c.state.ack = "OK"
    receipt = await submit(c, body)
    assert receipt.status == ("failed" if mode == "reject" else "reconciliation_required")
    assert (await submit(c, body)).change_id == receipt.change_id
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("change", ["reorder", "options", "permission", "digest"])
async def test_stale_review_refused_before_write(system, change):
    c = system
    body = await reviewed(c)
    if change == "reorder":
        c.state.rules.reverse()
    if change == "options":
        c.state.options["enable"] = 1
    if change == "permission":
        c.state.privileges.pop("Sys.Modify")
    if change == "digest":
        body = body.model_copy(update={"expected_digest": "0" * 64})
    assert (await submit(c, body)).status != "applied"
    assert not c.state.writes


async def test_native_digest_catches_race_after_review(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "race"
    receipt = await submit(c, body)
    assert receipt.status == "failed"
    assert len(c.state.rules) == 3 and c.state.rules[1]["action"] == "ACCEPT"
    assert len(c.state.writes) == 1


@pytest.mark.parametrize("malformed", ["rules", "positions", "digests", "flag", "options"])
async def test_malformed_read_never_becomes_empty_configuration(system, malformed):
    system.state.malformed = malformed
    with pytest.raises(HTTPException):
        await reviewed(system)
    assert not system.state.writes


@pytest.mark.parametrize("field", ["force", "confirmed", "recovery_confirmed", "read_only"])
async def test_write_gates(system, field, monkeypatch):
    c = system
    body = await reviewed(c)
    if field == "read_only":
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
    else:
        body = body.model_copy(update={field: False})
    with pytest.raises(HTTPException):
        await submit(c, body)
    assert not await rows(c) and not c.state.writes


@pytest.mark.parametrize("value", ["false", "0", 0, 1, "true"])
def test_rule_enable_rejects_coercion(value):
    with pytest.raises(ValidationError):
        FirewallReviewRequest(
            target=TARGETS[0], action="create", rule={"action": "ACCEPT", "enable": value}
        )


@pytest.mark.parametrize(
    "bad",
    [
        {"pos": True},
        {"pos": 0.2},
        {"force": "true"},
        {"confirmed": 1},
        {"recovery_confirmed": "yes"},
        {"options": {"enable": "false"}},
        {"unexpected": "value"},
    ],
)
def test_strict_contract(bad):
    data = intent().model_dump() | {"request_id": uuid4(), "expected_digest": "a" * 64} | bad
    with pytest.raises(ValidationError):
        FirewallOperationRequest(**data)


@pytest.mark.parametrize(
    "target",
    [
        {"scope": "cluster", "node": "pve1"},
        {"scope": "guest", "node": "pve1"},
        {"scope": "node", "node": "../pve1"},
        {"scope": "guest", "node": "pve1", "vm_type": "qemu", "vmid": True},
    ],
)
def test_exact_target(target):
    with pytest.raises(ValidationError):
        intent(target=target)


async def test_concurrent_requests_dispatch_only_once(system):
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
    assert (await first).change_id == second.change_id and len(c.state.writes) == 1


async def test_cancellation_retains_claim(system):
    c = system
    body = await reviewed(c)
    c.state.mode = "wait"
    first = asyncio.create_task(submit(c, body))
    await asyncio.wait_for(c.state.entered.wait(), 10)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert (await submit(c, body)).status == "applying" and len(c.state.writes) == 1


async def test_conflict_blocks_firewall_while_guest_operation_unresolved(system):
    c = system
    body = await reviewed(c)
    async with c.sessions() as db:
        db.add(
            AdapterPendingChange(
                id=uuid4(),
                organization_id=c.org,
                site_id=c.site,
                controller_id=c.controller,
                feature="proxmox.vm.power",
                operation="create",
                target_id="101",
                payload={},
                status="applying",
            )
        )
        await db.commit()
    with pytest.raises(HTTPException) as exc:
        await submit(c, body)
    assert exc.value.status_code == 409 and not c.state.writes


@pytest.mark.parametrize("feature", [control.FEATURE, *sorted(control.LEGACY_FEATURES)])
async def test_legacy_and_generic_staging_cannot_bypass_review(system, feature):
    c = system
    change = SimpleNamespace(
        feature=feature, operation="create", target_id="0", payload={"enable": "false"}
    )
    async with c.sessions() as db:
        with pytest.raises(HTTPException):
            await GatewayProxmoxFirewallService(db).build_applier(change)(change)
        with pytest.raises(HTTPException):
            await AdapterStagingService(db).stage_change(
                organization_id=c.org,
                site_id=c.site,
                controller_id=c.controller,
                actor_id=c.user.id,
                feature=feature,
                operation="create",
                target_id="0",
                payload={},
            )
    assert not c.calls and not await rows(c)


async def test_unknown_resolution_preserves_unknown_observation(system):
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


async def test_request_identity_cannot_be_reused_for_changed_plan(system):
    c = system
    body = await reviewed(c)
    await submit(c, body)
    with pytest.raises(HTTPException) as exc:
        await submit(c, body.model_copy(update={"expected_digest": "b" * 64}))
    assert exc.value.status_code == 409 and len(c.state.writes) == 1


@pytest.mark.parametrize("guard", ["accepted", "foreign_org", "site_grant", "scoped", "role"])
async def test_http_authorization_and_old_write_routes_refused(system, guard):
    from fastapi import FastAPI

    from app.core.dependencies import CurrentUser, get_current_active_user
    from app.core.site_access import current_user_var
    from app.models.core import User
    from app.modules.hypervisor import api

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
        url = f"/hypervisor/controllers/{c.controller}/firewall/operations"
        review = await client.post(url + "/review", json=intent().model_dump(mode="json"))
        response = await client.post(url, json=body.model_dump(mode="json"))
        assert (await client.post(url, json={"action": "delete", "pos": 0})).status_code in (
            403,
            422,
        )
        for method, path in [
            ("POST", "/nodes/pve1/firewall/rules"),
            ("DELETE", "/nodes/pve1/firewall/rules/0"),
            ("POST", "/nodes/pve1/qemu/101/firewall/rules"),
            ("DELETE", "/nodes/pve1/qemu/101/firewall/rules/0"),
            ("PUT", "/nodes/pve1/qemu/101/firewall/options"),
            ("PUT", "/cluster/firewall/options"),
        ]:
            legacy = await client.request(
                method, f"/hypervisor/controllers/{c.controller}" + path, json={"enable": True}
            )
            assert legacy.status_code in (404, 405)

    if guard == "accepted":
        assert review.status_code == 200 and response.status_code == 202
        assert response.json()["provider_task"]["status"] == "pending"
        assert len(c.state.writes) == 1
    else:
        assert review.status_code in (403, 404) and response.status_code in (403, 404)
        assert not c.state.writes and not c.calls


@pytest.mark.parametrize(
    "scope_change", ["controller_disabled", "site_disabled", "site_org", "sync_disabled"]
)
async def test_scope_revalidated_before_credentials(system, scope_change):
    from app.models.core import Controller, Site

    c = system
    body = await reviewed(c)
    async with c.sessions() as db:
        ctrl = await db.get(Controller, c.controller)
        site = await db.get(Site, c.site)
        if scope_change == "controller_disabled":
            ctrl.is_active = False
        if scope_change == "site_disabled":
            site.is_active = False
        if scope_change == "sync_disabled":
            ctrl.sync_enabled = False
        if scope_change == "site_org":
            # Avoid an invalid database FK/null fixture; change the saved intent's scope instead.
            await db.rollback()
            change = SimpleNamespace(
                feature=control.FEATURE,
                operation="create",
                target_id=control.digest(body.target.model_dump()),
                payload={
                    "confirmed": True,
                    "firewall_operation_version": 1,
                    **body.model_dump(exclude={"request_id", "force", "confirmed"}),
                },
                controller_id=c.controller,
                organization_id=uuid4(),
                site_id=c.site,
            )
            c.calls.clear()
            with pytest.raises(HTTPException) as exc:
                await GatewayProxmoxFirewallService(db).build_applier(change)(change)
            assert exc.value.status_code == 404
            assert not c.calls
            return
        await db.commit()
    c.calls.clear()
    with pytest.raises(HTTPException):
        await submit(c, body)
    assert not c.calls and not c.state.writes


@pytest.mark.parametrize("permission", ["Sys.Audit", "Sys.Modify", "VM.Audit", "VM.Config.Network"])
async def test_native_privilege_denial(system, permission):
    system.state.privileges.pop(permission)
    request = intent(target=TARGETS[2] if permission.startswith("VM.") else TARGETS[0])
    with pytest.raises(HTTPException) as exc:
        await reviewed(system, request)
    assert exc.value.status_code == 403 and not system.state.writes


@pytest.mark.parametrize(
    "method,args",
    [
        ("get_firewall_rules", []),
        ("get_guest_firewall_rules", ["pve1", "qemu", 101]),
        ("get_cluster_firewall_options", []),
        ("get_guest_firewall_options", ["pve1", "qemu", 101]),
    ],
)
async def test_legacy_read_failure_is_visible(method, args, monkeypatch):
    from unittest.mock import AsyncMock

    from app.adapters.base import AdapterResult
    from app.modules.hypervisor.service import HypervisorService

    service = HypervisorService(None)
    adapter, _ = connected(lambda _: httpx.Response(403))
    monkeypatch.setattr(adapter, "connect", AsyncMock())
    monkeypatch.setattr(adapter, method, AsyncMock(return_value=AdapterResult.fail("unavailable")))
    monkeypatch.setattr(service, "_get_adapter", AsyncMock(return_value=adapter))
    with pytest.raises(ConnectionError):
        await getattr(service, method)(None, *args)


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, False),
        (1, True),
        ("0", False),
        ("1", True),
        (False, False),
        (True, True),
        ("false", None),
        ("True", None),
        (0.0, None),
        (2, None),
    ],
)
async def test_display_read_never_uses_truthiness_for_provider_flag(value, expected):
    adapter, _ = connected(
        lambda _: httpx.Response(
            200, json={"data": [{"pos": 0, "action": "ACCEPT", "type": "in", "enable": value}]}
        )
    )
    try:
        result = await adapter.get_firewall_rules()
        if expected is None:
            assert not result.success
        else:
            assert result.success and result.data[0].enable is expected
    finally:
        await adapter.disconnect()


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("flag", [0, False, "0"])
async def test_exact_path_nonpropagating_privileges_allow_reviewed_write(system, target, flag):
    c = system
    c.state.privileges = dict.fromkeys(c.state.privileges, flag)
    body = await reviewed(c, intent(target=target))
    receipt = await submit(c, body)
    assert receipt.status == "applied" and len(c.state.writes) == 1
    await tracking.poll_due_tasks()
    assert (await rows(c))[0].provider_task["status"] == "succeeded"


@pytest.mark.parametrize("target", TARGETS)
async def test_nonpropagating_firewall_grant_revoked_after_review_blocks_write(system, target):
    c = system
    c.state.privileges = dict.fromkeys(c.state.privileges, 0)
    body = await reviewed(c, intent(target=target))
    c.state.privileges.pop("VM.Config.Network" if target["scope"] == "guest" else "Sys.Modify")
    assert (await submit(c, body)).status == "failed"
    assert not c.state.writes


async def test_firewall_propagation_change_does_not_revoke_exact_path_grant(system):
    c = system
    body = await reviewed(c)
    c.state.privileges = dict.fromkeys(c.state.privileges, 0)
    assert (await submit(c, body)).status == "applied"
    assert len(c.state.writes) == 1

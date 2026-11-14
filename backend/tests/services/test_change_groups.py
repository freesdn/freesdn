# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A change to several devices is one staged change group.

A site-to-site tunnel push wrote to both gateways concurrently, straight from
the request, with no staged row and nothing to undo side A when side B
refused; only OPNsense can receive a tunnel, so a tunnel between an OPNsense
and anything else always ended configured on one gateway. VLAN distribution
created the VLAN controller by controller the same way.

Now: a staged row per device under one group_id, every member preflighted
before any is applied (a refused preflight anywhere applies nothing), the
first failure stops the group and the members already applied are undone
where they can be, and the outcome reports every device.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select

import app.core.runtime_flags as rf
from app.adapters.base import AdapterResult
from app.db.models import Controller
from app.models.core import Organization, Site
from app.models.devices import Device
from app.models.staging import AdapterPendingChange
from app.services.adapter_staging import AdapterStagingService, GroupMember


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest_asyncio.fixture
async def world(db_session):
    org = Organization(name="groups", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    sites = [Site(name=f"s{i}", slug=uuid4().hex, organization_id=org.id) for i in range(2)]
    db_session.add_all(sites)
    await db_session.flush()
    ctrls = [
        Controller(
            name=f"c{i}",
            site_id=sites[i].id,
            controller_type="opnsense",
            host="127.0.0.1",
            port=443,
        )
        for i in range(2)
    ]
    db_session.add_all(ctrls)
    await db_session.flush()
    gateways = [
        Device(
            name=f"gw{i}",
            site_id=sites[i].id,
            controller_id=ctrls[i].id,
            device_type="gateway",
            mac_address=f"aa:bb:cc:00:00:0{i}",
            status="online",
        )
        for i in range(2)
    ]
    db_session.add_all(gateways)
    await db_session.commit()
    return SimpleNamespace(org=org, sites=sites, ctrls=ctrls, gateways=gateways)


async def _rows(db_session) -> list[AdapterPendingChange]:
    return list(
        (
            await db_session.execute(
                select(AdapterPendingChange)
                .where(AdapterPendingChange.feature.like("direct.%"))
                .order_by(AdapterPendingChange.created_at)
            )
        ).scalars()
    )


def _member(world, i: int, log: list[str], *, refuse: str | None = None, fail: bool = False):
    async def _preflight() -> str | None:
        log.append(f"preflight {i}")
        return refuse

    async def _perform() -> AdapterResult:
        log.append(f"apply {i}")
        if fail:
            return AdapterResult.fail(f"device {i} said no")
        return AdapterResult.ok({"id": f"obj-{i}"})

    async def _undo(result: Any) -> AdapterResult:
        log.append(f"undo {i} {result.data['id']}")
        return AdapterResult.ok()

    return GroupMember(
        key=f"dev{i}",
        organization_id=world.org.id,
        controller_id=world.ctrls[i].id,
        site_id=world.sites[i].id,
        feature="test.group",
        operation="create",
        target_id=f"t{i}",
        payload={"i": i},
        perform=_perform,
        preflight=_preflight,
        compensate=_undo,
    )


async def test_every_member_is_preflighted_then_applied(db_session, world, mode) -> None:
    log: list[str] = []
    outcome = await AdapterStagingService(db_session).apply_group_now(
        [_member(world, 0, log), _member(world, 1, log)], force=True, actor_id=None
    )

    assert log == ["preflight 0", "preflight 1", "apply 0", "apply 1"]
    assert outcome.applied
    assert [m.status for m in outcome.members] == ["applied", "applied"]
    rows = await _rows(db_session)
    assert [r.status for r in rows] == ["applied", "applied"]
    assert {r.group_id for r in rows} == {outcome.group_id}
    assert {r.controller_id for r in rows} == {c.id for c in world.ctrls}


async def test_a_refused_preflight_on_any_member_applies_nothing(db_session, world, mode) -> None:
    log: list[str] = []
    outcome = await AdapterStagingService(db_session).apply_group_now(
        [_member(world, 0, log), _member(world, 1, log, refuse="cannot take it")],
        force=True,
        actor_id=None,
    )

    assert not any(entry.startswith("apply") for entry in log)
    assert outcome.preflight_refused and not outcome.applied
    assert [m.status for m in outcome.members] == ["not_applied", "not_applied"]
    assert outcome.members[1].reason == "cannot take it"
    rows = await _rows(db_session)
    assert [r.status for r in rows] == ["failed", "failed"]
    assert "preflight refused: cannot take it" in rows[1].failure_reason
    assert "dev1: cannot take it" in rows[0].failure_reason


async def test_a_failure_stops_the_group_and_undoes_what_was_applied(
    db_session, world, mode
) -> None:
    log: list[str] = []
    outcome = await AdapterStagingService(db_session).apply_group_now(
        [_member(world, 0, log), _member(world, 1, log, fail=True)],
        force=True,
        actor_id=None,
    )

    assert log == ["preflight 0", "preflight 1", "apply 0", "apply 1", "undo 0 obj-0"]
    assert not outcome.applied
    statuses = {m.key: m.status for m in outcome.members}
    assert statuses == {"dev0": "compensated", "dev1": "failed"}
    assert outcome.members[1].reason == "device 1 said no"
    rows = await _rows(db_session)
    by_feature = [(r.feature, r.status) for r in rows]
    assert by_feature == [
        ("direct.test.group", "applied"),
        ("direct.test.group", "failed"),
        ("direct.test.group.compensate", "applied"),
    ]
    assert len({r.group_id for r in rows}) == 1


async def test_read_only_mode_refuses_the_whole_group(db_session, world, mode) -> None:
    mode["read_only"] = True
    log: list[str] = []
    with pytest.raises(HTTPException) as refused:
        await AdapterStagingService(db_session).apply_group_now(
            [_member(world, 0, log), _member(world, 1, log)], force=True, actor_id=None
        )
    assert refused.value.status_code == 403
    assert log == []
    assert await _rows(db_session) == []


# ── site-to-site tunnel push ────────────────────────────────────────────────


class _Gateway:
    """An adapter that can receive a tunnel."""

    def __init__(self, log: list[str], name: str, *, refuse: bool = False) -> None:
        self.log, self.name, self.refuse = log, name, refuse

    async def __aenter__(self) -> _Gateway:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def push_vpn_config(self, mac: str, config: Any) -> AdapterResult:
        self.log.append(f"push {self.name}")
        if self.refuse:
            return AdapterResult.fail(f"{self.name} refused the tunnel")
        return AdapterResult.ok({"configured": True})

    async def remove_vpn_config(self, mac: str, tunnel_id: str) -> AdapterResult:
        self.log.append(f"remove {self.name}")
        return AdapterResult.ok()


class _NoTunnels:
    """An adapter that cannot receive a tunnel (anything but OPNsense today)."""

    async def __aenter__(self) -> _NoTunnels:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False


def _tunnel(world) -> Any:
    return SimpleNamespace(
        id=uuid4(),
        organization_id=world.org.id,
        gateway_a_device_id=world.gateways[0].id,
        gateway_b_device_id=world.gateways[1].id,
        config_a={"peer": "b"},
        config_b={"peer": "a"},
        error_message=None,
    )


def _service(db_session, adapters: dict[Any, Any]) -> Any:
    from app.services.vpn_orchestration import VPNOrchestrationService

    svc = VPNOrchestrationService(db_session)
    svc._gateway_adapter = lambda device: adapters[device.id]  # type: ignore[method-assign]
    return svc


async def test_a_tunnel_is_pushed_to_both_gateways_as_one_group(db_session, world, mode) -> None:
    log: list[str] = []
    a, b = world.gateways
    svc = _service(db_session, {a.id: _Gateway(log, "a"), b.id: _Gateway(log, "b")})
    tunnel = _tunnel(world)

    assert await svc._push_to_gateways(tunnel) is True
    assert log == ["push a", "push b"]
    assert tunnel.error_message is None
    rows = await _rows(db_session)
    assert [(r.feature, r.status) for r in rows] == [("direct.vpn.s2s.push", "applied")] * 2
    assert len({r.group_id for r in rows}) == 1


async def test_a_side_that_cannot_take_the_tunnel_stops_both(db_session, world, mode) -> None:
    """The half-provisioned tunnel: side A configured, side B could never be."""
    log: list[str] = []
    a, b = world.gateways
    svc = _service(db_session, {a.id: _Gateway(log, "a"), b.id: _NoTunnels()})
    tunnel = _tunnel(world)

    assert await svc._push_to_gateways(tunnel) is False
    assert log == []  # nothing reached side A either
    assert "Side b" in tunnel.error_message
    assert "cannot receive a site-to-site tunnel" in tunnel.error_message
    assert "nothing was pushed to either gateway" in tunnel.error_message
    assert [r.status for r in await _rows(db_session)] == ["failed", "failed"]


async def test_a_refused_push_removes_the_side_already_pushed(db_session, world, mode) -> None:
    log: list[str] = []
    a, b = world.gateways
    svc = _service(
        db_session, {a.id: _Gateway(log, "a"), b.id: _Gateway(log, "b", refuse=True)}
    )
    tunnel = _tunnel(world)

    assert await svc._push_to_gateways(tunnel) is False
    assert log == ["push a", "push b", "remove a"]
    assert "Side b: b refused the tunnel" in tunnel.error_message
    assert "undone because Side b failed" in tunnel.error_message


async def test_read_only_mode_pushes_nothing(db_session, world, mode) -> None:
    mode["read_only"] = True
    log: list[str] = []
    a, b = world.gateways
    svc = _service(db_session, {a.id: _Gateway(log, "a"), b.id: _Gateway(log, "b")})
    tunnel = _tunnel(world)

    assert await svc._push_to_gateways(tunnel) is False
    assert log == []
    assert "Read-only mode is on" in tunnel.error_message

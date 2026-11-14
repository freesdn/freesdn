# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Distribute to limbs and the distribution engine are one staged change group,
and neither writes to a soft-deleted gateway.

``ReconciliationService.distribute_to_limbs`` wrote one ledger row per limb
and VLAN, each on its own: a limb that could never take the VLAN did not stop
the others, so a site ended half-distributed by design. The distribution engine
(``DistributionService._execute_plan``) dispatched each planned step with
``getattr(adapter, action)(**params)``, straight to the device with no staged
row at all. Both now stage one group per run: every device preflighted before
anything is written, the first failure stops the rest, and nothing already
written is deleted again automatically (a limb or brain may have had the VLAN
before; the engine keeps its rollback plan for the operator, as it did).

Soft-deleted gateways: ``_get_gateway_adapter`` loaded the gateway with
``db.get``, which ignores ``deleted_at``, and the engine's gateway cache did not
filter it either, so a distribution reached a gateway the operator had removed.
The adapter builders now refuse a soft-deleted gateway outright.

Adapters are fakes built through the adapter registry; nothing is contacted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

import app.core.runtime_flags as rf
from app.adapters.base import AdapterResult
from app.core.crypto import encrypt_dict
from app.db.models import Controller
from app.models.core import Organization, Site
from app.models.staging import AdapterPendingChange
from app.modules.firewall.models import GatewayConnection
from app.modules.gateway.models import CanonicalVLAN, DistributionStatus, NetworkRole


class _Device:
    """A fake controller or gateway; ``box.refuse`` names methods that refuse."""

    def __init__(self, box: SimpleNamespace, name: str) -> None:
        self.box, self.name = box, name

    async def __aenter__(self) -> _Device:
        if self.name in self.box.unreachable:
            raise ConnectionError("no route to host")
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def connect(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    async def _do(self, method: str, *args: Any, **kwargs: Any) -> Any:
        self.box.calls.append((self.name, method))
        if (self.name, method) in self.box.refuse:
            return AdapterResult.fail(f"{self.name} refused {method}")
        return AdapterResult.ok({"id": f"{self.name}-{method}"})

    async def create_vlan(self, *args: Any, **kwargs: Any) -> Any:
        return await self._do("create_vlan", *args, **kwargs)

    async def create_vlan_device(self, *args: Any, **kwargs: Any) -> Any:
        return await self._do("create_vlan_device", *args, **kwargs)

    async def create_vlan_interface(self, **kwargs: Any) -> Any:
        return await self._do("create_vlan_interface", **kwargs)

    async def create_dhcp_scope(self, **kwargs: Any) -> Any:
        return await self._do("create_dhcp_scope", **kwargs)

    async def create_alias(self, **kwargs: Any) -> Any:
        return await self._do("create_alias", **kwargs)

    async def delete_vlan(self, **kwargs: Any) -> Any:
        return await self._do("delete_vlan", **kwargs)

    async def delete_alias(self, **kwargs: Any) -> Any:
        return await self._do("delete_alias", **kwargs)

    async def delete_dhcp_scope(self, **kwargs: Any) -> Any:
        return await self._do("delete_dhcp_scope", **kwargs)

    async def delete_vlan_interface(self, **kwargs: Any) -> Any:
        return await self._do("delete_vlan_interface", **kwargs)


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest_asyncio.fixture
async def world(db_session, monkeypatch: pytest.MonkeyPatch):
    from app.modules.firewall import gateway_service
    from app.services import adapter_factory

    org = Organization(name="distribution groups", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrls = [
        Controller(
            name=f"ctrl{i}",
            site_id=site.id,
            controller_type="omada",
            host=f"192.0.2.10{i}",
            port=443,
        )
        for i in range(2)
    ]
    gws = [
        GatewayConnection(
            org_id=org.id,
            site_id=site.id,
            name=f"gw{i}",
            vendor="opnsense",
            host=f"192.0.2.11{i}",
            port=443,
            verify_ssl=True,
            credentials=encrypt_dict({"api_key": "k", "api_secret": "s"}),
            settings={},
            sync_enabled=False,
        )
        for i in range(2)
    ]
    db_session.add_all([*ctrls, *gws])
    await db_session.flush()
    vlan = CanonicalVLAN(
        organization_id=org.id,
        site_id=site.id,
        vlan_id=40,
        name="iot",
        subnet="10.40.0.0/24",
        gateway_ip="10.40.0.1",
        dhcp_enabled=True,
        dhcp_range_start="10.40.0.100",
        dhcp_range_end="10.40.0.200",
    )
    db_session.add(vlan)
    await db_session.commit()

    box = SimpleNamespace(calls=[], refuse=set(), unreachable=set(), built=[])
    names = {str(c.host): c.name for c in ctrls} | {str(g.host): g.name for g in gws}

    def _create(**kwargs: Any) -> _Device:
        name = names[kwargs["host"]]
        box.built.append(name)
        return _Device(box, name)

    def _controller_adapter(ctrl: Any) -> _Device:
        box.built.append(ctrl.name)
        return _Device(box, ctrl.name)

    monkeypatch.setattr(gateway_service.adapter_registry, "create_adapter", _create)
    monkeypatch.setattr(adapter_factory, "build_adapter_for_controller", _controller_adapter)
    return SimpleNamespace(org=org, site=site, ctrls=ctrls, gws=gws, vlan=vlan, box=box)


async def _ledger(db_session) -> list[AdapterPendingChange]:
    return list(
        (
            await db_session.execute(
                select(AdapterPendingChange).where(AdapterPendingChange.feature.like("direct.%"))
            )
        ).scalars()
    )


def _assignment(role: str, *, ctrl: Any = None, gw: Any = None) -> Any:
    return SimpleNamespace(
        role=role,
        device_type="controller" if ctrl is not None else "gateway",
        controller_id=ctrl.id if ctrl is not None else None,
        gateway_id=gw.id if gw is not None else None,
        device_id=(ctrl or gw).id,
        suppress_dhcp=False,
    )


def _role_map(w, *assignments: Any) -> Any:
    return SimpleNamespace(
        site_id=w.site.id, assignments=list(assignments), last_reconciled_at=None
    )


# ── distribute to limbs ──────────────────────────────────────────────────────


def _limbs(w) -> Any:
    return _role_map(
        w,
        _assignment(NetworkRole.LIMB, ctrl=w.ctrls[0]),
        _assignment(NetworkRole.LIMB, ctrl=w.ctrls[1]),
        _assignment(NetworkRole.LIMB, gw=w.gws[0]),
    )


async def _distribute(db_session, w, role_map: Any) -> Any:
    from app.modules.gateway.services.reconciliation_service import ReconciliationService

    return await ReconciliationService(db_session).distribute_to_limbs(role_map, org_id=w.org.id)


async def test_every_limb_takes_the_vlan_as_one_group(db_session, world, mode) -> None:
    out = await _distribute(db_session, world, _limbs(world))

    assert out.distributed == 3 and out.failed == 0 and not out.partial_failure
    assert [c[1] for c in world.box.calls] == ["create_vlan", "create_vlan", "create_vlan_device"]
    rows = await _ledger(db_session)
    assert [r.status for r in rows] == ["applied"] * 3
    assert len({r.group_id for r in rows}) == 1
    assert {r.feature for r in rows} == {
        "direct.network.vlan.limb",
        "direct.network.vlan.limb_gateway",
    }


async def test_a_limb_that_cannot_answer_stops_the_whole_distribution(
    db_session, world, mode
) -> None:
    world.box.unreachable.add("gw0")

    out = await _distribute(db_session, world, _limbs(world))

    assert world.box.calls == [], "a refused preflight must create the VLAN nowhere"
    assert out.distributed == 0
    assert out.partial_failure is True
    assert set(out.failed_devices) == {str(c.id) for c in world.ctrls} | {str(world.gws[0].id)}
    assert [r.status for r in await _ledger(db_session)] == ["failed"] * 3


async def test_the_first_refusal_stops_the_rest_and_nothing_is_deleted_again(
    db_session, world, mode
) -> None:
    world.box.refuse.add(("ctrl1", "create_vlan"))

    out = await _distribute(db_session, world, _limbs(world))

    assert world.box.calls == [("ctrl0", "create_vlan"), ("ctrl1", "create_vlan")]
    assert out.distributed == 1 and out.failed == 1 and out.skipped == 1
    assert out.failed_devices == sorted([str(world.ctrls[1].id), str(world.gws[0].id)])
    assert [d["action"] for d in out.details] == ["created", "failed", "not_applied"]


async def test_a_soft_deleted_gateway_limb_is_never_built_or_written(
    db_session, world, mode
) -> None:
    world.gws[0].deleted_at = datetime.now(UTC)
    await db_session.commit()

    out = await _distribute(db_session, world, _limbs(world))

    assert "gw0" not in world.box.built
    assert world.box.calls == []
    detail = next(d for d in out.details if d["device_id"] == str(world.gws[0].id))
    assert "no longer registered" in detail["error"]


async def test_read_only_mode_distributes_nothing(db_session, world, mode) -> None:
    mode["read_only"] = True

    out = await _distribute(db_session, world, _limbs(world))

    assert world.box.calls == []
    assert out.distributed == 0 and out.partial_failure is True
    assert any("Read-only mode is on" in e for e in out.errors)
    assert await _ledger(db_session) == []


# ── the distribution engine ──────────────────────────────────────────────────


def _engine_map(w) -> Any:
    return _role_map(
        w,
        _assignment(NetworkRole.BRAIN, gw=w.gws[0]),
        _assignment(NetworkRole.LIMB, gw=w.gws[1]),
    )


async def _engine(db_session, w, *, retract: bool = False) -> Any:
    from app.modules.gateway.services.distribution_service import DistributionService

    svc = DistributionService(db_session)
    if retract:
        return await svc.retract_vlan(w.vlan, _engine_map(w), triggered_by=None)
    return await svc.distribute_vlan(w.vlan, _engine_map(w), triggered_by=None)


async def test_a_distribution_is_one_group_in_tier_order(db_session, world, mode) -> None:
    record = await _engine(db_session, world)

    assert record.status == DistributionStatus.COMPLETED
    assert world.box.calls == [
        ("gw0", "create_vlan_interface"),
        ("gw0", "create_dhcp_scope"),
        ("gw0", "create_alias"),
        ("gw1", "create_vlan"),
    ]
    assert {s["status"] for s in record.step_results} == {"success"}
    assert [s["action"] for s in record.step_results] == [
        "verify_reachable",
        "verify_reachable",
        "create_vlan_interface",
        "create_dhcp_scope",
        "create_alias",
        "create_vlan",
        "verify_all",
    ]
    rows = await _ledger(db_session)
    assert sorted(r.feature for r in rows) == sorted(
        [
            "direct.gateway.distribution.create_vlan_interface",
            "direct.gateway.distribution.create_dhcp_scope",
            "direct.gateway.distribution.create_alias",
            "direct.gateway.distribution.create_vlan",
        ]
    )
    assert len({r.group_id for r in rows}) == 1
    assert all(r.status == "applied" for r in rows)


async def test_a_failed_step_stops_the_plan_and_keeps_the_rollback_plan(
    db_session, world, mode
) -> None:
    world.box.refuse.add(("gw1", "create_vlan"))

    record = await _engine(db_session, world)

    assert record.status == DistributionStatus.FAILED
    assert "create_vlan" in record.error_message
    assert record.rollback_executed is False
    # The steps that ran, most recent first (the engine's own inverse map
    # decides which become a delete and which a manual review).
    assert [s["tier"] for s in record.rollback_plan["steps"]] == [2, 2, 1]
    failed = [s for s in record.step_results if s["status"] == "failed"]
    assert [s["action"] for s in failed] == ["create_vlan"]
    # Nothing was undone automatically.
    assert not [c for c in world.box.calls if c[1].startswith("delete_")]


async def test_an_unreachable_device_runs_nothing(db_session, world, mode) -> None:
    world.box.unreachable.add("gw1")

    record = await _engine(db_session, world)

    assert record.status == DistributionStatus.FAILED
    assert world.box.calls == []
    assert "unreachable" in record.error_message
    verify = [s for s in record.step_results if s["action"] == "verify_reachable"]
    assert [s["status"] for s in verify] == ["success", "failed"]
    assert record.rollback_plan is None


async def test_a_soft_deleted_gateway_in_the_plan_runs_nothing(db_session, world, mode) -> None:
    world.gws[1].deleted_at = datetime.now(UTC)
    await db_session.commit()

    record = await _engine(db_session, world)

    assert record.status == DistributionStatus.FAILED
    assert world.box.calls == []
    assert "not found" in record.error_message


async def test_read_only_mode_runs_no_step(db_session, world, mode) -> None:
    mode["read_only"] = True

    record = await _engine(db_session, world)

    assert record.status == DistributionStatus.FAILED
    assert "Read-only mode is on" in record.error_message
    assert world.box.calls == []
    assert await _ledger(db_session) == []


async def test_a_retraction_is_staged_too(db_session, world, mode) -> None:
    record = await _engine(db_session, world, retract=True)

    assert record.status == DistributionStatus.COMPLETED
    assert world.box.calls == [
        ("gw1", "delete_vlan"),
        ("gw0", "delete_alias"),
        ("gw0", "delete_dhcp_scope"),
        ("gw0", "delete_vlan_interface"),
    ]
    rows = await _ledger(db_session)
    assert {r.operation for r in rows} == {"delete"}
    assert len({r.group_id for r in rows}) == 1

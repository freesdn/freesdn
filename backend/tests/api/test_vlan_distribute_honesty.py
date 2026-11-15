# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
"Distribute VLAN" calls each controller's create_vlan in the shape it takes.

The endpoint handed every adapter one Omada-shaped dict as the VLAN id. Only
Omada's create_vlan accepts that; MikroTik, OPNsense and OpenWrt take
``(vlan_id, name)`` and would have used the dict's text as the tag. It also
read ``AdapterResult.value`` (the field is ``data``), so the controller's id was
never stored, and copied subnet, gateway and DHCP into the record of a
controller that had only been sent a layer-2 VLAN. The UI then said
"distributed successfully" whatever the per-controller results were.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.adapters.base import AdapterResult
from app.api.v1.endpoints import network as ep


class _Adapter:
    def __init__(self, result: AdapterResult) -> None:
        self.result = result
        self.calls: list[tuple[Any, ...]] = []

    async def __aenter__(self) -> _Adapter:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def create_vlan(self, *args: Any, **kwargs: Any) -> AdapterResult:
        self.calls.append(args)
        return self.result


def _ctrl(kind: str) -> Any:
    return SimpleNamespace(id=uuid4(), name=f"{kind}-ctrl", controller_type=kind)


async def _distribute(monkeypatch: pytest.MonkeyPatch, adapters: dict[str, _Adapter]) -> Any:
    source = SimpleNamespace(
        id=uuid4(),
        site_id=uuid4(),
        name="cameras",
        vlan_id=30,
        description="",
        purpose="Interface",
        gateway="10.0.30.1",
        subnet="10.0.30.0",
        subnet_mask="255.255.255.0",
        cidr="10.0.30.0/24",
        dhcp_enabled=True,
        dhcp_start="10.0.30.100",
        dhcp_end="10.0.30.200",
    )
    ctrls = [_ctrl(kind) for kind in adapters]
    by_id = {c.id: adapters[c.controller_type] for c in ctrls}
    session = MagicMock()
    session.execute = AsyncMock(
        side_effect=[
            SimpleNamespace(scalar_one_or_none=lambda: source),
            SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: ctrls)),
        ]
    )
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    added: list[Any] = []
    session.add = added.append

    async def _adapter_for(ctrl: Any) -> _Adapter:
        return by_id[ctrl.id]

    monkeypatch.setattr(ep, "_org_id", lambda _user: uuid4())
    monkeypatch.setattr(ep, "_verify_site_grant", lambda *_a, **_k: None)
    monkeypatch.setattr(ep, "_get_adapter_for_controller", _adapter_for)
    # The change group needs a real session (test_change_groups.py covers it);
    # these tests are about the call shape and the per-controller report.
    import app.services.device_writes as device_writes
    from tests.fixtures_harness.change_groups import run_group

    monkeypatch.setattr(device_writes, "apply_group_through_staging", run_group)
    body = ep.VlanDistributeIn(
        source_network_id=str(source.id), target_controller_ids=[str(c.id) for c in ctrls]
    )
    resp = await ep.distribute_vlan(body, session=session, _user=SimpleNamespace(id=uuid4()))
    return resp, added


async def test_each_adapter_gets_the_call_shape_it_takes(monkeypatch: pytest.MonkeyPatch) -> None:
    omada = _Adapter(AdapterResult.ok({"id": "net-1"}, message="VLAN created"))
    mikrotik = _Adapter(AdapterResult.ok({"vlan_id": 30}, message="Bridge VLAN 30 created"))
    resp, added = await _distribute(monkeypatch, {"omada": omada, "mikrotik": mikrotik})

    (omada_args,) = omada.calls
    assert isinstance(omada_args[0], dict) and omada_args[0]["vlanId"] == 30
    assert mikrotik.calls == [(30, "cameras")]
    assert resp.succeeded == 2 and resp.failed == 0

    omada_row, mikrotik_row = added  # targets are processed in order
    assert omada_row.external_id == "net-1"  # read from .data, not .value
    assert omada_row.gateway == "10.0.30.1" and omada_row.dhcp_enabled is True
    assert mikrotik_row.gateway is None and mikrotik_row.dhcp_enabled is False
    l2 = next(r for r in resp.results if r.controller_name == "mikrotik-ctrl")
    assert "layer 2 only" in l2.message


async def test_a_refusing_controller_is_reported_with_its_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unifi = _Adapter(
        AdapterResult.fail(
            "UniFiAdapter does not support VLAN creation", error_code="NOT_SUPPORTED"
        )
    )
    resp, added = await _distribute(monkeypatch, {"unifi": unifi})
    assert resp.succeeded == 0 and resp.failed == 1
    assert resp.results[0].message == "UniFiAdapter does not support VLAN creation"
    assert added == []

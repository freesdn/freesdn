# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A delete the device refuses keeps FreeSDN's record and says why.

``DELETE /network/vlans/{id}`` and ``DELETE /network/wifi/{id}`` soft-deleted
FreeSDN's record whatever the controller answered, returning
``controller_synced: false`` in a body the UI does not read; ``DELETE
/vpn-orchestration/tunnels/{id}`` deleted the tunnel after trying each gateway
on its own and swallowing any refusal. Each left a VLAN, SSID or tunnel live on
the device with nothing in FreeSDN pointing at it.

Now the device is asked first, and a refusal (read-only mode, an ambiguous
site, a refusing controller or gateway) keeps the record and answers
``success: false, record_kept: true`` with the reason, which is what the UI
reads as "kept". An object the controller no longer has is already gone, so
its record goes too; ``local_only=true`` removes only FreeSDN's record. The
tunnel's two sides are one change group.

Also here: a site with two controllers answered 500 on every VLAN/WiFi write
(the controller lookup was ``scalar_one_or_none()`` outside the ``try``).

Adapters are fakes; nothing is contacted.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

import app.core.runtime_flags as rf
from app.adapters.base import AdapterResult
from app.db.models import Controller
from app.models.core import Organization, Site
from app.models.devices import Device
from app.models.staging import AdapterPendingChange
from app.models.vpn import SiteToSiteTunnel
from app.modules.network.models import Network, WifiNetwork


class _Controller:
    """A fake controller adapter; every write answers ``box.answer``."""

    def __init__(self, box: SimpleNamespace) -> None:
        self.box = box

    async def __aenter__(self) -> _Controller:
        return self

    async def __aexit__(self, *_exc: Any) -> bool:
        return False

    async def delete_vlan(self, vlan: str) -> Any:
        self.box.calls.append(("delete_vlan", vlan))
        return self.box.answer

    async def create_vlan(self, *args: Any, **_kwargs: Any) -> Any:
        self.box.calls.append(("create_vlan", args))
        return self.box.answer

    async def delete_ssid(self, ssid: str, **_kwargs: Any) -> Any:
        self.box.calls.append(("delete_ssid", ssid))
        return self.box.answer

    async def remove_vpn_config(self, mac: str, tunnel_id: str) -> Any:
        self.box.calls.append(("remove_vpn_config", mac))
        return self.box.answers.get(mac, self.box.answer)


@pytest.fixture
def mode(monkeypatch: pytest.MonkeyPatch) -> dict[str, bool]:
    state = {"read_only": False}
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: state["read_only"])
    return state


@pytest_asyncio.fixture
async def site(db_session, monkeypatch: pytest.MonkeyPatch):
    from app.api.v1.endpoints import network

    org = Organization(name="refused deletes", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(name="s", slug=uuid4().hex, organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    ctrl = Controller(
        name="omada", site_id=site.id, controller_type="omada", host="192.0.2.80", port=443
    )
    db_session.add(ctrl)
    await db_session.flush()
    vlan = Network(site_id=site.id, name="cameras", vlan_id=30, external_id="net-30")
    wifi = WifiNetwork(site_id=site.id, ssid="guests", external_id="ssid-1")
    db_session.add_all([vlan, wifi])
    await db_session.commit()
    box = SimpleNamespace(calls=[], answer=AdapterResult.ok({"id": "x"}), answers={})

    async def _adapter(_ctrl: Any) -> _Controller:
        return _Controller(box)

    monkeypatch.setattr(network, "_get_adapter_for_controller", _adapter)
    user = SimpleNamespace(
        id=uuid4(),
        organization_id=org.id,
        is_superuser=True,
        role="super_admin",
        can_access_site=lambda _site_id: True,
    )
    return SimpleNamespace(
        org=org, site=site, ctrl=ctrl, vlan=vlan, wifi=wifi, box=box, user=user, net=network
    )


async def _ledger(db_session) -> list[AdapterPendingChange]:
    return list(
        (
            await db_session.execute(
                select(AdapterPendingChange).where(AdapterPendingChange.feature.like("direct.%"))
            )
        ).scalars()
    )


def _delete(f, kind: str, db_session, **kw: Any) -> Any:
    if kind == "vlan":
        return f.net.delete_vlan(str(f.vlan.id), session=db_session, _user=f.user, **kw)
    return f.net.delete_wifi(str(f.wifi.id), session=db_session, _user=f.user, **kw)


def _row(f, kind: str) -> Any:
    return f.vlan if kind == "vlan" else f.wifi


@pytest.mark.parametrize("kind", ["vlan", "wifi"])
async def test_a_delete_the_controller_accepts_removes_the_record(
    db_session, site, mode, kind
) -> None:
    out = await _delete(site, kind, db_session, local_only=False)

    assert out == {"success": True, "controller_synced": True, "controller_warning": None}
    await db_session.refresh(_row(site, kind))
    assert _row(site, kind).deleted_at is not None
    (row,) = await _ledger(db_session)
    assert row.status == "applied" and row.operation == "delete"


@pytest.mark.parametrize("kind", ["vlan", "wifi"])
async def test_a_delete_the_controller_refuses_keeps_the_record(
    db_session, site, mode, kind
) -> None:
    site.box.answer = AdapterResult.fail("it is in use by a port profile")

    out = await _delete(site, kind, db_session, local_only=False)

    assert out["success"] is False and out["record_kept"] is True
    assert out["controller_synced"] is False
    assert "in use by a port profile" in out["controller_warning"]
    assert "so FreeSDN kept it" in out["reason"]
    assert "local_only=true" in out["reason"]
    await db_session.refresh(_row(site, kind))
    assert _row(site, kind).deleted_at is None
    (row,) = await _ledger(db_session)
    assert row.status == "failed"


@pytest.mark.parametrize("kind", ["vlan", "wifi"])
async def test_read_only_mode_keeps_the_record(db_session, site, mode, kind) -> None:
    mode["read_only"] = True

    out = await _delete(site, kind, db_session, local_only=False)

    assert out["success"] is False and out["record_kept"] is True
    assert "Read-only mode is on" in out["reason"]
    assert site.box.calls == []
    await db_session.refresh(_row(site, kind))
    assert _row(site, kind).deleted_at is None


@pytest.mark.parametrize("kind", ["vlan", "wifi"])
async def test_an_object_the_controller_no_longer_has_is_removed(
    db_session, site, mode, kind
) -> None:
    site.box.answer = AdapterResult.fail("not found", error_code="NOT_FOUND")

    out = await _delete(site, kind, db_session, local_only=False)

    assert out["success"] is True and out["controller_synced"] is True
    assert "no longer had" in out["controller_warning"]
    await db_session.refresh(_row(site, kind))
    assert _row(site, kind).deleted_at is not None


@pytest.mark.parametrize("kind", ["vlan", "wifi"])
async def test_local_only_removes_freesdns_record_without_asking_the_controller(
    db_session, site, mode, kind
) -> None:
    out = await _delete(site, kind, db_session, local_only=True)

    assert out["success"] is True and out["controller_synced"] is False
    assert "Removed from FreeSDN only" in out["controller_warning"]
    assert site.box.calls == []
    assert await _ledger(db_session) == []
    await db_session.refresh(_row(site, kind))
    assert _row(site, kind).deleted_at is not None


async def test_a_site_with_two_controllers_no_longer_answers_500(db_session, site, mode) -> None:
    db_session.add(
        Controller(
            name="unifi", site_id=site.site.id, controller_type="unifi", host="192.0.2.81", port=443
        )
    )
    await db_session.commit()

    sync = await site.net._push_vlan_to_controller(db_session, site.vlan, "create")
    assert sync["controller_synced"] is False
    assert "2 controllers" in sync["controller_warning"]

    out = await _delete(site, "wifi", db_session, local_only=False)
    assert out["record_kept"] is True and "2 controllers" in out["reason"]
    assert site.box.calls == []


# ── site-to-site tunnel teardown ──────────────────────────────────────────────


@pytest_asyncio.fixture
async def tunnel(db_session, monkeypatch: pytest.MonkeyPatch):
    from app.services.vpn_orchestration import VPNOrchestrationService

    org = Organization(name="teardown", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    sites = [Site(name=f"s{i}", slug=uuid4().hex, organization_id=org.id) for i in range(2)]
    db_session.add_all(sites)
    await db_session.flush()
    ctrls = [
        Controller(
            name=f"opn{i}",
            site_id=sites[i].id,
            controller_type="opnsense",
            host=f"192.0.2.9{i}",
            port=443,
        )
        for i in range(2)
    ]
    db_session.add_all(ctrls)
    await db_session.flush()
    gws = [
        Device(
            name=f"gw{i}",
            site_id=sites[i].id,
            controller_id=ctrls[i].id,
            device_type="gateway",
            mac_address=f"aa:bb:cc:00:01:0{i}",
            status="online",
        )
        for i in range(2)
    ]
    db_session.add_all(gws)
    await db_session.flush()
    row = SiteToSiteTunnel(
        organization_id=org.id,
        site_a_id=sites[0].id,
        site_b_id=sites[1].id,
        gateway_a_device_id=gws[0].id,
        gateway_b_device_id=gws[1].id,
        status="active",
        config_a={},
        config_b={},
    )
    db_session.add(row)
    await db_session.commit()
    box = SimpleNamespace(calls=[], answer=AdapterResult.ok(), answers={})
    svc = VPNOrchestrationService(db_session)
    svc._gateway_adapter = lambda _device: _Controller(box)  # type: ignore[method-assign]
    return SimpleNamespace(svc=svc, row=row, org=org, gws=gws, box=box)


async def _tunnel_gone(db_session, tunnel) -> bool:
    return (
        await db_session.execute(
            select(SiteToSiteTunnel).where(SiteToSiteTunnel.id == tunnel.row.id)
        )
    ).scalar_one_or_none() is None


async def test_a_teardown_removes_both_sides_as_one_group(db_session, tunnel, mode) -> None:
    assert await tunnel.svc.teardown_tunnel(tunnel.row.id, tunnel.org.id) is True

    assert [c[0] for c in tunnel.box.calls] == ["remove_vpn_config"] * 2
    rows = await _ledger(db_session)
    assert [(r.feature, r.status) for r in rows] == [("direct.vpn.s2s.remove", "applied")] * 2
    assert len({r.group_id for r in rows}) == 1
    assert await _tunnel_gone(db_session, tunnel)


async def test_a_gateway_that_refuses_keeps_the_tunnel(db_session, tunnel, mode) -> None:
    from app.services.vpn_orchestration import TunnelTeardownError

    tunnel.box.answers["aa:bb:cc:00:01:01"] = AdapterResult.fail("tunnel is busy")

    with pytest.raises(TunnelTeardownError) as refused:
        await tunnel.svc.teardown_tunnel(tunnel.row.id, tunnel.org.id)

    assert "Side b" in str(refused.value) and "tunnel is busy" in str(refused.value)
    assert "already removed from Side a" in str(refused.value)
    assert not await _tunnel_gone(db_session, tunnel)
    assert tunnel.row.status == "error"
    assert "tunnel is busy" in tunnel.row.error_message


async def test_read_only_mode_keeps_the_tunnel_and_contacts_nothing(
    db_session, tunnel, mode
) -> None:
    from app.services.vpn_orchestration import TunnelTeardownError

    mode["read_only"] = True
    with pytest.raises(TunnelTeardownError, match="Read-only mode is on"):
        await tunnel.svc.teardown_tunnel(tunnel.row.id, tunnel.org.id)
    assert tunnel.box.calls == []
    assert not await _tunnel_gone(db_session, tunnel)
    assert tunnel.row.status == "active", "nothing was touched, so the status stays"


async def test_local_only_deletes_the_tunnel_without_asking_the_gateways(
    db_session, tunnel, mode
) -> None:
    assert await tunnel.svc.teardown_tunnel(tunnel.row.id, tunnel.org.id, local_only=True)
    assert tunnel.box.calls == []
    assert await _tunnel_gone(db_session, tunnel)


async def test_a_soft_deleted_gateway_is_not_written_to(db_session, tunnel, mode) -> None:
    from datetime import UTC, datetime

    tunnel.gws[1].deleted_at = datetime.now(UTC)
    await db_session.commit()

    assert await tunnel.svc.teardown_tunnel(tunnel.row.id, tunnel.org.id) is True
    assert tunnel.box.calls == [("remove_vpn_config", "aa:bb:cc:00:01:00")]


async def test_the_teardown_route_says_the_tunnel_was_kept(
    db_session, tunnel, mode, monkeypatch
) -> None:
    from app.api.v1.endpoints import vpn_orchestration as api

    tunnel.box.answer = AdapterResult.fail("gateway refused")
    monkeypatch.setattr(api, "VPNOrchestrationService", lambda _db: tunnel.svc)
    user = SimpleNamespace(
        id=uuid4(),
        organization_id=tunnel.org.id,
        is_superuser=True,
        role="super_admin",
        can_access_site=lambda _site_id: True,
    )

    import json

    response = await api.teardown_tunnel(tunnel.row.id, local_only=False, db=db_session, user=user)

    assert response.status_code == 200
    body = json.loads(response.body)
    assert body["success"] is False and body["record_kept"] is True
    assert "so FreeSDN kept it" in body["reason"] and "gateway refused" in body["reason"]
    assert not await _tunnel_gone(db_session, tunnel)

    # Once it is gone, the route answers 204 with no body, as before.
    tunnel.box.answer = AdapterResult.ok()
    assert (
        await api.teardown_tunnel(tunnel.row.id, local_only=False, db=db_session, user=user) is None
    )
    assert await _tunnel_gone(db_session, tunnel)

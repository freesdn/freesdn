# SPDX-License-Identifier: AGPL-3.0-only
"""Real ledger/SQL checks with an isolated fake controller; no hardware writes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, create_autospec
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.adapters.omada.client import OmadaApiClient
from app.api.v1.endpoints import switches
from app.core.dependencies import CurrentUser
from app.core.site_access import current_user_var
from app.models.core import Controller, Organization, Site, User, UserRole
from app.models.devices import Device, DevicePort
from app.models.staging import AdapterPendingChange
from app.services.adapter_omada_switch_ports import GatewaySwitchPortsService
from app.services.adapter_staging import AdapterStagingService


@pytest.fixture
async def port_context(db_session, monkeypatch):
    org = Organization(id=uuid4(), name="Port governance fixture", slug=uuid4().hex)
    db_session.add(org)
    await db_session.flush()
    site = Site(id=uuid4(), organization_id=org.id, name="Fixture site", slug=uuid4().hex)
    user = User(
        id=uuid4(),
        organization_id=org.id,
        email=f"{uuid4().hex}@example.invalid",
        username=uuid4().hex,
        hashed_password="not-a-login",
        role=UserRole.ORG_ADMIN,
    )
    db_session.add_all([site, user])
    await db_session.flush()
    ctrl = Controller(
        id=uuid4(),
        site_id=site.id,
        name="Fake controller",
        controller_type="omada",
        host="192.0.2.10",
        port=8043,
        site_mappings={"native-site": str(site.id)},
    )
    db_session.add(ctrl)
    await db_session.flush()
    device = Device(
        id=uuid4(),
        site_id=site.id,
        controller_id=ctrl.id,
        name="Fake switch",
        device_type="switch",
        mac_address="02:" + ":".join(f"{value:02x}" for value in uuid4().bytes[:5]),
        device_metadata={"_omada_site_id": "native-site"},
    )
    db_session.add(device)
    await db_session.flush()
    port = DevicePort(device_id=device.id, port_number=1, is_enabled=True, is_poe_enabled=True)
    db_session.add(port)
    await db_session.commit()
    # Enforce the real client signatures: a permissive AsyncMock alone could
    # hide a broken readback argument or a misspelled controller method.
    client = create_autospec(OmadaApiClient, instance=True)
    client.update_switch_port.return_value = {}
    client.get_switch_port_overrides.return_value = {"enable": False, "poe": {"enable": False}}
    client_factory = AsyncMock(return_value=client)
    monkeypatch.setattr(GatewaySwitchPortsService, "_get_client", client_factory)
    monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: False))
    principal = CurrentUser(user=user, permissions=["*"])
    token = current_user_var.set(principal)
    try:
        yield SimpleNamespace(
            db=db_session,
            org=org,
            site=site,
            user=principal,
            ctrl=ctrl,
            device=device,
            port=port,
            client=client,
            client_factory=client_factory,
        )
    finally:
        current_user_var.reset(token)


@pytest.mark.parametrize("kind", ["enabled", "poe"])
async def test_synchronous_actions_use_ledger_and_fresh_readback(port_context, kind):
    c = port_context
    endpoint = switches.toggle_port if kind == "enabled" else switches.toggle_port_poe
    response = await endpoint(
        str(c.device.id), 1, switches.PortToggleIn(enabled=False, force=True), c.db, c.user
    )
    change = await c.db.get(AdapterPendingChange, UUID(response.data["change_id"]))
    assert response.success and response.data["readback_verified"]
    assert change.status == "applied" and change.created_by == c.user.id
    assert change.site_id == c.site.id and change.organization_id == c.org.id
    assert change.feature == f"switch.port.{kind}"
    expected = {"enable": False} if kind == "enabled" else {"poe": {"enable": False}}
    assert c.client.update_switch_port.await_args.args[-1] == expected
    assert c.client.get_switch_port_overrides.await_args.kwargs == {"fresh": True}
    await c.db.refresh(c.port)
    assert (c.port.is_enabled if kind == "enabled" else c.port.is_poe_enabled) is False
    # A duplicate apply cannot send the hardware operation again.
    svc = GatewaySwitchPortsService(c.db)
    with pytest.raises(HTTPException) as exc:
        await svc.staging.apply_change(change.id, force=True, applier=svc.build_applier(change))
    assert exc.value.status_code == 409
    c.client.update_switch_port.assert_awaited_once()


@pytest.mark.parametrize("failure", ["missing", "mismatch", "connect_failure"])
async def test_acknowledged_but_unverified_write_requires_reconciliation(port_context, failure):
    c = port_context
    if failure == "connect_failure":
        c.client.get_switch_port_overrides.side_effect = httpx.ConnectError("fake read failure")
    else:
        c.client.get_switch_port_overrides.return_value = (
            {} if failure == "missing" else {"enable": True}
        )
    with pytest.raises(HTTPException) as exc:
        await switches.toggle_port(
            str(c.device.id), 1, switches.PortToggleIn(enabled=False, force=True), c.db, c.user
        )
    assert exc.value.status_code == 502 and "staged change" in exc.value.detail
    row = (
        await c.db.execute(
            select(AdapterPendingChange).where(AdapterPendingChange.organization_id == c.org.id)
        )
    ).scalar_one()
    assert row.status == "reconciliation_required" and row.applied_at is None
    assert "readback" in row.failure_reason
    await c.db.refresh(c.port)
    assert c.port.is_enabled is True
    c.client.update_switch_port.assert_awaited_once()
    svc = GatewaySwitchPortsService(c.db)
    with pytest.raises(HTTPException) as retry:
        await svc.staging.apply_change(row.id, force=True, applier=svc.build_applier(row))
    assert retry.value.status_code == 409
    c.client.update_switch_port.assert_awaited_once()


@pytest.mark.parametrize(
    "guard", ["read_only", "force", "foreign_org", "missing_port", "site_grant"]
)
async def test_refusal_creates_no_change_and_calls_no_controller(port_context, monkeypatch, guard):
    c = port_context
    user = c.user
    if guard == "read_only":
        monkeypatch.setattr(AdapterStagingService, "is_read_only", staticmethod(lambda: True))
    elif guard == "foreign_org":
        user = CurrentUser(
            user=SimpleNamespace(id=c.user.id, organization_id=uuid4(), role=UserRole.ORG_ADMIN),
            permissions=["*"],
        )
    elif guard == "site_grant":
        user = CurrentUser(
            user=SimpleNamespace(id=c.user.id, organization_id=c.org.id, role="site_admin"),
            permissions=["network:write"],
            accessible_site_ids={uuid4()},
        )
    with pytest.raises(HTTPException) as exc:
        await switches.toggle_port(
            str(c.device.id),
            99 if guard == "missing_port" else 1,
            switches.PortToggleIn(enabled=False, force=guard != "force"),
            c.db,
            user,
        )
    assert exc.value.status_code == (403 if guard in {"read_only", "force"} else 404)
    c.client_factory.assert_not_awaited()
    assert (
        not (
            await c.db.execute(
                select(AdapterPendingChange).where(AdapterPendingChange.organization_id == c.org.id)
            )
        )
        .scalars()
        .all()
    )


async def test_mapping_change_between_stage_and_apply_blocks_write(port_context):
    c = port_context
    svc = GatewaySwitchPortsService(c.db)
    change = await svc.stage_state(c.device, 1, False, "enabled", c.org.id, c.user.id)
    c.ctrl.site_mappings = {"different-native-site": str(c.site.id)}
    await c.db.commit()
    with pytest.raises(HTTPException) as exc:
        await svc.staging.apply_change(change.id, force=True, applier=svc.build_applier(change))
    assert exc.value.status_code == 409
    c.client_factory.assert_not_awaited()


async def test_serialized_controller_rejection_never_reaches_readback(port_context):
    c = port_context
    c.client.update_switch_port.return_value = {"success": False, "error": "configuration refused"}
    with pytest.raises(HTTPException) as exc:
        await switches.toggle_port(
            str(c.device.id), 1, switches.PortToggleIn(enabled=False, force=True), c.db, c.user
        )
    assert exc.value.status_code == 502
    c.client.get_switch_port_overrides.assert_not_awaited()
    row = (
        await c.db.execute(
            select(AdapterPendingChange).where(AdapterPendingChange.organization_id == c.org.id)
        )
    ).scalar_one()
    assert row.status == "failed"


async def test_pending_change_api_uses_the_same_verified_applier(port_context):
    from app.api.v1.endpoints.adapter_omada_vpn import apply_change
    from app.schemas.gateway_vpn import ApplyPendingChangeRequest

    c = port_context
    svc = GatewaySwitchPortsService(c.db)
    change = await svc.stage_state(c.device, 1, False, "poe", c.org.id, c.user.id)
    response = await apply_change(
        change.id,
        ApplyPendingChangeRequest(force=True),
        c.user,
        c.db,
    )
    assert response.status == "applied"
    assert response.applied_response["readback_verified"] is True
    c.client.update_switch_port.assert_awaited_once()

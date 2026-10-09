# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Real committed inventory must not be reassigned across tenant boundaries."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError

from app.adapters.base import DiscoveredDevice
from app.db.session import CelerySessionLocal
from app.models.core import Controller, Organization, Site
from app.models.devices import Device
from app.tasks import discovery


@pytest_asyncio.fixture
async def inventory(monkeypatch):
    org, other, site, sibling, foreign, controller, peer, external, device = [
        uuid4() for _ in range(9)
    ]
    mac = "AA:BB:" + ":".join(f"{x:02X}" for x in uuid4().bytes[:4])
    async with CelerySessionLocal() as db:
        db.add_all(
            [Organization(id=i, name="Owned inventory fixture", slug=i.hex) for i in [org, other]]
        )
        await db.flush()
        db.add_all(
            [
                Site(id=i, name="Owned site", slug=i.hex, organization_id=o)
                for i, o in [(site, org), (sibling, org), (foreign, other)]
            ]
        )
        await db.flush()
        db.add_all(
            [
                Controller(
                    id=i,
                    name="Owned controller",
                    controller_type="omada",
                    host="127.0.0.1",
                    port=1,
                    site_id=s,
                    is_active=True,
                    sync_enabled=True,
                    config={},
                )
                for i, s in [(controller, site), (peer, sibling), (external, foreign)]
            ]
        )
        await db.commit()
    discovered = DiscoveredDevice(
        mac_address=mac,
        ip_address="192.0.2.10",
        name="Observed own device",
        vendor="Owned fixture",
        model="fixture",
        firmware_version="1",
        device_type="access_point",
        status="online",
        raw_data={},
    )
    state = SimpleNamespace(
        org=org,
        other=other,
        site=site,
        sibling=sibling,
        foreign=foreign,
        controller=controller,
        peer=peer,
        external=external,
        device=device,
        mac=mac,
        devices=[discovered],
        adapter_calls=0,
    )

    class Adapter:
        async def __aenter__(self):
            state.adapter_calls += 1
            return self

        async def __aexit__(self, *_args):
            return False

        async def discover_devices(self):
            if getattr(state, "before_return", None) is not None:
                await state.before_return()
            return state.devices

    monkeypatch.setattr(discovery, "get_adapter", lambda *_args, **_kwargs: Adapter())
    state.events = AsyncMock()
    monkeypatch.setattr(discovery, "publish_device_event", state.events)
    monkeypatch.setattr(discovery, "publish_controller_event", AsyncMock())
    monkeypatch.setattr(discovery, "deep_sync_controller", AsyncMock(return_value={}))
    from app.services.ztp import ZTPEngine

    monkeypatch.setattr(ZTPEngine, "evaluate_device", AsyncMock(return_value=None))
    try:
        yield state
    finally:
        async with CelerySessionLocal() as db:
            await db.execute(delete(Device).where(Device.mac_address == mac))
            await db.execute(
                delete(Controller).where(Controller.id.in_([controller, peer, external]))
            )
            await db.execute(delete(Site).where(Site.id.in_([site, sibling, foreign])))
            await db.execute(delete(Organization).where(Organization.id.in_([org, other])))
            await db.commit()


async def seed_device(fixture, owner_controller, owner_site):
    async with CelerySessionLocal() as writer:
        writer.add(
            Device(
                id=fixture.device,
                controller_id=owner_controller,
                site_id=owner_site,
                name="Keep original name",
                ip_address="192.0.2.20",
                mac_address=fixture.mac,
                device_type="access_point",
                model="Original model",
                status="offline",
                device_metadata={"owned": "preserve-original"},
            )
        )
        await writer.commit()


async def snapshot(fixture):
    async with CelerySessionLocal() as observer:
        row = await observer.get(Device, fixture.device)
        return (
            row.controller_id,
            row.site_id,
            row.name,
            row.ip_address,
            row.model,
            row.status,
            row.device_metadata,
            row.created_at,
            row.updated_at,
            row.last_seen,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["preload", "concurrent-insert"])
async def test_foreign_mac_never_reassigns_or_updates_existing_inventory(
    inventory, monkeypatch, path
):
    f = inventory
    if path == "preload":
        await seed_device(f, f.external, f.foreign)
    else:
        inserted = False

        @asynccontextmanager
        async def isolated_session():
            nonlocal inserted
            async with CelerySessionLocal() as db:
                execute = db.execute

                async def observed_execute(statement, *args, **kwargs):
                    nonlocal inserted
                    result = await execute(statement, *args, **kwargs)
                    if not inserted and "devices.devices.mac_address IN" in str(statement):
                        inserted = True
                        # Commit after the real preload SELECT, before its caller INSERT.
                        await seed_device(f, f.external, f.foreign)
                        f.original = await snapshot(f)
                    return result

                monkeypatch.setattr(db, "execute", observed_execute)
                yield db

        monkeypatch.setattr(discovery, "AsyncSessionLocal", isolated_session)
    if path == "preload":
        f.original = await snapshot(f)
    result = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert await snapshot(f) == f.original
    assert result["success"] is False
    assert result["error"] == "discovery_device_scope_conflict"
    f.events.assert_not_awaited()
    async with CelerySessionLocal() as observer:
        assert (
            await observer.execute(select(Device.id).where(Device.controller_id == f.controller))
        ).scalars().all() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mapping", ["foreign", "deleted", "disabled", "missing"])
async def test_invalid_target_site_mapping_never_materializes_device(inventory, mapping):
    f = inventory
    target = f.foreign if mapping == "foreign" else uuid4() if mapping == "missing" else f.sibling
    async with CelerySessionLocal() as writer:
        await writer.execute(
            update(Controller)
            .where(Controller.id == f.controller)
            .values(config={"site_mappings": {"external-site": str(target)}})
        )
        if mapping in ["deleted", "disabled"]:
            await writer.execute(
                update(Site)
                .where(Site.id == target)
                .values(
                    **(
                        {"deleted_at": datetime.now(UTC)}
                        if mapping == "deleted"
                        else {"is_active": False}
                    )
                )
            )
        await writer.commit()
    f.devices[0].raw_data = {"_omada_site_id": "external-site"}
    result = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert result["success"] is False and result["error"] == "discovery_device_scope_conflict"
    async with CelerySessionLocal() as observer:
        assert (
            await observer.execute(select(Device.id).where(Device.mac_address == f.mac))
        ).scalars().all() == []
    f.events.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["deleted", "disabled"])
async def test_unavailable_controller_site_refuses_adapter_access(inventory, state):
    f = inventory
    async with CelerySessionLocal() as writer:
        await writer.execute(
            update(Site)
            .where(Site.id == f.site)
            .values(
                **(
                    {"deleted_at": datetime.now(UTC)}
                    if state == "deleted"
                    else {"is_active": False}
                )
            )
        )
        await writer.commit()
    result = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert result["success"] is False and f.adapter_calls == 0
    f.events.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode", ["new", "same-controller", "same-tenant-peer-controller", "same-tenant-site-mapping"]
)
async def test_legitimate_inventory_discovery_keeps_existing_contract(inventory, mode):
    f = inventory
    if mode in ["same-controller", "same-tenant-peer-controller"]:
        await seed_device(
            f,
            f.controller if mode == "same-controller" else f.peer,
            f.site if mode == "same-controller" else f.sibling,
        )
    if mode == "same-tenant-site-mapping":
        async with CelerySessionLocal() as writer:
            await writer.execute(
                update(Controller)
                .where(Controller.id == f.controller)
                .values(config={"site_mappings": {"external-site": str(f.sibling)}})
            )
            await writer.commit()
        f.devices[0].raw_data = {"_omada_site_id": "external-site"}
    result = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert result["success"] is True
    async with CelerySessionLocal() as observer:
        row = (
            await observer.execute(select(Device).where(Device.mac_address == f.mac))
        ).scalar_one()
        assert row.controller_id == f.controller and row.name == "Observed own device"
        assert row.site_id == (f.sibling if mode == "same-tenant-site-mapping" else f.site)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcomes",
    [
        ("ok", "ok"),
        ("ok", "refused"),
        ("ok", "exception"),
        ("refused", "refused"),
        ("exception", "exception"),
        ("refused", "exception"),
    ],
)
async def test_aggregate_does_not_report_all_success_after_controller_refusal_or_exception(
    inventory, monkeypatch, outcomes
):
    f = inventory
    selected = {str(f.controller): outcomes[0], str(f.peer): outcomes[1]}

    async def result(controller_id):
        mode = selected[controller_id]
        if mode == "exception":
            raise RuntimeError("synthetic-controller-error")
        return {
            "success": mode == "ok",
            "devices_discovered": 7 if mode == "ok" else 0,
            "devices_created": 1 if mode == "ok" else 0,
            "controller_id": controller_id,
            "error": None if mode == "ok" else "discovery_device_scope_conflict",
        }

    monkeypatch.setattr(discovery, "_discover_devices_for_controller", result)
    observed = await discovery._discover_all_devices(str(f.org))
    successful = outcomes.count("ok")
    assert observed["success"] is (successful == 2)
    assert observed["controllers_processed"] == 2
    assert observed["controllers_successful"] == successful
    assert observed["controllers_failed"] == 2 - successful
    assert observed["total_devices_discovered"] == 7 * successful


@pytest.mark.asyncio
async def test_empty_enabled_controller_set_is_an_explicit_no_work_success():
    result = await discovery._discover_all_devices(str(uuid4()))
    assert result["success"] is True and result["controllers_processed"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "controller-moved",
        "controller-disabled",
        "controller-deleted",
        "site-moved",
        "site-disabled",
        "org-disabled",
        "org-deleted",
    ],
)
async def test_committed_authority_change_during_adapter_io_refuses_captured_inventory(
    inventory, change
):
    f = inventory
    model, identity, values = {
        "controller-moved": (Controller, f.controller, {"site_id": f.foreign}),
        "controller-disabled": (Controller, f.controller, {"is_active": False}),
        "controller-deleted": (Controller, f.controller, {"deleted_at": datetime.now(UTC)}),
        "site-moved": (Site, f.site, {"organization_id": f.other}),
        "site-disabled": (Site, f.site, {"is_active": False}),
        "org-disabled": (Organization, f.org, {"is_active": False}),
        "org-deleted": (Organization, f.org, {"deleted_at": datetime.now(UTC)}),
    }[change]

    async def committed_change():
        async with CelerySessionLocal() as writer:
            await writer.execute(update(model).where(model.id == identity).values(**values))
            await writer.commit()

    f.before_return = committed_change
    result = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert result["success"] is False and result["error"] == "discovery_device_scope_conflict"
    assert f.adapter_calls == 1
    async with CelerySessionLocal() as observer:
        assert (
            await observer.execute(select(Device.id).where(Device.mac_address == f.mac))
        ).scalars().all() == []
    f.events.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("authority", ["controller", "site", "organization"])
async def test_authority_rows_cannot_change_during_inventory_transaction(
    inventory, monkeypatch, authority
):
    f = inventory
    model, identity, values = {
        "controller": (Controller, f.controller, {"site_id": f.foreign}),
        "site": (Site, f.site, {"organization_id": f.other}),
        "organization": (Organization, f.org, {"is_active": False}),
    }[authority]
    attempts = []

    async def check_independent_write(*_args, **_kwargs):
        async with CelerySessionLocal() as writer:
            await writer.execute(text("SET LOCAL lock_timeout = '100ms'"))
            try:
                await writer.execute(update(model).where(model.id == identity).values(**values))
                await writer.commit()
            except DBAPIError as error:
                attempts.append(getattr(error.orig, "sqlstate", None) == "55P03")
                await writer.rollback()
            else:
                attempts.append(False)

    monkeypatch.setattr(discovery, "publish_device_event", check_independent_write)
    result = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert result["success"] is True
    assert attempts == [True]
    async with CelerySessionLocal() as observer:
        row = (
            await observer.execute(select(Device).where(Device.mac_address == f.mac))
        ).scalar_one()
        assert row.controller_id == f.controller and row.site_id == f.site

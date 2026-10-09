# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Discovery failure bookkeeping must not commit a partly failed inventory batch."""

import json
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select, update

from app.db.session import CelerySessionLocal
from app.models.core import Controller
from app.models.devices import Device
from app.tasks import discovery
from tests.tasks.test_discovery_tenant_device_authority import inventory as inventory
from tests.tasks.test_discovery_tenant_device_authority import seed_device, snapshot

MARKER = "owned-private-adapter-credential-diagnostic"


@pytest.mark.asyncio
async def test_failure_history_never_commits_partial_existing_device_update(inventory, monkeypatch):
    f = inventory
    await seed_device(f, f.controller, f.site)
    before = await snapshot(f)
    monkeypatch.setattr(
        discovery, "publish_device_event", AsyncMock(side_effect=RuntimeError(MARKER))
    )
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    assert await snapshot(f) == before


@pytest.mark.asyncio
async def test_failure_history_never_commits_partial_new_device_insert(inventory, monkeypatch):
    f = inventory
    monkeypatch.setattr(
        discovery, "publish_device_event", AsyncMock(side_effect=RuntimeError(MARKER))
    )
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    async with CelerySessionLocal() as db:
        assert await db.scalar(select(Device.id).where(Device.mac_address == f.mac)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["return", "last_error", "history", "event", "log"])
async def test_failed_discovery_never_exposes_raw_adapter_diagnostic(
    inventory, monkeypatch, caplog, boundary
):
    f = inventory
    monkeypatch.setattr(
        discovery,
        "get_adapter",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(MARKER)),
    )
    event = AsyncMock()
    monkeypatch.setattr(discovery, "publish_controller_event", event)
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    async with CelerySessionLocal() as db:
        controller = await db.get(Controller, f.controller)
        exposed = {
            "return": outcome,
            "last_error": controller.last_error,
            "history": controller.config.get("error_history"),
            "event": str(event.call_args_list),
            "log": caplog.text,
        }[boundary]
        assert MARKER not in json.dumps(exposed, default=str)


@pytest.mark.asyncio
async def test_adapter_failure_after_reassignment_cannot_mark_new_tenant_controller(inventory):
    f = inventory

    async def change_authority_then_fail():
        async with CelerySessionLocal() as writer:
            await writer.execute(
                update(Controller)
                .where(Controller.id == f.controller)
                .values(site_id=f.foreign, last_error="Preserve new owner status")
            )
            await writer.commit()
        raise RuntimeError(MARKER)

    f.before_return = change_authority_then_fail
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    async with CelerySessionLocal() as db:
        controller = await db.get(Controller, f.controller)
        assert controller.last_error == "Preserve new owner status"


@pytest.mark.asyncio
async def test_successful_discovery_still_commits_inventory(inventory):
    f = inventory
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is True
    async with CelerySessionLocal() as db:
        row = await db.scalar(select(Device).where(Device.mac_address == f.mac))
        assert row is not None and row.name == f.devices[0].name


@pytest.mark.asyncio
async def test_failure_does_not_delete_previously_committed_inventory(inventory, monkeypatch):
    f = inventory
    await seed_device(f, f.controller, f.site)
    before = await snapshot(f)

    def failed_adapter(*_args, **_kwargs):
        raise RuntimeError(MARKER)

    monkeypatch.setattr(discovery, "get_adapter", failed_adapter)
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    assert await snapshot(f) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changed",
    [
        "controller-disabled",
        "controller-deleted",
        "site-disabled",
        "site-moved",
        "org-disabled",
        "org-deleted",
    ],
)
async def test_failed_adapter_rechecks_live_authority_before_recording_error(inventory, changed):
    from datetime import UTC, datetime

    from app.models.core import Organization, Site

    f = inventory
    async with CelerySessionLocal() as writer:
        await writer.execute(
            update(Controller)
            .where(Controller.id == f.controller)
            .values(last_error="Preserve current authority")
        )
        await writer.commit()

    async def change_authority_then_fail():
        async with CelerySessionLocal() as writer:
            model, identity, fields = {
                "controller-disabled": (Controller, f.controller, {"is_active": False}),
                "controller-deleted": (Controller, f.controller, {"deleted_at": datetime.now(UTC)}),
                "site-disabled": (Site, f.site, {"is_active": False}),
                "site-moved": (Site, f.site, {"organization_id": f.other}),
                "org-disabled": (Organization, f.org, {"is_active": False}),
                "org-deleted": (Organization, f.org, {"deleted_at": datetime.now(UTC)}),
            }[changed]
            await writer.execute(update(model).where(model.id == identity).values(**fields))
            await writer.commit()
        raise RuntimeError(MARKER)

    f.before_return = change_authority_then_fail
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    async with CelerySessionLocal() as db:
        # Include a deliberately soft-deleted controller in this independent assertion.
        error = await db.scalar(
            select(Controller.last_error)
            .where(Controller.id == f.controller)
            .execution_options(include_deleted=True)
        )
        assert error == "Preserve current authority"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "history",
    [
        "invalid",
        {"error": MARKER},
        [None, MARKER],
        [{"timestamp": MARKER, "error": MARKER}],
        [{"timestamp": "2026-09-24T00:00:00+00:00", "error": MARKER, "extra": MARKER}],
    ],
)
async def test_failure_history_is_bounded_safe_and_tolerates_legacy_shapes(
    inventory, monkeypatch, history
):
    f = inventory
    async with CelerySessionLocal() as writer:
        await writer.execute(
            update(Controller)
            .where(Controller.id == f.controller)
            .values(config={"error_history": history, "preserve_setting": "owned"})
        )
        await writer.commit()

    def failed_adapter(*_args, **_kwargs):
        raise RuntimeError(MARKER)

    monkeypatch.setattr(discovery, "get_adapter", failed_adapter)
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    async with CelerySessionLocal() as db:
        controller = await db.get(Controller, f.controller)
        assert controller.config["preserve_setting"] == "owned"
        assert MARKER not in json.dumps(controller.config)
        assert 1 <= len(controller.config["error_history"]) <= 10


@pytest.mark.asyncio
async def test_failure_event_outage_preserves_failed_outcome_without_raw_error(
    inventory, monkeypatch, caplog
):
    f = inventory

    def failed_adapter(*_args, **_kwargs):
        raise RuntimeError(MARKER)

    monkeypatch.setattr(discovery, "get_adapter", failed_adapter)

    async def event(kind, **_kwargs):
        if kind == discovery.EventType.CONTROLLER_SYNC_FAILED:
            raise RuntimeError(MARKER)

    monkeypatch.setattr(discovery, "publish_controller_event", event)
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    assert MARKER not in json.dumps(outcome) + caplog.text
    async with CelerySessionLocal() as db:
        controller = await db.get(Controller, f.controller)
        assert controller.last_error and MARKER not in controller.last_error


@pytest.mark.asyncio
@pytest.mark.parametrize("existing", [False, True])
async def test_failed_database_statement_rolls_back_before_status_bookkeeping(inventory, existing):
    f = inventory
    if existing:
        await seed_device(f, f.controller, f.site)
        before = await snapshot(f)
    f.devices[0].name = "x" * 256  # Real PostgreSQL varchar(255) rejection.
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    async with CelerySessionLocal() as db:
        controller = await db.get(Controller, f.controller)
        assert controller.last_error and controller.status == "error"
        if not existing:
            assert await db.scalar(select(Device.id).where(Device.mac_address == f.mac)) is None
    if existing:
        assert await snapshot(f) == before


@pytest.mark.asyncio
async def test_late_event_failure_does_not_undo_already_committed_inventory(inventory, monkeypatch):
    f = inventory

    async def event(kind, **_kwargs):
        if kind == discovery.EventType.CONTROLLER_SYNC_COMPLETED:
            raise RuntimeError(MARKER)

    monkeypatch.setattr(discovery, "publish_controller_event", event)
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    async with CelerySessionLocal() as db:
        row = await db.scalar(select(Device).where(Device.mac_address == f.mac))
        assert row is not None and row.name == f.devices[0].name


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["controller", "site", "organization"])
async def test_error_record_holds_current_authority_until_commit(inventory, monkeypatch, target):
    from contextlib import asynccontextmanager

    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    from app.models.core import Organization, Site

    f = inventory
    observed = []

    def failed_adapter(*_args, **_kwargs):
        raise RuntimeError(MARKER)

    monkeypatch.setattr(discovery, "get_adapter", failed_adapter)

    @asynccontextmanager
    async def session():
        async with CelerySessionLocal() as db:
            commit = db.commit

            async def check_then_commit():
                model, identity = {
                    "controller": (Controller, f.controller),
                    "site": (Site, f.site),
                    "organization": (Organization, f.org),
                }[target]
                async with CelerySessionLocal() as writer:
                    await writer.execute(text("SET LOCAL lock_timeout = '100ms'"))
                    try:
                        await writer.execute(
                            update(model).where(model.id == identity).values(is_active=False)
                        )
                    except DBAPIError as exc:
                        observed.append(getattr(exc.orig, "sqlstate", None) == "55P03")
                    else:
                        observed.append(False)
                    await writer.rollback()
                await commit()

            db.commit = check_then_commit
            yield db

    monkeypatch.setattr(discovery, "AsyncSessionLocal", session)
    outcome = await discovery._discover_devices_for_controller_impl(str(f.controller))
    assert outcome["success"] is False
    assert observed == [True]

# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Delayed onboarding may not use inactive scope or commit a stale result."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from fastapi import BackgroundTasks
from sqlalchemy import delete, select, update
from sqlalchemy.exc import DBAPIError

import app.db
from app.adapters.registry import adapter_registry
from app.api.v1.endpoints import controllers
from app.core.dependencies import CurrentUser
from app.db.session import CelerySessionLocal
from app.models.core import Controller, Organization, Site, User
from app.schemas.core import ControllerCreate
from app.services.organization import OrganizationService
from app.tasks.discovery import discover_devices_for_controller

AUTHORITY_CHANGES = [
    "controller-disabled",
    "controller-deleted",
    "controller-moved",
    "controller-foreign",
    "site-disabled",
    "site-deleted",
    "site-moved",
    "org-disabled",
    "org-deleted",
]
CONNECTION_CHANGES = ["config", "host", "port", "ssl", "verify", "type", "status", "revision"]
MARKER = "owned-private-initial-controller-diagnostic"


@pytest_asyncio.fixture
async def onboarding(monkeypatch):
    org, other, site, sibling, foreign = [uuid4() for _ in range(5)]
    f = SimpleNamespace(
        org=org,
        other=other,
        site=site,
        sibling=sibling,
        foreign=foreign,
        controller=None,
        outcome="success",
        during_io=None,
        before_commit=None,
        sessions=[],
        observed_transactions=[],
        options=[],
        calls=0,
    )
    async with CelerySessionLocal() as db:
        db.add_all(
            [
                Organization(id=org, name="Owned onboarding", slug=org.hex),
                Organization(id=other, name="Other onboarding", slug=other.hex),
            ]
        )
        await db.flush()
        db.add_all(
            [
                Site(
                    id=identity, organization_id=organization, name="Owned site", slug=identity.hex
                )
                for identity, organization in [(site, org), (sibling, org), (foreign, other)]
            ]
        )
        await db.commit()

    @asynccontextmanager
    async def session_factory():
        async with CelerySessionLocal() as db:
            f.sessions.append(db)
            commit = db.commit

            async def observed_commit():
                if f.before_commit:
                    await f.before_commit()
                await commit()

            db.commit = observed_commit
            yield db

    class Adapter:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def test_connection(self):
            f.calls += 1
            f.observed_transactions.append(any(s.in_transaction() for s in f.sessions))
            if f.during_io:
                await f.during_io()
            if f.outcome == "exception":
                raise RuntimeError(MARKER)
            return SimpleNamespace(success=f.outcome == "success", error=MARKER)

    def adapter(**kwargs):
        f.options.append(kwargs)
        return Adapter()

    monkeypatch.setattr(app.db, "async_session_factory", session_factory)
    monkeypatch.setattr(OrganizationService, "_check_quota", AsyncMock())
    monkeypatch.setattr(adapter_registry, "create_adapter", adapter)
    f.publish = MagicMock()
    monkeypatch.setattr(discover_devices_for_controller, "apply_async", f.publish)
    actor = CurrentUser(
        user=User(
            id=uuid4(),
            email="owned@example.invalid",
            organization_id=org,
            role="org_admin",
            hashed_password="owned",
            is_active=True,
        ),
        permissions=["controller:create"],
        accessible_site_ids=set(),
    )
    background = BackgroundTasks()
    try:
        async with CelerySessionLocal() as db:
            row = await controllers.create_controller(
                ControllerCreate(
                    site_id=site,
                    name="Owned delayed controller",
                    controller_type="omada",
                    host="192.168.254.254",
                    port=8043,
                    username="owned",
                    password="owned",
                ),
                actor,
                db,
                background,
                confirm_public_host=False,
            )
            f.controller = row.id
        assert len(background.tasks) == 1
        f.run = background
        yield f
    finally:
        async with CelerySessionLocal() as db:
            if f.controller:
                await db.execute(delete(Controller).where(Controller.id == f.controller))
            await db.execute(delete(Site).where(Site.id.in_([site, sibling, foreign])))
            await db.execute(delete(Organization).where(Organization.id.in_([org, other])))
            await db.commit()


async def change(f, name):
    model, identity, fields = {
        "controller-disabled": (Controller, f.controller, {"is_active": False}),
        "controller-deleted": (Controller, f.controller, {"deleted_at": datetime.now(UTC)}),
        "controller-moved": (Controller, f.controller, {"site_id": f.sibling}),
        "controller-foreign": (Controller, f.controller, {"site_id": f.foreign}),
        "site-disabled": (Site, f.site, {"is_active": False}),
        "site-deleted": (Site, f.site, {"deleted_at": datetime.now(UTC)}),
        "site-moved": (Site, f.site, {"organization_id": f.other}),
        "org-disabled": (Organization, f.org, {"is_active": False}),
        "org-deleted": (Organization, f.org, {"deleted_at": datetime.now(UTC)}),
        "config": (Controller, f.controller, {"config": {"username": "new-owner"}}),
        "host": (Controller, f.controller, {"host": "192.168.254.253"}),
        "port": (Controller, f.controller, {"port": 9443}),
        "ssl": (Controller, f.controller, {"use_ssl": False}),
        "verify": (Controller, f.controller, {"verify_ssl": False}),
        "type": (Controller, f.controller, {"controller_type": "unifi"}),
        "status": (Controller, f.controller, {"status": "error", "last_error": "Newer result"}),
        "revision": (
            Controller,
            f.controller,
            {"updated_at": datetime.now(UTC) + timedelta(seconds=1)},
        ),
    }[name]
    async with CelerySessionLocal() as db:
        await db.execute(update(model).where(model.id == identity).values(**fields))
        await db.commit()


async def outcome(f):
    async with CelerySessionLocal() as db:
        return (
            await db.execute(
                select(Controller.status, Controller.last_error)
                .where(Controller.id == f.controller)
                .execution_options(include_deleted=True)
            )
        ).one()


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", AUTHORITY_CHANGES)
async def test_initial_check_requires_original_active_scope_before_contact(onboarding, changed):
    f = onboarding
    await change(f, changed)
    before = await outcome(f)
    await f.run()
    assert f.calls == 0 and not f.options
    assert await outcome(f) == before
    f.publish.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", AUTHORITY_CHANGES + CONNECTION_CHANGES)
@pytest.mark.parametrize("result", ["success", "exception"])
async def test_changed_scope_or_connection_cannot_receive_stale_result(onboarding, changed, result):
    f = onboarding
    f.outcome = result
    expected = []

    async def concurrent_edit():
        await change(f, changed)
        expected.append(await outcome(f))

    f.during_io = concurrent_edit
    await f.run()
    assert f.calls == 1
    assert await outcome(f) == expected[0]
    f.publish.assert_not_called()


@pytest.mark.asyncio
async def test_controller_io_does_not_hold_database_transaction(onboarding):
    f = onboarding
    await f.run()
    assert f.observed_transactions == [False]
    assert await outcome(f) == ("connected", None)
    f.publish.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("model_name", ["controller", "site", "org"])
async def test_current_authority_is_locked_until_result_commit(onboarding, model_name):
    f = onboarding
    model = {"controller": Controller, "site": Site, "org": Organization}[model_name]
    observed = []

    async def try_concurrent_lock():
        async with CelerySessionLocal() as writer:
            try:
                await writer.execute(
                    select(model)
                    .where(model.id == getattr(f, model_name))
                    .with_for_update(nowait=True)
                )
            except DBAPIError as exc:
                observed.append(getattr(exc.orig, "sqlstate", None))
                await writer.rollback()
            else:
                observed.append("unlocked")

    f.before_commit = try_concurrent_lock
    await f.run()
    assert observed == ["55P03"]
    assert await outcome(f) == ("connected", None)
    f.publish.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "vendor,field,mode",
    [
        ("omada", "client_secret", "cloud"),
        ("proxmox", "token_secret", "local"),
        ("truenas", "password", "local"),
    ],
)
async def test_credential_failure_records_safe_error_without_device_contact(
    onboarding, vendor, field, mode, caplog
):
    f = onboarding
    wrong_key = Fernet(Fernet.generate_key()).encrypt(b"owned-foreign-credential").decode()
    async with CelerySessionLocal() as db:
        await db.execute(
            update(Controller)
            .where(Controller.id == f.controller)
            .values(
                controller_type=vendor,
                config={"connection_mode": mode, "token_id": "owned@pam!test", field: wrong_key},
            )
        )
        await db.commit()
    await f.run()
    status, error = await outcome(f)
    assert status == "error" and error and wrong_key not in error + caplog.text
    assert not f.calls and not f.options
    f.publish.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "result,status", [("success", "connected"), ("failure", "disconnected"), ("exception", "error")]
)
async def test_unchanged_controller_records_current_result(onboarding, result, status, caplog):
    f = onboarding
    f.outcome = result
    await f.run()
    actual, error = await outcome(f)
    assert actual == status and MARKER not in (error or "") + caplog.text
    assert f.publish.call_count == int(result == "success")


@pytest.mark.asyncio
async def test_edit_before_execution_uses_current_configuration_in_original_scope(onboarding):
    f = onboarding
    await change(f, "host")
    await f.run()
    assert f.options[0]["host"] == "192.168.254.253"
    assert await outcome(f) == ("connected", None)

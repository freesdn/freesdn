"""Real-model/SQL regression for TrueNAS resolution; no NAS I/O.

Only the final network adapter builder is an owned observation boundary.
Real Controller/Site rows and the actual lookup/organization checks execute.
Inactive/wrong-type/unscoped refusal cases state the proposed safe contract;
their runtime outcome and later assertions are not assumed from source review.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import session as sessions
from app.db.session import create_test_engine
from app.models.core import Controller, Organization, Site
from app.services import adapter_truenas_storage
from app.services.backup import TrueNASStorageBackend


@pytest_asyncio.fixture
async def operations():
    """Independently committed owned Controller/Site rows, no auth/export drafts."""
    engine = create_test_engine()
    f = SimpleNamespace(engine=engine, org=uuid4(), other_org=uuid4(),
                        site=uuid4(), controller=uuid4())
    try:
        async with AsyncSession(engine) as db:
            db.add_all([
                Organization(id=i, name="Owned TrueNAS organization", slug=uuid4().hex)
                for i in (f.org, f.other_org)
            ])
            await db.flush()
            db.add(Site(id=f.site, organization_id=f.org,
                        name="Owned TrueNAS site", slug=uuid4().hex))
            await db.flush()
            db.add(Controller(id=f.controller, site_id=f.site,
                              name="Owned backup controller", controller_type="truenas",
                              host="nas.example.invalid", port=443, use_ssl=True,
                              verify_ssl=True, is_active=True,
                              config={"username": "owned", "password": "Owned encrypted reference"}))
            await db.commit()
        yield f
    finally:
        async with AsyncSession(engine) as db:
            await db.execute(delete(Controller).where(Controller.id == f.controller))
            await db.execute(delete(Site).where(Site.id == f.site))
            await db.execute(delete(Organization).where(Organization.id.in_([f.org, f.other_org])))
            await db.commit()
        await engine.dispose()


@pytest.mark.parametrize(
    "case",
    [
        "owned",
        "foreign-site",
        "deleted-controller",
        "deleted-site",
        "inactive",
        "wrong-type",
        "missing-organization",
        "missing-controller",
    ],
)
async def test_real_controller_lookup_obeys_site_owner_and_availability(
    operations, monkeypatch, case, record_property
):
    f = operations
    adapter = object()
    calls = []

    async def owned_build(controller):
        assert isinstance(controller, Controller)
        calls.append(controller.id)
        return adapter

    monkeypatch.setattr(
        sessions, "AsyncSessionLocal", lambda: AsyncSession(f.engine, expire_on_commit=False)
    )
    monkeypatch.setattr(adapter_truenas_storage, "build_truenas_adapter", owned_build)
    async with AsyncSession(f.engine) as db:
        if case == "foreign-site":
            await db.execute(
                update(Site).where(Site.id == f.site).values(organization_id=f.other_org)
            )
        elif case == "deleted-controller":
            await db.execute(
                update(Controller)
                .where(Controller.id == f.controller)
                .values(deleted_at=datetime.now(UTC))
            )
        elif case == "deleted-site":
            await db.execute(
                update(Site).where(Site.id == f.site).values(deleted_at=datetime.now(UTC))
            )
        elif case == "inactive":
            await db.execute(
                update(Controller).where(Controller.id == f.controller).values(is_active=False)
            )
        elif case == "wrong-type":
            await db.execute(
                update(Controller)
                .where(Controller.id == f.controller)
                .values(controller_type="unifi")
            )
        await db.commit()
    from uuid import uuid4

    config = {
        "controller_id": str(uuid4() if case == "missing-controller" else f.controller),
        "dataset_path": "tank/owned",
        "_organization_id": str(f.org),
    }
    if case == "missing-organization":
        config.pop("_organization_id")
    backend = TrueNASStorageBackend(config)
    result = None
    failure = None
    try:
        result = await backend._adapter()
    except Exception as exc:
        failure = exc
    record_property("adapter_builder_call_count", len(calls))
    record_property("actual_failure_type", type(failure).__name__ if failure else "none")
    if case == "owned":
        assert failure is None, type(failure).__name__
        assert result is adapter and calls == [f.controller]
    else:
        assert isinstance(failure, ValueError), type(failure).__name__
        assert calls == []

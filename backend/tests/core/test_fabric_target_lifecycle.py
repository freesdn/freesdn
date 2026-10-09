# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Execute the real controller predicate against SQL, without device or staging I/O.

The small SQLite fixture models row selection, not PostgreSQL constraints or
concurrent deletion. Production-database acceptance is a separate qualification.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.fabric.execution import OperationContext
from app.core.fabric.executor import OperationExecutor, _controller_in_org
from app.core.fabric.operations import Operation, OperationTier
from app.models.core import Controller, Site


@pytest.mark.asyncio
@pytest.mark.parametrize("limited", [False, True], ids=["unrestricted", "site-limited"])
@pytest.mark.parametrize(
    "state",
    [
        "live",
        "controller_deleted",
        "site_deleted",
        "both_deleted",
        "foreign",
        "missing_controller",
        "missing_site",
    ],
)
async def test_deleted_or_missing_target_never_reaches_staging(monkeypatch, state, limited):
    from app.services.adapter_staging import AdapterStagingService

    org, site_id, controller_id = uuid4(), uuid4(), uuid4()
    engine = create_engine("sqlite://")
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("ATTACH DATABASE ':memory:' AS core")
            # Deliberately omit constraints/defaults: this fixture exercises the
            # application's actual SELECT and JOIN, including missing parent rows.
            # SQLAlchemy still binds and decodes each mapped production column.
            for model in [Site, Controller]:
                columns = ", ".join('"' + column.name + '"' for column in model.__table__.columns)
                connection.exec_driver_sql(f"CREATE TABLE core.{model.__tablename__} ({columns})")
            if state != "missing_site":
                connection.execute(
                    Site.__table__.insert().values(
                        id=site_id,
                        organization_id=uuid4() if state == "foreign" else org,
                        name="Owned site",
                        slug="owned-site",
                        deleted_at=datetime.now(UTC)
                        if state in ["site_deleted", "both_deleted"]
                        else None,
                    )
                )
            if state != "missing_controller":
                connection.execute(
                    Controller.__table__.insert().values(
                        id=controller_id,
                        site_id=site_id,
                        name="Owned controller",
                        controller_type="omada",
                        host="controller.invalid",
                        port=443,
                        deleted_at=datetime.now(UTC)
                        if state in ["controller_deleted", "both_deleted"]
                        else None,
                    )
                )
            connection.commit()
            with Session(bind=connection) as session:

                class Database:
                    async def execute(self, statement):
                        return session.execute(statement)

                db = Database()
                row = await _controller_in_org(db, controller_id, org)
                stage = AsyncMock(return_value=SimpleNamespace(id=uuid4()))
                monkeypatch.setattr(AdapterStagingService, "stage_change", stage)
                op = Operation(
                    id="network.port.update",
                    title="Owned staged-write probe",
                    permission="network.manage",
                    write=True,
                    feature="network.port",
                    tier=OperationTier.NATIVE,
                    provider_id="network",
                )
                ctx = OperationContext(
                    org,
                    {"controller_id": str(controller_id)},
                    actor_id=uuid4(),
                    db=db,
                    accessible_site_ids={site_id} if limited else None,
                )
                result = await OperationExecutor().execute(op, ctx)
                assert result.success is (state == "live")
                if state == "live":
                    assert (
                        isinstance(row, Controller)
                        and row.id == controller_id
                        and row.site_id == site_id
                    )
                    stage.assert_awaited_once()
                    assert stage.await_args.kwargs["controller_id"] == controller_id
                else:
                    assert row is None
                    assert result.error_code == "CROSS_TENANT_TARGET"
                    stage.assert_not_awaited()
    finally:
        engine.dispose()

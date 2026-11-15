# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
A direct write's ledger row is written in its own transaction.

The staging chokepoint commits twice: the ``applying`` row before the device is
contacted, the result after. On the request's own session those commits would
also commit whatever the request had changed so far, before the device
accepted the write; a refused write would then leave a local change in place
that used to be rolled back with the request. So write_through_staging records
in a session of its own.

The rest of the suite joins the record to the test transaction
(tests/conftest.py); this test runs the production path, on committed rows it
removes afterwards.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import delete, select

import app.core.runtime_flags as rf
import app.services.device_writes as device_writes
from app.db.models import Controller
from app.db.session import celery_session_factory
from app.models.core import Organization, Site
from app.models.staging import AdapterPendingChange


async def test_a_refused_write_does_not_commit_the_requests_own_changes(monkeypatch) -> None:
    monkeypatch.setattr(device_writes, "ledger_session_factory", None)
    monkeypatch.setattr(rf, "is_adapter_read_only", lambda: False)

    org_id, other_org = uuid4(), uuid4()
    async with celery_session_factory() as setup:
        setup.add(Organization(id=org_id, name="ledger-own-tx", slug=uuid4().hex))
        await setup.flush()
        site = Site(name="s", slug=uuid4().hex, organization_id=org_id)
        setup.add(site)
        await setup.flush()
        ctrl = Controller(
            name="c", site_id=site.id, controller_type="omada", host="127.0.0.1", port=443
        )
        setup.add(ctrl)
        await setup.commit()
        ctrl_id, site_id = ctrl.id, site.id

    class _Refused(RuntimeError):
        pass

    async def _perform() -> None:
        raise _Refused("device said no")

    try:
        async with celery_session_factory() as request:
            # The request changed something before writing to the device.
            request.add(Organization(id=other_org, name="uncommitted", slug=uuid4().hex))
            await request.flush()
            with pytest.raises(_Refused):
                await device_writes.write_through_staging(
                    request,
                    organization_id=org_id,
                    controller_id=ctrl_id,
                    site_id=site_id,
                    feature="test.own_transaction",
                    operation="update",
                    payload={},
                    perform=_perform,
                    force=True,
                    actor_id=None,
                )
            await request.rollback()

        async with celery_session_factory() as check:
            assert await check.get(Organization, other_org) is None
            rows = (
                await check.execute(
                    select(AdapterPendingChange).where(
                        AdapterPendingChange.organization_id == org_id
                    )
                )
            ).scalars().all()
            assert [(r.feature, r.status) for r in rows] == [
                ("direct.test.own_transaction", "failed")
            ]
    finally:
        async with celery_session_factory() as cleanup:
            await cleanup.execute(delete(Organization).where(Organization.id.in_([org_id, other_org])))
            await cleanup.commit()

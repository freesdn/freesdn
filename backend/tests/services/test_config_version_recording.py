# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Config versions record on PostgreSQL.

record_version selected max(version_number) ... FOR UPDATE, which PostgreSQL
refuses on an aggregate, so every recording (config push, rollback, drift
remediation) failed and left the session's transaction aborted. These run
against the real database.
"""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select

from app.models.core import Organization, Site
from app.models.devices import Device, DeviceType
from app.models.enterprise import ConfigVersion
from app.services.config_versions import ConfigVersionService


async def _device(db_session):
    suffix = uuid4().hex[:8]
    org = Organization(name="Ver Org", slug=f"ver-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="Ver Site", slug=f"ver-site-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()
    dev = Device(
        site_id=site.id, status="unknown", name=f"sw-{suffix}", device_type=DeviceType.SWITCH
    )
    db_session.add(dev)
    await db_session.flush()
    return org, dev


async def test_versions_are_numbered_and_the_session_stays_usable(db_session):
    org, dev = await _device(db_session)
    svc = ConfigVersionService(db_session)

    first = await svc.record_version(dev.id, {"vlan": 10}, "manual_save", organization_id=org.id)
    second = await svc.record_version(dev.id, {"vlan": 20}, "config_push", organization_id=org.id)

    assert (first.version_number, second.version_number) == (1, 2)
    # The transaction is still usable: no aborted-transaction error.
    numbers = (
        (
            await db_session.execute(
                select(ConfigVersion.version_number)
                .where(ConfigVersion.device_id == dev.id)
                .order_by(ConfigVersion.version_number)
            )
        )
        .scalars()
        .all()
    )
    assert numbers == [1, 2]


async def test_the_organization_is_taken_from_the_previous_version(db_session):
    org, dev = await _device(db_session)
    svc = ConfigVersionService(db_session)

    await svc.record_version(dev.id, {"a": 1}, "manual_save", organization_id=org.id)
    later = await svc.record_version(dev.id, {"a": 2}, "rollback")

    assert later.organization_id == org.id
    assert later.version_number == 2

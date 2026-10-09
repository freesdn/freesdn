# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""A restored device must retain its usable, tenant-owned credential reference."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.models.core import Controller, Credential, Organization, Site
from app.models.devices import Device
from app.services.backup import BackupService


async def fixtures(db):
    org = Organization(name="Recovery", slug="recovery-" + uuid4().hex)
    db.add(org)
    await db.flush()
    site = Site(organization_id=org.id, name="Recovery", slug="recovery")
    db.add(site)
    await db.flush()
    credential = Credential(organization_id=org.id, name="Device credential", credential_type="ssh")
    db.add(credential)
    await db.flush()
    controller = Controller(
        site_id=site.id,
        name="Recovery controller",
        controller_type="proxmox",
        host="controller.invalid",
        port=8006,
        use_ssl=True,
        verify_ssl=True,
        sync_enabled=False,
        sync_interval_seconds=900,
        credential_id=credential.id,
    )
    db.add(controller)
    await db.flush()
    device = Device(
        site_id=site.id,
        controller_id=controller.id,
        name="Recovered device",
        device_type="switch",
        external_id="provider-id",
        credential_id=credential.id,
    )
    db.add(device)
    await db.flush()
    return org, site, credential, controller, device


async def test_core_round_trip_preserves_credential_and_connection_settings(db_session):
    org, _site, credential, controller, device = await fixtures(db_session)
    service = BackupService(db_session)
    service.org_id = org.id
    payload = await service.collect_backup_data(organization_id=org.id, include_secrets=True)
    data = payload.get("data", payload)
    device_id, controller_id = device.id, controller.id
    await db_session.delete(device)
    await db_session.flush()
    await db_session.delete(controller)
    await db_session.flush()
    await service._restore_data(
        data,
        dry_run=False,
        overwrite_existing=True,
        restore_devices=True,
        restore_users=False,
        include_secrets=True,
    )
    device = await db_session.get(Device, device_id)
    controller = await db_session.get(Controller, controller_id)
    assert device.credential_id == credential.id
    assert device.external_id == "provider-id" and device.ip_address is None
    assert controller.credential_id == credential.id
    assert controller.use_ssl is True and controller.verify_ssl is True
    assert controller.sync_enabled is False and controller.sync_interval_seconds == 900


@pytest.mark.parametrize("resource", ["controllers", "devices"])
@pytest.mark.parametrize("deleted", [False, True])
async def test_foreign_credential_cannot_be_linked_by_restore(db_session, resource, deleted):
    org, site, _credential, _controller, _device = await fixtures(db_session)
    other = Organization(name="Other tenant", slug="other-" + uuid4().hex)
    db_session.add(other)
    await db_session.flush()
    foreign = Credential(
        organization_id=org.id if deleted else other.id,
        name="Other credential",
        credential_type="ssh",
        deleted_at=datetime.now(UTC) if deleted else None,
    )
    db_session.add(foreign)
    await db_session.flush()
    record_id = uuid4()
    service = BackupService(db_session)
    service.org_id = org.id
    result = await service._restore_data(
        {
            resource: [
                {"id": str(record_id), "site_id": str(site.id), "credential_id": str(foreign.id)}
            ],
            # A malicious archive cannot disguise a foreign existing credential as its own.
            "credentials": [{"id": str(foreign.id), "organization_id": str(org.id)}],
        },
        dry_run=False,
        overwrite_existing=True,
        restore_devices=True,
        restore_users=False,
        include_secrets=True,
    )
    model = Controller if resource == "controllers" else Device
    assert await db_session.get(model, record_id) is None
    assert result[resource]["rejected_cross_org"] == 1
    assert foreign.organization_id == (org.id if deleted else other.id)

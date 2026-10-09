# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Deleted groups cannot supply permissions; independent access remains intact.

These tests execute the actual ORM queries against a small SQLite schema. The
synchronous session facade avoids adding a test-only async driver dependency.
Migrated PostgreSQL constraints and endpoint authorization are qualified apart.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text, update
from sqlalchemy.orm import Session

from app.modules.cameras.models import Camera, CameraAccessGrant, CameraGroup
from app.modules.cameras.service import CameraAccessService

pytestmark = pytest.mark.asyncio

FLAGS = ["can_live", "can_playback", "can_ptz", "can_export", "can_configure"]


@pytest.fixture
def grants():
    engine = create_engine("sqlite://")
    with engine.connect() as connection:
        connection.execute(text("ATTACH DATABASE ':memory:' AS cameras"))
        # Minimal queried columns only; this is not a production migration.
        for statement in [
            "CREATE TABLE cameras.cameras (id CHAR(32), organization_id CHAR(32), deleted_at DATETIME, updated_at DATETIME)",
            "CREATE TABLE cameras.camera_groups (id CHAR(32), organization_id CHAR(32), deleted_at DATETIME, updated_at DATETIME)",
            "CREATE TABLE cameras.camera_group_members (camera_id CHAR(32), group_id CHAR(32))",
        ]:
            connection.execute(text(statement))
        CameraAccessGrant.__table__.create(connection)
        connection.commit()
    db = Session(engine, expire_on_commit=False)
    org, user, camera = (uuid4() for _ in range(3))
    db.execute(
        text(
            "INSERT INTO cameras.cameras (id, organization_id, deleted_at) VALUES (:id, :org, NULL)"
        ),
        {"id": camera.hex, "org": org.hex},
    )
    db.commit()

    class QuerySession:
        async def execute(self, statement):
            return db.execute(statement)

    def grant(
        *,
        group_id=None,
        camera_id=None,
        organization_id=org,
        flags=(),
        level="operator",
    ):
        record = CameraAccessGrant(
            id=uuid4(),
            user_id=user,
            organization_id=organization_id,
            group_id=group_id,
            camera_id=camera_id,
            access_level=level,
            expires_at=None,
            **{name: name in flags for name in FLAGS},
        )
        db.add(record)
        db.commit()
        return record

    def group(*, organization_id=org, deleted=False, member=True, flags=(), grant_org=org):
        identity = uuid4()
        db.execute(
            text(
                "INSERT INTO cameras.camera_groups (id, organization_id, deleted_at) VALUES (:id, :org, :deleted)"
            ),
            {
                "id": identity.hex,
                "org": organization_id.hex,
                "deleted": datetime.now(UTC) if deleted else None,
            },
        )
        if member:
            db.execute(
                text("INSERT INTO cameras.camera_group_members VALUES (:camera, :group)"),
                {"camera": camera.hex, "group": identity.hex},
            )
        db.commit()
        grant(group_id=identity, organization_id=grant_org, flags=flags)
        return identity

    def delete_group(identity):
        db.execute(
            update(CameraGroup)
            .where(CameraGroup.id == identity)
            .values(deleted_at=datetime.now(UTC))
        )
        db.commit()

    async def access(role="guest"):
        return await CameraAccessService(QuerySession()).check_access(
            user, camera, org, user_role=role
        )

    yield SimpleNamespace(
        db=db,
        org=org,
        user=user,
        camera=camera,
        grant=grant,
        group=group,
        delete_group=delete_group,
        access=access,
    )
    db.close()
    engine.dispose()


@pytest.mark.parametrize("role", ["guest", "viewer"])
@pytest.mark.parametrize("flag", FLAGS)
async def test_group_deletion_restores_independent_role_permissions(grants, role, flag):
    f = grants
    baseline = await f.access(role)
    identity = f.group(flags=[flag])
    current = await f.access(role)
    assert current[flag] and current["grant_source"] == "group_grant"
    f.delete_group(identity)
    assert await f.access(role) == baseline
    # Soft deletion keeps the historical grant; authorization must ignore it.
    assert f.db.query(CameraAccessGrant).count() == 1


@pytest.mark.parametrize("flag", FLAGS)
async def test_deleted_group_does_not_inflate_another_active_group(grants, flag):
    f = grants
    remaining = [name for name in FLAGS if name != flag]
    f.group(flags=remaining)
    baseline = await f.access()
    removed = f.group(flags=[flag])
    assert (await f.access())[flag]
    f.delete_group(removed)
    assert await f.access() == baseline


@pytest.mark.parametrize("role", ["guest", "viewer"])
async def test_direct_grant_keeps_precedence_over_deleted_group(grants, role):
    f = grants
    f.grant(camera_id=f.camera, flags=["can_live"], level="viewer")
    baseline = await f.access(role)
    assert baseline["grant_source"] == "camera_grant"
    f.group(flags=FLAGS, deleted=True)
    assert await f.access(role) == baseline


@pytest.mark.parametrize("role", ["super_admin", "admin", "org_admin"])
@pytest.mark.parametrize("deleted", [False, True])
async def test_admin_role_access_does_not_depend_on_group(grants, role, deleted):
    f = grants
    baseline = await f.access(role)
    f.group(flags=[], deleted=deleted)
    assert await f.access(role) == baseline
    assert baseline["grant_source"] == "role" and all(baseline[name] for name in FLAGS)


@pytest.mark.parametrize(
    "reason", ["foreign_group", "foreign_grant", "not_member", "deleted_camera"]
)
async def test_unrelated_or_invalid_target_never_supplies_group_access(grants, reason):
    f = grants
    baseline = await f.access()
    options = {"flags": FLAGS}
    if reason == "foreign_group":
        options["organization_id"] = uuid4()
    elif reason == "foreign_grant":
        options["grant_org"] = uuid4()
    elif reason == "not_member":
        options["member"] = False
    else:
        f.db.execute(
            update(Camera).where(Camera.id == f.camera).values(deleted_at=datetime.now(UTC))
        )
        f.db.commit()
    f.group(**options)
    assert await f.access() == baseline

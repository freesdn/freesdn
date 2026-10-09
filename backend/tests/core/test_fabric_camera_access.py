# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Fabric snapshots enforce author, site and camera grants before device I/O."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.core.fabric.artifact_broker import ArtifactBroker
from app.core.fabric.execution import OperationContext
from app.core.fabric.executor import OperationExecutor
from app.modules.cameras.module import CamerasModule


@pytest.fixture
def snapshot(monkeypatch, tmp_path):
    org, actor_id, camera_id, site = (uuid4() for _ in range(4))
    author = SimpleNamespace(
        id=actor_id,
        organization_id=org,
        role="org_admin",
        is_active=True,
        deleted_at=None,
        site_access=[],
    )
    camera = SimpleNamespace(id=camera_id, organization_id=org, site_id=site, deleted_at=None)
    db = MagicMock()
    db.get = AsyncMock(return_value=camera)
    db.execute = AsyncMock(
        return_value=SimpleNamespace(
            scalar_one_or_none=lambda: site, one_or_none=lambda: (camera.id, camera.site_id)
        )
    )
    lookup = AsyncMock(return_value=author)
    monkeypatch.setattr("app.core.dependencies._get_user_by_id", lookup)
    access = AsyncMock(return_value={"has_access": True, "can_live": True})
    monkeypatch.setattr("app.modules.cameras.service.CameraAccessService.check_access", access)
    capture = AsyncMock(return_value=b"owned JPEG bytes")
    monkeypatch.setattr("app.modules.cameras.service.StreamService.get_snapshot", capture)
    broker = ArtifactBroker(base_dir=tmp_path)
    put = AsyncMock(wraps=broker.put)
    monkeypatch.setattr(broker, "put", put)
    op = next(op for op in CamerasModule().get_operations() if op.id == "cameras.snapshot")
    context = OperationContext(
        org,
        {"camera_id": str(camera_id), "actor_id": str(uuid4())},
        actor_id=actor_id,
        db=db,
        artifacts=broker,
    )
    return SimpleNamespace(
        author=author,
        camera=camera,
        lookup=lookup,
        access=access,
        capture=capture,
        put=put,
        context=context,
        op=op,
        db=db,
        executor=OperationExecutor(artifact_broker=broker),
    )


@pytest.mark.parametrize(
    "reason",
    [
        "missing_actor",
        "invalid_actor",
        "missing_author",
        "inactive_author",
        "deleted_author",
        "foreign_author",
        "lost_permission",
        "missing_camera",
        "deleted_camera",
        "foreign_camera",
        "outside_author_site",
        "unknown_site_level",
        "outside_context_site",
        "empty_context_scope",
        "camera_denied",
        "live_denied",
        "author_lookup_failure",
        "camera_lookup_failure",
        "camera_grant_failure",
    ],
)
async def test_unauthorized_fabric_snapshot_never_captures_or_brokers(
    snapshot, reason, monkeypatch
):
    f = snapshot
    if reason == "missing_actor":
        f.context.actor_id = None
    elif reason == "invalid_actor":
        f.context.actor_id = "not-a-uuid"
    elif reason == "missing_author":
        f.lookup.return_value = None
    elif reason == "inactive_author":
        f.author.is_active = False
    elif reason == "deleted_author":
        f.author.deleted_at = object()
    elif reason == "foreign_author":
        f.author.organization_id = uuid4()
    elif reason == "lost_permission":
        f.author.role = "operator"
        monkeypatch.setattr(
            "app.core.dependencies._load_user_permissions", AsyncMock(return_value=[])
        )
    elif reason == "missing_camera":
        f.db.get.return_value = None
    elif reason == "deleted_camera":
        f.camera.deleted_at = object()
    elif reason == "foreign_camera":
        f.camera.organization_id = uuid4()
    elif reason in ["outside_author_site", "unknown_site_level"]:
        f.author.role = "site_admin"
        f.author.site_access = [
            SimpleNamespace(
                site_id=uuid4() if reason == "outside_author_site" else f.camera.site_id,
                access_level="admin" if reason == "outside_author_site" else "unknown",
            )
        ]
    elif reason == "outside_context_site":
        f.context.accessible_site_ids = {uuid4()}
    elif reason == "empty_context_scope":
        f.context.accessible_site_ids = set()
    elif reason == "camera_denied":
        f.access.return_value["has_access"] = False
    elif reason == "live_denied":
        f.access.return_value["can_live"] = False
    elif reason == "author_lookup_failure":
        f.lookup.side_effect = RuntimeError("PRIVATE_LOOKUP_DETAIL")
    elif reason == "camera_lookup_failure":
        f.db.get.side_effect = RuntimeError("PRIVATE_LOOKUP_DETAIL")
    else:
        f.access.side_effect = RuntimeError("PRIVATE_LOOKUP_DETAIL")
    result = await f.executor.execute(f.op, f.context)
    assert result.success is False
    assert result.error_code == "CAMERA_ACCESS_DENIED"
    assert "PRIVATE_LOOKUP_DETAIL" not in result.error
    f.capture.assert_not_awaited()
    f.put.assert_not_awaited()


@pytest.mark.parametrize("principal", ["org_admin", "viewer", "site_reader", "narrowed_context"])
async def test_authorized_snapshot_preserves_artifact_and_identity(snapshot, principal):
    f = snapshot
    if principal == "viewer":
        f.author.role = "viewer"
    elif principal == "site_reader":
        f.author.role = "site_admin"
        f.author.site_access = [SimpleNamespace(site_id=f.camera.site_id, access_level="read")]
    elif principal == "narrowed_context":
        f.context.accessible_site_ids = {f.camera.site_id}
    result = await f.executor.execute(f.op, f.context)
    assert result.success and result.artifact and result.artifact.media_type == "image/jpeg"
    f.lookup.assert_awaited_once_with(f.db, str(f.author.id))
    f.capture.assert_awaited_once_with(f.camera.id, organization_id=f.context.organization_id)
    f.access.assert_awaited_once_with(
        user_id=f.author.id,
        camera_id=f.camera.id,
        organization_id=f.context.organization_id,
        user_role=f.author.role,
    )
    payload, _ = await f.context.artifacts.get(result.artifact.handle, f.context.organization_id)
    assert payload == b"owned JPEG bytes"


async def test_revoked_camera_grant_is_observed_on_next_snapshot(snapshot):
    f = snapshot
    first = await f.executor.execute(f.op, f.context)
    f.access.return_value["can_live"] = False
    second = await f.executor.execute(f.op, f.context)
    assert first.success and not second.success
    f.capture.assert_awaited_once()
    f.put.assert_awaited_once()


@pytest.mark.parametrize("invalid", ["missing_target", "invalid_target", "no_db"])
async def test_existing_input_refusals_remain_before_capture(snapshot, invalid):
    f = snapshot
    if invalid == "missing_target":
        f.context.params = {}
    elif invalid == "invalid_target":
        f.context.params["camera_id"] = "invalid"
    else:
        f.context.db = None
    result = await f.executor.execute(f.op, f.context)
    assert not result.success
    f.capture.assert_not_awaited()


async def test_snapshot_adapter_failure_does_not_expose_private_details(snapshot):
    f = snapshot
    f.capture.side_effect = RuntimeError("PRIVATE_ADAPTER_URL_AND_PASSWORD")
    result = await f.executor.execute(f.op, f.context)
    assert not result.success and result.error_code == "SNAPSHOT_FAILED"
    assert "PRIVATE_ADAPTER_URL_AND_PASSWORD" not in result.error
    f.put.assert_not_awaited()

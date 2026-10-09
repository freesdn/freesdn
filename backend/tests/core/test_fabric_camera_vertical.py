# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""End-to-end proof of the headline automation vertical:

    camera.alert.line_cross  →  cameras.snapshot  →  (sink receives the image)

Uses the REAL ``cameras.snapshot`` Operation (its real handler, only the
device-touching ``CameraService.get_snapshot`` is mocked) wired to a Connection
whose ``source_event`` is the canonical ``camera.alert.line_cross`` trigger the
module now advertises — so this fails if the catalog and the firing namespace
ever diverge again, or if the snapshot handler stops brokering an image.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core.fabric.artifact_broker import ArtifactBroker
from app.core.fabric.execution import OperationResult
from app.core.fabric.executor import OperationExecutor
from app.core.fabric.negotiator import Connection, ConnectionStep
from app.core.fabric.operations import Operation, OperationTier
from tests.core.fabric_fakes import coordinated_negotiator

ORG = uuid.uuid4()


class _Event:
    def __init__(self, event_type, payload, organization_id):
        self.event_type = event_type
        self.payload = payload
        self.organization_id = organization_id
        self.id = str(uuid.uuid4())


class _FakeRegistry:
    def __init__(self, ops):
        self._ops = {o.id: o for o in ops}

    def get_operation(self, op_id):
        return self._ops.get(op_id)


class _FakeSession:
    """Author and target records for a positive, device-mocked snapshot chain."""

    def __init__(self, author, camera):
        self.author, self.camera = author, camera

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, _model, identity):
        assert identity == self.camera.id
        return self.camera

    async def commit(self):
        # This positive fixture models a successful session, including commit.
        return None

    async def execute(self, query):
        if [column["name"] for column in query.column_descriptions] == ["id", "site_id"]:
            return SimpleNamespace(one_or_none=lambda: (self.camera.id, self.camera.site_id))
        value = (
            self.camera.site_id
            if query.column_descriptions[0]["name"] == "site_id"
            else self.author
        )
        return SimpleNamespace(scalar_one_or_none=lambda: value)


@pytest.mark.asyncio
async def test_line_cross_triggers_snapshot_and_threads_image(tmp_path, monkeypatch) -> None:
    from app.modules.cameras.module import CamerasModule

    # The trigger the operator wires to MUST be a real advertised camera alert.
    advertised = {e.event_type for e in CamerasModule().get_emitted_events()}
    assert "camera.alert.line_cross" in advertised

    # Real snapshot op; device capture and permission-service result are mocked.
    snap_op = next(o for o in CamerasModule().get_operations() if o.id == "cameras.snapshot")
    monkeypatch.setattr(
        "app.modules.cameras.service.StreamService.get_snapshot",
        AsyncMock(return_value=b"\xff\xd8\xff-jpeg-bytes"),
    )

    received: dict = {}

    async def _notify(ctx):
        # The downstream sink receives the snapshot as a threaded artifact.
        received["artifact"] = ctx.input_artifact
        received["camera_id"] = ctx.params.get("camera_id")
        return OperationResult.ok(output={"notified": True})

    notify_op = Operation(
        id="test.notify",
        title="notify",
        accepts=("image/jpeg",),
        handler=_notify,
        tier=OperationTier.NATIVE,
        provider_id="test",
    )

    async def _allow(actor_id, permission, org_id):
        return True  # cameras.snapshot requires cameras.view

    author = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=ORG,
        role="org_admin",
        is_active=True,
        deleted_at=None,
        site_access=[],
    )
    camera = SimpleNamespace(
        id=uuid.uuid4(), organization_id=ORG, site_id=uuid.uuid4(), deleted_at=None
    )
    monkeypatch.setattr(
        "app.modules.cameras.service.CameraAccessService.check_access",
        AsyncMock(return_value={"has_access": True, "can_live": True}),
    )
    executor = OperationExecutor(artifact_broker=ArtifactBroker(base_dir=tmp_path))
    neg = coordinated_negotiator(
        registry=_FakeRegistry([snap_op, notify_op]),
        executor=executor,
        permission_checker=_allow,
        session_factory=lambda: _FakeSession(author, camera),
    )
    cam_id = str(camera.id)
    neg.add_connection(
        Connection(
            id="cam-vertical",
            organization_id=ORG,
            name="line-cross → snapshot → notify",
            source_event="camera.alert.line_cross",
            steps=[
                ConnectionStep("cameras.snapshot", params={"camera_id": "{{trigger.camera_id}}"}),
                ConnectionStep("test.notify", params={"camera_id": "{{trigger.camera_id}}"}),
            ],
            actor_id=author.id,
        )
    )

    runs = await neg.handle_event(
        _Event("camera.alert.line_cross", {"camera_id": cam_id, "event_type": "line_cross"}, ORG)
    )

    assert len(runs) == 1
    run = runs[0]
    assert run["success"] is True, run
    # Step 0: the real snapshot handler captured + brokered an image artifact.
    snap_step = run["steps"][0]
    assert snap_step["operation_id"] == "cameras.snapshot" and snap_step["success"]
    assert snap_step["artifact"]["media_type"] == "image/jpeg"
    # Step 1: the image threaded into the sink, and templating passed camera_id.
    assert received["artifact"] is not None
    assert received["artifact"].media_type == "image/jpeg"
    assert received["camera_id"] == cam_id


@pytest.mark.asyncio
async def test_motion_is_not_an_automation_trigger(tmp_path) -> None:
    # motion is intentionally NOT pushed/advertised (too chatty) — a connection
    # wired to camera.alert.motion must simply never fire (it isn't on the bus).
    from app.modules.cameras.module import CamerasModule

    advertised = {e.event_type for e in CamerasModule().get_emitted_events()}
    assert "camera.alert.motion" not in advertised

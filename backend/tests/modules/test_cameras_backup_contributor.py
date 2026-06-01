# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Tests for CamerasBackupContributor (enterprise backup chapter).

Same FakeAsyncSession approach as the VoIP contributor tests (no live
Postgres in the unit env). Covers redaction, collect shape + secret
exclusion, and restore tenant/FK guards (now via the shared
``restore_records`` helper).
"""

from __future__ import annotations

from collections import deque
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from app.modules.cameras.backup import CamerasBackupContributor, _redact
from app.services.backup_contributors import (
    BackupContributor,
    ContributorPayload,
)


class _Result:
    def __init__(self, rows): self._rows = rows
    def scalars(self): return self
    def all(self): return self._rows


class FakeAsyncSession:
    def __init__(self, *, execute_results=None, store=None):
        self._q = deque(execute_results or [])
        self._store = store or {}
        self.added: list[Any] = []
        self.flush_count = 0

    async def execute(self, _q): return _Result(self._q.popleft() if self._q else [])
    async def get(self, model_cls, pk): return self._store.get((model_cls.__name__, str(pk)))
    def add(self, obj): self.added.append(obj)
    async def flush(self): self.flush_count += 1


# ── redaction ────────────────────────────────────────────────────────────


class TestRedact:
    def test_drops_secrets_recursively(self) -> None:
        out = _redact({
            "rtsp_url": "rtsp://x",
            "password": "p",
            "nested": {"onvif_password": "q", "fps": 30},
            "list": [{"admin_password": "z", "ok": 1}],
        })
        assert out == {
            "rtsp_url": "rtsp://x",
            "nested": {"fps": 30},
            "list": [{"ok": 1}],
        }


def test_protocol() -> None:
    c = CamerasBackupContributor()
    assert isinstance(c, BackupContributor)
    assert c.contributor_id == "cameras"
    assert c.depends_on == ("core",)


# ── collect ──────────────────────────────────────────────────────────────


def _nvr(org, site, **kw):
    base = dict(
        id=uuid4(), site_id=site, controller_id=None, organization_id=org,
        name="NVR-1", description=None, ip_address="10.0.0.9", port=80,
        mac_address=None, vendor="hikvision", model="DS-7608",
        firmware_version="4.0", serial_number="SN1", device_type="hikvision",
        username="admin", external_device_id="EXT1", channel_count=8,
        settings={"tz": "UTC", "password": "LEAK"},
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _cam(org, site, **kw):
    base = dict(
        id=uuid4(), site_id=site, nvr_id=None, controller_id=None,
        organization_id=org, channel_id=1, name="Lobby", description=None,
        camera_type="ip_camera", ip_address="10.0.0.20", port=554,
        mac_address=None, vendor="hikvision", model="DS-2CD",
        firmware_version="5.0", serial_number="C1",
        rtsp_main_stream="rtsp://main", rtsp_sub_stream=None, snapshot_url=None,
        device_type="hikvision", username="admin",
        has_ptz=False, has_audio=True, has_two_way_audio=False, has_ir=True,
        resolution_width=1920, resolution_height=1080,
        motion_detection_enabled=True, location="Lobby", floor="1",
        settings={"codec": "h265", "rtsp_password": "LEAK"},
    )
    base.update(kw)
    return SimpleNamespace(**base)


class TestCollect:
    @pytest.mark.asyncio
    async def test_shape_counts_and_secret_exclusion(self) -> None:
        org, site = uuid4(), uuid4()
        nvr = _nvr(org, site)
        cam = _cam(org, site)
        grp = SimpleNamespace(
            id=uuid4(), organization_id=org, name="G", description=None,
            color="#fff", icon="folder", sort_order=0, is_default=False,
        )
        member = SimpleNamespace(
            id=uuid4(), group_id=grp.id, camera_id=cam.id, sort_order=0,
        )
        view = SimpleNamespace(
            id=uuid4(), organization_id=org, user_id=None, name="V",
            description=None, layout="2x2", camera_ids=[cam.id],
            filters={"secret": "drop", "q": "keep"}, is_default=False,
            is_shared=True, sort_order=0,
        )
        tmpl = SimpleNamespace(
            id=uuid4(), organization_id=org, name="24x7", description=None,
            is_builtin=False, schedule={"days": 7},
        )
        # collect order: nvrs, cameras, groups, (members if groups),
        # views, templates
        session = FakeAsyncSession(execute_results=[
            [nvr], [cam], [grp], [member], [view], [tmpl],
        ])

        payload = await CamerasBackupContributor().collect(session, org, {})
        assert isinstance(payload, ContributorPayload)
        assert payload.counts == {
            "nvrs": 1, "cameras": 1, "camera_groups": 1,
            "camera_group_members": 1, "camera_views": 1,
            "recording_schedule_templates": 1,
        }

        # No credential columns serialized.
        nvr_out = payload.data["nvrs"][0]
        cam_out = payload.data["cameras"][0]
        assert "password_encrypted" not in nvr_out
        assert "password_encrypted" not in cam_out
        # username (non-secret) IS carried.
        assert nvr_out["username"] == "admin"
        # settings secrets stripped.
        assert "password" not in nvr_out["settings"]
        assert nvr_out["settings"]["tz"] == "UTC"
        assert "rtsp_password" not in cam_out["settings"]
        assert cam_out["settings"]["codec"] == "h265"
        # view filters redacted.
        assert "secret" not in payload.data["camera_views"][0]["filters"]
        assert payload.data["camera_views"][0]["filters"]["q"] == "keep"

    @pytest.mark.asyncio
    async def test_no_groups_skips_member_query(self) -> None:
        org = uuid4()
        # nvrs, cameras, groups(empty), views, templates → 5 results
        # (member query skipped when no groups).
        session = FakeAsyncSession(execute_results=[[], [], [], [], []])
        payload = await CamerasBackupContributor().collect(session, org, {})
        assert payload.counts["camera_group_members"] == 0


# ── restore ──────────────────────────────────────────────────────────────


class TestRestore:
    def _payload(self, data): return ContributorPayload(
        schema_version="1.0.0", counts={}, data=data, metadata={},
    )

    @pytest.mark.asyncio
    async def test_cross_tenant_nvr_rejected(self) -> None:
        org, org_site, foreign_site = uuid4(), uuid4(), uuid4()
        # restore execute order: org sites, org controllers, users
        session = FakeAsyncSession(execute_results=[[org_site], [], []])
        data = {
            "nvrs": [{"id": str(uuid4()), "site_id": str(foreign_site),
                      "organization_id": str(org), "name": "Evil",
                      "ip_address": "1.2.3.4"}],
            "cameras": [], "camera_groups": [], "camera_group_members": [],
            "camera_views": [], "recording_schedule_templates": [],
        }
        result = await CamerasBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )
        assert result.skipped["nvrs"] == 1
        assert result.created["nvrs"] == 0
        assert any("cross-tenant" in w for w in result.warnings)
        assert session.added == []

    @pytest.mark.asyncio
    async def test_camera_nvr_id_nulled_when_nvr_missing(self) -> None:
        org, site = uuid4(), uuid4()
        ghost_nvr = uuid4()
        session = FakeAsyncSession(execute_results=[[site], [], []])
        data = {
            "nvrs": [],  # no NVRs restored
            "cameras": [{"id": str(uuid4()), "site_id": str(site),
                         "nvr_id": str(ghost_nvr),
                         "organization_id": str(org),
                         "name": "Cam", "ip_address": "10.0.0.20"}],
            "camera_groups": [], "camera_group_members": [],
            "camera_views": [], "recording_schedule_templates": [],
        }
        await CamerasBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )
        cam_instances = [o for o in session.added if type(o).__name__ == "Camera"]
        assert len(cam_instances) == 1
        # nvr_id was nulled because the NVR wasn't restored.
        assert cam_instances[0].nvr_id is None

    @pytest.mark.asyncio
    async def test_orphan_group_member_skipped(self) -> None:
        org, site = uuid4(), uuid4()
        good_group = uuid4()
        good_cam = uuid4()
        missing_cam = uuid4()
        session = FakeAsyncSession(execute_results=[[site], [], []])
        data = {
            "nvrs": [],
            "cameras": [{"id": str(good_cam), "site_id": str(site),
                         "organization_id": str(org), "name": "Cam",
                         "ip_address": "10.0.0.20"}],
            "camera_groups": [{"id": str(good_group),
                               "organization_id": str(org), "name": "G"}],
            "camera_group_members": [
                # references a camera that wasn't restored → orphan
                {"id": str(uuid4()), "group_id": str(good_group),
                 "camera_id": str(missing_cam)},
            ],
            "camera_views": [], "recording_schedule_templates": [],
        }
        result = await CamerasBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )
        assert result.created["camera_group_members"] == 0
        assert result.skipped["camera_group_members"] == 1
        assert any("orphan" in w.lower() for w in result.warnings)

    @pytest.mark.asyncio
    async def test_force_org_on_insert(self) -> None:
        """A record claiming a foreign organization_id still gets the
        caller's org forced on insert (defense-in-depth — and the
        Camera's site_id keeps it in-org anyway)."""
        org, site = uuid4(), uuid4()
        foreign_org = uuid4()
        session = FakeAsyncSession(execute_results=[[site], [], []])
        data = {
            "nvrs": [], "cameras": [],
            "camera_groups": [{"id": str(uuid4()),
                               "organization_id": str(foreign_org),
                               "name": "G"}],
            "camera_group_members": [],
            "camera_views": [], "recording_schedule_templates": [],
        }
        await CamerasBackupContributor().restore(
            session, org, self._payload(data), dry_run=False, options={},
        )
        grp = [o for o in session.added if type(o).__name__ == "CameraGroup"][0]
        # organization_id forced to caller's org, NOT the foreign one.
        assert grp.organization_id == org

    @pytest.mark.asyncio
    async def test_dry_run_writes_nothing(self) -> None:
        org, site = uuid4(), uuid4()
        session = FakeAsyncSession(execute_results=[[site], [], []])
        data = {
            "nvrs": [{"id": str(uuid4()), "site_id": str(site),
                      "organization_id": str(org), "name": "NVR",
                      "ip_address": "10.0.0.9"}],
            "cameras": [], "camera_groups": [], "camera_group_members": [],
            "camera_views": [], "recording_schedule_templates": [],
        }
        result = await CamerasBackupContributor().restore(
            session, org, self._payload(data), dry_run=True, options={},
        )
        assert result.created["nvrs"] == 1
        assert result.status == "dry_run_ok"
        assert session.added == []

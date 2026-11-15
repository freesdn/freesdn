# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""The Hikvision-ISAPI periodic tasks only poll Hikvision recorders.

cameras.poll_camera_health (every minute) and cameras.ingest_nvr_alerts (every
30 s) build a HikvisionAdapter for every NVR row, but onboarding also records
ONVIF and other vendors' recorders (device_type "onvif"). Each of those was
sent ISAPI requests with its stored login twice a minute, failing every time.
Real PostgreSQL; the per-NVR pollers are stubbed, nothing is contacted.
"""

from __future__ import annotations

from uuid import uuid4

import app.tasks.cameras as cam_tasks
from app.models.core import Organization, Site
from app.modules.cameras.models import NVR


async def _nvrs(db_session):
    suffix = uuid4().hex[:8]
    org = Organization(name="Cam Org", slug=f"cam-{suffix}")
    db_session.add(org)
    await db_session.flush()
    site = Site(name="Cam Site", slug=f"cam-site-{suffix}", organization_id=org.id)
    db_session.add(site)
    await db_session.flush()

    def nvr(name, **kw):
        return NVR(
            organization_id=org.id,
            site_id=site.id,
            name=name,
            ip_address="192.0.2.40",
            **kw,
        )

    rows = {
        "hikvision": nvr("hik", vendor="Hikvision", device_type="hikvision"),
        "legacy": nvr("legacy"),  # column default device_type="hikvision"
        "onvif": nvr("dahua", vendor="Dahua", device_type="onvif"),
    }
    db_session.add_all(rows.values())
    await db_session.flush()
    return {v.id: k for k, v in rows.items()}


def _wire(monkeypatch, db_session, per_nvr):
    called = []

    async def _one(nvr_id):
        called.append(nvr_id)
        return {"nvr_id": str(nvr_id), "saved": 0, "errors": 0, "ingested": 0}

    class _Ctx:
        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(cam_tasks, per_nvr, _one)
    monkeypatch.setattr(cam_tasks, "AsyncSessionLocal", lambda: _Ctx())
    return called


async def test_health_poll_skips_non_hikvision_recorders(db_session, monkeypatch):
    mine = await _nvrs(db_session)
    called = _wire(monkeypatch, db_session, "_poll_single_nvr_health")

    await cam_tasks._poll_all_camera_health()

    assert sorted(mine[c] for c in called if c in mine) == ["hikvision", "legacy"]


async def test_alert_ingest_skips_non_hikvision_recorders(db_session, monkeypatch):
    mine = await _nvrs(db_session)
    called = _wire(monkeypatch, db_session, "_ingest_nvr_alerts")

    await cam_tasks._ingest_all_nvr_alerts()

    assert sorted(mine[c] for c in called if c in mine) == ["hikvision", "legacy"]

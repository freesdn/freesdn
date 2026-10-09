# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Source events stay committed while their owners persist notification work."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

CANARY = "synthetic-private-owner-persistence-error"


def owned_session(mode):
    db = MagicMock()
    db.__aenter__ = AsyncMock(return_value=db)
    db.__aexit__ = AsyncMock(return_value=False)
    db.commit = AsyncMock(
        side_effect=[None, RuntimeError(CANARY)]
        if mode in {"commit_failed", "rollback_failed"}
        else None
    )
    db.rollback = AsyncMock(side_effect=RuntimeError(CANARY) if mode == "rollback_failed" else None)
    return db


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["success", "commit_failed", "rollback_failed", "dispatch_failed"])
async def test_camera_ingestion_owner_persists_notifications_without_losing_ingestion(
    monkeypatch, caplog, mode
):
    from app.adapters.hikvision import adapter as adapter_module
    from app.core import crypto
    from app.tasks import cameras

    db = owned_session(mode)
    nvr_id, camera_id, org_id = [uuid4() for _ in range(3)]
    nvr = SimpleNamespace(
        id=nvr_id,
        organization_id=org_id,
        username="synthetic",
        password_encrypted="synthetic",
        ip_address="127.0.0.1",
        port=1,
    )
    db.get = AsyncMock(return_value=nvr)
    db.execute = AsyncMock(
        side_effect=[
            SimpleNamespace(all=lambda: [(camera_id, 1, "owned-camera")]),
            SimpleNamespace(all=lambda: []),
        ]
    )
    hardware = SimpleNamespace(
        connect=AsyncMock(),
        disconnect=AsyncMock(),
        get_event_state=AsyncMock(
            return_value={
                "events": [
                    {
                        "channel_id": 1,
                        "event_type": "linedetection",
                        "date_time": "2026-09-24T12:00:00+00:00",
                    }
                ]
            }
        ),
    )
    monkeypatch.setattr(adapter_module, "HikvisionAdapter", lambda **_kwargs: hardware)
    monkeypatch.setattr(crypto, "decrypt_credential", lambda _ciphertext: "synthetic")
    monkeypatch.setattr(cameras, "AsyncSessionLocal", lambda: db)

    async def dispatch(*_args):
        assert db.commit.await_count == 1
        if mode == "dispatch_failed":
            raise RuntimeError(CANARY)

    sender = AsyncMock(side_effect=dispatch)
    monkeypatch.setattr(cameras, "_dispatch_alerts", sender)
    result = await cameras._ingest_nvr_alerts(nvr_id)
    assert result == {"nvr_id": str(nvr_id), "ingested": 1}
    assert db.commit.await_count == (1 if mode == "dispatch_failed" else 2)
    assert db.rollback.await_count == int(mode != "success")
    sender.assert_awaited_once()
    hardware.disconnect.assert_awaited_once()
    assert CANARY not in caplog.text and all(row.exc_info is None for row in caplog.records)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["success", "commit_failed", "rollback_failed", "dispatch_failed"])
async def test_remote_scan_owner_commits_notifications_after_its_run_record(
    monkeypatch, caplog, mode
):
    import app.db
    from app.services import remote_agent

    db = owned_session(mode)
    agent, site, org, schedule = [uuid4() for _ in range(4)]
    schedule_row = SimpleNamespace(id=schedule, name="owned", last_fired_at=None)
    db.execute = AsyncMock(
        side_effect=[
            SimpleNamespace(scalar_one_or_none=lambda: SimpleNamespace(organization_id=org)),
            SimpleNamespace(scalar_one_or_none=lambda: schedule_row),
        ]
    )
    monkeypatch.setattr(app.db, "async_session_factory", lambda: db)

    async def dispatch(*_args, **_kwargs):
        assert db.commit.await_count == 1 and db.add.call_count == 1
        if mode == "dispatch_failed":
            raise RuntimeError(CANARY)

    sender = AsyncMock(side_effect=dispatch)
    monkeypatch.setattr(remote_agent, "_maybe_notify_schedule_run", sender)
    owner = SimpleNamespace(
        _connections={str(agent): SimpleNamespace(info=SimpleNamespace(site_id=site))}
    )
    report = SimpleNamespace(
        agent_id=str(agent),
        payload={"devices": [], "schedule_name": "owned", "status": "completed"},
    )
    await remote_agent.AgentRegistryService._persist_scan_result(owner, report)
    assert db.commit.await_count == (1 if mode == "dispatch_failed" else 2)
    assert db.rollback.await_count == int(mode != "success")
    sender.assert_awaited_once()
    assert CANARY not in caplog.text and all(row.exc_info is None for row in caplog.records)

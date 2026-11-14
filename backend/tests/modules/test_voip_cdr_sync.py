# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Stored call history is filled by a scheduled, bounded, incremental CDR sync.

``voip.sync_cdr`` was registered and never scheduled, the FreePBX client's CDR
read returned ``[]`` in every auth mode, and the task logged in with an empty
password, so voip.call_logs stayed empty on every install: the Call History
page and its stats showed nothing, indistinguishable from "nobody called".

Runs the real task body against the real database with only the PBX transport
replaced: PBX + extensions rows -> ``voip.sync_cdr`` -> CallLog rows (direction
and status normalised) -> a second run re-reads from the newest stored call and
adds nothing -> the outcome is recorded on the PBX row. A PBX connected without
an Admin API application is recorded as unsupported without being contacted.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from app.adapters.base import AdapterResult
from app.core.crypto import encrypt_credential
from app.db.session import CelerySessionLocal
from app.models.core import Organization, Site
from app.modules.voip import tasks
from app.modules.voip.models import PBX, CallLog, Extension


class _FakeCdrAdapter:
    """Stands in for FreePBXAdapter; serves CDR rows by day."""

    by_day: dict[str, list[dict]] = {}
    requested: list[str] = []
    connected = 0

    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        type(self).connected += 1
        return self

    async def __aexit__(self, *_exc):
        return False

    async def search_call_logs(self, *, start_date, end_date, limit):
        assert start_date == end_date and limit == tasks.CDR_MAX_RECORDS_PER_DAY
        type(self).requested.append(start_date)
        return AdapterResult.ok(data=[dict(r) for r in type(self).by_day.get(start_date, [])])


def _cdr(uniqueid, when, src, dst, disposition="ANSWERED", duration=60):
    return {
        "uniqueid": uniqueid,
        "calldate": when.strftime("%Y-%m-%d %H:%M:%S"),
        "src": src,
        "cnum": src,
        "dst": dst,
        "disposition": disposition,
        "duration": str(duration),
        "billsec": str(max(duration - 5, 0)),
    }


@pytest.fixture
def pbx(monkeypatch):
    import app.adapters.freepbx as freepbx_pkg

    org, site, pbx_id, bare_id = uuid4(), uuid4(), uuid4(), uuid4()
    _FakeCdrAdapter.by_day, _FakeCdrAdapter.requested, _FakeCdrAdapter.connected = {}, [], 0
    monkeypatch.setattr(freepbx_pkg, "FreePBXAdapter", _FakeCdrAdapter)

    async def _create():
        async with CelerySessionLocal() as db:
            db.add(Organization(id=org, name="CDR fixture", slug="cdr-" + org.hex))
            await db.flush()
            db.add(Site(id=site, name="CDR site", slug="cdr-" + site.hex, organization_id=org))
            await db.flush()
            db.add_all(
                [
                    PBX(
                        id=pbx_id,
                        site_id=site,
                        name="pbx",
                        pbx_type="freepbx",
                        ip_address="192.0.2.30",
                        settings={"api_username": "admin"},
                        web_password_enc=encrypt_credential("web"),
                        api_client_id="client-id",
                        api_client_secret_enc=encrypt_credential("client-secret"),
                    ),
                    # Connected with a web session only: cannot serve CDR.
                    PBX(
                        id=bare_id,
                        site_id=site,
                        name="bare",
                        pbx_type="freepbx",
                        ip_address="192.0.2.31",
                        settings={"api_username": "admin"},
                        web_password_enc=encrypt_credential("web"),
                    ),
                ]
            )
            await db.flush()
            db.add_all(
                [
                    Extension(pbx_id=pbx_id, extension_number=n, display_name=n)
                    for n in ("101", "102")
                ]
            )
            await db.commit()

    async def _drop():
        async with CelerySessionLocal() as db:
            await db.execute(delete(CallLog).where(CallLog.pbx_id.in_([pbx_id, bare_id])))
            await db.execute(delete(Extension).where(Extension.pbx_id == pbx_id))
            await db.execute(delete(PBX).where(PBX.id.in_([pbx_id, bare_id])))
            await db.execute(delete(Site).where(Site.id == site))
            await db.execute(delete(Organization).where(Organization.id == org))
            await db.commit()

    asyncio.run(_create())
    try:
        yield {"id": pbx_id, "bare": bare_id, "org": org}
    finally:
        asyncio.run(_drop())


def _read(pbx_id):
    async def _go():
        async with CelerySessionLocal() as db:
            calls = list(
                (await db.execute(select(CallLog).where(CallLog.pbx_id == pbx_id))).scalars()
            )
            row = await db.get(PBX, pbx_id)
            return calls, dict(row.settings or {})

    return asyncio.run(_go())


def test_call_records_are_imported_once_and_resumed_from_the_newest(pbx):
    now = datetime.now(UTC).replace(microsecond=0)
    today, yesterday = now.date().isoformat(), (now - timedelta(days=1)).date().isoformat()
    _FakeCdrAdapter.by_day = {
        yesterday: [_cdr("u1", now - timedelta(days=1), "+15550100", "101")],
        today: [
            _cdr("u2", now - timedelta(minutes=30), "101", "+15550199", "NO ANSWER", 0),
            _cdr("u3", now - timedelta(minutes=5), "101", "102"),
        ],
    }

    first = tasks.sync_cdr.run(str(pbx["id"]))

    assert first["status"] == "ok" and first["new_records"] == 3, first
    # First sync of a PBX: bounded backfill, one request per day, oldest first.
    assert (
        _FakeCdrAdapter.requested[0]
        == (now.date() - timedelta(days=tasks.CDR_BACKFILL_DAYS)).isoformat()
    )
    assert _FakeCdrAdapter.requested[-1] == today
    calls, settings = _read(pbx["id"])
    shape = {c.unique_id: (c.direction, c.status, c.caller_number, c.callee_number) for c in calls}
    assert shape == {
        "u1": ("inbound", "completed", "+15550100", "101"),
        "u2": ("outbound", "no_answer", "101", "+15550199"),
        "u3": ("internal", "completed", "101", "102"),
    }
    assert settings["cdr_sync"]["status"] == "ok"
    assert settings["cdr_sync"]["imported"] == 3

    # Second run: resumes from the newest stored call's day, stores nothing twice.
    _FakeCdrAdapter.requested = []
    second = tasks.sync_cdr.run(str(pbx["id"]))

    assert second["status"] == "ok" and second["new_records"] == 0, second
    newest_day = (now - timedelta(minutes=5)).date()
    expected = []
    while newest_day <= now.date():
        expected.append(newest_day.isoformat())
        newest_day += timedelta(days=1)
    assert _FakeCdrAdapter.requested == expected
    calls, settings = _read(pbx["id"])
    assert sorted(c.unique_id for c in calls) == ["u1", "u2", "u3"]
    assert settings["cdr_sync"]["imported"] == 0


def test_a_pbx_without_an_admin_api_app_is_recorded_unsupported_not_contacted(pbx):
    result = tasks.sync_cdr.run(str(pbx["bare"]))

    assert result["status"] == "unsupported"
    assert _FakeCdrAdapter.connected == 0
    calls, settings = _read(pbx["bare"])
    assert calls == []
    assert settings["cdr_sync"]["status"] == "unsupported"
    assert "OAuth2" in settings["cdr_sync"]["error"]


def test_the_beat_fan_out_queues_every_active_pbx(pbx, monkeypatch):
    queued: list[str] = []
    monkeypatch.setattr(tasks.sync_cdr, "apply_async", lambda args, **_kw: queued.append(args[0]))

    tasks.sync_all_cdr.run()

    assert {str(pbx["id"]), str(pbx["bare"])} <= set(queued)


def test_an_organization_that_disabled_voip_is_not_polled(pbx, monkeypatch):
    from app.modules.models import OrganizationModule

    async def _disable():
        async with CelerySessionLocal() as db:
            db.add(
                OrganizationModule(organization_id=pbx["org"], module_id="voip", is_enabled=False)
            )
            await db.commit()

    asyncio.run(_disable())
    queued: list[str] = []
    monkeypatch.setattr(tasks.sync_cdr, "apply_async", lambda args, **_kw: queued.append(args[0]))
    try:
        tasks.sync_all_cdr.run()
    finally:

        async def _enable():
            async with CelerySessionLocal() as db:
                await db.execute(
                    delete(OrganizationModule).where(
                        OrganizationModule.organization_id == pbx["org"]
                    )
                )
                await db.commit()

        asyncio.run(_enable())

    assert not {str(pbx["id"]), str(pbx["bare"])} & set(queued)


def test_the_cdr_sync_is_on_the_beat_schedule():
    from app.core.celery_app import celery_app

    entries = [
        e for e in celery_app.conf.beat_schedule.values() if e["task"] == "voip.sync_all_cdr"
    ]
    assert len(entries) == 1
    assert entries[0]["options"]["queue"] == "default"


# --------------------------------------------------------------------------
# The FreePBX client's CDR read: honest about what it cannot do
# --------------------------------------------------------------------------


def _client(mode):
    from app.adapters.freepbx.rest_client import FreePBXRestClient

    client = FreePBXRestClient("192.0.2.30", "admin", "pw")
    client._auth_mode = mode
    return client


async def test_a_web_session_cannot_read_cdr_and_says_so():
    from app.adapters.freepbx.exceptions import FreePBXApiError

    with pytest.raises(FreePBXApiError, match="OAuth2"):
        await _client("session").search_cdr(start_date="2026-11-01")


async def test_the_admin_api_read_sends_validated_literals_and_parses_rows(monkeypatch):
    client = _client("oauth2")
    sent: list[str] = []

    async def _graphql(query, variables=None, **_kw):
        sent.append(query)
        return {
            "fetchAllCdrs": {
                "cdrs": [{"uniqueid": "a", "src": "101"}, {"uniqueid": "b", "src": "102"}],
                "totalCount": 2,
                "status": True,
            }
        }

    monkeypatch.setattr(client, "_graphql", _graphql)

    rows = await client.search_cdr(start_date="2026-11-01", end_date="2026-11-01", src="102")

    assert rows == [{"uniqueid": "b", "src": "102"}]
    assert 'startDate: "2026-11-01"' in sent[0] and "fetchAllCdrs(" in sent[0]


async def test_a_malformed_date_never_reaches_the_query(monkeypatch):
    from app.adapters.freepbx.exceptions import FreePBXApiError

    client = _client("oauth2")
    monkeypatch.setattr(client, "_graphql", lambda *_a, **_k: pytest.fail("query sent"))
    with pytest.raises(FreePBXApiError, match="YYYY-MM-DD"):
        await client.search_cdr(start_date='2026-11-01") { injected }')

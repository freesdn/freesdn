# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""Freshness boundaries, atomic ingest and executable-code authorization."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api.v1.endpoints import marketplace as mp
from app.models.marketplace import MarketplaceCatalogState, MarketplacePlugin
from app.services import marketplace_catalog as policy
from tests.services.test_marketplace_replay_regression import (
    _catalog_request_actor,
    _catalog_setup,
    _sync_with_catalog_actor,
)


@pytest.fixture
def catalogs(monkeypatch):
    return _catalog_setup(monkeypatch)


@pytest.mark.parametrize("value", [True, False, 0, -1, 2**63, 1.0, "1", None])
async def test_invalid_signed_serial_cannot_write(db_session, catalogs, value):
    make, sync = catalogs
    with pytest.raises(HTTPException):
        await sync(db_session, make(value))
    assert (await db_session.execute(select(MarketplaceCatalogState))).scalar_one_or_none() is None


@pytest.mark.parametrize(
    "fields",
    [
        {"generated_at": None},
        {"expires_at": None},
        {"generated_at": "2026-01-01T00:00:00"},
        {"generated_at": "bad"},
        {"generated_at": "2026-01-01"},
        {"generated_at": "9999-12-31T23:59:59-23:59"},
        {"generated_at": "9998-01-01T00:00:00Z", "expires_at": "9999-01-01T00:00:00Z"},
        {"generated_at": "2026-01-02T00:00:00Z", "expires_at": "2026-01-01T00:00:00Z"},
    ],
)
async def test_invalid_signed_times_cannot_write(db_session, catalogs, fields):
    make, sync = catalogs
    with pytest.raises(HTTPException):
        await sync(db_session, make(1, **fields))
    assert (await db_session.execute(select(MarketplaceCatalogState))).scalar_one_or_none() is None


async def test_identical_snapshot_is_idempotent(db_session, catalogs):
    make, sync = catalogs
    snapshot = make(7)
    first = await sync(db_session, snapshot)
    second = await sync(db_session, snapshot)
    assert first["catalog_serial"] == second["catalog_serial"] == 7
    assert len((await db_session.execute(select(MarketplacePlugin))).scalars().all()) == 2


@pytest.mark.parametrize("entries", [None, {}, "bad", [None], [{"plugin_id": "incomplete"}]])
async def test_malformed_snapshot_does_not_advance_floor(db_session, catalogs, entries):
    make, sync = catalogs
    await sync(db_session, make(1))
    with pytest.raises(HTTPException):
        await sync(db_session, make(2, plugins=entries))
    assert (await db_session.execute(select(MarketplaceCatalogState))).scalar_one().serial == 1


async def test_duplicate_ids_and_slug_conflicts_preserve_whole_snapshot(db_session, catalogs):
    make, sync = catalogs
    await sync(db_session, make(1, ("kept",)))
    for entries in (
        make(2, ("other", "other"))["plugins"],
        [{**make(2, ("other",))["plugins"][0], "slug": "kept"}],
    ):
        with pytest.raises(HTTPException):
            await sync(db_session, make(2, plugins=entries))
        assert (await db_session.execute(select(MarketplaceCatalogState))).scalar_one().serial == 1
        rows = (await db_session.execute(select(MarketplacePlugin))).scalars().all()
        assert [(r.plugin_id, r.status) for r in rows] == [("kept", "published")]


async def test_seed_after_acceptance_does_not_change_withdrawal_or_floor(
    db_session, catalogs, monkeypatch
):
    make, sync = catalogs
    await sync(db_session, make(1))
    await sync(db_session, make(2, ()))
    monkeypatch.setattr(mp, "_fetch_registry_catalog", AsyncMock(side_effect=OSError("offline")))
    result = await _sync_with_catalog_actor(db_session)
    assert result["seed_ignored"] and result["synced"] == 0
    assert (await db_session.execute(select(MarketplaceCatalogState))).scalar_one().serial == 2
    assert {r.status for r in (await db_session.execute(select(MarketplacePlugin))).scalars()} == {
        "withdrawn"
    }


async def test_restore_floor_refuses_old_database_snapshot(db_session, catalogs, monkeypatch):
    make, sync = catalogs
    old = make(1)
    await sync(db_session, old)
    monkeypatch.setattr(mp, "MARKETPLACE_MIN_SERIAL", "3")
    with pytest.raises(HTTPException, match="minimum"):
        await sync(db_session, make(2))
    with pytest.raises(HTTPException, match="minimum"):
        await mp._resolve_published(db_session, "kept")
    await sync(db_session, make(3))
    assert (await mp._resolve_published(db_session, "kept")).plugin_id == "kept"


async def test_feed_change_cannot_silently_reset_floor(db_session, catalogs, monkeypatch):
    make, sync = catalogs
    await sync(db_session, make(10))
    monkeypatch.setattr(
        mp, "MARKETPLACE_REGISTRY_URL", "https://changed.example.invalid/catalog.json"
    )
    with pytest.raises(HTTPException, match="changed"):
        await sync(db_session, make(11))
    with pytest.raises(HTTPException, match="accepted catalog"):
        await mp._resolve_published(db_session, "kept")


@pytest.mark.parametrize("operation", ["install", "upgrade"])
async def test_expiry_after_download_refuses_loader_execution(
    db_session, catalogs, monkeypatch, operation
):
    from app.models.plugins import InstalledPlugin
    from app.plugins.loader import plugin_loader

    make, sync = catalogs
    snapshot = make(1)
    await sync(db_session, snapshot)
    called = AsyncMock()
    monkeypatch.setattr(
        plugin_loader, "install_plugin" if operation == "install" else "upgrade_plugin", called
    )
    stopped = AsyncMock()
    monkeypatch.setattr(plugin_loader, "stop_plugin_everywhere", stopped)
    if operation == "upgrade":
        db_session.add(
            InstalledPlugin(
                plugin_id="kept",
                name="Fixture",
                version="0.9.0",
                plugin_dir="/fixture/never-executed",
            )
        )
        await db_session.commit()

    async def download(_plugin):
        monkeypatch.setattr(
            policy,
            "utc_now",
            lambda: datetime.fromisoformat(snapshot["expires_at"]) + timedelta(seconds=1),
        )
        return b"not-executed"

    monkeypatch.setattr(mp, "_download_and_verify", download)
    with pytest.raises(HTTPException, match="expired"):
        endpoint = (
            mp.install_from_marketplace if operation == "install" else mp.upgrade_from_marketplace
        )
        request, actor = await _catalog_request_actor(db_session)
        await endpoint("kept", request, actor, db_session)
    called.assert_not_awaited()
    stopped.assert_not_awaited()


async def test_local_unknown_provenance_is_not_installable(db_session, catalogs):
    make, sync = catalogs
    await sync(db_session, make(1))
    plugin = (
        await db_session.execute(select(MarketplacePlugin).where(MarketplacePlugin.slug == "kept"))
    ).scalar_one()
    plugin.catalog_serial = None
    await db_session.flush()
    with pytest.raises(HTTPException, match="accepted catalog"):
        await mp._resolve_published(db_session, "kept")


@pytest.mark.parametrize("value", ["-1", "true", "1.5", str(2**63), ""])
def test_invalid_external_floor_fails_closed(value):
    with pytest.raises(HTTPException) as error:
        policy.minimum_serial(value)
    assert error.value.status_code == 503


async def test_catalog_expiring_while_waiting_for_lock_is_refused(
    db_session, catalogs, monkeypatch
):
    make, sync = catalogs
    snapshot = make(1)
    original = policy.lock_catalog

    async def delayed_lock(session):
        state = await original(session)
        monkeypatch.setattr(
            policy, "utc_now", lambda: datetime.fromisoformat(snapshot["expires_at"])
        )
        return state

    monkeypatch.setattr(policy, "lock_catalog", delayed_lock)
    with pytest.raises(HTTPException, match="expired"):
        await sync(db_session, snapshot)
    assert (await db_session.execute(select(MarketplaceCatalogState))).scalar_one_or_none() is None
    assert not (await db_session.execute(select(MarketplacePlugin))).scalars().all()


async def test_suspended_row_is_not_republished_by_new_signed_snapshot(db_session, catalogs):
    make, sync = catalogs
    await sync(db_session, make(1))
    row = (
        await db_session.execute(select(MarketplacePlugin).where(MarketplacePlugin.slug == "kept"))
    ).scalar_one()
    row.status = "suspended"
    await db_session.commit()
    await sync(db_session, make(2))
    assert (
        await db_session.execute(select(MarketplacePlugin).where(MarketplacePlugin.slug == "kept"))
    ).scalar_one().status == "suspended"


async def test_tampered_freshness_fields_never_fall_back_to_seed(db_session, catalogs):
    make, sync = catalogs
    snapshot = make(1)
    snapshot["serial"] = 999
    with pytest.raises(HTTPException, match="INVALID") as error:
        await sync(db_session, snapshot)
    assert error.value.status_code == 403
    assert not (await db_session.execute(select(MarketplacePlugin))).scalars().all()


async def test_seed_before_first_sync_cannot_revive_legacy_withdrawal(
    db_session, catalogs, monkeypatch
):
    make, _ = catalogs
    entry = make(1, ("hello-world",))["plugins"][0]
    row = MarketplacePlugin(**entry, status="withdrawn")
    db_session.add(row)
    await db_session.commit()
    monkeypatch.setattr(mp, "_fetch_registry_catalog", AsyncMock(side_effect=OSError("offline")))
    result = await _sync_with_catalog_actor(db_session)
    assert result["used_seed"] and not result["seed_ignored"]
    legacy = (
        await db_session.execute(
            select(MarketplacePlugin).where(MarketplacePlugin.plugin_id == "hello-world")
        )
    ).scalar_one()
    assert legacy.status == "withdrawn" and legacy.latest_version == "1.0.0"
    assert legacy.catalog_identity is None and legacy.catalog_serial is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("checksum_sha256", "x" * 64),
        ("download_url", "http://example.invalid/p.zip"),
        ("download_url", "https://name:secret@example.invalid/p.zip"),
        ("tags", "not-an-array"),
        ("screenshots", [17]),
        ("name", "x" * 201),
    ],
)
async def test_signed_invalid_entry_aborts_before_floor_is_written(
    db_session, catalogs, field, value
):
    make, sync = catalogs
    entry = make(1, ("kept",))["plugins"][0]
    with pytest.raises(HTTPException):
        await sync(db_session, make(1, plugins=[{**entry, field: value}]))
    assert (await db_session.execute(select(MarketplaceCatalogState))).scalar_one_or_none() is None


async def test_remote_trust_flags_do_not_become_local_trust(db_session, catalogs):
    make, sync = catalogs
    entry = make(1, ("kept",))["plugins"][0]
    await sync(
        db_session,
        make(
            1,
            plugins=[
                {
                    **entry,
                    "is_verified": True,
                    "is_featured": True,
                    "status": "suspended",
                    "download_count": 999,
                }
            ],
        ),
    )
    row = (await db_session.execute(select(MarketplacePlugin))).scalar_one()
    assert not row.is_verified and not row.is_featured
    assert row.status == "published" and row.download_count == 0

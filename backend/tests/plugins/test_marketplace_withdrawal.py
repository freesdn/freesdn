# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
Withdrawing a plugin from the registry did nothing to anyone who already had it.

The sync loop only ever upserted. A plugin the registry DROPPED -- retired,
renamed, or pulled because it turned out to be harmful -- stayed listed and
installable for ever on every deployment that had synced it once. Withdrawal was
the only lever the project had over a bad plugin, and it reached exactly the
installs that had never fetched the catalogue.

Found by driving the marketplace install button end to end against the live
registry. Two plugins retired days earlier because they shadowed native
subsystems, ``notify-hub`` and ``ai-ops-tools``, were still on offer, and
``notify-hub`` installed cleanly on HTTP 201.

Reproduced and then fixed:

    BEFORE sync -- listed: 11, retired plugins still on offer: notify-hub, ai-ops-tools
    sync        -- "Synced 9 plugins from registry (0 skipped).
                    Withdrawn (no longer in the registry): ai-ops-tools, notify-hub"
    AFTER sync  -- listed: 9,  retired plugins still on offer: none
    install     -- HTTP 410, and the copy already installed is still running

The three properties below are each a decision, and the third is the one that
matters most: the registry decides what is on OFFER, the operator decides what
RUNS. An upstream index change must never stop production work.
"""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api.v1.endpoints import marketplace as mp
from app.models.marketplace import MarketplacePlugin
from tests.services.test_marketplace_replay_regression import (
    _catalog_setup,
    _sync_with_catalog_actor,
)


@pytest.fixture
def catalogs(monkeypatch):
    return _catalog_setup(monkeypatch)


async def test_a_plugin_the_registry_dropped_is_withdrawn(db_session, catalogs):
    make, sync = catalogs
    await sync(db_session, make(1, ("netbox-sync", "notify-hub", "ai-ops-tools")))
    out = await sync(db_session, make(2, ("netbox-sync",)))
    assert sorted(out["withdrawn"]) == ["ai-ops-tools", "notify-hub"]
    rows = (await db_session.execute(select(MarketplacePlugin))).scalars().all()
    assert {r.plugin_id: r.status for r in rows} == {
        "netbox-sync": "published",
        "notify-hub": "withdrawn",
        "ai-ops-tools": "withdrawn",
    }


async def test_the_operator_is_told_which_ones(db_session, catalogs):
    make, sync = catalogs
    await sync(db_session, make(1, ("netbox-sync", "notify-hub")))
    out = await sync(db_session, make(2, ("netbox-sync",)))
    assert "notify-hub" in out["message"] and "withdraw" in out["message"].lower()


async def test_a_withdrawn_row_is_not_deleted(db_session, catalogs):
    make, sync = catalogs
    await sync(db_session, make(1, ("notify-hub",)))
    before = (await db_session.execute(select(MarketplacePlugin))).scalar_one()
    before.rating_count = 5
    row_id = before.id
    await db_session.commit()
    await sync(db_session, make(2, ("netbox-sync",)))
    row = (
        await db_session.execute(select(MarketplacePlugin).where(MarketplacePlugin.id == row_id))
    ).scalar_one()
    assert row.plugin_id == "notify-hub" and row.rating_count == 5 and row.status == "withdrawn"
    with pytest.raises(HTTPException) as error:
        await mp._resolve_published(db_session, "notify-hub")
    assert error.value.status_code == 410


async def test_a_relisted_plugin_comes_back_with_newer_signed_catalog(db_session, catalogs):
    make, sync = catalogs
    await sync(db_session, make(1, ("netbox-sync",)))
    await sync(db_session, make(2, ()))
    out = await sync(db_session, make(3, ("netbox-sync",)))
    row = await mp._resolve_published(db_session, "netbox-sync")
    assert row.status == "published" and row.catalog_serial == 3 and out["withdrawn"] == []


async def test_the_seed_fallback_never_withdraws_anything(db_session, catalogs, monkeypatch):
    make, sync = catalogs
    await sync(db_session, make(1, ("some-private-plugin", "another-one")))
    monkeypatch.setattr(mp, "_fetch_registry_catalog", AsyncMock(side_effect=OSError("offline")))
    out = await _sync_with_catalog_actor(db_session)
    assert out["used_seed"] and out["seed_ignored"] and out["withdrawn"] == []
    assert all(
        r.status == "published"
        for r in (await db_session.execute(select(MarketplacePlugin))).scalars()
    )


async def test_an_empty_signed_catalogue_withdraws_offers(db_session, catalogs):
    # A signed empty snapshot is the publisher's only way to withdraw everything.
    # Invalid, unsigned and incomplete snapshots are rejected before mutations.
    make, sync = catalogs
    await sync(db_session, make(1, ("netbox-sync", "hello-world")))
    out = await sync(db_session, make(2, ()))
    assert set(out["withdrawn"]) == {"netbox-sync", "hello-world"}
    assert all(
        r.status == "withdrawn"
        for r in (await db_session.execute(select(MarketplacePlugin))).scalars()
    )


def test_sync_never_touches_an_installed_plugin():
    """
    THE property. The registry decides what is on offer; the operator decides
    what runs. Uninstalling somebody's running integration because an upstream
    index changed would be a remote actor stopping production work.

    Verified live too: after notify-hub was withdrawn, GET /plugins/notify-hub
    still answered 200 and the plugin kept running.
    """
    from app.api.v1.endpoints.marketplace import sync_marketplace

    src = inspect.getsource(sync_marketplace)
    body = "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))
    for forbidden in ("uninstall", "plugin_loader", "InstalledPlugin"):
        assert forbidden not in body, f"sync reaches into installed plugins via {forbidden!r}"


# ── the install refusal ─────────────────────────────────────────


def test_a_withdrawn_plugin_says_so():
    """
    A flat 404 made a plugin the registry had deliberately pulled look like a
    typo. The two need opposite reactions from whoever is reading.
    """
    from app.api.v1.endpoints.marketplace import _resolve_published

    src = inspect.getsource(_resolve_published)
    assert '"withdrawn"' in src, "cannot tell withdrawn from unknown"
    assert "410" in src, "a withdrawn plugin is not reported as gone"
    assert "404" in src, "an unknown slug is no longer a 404"


def test_resolution_still_requires_a_published_row():
    """
    The de-listing is only worth anything because this filters on it. If that
    filter ever goes, withdrawal becomes cosmetic.
    """
    from app.api.v1.endpoints.marketplace import _resolve_published

    assert 'status == "published"' in inspect.getsource(_resolve_published)


@pytest.mark.parametrize("endpoint", ["install_from_marketplace", "upgrade_from_marketplace"])
def test_every_entry_point_goes_through_that_check(endpoint: str):
    """
    Both buttons load third-party code, so both have to refuse a withdrawn
    plugin. Having the check in one shared place is the point -- an install path
    that resolved its own row would be the obvious way for the two to drift.
    """
    import app.api.v1.endpoints.marketplace as mp

    src = inspect.getsource(getattr(mp, endpoint))
    assert "_resolve_published(" in src, f"{endpoint} resolves the catalogue row itself"
